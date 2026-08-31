# Copyright (c) 2026 Cockroach Labs, Inc.
# SPDX-License-Identifier: MIT
"""Unit tests for dbprofiler.

Run with:  python3 -m unittest -v

These tests never open a network connection. Where a connection string is
needed to exercise parsing, it is built from the synthetic values fixed by
.claude/rules/development.md -- host db.invalid (RFC 2606 reserved, can never
resolve), user example-user, password example-password, database example-db --
so that a reviewer grepping for a credential leak can tell test data apart from
the real thing.
"""

import ast
import contextlib
import csv
import dataclasses
import fnmatch
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest import mock

import dbprofiler

HOST = "db.invalid"
USER = "example-user"
PASSWORD = "example-password"
DATABASE = "example-db"
URL = f"postgres://{USER}:{PASSWORD}@{HOST}:5433/{DATABASE}"


def postgres_args(**overrides):
    """Parse a postgres command line, with --output defaulted."""
    argv = ["postgres", "--output", overrides.pop("output", "profile.zip")]
    for flag, value in overrides.items():
        flag = "--" + flag.replace("_", "-")
        if isinstance(value, (list, tuple)):
            for item in value:
                argv += [flag, str(item)]
        else:
            argv += [flag, str(value)]
    return dbprofiler.build_parser().parse_args(argv)


class TestVersion(unittest.TestCase):
    def test_version_is_a_nonempty_string(self):
        self.assertIsInstance(dbprofiler.VERSION, str)
        self.assertTrue(dbprofiler.VERSION)

    def test_version_is_a_release_number_not_a_placeholder(self):
        # The release workflow refuses to publish unless the tag equals this
        # string, so a placeholder here makes every tag unpublishable -- and the
        # way you find out is a failed release, after the tag is already pushed.
        # Requiring a real number keeps main taggable and moves that discovery
        # into the unit suite, where it costs nothing.
        self.assertRegex(dbprofiler.VERSION, r"^\d+\.\d+\.\d+$")

    def test_contract_version_is_1_0(self):
        self.assertEqual(dbprofiler.CONTRACT_VERSION, "1.0")

    def test_version_flag_prints_version_and_exits_zero(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            dbprofiler.main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(stdout.getvalue().strip(), dbprofiler.VERSION)


class TestCheckSafety(unittest.TestCase):
    def test_check_safety_passes_on_the_current_source(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(dbprofiler.check_safety(), 0)

    def test_check_safety_flag_exits_zero(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(dbprofiler.main(["--check-safety"]), 0)

    def test_every_sql_constant_is_a_string(self):
        for name, sql in dbprofiler.iter_sql_constants():
            self.assertIsInstance(sql, str, f"{name} is not a string")

    def test_check_safety_rejects_a_planted_forbidden_token(self):
        """The guard must actually fail on a violation, not just pass vacuously."""
        for token, sql in (
            ("COUNT(", "SELECT COUNT(*) FROM users"),
            ("ANALYZE", "ANALYZE public.users"),
            ("CREATE STATISTICS", "CREATE STATISTICS s ON a, b FROM t"),
        ):
            with self.subTest(token=token):
                stderr = io.StringIO()
                with mock.patch.object(dbprofiler, "SQL_PLANTED", sql, create=True):
                    with contextlib.redirect_stderr(stderr):
                        self.assertEqual(dbprofiler.check_safety(), 1)
                self.assertIn("SQL_PLANTED", stderr.getvalue())

    def test_check_safety_is_not_evaded_by_formatting(self):
        """Case, newlines, and a space before the paren must not hide a violation."""
        for sql in (
            "select\n  count(\n *)\nfrom t",
            "SELECT COUNT (*) FROM t",
            "select\n  count (*) from t",
        ):
            with self.subTest(sql=sql):
                stderr = io.StringIO()
                with mock.patch.object(dbprofiler, "SQL_PLANTED", sql, create=True):
                    with contextlib.redirect_stderr(stderr):
                        self.assertEqual(dbprofiler.check_safety(), 1)
                self.assertIn("SQL_PLANTED", stderr.getvalue())


class TestParseConnectionUrl(unittest.TestCase):
    def test_full_url_maps_to_libpq_env(self):
        env = dbprofiler.parse_connection_url(URL)
        self.assertEqual(
            env,
            {
                "PGHOST": HOST,
                "PGPORT": "5433",
                "PGUSER": USER,
                "PGPASSWORD": PASSWORD,
                "PGDATABASE": DATABASE,
            },
        )

    def test_postgresql_scheme_is_accepted(self):
        env = dbprofiler.parse_connection_url(f"postgresql://{HOST}/{DATABASE}")
        self.assertEqual(env["PGHOST"], HOST)

    def test_rejects_other_schemes(self):
        for url in (f"mysql://{HOST}/{DATABASE}", f"http://{HOST}/{DATABASE}", HOST):
            with self.subTest(url=url), self.assertRaises(dbprofiler.ConfigError):
                dbprofiler.parse_connection_url(url)

    def test_percent_encoded_credentials_are_decoded(self):
        # A password containing @ : / must survive the round trip.
        url = "postgres://ex%40mple-user:p%40ss%3Aword%2F1@db.invalid/example-db"
        env = dbprofiler.parse_connection_url(url)
        self.assertEqual(env["PGUSER"], "ex@mple-user")
        self.assertEqual(env["PGPASSWORD"], "p@ss:word/1")

    def test_absent_parts_are_omitted_rather_than_defaulted(self):
        # libpq supplies its own defaults; inventing them here would mask the
        # customer's own PGPORT/PGUSER settings.
        env = dbprofiler.parse_connection_url(f"postgres://{HOST}/{DATABASE}")
        self.assertNotIn("PGPORT", env)
        self.assertNotIn("PGUSER", env)
        self.assertNotIn("PGPASSWORD", env)

    def test_database_is_required(self):
        with self.assertRaises(dbprofiler.ConfigError):
            dbprofiler.parse_connection_url(f"postgres://{USER}@{HOST}:5433/")

    def test_database_may_come_from_a_query_parameter(self):
        env = dbprofiler.parse_connection_url(f"postgres://{HOST}/?dbname={DATABASE}")
        self.assertEqual(env["PGDATABASE"], DATABASE)

    def test_ipv6_host_is_unbracketed(self):
        env = dbprofiler.parse_connection_url(f"postgres://[::1]:5433/{DATABASE}")
        self.assertEqual(env["PGHOST"], "::1")

    def test_sslmode_is_carried_through(self):
        """Silently dropping sslmode would downgrade a connection the customer
        asked to encrypt."""
        env = dbprofiler.parse_connection_url(f"postgres://{HOST}/{DATABASE}?sslmode=require")
        self.assertEqual(env["PGSSLMODE"], "require")

    def test_unknown_query_parameters_are_rejected(self):
        # Failing loudly beats dropping an option the customer believed was applied.
        with self.assertRaises(dbprofiler.ConfigError):
            dbprofiler.parse_connection_url(f"postgres://{HOST}/{DATABASE}?nonsense=1")

    def test_error_messages_never_quote_the_url(self):
        with self.assertRaises(dbprofiler.ConfigError) as raised:
            dbprofiler.parse_connection_url(f"mysql://{USER}:{PASSWORD}@{HOST}/{DATABASE}")
        message = str(raised.exception)
        self.assertNotIn(PASSWORD, message)
        self.assertNotIn(USER, message)
        self.assertNotIn(HOST, message)

    def test_invalid_port_is_rejected(self):
        for port in ("abc", "0", "70000"):
            with self.subTest(port=port), self.assertRaises(dbprofiler.ConfigError):
                dbprofiler.parse_connection_url(f"postgres://{HOST}:{port}/{DATABASE}")


class TestBuildPostgresConfig(unittest.TestCase):
    def test_url_comes_from_the_environment(self):
        cfg = dbprofiler.build_postgres_config(
            postgres_args(), {"DBPROFILER_POSTGRES_URL": URL}
        )
        self.assertEqual(cfg.env["PGHOST"], HOST)

    def test_url_flag_overrides_the_environment(self):
        cfg = dbprofiler.build_postgres_config(
            postgres_args(url=f"postgres://other.invalid/{DATABASE}"),
            {"DBPROFILER_POSTGRES_URL": URL},
        )
        self.assertEqual(cfg.env["PGHOST"], "other.invalid")

    def test_reads_the_real_process_environment_by_default(self):
        with mock.patch.dict("os.environ", {"DBPROFILER_POSTGRES_URL": URL}, clear=True):
            cfg = dbprofiler.build_postgres_config(postgres_args())
        self.assertEqual(cfg.env["PGDATABASE"], DATABASE)

    def test_missing_url_is_an_error(self):
        with self.assertRaises(dbprofiler.ConfigError) as raised:
            dbprofiler.build_postgres_config(postgres_args(), {})
        self.assertIn("DBPROFILER_POSTGRES_URL", str(raised.exception))

    def test_output_must_be_a_zip(self):
        for output in ("profile.tar", "profile", "profile.zip.gz"):
            with self.subTest(output=output), self.assertRaises(dbprofiler.ConfigError):
                dbprofiler.build_postgres_config(
                    postgres_args(output=output), {"DBPROFILER_POSTGRES_URL": URL}
                )

    def test_output_becomes_an_absolute_path(self):
        cfg = dbprofiler.build_postgres_config(
            postgres_args(output="profile.zip"), {"DBPROFILER_POSTGRES_URL": URL}
        )
        self.assertIsInstance(cfg.output, Path)
        self.assertTrue(cfg.output.is_absolute())

    def test_a_symlinked_output_is_not_resolved_away(self):
        """Path.resolve() follows the final symlink, which would leave the
        publication-time symlink check with nothing to see."""
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "link.zip"
            link.symlink_to(Path(directory) / "elsewhere.zip")
            cfg = dbprofiler.build_postgres_config(
                postgres_args(output=str(link)), {"DBPROFILER_POSTGRES_URL": URL}
            )
            self.assertTrue(cfg.output.is_symlink())
            self.assertEqual(cfg.output.name, "link.zip")

    def test_the_output_directory_is_still_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            nested = Path(directory) / "sub"
            nested.mkdir()
            cfg = dbprofiler.build_postgres_config(
                postgres_args(output=str(nested / ".." / "profile.zip")),
                {"DBPROFILER_POSTGRES_URL": URL},
            )
        self.assertNotIn("..", cfg.output.parts)

    def test_schema_include_and_exclude_are_mutually_exclusive(self):
        args = postgres_args(schema_include="app", schema_exclude="audit")
        with self.assertRaises(dbprofiler.ConfigError):
            dbprofiler.build_postgres_config(args, {"DBPROFILER_POSTGRES_URL": URL})

    def test_schema_filters_accumulate_and_deduplicate(self):
        args = postgres_args(schema_include=["app", "billing", "app"])
        cfg = dbprofiler.build_postgres_config(args, {"DBPROFILER_POSTGRES_URL": URL})
        self.assertEqual(cfg.schema_include, ("app", "billing"))

    def test_timeout_must_be_positive(self):
        for timeout in ("0", "-1"):
            with self.subTest(timeout=timeout), self.assertRaises(dbprofiler.ConfigError):
                dbprofiler.build_postgres_config(
                    postgres_args(timeout=timeout), {"DBPROFILER_POSTGRES_URL": URL}
                )

    def test_defaults(self):
        cfg = dbprofiler.build_postgres_config(postgres_args(), {"DBPROFILER_POSTGRES_URL": URL})
        self.assertEqual(cfg.psql_path, "psql")
        self.assertEqual(cfg.pg_dump_path, "pg_dump")
        self.assertEqual(cfg.timeout, dbprofiler.DEFAULT_TIMEOUT_SECONDS)
        self.assertEqual(cfg.schema_include, ())
        self.assertEqual(cfg.schema_exclude, ())


class TestCredentialRedaction(unittest.TestCase):
    def test_password_never_appears_in_repr_or_str(self):
        cfg = dbprofiler.build_postgres_config(postgres_args(), {"DBPROFILER_POSTGRES_URL": URL})
        for rendering in (repr(cfg), str(cfg), f"{cfg}"):
            self.assertNotIn(PASSWORD, rendering)
        self.assertIn(dbprofiler.REDACTED, repr(cfg))

    def test_password_is_still_available_to_child_processes(self):
        cfg = dbprofiler.build_postgres_config(postgres_args(), {"DBPROFILER_POSTGRES_URL": URL})
        self.assertEqual(cfg.env["PGPASSWORD"], PASSWORD)

    def test_redact_env_masks_every_secret_key(self):
        masked = dbprofiler.redact_env({"PGPASSWORD": PASSWORD, "PGHOST": HOST})
        self.assertEqual(masked["PGPASSWORD"], dbprofiler.REDACTED)
        self.assertEqual(masked["PGHOST"], HOST)


class TestServerVersionGate(unittest.TestCase):
    def test_accepts_postgresql_16(self):
        for version_num in (160000, 160002, 169999):
            with self.subTest(version_num=version_num):
                dbprofiler.require_supported_version(version_num)

    def test_rejects_anything_else(self):
        for version_num in (150004, 159999, 170000, 180001):
            with self.subTest(version_num=version_num):
                with self.assertRaises(dbprofiler.UnsupportedServerVersion):
                    dbprofiler.require_supported_version(version_num)

    def test_rejection_message_names_versions_not_connections(self):
        with self.assertRaises(dbprofiler.UnsupportedServerVersion) as raised:
            dbprofiler.require_supported_version(150004)
        message = str(raised.exception)
        self.assertIn("15.4", message)
        self.assertIn("16", message)
        for secret in (HOST, USER, PASSWORD, DATABASE):
            self.assertNotIn(secret, message)

    def test_format_server_version(self):
        self.assertEqual(dbprofiler.format_server_version(160002), "16.2")
        self.assertEqual(dbprofiler.format_server_version(150004), "15.4")
        self.assertEqual(dbprofiler.format_server_version(160000), "16.0")

    def test_the_probe_query_is_declared_as_a_sql_constant(self):
        # It must be a SQL_* constant so --check-safety can see it.
        self.assertIn("server_version_num", dbprofiler.SQL_SERVER_VERSION)
        self.assertIn(
            "SQL_SERVER_VERSION", [name for name, _ in dbprofiler.iter_sql_constants()]
        )


class TestContractTypes(unittest.TestCase):
    CONTRACT = (
        "Profile",
        "Source",
        "Table",
        "Column",
        "Relationship",
        "FanOut",
        "Manifest",
        "Observation",
        "ProfileWarning",
    )

    def test_every_contract_type_exists_and_is_a_frozen_dataclass(self):
        for name in self.CONTRACT:
            with self.subTest(name=name):
                cls = getattr(dbprofiler, name)
                self.assertTrue(dataclasses.is_dataclass(cls))
                self.assertTrue(cls.__dataclass_params__.frozen, f"{name} is not frozen")

    def test_no_untyped_mapping_in_the_contract(self):
        """A dict in the contract is a hole in it -- fields must be declared."""
        for name in self.CONTRACT:
            for field in dataclasses.fields(getattr(dbprofiler, name)):
                with self.subTest(name=name, field=field.name):
                    self.assertNotIn("dict", str(field.type).lower())
                    self.assertNotIn("Any", str(field.type))

    def test_contract_collections_are_immutable_tuples(self):
        """Frozen dataclasses holding lists would still be mutable in practice."""
        for name in self.CONTRACT:
            for field in dataclasses.fields(getattr(dbprofiler, name)):
                with self.subTest(name=name, field=field.name):
                    self.assertNotIn("list[", str(field.type))

    def test_profile_defaults_to_the_current_contract_version(self):
        profile = dbprofiler.Profile(source=self.a_source())
        self.assertEqual(profile.contract_version, dbprofiler.CONTRACT_VERSION)
        self.assertEqual(profile.tables, ())
        self.assertEqual(profile.relationships, ())

    def test_fanout_records_insufficient_statistics_without_a_number(self):
        fan_out = dbprofiler.FanOut(status="insufficient_statistics", basis="composite")
        self.assertIsNone(fan_out.mean)
        self.assertIsNone(fan_out.p99)

    @staticmethod
    def a_source():
        return dbprofiler.Source(
            kind="postgres",
            server_version_num=160002,
            server_version="16.2",
            database=DATABASE,
        )


def a_config(**overrides):
    return dbprofiler.build_postgres_config(
        postgres_args(**overrides), {"DBPROFILER_POSTGRES_URL": URL}
    )


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestSafeEnv(unittest.TestCase):
    def test_libpq_variables_reach_the_child(self):
        env = dbprofiler.safe_env(a_config())
        self.assertEqual(env["PGPASSWORD"], PASSWORD)
        self.assertEqual(env["PGHOST"], HOST)

    def test_our_own_secrets_are_stripped_from_the_child(self):
        """The child has no use for the tokenization key, and a child's
        environment is readable by anything that can see the process."""
        with mock.patch.dict(
            "os.environ",
            {"DBPROFILER_TOKEN_KEY": "example-token-key", "DBPROFILER_POSTGRES_URL": URL},
            clear=True,
        ):
            env = dbprofiler.safe_env(a_config())
        self.assertNotIn("DBPROFILER_TOKEN_KEY", env)
        self.assertNotIn("DBPROFILER_POSTGRES_URL", env)

    def test_inherited_pg_settings_survive_unless_the_url_overrides_them(self):
        with mock.patch.dict("os.environ", {"PGSSLMODE": "verify-full"}, clear=True):
            env = dbprofiler.safe_env(a_config())
        self.assertEqual(env["PGSSLMODE"], "verify-full")
        self.assertEqual(env["PGHOST"], HOST)  # from the URL, which wins

    def test_locale_is_pinned_for_deterministic_output(self):
        with mock.patch.dict("os.environ", {"LC_ALL": "fr_FR.UTF-8"}, clear=True):
            env = dbprofiler.safe_env(a_config())
        self.assertEqual(env["LC_ALL"], "C")


class TestRunPsql(unittest.TestCase):
    def test_argv_is_exactly_the_audited_flag_set(self):
        with mock.patch("subprocess.run", return_value=completed()) as run:
            dbprofiler.run_psql("SELECT 1", a_config())
        self.assertEqual(
            run.call_args.args[0],
            ["psql", "-X", "-w", "--csv", "-t", "-v", "ON_ERROR_STOP=1", "-c", "SELECT 1"],
        )

    def test_no_credential_reaches_argv(self):
        with mock.patch("subprocess.run", return_value=completed()) as run:
            dbprofiler.run_psql("SELECT 1", a_config())
        argv = " ".join(run.call_args.args[0])
        for secret in (PASSWORD, USER, HOST, DATABASE, "postgres://"):
            self.assertNotIn(secret, argv)

    def test_credentials_travel_by_environment(self):
        with mock.patch("subprocess.run", return_value=completed()) as run:
            dbprofiler.run_psql("SELECT 1", a_config())
        self.assertEqual(run.call_args.kwargs["env"]["PGPASSWORD"], PASSWORD)

    def test_never_uses_a_shell(self):
        with mock.patch("subprocess.run", return_value=completed()) as run:
            dbprofiler.run_psql("SELECT 1", a_config())
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_timeout_is_passed_through(self):
        with mock.patch("subprocess.run", return_value=completed()) as run:
            dbprofiler.run_psql("SELECT 1", a_config(timeout=7))
        self.assertEqual(run.call_args.kwargs["timeout"], 7)

    def test_honours_the_psql_path_override(self):
        with mock.patch("subprocess.run", return_value=completed()) as run:
            dbprofiler.run_psql("SELECT 1", a_config(psql_path="/opt/pg16/bin/psql"))
        self.assertEqual(run.call_args.args[0][0], "/opt/pg16/bin/psql")

    def test_csv_output_is_parsed_into_rows(self):
        out = "public,users,10\npublic,orders,20\n"
        with mock.patch("subprocess.run", return_value=completed(stdout=out)):
            rows = dbprofiler.run_psql("SELECT 1", a_config())
        self.assertEqual(rows, [["public", "users", "10"], ["public", "orders", "20"]])

    def test_embedded_commas_and_newlines_survive_csv_parsing(self):
        out = '"a,b","line1\nline2"\n'
        with mock.patch("subprocess.run", return_value=completed(stdout=out)):
            rows = dbprofiler.run_psql("SELECT 1", a_config())
        self.assertEqual(rows, [["a,b", "line1\nline2"]])

    def test_scalar_helper_returns_one_value(self):
        with mock.patch("subprocess.run", return_value=completed(stdout="160002\n")):
            self.assertEqual(dbprofiler.run_psql_scalar("SELECT 1", a_config()), "160002")

    def test_scalar_helper_rejects_an_unexpected_shape(self):
        with mock.patch("subprocess.run", return_value=completed(stdout="")):
            with self.assertRaises(dbprofiler.CommandError):
                dbprofiler.run_psql_scalar("SELECT 1", a_config())

    def test_nonzero_exit_raises_with_redacted_stderr(self):
        stderr = (
            f'psql: error: connection to server at "{HOST}" failed: '
            f'password authentication failed for user "{USER}"'
        )
        with mock.patch("subprocess.run", return_value=completed(returncode=2, stderr=stderr)):
            with self.assertRaises(dbprofiler.CommandError) as raised:
                dbprofiler.run_psql("SELECT 1", a_config())
        message = str(raised.exception)
        self.assertIn("password authentication failed", message)  # still diagnosable
        for secret in (HOST, USER, PASSWORD):
            self.assertNotIn(secret, message)

    def test_missing_executable_is_a_clear_error(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(dbprofiler.CommandError) as raised:
                dbprofiler.run_psql("SELECT 1", a_config(psql_path="psql16"))
        self.assertIn("psql16", str(raised.exception))

    def test_timeout_is_reported_not_swallowed(self):
        with mock.patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="psql", timeout=7)
        ):
            with self.assertRaises(dbprofiler.CommandError) as raised:
                dbprofiler.run_psql("SELECT 1", a_config(timeout=7))
        self.assertIn("timed out", str(raised.exception))

    def test_no_password_prompt(self):
        """Without -w, psql prompts on a missing password and hangs until the
        timeout instead of failing immediately."""
        with mock.patch("subprocess.run", return_value=completed()) as run:
            dbprofiler.run_psql("SELECT 1", a_config())
        self.assertIn("-w", run.call_args.args[0])


class TestRunPgDump(unittest.TestCase):
    def test_extra_arguments_follow_the_audited_prefix(self):
        with mock.patch("subprocess.run", return_value=completed(stdout="-- schema\n")) as run:
            out = dbprofiler.run_pg_dump(["--schema-only", "--no-owner"], a_config())
        self.assertEqual(
            run.call_args.args[0], ["pg_dump", "-w", "--schema-only", "--no-owner"]
        )
        self.assertEqual(out, "-- schema\n")

    def test_no_credential_reaches_argv(self):
        with mock.patch("subprocess.run", return_value=completed()) as run:
            dbprofiler.run_pg_dump(["--schema-only"], a_config())
        argv = " ".join(run.call_args.args[0])
        for secret in (PASSWORD, USER, HOST, DATABASE):
            self.assertNotIn(secret, argv)


class TestRedactError(unittest.TestCase):
    ENV = {"PGHOST": HOST, "PGUSER": USER, "PGPASSWORD": PASSWORD, "PGDATABASE": DATABASE}

    def test_connection_urls_are_scrubbed(self):
        text = f"could not connect using {URL} -- retrying"
        redacted = dbprofiler.redact_error(text, {})
        self.assertNotIn(PASSWORD, redacted)
        self.assertNotIn(HOST, redacted)
        self.assertIn(dbprofiler.REDACTED, redacted)

    def test_password_assignments_are_scrubbed(self):
        # Empty env, so only the pattern can be doing the work here.
        for text in (
            f"password={PASSWORD} rejected",
            f"PGPASSWORD={PASSWORD}",
            f"password = {PASSWORD}",
        ):
            with self.subTest(text=text):
                self.assertNotIn(PASSWORD, dbprofiler.redact_error(text, {}))

    def test_libpq_values_are_scrubbed_wherever_they_appear(self):
        text = f'host "{HOST}" user "{USER}" database "{DATABASE}" password {PASSWORD}'
        redacted = dbprofiler.redact_error(text, self.ENV)
        for secret in (HOST, USER, DATABASE, PASSWORD):
            self.assertNotIn(secret, redacted)

    def test_a_short_password_is_still_scrubbed(self):
        redacted = dbprofiler.redact_error("the password is x", {"PGPASSWORD": "x"})
        self.assertNotIn("password is x", redacted)

    def test_short_nonsecret_values_do_not_shred_the_message(self):
        """Blindly replacing a 2-character username would destroy the text."""
        redacted = dbprofiler.redact_error(
            "could not connect to the server", {"PGUSER": "ab"}
        )
        self.assertEqual(redacted, "could not connect to the server")

    def test_the_port_is_not_scrubbed(self):
        redacted = dbprofiler.redact_error("connection to port 5433 refused", {"PGPORT": "5433"})
        self.assertIn("5433", redacted)

    def test_empty_input_is_handled(self):
        self.assertEqual(dbprofiler.redact_error("", self.ENV), "")
        self.assertEqual(dbprofiler.redact_error(None, self.ENV), "")


class TestRelationAllowlist(unittest.TestCase):
    def plant(self, sql):
        stderr = io.StringIO()
        with mock.patch.object(dbprofiler, "SQL_PLANTED", sql, create=True):
            with contextlib.redirect_stderr(stderr):
                status = dbprofiler.check_safety()
        return status, stderr.getvalue()

    def test_allowed_relations_pass(self):
        status, _ = self.plant(
            "SELECT c.relname FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
        )
        self.assertEqual(status, 0)

    def test_a_user_table_is_rejected(self):
        status, output = self.plant("SELECT id FROM public.users")
        self.assertEqual(status, 1)
        self.assertIn("users", output)

    def test_an_unqualified_user_table_is_rejected(self):
        status, output = self.plant("SELECT id FROM orders")
        self.assertEqual(status, 1)
        self.assertIn("orders", output)

    def test_catalog_relations_holding_secrets_are_rejected(self):
        """pg_catalog is not a safe blanket allowlist. These live in it."""
        for relation in (
            "pg_authid",  # role password hashes
            "pg_shadow",  # role password hashes
            "pg_largeobject",  # user data
            "pg_statistic",  # raw stat values, not permission-filtered like pg_stats
            "pg_subscription",  # subconninfo carries a password
            "pg_user_mapping",  # umoptions can carry a password
        ):
            with self.subTest(relation=relation):
                status, output = self.plant(f"SELECT * FROM pg_catalog.{relation}")
                self.assertEqual(status, 1)
                self.assertIn(relation, output)

    def test_a_non_catalog_schema_is_rejected_even_for_an_allowed_name(self):
        status, _ = self.plant("SELECT * FROM evil.pg_class")
        self.assertEqual(status, 1)

    def test_set_returning_functions_are_checked_against_their_own_allowlist(self):
        allowed, _ = self.plant("SELECT x FROM unnest(ARRAY[1,2]) AS x")
        self.assertEqual(allowed, 0)
        denied, output = self.plant("SELECT * FROM pg_read_file('/etc/passwd')")
        self.assertEqual(denied, 1)
        self.assertIn("pg_read_file", output)

    def test_subqueries_and_lateral_do_not_confuse_the_scanner(self):
        status, output = self.plant(
            "SELECT * FROM (SELECT oid FROM pg_catalog.pg_class) s "
            "JOIN LATERAL unnest(ARRAY[1]) AS u ON true"
        )
        self.assertEqual(status, 0, output)

    def test_every_shipped_sql_constant_passes_the_allowlist(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(dbprofiler.check_safety(), 0)


class TestSubprocessAudit(unittest.TestCase):
    def test_the_shipped_source_passes(self):
        self.assertEqual(dbprofiler.audit_subprocess_usage(dbprofiler.own_source()), [])

    def test_a_shell_invocation_is_rejected(self):
        source = "import subprocess\ndef f(env):\n    subprocess.run('ls', shell=True, env=env)\n"
        violations = dbprofiler.audit_subprocess_usage(source)
        self.assertTrue(any("shell" in v for v in violations), violations)

    def test_a_subprocess_call_without_an_environment_is_rejected(self):
        source = "import subprocess\ndef f():\n    subprocess.run(['psql'])\n"
        violations = dbprofiler.audit_subprocess_usage(source)
        self.assertTrue(any("env=" in v for v in violations), violations)

    def test_more_than_one_call_site_is_rejected(self):
        """One choke point is what makes the credential handling auditable."""
        source = (
            "import subprocess\n"
            "def a(env):\n    subprocess.run(['psql'], env=env)\n"
            "def b(env):\n    subprocess.run(['pg_dump'], env=env)\n"
        )
        violations = dbprofiler.audit_subprocess_usage(source)
        self.assertTrue(any("call site" in v for v in violations), violations)

    def test_a_credentialed_url_literal_in_the_source_is_rejected(self):
        source = "URL = 'postgres://example-user:example-password@db.invalid/example-db'\n"
        violations = dbprofiler.audit_subprocess_usage(source)
        self.assertTrue(any("connection URL" in v for v in violations), violations)

    def test_a_placeholder_url_without_credentials_is_allowed(self):
        source = "DOC = 'postgres://...'\n"
        self.assertEqual(dbprofiler.audit_subprocess_usage(source), [])

    def test_check_safety_reports_source_audit_failures(self):
        stderr = io.StringIO()
        planted = "import subprocess\nsubprocess.run(['x'])\n"
        with mock.patch.object(dbprofiler, "own_source", lambda: planted):
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(dbprofiler.check_safety(), 1)
        self.assertIn("env=", stderr.getvalue())


class TestProbeServerVersion(unittest.TestCase):
    def test_probe_uses_the_declared_constant_and_returns_an_int(self):
        with mock.patch("subprocess.run", return_value=completed(stdout="160002\n")) as run:
            self.assertEqual(dbprofiler.probe_server_version(a_config()), 160002)
        self.assertIn(dbprofiler.SQL_SERVER_VERSION, run.call_args.args[0])

    def test_probe_rejects_an_unsupported_major(self):
        with mock.patch("subprocess.run", return_value=completed(stdout="150004\n")):
            with self.assertRaises(dbprofiler.UnsupportedServerVersion):
                dbprofiler.probe_server_version(a_config())

    def test_probe_rejects_unparseable_output(self):
        with mock.patch("subprocess.run", return_value=completed(stdout="not-a-number\n")):
            with self.assertRaises(dbprofiler.CommandError):
                dbprofiler.probe_server_version(a_config())


class TestPgDumpVersion(unittest.TestCase):
    def test_version_is_probed_without_connecting(self):
        """--version must be argv[1] and nothing may follow it.

        pg_dump handles --version by inspecting argv[1] directly, before getopt
        runs, and its option table has no entry for it. Anything ahead of it --
        even a harmless -w -- sends it down the getopt path, where it is an
        unrecognized option and the process exits 1 with only a "try --help"
        hint. Real pg_dump 16.15 does this; a mock that matches on
        `"--version" in argv` does not.
        """
        with mock.patch(
            "subprocess.run", return_value=completed(stdout="pg_dump (PostgreSQL) 16.2\n")
        ) as run:
            self.assertEqual(dbprofiler.probe_pg_dump_major(a_config()), 16)
        self.assertEqual(run.call_args.args[0], ["pg_dump", "--version"])

    def test_version_parsing_tolerates_packager_suffixes(self):
        for text, expected in (
            ("pg_dump (PostgreSQL) 16.2\n", 16),
            ("pg_dump (PostgreSQL) 16.2 (Ubuntu 16.2-1.pgdg22.04+1)\n", 16),
            ("pg_dump (PostgreSQL) 17.0\n", 17),
            ("pg_dump (PostgreSQL) 16beta1\n", 16),
        ):
            with self.subTest(text=text):
                with mock.patch("subprocess.run", return_value=completed(stdout=text)):
                    self.assertEqual(dbprofiler.probe_pg_dump_major(a_config()), expected)

    def test_unparseable_version_is_an_error(self):
        with mock.patch("subprocess.run", return_value=completed(stdout="not a version\n")):
            with self.assertRaises(dbprofiler.CommandError):
                dbprofiler.probe_pg_dump_major(a_config())

    def test_a_pg_dump_older_than_the_server_is_rejected(self):
        """An older pg_dump cannot represent newer server syntax, and says so only
        by emitting a subtly wrong dump."""
        with self.assertRaises(dbprofiler.UnsupportedClientVersion):
            dbprofiler.require_compatible_pg_dump(15, 160002)

    def test_a_matching_or_newer_pg_dump_is_accepted(self):
        for major in (16, 17):
            with self.subTest(major=major):
                dbprofiler.require_compatible_pg_dump(major, 160002)

    def test_the_rejection_names_both_versions(self):
        with self.assertRaises(dbprofiler.UnsupportedClientVersion) as raised:
            dbprofiler.require_compatible_pg_dump(15, 160002)
        message = str(raised.exception)
        self.assertIn("15", message)
        self.assertIn("16", message)


class TestPgDumpArgs(unittest.TestCase):
    def test_the_required_flags_are_present(self):
        args = dbprofiler.build_pg_dump_args(a_config())
        for flag in ("--schema-only", "--no-owner", "--no-privileges"):
            self.assertIn(flag, args)

    def test_schema_include_becomes_dash_n(self):
        args = dbprofiler.build_pg_dump_args(a_config(schema_include=["public", "sales"]))
        self.assertEqual(args.count("-n"), 2)
        self.assertIn("public", args)
        self.assertIn("sales", args)

    def test_schema_exclude_becomes_dash_capital_n(self):
        args = dbprofiler.build_pg_dump_args(a_config(schema_exclude=["archive"]))
        self.assertIn("-N", args)
        self.assertIn("archive", args)
        self.assertNotIn("-n", args)

    def test_no_credential_reaches_the_command_line(self):
        config = a_config(schema_include=["public"])
        argv = [
            config.pg_dump_path,
            *dbprofiler.PG_DUMP_ARGS,
            *dbprofiler.build_pg_dump_args(config),
        ]
        joined = " ".join(argv)
        for secret in (URL, HOST, USER, PASSWORD, DATABASE):
            self.assertNotIn(secret, joined)

    def test_the_pg_dump_path_override_is_honoured(self):
        config = a_config(pg_dump_path="/opt/pg16/bin/pg_dump")
        with mock.patch("subprocess.run", return_value=completed(stdout="-- dump\n")) as run:
            dbprofiler.run_pg_dump(dbprofiler.build_pg_dump_args(config), config)
        self.assertEqual(run.call_args.args[0][0], "/opt/pg16/bin/pg_dump")


class TestSchemaFilterValidation(unittest.TestCase):
    def test_system_schemas_are_rejected_in_schema_include(self):
        # Dumping a system schema is never what the operator meant, and
        # pg_temp_* would make the bundle depend on a live session.
        for name in ("pg_catalog", "information_schema", "pg_toast", "pg_temp_1"):
            with self.subTest(name=name), self.assertRaises(dbprofiler.ConfigError):
                dbprofiler.build_postgres_config(
                    postgres_args(schema_include=[name]), {"DBPROFILER_POSTGRES_URL": URL}
                )

    def test_the_rejection_names_the_offending_schema(self):
        with self.assertRaises(dbprofiler.ConfigError) as raised:
            dbprofiler.build_postgres_config(
                postgres_args(schema_include=["pg_catalog"]), {"DBPROFILER_POSTGRES_URL": URL}
            )
        self.assertIn("pg_catalog", str(raised.exception))

    def test_a_user_schema_named_like_a_system_one_is_still_rejected(self):
        # PostgreSQL reserves the pg_ prefix, so this cannot be a real user schema.
        with self.assertRaises(dbprofiler.ConfigError):
            dbprofiler.build_postgres_config(
                postgres_args(schema_include=["pg_myschema"]), {"DBPROFILER_POSTGRES_URL": URL}
            )

    def test_ordinary_schemas_are_accepted(self):
        config = dbprofiler.build_postgres_config(
            postgres_args(schema_include=["public", "sales"]),
            {"DBPROFILER_POSTGRES_URL": URL},
        )
        self.assertEqual(config.schema_include, ("public", "sales"))


class TestSchemaFingerprint(unittest.TestCase):
    ROWS = "public,users,r\npublic,orders,r\nsales,invoices,v\n"

    def fingerprint(self, rows):
        with mock.patch("subprocess.run", return_value=completed(stdout=rows)):
            return dbprofiler.schema_fingerprint(a_config())

    def test_the_fingerprint_query_is_a_declared_constant(self):
        with mock.patch("subprocess.run", return_value=completed(stdout=self.ROWS)) as run:
            dbprofiler.schema_fingerprint(a_config())
        self.assertIn(dbprofiler.SQL_SCHEMA_FINGERPRINT, run.call_args.args[0])

    def test_the_fingerprint_is_hex_sha256(self):
        digest = self.fingerprint(self.ROWS)
        self.assertEqual(len(digest), 64)
        int(digest, 16)  # raises if it is not hex

    def test_the_fingerprint_is_deterministic(self):
        self.assertEqual(self.fingerprint(self.ROWS), self.fingerprint(self.ROWS))

    def test_row_order_does_not_change_the_fingerprint(self):
        """psql makes no ordering promise, so drift detection must not depend on it."""
        shuffled = "sales,invoices,v\npublic,users,r\npublic,orders,r\n"
        self.assertEqual(self.fingerprint(self.ROWS), self.fingerprint(shuffled))

    def test_a_changed_relkind_changes_the_fingerprint(self):
        changed = "public,users,r\npublic,orders,v\nsales,invoices,v\n"
        self.assertNotEqual(self.fingerprint(self.ROWS), self.fingerprint(changed))

    def test_a_dropped_relation_changes_the_fingerprint(self):
        dropped = "public,users,r\nsales,invoices,v\n"
        self.assertNotEqual(self.fingerprint(self.ROWS), self.fingerprint(dropped))

    def test_a_field_boundary_cannot_be_forged(self):
        """Concatenating fields without a delimiter would make these two collide."""
        a = "public,ab,r\n"
        b = "publica,b,r\n"
        self.assertNotEqual(self.fingerprint(a), self.fingerprint(b))

    def test_an_empty_schema_still_fingerprints(self):
        self.assertEqual(len(self.fingerprint("")), 64)

    def test_the_fingerprint_query_passes_the_safety_audit(self):
        self.assertEqual(dbprofiler.audit_sql(dbprofiler.SQL_SCHEMA_FINGERPRINT), [])

    def test_out_of_scope_schemas_do_not_affect_the_fingerprint(self):
        """A schema the operator excluded must not be able to abort the run by
        changing underneath it."""
        with mock.patch("subprocess.run", return_value=completed(stdout=self.ROWS)):
            included = dbprofiler.schema_fingerprint(a_config(schema_include=["public"]))
        churned = self.ROWS.replace("sales,invoices,v", "sales,invoices,r")
        with mock.patch("subprocess.run", return_value=completed(stdout=churned)):
            after = dbprofiler.schema_fingerprint(a_config(schema_include=["public"]))
        self.assertEqual(included, after)

    def test_an_excluded_schema_is_dropped_from_the_fingerprint(self):
        with mock.patch("subprocess.run", return_value=completed(stdout=self.ROWS)):
            excluded = dbprofiler.schema_fingerprint(a_config(schema_exclude=["sales"]))
        self.assertNotEqual(excluded, self.fingerprint(self.ROWS))

    def test_in_scope_change_is_still_detected_under_a_filter(self):
        with mock.patch("subprocess.run", return_value=completed(stdout=self.ROWS)):
            before = dbprofiler.schema_fingerprint(a_config(schema_include=["public"]))
        churned = self.ROWS.replace("public,orders,r", "public,orders,v")
        with mock.patch("subprocess.run", return_value=completed(stdout=churned)):
            after = dbprofiler.schema_fingerprint(a_config(schema_include=["public"]))
        self.assertNotEqual(before, after)


class TestCollectSchema(unittest.TestCase):
    VERSION = "pg_dump (PostgreSQL) 16.2\n"
    ROWS = "public,users,r\n"
    DUMP = "--\n-- PostgreSQL database dump\n--\nCREATE TABLE public.users (id bigint);\n"

    def calls(self, **overrides):
        return [
            completed(stdout=overrides.get("version", self.VERSION)),
            completed(stdout=overrides.get("rows", self.ROWS)),
            completed(stdout=overrides.get("dump", self.DUMP)),
        ]

    def test_returns_the_ddl_and_a_fingerprint(self):
        with mock.patch("subprocess.run", side_effect=self.calls()):
            schema_sql, digest = dbprofiler.collect_schema(a_config(), 160002)
        self.assertIn("CREATE TABLE", schema_sql)
        self.assertEqual(len(digest), 64)

    def test_the_client_is_checked_before_anything_is_dumped(self):
        """A too-old pg_dump must fail before it writes a subtly wrong dump."""
        calls = self.calls(version="pg_dump (PostgreSQL) 15.6\n")
        with mock.patch("subprocess.run", side_effect=calls) as run:
            with self.assertRaises(dbprofiler.UnsupportedClientVersion):
                dbprofiler.collect_schema(a_config(), 160002)
        self.assertEqual(run.call_count, 1)

    def test_the_fingerprint_is_taken_before_the_dump(self):
        # The after-collection recheck then covers drift during the dump itself.
        with mock.patch("subprocess.run", side_effect=self.calls()) as run:
            dbprofiler.collect_schema(a_config(), 160002)
        argvs = [call.args[0] for call in run.call_args_list]
        self.assertEqual(argvs[0], ["pg_dump", "--version"])
        self.assertIn(dbprofiler.SQL_SCHEMA_FINGERPRINT, argvs[1])
        self.assertIn("--schema-only", argvs[2])

    def test_the_dump_is_returned_as_a_string_not_written_to_disk(self):
        with mock.patch("subprocess.run", side_effect=self.calls()):
            schema_sql, _ = dbprofiler.collect_schema(a_config(), 160002)
        self.assertIsInstance(schema_sql, str)

    def test_a_failing_dump_raises_with_redacted_stderr(self):
        calls = [
            completed(stdout=self.VERSION),
            completed(stdout=self.ROWS),
            completed(returncode=1, stderr=f'pg_dump: error: connection to "{HOST}" failed'),
        ]
        with mock.patch("subprocess.run", side_effect=calls):
            with self.assertRaises(dbprofiler.CommandError) as raised:
                dbprofiler.collect_schema(a_config(), 160002)
        self.assertNotIn(HOST, str(raised.exception))

    def test_schema_filters_reach_the_dump_command(self):
        with mock.patch("subprocess.run", side_effect=self.calls()) as run:
            dbprofiler.collect_schema(a_config(schema_include=["sales"]), 160002)
        dump_argv = run.call_args_list[2].args[0]
        self.assertIn("-n", dump_argv)
        self.assertIn("sales", dump_argv)


GOLDEN = Path(__file__).parent / "testdata" / "golden"


def golden(name):
    """Read a recorded psql --csv -t fixture."""
    return (GOLDEN / f"{name}.csv").read_text(encoding="utf-8")


# The order collect_catalog issues its queries in. Tables and inheritance come
# first so an unsupported layout fails before anything else is read.
CATALOG_FIXTURES = (
    "tables",
    "inherited",
    "columns",
    "column_stats",
    "extended_stats",
    "foreign_keys",
    "indexes",
)


def catalog_calls(**overrides):
    """A subprocess.run side_effect list covering one collect_catalog() run."""
    return [
        completed(stdout=overrides.get(name, golden(name))) for name in CATALOG_FIXTURES
    ]


class TestCatalogSql(unittest.TestCase):
    def test_every_catalog_query_passes_the_safety_audit(self):
        for name, sql in dbprofiler.iter_sql_constants():
            with self.subTest(name=name):
                self.assertEqual(dbprofiler.audit_sql(sql), [])

    def test_the_collectors_declare_their_sql_as_constants(self):
        for name in (
            "SQL_TABLES",
            "SQL_COLUMNS",
            "SQL_COLUMN_STATS",
            "SQL_EXTENDED_STATS",
            "SQL_FOREIGN_KEYS",
            "SQL_INDEXES",
            "SQL_INHERITED",
        ):
            with self.subTest(name=name):
                self.assertIsInstance(getattr(dbprofiler, name), str)

    def test_pg_inherits_is_on_the_allowlist(self):
        # Added in the same change as the collector that reads it.
        self.assertIn("pg_inherits", dbprofiler.ALLOWED_RELATIONS)

    def test_no_catalog_query_counts_rows(self):
        for name, sql in dbprofiler.iter_sql_constants():
            with self.subTest(name=name):
                self.assertNotIn("count(", sql.lower())


class TestCollectCatalog(unittest.TestCase):
    def collect(self, **overrides):
        with mock.patch("subprocess.run", side_effect=catalog_calls(**overrides)):
            return dbprofiler.collect_catalog(a_config())

    def test_tables_carry_estimates_never_counts(self):
        catalog = self.collect()
        users = next(t for t in catalog.tables if t.name == "users")
        self.assertEqual(users.schema, "public")
        self.assertEqual(users.reltuples, 1000.0)
        self.assertEqual(users.size_bytes, 163840)

    def test_all_three_tables_are_collected(self):
        catalog = self.collect()
        self.assertEqual(
            sorted((t.schema, t.name) for t in catalog.tables),
            [("public", "orders"), ("public", "users"), ("sales", "invoices")],
        )

    def test_columns_carry_ordinal_type_and_nullability(self):
        catalog = self.collect()
        email = next(c for c in catalog.columns if c.name == "email")
        self.assertEqual(email.ordinal, 2)
        self.assertEqual(email.data_type, "text")
        self.assertTrue(email.is_nullable)
        ident = next(c for c in catalog.columns if c.table == "users" and c.name == "id")
        self.assertFalse(ident.is_nullable)

    def test_supported_and_unsupported_types_are_classified(self):
        catalog = self.collect()
        by_name = {(c.table, c.name): c for c in catalog.columns}
        self.assertTrue(by_name[("users", "id")].is_supported)
        self.assertTrue(by_name[("users", "profile")].is_supported)  # jsonb
        self.assertTrue(by_name[("users", "tags")].is_supported)  # text[]
        self.assertTrue(by_name[("invoices", "region")].is_supported)  # enum
        self.assertFalse(by_name[("users", "legacy_balance")].is_supported)  # money

    def test_column_statistics_are_kept_separate_from_columns(self):
        """Statistics carry raw values. They stay in their own records so the
        tokenization step in task 7 has one place to look."""
        catalog = self.collect()
        stat = next(
            s for s in catalog.column_stats if s.table == "orders" and s.column == "user_id"
        )
        self.assertEqual(stat.null_frac, 0.0)
        self.assertEqual(stat.avg_width, 8)
        self.assertEqual(stat.n_distinct, 500.0)
        self.assertEqual(stat.most_common_vals, ("1", "2", "3"))
        self.assertEqual(stat.most_common_freqs, (0.1, 0.05, 0.02))

    def test_a_negative_n_distinct_is_carried_through_unresolved(self):
        # PostgreSQL encodes "fraction of rows" as a negative. Resolving it needs
        # the row count, which is normalization's job, not collection's.
        catalog = self.collect()
        stat = next(s for s in catalog.column_stats if s.table == "users" and s.column == "id")
        self.assertEqual(stat.n_distinct, -1.0)

    def test_histogram_bounds_are_parsed_into_a_tuple(self):
        catalog = self.collect()
        stat = next(s for s in catalog.column_stats if s.table == "users" and s.column == "id")
        self.assertEqual(stat.histogram_bounds, ("1", "250", "500", "750", "1000"))

    def test_absent_statistics_are_empty_not_none(self):
        catalog = self.collect()
        stat = next(s for s in catalog.column_stats if s.table == "users" and s.column == "id")
        self.assertEqual(stat.most_common_vals, ())
        self.assertEqual(stat.most_common_freqs, ())

    def test_foreign_key_columns_keep_declaration_order(self):
        catalog = self.collect()
        fk = next(f for f in catalog.foreign_keys if f.constraint_name == "orders_user_id_fkey")
        self.assertEqual(fk.child_schema, "public")
        self.assertEqual(fk.child_table, "orders")
        self.assertEqual(fk.child_columns, ("user_id",))
        self.assertEqual(fk.parent_table, "users")
        self.assertEqual(fk.parent_columns, ("id",))

    def test_referential_actions_are_decoded_from_their_catalog_codes(self):
        catalog = self.collect()
        fk = next(f for f in catalog.foreign_keys if f.constraint_name == "orders_user_id_fkey")
        self.assertEqual(fk.on_update, "NO ACTION")
        self.assertEqual(fk.on_delete, "CASCADE")

    def test_a_composite_foreign_key_is_assembled_from_its_rows(self):
        rows = (
            "orders_composite_fkey,public,orders,public,users,tenant_id,tenant_id,1,a,a\n"
            "orders_composite_fkey,public,orders,public,users,user_id,id,2,a,a\n"
        )
        catalog = self.collect(foreign_keys=rows)
        fk = catalog.foreign_keys[0]
        self.assertEqual(fk.child_columns, ("tenant_id", "user_id"))
        self.assertEqual(fk.parent_columns, ("tenant_id", "id"))

    def test_composite_key_column_order_follows_the_ordinal_not_the_row_order(self):
        rows = (
            "orders_composite_fkey,public,orders,public,users,user_id,id,2,a,a\n"
            "orders_composite_fkey,public,orders,public,users,tenant_id,tenant_id,1,a,a\n"
        )
        catalog = self.collect(foreign_keys=rows)
        self.assertEqual(catalog.foreign_keys[0].child_columns, ("tenant_id", "user_id"))

    def test_extended_statistics_are_collected_with_their_column_set(self):
        catalog = self.collect()
        ext = catalog.extended_stats[0]
        self.assertEqual(ext.table, "orders")
        self.assertEqual(ext.columns, ("user_id", "placed_at"))
        self.assertEqual(ext.n_distinct, {("user_id", "placed_at"): 4200.0})

    def test_extended_mcv_presence_is_recorded_but_values_are_not(self):
        """Extended MCV values are raw customer data. Only their existence is
        useful for planning, so only their existence is read."""
        catalog = self.collect()
        self.assertTrue(catalog.extended_stats[0].has_most_common_values)
        self.assertNotIn("most_common_vals", dbprofiler.SQL_EXTENDED_STATS.split("FROM")[0])

    def test_indexes_are_collected_with_uniqueness_and_primary_flags(self):
        catalog = self.collect()
        pkey = next(i for i in catalog.indexes if i.name == "users_pkey")
        self.assertTrue(pkey.is_unique)
        self.assertTrue(pkey.is_primary)
        plain = next(i for i in catalog.indexes if i.name == "orders_user_id_idx")
        self.assertFalse(plain.is_unique)

    def test_the_query_order_puts_the_layout_check_first(self):
        with mock.patch("subprocess.run", side_effect=catalog_calls()) as run:
            dbprofiler.collect_catalog(a_config())
        issued = [call.args[0][-1] for call in run.call_args_list]
        self.assertEqual(issued[0], dbprofiler.SQL_TABLES)
        self.assertEqual(issued[1], dbprofiler.SQL_INHERITED)

    def test_scope_filters_apply_to_every_collected_relation(self):
        with mock.patch("subprocess.run", side_effect=catalog_calls()):
            catalog = dbprofiler.collect_catalog(a_config(schema_include=["public"]))
        self.assertNotIn("sales", {t.schema for t in catalog.tables})
        self.assertNotIn("sales", {c.schema for c in catalog.columns})
        self.assertNotIn("sales", {f.child_schema for f in catalog.foreign_keys})
        self.assertNotIn("sales", {i.schema for i in catalog.indexes})


class TestUnsupportedLayouts(unittest.TestCase):
    """Partitioning and inheritance change row-count and fan-out arithmetic in
    ways the MVP does not model. Failing loudly beats publishing a wrong number."""

    def test_a_partitioned_table_is_rejected(self):
        rows = "public,events,p,0,0\n"
        with mock.patch("subprocess.run", side_effect=catalog_calls(tables=rows)):
            with self.assertRaises(dbprofiler.UnsupportedObject) as raised:
                dbprofiler.collect_catalog(a_config())
        self.assertIn("events", str(raised.exception))

    def test_a_partitioned_index_relkind_is_rejected(self):
        rows = "public,events,I,0,0\n"
        with mock.patch("subprocess.run", side_effect=catalog_calls(tables=rows)):
            with self.assertRaises(dbprofiler.UnsupportedObject):
                dbprofiler.collect_catalog(a_config())

    def test_an_inheritance_child_is_rejected(self):
        with mock.patch(
            "subprocess.run", side_effect=catalog_calls(inherited="public,users_2026,\n")
        ):
            with self.assertRaises(dbprofiler.UnsupportedObject) as raised:
                dbprofiler.collect_catalog(a_config())
        self.assertIn("users_2026", str(raised.exception))

    def test_the_check_happens_before_the_remaining_queries_run(self):
        rows = "public,events,p,0,0\n"
        calls = catalog_calls(tables=rows)
        with mock.patch("subprocess.run", side_effect=calls) as run:
            with self.assertRaises(dbprofiler.UnsupportedObject):
                dbprofiler.collect_catalog(a_config())
        self.assertEqual(run.call_count, 2)

    def test_an_out_of_scope_partitioned_table_does_not_fail_the_run(self):
        rows = golden("tables") + "archive,events,p,0,0\n"
        with mock.patch("subprocess.run", side_effect=catalog_calls(tables=rows)):
            catalog = dbprofiler.collect_catalog(a_config(schema_exclude=["archive"]))
        self.assertEqual(len(catalog.tables), 3)


class TestSupportedTypes(unittest.TestCase):
    def test_core_scalar_types_are_supported(self):
        for typname in ("int8", "text", "numeric", "timestamptz", "uuid", "bool", "jsonb"):
            with self.subTest(typname=typname):
                self.assertTrue(dbprofiler.is_supported_type(typname, "b", "N"))

    def test_types_without_a_cockroachdb_equivalent_are_not(self):
        for typname in ("money", "xml", "tsvector", "macaddr", "cidr", "point"):
            with self.subTest(typname=typname):
                self.assertFalse(dbprofiler.is_supported_type(typname, "b", "N"))

    def test_an_array_is_supported_when_its_element_type_is(self):
        self.assertTrue(dbprofiler.is_supported_type("_text", "b", "A"))
        self.assertFalse(dbprofiler.is_supported_type("_money", "b", "A"))

    def test_enums_are_supported(self):
        self.assertTrue(dbprofiler.is_supported_type("region_code", "e", "E"))

    def test_composite_domain_and_range_types_are_not(self):
        for typtype in ("c", "d", "r", "m"):
            with self.subTest(typtype=typtype):
                self.assertFalse(dbprofiler.is_supported_type("custom", typtype, "U"))

    def test_an_unknown_type_defaults_to_unsupported(self):
        """A migration planner is better served by a false negative than by a
        silent claim of compatibility."""
        self.assertFalse(dbprofiler.is_supported_type("some_extension_type", "b", "U"))


# The order collect_workload issues its queries in. The extension probe comes
# first so a database without pg_stat_statements costs one query, not three.
WORKLOAD_FIXTURES = (
    "table_activity",
    "index_activity",
    "statements_installed",
    "statements_reset",
    "statements",
)


def workload_calls(**overrides):
    """A subprocess.run side_effect list covering one collect_workload() run."""
    calls = []
    for name in WORKLOAD_FIXTURES:
        value = overrides.get(name, golden(name))
        # A str override supplies stdout; anything else is a CompletedProcess
        # standing in for a failure.
        calls.append(completed(stdout=value) if isinstance(value, str) else value)
    return calls


def denied(relation):
    """What psql does when the role cannot read a statistics view."""
    return completed(returncode=1, stderr=f'ERROR:  permission denied for view {relation}\n')


class TestWorkloadSql(unittest.TestCase):
    def test_the_workload_collectors_declare_their_sql_as_constants(self):
        for name in (
            "SQL_TABLE_ACTIVITY",
            "SQL_INDEX_ACTIVITY",
            "SQL_STATEMENTS",
            "SQL_STATEMENTS_RESET",
            "SQL_STATEMENTS_INSTALLED",
        ):
            with self.subTest(name=name):
                self.assertIsInstance(getattr(dbprofiler, name), str)

    def test_every_workload_query_passes_the_safety_audit(self):
        for name, sql in dbprofiler.iter_sql_constants():
            with self.subTest(name=name):
                self.assertEqual(dbprofiler.audit_sql(sql), [])

    def test_the_new_relations_are_on_the_allowlist(self):
        # Allowlisted in the same change as the collectors that read them.
        for relation in ("pg_stat_user_tables", "pg_stat_user_indexes",
                         "pg_stat_statements", "pg_stat_statements_info",
                         "pg_extension", "pg_database"):
            with self.subTest(relation=relation):
                self.assertIn(relation, dbprofiler.ALLOWED_RELATIONS)

    def test_the_statement_query_bounds_what_it_transfers(self):
        # Unbounded, this reads every entry in a shared-memory hash that can hold
        # tens of thousands. The cap belongs in SQL, not in Python.
        self.assertIn("200", dbprofiler.SQL_STATEMENTS)

    def test_the_statement_query_is_scoped_to_the_profiled_database(self):
        # pg_stat_statements is cluster-wide. Without this filter the profile
        # would describe a workload that never touched the target database.
        self.assertIn("current_database()", dbprofiler.SQL_STATEMENTS)


class TestForbiddenTokenMatching(unittest.TestCase):
    """ANALYZE is forbidden as a statement, not as a substring.

    pg_stat_user_tables exposes last_analyze, analyze_count, autoanalyze_count
    and n_mod_since_analyze. A substring match would make those columns
    unreadable, and the workaround -- dropping them -- would cost real signal
    about whether the source statistics are stale.
    """

    def test_an_analyze_statement_is_still_rejected(self):
        for sql in ("ANALYZE public.users", "VACUUM ANALYZE", "analyze;", "ANALYZE (VERBOSE) t"):
            with self.subTest(sql=sql):
                self.assertTrue(any("ANALYZE" in v for v in dbprofiler.audit_sql(sql)))

    def test_a_column_name_ending_in_analyze_is_allowed(self):
        sql = (
            "SELECT s.last_analyze, s.analyze_count, s.autoanalyze_count, "
            "s.n_mod_since_analyze FROM pg_catalog.pg_stat_user_tables s"
        )
        self.assertEqual(dbprofiler.audit_sql(sql), [])

    def test_count_is_still_rejected_however_it_is_spaced(self):
        for sql in ("SELECT count(*) FROM pg_catalog.pg_class",
                    "SELECT COUNT (*) FROM pg_catalog.pg_class",
                    "SELECT pg_catalog.count(*) FROM pg_catalog.pg_class"):
            with self.subTest(sql=sql):
                self.assertTrue(any("COUNT(" in v for v in dbprofiler.audit_sql(sql)))

    def test_a_word_ending_in_count_is_not_a_row_count(self):
        self.assertEqual(
            dbprofiler.audit_sql("SELECT s.autovacuum_count FROM pg_catalog.pg_stat_user_tables s"),
            [],
        )

    def test_create_statistics_is_still_rejected(self):
        self.assertTrue(dbprofiler.audit_sql("CREATE STATISTICS s ON a, b FROM t"))


class TestCollectWorkload(unittest.TestCase):
    def collect(self, config=None, **overrides):
        with mock.patch("subprocess.run", side_effect=workload_calls(**overrides)):
            return dbprofiler.collect_workload(config or a_config())

    def test_table_activity_carries_the_full_column_set(self):
        workload = self.collect()
        users = next(t for t in workload.table_activity if t.table == "users")
        self.assertEqual(users.schema, "public")
        self.assertEqual(users.seq_scan, 12)
        self.assertEqual(users.idx_scan, 4500)
        self.assertEqual(users.n_live_tup, 1000)
        self.assertEqual(users.n_dead_tup, 40)
        self.assertEqual(users.n_mod_since_analyze, 5)
        self.assertEqual(users.autovacuum_count, 7)
        self.assertEqual(users.last_analyze, "2026-08-20 03:15:00+00")

    def test_a_table_that_has_never_been_vacuumed_reports_no_timestamp(self):
        workload = self.collect()
        invoices = next(t for t in workload.table_activity if t.table == "invoices")
        self.assertEqual(invoices.last_vacuum, "")
        self.assertEqual(invoices.last_autovacuum, "")

    def test_index_activity_carries_scan_counts_and_size(self):
        workload = self.collect()
        idx = next(i for i in workload.index_activity if i.index == "orders_user_id_idx")
        self.assertEqual(idx.schema, "public")
        self.assertEqual(idx.table, "orders")
        self.assertEqual(idx.idx_scan, 38000)
        self.assertEqual(idx.idx_tup_read, 410000)
        self.assertEqual(idx.size_bytes, 901120)

    def test_an_unused_index_is_reported_not_dropped(self):
        # A zero-scan index is the single most actionable thing in this report.
        workload = self.collect(index_activity="public,users,users_unused_idx,0,0,0,8192\n")
        self.assertEqual(len(workload.index_activity), 1)
        self.assertEqual(workload.index_activity[0].idx_scan, 0)

    def test_statements_are_collected_with_their_counters(self):
        workload = self.collect()
        top = workload.statements[0]
        self.assertEqual(top.queryid, "-4123456789012345678")
        self.assertEqual(top.calls, 480000)
        self.assertAlmostEqual(top.total_exec_time, 912345.5)
        self.assertAlmostEqual(top.mean_exec_time, 1.9)
        self.assertEqual(top.rows, 480000)
        self.assertEqual(top.shared_blks_hit, 1920000)

    def test_statements_are_deduplicated_by_queryid(self):
        # The same queryid appears once per role that ran it. The fixture has
        # one queryid twice; the more expensive occurrence is the one kept.
        workload = self.collect()
        ids = [s.queryid for s in workload.statements]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 3)
        first = next(s for s in workload.statements if s.queryid == "-4123456789012345678")
        self.assertEqual(first.calls, 480000)

    def test_the_statistics_reset_timestamp_is_captured(self):
        workload = self.collect()
        self.assertEqual(workload.stats_reset, "2026-08-01 00:00:00+00")

    def test_workload_collection_reads_no_user_table(self):
        with mock.patch("subprocess.run", side_effect=workload_calls()) as run:
            dbprofiler.collect_workload(a_config())
        for call in run.call_args_list:
            sql = call.args[0][-1]
            with self.subTest(sql=sql[:40]):
                self.assertEqual(dbprofiler.audit_sql(sql), [])


class TestWorkloadScopeFiltering(unittest.TestCase):
    def test_schema_exclude_drops_table_and_index_activity(self):
        with mock.patch("subprocess.run", side_effect=workload_calls()):
            workload = dbprofiler.collect_workload(a_config(schema_exclude=["sales"]))
        self.assertNotIn("sales", {t.schema for t in workload.table_activity})
        self.assertNotIn("sales", {i.schema for i in workload.index_activity})

    def test_schema_include_keeps_only_the_named_schema(self):
        with mock.patch("subprocess.run", side_effect=workload_calls()):
            workload = dbprofiler.collect_workload(a_config(schema_include=["sales"]))
        self.assertEqual({t.schema for t in workload.table_activity}, {"sales"})
        self.assertEqual({i.schema for i in workload.index_activity}, {"sales"})


class TestWorkloadDegradation(unittest.TestCase):
    """Telemetry is best-effort. A restricted role still gets a bundle."""

    def collect(self, **overrides):
        with mock.patch("subprocess.run", side_effect=workload_calls(**overrides)):
            return dbprofiler.collect_workload(a_config())

    def codes(self, workload):
        return [w.code for w in workload.warnings]

    def test_a_missing_pg_stat_statements_warns_and_omits(self):
        workload = self.collect(statements_installed="")
        self.assertEqual(workload.statements, ())
        self.assertIsNone(workload.stats_reset)
        self.assertIn("pg_stat_statements_missing", self.codes(workload))

    def test_a_missing_pg_stat_statements_does_not_cost_three_queries(self):
        calls = workload_calls(statements_installed="")
        with mock.patch("subprocess.run", side_effect=calls) as run:
            dbprofiler.collect_workload(a_config())
        # table activity, index activity, extension probe. Nothing after it.
        self.assertEqual(run.call_count, 3)

    def test_permission_denied_on_table_activity_warns_and_omits(self):
        workload = self.collect(table_activity=denied("pg_stat_user_tables"))
        self.assertEqual(workload.table_activity, ())
        self.assertIn("pg_stat_user_tables_unavailable", self.codes(workload))
        # The rest of the collection still happened.
        self.assertTrue(workload.index_activity)
        self.assertTrue(workload.statements)

    def test_permission_denied_on_index_activity_warns_and_omits(self):
        workload = self.collect(index_activity=denied("pg_stat_user_indexes"))
        self.assertEqual(workload.index_activity, ())
        self.assertIn("pg_stat_user_indexes_unavailable", self.codes(workload))
        self.assertTrue(workload.table_activity)

    def test_permission_denied_on_statements_warns_and_omits(self):
        workload = self.collect(statements=denied("pg_stat_statements"))
        self.assertEqual(workload.statements, ())
        self.assertIn("pg_stat_statements_unavailable", self.codes(workload))

    def test_an_unreadable_reset_timestamp_does_not_lose_the_statements(self):
        workload = self.collect(statements_reset=denied("pg_stat_statements_info"))
        self.assertIsNone(workload.stats_reset)
        self.assertTrue(workload.statements)
        self.assertIn("pg_stat_statements_info_unavailable", self.codes(workload))

    def test_no_source_available_is_still_not_a_failure(self):
        workload = self.collect(
            table_activity=denied("pg_stat_user_tables"),
            index_activity=denied("pg_stat_user_indexes"),
            statements_installed="",
        )
        self.assertEqual(len(workload.warnings), 3)

    def test_a_degradation_warning_never_carries_a_credential(self):
        stderr = completed(
            returncode=1,
            stderr=f'psql: error: connection to server failed: FATAL: password "{PASSWORD}"\n',
        )
        workload = self.collect(table_activity=stderr)
        message = workload.warnings[0].message
        self.assertNotIn(PASSWORD, message)
        self.assertIn("***", message)


# Synthetic, and long enough to satisfy the minimum-length check. Never a real
# key: a reviewer grepping this repository has to be able to tell at a glance.
TOKEN_KEY = "example-token-key-0123456789"


def a_tokenizer(key=TOKEN_KEY):
    return dbprofiler.Tokenizer(key.encode("utf-8"))


class TestLoadTokenKey(unittest.TestCase):
    def test_the_key_comes_from_the_environment(self):
        key = dbprofiler.load_token_key({dbprofiler.TOKEN_KEY_ENV_VAR: TOKEN_KEY})
        self.assertEqual(key, TOKEN_KEY.encode("utf-8"))

    def test_a_missing_key_is_a_configuration_error(self):
        with self.assertRaises(dbprofiler.ConfigError) as raised:
            dbprofiler.load_token_key({})
        self.assertIn(dbprofiler.TOKEN_KEY_ENV_VAR, str(raised.exception))

    def test_a_short_key_is_rejected(self):
        # A guessable key makes every token reversible by brute force.
        with self.assertRaises(dbprofiler.ConfigError):
            dbprofiler.load_token_key({dbprofiler.TOKEN_KEY_ENV_VAR: "short"})

    def test_no_rejection_message_echoes_the_key(self):
        for value in ("zq7wv", " " * 40):
            with self.subTest(value=value), self.assertRaises(dbprofiler.ConfigError) as raised:
                dbprofiler.load_token_key({dbprofiler.TOKEN_KEY_ENV_VAR: value})
            self.assertNotIn(value, str(raised.exception))

    def test_a_whitespace_only_key_is_not_a_key(self):
        with self.assertRaises(dbprofiler.ConfigError):
            dbprofiler.load_token_key({dbprofiler.TOKEN_KEY_ENV_VAR: "                    "})

    def test_there_is_no_default_key(self):
        """A default key would tokenize every deployment identically, which is
        the same as not tokenizing at all."""
        with self.assertRaises(dbprofiler.ConfigError):
            dbprofiler.load_token_key({"PGPASSWORD": PASSWORD})

    def test_an_explicit_environment_is_not_topped_up_from_the_process(self):
        # Otherwise a test -- or a caller passing a deliberately restricted
        # environment -- would silently pick up the ambient key.
        with mock.patch.dict(os.environ, {dbprofiler.TOKEN_KEY_ENV_VAR: TOKEN_KEY}):
            with self.assertRaises(dbprofiler.ConfigError):
                dbprofiler.load_token_key({})
            self.assertEqual(dbprofiler.load_token_key(), TOKEN_KEY.encode("utf-8"))


class TestTokenizerSecrecy(unittest.TestCase):
    def test_the_tokenizer_never_reprs_its_key(self):
        tokenizer = a_tokenizer()
        self.assertNotIn(TOKEN_KEY, repr(tokenizer))
        self.assertNotIn(TOKEN_KEY, str(tokenizer))
        self.assertNotIn(TOKEN_KEY, f"{tokenizer}")
        self.assertIn(dbprofiler.REDACTED, repr(tokenizer))

    def test_the_key_never_reaches_a_child_process(self):
        env = dbprofiler.safe_env(a_config())
        self.assertNotIn(dbprofiler.TOKEN_KEY_ENV_VAR, env)
        self.assertNotIn(TOKEN_KEY, env.values())

    def test_a_token_does_not_contain_its_input(self):
        tokenizer = a_tokenizer()
        for value in ("user@example.invalid", "sample-region-1", "42"):
            with self.subTest(value=value):
                token = tokenizer.token(value, "public.users.email")
                self.assertNotIn(value, token)
                self.assertNotIn(TOKEN_KEY, token)

    def test_a_token_is_hex(self):
        token = a_tokenizer().token("x", "d")
        self.assertEqual(len(token), 64)
        int(token, 16)  # raises if it is not


class TestTokenizeDeterminism(unittest.TestCase):
    def setUp(self):
        self.tokenizer = a_tokenizer()

    def test_equal_values_in_one_domain_tokenize_equally(self):
        # This is the property the whole design rests on: a join key on both
        # sides of a foreign key has to survive tokenization as a join key.
        left = self.tokenizer.token("4200", "public.users.id")
        right = self.tokenizer.token("4200", "public.users.id")
        self.assertEqual(left, right)

    def test_different_domains_do_not_collide(self):
        left = self.tokenizer.token("4200", "public.users.id")
        right = self.tokenizer.token("4200", "public.orders.id")
        self.assertNotEqual(left, right)

    def test_a_domain_boundary_cannot_be_forged(self):
        """Concatenating domain and value without a separator would make
        ("ab", "c") and ("a", "bc") the same token."""
        self.assertNotEqual(
            self.tokenizer.token("c", "ab"),
            self.tokenizer.token("bc", "a"),
        )

    def test_a_different_key_gives_a_different_token(self):
        other = a_tokenizer("example-token-key-9876543210")
        self.assertNotEqual(
            self.tokenizer.token("4200", "public.users.id"),
            other.token("4200", "public.users.id"),
        )

    def test_null_is_distinguishable_from_the_empty_string(self):
        self.assertNotEqual(
            self.tokenizer.token(None, "public.users.email"),
            self.tokenizer.token("", "public.users.email"),
        )


class TestTokenDomain(unittest.TestCase):
    def test_a_domain_names_the_schema_table_and_column(self):
        domain = dbprofiler.token_domain("public", "users", "id")
        self.assertEqual(domain.split(dbprofiler.DOMAIN_SEPARATOR), ["public", "users", "id"])

    def test_identifiers_containing_a_dot_cannot_forge_a_domain(self):
        # PostgreSQL permits a dot inside a quoted identifier, so a dotted join
        # would let one column's values impersonate another's.
        self.assertNotEqual(
            dbprofiler.token_domain("public", "users.id", "x"),
            dbprofiler.token_domain("public", "users", "id.x"),
        )


class TestTypedRepresentation(unittest.TestCase):
    """Numeric canonicalization, so a foreign key across int4 and int8 -- which
    PostgreSQL permits -- still tokenizes to the same value on both sides."""

    def setUp(self):
        self.tokenizer = a_tokenizer()

    def test_numeric_types_are_canonicalized(self):
        domain = "public.orders.total"
        self.assertEqual(
            self.tokenizer.token("42", domain, "int8"),
            self.tokenizer.token("42.0", domain, "numeric"),
        )
        self.assertEqual(
            self.tokenizer.token("42", domain, "int4"),
            self.tokenizer.token("4.2e1", domain, "float8"),
        )

    def test_text_is_never_canonicalized_as_a_number(self):
        """"0001" and "1" are different strings. Collapsing them would merge two
        most-common values into one token and corrupt the frequency it carries."""
        domain = "public.users.code"
        self.assertNotEqual(
            self.tokenizer.token("0001", domain, "text"),
            self.tokenizer.token("1", domain, "text"),
        )

    def test_significant_whitespace_in_text_is_preserved(self):
        domain = "public.users.name"
        self.assertNotEqual(
            self.tokenizer.token("ada ", domain, "text"),
            self.tokenizer.token("ada", domain, "text"),
        )

    def test_an_unparseable_numeric_falls_back_to_its_text(self):
        # "NaN" and "Infinity" are legal float8 values and must not crash.
        domain = "public.readings.value"
        for value in ("NaN", "Infinity", "-Infinity", ""):
            with self.subTest(value=value):
                self.assertEqual(len(self.tokenizer.token(value, domain, "float8")), 64)

    def test_the_type_name_is_not_part_of_the_hashed_material(self):
        """A foreign key may cross int4 and int8. Hashing the type name would
        break exactly the equality the tokens exist to preserve."""
        domain = "public.users.id"
        self.assertEqual(
            self.tokenizer.token("7", domain, "int4"),
            self.tokenizer.token("7", domain, "int8"),
        )


class TestTypeShapedTokens(unittest.TestCase):
    """A tokenized UUID stays loadable as a UUID.

    The profile is meant to be replayed into a CockroachDB schema for sizing. A
    64-character hex string in a uuid column would not load, so the migration
    team would have to retype the column and the shape they were testing would
    no longer be the shape being migrated.
    """

    def setUp(self):
        self.tokenizer = a_tokenizer()

    def test_a_uuid_tokenizes_to_a_uuid(self):
        token = self.tokenizer.token(
            "6b3a8f2e-1d4c-4a5b-9e7f-0c1d2e3f4a5b", "public.users.id", "uuid"
        )
        self.assertEqual(str(uuid.UUID(token)), token)

    def test_uuid_tokens_stay_deterministic_and_distinct(self):
        domain = "public.users.id"
        one = self.tokenizer.token("6b3a8f2e-1d4c-4a5b-9e7f-0c1d2e3f4a5b", domain, "uuid")
        again = self.tokenizer.token("6b3a8f2e-1d4c-4a5b-9e7f-0c1d2e3f4a5b", domain, "uuid")
        other = self.tokenizer.token("11111111-2222-3333-4444-555555555555", domain, "uuid")
        self.assertEqual(one, again)
        self.assertNotEqual(one, other)

    def test_a_uuid_is_case_and_hyphen_canonical_before_hashing(self):
        # PostgreSQL renders uuid lowercase and hyphenated, but a text column
        # holding a uuid may not be. Both sides of a foreign key must agree.
        domain = "public.users.id"
        self.assertEqual(
            self.tokenizer.token("6B3A8F2E-1D4C-4A5B-9E7F-0C1D2E3F4A5B", domain, "uuid"),
            self.tokenizer.token("6b3a8f2e1d4c4a5b9e7f0c1d2e3f4a5b", domain, "uuid"),
        )

    def test_an_unparseable_uuid_does_not_crash(self):
        token = self.tokenizer.token("not-a-uuid", "public.users.id", "uuid")
        self.assertEqual(str(uuid.UUID(token)), token)

    def test_every_other_type_gets_a_plain_hex_token(self):
        for type_name in ("text", "int8", "jsonb", ""):
            with self.subTest(type_name=type_name):
                self.assertEqual(len(self.tokenizer.token("x", "d", type_name)), 64)


class TestTokenizeSequences(unittest.TestCase):
    def test_a_sequence_tokenizes_elementwise_and_in_order(self):
        tokenizer = a_tokenizer()
        tokens = tokenizer.tokens(("a", "b", "a"), "public.users.email", "text")
        self.assertEqual(len(tokens), 3)
        self.assertEqual(tokens[0], tokens[2])
        self.assertNotEqual(tokens[0], tokens[1])

    def test_an_empty_sequence_tokenizes_to_an_empty_tuple(self):
        self.assertEqual(a_tokenizer().tokens((), "d", "text"), ())


def a_catalog(**overrides):
    """The golden catalog, collected once and reused across normalization tests."""
    with mock.patch("subprocess.run", side_effect=catalog_calls(**overrides)):
        return dbprofiler.collect_catalog(a_config())


class NormalizationCase(unittest.TestCase):
    def setUp(self):
        self.tokenizer = a_tokenizer()
        self.catalog = a_catalog()
        self.tables = dbprofiler.normalize_tables(self.catalog, self.tokenizer)
        self.by_table = {(t.schema, t.name): t for t in self.tables}

    def column(self, schema, table, name):
        return next(c for c in self.by_table[(schema, table)].columns if c.name == name)


class TestNormalizeTables(NormalizationCase):
    def test_row_counts_come_from_reltuples(self):
        self.assertEqual(self.by_table[("public", "users")].row_count_estimate, 1000.0)
        self.assertEqual(self.by_table[("public", "orders")].row_count_estimate, 5000.0)

    def test_sizes_are_carried_through(self):
        self.assertEqual(self.by_table[("public", "users")].size_bytes, 163840)

    def test_tables_are_sorted_deterministically(self):
        self.assertEqual(
            [(t.schema, t.name) for t in self.tables],
            [("public", "orders"), ("public", "users"), ("sales", "invoices")],
        )

    def test_columns_are_ordered_by_ordinal(self):
        columns = self.by_table[("public", "users")].columns
        self.assertEqual([c.ordinal for c in columns], sorted(c.ordinal for c in columns))
        self.assertEqual(columns[0].name, "id")

    def test_table_provenance_names_the_postgresql_source(self):
        provenance = self.by_table[("public", "users")].provenance
        self.assertIn("reltuples", provenance)
        self.assertIn("estimate", provenance)


class TestNormalizeColumns(NormalizationCase):
    def test_a_relative_n_distinct_is_resolved_against_the_row_count(self):
        # -1 means "every row is distinct". 1.0 * 1000 rows.
        self.assertEqual(self.column("public", "users", "id").distinct_estimate, 1000.0)
        # -0.5 over 5000 rows.
        self.assertEqual(self.column("public", "orders", "placed_at").distinct_estimate, 2500.0)

    def test_an_absolute_n_distinct_is_used_as_is(self):
        self.assertEqual(self.column("public", "orders", "user_id").distinct_estimate, 500.0)

    def test_null_fraction_and_width_are_carried_through(self):
        placed_at = self.column("public", "orders", "placed_at")
        self.assertEqual(placed_at.null_fraction, 0.25)
        self.assertEqual(placed_at.avg_width_bytes, 8)

    def test_a_column_with_no_statistics_row_reports_nothing_rather_than_zero(self):
        """profile is jsonb and has never been analyzed. Reporting 0 distinct
        values would be a claim; reporting nothing is the truth."""
        profile = self.column("public", "users", "profile")
        self.assertIsNone(profile.distinct_estimate)
        self.assertIsNone(profile.null_fraction)
        self.assertIsNone(profile.avg_width_bytes)
        self.assertEqual(profile.most_common_tokens, ())
        self.assertIn("no pg_stats row", profile.provenance)

    def test_type_support_is_carried_onto_the_contract(self):
        self.assertTrue(self.column("public", "users", "id").is_supported)
        self.assertFalse(self.column("public", "users", "legacy_balance").is_supported)
        self.assertTrue(self.column("sales", "invoices", "region").is_supported)

    def test_declared_types_are_the_readable_form(self):
        self.assertEqual(self.column("public", "users", "tags").data_type, "text[]")
        self.assertEqual(
            self.column("public", "orders", "placed_at").data_type, "timestamp with time zone"
        )

    def test_nullability_is_carried_through(self):
        self.assertFalse(self.column("public", "users", "id").is_nullable)
        self.assertTrue(self.column("public", "users", "email").is_nullable)

    def test_column_provenance_records_the_n_distinct_encoding(self):
        relative = self.column("public", "users", "id").provenance
        self.assertIn("n_distinct=-1", relative)
        self.assertIn("fraction of rows", relative)
        absolute = self.column("public", "orders", "user_id").provenance
        self.assertIn("n_distinct=500", absolute)
        self.assertIn("absolute", absolute)


class TestNormalizedValuesAreTokens(NormalizationCase):
    def test_most_common_values_are_replaced_by_tokens(self):
        user_id = self.column("public", "orders", "user_id")
        self.assertEqual(len(user_id.most_common_tokens), 3)
        for raw in ("1", "2", "3"):
            for token in user_id.most_common_tokens:
                self.assertNotEqual(token, raw)

    def test_frequencies_survive_tokenization_in_order(self):
        # The tokens hide which parent is hot. The frequencies must not.
        user_id = self.column("public", "orders", "user_id")
        self.assertEqual(user_id.most_common_freqs, (0.1, 0.05, 0.02))
        self.assertEqual(len(user_id.most_common_tokens), len(user_id.most_common_freqs))

    def test_histogram_bounds_are_replaced_by_tokens(self):
        bounds = self.column("public", "users", "id").histogram_token_bounds
        self.assertEqual(len(bounds), 5)
        self.assertNotIn("250", bounds)

    def test_an_email_never_appears_in_a_normalized_record(self):
        planted = "alpha@example.invalid"
        self.assertIn(planted, golden("column_stats"))
        self.assertNotIn(planted, repr(self.tables))

    def test_a_foreign_key_still_joins_after_tokenization(self):
        """The whole point. orders.user_id = 1 and users.id = 1 have to produce
        the same token, or the profile shows no relationship at all."""
        child = self.column("public", "orders", "user_id").most_common_tokens[0]
        parent = self.column("public", "users", "id").histogram_token_bounds[0]
        self.assertEqual(child, parent)

    def test_a_transitive_foreign_key_chain_resolves_to_one_domain(self):
        # invoices.order_id -> orders.id, and orders.id is nobody's child.
        child = self.column("sales", "invoices", "order_id").histogram_token_bounds[0]
        parent = self.column("public", "orders", "id").histogram_token_bounds[0]
        self.assertEqual(child, parent)

    def test_unrelated_columns_do_not_share_a_domain(self):
        users_id = self.column("public", "users", "id").histogram_token_bounds[0]
        orders_id = self.column("public", "orders", "id").histogram_token_bounds[0]
        self.assertNotEqual(users_id, orders_id)


class TestNormalizeRelationships(unittest.TestCase):
    def setUp(self):
        self.tokenizer = a_tokenizer()
        self.catalog = a_catalog()
        self.relationships = dbprofiler.normalize_relationships(self.catalog)
        self.by_name = {r.constraint_name: r for r in self.relationships}

    def test_relationships_carry_ordered_columns_and_actions(self):
        fk = self.by_name["orders_user_id_fkey"]
        self.assertEqual(fk.child_schema, "public")
        self.assertEqual(fk.child_table, "orders")
        self.assertEqual(fk.child_columns, ("user_id",))
        self.assertEqual(fk.parent_table, "users")
        self.assertEqual(fk.parent_columns, ("id",))
        self.assertEqual(fk.on_delete, "CASCADE")
        self.assertEqual(fk.on_update, "NO ACTION")

    def test_relationships_are_sorted_deterministically(self):
        self.assertEqual(
            [(r.child_schema, r.child_table, r.constraint_name) for r in self.relationships],
            sorted((r.child_schema, r.child_table, r.constraint_name) for r in self.relationships),
        )


class TestSingleColumnFanOut(unittest.TestCase):
    def setUp(self):
        self.catalog = a_catalog()
        self.by_name = {
            r.constraint_name: r for r in dbprofiler.normalize_relationships(self.catalog)
        }

    def test_the_mean_is_non_null_child_rows_over_distinct_values(self):
        # 5000 orders, no nulls, 500 distinct user_id values.
        fan_out = self.by_name["orders_user_id_fkey"].fan_out
        self.assertEqual(fan_out.status, "estimated")
        self.assertEqual(fan_out.basis, "single_column")
        self.assertAlmostEqual(fan_out.mean, 10.0)

    def test_nulls_are_excluded_from_the_numerator(self):
        # A nullable foreign key with half its rows null has half the children
        # to distribute, and counting them would double the estimate.
        stats = "public,orders,user_id,0.5,8,500,,,\n"
        catalog = a_catalog(column_stats=stats)
        fan_out = next(
            r for r in dbprofiler.normalize_relationships(catalog)
            if r.constraint_name == "orders_user_id_fkey"
        ).fan_out
        self.assertAlmostEqual(fan_out.mean, 5.0)

    def test_the_hot_parent_shape_survives_as_p99(self):
        """The mean says 10 children per parent. The most common user_id holds
        10% of 5000 rows. A migration sized on the mean would be wrong by 50x."""
        fan_out = self.by_name["orders_user_id_fkey"].fan_out
        self.assertIsNotNone(fan_out.p99)
        self.assertGreater(fan_out.p99, fan_out.mean)

    def test_a_uniform_key_has_a_fan_out_of_one(self):
        fan_out = self.by_name["invoices_order_fkey"].fan_out
        self.assertAlmostEqual(fan_out.mean, 1.0)

    def test_a_child_column_with_no_statistics_is_insufficient(self):
        catalog = a_catalog(column_stats="")
        for relationship in dbprofiler.normalize_relationships(catalog):
            with self.subTest(constraint=relationship.constraint_name):
                self.assertEqual(relationship.fan_out.status, "insufficient_statistics")
                self.assertIsNone(relationship.fan_out.mean)

    def test_an_unknown_n_distinct_is_insufficient_not_a_division_by_zero(self):
        # PostgreSQL writes 0 for "no estimate available".
        stats = "public,orders,user_id,0,8,0,,,\n"
        fan_out = next(
            r for r in dbprofiler.normalize_relationships(a_catalog(column_stats=stats))
            if r.constraint_name == "orders_user_id_fkey"
        ).fan_out
        self.assertEqual(fan_out.status, "insufficient_statistics")


class TestCompositeFanOut(unittest.TestCase):
    """A composite key's distinct count is not the product of its columns'.

    user_id has 500 distinct values and placed_at has 2500, but orders are not
    placed at independently random times: the real pair count is 4200, not
    1,250,000. Multiplying would understate fan-out by 300x and size the
    migration against a workload that does not exist.
    """

    def composite_catalog(self, extended_stats=None):
        foreign_keys = (
            "orders_user_placed_fkey,public,orders,public,users,user_id,id,1,a,c\n"
            "orders_user_placed_fkey,public,orders,public,users,placed_at,created_at,2,a,c\n"
        )
        overrides = {"foreign_keys": foreign_keys}
        if extended_stats is not None:
            overrides["extended_stats"] = extended_stats
        return a_catalog(**overrides)

    def fan_out(self, catalog):
        return dbprofiler.normalize_relationships(catalog)[0].fan_out

    def test_matching_extended_statistics_give_an_estimate(self):
        fan_out = self.fan_out(self.composite_catalog())
        self.assertEqual(fan_out.status, "estimated")
        self.assertEqual(fan_out.basis, "extended_statistics")
        # 5000 rows and 4200 distinct pairs, less the nulls. A composite key
        # references a parent only when every column is non-null, and PostgreSQL
        # has no joint null fraction, so the most-null column -- placed_at at
        # 0.25 -- is the tightest bound available and the estimate errs high.
        self.assertAlmostEqual(fan_out.mean, 5000 * 0.75 / 4200)

    def test_column_order_does_not_matter_to_the_lookup(self):
        # n-distinct over a column set is order-independent; pg_stats_ext lists
        # attnums in catalog order, which need not match the key's.
        reordered = (
            "orders_user_placed_fkey,public,orders,public,users,placed_at,created_at,1,a,c\n"
            "orders_user_placed_fkey,public,orders,public,users,user_id,id,2,a,c\n"
        )
        fan_out = self.fan_out(a_catalog(foreign_keys=reordered))
        self.assertEqual(fan_out.status, "estimated")

    def test_without_extended_statistics_it_is_insufficient(self):
        fan_out = self.fan_out(self.composite_catalog(extended_stats=""))
        self.assertEqual(fan_out.status, "insufficient_statistics")
        self.assertEqual(fan_out.basis, "composite")
        self.assertIsNone(fan_out.mean)

    def test_independent_single_column_estimates_are_never_multiplied(self):
        fan_out = self.fan_out(self.composite_catalog(extended_stats=""))
        self.assertNotAlmostEqual(fan_out.mean or 0.0, 5000 / (500 * 2500))

    def test_extended_statistics_for_a_different_column_set_do_not_count(self):
        other = (
            'public,orders,orders_other_stx,"{id,placed_at}","{""1, 3"": 900}",t\n'
        )
        fan_out = self.fan_out(self.composite_catalog(extended_stats=other))
        self.assertEqual(fan_out.status, "insufficient_statistics")


class TestProfileAssembly(unittest.TestCase):
    def build(self):
        catalog = a_catalog()
        with mock.patch("subprocess.run", side_effect=workload_calls()):
            workload = dbprofiler.collect_workload(a_config())
        source = dbprofiler.Source(
            kind="postgres",
            server_version_num=160002,
            server_version="16.2",
            database=DATABASE,
            collected_schemas=("public", "sales"),
        )
        return dbprofiler.build_profile(source, catalog, workload, a_tokenizer())

    def test_the_profile_carries_the_contract_version(self):
        self.assertEqual(self.build().contract_version, dbprofiler.CONTRACT_VERSION)

    def test_the_profile_carries_tables_and_relationships(self):
        profile = self.build()
        self.assertEqual(len(profile.tables), 3)
        self.assertEqual(len(profile.relationships), 2)

    def test_workload_warnings_reach_the_profile(self):
        catalog = a_catalog()
        with mock.patch("subprocess.run", side_effect=workload_calls(statements_installed="")):
            workload = dbprofiler.collect_workload(a_config())
        profile = dbprofiler.build_profile(
            dbprofiler.Source("postgres", 160002, "16.2", DATABASE), catalog, workload,
            a_tokenizer(),
        )
        self.assertIn("pg_stat_statements_missing", [w.code for w in profile.warnings])

    def test_the_contract_reserves_postgresql_native_names_for_provenance(self):
        """A consumer reading profile.json should not have to know that
        reltuples is an estimate or that n_distinct can be negative."""
        native = ("reltuples", "n_distinct", "null_frac", "attnum", "relkind")
        fields = set()
        for record in (dbprofiler.Table, dbprofiler.Column, dbprofiler.Relationship):
            fields.update(f.name for f in dataclasses.fields(record))
        for name in native:
            with self.subTest(name=name):
                self.assertNotIn(name, fields)

    def test_the_build_is_deterministic(self):
        self.assertEqual(repr(self.build()), repr(self.build()))


# ---------------------------------------------------------------------------
# Bundle publication
# ---------------------------------------------------------------------------

# A value that exists nowhere else in the repository. Planted into a raw
# observation before serialization so the "no raw literal reaches disk"
# assertions have something they would actually catch if the sanitizer broke.
PLANTED = "planted-literal-4f2c9ae7"

SCHEMA_SQL = "CREATE TABLE public.users (id bigint PRIMARY KEY);\n"

FINGERPRINT = "0" * 64


def a_source():
    return dbprofiler.Source("postgres", 160002, "16.2", DATABASE, ("public", "sales"))


def a_workload(**overrides):
    """The golden workload, collected once and reused across bundle tests."""
    with mock.patch("subprocess.run", side_effect=workload_calls(**overrides)):
        return dbprofiler.collect_workload(a_config())


def zip_bytes(path):
    """Everything a reader could recover from a bundle.

    Both the file as stored and every member decompressed. Searching only the
    stored bytes would be a hollow assertion: DEFLATE would hide the very
    literal the test is looking for.
    """
    raw = Path(path).read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = b"".join(archive.read(name) for name in archive.namelist())
    return raw + members


def read_csv(entry):
    return list(csv.reader(io.StringIO(entry.data.decode("utf-8"))))


class BundleCase(unittest.TestCase):
    def setUp(self):
        self.tokenizer = a_tokenizer()
        self.catalog = a_catalog()
        self.workload = a_workload()
        self.profile = dbprofiler.build_profile(
            a_source(), self.catalog, self.workload, self.tokenizer
        )
        self.payloads = self.build_payloads()
        self.by_path = {entry.path: entry for entry in self.payloads}
        self.manifest = dbprofiler.build_manifest(
            source=a_source(),
            schema_fingerprint=FINGERPRINT,
            payloads=self.payloads,
            warnings=self.workload.warnings,
            stats_reset=self.workload.stats_reset,
        )
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.destination = Path(self.directory.name) / "source-profile.zip"

    def build_payloads(self, **overrides):
        return dbprofiler.build_payloads(
            profile=overrides.get("profile", self.profile),
            catalog=overrides.get("catalog", self.catalog),
            workload=overrides.get("workload", self.workload),
            tokenizer=overrides.get("tokenizer", self.tokenizer),
            schema_sql=overrides.get("schema_sql", SCHEMA_SQL),
        )

    def publish(self, payloads=None, manifest=None, destination=None):
        return dbprofiler.write_bundle(
            destination or self.destination,
            self.payloads if payloads is None else payloads,
            manifest or self.manifest,
        )

    def leftovers(self):
        return sorted(p.name for p in Path(self.directory.name).iterdir())


class TestSafeEntryPaths(unittest.TestCase):
    def test_the_documented_bundle_paths_are_accepted(self):
        for path in dbprofiler.BUNDLE_PAYLOAD_PATHS + (dbprofiler.BUNDLE_MANIFEST,):
            with self.subTest(path=path):
                dbprofiler.require_safe_entry_path(path)

    def test_absolute_paths_are_rejected(self):
        for path in ("/etc/passwd", "//tmp/x.csv", "/observations/pg_class.csv"):
            with self.subTest(path=path), self.assertRaises(dbprofiler.BundleError):
                dbprofiler.require_safe_entry_path(path)

    def test_parent_traversal_is_rejected(self):
        for path in ("../escape.csv", "observations/../../escape.csv", ".."):
            with self.subTest(path=path), self.assertRaises(dbprofiler.BundleError):
                dbprofiler.require_safe_entry_path(path)

    def test_windows_separators_and_drive_letters_are_rejected(self):
        for path in ("observations\\pg_class.csv", "C:/observations/pg_class.csv"):
            with self.subTest(path=path), self.assertRaises(dbprofiler.BundleError):
                dbprofiler.require_safe_entry_path(path)

    def test_empty_and_dot_segments_are_rejected(self):
        for path in ("", "observations//pg_class.csv", "./profile.json", "observations/"):
            with self.subTest(path=path), self.assertRaises(dbprofiler.BundleError):
                dbprofiler.require_safe_entry_path(path)

    def test_control_characters_and_newlines_are_rejected(self):
        for path in ("profile\n.json", "profile\x00.json", "obs ervations/x.csv"):
            with self.subTest(path=path), self.assertRaises(dbprofiler.BundleError):
                dbprofiler.require_safe_entry_path(path)


class TestJsonSerialization(unittest.TestCase):
    def test_contract_records_serialize_to_plain_json(self):
        source = a_source()
        payload = json.loads(dbprofiler.json_bytes(source))
        self.assertEqual(payload["kind"], "postgres")
        self.assertEqual(payload["collected_schemas"], ["public", "sales"])

    def test_a_collector_record_refuses_to_serialize(self):
        """The records holding raw values are dataclasses too. Serializing by
        structure rather than by name would put them straight onto disk."""
        raw = dbprofiler.ColumnStatistics(
            schema="public",
            table="users",
            column="email",
            null_frac=0.0,
            avg_width=32,
            n_distinct=-1.0,
            most_common_vals=(PLANTED,),
            most_common_freqs=(1.0,),
            histogram_bounds=(),
        )
        with self.assertRaises(dbprofiler.BundleError):
            dbprofiler.json_bytes(raw)

    def test_a_mapping_refuses_to_serialize(self):
        with self.assertRaises(dbprofiler.BundleError):
            dbprofiler.to_jsonable({"user_id": PLANTED})

    def test_bytes_refuse_to_serialize(self):
        with self.assertRaises(dbprofiler.BundleError):
            dbprofiler.to_jsonable(PLANTED.encode("utf-8"))

    def test_non_finite_floats_refuse_to_serialize(self):
        """json.dumps writes a bare NaN by default, which is not JSON."""
        with self.assertRaises(ValueError):
            dbprofiler.json_bytes(dbprofiler.FanOut(status="estimated", basis="composite",
                                                    mean=float("nan")))

    def test_the_serialization_is_stable(self):
        self.assertEqual(dbprofiler.json_bytes(a_source()), dbprofiler.json_bytes(a_source()))


class TestPayloads(BundleCase):
    def test_the_bundle_carries_the_documented_entries(self):
        self.assertEqual(
            sorted(self.by_path),
            [
                "observations/foreign_keys.csv",
                "observations/pg_class.csv",
                "observations/pg_stat_indexes.csv",
                "observations/pg_stat_statements.csv",
                "observations/pg_stat_tables.csv",
                "observations/pg_stats.csv",
                "observations/pg_stats_ext.csv",
                "profile.json",
                "schema.sql",
            ],
        )

    def test_payloads_arrive_sorted_by_path(self):
        self.assertEqual([e.path for e in self.payloads], sorted(self.by_path))

    def test_every_payload_path_is_allowlisted(self):
        for entry in self.payloads:
            with self.subTest(path=entry.path):
                self.assertIn(entry.path, dbprofiler.BUNDLE_ALLOWED_PATHS)

    def test_the_manifest_is_not_a_payload(self):
        self.assertNotIn(dbprofiler.BUNDLE_MANIFEST, self.by_path)

    def test_row_counts_match_the_csv_bodies(self):
        for entry in self.payloads:
            if not entry.path.endswith(".csv"):
                continue
            with self.subTest(path=entry.path):
                self.assertEqual(entry.row_count, len(read_csv(entry)) - 1)

    def test_the_schema_payload_is_the_dump_verbatim(self):
        self.assertEqual(self.by_path["schema.sql"].data, SCHEMA_SQL.encode("utf-8"))

    def test_pg_class_reports_estimates_and_sizes(self):
        rows = read_csv(self.by_path["observations/pg_class.csv"])
        header, body = rows[0], rows[1:]
        users = next(row for row in body if row[:2] == ["public", "users"])
        self.assertEqual(users[header.index("row_count_estimate")], "1000.0")
        self.assertEqual(users[header.index("size_bytes")], "163840")

    def test_pg_stats_carries_tokens_and_never_values(self):
        rows = read_csv(self.by_path["observations/pg_stats.csv"])
        header, body = rows[0], rows[1:]
        user_id = next(row for row in body if row[:3] == ["public", "orders", "user_id"])
        tokens = user_id[header.index("most_common_tokens")].split("|")
        self.assertEqual(len(tokens), 3)
        for token in tokens:
            self.assertRegex(token, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(user_id[header.index("most_common_freqs")], "0.1|0.05|0.02")

    def test_pg_stats_ext_reports_one_row_per_column_combination(self):
        rows = read_csv(self.by_path["observations/pg_stats_ext.csv"])
        header, body = rows[0], rows[1:]
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0][header.index("combination")], "user_id|placed_at")
        self.assertEqual(body[0][header.index("distinct_estimate")], "4200.0")
        self.assertEqual(body[0][header.index("has_most_common_values")], "true")

    def test_foreign_keys_carry_the_fan_out_estimate(self):
        rows = read_csv(self.by_path["observations/foreign_keys.csv"])
        header, body = rows[0], rows[1:]
        fk = next(row for row in body if row[0] == "orders_user_id_fkey")
        self.assertEqual(fk[header.index("fan_out_status")], "estimated")
        self.assertEqual(fk[header.index("fan_out_basis")], "single_column")
        self.assertEqual(fk[header.index("on_delete")], "CASCADE")

    def test_pg_stat_indexes_joins_the_catalog_for_uniqueness(self):
        """Whether an unused index can simply be dropped depends on whether it
        backs a constraint, and only the catalog knows that."""
        rows = read_csv(self.by_path["observations/pg_stat_indexes.csv"])
        header, body = rows[0], rows[1:]
        pkey = next(row for row in body if row[2] == "users_pkey")
        secondary = next(row for row in body if row[2] == "orders_user_id_idx")
        self.assertEqual(pkey[header.index("is_primary")], "true")
        self.assertEqual(secondary[header.index("is_primary")], "false")
        self.assertEqual(secondary[header.index("size_bytes")], "901120")

    def test_pg_stat_tables_keeps_the_autovacuum_signal(self):
        rows = read_csv(self.by_path["observations/pg_stat_tables.csv"])
        header, body = rows[0], rows[1:]
        orders = next(row for row in body if row[:2] == ["public", "orders"])
        self.assertEqual(orders[header.index("n_dead_tup")], "1500")
        self.assertEqual(orders[header.index("last_vacuum")], "")
        self.assertEqual(orders[header.index("autovacuum_count")], "9")

    def test_statement_text_is_replaced_by_a_token(self):
        rows = read_csv(self.by_path["observations/pg_stat_statements.csv"])
        header, body = rows[0], rows[1:]
        self.assertNotIn("query", header)
        for row in body:
            self.assertRegex(row[header.index("query_token")], r"\A[0-9a-f]{64}\Z")

    def test_identical_statement_text_tokenizes_identically(self):
        rows = read_csv(self.by_path["observations/pg_stat_statements.csv"])
        header, body = rows[0], rows[1:]
        tokens = {row[header.index("queryid")]: row[header.index("query_token")] for row in body}
        self.assertEqual(len(tokens), len(body))
        again = dbprofiler.build_payloads(
            self.profile, self.catalog, self.workload, a_tokenizer(), SCHEMA_SQL
        )
        self.assertEqual(
            self.by_path["observations/pg_stat_statements.csv"].data,
            {e.path: e for e in again}["observations/pg_stat_statements.csv"].data,
        )

    def test_a_different_key_produces_different_tokens(self):
        other = dbprofiler.Tokenizer(b"a-different-example-key-0123456789")
        rows = dbprofiler.build_payloads(self.profile, self.catalog, self.workload, other,
                                         SCHEMA_SQL)
        self.assertNotEqual(
            self.by_path["observations/pg_stat_statements.csv"].data,
            {e.path: e for e in rows}["observations/pg_stat_statements.csv"].data,
        )


class TestDegradedPayloads(BundleCase):
    def omitted(self, **overrides):
        workload = a_workload(**overrides)
        profile = dbprofiler.build_profile(a_source(), self.catalog, workload, self.tokenizer)
        payloads = self.build_payloads(profile=profile, workload=workload)
        return {entry.path for entry in payloads}, workload.warnings

    def test_a_missing_extension_omits_the_statements_csv(self):
        paths, warnings = self.omitted(statements_installed="")
        self.assertNotIn("observations/pg_stat_statements.csv", paths)
        self.assertIn("pg_stat_statements_missing", [w.code for w in warnings])

    def test_a_permission_error_omits_the_statements_csv(self):
        paths, _ = self.omitted(statements=denied("pg_stat_statements"))
        self.assertNotIn("observations/pg_stat_statements.csv", paths)

    def test_a_permission_error_omits_the_table_activity_csv(self):
        paths, _ = self.omitted(table_activity=denied("pg_stat_user_tables"))
        self.assertNotIn("observations/pg_stat_tables.csv", paths)
        self.assertIn("observations/pg_stat_indexes.csv", paths)

    def test_a_permission_error_omits_the_index_activity_csv(self):
        paths, _ = self.omitted(index_activity=denied("pg_stat_user_indexes"))
        self.assertNotIn("observations/pg_stat_indexes.csv", paths)

    def test_omission_never_loses_the_catalog_sections(self):
        paths, _ = self.omitted(table_activity=denied("pg_stat_user_tables"))
        self.assertIn("profile.json", paths)
        self.assertIn("observations/pg_class.csv", paths)

    def test_a_degraded_bundle_still_publishes(self):
        workload = a_workload(statements_installed="")
        profile = dbprofiler.build_profile(a_source(), self.catalog, workload, self.tokenizer)
        payloads = self.build_payloads(profile=profile, workload=workload)
        manifest = dbprofiler.build_manifest(
            a_source(), FINGERPRINT, payloads, warnings=workload.warnings
        )
        dbprofiler.write_bundle(self.destination, payloads, manifest)
        with zipfile.ZipFile(self.destination) as archive:
            recorded = json.loads(archive.read("manifest.json"))
        self.assertIn("pg_stat_statements_missing", [w["code"] for w in recorded["warnings"]])


class TestManifest(BundleCase):
    def test_every_payload_is_hashed(self):
        described = {o.path: o for o in self.manifest.payloads}
        self.assertEqual(set(described), set(self.by_path))
        for path, observation in described.items():
            with self.subTest(path=path):
                expected = hashlib.sha256(self.by_path[path].data).hexdigest()
                self.assertEqual(observation.sha256, expected)

    def test_the_manifest_does_not_hash_itself(self):
        self.assertNotIn("manifest.json", [o.path for o in self.manifest.payloads])

    def test_the_manifest_records_the_schema_fingerprint(self):
        self.assertEqual(self.manifest.schema_fingerprint, FINGERPRINT)

    def test_the_manifest_records_the_statistics_reset_time(self):
        self.assertEqual(self.manifest.stats_reset, self.workload.stats_reset)

    def test_created_at_is_rfc_3339_utc(self):
        self.assertRegex(self.manifest.created_at, r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")

    def test_the_tool_identifies_itself(self):
        self.assertEqual(self.manifest.tool, dbprofiler.PROG)
        self.assertEqual(self.manifest.tool_version, dbprofiler.VERSION)
        self.assertEqual(self.manifest.contract_version, dbprofiler.CONTRACT_VERSION)


class TestWriteBundle(BundleCase):
    def test_the_archive_holds_the_payloads_and_the_manifest(self):
        self.publish()
        with zipfile.ZipFile(self.destination) as archive:
            self.assertEqual(sorted(archive.namelist()),
                             sorted(list(self.by_path) + ["manifest.json"]))

    def test_entries_are_stored_in_sorted_order_with_the_manifest_last(self):
        """The manifest hashes the others, so it can only be written once they
        exist. Storing it last makes that visible in the archive itself."""
        self.publish()
        with zipfile.ZipFile(self.destination) as archive:
            names = archive.namelist()
        self.assertEqual(names[-1], "manifest.json")
        self.assertEqual(names[:-1], sorted(names[:-1]))

    def test_stored_bytes_match_the_hashes_the_manifest_recorded(self):
        self.publish()
        with zipfile.ZipFile(self.destination) as archive:
            recorded = json.loads(archive.read("manifest.json"))
            for observation in recorded["payloads"]:
                with self.subTest(path=observation["path"]):
                    stored = archive.read(observation["path"])
                    self.assertEqual(hashlib.sha256(stored).hexdigest(), observation["sha256"])

    def test_entries_are_regular_files(self):
        """A ZIP entry can carry a unix mode. A symlink bit here would let an
        extractor write outside the destination directory."""
        self.publish()
        with zipfile.ZipFile(self.destination) as archive:
            for info in archive.infolist():
                with self.subTest(name=info.filename):
                    self.assertEqual(info.external_attr >> 16, 0o100644)

    def test_timestamps_are_fixed_so_two_runs_are_byte_identical(self):
        first = self.destination
        second = Path(self.directory.name) / "second.zip"
        manifest = dataclasses.replace(self.manifest, created_at="2026-08-24T00:00:00Z")
        dbprofiler.write_bundle(first, self.payloads, manifest)
        dbprofiler.write_bundle(second, self.payloads, manifest)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_no_temporary_file_survives_a_successful_run(self):
        self.publish()
        self.assertEqual(self.leftovers(), ["source-profile.zip"])

    def test_publication_uses_an_atomic_rename(self):
        with mock.patch("os.replace", wraps=os.replace) as replace:
            self.publish()
        self.assertEqual(replace.call_count, 1)
        self.assertEqual(Path(replace.call_args[0][1]), self.destination)

    def test_a_failed_write_leaves_no_temporary_file(self):
        with mock.patch.object(dbprofiler, "json_bytes", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.publish()
        self.assertEqual(self.leftovers(), [])

    def test_a_failed_rename_leaves_the_previous_bundle_intact(self):
        self.destination.write_bytes(b"previous bundle")
        with mock.patch("os.replace", side_effect=OSError("cross-device link")):
            with self.assertRaises(OSError):
                self.publish()
        self.assertEqual(self.destination.read_bytes(), b"previous bundle")
        self.assertEqual(self.leftovers(), ["source-profile.zip"])

    def test_a_partial_archive_is_never_visible_at_the_destination(self):
        seen = []
        real = os.replace

        def watch(source, target):
            seen.append(Path(target).exists())
            real(source, target)

        with mock.patch("os.replace", side_effect=watch):
            self.publish()
        self.assertEqual(seen, [False])

    def test_a_symlink_destination_is_refused(self):
        target = Path(self.directory.name) / "elsewhere.zip"
        link = Path(self.directory.name) / "link.zip"
        link.symlink_to(target)
        with self.assertRaises(dbprofiler.BundleError):
            self.publish(destination=link)
        self.assertFalse(target.exists())

    def test_a_directory_destination_is_refused(self):
        directory = Path(self.directory.name) / "a-directory.zip"
        directory.mkdir()
        with self.assertRaises(dbprofiler.BundleError):
            self.publish(destination=directory)


class TestWriteBundleRejections(BundleCase):
    def entry(self, path, data=b"x"):
        return dbprofiler.BundleEntry(path=path, data=data, row_count=0)

    def with_payloads(self, payloads):
        manifest = dbprofiler.build_manifest(a_source(), FINGERPRINT, payloads)
        with self.assertRaises(dbprofiler.BundleError):
            dbprofiler.write_bundle(self.destination, payloads, manifest)
        self.assertEqual(self.leftovers(), [])

    def test_an_unexpected_entry_is_rejected(self):
        self.with_payloads(self.payloads + (self.entry("notes.txt"),))

    def test_an_absolute_entry_is_rejected(self):
        self.with_payloads(self.payloads + (self.entry("/etc/passwd"),))

    def test_a_traversing_entry_is_rejected(self):
        self.with_payloads(self.payloads + (self.entry("../escape.csv"),))

    def test_a_duplicate_entry_is_rejected(self):
        self.with_payloads(self.payloads + (self.by_path["profile.json"],))

    def test_a_payload_named_manifest_json_is_rejected(self):
        """The manifest is written by write_bundle. A caller-supplied one would
        be a second file claiming to be the authority on the first."""
        self.with_payloads(self.payloads + (self.entry("manifest.json"),))

    def test_a_manifest_that_omits_a_payload_is_rejected(self):
        manifest = dbprofiler.build_manifest(a_source(), FINGERPRINT, self.payloads[1:])
        with self.assertRaises(dbprofiler.BundleError):
            dbprofiler.write_bundle(self.destination, self.payloads, manifest)

    def test_a_manifest_hash_that_does_not_match_is_rejected(self):
        """Catches a payload mutated between hashing and writing."""
        tampered = tuple(
            dataclasses.replace(entry, data=entry.data + b"\n") if entry.path == "profile.json"
            else entry
            for entry in self.payloads
        )
        with self.assertRaises(dbprofiler.BundleError):
            dbprofiler.write_bundle(self.destination, tampered, self.manifest)


class TestNothingRawReachesDisk(BundleCase):
    """The negative assertions. Each plants a value and proves its absence."""

    def bundle_and_temp(self, payloads=None, manifest=None):
        """Publish, capturing the temporary file's bytes before the rename."""
        captured = {}
        real = os.replace

        def capture(source, target):
            captured["temp"] = Path(source).read_bytes()
            real(source, target)

        with mock.patch("os.replace", side_effect=capture):
            self.publish(payloads=payloads, manifest=manifest)
        return zip_bytes(self.destination) + captured["temp"]

    def test_an_unnormalized_query_literal_never_reaches_the_bundle(self):
        """pg_stat_statements normalizes literals to $1 -- usually. The golden
        fixture carries one that was not normalized."""
        statements = golden("statements").replace("sample-region-1", PLANTED)
        workload = a_workload(statements=statements)
        self.assertIn(PLANTED, "".join(s.query_text for s in workload.statements))

        profile = dbprofiler.build_profile(a_source(), self.catalog, workload, self.tokenizer)
        payloads = self.build_payloads(profile=profile, workload=workload)
        manifest = dbprofiler.build_manifest(a_source(), FINGERPRINT, payloads)
        self.assertNotIn(PLANTED.encode("utf-8"), self.bundle_and_temp(payloads, manifest))

    def test_a_most_common_value_never_reaches_the_bundle(self):
        stats = golden("column_stats").replace("{1,2,3}", f"{{{PLANTED},2,3}}")
        catalog = a_catalog(column_stats=stats)
        self.assertIn(
            PLANTED,
            "".join("".join(s.most_common_vals) for s in catalog.column_stats),
        )

        profile = dbprofiler.build_profile(a_source(), catalog, self.workload, self.tokenizer)
        payloads = self.build_payloads(profile=profile, catalog=catalog)
        manifest = dbprofiler.build_manifest(a_source(), FINGERPRINT, payloads)
        self.assertNotIn(PLANTED.encode("utf-8"), self.bundle_and_temp(payloads, manifest))

    def test_a_histogram_bound_never_reaches_the_bundle(self):
        stats = golden("column_stats").replace("{1,250,500,750,1000}", f"{{{PLANTED},250}}")
        catalog = a_catalog(column_stats=stats)
        profile = dbprofiler.build_profile(a_source(), catalog, self.workload, self.tokenizer)
        payloads = self.build_payloads(profile=profile, catalog=catalog)
        manifest = dbprofiler.build_manifest(a_source(), FINGERPRINT, payloads)
        self.assertNotIn(PLANTED.encode("utf-8"), self.bundle_and_temp(payloads, manifest))

    def test_the_tokenization_key_never_reaches_the_bundle(self):
        self.assertNotIn(TOKEN_KEY.encode("utf-8"), self.bundle_and_temp())

    def test_no_connection_detail_reaches_the_bundle(self):
        published = self.bundle_and_temp()
        for secret in (URL, PASSWORD, USER, HOST):
            with self.subTest(secret=secret):
                self.assertNotIn(secret.encode("utf-8"), published)

    def test_the_database_name_is_recorded_but_the_credentials_are_not(self):
        """The bundle must say which database it profiled. That is not a secret;
        the role and password that reached it are."""
        self.publish()
        with zipfile.ZipFile(self.destination) as archive:
            manifest = json.loads(archive.read("manifest.json"))
        self.assertEqual(manifest["source"]["database"], DATABASE)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

# Which fixture answers which query. Keyed on the SQL constant itself so the
# fake dispatches on what the run asked for rather than on how many calls have
# gone by -- a positional list would have to be renumbered every time a step
# moves, and would not prove the order was the intended one.
SQL_FIXTURES = {
    dbprofiler.SQL_SERVER_VERSION: "server_version",
    dbprofiler.SQL_SCHEMA_FINGERPRINT: "schema_fingerprint",
    dbprofiler.SQL_TABLES: "tables",
    dbprofiler.SQL_INHERITED: "inherited",
    dbprofiler.SQL_COLUMNS: "columns",
    dbprofiler.SQL_COLUMN_STATS: "column_stats",
    dbprofiler.SQL_EXTENDED_STATS: "extended_stats",
    dbprofiler.SQL_FOREIGN_KEYS: "foreign_keys",
    dbprofiler.SQL_INDEXES: "indexes",
    dbprofiler.SQL_TABLE_ACTIVITY: "table_activity",
    dbprofiler.SQL_INDEX_ACTIVITY: "index_activity",
    dbprofiler.SQL_STATEMENTS_INSTALLED: "statements_installed",
    dbprofiler.SQL_STATEMENTS_RESET: "statements_reset",
    dbprofiler.SQL_STATEMENTS: "statements",
}

PG_DUMP_VERSION_OUTPUT = "pg_dump (PostgreSQL) 16.2\n"


class FakePostgres:
    """A stand-in for every child process one run makes.

    Records the step names in order. An override supplies a replacement for a
    step: a str is stdout, a CompletedProcess or an exception is a failure, and
    a list is consumed one entry per call, which is how the two fingerprint
    reads are given different answers.
    """

    def __init__(self, **overrides):
        self.calls = []
        self.queues = {
            name: list(value) if isinstance(value, list) else [value]
            for name, value in overrides.items()
        }

    def __call__(self, argv, **kwargs):
        if "pg_dump" in argv[0]:
            step = "pg_dump_version" if "--version" in argv else "pg_dump"
            default = PG_DUMP_VERSION_OUTPUT if step == "pg_dump_version" else SCHEMA_SQL
        else:
            step = SQL_FIXTURES[argv[argv.index("-c") + 1]]
            default = golden(step)
        self.calls.append(step)

        queue = self.queues.get(step)
        reply = default if not queue else (queue.pop(0) if len(queue) > 1 else queue[0])
        if isinstance(reply, BaseException):
            raise reply
        return completed(stdout=reply) if isinstance(reply, str) else reply


# Every step of a complete run, in the order the plan specifies.
FULL_RUN = [
    "server_version",
    "pg_dump_version",
    "schema_fingerprint",
    "pg_dump",
    "tables",
    "inherited",
    "columns",
    "column_stats",
    "extended_stats",
    "foreign_keys",
    "indexes",
    "table_activity",
    "index_activity",
    "statements_installed",
    "statements_reset",
    "statements",
    "schema_fingerprint",
]


class OrchestrationCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "source-profile.zip"
        self.stderr = io.StringIO()
        self.stdout = io.StringIO()

    def run_cli(self, fake=None, output=None, env=None, extra=()):
        fake = FakePostgres() if fake is None else fake
        environment = {
            dbprofiler.URL_ENV_VAR: URL,
            dbprofiler.TOKEN_KEY_ENV_VAR: TOKEN_KEY,
        }
        environment.update(env or {})
        argv = ["postgres", "--output", str(output or self.output), *extra]
        with mock.patch.dict("os.environ", environment, clear=True):
            with mock.patch("subprocess.run", side_effect=fake):
                with contextlib.redirect_stderr(self.stderr):
                    with contextlib.redirect_stdout(self.stdout):
                        return dbprofiler.main(argv), fake

    def leftovers(self):
        return sorted(p.name for p in Path(self.directory.name).iterdir())

    def archive(self, path=None):
        with zipfile.ZipFile(path or self.output) as handle:
            return {name: handle.read(name) for name in handle.namelist()}

    def manifest(self):
        return json.loads(self.archive()["manifest.json"])


class TestOrchestrationOrder(OrchestrationCase):
    def test_the_run_follows_the_documented_sequence(self):
        code, fake = self.run_cli()
        self.assertEqual(code, 0)
        self.assertEqual(fake.calls, FULL_RUN)

    def test_the_client_is_checked_before_anything_is_dumped(self):
        _, fake = self.run_cli()
        self.assertLess(fake.calls.index("pg_dump_version"), fake.calls.index("pg_dump"))

    def test_the_catalog_is_fingerprinted_before_and_after_collection(self):
        """Each psql call is its own transaction, so drift is caught by
        comparison rather than prevented by isolation."""
        _, fake = self.run_cli()
        first = fake.calls.index("schema_fingerprint")
        last = len(fake.calls) - 1 - fake.calls[::-1].index("schema_fingerprint")
        self.assertNotEqual(first, last)
        self.assertLess(first, fake.calls.index("pg_dump"))
        self.assertGreater(last, fake.calls.index("statements"))

    def test_the_bundle_is_the_only_thing_left_on_disk(self):
        self.run_cli()
        self.assertEqual(self.leftovers(), ["source-profile.zip"])

    def test_the_bundle_holds_every_documented_entry(self):
        self.run_cli()
        self.assertEqual(
            sorted(self.archive()),
            [
                "manifest.json",
                "observations/foreign_keys.csv",
                "observations/pg_class.csv",
                "observations/pg_stat_indexes.csv",
                "observations/pg_stat_statements.csv",
                "observations/pg_stat_tables.csv",
                "observations/pg_stats.csv",
                "observations/pg_stats_ext.csv",
                "profile.json",
                "schema.sql",
            ],
        )

    def test_the_output_path_is_reported(self):
        self.run_cli()
        self.assertIn(str(self.output), self.stdout.getvalue())


class TestOrchestrationContent(OrchestrationCase):
    def setUp(self):
        super().setUp()
        self.run_cli()

    def test_the_source_records_the_server_it_profiled(self):
        source = self.manifest()["source"]
        self.assertEqual(source["kind"], "postgres")
        self.assertEqual(source["server_version_num"], 160002)
        self.assertEqual(source["server_version"], "16.2")
        self.assertEqual(source["database"], DATABASE)

    def test_the_source_records_the_schemas_actually_collected(self):
        self.assertEqual(self.manifest()["source"]["collected_schemas"], ["public", "sales"])

    def test_the_manifest_carries_the_verified_fingerprint(self):
        self.assertRegex(self.manifest()["schema_fingerprint"], r"\A[0-9a-f]{64}\Z")

    def test_the_manifest_carries_the_statistics_reset_time(self):
        self.assertEqual(self.manifest()["stats_reset"], golden("statements_reset").strip())

    def test_the_schema_dump_is_stored_verbatim(self):
        self.assertEqual(self.archive()["schema.sql"], SCHEMA_SQL.encode("utf-8"))

    def test_the_profile_carries_the_normalized_contract(self):
        profile = json.loads(self.archive()["profile.json"])
        self.assertEqual(profile["contract_version"], dbprofiler.CONTRACT_VERSION)
        self.assertEqual(len(profile["tables"]), 3)
        self.assertEqual(len(profile["relationships"]), 2)

    def test_every_payload_hash_in_the_manifest_matches_what_was_stored(self):
        entries = self.archive()
        for observation in self.manifest()["payloads"]:
            with self.subTest(path=observation["path"]):
                stored = hashlib.sha256(entries[observation["path"]]).hexdigest()
                self.assertEqual(stored, observation["sha256"])

    def test_a_clean_run_reports_no_warnings(self):
        self.assertEqual(self.manifest()["warnings"], [])


class TestOrchestrationScope(OrchestrationCase):
    def test_an_excluded_schema_is_left_out_of_the_bundle(self):
        self.run_cli(extra=["--schema-exclude", "sales"])
        self.assertEqual(self.manifest()["source"]["collected_schemas"], ["public"])
        profile = json.loads(self.archive()["profile.json"])
        self.assertEqual([t["schema"] for t in profile["tables"]], ["public", "public"])

    def test_an_included_schema_is_the_only_one_collected(self):
        self.run_cli(extra=["--schema-include", "sales"])
        self.assertEqual(self.manifest()["source"]["collected_schemas"], ["sales"])


class TestOrchestrationDegradation(OrchestrationCase):
    def test_a_missing_extension_warns_and_still_publishes(self):
        code, _ = self.run_cli(FakePostgres(statements_installed=""))
        self.assertEqual(code, 0)
        self.assertNotIn("observations/pg_stat_statements.csv", self.archive())
        self.assertIn(
            "pg_stat_statements_missing", [w["code"] for w in self.manifest()["warnings"]]
        )

    def test_an_unreadable_statistics_view_warns_and_still_publishes(self):
        code, _ = self.run_cli(FakePostgres(table_activity=denied("pg_stat_user_tables")))
        self.assertEqual(code, 0)
        self.assertNotIn("observations/pg_stat_tables.csv", self.archive())

    def test_degradations_are_reported_to_the_operator(self):
        self.run_cli(FakePostgres(statements_installed=""))
        self.assertIn("pg_stat_statements_missing", self.stderr.getvalue())


class TestOrchestrationFailures(OrchestrationCase):
    def expect_failure(self, fake=None, code=2, **kwargs):
        actual, fake = self.run_cli(fake, **kwargs)
        self.assertEqual(actual, code)
        self.assertEqual(self.leftovers(), [], "publication left something behind")
        self.assertNotIn("Traceback", self.stderr.getvalue())
        return fake

    def test_concurrent_ddl_prevents_publication(self):
        """The two fingerprints disagree, so the bundle would mix two versions
        of a schema."""
        drifted = golden("schema_fingerprint") + "public,new_table,r\n"
        self.expect_failure(FakePostgres(schema_fingerprint=[golden("schema_fingerprint"),
                                                            drifted]))
        self.assertIn("changed during collection", self.stderr.getvalue())

    def test_a_catalog_failure_prevents_publication(self):
        self.expect_failure(FakePostgres(columns=denied("pg_attribute")))

    def test_an_unreadable_schema_dump_prevents_publication(self):
        self.expect_failure(FakePostgres(pg_dump=completed(returncode=1, stderr="denied\n")))

    def test_an_empty_schema_dump_prevents_publication(self):
        """pg_dump exiting zero with nothing to say means the run collected no
        schema, which is not a bundle worth publishing."""
        self.expect_failure(FakePostgres(pg_dump="   \n"))

    def test_an_unsupported_server_version_prevents_publication(self):
        fake = self.expect_failure(FakePostgres(server_version="150004\n"))
        self.assertEqual(fake.calls, ["server_version"])

    def test_an_unsupported_layout_prevents_publication(self):
        partitioned = golden("tables") + "public,events,p,0,0\n"
        self.expect_failure(FakePostgres(tables=partitioned))

    def test_cancellation_prevents_publication(self):
        """SIGINT arrives as KeyboardInterrupt. Nothing half-written survives."""
        fake = self.expect_failure(FakePostgres(table_activity=KeyboardInterrupt()), code=130)
        self.assertEqual(fake.calls[-1], "table_activity")
        self.assertIn("cancelled", self.stderr.getvalue())

    def test_a_missing_tokenization_key_fails_before_connecting(self):
        """A key that is only discovered missing after collection wastes minutes
        of the operator's time and a full pass over the catalog."""
        fake = self.expect_failure(env={dbprofiler.TOKEN_KEY_ENV_VAR: ""})
        self.assertEqual(fake.calls, [])
        self.assertIn(dbprofiler.TOKEN_KEY_ENV_VAR, self.stderr.getvalue())

    def test_an_unusable_destination_fails_before_connecting(self):
        link = Path(self.directory.name) / "link.zip"
        link.symlink_to(Path(self.directory.name) / "elsewhere.zip")
        actual, fake = self.run_cli(output=link)
        self.assertEqual(actual, 2)
        self.assertEqual(fake.calls, [])
        self.assertIn("symlink", self.stderr.getvalue())

    def test_an_existing_bundle_survives_a_failed_run(self):
        self.output.write_bytes(b"previous bundle")
        actual, _ = self.run_cli(FakePostgres(columns=denied("pg_attribute")))
        self.assertEqual(actual, 2)
        self.assertEqual(self.output.read_bytes(), b"previous bundle")
        self.assertEqual(self.leftovers(), ["source-profile.zip"])


class TestOrchestrationSecrecy(OrchestrationCase):
    SECRETS = (URL, PASSWORD, USER, HOST, TOKEN_KEY)

    def assert_nothing_leaked(self):
        for stream, name in ((self.stderr, "stderr"), (self.stdout, "stdout")):
            for secret in self.SECRETS:
                with self.subTest(stream=name, secret=secret):
                    self.assertNotIn(secret, stream.getvalue())

    def test_a_successful_run_prints_no_connection_detail(self):
        self.run_cli()
        self.assert_nothing_leaked()

    def test_a_successful_run_writes_no_connection_detail_into_the_bundle(self):
        self.run_cli()
        published = zip_bytes(self.output)
        for secret in self.SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret.encode("utf-8"), published)

    def test_a_server_error_quoting_the_url_is_redacted(self):
        """psql echoes the connection string in some failures. Whatever it says
        passes through redaction before an operator or a log file sees it."""
        echoed = completed(returncode=2, stderr=f'could not connect to "{URL}"\n')
        self.run_cli(FakePostgres(server_version=echoed))
        self.assert_nothing_leaked()

    def test_a_server_error_quoting_the_password_is_redacted(self):
        echoed = completed(returncode=2, stderr=f"password={PASSWORD} rejected\n")
        self.run_cli(FakePostgres(tables=echoed))
        self.assert_nothing_leaked()

    def test_the_child_environment_carries_the_credentials_and_not_our_key(self):
        captured = {}
        fake = FakePostgres()

        def record(argv, **kwargs):
            captured.update(kwargs.get("env", {}))
            return fake(argv, **kwargs)

        with mock.patch.dict(
            "os.environ",
            {dbprofiler.URL_ENV_VAR: URL, dbprofiler.TOKEN_KEY_ENV_VAR: TOKEN_KEY},
            clear=True,
        ):
            with mock.patch("subprocess.run", side_effect=record):
                with contextlib.redirect_stderr(self.stderr):
                    with contextlib.redirect_stdout(self.stdout):
                        dbprofiler.main(["postgres", "--output", str(self.output)])
        self.assertEqual(captured["PGPASSWORD"], PASSWORD)
        self.assertNotIn(dbprofiler.TOKEN_KEY_ENV_VAR, captured)
        self.assertNotIn(dbprofiler.URL_ENV_VAR, captured)

    def test_no_credential_reaches_a_child_command_line(self):
        seen = []
        fake = FakePostgres()

        def record(argv, **kwargs):
            seen.append(" ".join(argv))
            return fake(argv, **kwargs)

        with mock.patch.dict(
            "os.environ",
            {dbprofiler.URL_ENV_VAR: URL, dbprofiler.TOKEN_KEY_ENV_VAR: TOKEN_KEY},
            clear=True,
        ):
            with mock.patch("subprocess.run", side_effect=record):
                with contextlib.redirect_stderr(self.stderr):
                    with contextlib.redirect_stdout(self.stdout):
                        dbprofiler.main(["postgres", "--output", str(self.output)])
        for line in seen:
            for secret in self.SECRETS:
                with self.subTest(secret=secret):
                    self.assertNotIn(secret, line)


class TestCLI(unittest.TestCase):
    def test_no_subcommand_prints_help_and_returns_two(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(dbprofiler.main([]), 2)
        self.assertIn("usage:", stderr.getvalue())

    def test_postgres_subcommand_requires_output(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            dbprofiler.main(["postgres"])
        self.assertNotEqual(raised.exception.code, 0)

    def test_config_errors_exit_nonzero_without_a_traceback(self):
        stderr = io.StringIO()
        with mock.patch.dict("os.environ", {}, clear=True):
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(dbprofiler.main(["postgres", "--output", "p.zip"]), 2)
        self.assertIn("DBPROFILER_POSTGRES_URL", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_an_output_that_is_not_a_zip_is_rejected(self):
        stderr = io.StringIO()
        with mock.patch.dict("os.environ", {dbprofiler.URL_ENV_VAR: URL}, clear=True):
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(dbprofiler.main(["postgres", "--output", "profile.tar"]), 2)
        self.assertIn(".zip", stderr.getvalue())


REPO = Path(__file__).resolve().parent
COMPOSE_FILE = REPO / "docker-compose.postgres-test.yml"
COMPOSE_INIT_SQL = REPO / "testdata" / "postgres-test-init.sql"
TESTING_DOC = REPO / "docs" / "TESTING.md"
ENV_FILE = ".env.test.local"


GIT = shutil.which("git")


def git(*args):
    """Run git in this repository, or return None if that is not possible.

    Absolute path because a relative one resolves against PATH at call time;
    these tests also run in CI, where being precise about which binary answers
    a question about what is committed is worth one lookup.
    """
    if GIT is None:
        return None
    done = subprocess.run([GIT, "-C", str(REPO), *args], capture_output=True, text=True)
    return None if done.returncode == 128 else done


def tracked_files():
    """Everything git would ship, or None outside a work tree."""
    done = git("ls-files", "-z")
    if done is None or done.returncode != 0:
        return None
    return [name for name in done.stdout.split("\0") if name]


class TestComposeSecrecy(unittest.TestCase):
    """The Docker environment is committed; the credentials it uses are not.

    docker-compose.postgres-test.yml is readable by anyone who can read this
    public repository. Everything secret in it has to arrive by substitution
    from the gitignored .env.test.local, and nothing may hardcode a value that
    a reader could mistake for a real one.
    """

    def setUp(self):
        self.text = COMPOSE_FILE.read_text()

    def test_the_compose_file_holds_no_connection_string(self):
        self.assertNotIn("://", self.text)

    def test_the_compose_file_holds_no_token_key(self):
        # The HMAC key belongs to the tool, not the server. If it appeared here
        # it would also be handed to the container for no reason.
        self.assertNotIn("DBPROFILER_TOKEN_KEY", self.text)

    def test_every_credential_field_is_a_substitution(self):
        for key in ("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB"):
            line = next(
                stripped
                for stripped in (raw.strip() for raw in self.text.splitlines())
                if stripped.startswith(key + ":")
            )
            value = line.split(":", 1)[1].strip()
            self.assertTrue(
                value.startswith("${") and value.endswith("}"),
                f"{key} must come from .env.test.local, got {value!r}",
            )

    def test_no_substitution_carries_a_default_value(self):
        """${VAR:-fallback} would start a server with credentials nobody chose."""
        for match in re.finditer(r"\$\{([^}]*)\}", self.text):
            self.assertNotIn(":-", match.group(1))
            self.assertNotIn("-", match.group(1).split(":?")[0])

    def test_the_published_port_is_loopback_only(self):
        published = [
            raw.strip().lstrip("- ").strip('"')
            for raw in self.text.splitlines()
            if ":5432\"" in raw
        ]
        self.assertTrue(published, "expected a published port")
        for mapping in published:
            self.assertTrue(
                mapping.startswith("127.0.0.1:"),
                f"port must bind to loopback, got {mapping!r}",
            )

    def test_pg_stat_statements_is_preloaded(self):
        # Otherwise the integration test silently exercises the degraded path.
        self.assertIn("shared_preload_libraries=pg_stat_statements", self.text)
        self.assertIn("CREATE EXTENSION", COMPOSE_INIT_SQL.read_text())

    def test_the_env_file_is_ignored_by_git(self):
        done = git("check-ignore", ENV_FILE)
        if done is None:
            self.skipTest("git unavailable, or not a work tree")
        self.assertEqual(done.returncode, 0, f"{ENV_FILE} is not gitignored")

    def test_no_env_file_is_tracked(self):
        """Not even an example one. An example env file is where a real URL

        eventually gets pasted, and the reviewer reading the diff has no way to
        tell that the value in it was meant to be fake.
        """
        tracked = tracked_files()
        if tracked is None:
            self.skipTest("not a git work tree")
        self.assertEqual([name for name in tracked if Path(name).name.startswith(".env")], [])

    def test_the_testing_doc_holds_no_credentialed_url(self):
        for line in TESTING_DOC.read_text().splitlines():
            self.assertNotRegex(line, r"://[^/\s]*:[^/\s]*@")


# --- the integration suite's blast radius -----------------------------------
#
# integration_test.py is the one file in this repository allowed to issue DDL,
# DML, ANALYZE and CREATE STATISTICS. It runs against whatever server the
# operator pointed it at, which will not always be the disposable container.
# Reviewing that boundary by eye every time it changes is not a control; these
# are. They read the file rather than run it, so they need no server.

INTEGRATION_TEST = REPO / "integration_test.py"

# Anything that changes the server. PERFORM and SELECT are deliberately absent:
# a read needs no schema qualification to be harmless.
MUTATING_SQL = re.compile(
    r"\b(CREATE|DROP|ALTER|INSERT|UPDATE|DELETE|TRUNCATE|ANALYZE|VACUUM|REINDEX"
    r"|GRANT|REVOKE|COPY|SET|RESET)\b"
)


def sql_of(call):
    """Reconstruct the SQL text of an execute(...) call, or None.

    Unannotated, like the other helpers here: this file has no
    `from __future__ import annotations`, so on 3.9 a `str | None` in a
    signature is evaluated at import and raises.

    Interpolations become the placeholder the source wrote -- `{SCHEMA}` stays
    `{SCHEMA}` -- so a statement can be checked for the schema qualification
    without evaluating anything.
    """
    if not (isinstance(call.func, ast.Name) and call.func.id == "execute"):
        return None
    if not call.args:
        return None
    parts = []
    for node in ast.walk(call.args[0]):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            parts.append(node.value)
        elif isinstance(node, ast.FormattedValue):
            inner = node.value
            parts.append("{" + (inner.id if isinstance(inner, ast.Name) else "...") + "}")
    return "".join(parts)


class TestIntegrationSuiteScope(unittest.TestCase):
    def setUp(self):
        self.text = INTEGRATION_TEST.read_text()
        self.tree = ast.parse(self.text, filename=str(INTEGRATION_TEST))

    def statements(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                sql = sql_of(node)
                if sql:
                    yield sql

    def test_the_offline_suite_does_not_discover_it(self):
        """`python3 -m unittest` must open no sockets. Discovery's default
        pattern is test*.py, and this file is named so it does not match --
        which is load-bearing, not cosmetic."""
        self.assertFalse(fnmatch.fnmatch(INTEGRATION_TEST.name, "test*.py"))

    def test_every_mutating_statement_names_the_disposable_schema(self):
        checked = 0
        for sql in self.statements():
            if not MUTATING_SQL.search(sql):
                continue
            checked += 1
            with self.subTest(sql=" ".join(sql.split())[:70]):
                self.assertIn("{SCHEMA}", sql)
        self.assertGreater(checked, 0, "expected the fixture DDL to be found")

    def test_the_schema_name_is_unique_per_run(self):
        """Two people testing against one server, or one person whose previous
        run died before its teardown, must not collide."""
        self.assertRegex(self.text, r"SCHEMA\s*=\s*f\"dbprofiler_it_.*uuid")

    def test_the_schema_is_dropped_on_every_exit(self):
        """Including the failure path. A fixture schema left on a shared server
        is the worst thing this suite can do."""
        callers = set()
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for inner in ast.walk(node):
                if (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Name)
                    and inner.func.id == "drop_fixtures"
                ):
                    callers.add(node.name)
        self.assertIn("tearDownModule", callers)
        self.assertIn("setUpModule", callers)

    def test_it_holds_no_credentialed_url(self):
        for line in self.text.splitlines():
            self.assertNotRegex(line, r"://[^/\s]*:[^/\s]*@")

    def test_it_invents_no_new_token_key(self):
        """Only the synthetic keys the rules fix, so a reviewer grepping for a
        leaked key can tell test data from the real thing."""
        found = set(re.findall(r"\"(example-token-key-[0-9]+)\"", self.text))
        self.assertEqual(found, {"example-token-key-0123456789", "example-token-key-9876543210"})
        self.assertEqual(re.findall(r"\btoken_key\s*=\s*\"", self.text), [])

    def test_it_reads_the_connection_string_only_from_the_environment(self):
        self.assertNotIn("--url", self.text)
        self.assertIn("os.environ[TEST_URL_ENV_VAR]", self.text)

    def test_it_never_prints_a_configured_value(self):
        """The skip reason names the variables; it must not carry their values."""
        self.assertNotRegex(self.text, r"WHY_SKIPPED\s*=.*os\.getenv")
        self.assertNotRegex(self.text, r"print\(")


# --- release plumbing -------------------------------------------------------
#
# What a customer downloads is what a reviewer read. These tests exist to keep
# that sentence true: the release workflow publishes the tagged file unmodified,
# refuses to publish one that has not passed the safety audit, and refuses to
# publish under a tag the file does not claim.

RELEASE_WORKFLOW = REPO / ".github" / "workflows" / "release.yaml"
SCRIPT_NAME = "dbprofiler.py"
CHECKSUM_NAME = "dbprofiler.py.sha256"


class TestReleaseWorkflow(unittest.TestCase):
    def setUp(self):
        self.text = RELEASE_WORKFLOW.read_text()
        self.lines = self.text.splitlines()

    def index_of(self, needle):
        for number, line in enumerate(self.lines):
            if needle in line:
                return number
        raise AssertionError(f"{needle!r} not found in {RELEASE_WORKFLOW.name}")

    def test_it_triggers_on_version_tags_only(self):
        self.assertRegex(self.text, r"tags:\s*\[\s*[\"']v\*[\"']\s*\]")
        self.assertNotIn("branches:", self.text)
        self.assertNotIn("workflow_dispatch", self.text)

    def test_nothing_ships_before_the_safety_audit(self):
        """A release is the one moment the boundary stops being reviewable by
        reading the repository, so the audit gates it."""
        self.assertLess(self.index_of("--check-safety"), self.index_of("gh release create"))
        self.assertLess(self.index_of("unittest"), self.index_of("gh release create"))

    def test_the_tag_must_agree_with_the_version_in_the_script(self):
        """Publishing v1.2.0 from a file that reports 1.1.0 would put the wrong
        tool_version in every manifest produced by that download."""
        self.assertIn("--version", self.text)
        self.assertIn("GITHUB_REF_NAME", self.text)
        self.assertLess(
            self.index_of("GITHUB_REF_NAME"), self.index_of("gh release create")
        )

    def test_the_checksum_is_taken_over_the_script_and_verified(self):
        self.assertIn(f"sha256sum {SCRIPT_NAME} > {CHECKSUM_NAME}", self.text)
        self.assertIn(f"sha256sum -c {CHECKSUM_NAME}", self.text)

    def test_both_assets_are_uploaded(self):
        publish = self.lines[self.index_of("gh release create"):]
        uploaded = "\n".join(publish)
        self.assertIn(SCRIPT_NAME, uploaded)
        self.assertIn(CHECKSUM_NAME, uploaded)

    def test_the_published_file_is_the_tagged_file(self):
        """No step may rewrite the script on its way out. The download has to be
        byte-identical to what is in the tag, or reading the repository tells a
        reviewer nothing about what they ran."""
        for rewrite in (r"sed\s+-i", r"tee\s+dbprofiler\.py", r"\bpatch\b", r"\bapply\b"):
            self.assertNotRegex(self.text, rewrite)
        # A redirect onto the script itself. The negative lookahead spares
        # `> dbprofiler.py.sha256`, which is the checksum, not the script.
        self.assertNotRegex(self.text, r">>?\s*dbprofiler\.py(?!\.)")

    def test_provenance_is_attested(self):
        self.assertIn("actions/attest-build-provenance@", self.text)
        self.assertIn("id-token: write", self.text)
        self.assertIn("attestations: write", self.text)

    def test_write_permission_is_scoped_to_the_publishing_job(self):
        """Default read-only at the top of the file, widened only where the
        release is actually created."""
        jobs = self.index_of("jobs:")
        self.assertIn("contents: read", "\n".join(self.lines[:jobs]))
        self.assertNotIn("contents: write", "\n".join(self.lines[:jobs]))
        self.assertIn("contents: write", "\n".join(self.lines[jobs:]))

    def test_it_uses_no_secret_beyond_the_workflow_token(self):
        """A single-file tool needs no signing key and no registry credential.
        Anything referencing secrets. here would be a new thing to trust."""
        self.assertNotIn("secrets.", self.text)
        self.assertIn("github.token", self.text)

    def test_every_action_is_pinned_to_a_major_version(self):
        for match in re.finditer(r"uses:\s*(\S+)", self.text):
            with self.subTest(action=match.group(1)):
                self.assertRegex(match.group(1), r"@v\d+$")

    def test_the_readme_documents_the_flow_it_actually_publishes(self):
        readme = (REPO / "README.md").read_text()
        self.assertIn(f"releases/latest/download/{SCRIPT_NAME}", readme)
        self.assertIn(f"releases/latest/download/{CHECKSUM_NAME}", readme)
        self.assertIn(f"sha256sum -c {CHECKSUM_NAME}", readme)


if __name__ == "__main__":
    unittest.main()
