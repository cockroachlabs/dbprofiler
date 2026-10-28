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

import argparse
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

    def test_contract_version_is_2_0(self):
        self.assertEqual(dbprofiler.CONTRACT_VERSION, "2.0")

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
        """The connection URL carries a password, and a child's environment is
        readable by anything that can see the process."""
        with mock.patch.dict(
            "os.environ",
            {"DBPROFILER_POSTGRES_URL": URL, "DBPROFILER_ANYTHING": "example-value"},
            clear=True,
        ):
            env = dbprofiler.safe_env(a_config())
        self.assertNotIn("DBPROFILER_POSTGRES_URL", env)
        self.assertNotIn("DBPROFILER_ANYTHING", env)

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

    def test_a_field_past_the_csv_default_limit_survives_parsing(self):
        """`csv` caps a single field at 128 KiB unless told otherwise, and a
        statistics array goes well past that: ANALYZE caps an individual value
        at about 1 KiB, but it collects `statistics_target` of them, and that
        target can be raised to 10000. Publishing values verbatim rather than as
        fixed-width digests is what made this reachable.
        """
        cell = "{" + ",".join("x" * 1000 for _ in range(200)) + "}"
        out = 'public,users,email,"' + cell + '"\n'
        self.assertGreater(len(cell), 131072, "fixture must exceed the default cap")
        with mock.patch("subprocess.run", return_value=completed(stdout=out)):
            rows = dbprofiler.run_psql("SELECT 1", a_config())
        self.assertEqual(rows, [["public", "users", "email", cell]])

    def test_the_csv_field_limit_is_raised_portably(self):
        """`sys.maxsize` is the usual idiom and overflows the C long behind this
        limit on 64-bit Windows, where a long is 32 bits."""
        self.assertGreaterEqual(csv.field_size_limit(), 2**31 - 1)

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


def golden_sql(name):
    """Read a recorded pg_dump fixture."""
    return (GOLDEN / f"{name}.sql").read_text(encoding="utf-8")


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
    "index_columns",
    "sequences",
    "database_collation",
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
            "SQL_DATABASE_COLLATION",
            "SQL_EXTENDED_STATS",
            "SQL_FOREIGN_KEYS",
            "SQL_INDEXES",
            "SQL_INDEX_COLUMNS",
            "SQL_INHERITED",
            "SQL_SEQUENCES",
        ):
            with self.subTest(name=name):
                self.assertIsInstance(getattr(dbprofiler, name), str)

    def test_pg_inherits_is_on_the_allowlist(self):
        # Added in the same change as the collector that reads it.
        self.assertIn("pg_inherits", dbprofiler.ALLOWED_RELATIONS)

    def test_the_ordering_collectors_relations_are_on_the_allowlist(self):
        """Each of these earns its place with the collector added beside it:
        pg_index for key order, pg_opclass for the operator class, pg_collation
        for the collation the order is taken under, pg_sequence for the key
        stream, pg_attrdef for the DEFAULT expression that drives it."""
        for relation in (
            "pg_attrdef",
            "pg_collation",
            "pg_index",
            "pg_opclass",
            "pg_sequence",
        ):
            with self.subTest(relation=relation):
                self.assertIn(relation, dbprofiler.ALLOWED_RELATIONS)

    def test_the_ordering_collectors_actually_read_what_they_allowlisted(self):
        """The allowlist grants a permission; a grant with no collector behind it
        is a permission nobody reviewed the use of."""
        read = set()
        for _, sql in dbprofiler.iter_sql_constants():
            for match in dbprofiler.RELATION_REFERENCE.finditer(sql):
                if not match.group(2):
                    read.add(match.group(1).lower().split(".")[-1])
        for relation in ("pg_attrdef", "pg_collation", "pg_opclass", "pg_sequence"):
            with self.subTest(relation=relation):
                self.assertIn(relation, read)

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

    def test_tables_carry_the_page_count_and_whether_they_toast(self):
        """size_bytes is the total including indexes and TOAST, so it cannot say
        how densely the heap itself is packed. relpages can."""
        catalog = self.collect()
        by_name = {t.name: t for t in catalog.tables}
        self.assertEqual(by_name["users"].relpages, 20)
        self.assertTrue(by_name["users"].has_toast)
        self.assertFalse(by_name["orders"].has_toast)

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

    def test_columns_carry_their_collation(self):
        """Two text columns with identical histogram bounds sort differently
        under 'C' and under 'en_US.UTF-8'. The bounds do not say which."""
        catalog = self.collect()
        by_name = {(c.table, c.name): c for c in catalog.columns}
        self.assertEqual(by_name[("users", "email")].collation, "default")
        self.assertIsNone(by_name[("users", "id")].collation)

    def test_columns_carry_their_default_and_identity(self):
        """A sequential default is what makes a key monotonically increasing,
        and an identity column's default is not in pg_attrdef at all."""
        catalog = self.collect()
        by_name = {(c.table, c.name): c for c in catalog.columns}
        self.assertIn("nextval", by_name[("orders", "id")].default_expression)
        self.assertIsNone(by_name[("orders", "id")].identity)
        self.assertEqual(by_name[("users", "id")].identity, "always")
        self.assertEqual(by_name[("invoices", "id")].identity, "by default")
        self.assertIsNone(by_name[("users", "email")].default_expression)

    def test_a_lowered_statistics_target_is_recorded(self):
        """A column analyzed at a lower target has a coarser histogram than the
        rest of the profile, and nothing else in the bundle would say so."""
        catalog = self.collect()
        by_name = {(c.table, c.name): c for c in catalog.columns}
        self.assertEqual(by_name[("orders", "placed_at")].stats_target, 250)
        self.assertEqual(
            by_name[("orders", "user_id")].stats_target, dbprofiler.DEFAULT_STATS_TARGET
        )

    def test_the_database_collation_is_collected(self):
        catalog = self.collect()
        self.assertEqual(catalog.collate, "en_US.UTF-8")
        self.assertEqual(catalog.ctype, "en_US.UTF-8")

    def test_column_statistics_are_kept_separate_from_columns(self):
        """Statistics hold the source's own values and its own encodings. They
        stay in their own records so normalization has one place to look."""
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

    def test_correlation_is_collected(self):
        """Correlation is what says whether an index scan over this column reads
        sequentially or jumps, and it is not derivable from anything else here."""
        catalog = self.collect()
        stats = {(s.table, s.column): s for s in catalog.column_stats}
        self.assertEqual(stats[("orders", "placed_at")].correlation, 0.99)
        self.assertEqual(stats[("users", "email")].correlation, 0.02)
        self.assertEqual(stats[("users", "legacy_balance")].correlation, -0.1)

    def test_an_absent_correlation_is_none_and_not_zero(self):
        # Zero is a real correlation, meaning no physical ordering at all. It is
        # not the same claim as "PostgreSQL did not compute one".
        catalog = self.collect()
        stat = next(s for s in catalog.column_stats if s.table == "invoices")
        self.assertIsNone(stat.correlation)

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

    def test_extended_mcv_combinations_are_collected_with_both_frequencies(self):
        """Which combinations are hot is what single-column statistics cannot
        express, and the base frequency beside it is the independence assumption
        the extended statistics object exists to correct."""
        catalog = self.collect()
        extended = catalog.extended_stats[0]
        self.assertEqual(
            extended.most_common_vals, ("{1,2026-01-01}", "{2,2026-06-01}")
        )
        self.assertEqual(extended.most_common_freqs, (0.08, 0.03))
        self.assertEqual(extended.most_common_base_freqs, (0.02, 0.01))

    def test_indexes_are_collected_with_uniqueness_and_primary_flags(self):
        catalog = self.collect()
        pkey = next(i for i in catalog.indexes if i.name == "users_pkey")
        self.assertTrue(pkey.is_unique)
        self.assertTrue(pkey.is_primary)
        plain = next(i for i in catalog.indexes if i.name == "orders_user_id_idx")
        self.assertFalse(plain.is_unique)

    def test_index_shape_flags_are_collected(self):
        """Partial, expression-based, invalid and clustered are all visible in
        schema.sql only as DDL a consumer would have to parse."""
        catalog = self.collect()
        by_name = {i.name: i for i in catalog.indexes}
        self.assertTrue(by_name["users_pkey"].is_clustered)
        self.assertTrue(by_name["orders_lower_ref_idx"].is_partial)
        self.assertTrue(by_name["orders_lower_ref_idx"].has_expressions)
        self.assertFalse(by_name["orders_pkey"].is_partial)
        self.assertTrue(by_name["orders_pkey"].is_valid)

    def test_an_include_column_is_counted_but_is_not_a_key(self):
        catalog = self.collect()
        index = next(i for i in catalog.indexes if i.name == "orders_user_id_idx")
        self.assertEqual(index.key_attribute_count, 2)
        self.assertEqual(index.attribute_count, 3)

    def test_index_key_columns_keep_their_declared_order(self):
        catalog = self.collect()
        keys = [
            entry
            for entry in catalog.index_columns
            if entry.index == "orders_user_id_idx"
        ]
        self.assertEqual([k.position for k in keys], [1, 2, 3])
        self.assertEqual([k.name for k in keys], ["user_id", "placed_at", "id"])

    def test_an_include_column_has_no_sort_direction(self):
        """indoption holds only indnkeyatts entries, so the subscript runs off
        the end for a payload column and PostgreSQL yields NULL. Absent, not
        ascending."""
        catalog = self.collect()
        payload = next(
            entry
            for entry in catalog.index_columns
            if entry.index == "orders_user_id_idx" and entry.position == 3
        )
        self.assertIsNone(payload.option_bits)
        self.assertFalse(payload.is_key)

    def test_an_expression_key_has_a_position_but_no_column_name(self):
        catalog = self.collect()
        key = next(
            entry for entry in catalog.index_columns if entry.index == "orders_lower_ref_idx"
        )
        self.assertEqual(key.position, 1)
        self.assertIsNone(key.name)
        self.assertEqual(key.collation, "C")

    def test_sequences_are_collected_with_their_parameters(self):
        """A sequence-backed key is the classic monotonically increasing index
        key; start and increment are what reproduce the same key stream."""
        catalog = self.collect()
        sequence = catalog.sequences[0]
        self.assertEqual((sequence.schema, sequence.name), ("public", "orders_id_seq"))
        self.assertEqual(sequence.start, 1)
        self.assertEqual(sequence.increment, 1)
        self.assertEqual(sequence.maximum, 9223372036854775807)
        self.assertFalse(sequence.cycles)

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
        self.assertNotIn("sales", {i.schema for i in catalog.index_columns})


class TestUnsupportedLayouts(unittest.TestCase):
    """Partitioning and inheritance change row-count and fan-out arithmetic in
    ways the MVP does not model. Failing loudly beats publishing a wrong number."""

    def test_a_partitioned_table_is_rejected(self):
        rows = "public,events,p,0,0,0,f\n"
        with mock.patch("subprocess.run", side_effect=catalog_calls(tables=rows)):
            with self.assertRaises(dbprofiler.UnsupportedObject) as raised:
                dbprofiler.collect_catalog(a_config())
        self.assertIn("events", str(raised.exception))

    def test_a_partitioned_index_relkind_is_rejected(self):
        rows = "public,events,I,0,0,0,f\n"
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
        rows = "public,events,p,0,0,0,f\n"
        calls = catalog_calls(tables=rows)
        with mock.patch("subprocess.run", side_effect=calls) as run:
            with self.assertRaises(dbprofiler.UnsupportedObject):
                dbprofiler.collect_catalog(a_config())
        self.assertEqual(run.call_count, 2)

    def test_an_out_of_scope_partitioned_table_does_not_fail_the_run(self):
        rows = golden("tables") + "archive,events,p,0,0,0,f\n"
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


def a_catalog(**overrides):
    """The golden catalog, collected once and reused across normalization tests."""
    with mock.patch("subprocess.run", side_effect=catalog_calls(**overrides)):
        return dbprofiler.collect_catalog(a_config())


class NormalizationCase(unittest.TestCase):
    def setUp(self):
        self.catalog = a_catalog()
        self.tables = dbprofiler.normalize_tables(self.catalog)
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
        self.assertEqual(profile.most_common_values, ())
        self.assertIsNone(profile.correlation)
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


class TestNormalizedValues(NormalizationCase):
    """The statistics are published as PostgreSQL computed them.

    Ordering, spacing and skew are the signal a downstream generator replays,
    so a value-preserving transform is not enough: the values themselves have
    to survive.
    """

    def test_most_common_values_are_carried_through_verbatim(self):
        user_id = self.column("public", "orders", "user_id")
        self.assertEqual(user_id.most_common_values, ("1", "2", "3"))

    def test_frequencies_stay_positionally_paired_with_their_values(self):
        user_id = self.column("public", "orders", "user_id")
        self.assertEqual(user_id.most_common_freqs, (0.1, 0.05, 0.02))
        self.assertEqual(len(user_id.most_common_values), len(user_id.most_common_freqs))

    def test_histogram_bounds_keep_their_ascending_order(self):
        bounds = self.column("public", "users", "id").histogram_bounds
        self.assertEqual(bounds, ("1", "250", "500", "750", "1000"))

    def test_a_text_histogram_survives_as_text(self):
        # Bounds are sorted under the database collation, not as bytes, which
        # is why Source carries datcollate alongside them.
        bounds = self.column("public", "users", "email").histogram_bounds
        self.assertEqual(bounds, ("alpha@example.invalid", "zulu@example.invalid"))

    def test_correlation_is_carried_through_with_its_sign(self):
        self.assertEqual(self.column("public", "users", "id").correlation, 0.98)
        self.assertEqual(self.column("public", "users", "legacy_balance").correlation, -0.1)

    def test_a_missing_correlation_is_absent_rather_than_zero(self):
        """Zero correlation is a claim about physical order. A column PostgreSQL
        recorded nothing for has to say nothing."""
        self.assertIsNone(self.column("sales", "invoices", "order_id").correlation)

    def test_column_provenance_explains_what_the_numbers_are_relative_to(self):
        provenance = self.column("public", "orders", "user_id").provenance
        self.assertIn("most_common_freqs", provenance)
        self.assertIn("correlation", provenance)


class TestNormalizeColumnShape(NormalizationCase):
    """The declarations a generator needs in order to recreate the column."""

    def test_a_collation_is_recorded_where_one_applies(self):
        self.assertEqual(self.column("public", "users", "email").collation, "default")
        self.assertIsNone(self.column("public", "users", "id").collation)

    def test_a_column_default_is_carried_as_its_expression(self):
        self.assertEqual(
            self.column("public", "orders", "id").default_expression,
            "nextval('public.orders_id_seq'::regclass)",
        )
        self.assertEqual(self.column("public", "orders", "placed_at").default_expression, "now()")
        self.assertIsNone(self.column("public", "users", "email").default_expression)

    def test_an_identity_column_reports_its_kind(self):
        """An identity column has no pg_attrdef row, so without this it would
        look like a column with no default at all."""
        self.assertEqual(self.column("public", "users", "id").identity, "always")
        self.assertEqual(self.column("sales", "invoices", "id").identity, "by default")
        self.assertIsNone(self.column("public", "orders", "id").identity)

    def test_a_raised_statistics_target_is_reported_and_the_default_is_not(self):
        # -1 means "use default_statistics_target", which is a server setting
        # and not a property of the column.
        self.assertEqual(self.column("public", "orders", "placed_at").statistics_target, 250)
        self.assertIsNone(self.column("public", "users", "id").statistics_target)


class TestNormalizeTableStorage(NormalizationCase):
    def test_page_count_is_separate_from_total_size(self):
        """relpages covers the main fork; pg_total_relation_size covers indexes
        and TOAST too. A sizing estimate that conflated them would be wrong by
        whatever the indexes cost."""
        users = self.by_table[("public", "users")]
        self.assertEqual(users.page_count, 20)
        self.assertEqual(users.size_bytes, 163840)

    def test_a_toast_relation_is_reported(self):
        self.assertTrue(self.by_table[("public", "users")].has_toast)
        self.assertFalse(self.by_table[("public", "orders")].has_toast)

    def test_table_provenance_names_the_page_size(self):
        self.assertIn("8192", self.by_table[("public", "users")].provenance)


class TestNormalizeIndexes(unittest.TestCase):
    def setUp(self):
        self.indexes = dbprofiler.normalize_indexes(a_catalog())
        self.by_name = {i.name: i for i in self.indexes}

    def test_indexes_are_sorted_deterministically(self):
        self.assertEqual(
            [(i.schema, i.table, i.name) for i in self.indexes],
            sorted((i.schema, i.table, i.name) for i in self.indexes),
        )

    def test_key_columns_keep_their_declared_order(self):
        index = self.by_name["orders_user_id_idx"]
        self.assertEqual([c.name for c in index.columns], ["user_id", "placed_at", "id"])
        self.assertEqual([c.position for c in index.columns], [1, 2, 3])

    def test_a_descending_nulls_first_key_is_decoded_from_indoption(self):
        """indoption is a bitmask. Publishing the integer would make every
        consumer reimplement this decode, and one of them would get it wrong."""
        placed_at = self.by_name["orders_user_id_idx"].columns[1]
        self.assertTrue(placed_at.descending)
        self.assertTrue(placed_at.nulls_first)

    def test_an_ascending_key_defaults_to_nulls_last(self):
        user_id = self.by_name["orders_user_id_idx"].columns[0]
        self.assertFalse(user_id.descending)
        self.assertFalse(user_id.nulls_first)

    def test_an_include_column_is_marked_as_payload_not_key(self):
        """An INCLUDE column is stored but not ordered on, so it cannot satisfy
        a range scan. Reporting it as a key would overstate what the index does."""
        columns = self.by_name["orders_user_id_idx"].columns
        self.assertEqual([c.is_key for c in columns], [True, True, False])

    def test_an_include_column_has_no_direction_of_its_own(self):
        # Its indoption subscript runs past indnkeyatts and arrives as NULL.
        payload = self.by_name["orders_user_id_idx"].columns[2]
        self.assertFalse(payload.descending)
        self.assertFalse(payload.nulls_first)
        self.assertIsNone(payload.operator_class)

    def test_an_expression_key_has_no_column_name(self):
        index = self.by_name["orders_lower_ref_idx"]
        self.assertTrue(index.has_expressions)
        self.assertIsNone(index.columns[0].name)
        self.assertEqual(index.columns[0].collation, "C")

    def test_operator_class_is_recorded_per_key(self):
        self.assertEqual(self.by_name["users_pkey"].columns[0].operator_class, "int8_ops")

    def test_uniqueness_primacy_and_validity_are_carried_through(self):
        pkey = self.by_name["users_pkey"]
        self.assertTrue(pkey.is_unique)
        self.assertTrue(pkey.is_primary)
        self.assertTrue(pkey.is_valid)

    def test_clustering_is_recorded(self):
        """CLUSTER is what pg_stats.correlation is measuring against, so the two
        have to be readable together."""
        self.assertTrue(self.by_name["users_pkey"].is_clustered)
        self.assertFalse(self.by_name["orders_pkey"].is_clustered)

    def test_a_partial_index_is_flagged(self):
        self.assertTrue(self.by_name["orders_lower_ref_idx"].is_partial)
        self.assertFalse(self.by_name["users_pkey"].is_partial)

    def test_index_provenance_points_at_the_schema_for_the_predicate(self):
        self.assertIn("schema.sql", self.by_name["orders_lower_ref_idx"].provenance)


class TestNormalizeSequences(unittest.TestCase):
    def setUp(self):
        self.sequences = dbprofiler.normalize_sequences(a_catalog())

    def test_sequence_parameters_are_carried_through(self):
        sequence = self.sequences[0]
        self.assertEqual((sequence.schema, sequence.name), ("public", "orders_id_seq"))
        self.assertEqual(sequence.start, 1)
        self.assertEqual(sequence.increment, 1)
        self.assertEqual(sequence.minimum, 1)
        self.assertEqual(sequence.cache, 1)
        self.assertFalse(sequence.cycles)

    def test_a_bigint_bound_survives_exactly(self):
        """bigint's maximum does not fit a float64. Routing it through one
        returns a number one larger than the sequence will ever reach."""
        self.assertEqual(self.sequences[0].maximum, 9223372036854775807)


class TestNormalizeRelationships(unittest.TestCase):
    def setUp(self):
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
        stats = "public,orders,user_id,0.5,8,500,,,,0.15\n"
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
        stats = "public,orders,user_id,0,8,0,,,,0.15\n"
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
            'public,orders,orders_other_stx,"{id,placed_at}","{""1, 3"": 900}",,,\n'
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
        return dbprofiler.build_profile(source, catalog, workload)

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
            dbprofiler.Source("postgres", 160002, "16.2", DATABASE), catalog, workload
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

SCHEMA_SQL = golden_sql("schema_dump")

# The same dump regrouped. Recorded rather than recomputed: asserting the
# payload against render_schema_by_table() applied to the same input would pass
# no matter what the renderer did.
SCHEMA_BY_TABLE_SQL = golden_sql("schema_by_table")

# A dump of a declarative partition hierarchy: range and list parents, a
# default partition, a partition attached after the fact, a sub-partitioned
# child, and a partitioned index. require_supported_layout refuses to profile
# a source containing any of it, so the integration test cannot reach these
# shapes -- but a dump handed to the renderer still can, and a release that
# lifts that restriction should not also have to rediscover the ordering
# rules. Recorded from PostgreSQL 16, which also makes this the one fixture
# carrying pg_dump's \restrict wrapper.
SCHEMA_PARTITIONED_SQL = golden_sql("schema_partitioned_dump")
SCHEMA_PARTITIONED_BY_TABLE_SQL = golden_sql("schema_partitioned_by_table")

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
        self.catalog = a_catalog()
        self.workload = a_workload()
        self.profile = dbprofiler.build_profile(a_source(), self.catalog, self.workload)
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


# --- schema regrouping -----------------------------------------------------

SECTION_TITLE = re.compile(r"^-- ={20} (.*?) ={20}$", re.MULTILINE)
TABLE_SECTION_TITLE = re.compile(r"^-- ={20} TABLE: (\S+) ={20}$", re.MULTILINE)
INLINE_FK = re.compile(
    r"^ALTER TABLE ONLY ([\w.\"]+)\n"
    r"    ADD CONSTRAINT ([\w\"]+) FOREIGN KEY \([^)]*\) REFERENCES ([\w\"]+)\.([\w\"]+)",
    re.MULTILINE,
)


def sql_lines(text):
    """Every non-comment, non-blank line, whitespace-normalized and sorted.

    A multiset rather than a sequence: the regrouping reorders statements on
    purpose, so order is what the other assertions check. What this one catches
    is a statement the transform dropped, duplicated, or rewrote.
    """
    return sorted(
        " ".join(line.split())
        for line in text.split("\n")
        if line.strip() and not line.lstrip().startswith("--")
    )


def a_dump(*blocks):
    """Assemble a minimal pg_dump file out of (name, type, schema, sql) blocks."""
    lines = ["--", "-- PostgreSQL database dump", "--", ""]
    for name, kind, schema, sql in blocks:
        lines += [
            "--",
            f"-- Name: {name}; Type: {kind}; Schema: {schema}; Owner: -",
            "--",
            "",
            sql,
            "",
            "",
        ]
    lines += ["--", "-- PostgreSQL database dump complete", "--", ""]
    return "\n".join(lines)


def a_table(schema, name):
    return (name, "TABLE", schema, f"CREATE TABLE {schema}.{name} (\n    id bigint NOT NULL\n);")


def a_foreign_key(schema, name, constraint, references):
    return (
        f"{name} {constraint}",
        "FK CONSTRAINT",
        schema,
        f"ALTER TABLE ONLY {schema}.{name}\n"
        f"    ADD CONSTRAINT {constraint} FOREIGN KEY (id) REFERENCES {references}(id);",
    )


class TestSchemaRegrouping(unittest.TestCase):
    def setUp(self):
        self.rendered = dbprofiler.render_schema_by_table(SCHEMA_SQL)

    def sections(self, text=None):
        return SECTION_TITLE.findall(self.rendered if text is None else text)

    def section_body(self, title):
        """Everything between one section banner and the next."""
        starts = [(m.group(1), m.start()) for m in SECTION_TITLE.finditer(self.rendered)]
        for position, (found, start) in enumerate(starts):
            if found != title:
                continue
            end = starts[position + 1][1] if position + 1 < len(starts) else len(self.rendered)
            return self.rendered[start:end]
        raise AssertionError(f"no section {title!r} in the rendered schema")

    def test_the_recorded_rendering_is_reproduced(self):
        self.assertEqual(self.rendered, SCHEMA_BY_TABLE_SQL)

    def test_no_sql_is_added_lost_or_rewritten(self):
        self.assertEqual(sql_lines(SCHEMA_SQL), sql_lines(self.rendered))

    def test_the_sections_appear_in_the_documented_order(self):
        self.assertEqual(
            self.sections(),
            [
                "SECTION: PREAMBLE (non-table-scoped objects)",
                "TABLE: public.regions",
                "TABLE: public.users",
                "TABLE: public.orders",
                "TABLE: sales.invoices",
                "SECTION: CROSS-TABLE OBJECTS (FKs, triggers, views, other)",
            ],
        )

    def test_every_table_gets_exactly_one_section(self):
        found = TABLE_SECTION_TITLE.findall(self.rendered)
        self.assertEqual(sorted(found), sorted(set(found)))

    def test_a_table_section_holds_everything_that_table_owns(self):
        """The whole point: a reader sees one table without scrolling."""
        body = self.section_body("TABLE: public.orders")
        for statement in (
            "CREATE TABLE public.orders (",
            "ADD CONSTRAINT orders_pkey PRIMARY KEY (id);",
            "ADD CONSTRAINT orders_total_check CHECK",
            "CREATE INDEX orders_placed_by_idx ON public.orders",
            "ADD CONSTRAINT orders_placed_by_fkey FOREIGN KEY",
            "COMMENT ON TABLE public.orders IS",
            "COMMENT ON COLUMN public.orders.total IS",
            "ALTER PUBLICATION ledger_pub ADD TABLE ONLY public.orders;",
        ):
            with self.subTest(statement=statement):
                self.assertIn(statement, body)

    def test_the_owned_sequence_travels_with_its_table(self):
        body = self.section_body("TABLE: public.users")
        self.assertIn("CREATE SEQUENCE public.users_id_seq", body)
        self.assertIn("ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;", body)
        self.assertIn("ALTER COLUMN id SET DEFAULT nextval", body)

    def test_a_table_section_orders_its_statements_so_it_can_replay(self):
        body = self.section_body("TABLE: sales.invoices")
        positions = [
            body.index("CREATE TABLE sales.invoices"),
            body.index("ADD CONSTRAINT invoices_pkey"),
            body.index("CREATE INDEX invoices_order_id_idx"),
            body.index("ADD CONSTRAINT invoices_order_id_fkey"),
            body.index("CREATE UNIQUE INDEX invoices_replica_identity_idx"),
        ]
        self.assertEqual(positions, sorted(positions))

    def test_a_replica_identity_alter_follows_its_index_immediately(self):
        """The ALTER is only valid once the index exists, and reads as noise
        anywhere other than directly beneath it."""
        self.assertIn(
            "CREATE UNIQUE INDEX invoices_replica_identity_idx ON sales.invoices"
            " USING btree (id, issued_on);\n\n"
            "ALTER TABLE ONLY sales.invoices REPLICA IDENTITY USING INDEX"
            " invoices_replica_identity_idx;",
            self.rendered,
        )

    def test_an_inlined_foreign_key_follows_the_table_it_references(self):
        """The property that makes inlining legal: by the time an FK runs, the
        referenced table has already been created."""
        starts = {
            m.group(1): m.start() for m in TABLE_SECTION_TITLE.finditer(self.rendered)
        }
        cross_table = self.rendered.index("SECTION: CROSS-TABLE OBJECTS")
        checked = 0
        for match in INLINE_FK.finditer(self.rendered):
            if match.start() > cross_table:
                continue
            referenced = f"{match.group(3)}.{match.group(4)}"
            with self.subTest(constraint=match.group(2)):
                self.assertIn(referenced, starts)
                self.assertLess(starts[referenced], match.start())
            checked += 1
        self.assertEqual(checked, 4)

    def test_cross_table_objects_are_held_back_to_the_end(self):
        body = self.section_body("SECTION: CROSS-TABLE OBJECTS (FKs, triggers, views, other)")
        self.assertIn("CREATE VIEW public.recent_orders AS", body)
        self.assertIn("CREATE TRIGGER touch_orders", body)
        self.assertIn("CREATE EVENT TRIGGER audit_ddl", body)

    def test_the_preamble_holds_what_is_not_table_scoped(self):
        body = self.section_body("SECTION: PREAMBLE (non-table-scoped objects)")
        for statement in (
            "CREATE SCHEMA sales;",
            "CREATE EXTENSION IF NOT EXISTS pgcrypto",
            "COMMENT ON EXTENSION pgcrypto IS",
            "CREATE FUNCTION public.touch_updated_at()",
            "CREATE PUBLICATION ledger_pub",
            "SET default_tablespace = '';",
            "SET default_table_access_method = heap;",
        ):
            with self.subTest(statement=statement):
                self.assertIn(statement, body)

    def test_the_pg_dump_header_and_trailer_are_kept(self):
        self.assertTrue(self.rendered.startswith("--\n-- PostgreSQL database dump\n--\n"))
        self.assertIn("-- Dumped by pg_dump version 16.2", self.rendered)
        trailer = self.rendered.index("-- PostgreSQL database dump complete")
        last_section = max(match.start() for match in SECTION_TITLE.finditer(self.rendered))
        self.assertGreater(trailer, last_section)

    def test_the_rendering_is_deterministic(self):
        self.assertEqual(self.rendered, dbprofiler.render_schema_by_table(SCHEMA_SQL))

    def test_a_dump_with_no_object_banners_is_passed_through_unchanged(self):
        for text in ("", "-- nothing here\n", "SET row_security = off;\n"):
            with self.subTest(text=text):
                self.assertEqual(dbprofiler.render_schema_by_table(text), text)

    def test_a_foreign_key_cycle_keeps_one_edge_cross_table(self):
        """Two tables referencing each other cannot both be inlined. The edge
        out of the alphabetically first table is the one that gives way, so the
        choice does not depend on the order pg_dump happened to emit."""
        dump = a_dump(
            a_table("public", "a"),
            a_table("public", "b"),
            a_foreign_key("public", "a", "a_b_fkey", "public.b"),
            a_foreign_key("public", "b", "b_a_fkey", "public.a"),
        )
        rendered = dbprofiler.render_schema_by_table(dump)
        cross_table = rendered.index("SECTION: CROSS-TABLE OBJECTS")
        self.assertLess(rendered.index("b_a_fkey"), cross_table)
        self.assertGreater(rendered.index("a_b_fkey"), cross_table)
        self.assertEqual(sql_lines(dump), sql_lines(rendered))

    def test_a_foreign_key_to_a_table_outside_the_dump_stays_cross_table(self):
        """Nothing in this file says where that table gets created, so there is
        no position the FK can be inlined at and still be known to replay."""
        dump = a_dump(
            a_table("public", "a"),
            a_foreign_key("public", "a", "a_elsewhere_fkey", "other.elsewhere"),
        )
        rendered = dbprofiler.render_schema_by_table(dump)
        self.assertGreater(
            rendered.index("a_elsewhere_fkey"), rendered.index("SECTION: CROSS-TABLE OBJECTS")
        )

    def test_a_self_reference_is_inlined(self):
        """A table exists by the time its own FK runs, so a self-reference is
        not a cycle and does not need to be held back."""
        body = self.section_body("TABLE: public.users")
        self.assertIn("ADD CONSTRAINT users_manager_id_fkey FOREIGN KEY", body)

    def test_a_block_that_cannot_be_attributed_goes_to_the_cross_table_section(self):
        """A wrong guess would put a statement somewhere it cannot run. The
        cross-table section replays after every table, so it always can."""
        dump = a_dump(
            a_table("public", "a"),
            ("orphan_idx", "INDEX", "public", "CREATE INDEX orphan_idx ON public.ghost (id);"),
        )
        rendered = dbprofiler.render_schema_by_table(dump)
        self.assertGreater(
            rendered.index("orphan_idx"), rendered.index("SECTION: CROSS-TABLE OBJECTS")
        )


class TestSchemaRegroupingOfPartitions(unittest.TestCase):
    """The renderer over a declarative partition hierarchy.

    Partitioning is the one shape where regrouping can break replay in a way
    the flat dump cannot: ATTACH PARTITION names two tables, so moving either
    one past it is enough to make the file stop loading.
    """

    def setUp(self):
        self.rendered = dbprofiler.render_schema_by_table(SCHEMA_PARTITIONED_SQL)

    def position(self, needle):
        found = self.rendered.index(needle)
        self.assertNotIn(needle, self.rendered[found + len(needle):], f"{needle} is ambiguous")
        return found

    def test_the_recorded_rendering_still_matches(self):
        self.assertEqual(self.rendered, SCHEMA_PARTITIONED_BY_TABLE_SQL)

    def test_no_sql_is_lost(self):
        self.assertEqual(sql_lines(SCHEMA_PARTITIONED_SQL), sql_lines(self.rendered))

    def test_every_partition_gets_its_own_block(self):
        titles = set(SECTION_TITLE.findall(self.rendered))
        for name in (
            "sales.shipments", "sales.shipments_2025", "sales.shipments_2026",
            "sales.shipments_overflow", "sales.accounts", "sales.accounts_standard",
            "sales.accounts_premium", "sales.events", "sales.events_2026",
            "sales.events_2026_click", "sales.events_2026_view",
        ):
            with self.subTest(name=name):
                self.assertIn(f"TABLE: {name}", titles)

    def test_a_parent_block_precedes_every_partition_of_it(self):
        for parent, child in (
            ("sales.shipments", "sales.shipments_2025"),
            ("sales.shipments", "sales.shipments_overflow"),
            ("sales.accounts", "sales.accounts_premium"),
            ("sales.events", "sales.events_2026"),
            # Two levels down: the intermediate parent is itself partitioned.
            ("sales.events_2026", "sales.events_2026_click"),
        ):
            with self.subTest(parent=parent, child=child):
                self.assertLess(
                    self.position(f"TABLE: {parent} ="),
                    self.position(f"TABLE: {child} ="),
                )

    def test_every_attach_partition_follows_both_tables_it_names(self):
        """The statement that would fail first if regrouping got this wrong."""
        attaches = re.findall(
            r"ALTER TABLE ONLY (\S+) ATTACH PARTITION (\S+)", self.rendered
        )
        self.assertTrue(attaches, "expected the dump to carry ATTACH PARTITION")
        for parent, child in attaches:
            with self.subTest(parent=parent, child=child):
                attach = self.rendered.index(
                    f"ALTER TABLE ONLY {parent} ATTACH PARTITION {child}"
                )
                self.assertGreater(attach, self.position(f"TABLE: {parent} ="))
                self.assertGreater(attach, self.position(f"TABLE: {child} ="))

    def test_a_partitioned_index_is_attached_after_the_child_index_exists(self):
        """CREATE INDEX on the parent fans out to one index per partition,
        and each child index is then attached to the parent's. A child index
        arrives either as CREATE INDEX or, when it backs the partitioned
        primary key, as ADD CONSTRAINT."""
        attaches = re.findall(
            r"ALTER INDEX (\S+) ATTACH PARTITION ([^;\s]+);", self.rendered
        )
        self.assertTrue(attaches, "expected the dump to carry ALTER INDEX ... ATTACH")
        for parent_index, child_index in attaches:
            with self.subTest(index=child_index):
                bare = child_index.split(".")[-1]
                created = max(
                    self.rendered.find(f"CREATE INDEX {bare} ON "),
                    self.rendered.find(f"CREATE UNIQUE INDEX {bare} ON "),
                    self.rendered.find(f"ADD CONSTRAINT {bare} PRIMARY KEY"),
                )
                self.assertNotEqual(created, -1, f"{child_index} is never created")
                attach = self.rendered.index(
                    f"ALTER INDEX {parent_index} ATTACH PARTITION {child_index};"
                )
                self.assertGreater(attach, created)

    def test_every_attach_waits_for_the_cross_table_section(self):
        """Both ATTACH forms name objects from two different blocks, so the
        only position guaranteed to be after all of them is the section that
        replays last."""
        cross_table = self.rendered.index("SECTION: CROSS-TABLE OBJECTS")
        attach = re.compile(r"(?m)^ALTER (?:TABLE ONLY|INDEX) .* ATTACH PARTITION")
        for match in attach.finditer(self.rendered):
            with self.subTest(statement=match.group(0)[:60]):
                self.assertGreater(match.start(), cross_table)


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
                "observations/pg_index.csv",
                "observations/pg_sequence.csv",
                "observations/pg_stat_indexes.csv",
                "observations/pg_stat_statements.csv",
                "observations/pg_stat_tables.csv",
                "observations/pg_stats.csv",
                "observations/pg_stats_ext.csv",
                "profile.json",
                "schema.sql",
                "schema_by_table.sql",
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

    def test_the_regrouped_schema_payload_matches_the_recorded_rendering(self):
        self.assertEqual(
            self.by_path["schema_by_table.sql"].data, SCHEMA_BY_TABLE_SQL.encode("utf-8")
        )

    def test_the_regrouped_schema_does_not_displace_the_verbatim_dump(self):
        """Downstream consumers read schema.sql. The regrouped file is an
        addition, so the two payloads have to differ and both have to be here."""
        self.assertNotEqual(
            self.by_path["schema.sql"].data, self.by_path["schema_by_table.sql"].data
        )

    def test_pg_class_reports_estimates_and_sizes(self):
        rows = read_csv(self.by_path["observations/pg_class.csv"])
        header, body = rows[0], rows[1:]
        users = next(row for row in body if row[:2] == ["public", "users"])
        self.assertEqual(users[header.index("row_count_estimate")], "1000.0")
        self.assertEqual(users[header.index("size_bytes")], "163840")

    def test_pg_stats_carries_the_values_and_their_frequencies(self):
        rows = read_csv(self.by_path["observations/pg_stats.csv"])
        header, body = rows[0], rows[1:]
        user_id = next(row for row in body if row[:3] == ["public", "orders", "user_id"])
        self.assertEqual(user_id[header.index("most_common_values")], "1|2|3")
        self.assertEqual(user_id[header.index("most_common_freqs")], "0.1|0.05|0.02")

    def test_pg_stats_carries_the_histogram_in_order(self):
        rows = read_csv(self.by_path["observations/pg_stats.csv"])
        header, body = rows[0], rows[1:]
        users_id = next(row for row in body if row[:3] == ["public", "users", "id"])
        self.assertEqual(users_id[header.index("histogram_bounds")], "1|250|500|750|1000")
        self.assertEqual(users_id[header.index("correlation")], "0.98")

    def test_pg_stats_carries_the_column_declaration(self):
        rows = read_csv(self.by_path["observations/pg_stats.csv"])
        header, body = rows[0], rows[1:]
        placed_at = next(row for row in body if row[:3] == ["public", "orders", "placed_at"])
        self.assertEqual(placed_at[header.index("default_expression")], "now()")
        self.assertEqual(placed_at[header.index("statistics_target")], "250")
        users_id = next(row for row in body if row[:3] == ["public", "users", "id"])
        self.assertEqual(users_id[header.index("identity")], "always")

    def test_pg_class_carries_the_storage_shape(self):
        rows = read_csv(self.by_path["observations/pg_class.csv"])
        header, body = rows[0], rows[1:]
        users = next(row for row in body if row[:2] == ["public", "users"])
        self.assertEqual(users[header.index("page_count")], "20")
        self.assertEqual(users[header.index("has_toast")], "true")

    def test_pg_index_carries_one_row_per_key_position(self):
        rows = read_csv(self.by_path["observations/pg_index.csv"])
        header, body = rows[0], rows[1:]
        keys = [row for row in body if row[header.index("index")] == "orders_user_id_idx"]
        self.assertEqual([row[header.index("position")] for row in keys], ["1", "2", "3"])
        self.assertEqual([row[header.index("column")] for row in keys],
                         ["user_id", "placed_at", "id"])
        self.assertEqual([row[header.index("is_key")] for row in keys],
                         ["true", "true", "false"])
        self.assertEqual([row[header.index("descending")] for row in keys],
                         ["false", "true", "false"])

    def test_pg_sequence_carries_a_bigint_bound_without_rounding(self):
        rows = read_csv(self.by_path["observations/pg_sequence.csv"])
        header, body = rows[0], rows[1:]
        self.assertEqual(body[0][header.index("maximum")], "9223372036854775807")

    def test_a_value_containing_the_separator_is_escaped_not_split(self):
        """With the values published literally, a pipe inside one of them would
        otherwise split it in two and shift every frequency after it."""
        stats = 'public,orders,user_id,0,8,500,"{a|b,c}","{0.1,0.05}",,0.15\n'
        catalog = a_catalog(column_stats=stats)
        profile = dbprofiler.build_profile(a_source(), catalog, self.workload)
        payloads = self.build_payloads(profile=profile, catalog=catalog)
        rows = read_csv({e.path: e for e in payloads}["observations/pg_stats.csv"])
        header, body = rows[0], rows[1:]
        user_id = next(row for row in body if row[:3] == ["public", "orders", "user_id"])
        self.assertEqual(user_id[header.index("most_common_values")], r"a\|b|c")

    def test_pg_stats_ext_reports_one_row_per_column_combination(self):
        rows = read_csv(self.by_path["observations/pg_stats_ext.csv"])
        header, body = rows[0], rows[1:]
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0][header.index("combination")], "user_id|placed_at")
        self.assertEqual(body[0][header.index("distinct_estimate")], "4200.0")

    def test_pg_stats_ext_carries_the_dependence_the_planner_would_miss(self):
        """most_common_base_freqs is what the frequency would have been under
        the independence assumption. The gap between it and the observed
        frequency is the correlation, and it is the only reason the extended
        statistics object exists."""
        rows = read_csv(self.by_path["observations/pg_stats_ext.csv"])
        header, body = rows[0], rows[1:]
        self.assertEqual(body[0][header.index("most_common_freqs")], "0.08|0.03")
        self.assertEqual(body[0][header.index("most_common_base_freqs")], "0.02|0.01")
        self.assertIn("2026-01-01", body[0][header.index("most_common_values")])

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

    def test_statement_text_is_carried_as_postgresql_normalized_it(self):
        rows = read_csv(self.by_path["observations/pg_stat_statements.csv"])
        header, body = rows[0], rows[1:]
        self.assertIn("query_text", header)
        self.assertTrue(any("$1" in row[header.index("query_text")] for row in body))

    def test_the_build_is_byte_for_byte_reproducible(self):
        again = dbprofiler.build_payloads(
            self.profile, self.catalog, self.workload, SCHEMA_SQL
        )
        self.assertEqual(
            [(e.path, e.data) for e in self.payloads],
            [(e.path, e.data) for e in again],
        )


class TestDegradedPayloads(BundleCase):
    def omitted(self, **overrides):
        workload = a_workload(**overrides)
        profile = dbprofiler.build_profile(a_source(), self.catalog, workload)
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
        profile = dbprofiler.build_profile(a_source(), self.catalog, workload)
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


class TestWhatReachesDisk(BundleCase):
    """What the bundle carries, and what it must never carry.

    The statistics are published as PostgreSQL computed them, so the planted
    values here are asserted *present* and intact. The negative assertion is
    reserved for what has no business leaving the operator's machine: the
    connection URL and the credentials in it.
    """

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

    def with_stats(self, stats):
        catalog = a_catalog(column_stats=stats)
        profile = dbprofiler.build_profile(a_source(), catalog, self.workload)
        payloads = self.build_payloads(profile=profile, catalog=catalog)
        manifest = dbprofiler.build_manifest(a_source(), FINGERPRINT, payloads)
        return self.bundle_and_temp(payloads, manifest)

    def test_an_unnormalized_query_literal_reaches_the_bundle(self):
        """pg_stat_statements normalizes literals to $1 -- usually. The golden
        fixture carries one that was not, and the bundle carries it through.
        This is the case the bundle's own documentation has to warn about."""
        statements = golden("statements").replace("sample-region-1", PLANTED)
        workload = a_workload(statements=statements)
        self.assertIn(PLANTED, "".join(s.query_text for s in workload.statements))

        profile = dbprofiler.build_profile(a_source(), self.catalog, workload)
        payloads = self.build_payloads(profile=profile, workload=workload)
        manifest = dbprofiler.build_manifest(a_source(), FINGERPRINT, payloads)
        self.assertIn(PLANTED.encode("utf-8"), self.bundle_and_temp(payloads, manifest))

    def test_a_most_common_value_reaches_the_bundle_intact(self):
        stats = golden("column_stats").replace("{1,2,3}", f"{{{PLANTED},2,3}}")
        self.assertIn(PLANTED.encode("utf-8"), self.with_stats(stats))

    def test_a_histogram_bound_reaches_the_bundle_intact(self):
        stats = golden("column_stats").replace("{1,250,500,750,1000}", f"{{{PLANTED},250}}")
        self.assertIn(PLANTED.encode("utf-8"), self.with_stats(stats))

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
    dbprofiler.SQL_INDEX_COLUMNS: "index_columns",
    dbprofiler.SQL_SEQUENCES: "sequences",
    dbprofiler.SQL_DATABASE_COLLATION: "database_collation",
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
    "index_columns",
    "sequences",
    "database_collation",
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
        environment = {dbprofiler.URL_ENV_VAR: URL}
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
                "observations/pg_index.csv",
                "observations/pg_sequence.csv",
                "observations/pg_stat_indexes.csv",
                "observations/pg_stat_statements.csv",
                "observations/pg_stat_tables.csv",
                "observations/pg_stats.csv",
                "observations/pg_stats_ext.csv",
                "profile.json",
                "schema.sql",
                "schema_by_table.sql",
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

    def test_the_regrouped_schema_is_stored_beside_it(self):
        self.assertEqual(
            self.archive()["schema_by_table.sql"], SCHEMA_BY_TABLE_SQL.encode("utf-8")
        )

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
        partitioned = golden("tables") + "public,events,p,0,0,0,f\n"
        self.expect_failure(FakePostgres(tables=partitioned))

    def test_cancellation_prevents_publication(self):
        """SIGINT arrives as KeyboardInterrupt. Nothing half-written survives."""
        fake = self.expect_failure(FakePostgres(table_activity=KeyboardInterrupt()), code=130)
        self.assertEqual(fake.calls[-1], "table_activity")
        self.assertIn("cancelled", self.stderr.getvalue())

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
    SECRETS = (URL, PASSWORD, USER, HOST)

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

    def test_the_child_environment_carries_the_credentials_and_not_our_own(self):
        captured = {}
        fake = FakePostgres()

        def record(argv, **kwargs):
            captured.update(kwargs.get("env", {}))
            return fake(argv, **kwargs)

        with mock.patch.dict(
            "os.environ",
            {dbprofiler.URL_ENV_VAR: URL},
            clear=True,
        ):
            with mock.patch("subprocess.run", side_effect=record):
                with contextlib.redirect_stderr(self.stderr):
                    with contextlib.redirect_stdout(self.stdout):
                        dbprofiler.main(["postgres", "--output", str(self.output)])
        self.assertEqual(captured["PGPASSWORD"], PASSWORD)
        self.assertNotIn(dbprofiler.URL_ENV_VAR, captured)

    def test_no_credential_reaches_a_child_command_line(self):
        seen = []
        fake = FakePostgres()

        def record(argv, **kwargs):
            seen.append(" ".join(argv))
            return fake(argv, **kwargs)

        with mock.patch.dict(
            "os.environ",
            {dbprofiler.URL_ENV_VAR: URL},
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

    def test_the_compose_file_holds_no_variable_the_profiler_reads(self):
        # The DBPROFILER_TEST_PG* substitutions below configure the server. The
        # profiler's own variables carry the URL it connects with, which belongs
        # to the operator, not to a committed container definition.
        self.assertNotIn(dbprofiler.URL_ENV_VAR, self.text)
        self.assertNotIn("DBPROFILER_POSTGRES_TEST_URL", self.text)

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


# ---------------------------------------------------------------------------
# Kit generation
# ---------------------------------------------------------------------------
# A bundle carries a sample of a source database, so no real bundle is read
# here. Every fixture below is synthetic and built in-test, and the names in it
# are the ones fixed by .claude/rules/development.md.

KIT_SCHEMA = "example_schema"


def kit_column(name, data_type, **overrides):
    column = {
        "schema": KIT_SCHEMA,
        "table": overrides.pop("table", "parent"),
        "name": name,
        "ordinal": overrides.pop("ordinal", 1),
        "data_type": data_type,
        "is_nullable": True,
        "is_supported": True,
        "null_fraction": 0.0,
        "avg_width_bytes": 16,
        "distinct_estimate": 100.0,
        "most_common_values": [],
        "most_common_freqs": [],
        "histogram_bounds": [],
        "correlation": None,
        "collation": None,
        "default_expression": None,
        "identity": None,
        "statistics_target": None,
        "provenance": "",
    }
    column.update(overrides)
    return column


def kit_table(name, columns, row_count_estimate=1000):
    return {
        "schema": KIT_SCHEMA,
        "name": name,
        "row_count_estimate": row_count_estimate,
        "size_bytes": 8192,
        "columns": columns,
        "provenance": "",
    }


def kit_relationship(child, parent, child_columns=("parent_id",), parent_columns=("id",)):
    return {
        "constraint_name": f"fk_{child}_{parent}",
        "child_schema": KIT_SCHEMA,
        "child_table": child,
        "child_columns": list(child_columns),
        "parent_schema": KIT_SCHEMA,
        "parent_table": parent,
        "parent_columns": list(parent_columns),
        "on_update": "NO ACTION",
        "on_delete": "RESTRICT",
        "fan_out": {"status": "estimated", "basis": "single_column", "mean": 3.0, "p99": 9.0},
    }


def kit_index(table, name, columns, is_primary=False, is_unique=False,
              storing=(), descending=(), is_partial=False, has_expressions=False):
    keys = [
        {"position": i, "name": c, "is_key": True,
         "descending": c in descending, "nulls_first": False,
         "operator_class": None, "collation": None}
        for i, c in enumerate(columns, 1)
    ]
    payload = [
        {"position": len(columns) + i, "name": c, "is_key": False,
         "descending": False, "nulls_first": False,
         "operator_class": None, "collation": None}
        for i, c in enumerate(storing, 1)
    ]
    if has_expressions:
        keys[0] = dict(keys[0], name=None)
    return {
        "schema": KIT_SCHEMA, "table": table, "name": name,
        "is_unique": is_unique or is_primary, "is_primary": is_primary,
        "is_valid": True, "is_clustered": False, "is_partial": is_partial,
        "has_expressions": has_expressions, "columns": keys + payload, "provenance": "",
    }


def kit_profile(tables=None, relationships=None, contract_version=None,
                indexes=None, sequences=None):
    if tables is None:
        tables = [
            kit_table("parent", [kit_column("id", "uuid", table="parent")]),
            kit_table(
                "child",
                [
                    kit_column("id", "uuid", table="child"),
                    kit_column("parent_id", "uuid", table="child", ordinal=2),
                ],
            ),
        ]
    if relationships is None:
        relationships = [kit_relationship("child", "parent")]
    return {
        "source": {
            "kind": "postgres",
            "server_version_num": 160013,
            "server_version": "16.13",
            "database": DATABASE,
            "collected_schemas": [KIT_SCHEMA],
            "collate": "en_US.utf8",
            "ctype": "en_US.utf8",
        },
        "contract_version": contract_version or dbprofiler.CONTRACT_VERSION,
        "tables": tables,
        "relationships": relationships,
        "indexes": indexes if indexes is not None else [
            kit_index("parent", "parent_pkey", ["id"], is_primary=True),
            kit_index("child", "child_pkey", ["id"], is_primary=True),
        ],
        "sequences": sequences or [],
        "warnings": [],
    }


def write_kit_bundle(directory, profile=None, corrupt=False):
    """Write a minimal but checksum-correct bundle directory."""
    directory = Path(directory)
    (directory / "observations").mkdir(parents=True, exist_ok=True)
    profile = profile if profile is not None else kit_profile()

    payloads = {
        "profile.json": json.dumps(profile, indent=2).encode(),
        "schema.sql": b"-- synthetic schema\n",
    }
    entries = []
    for name, data in payloads.items():
        (directory / name).write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        if corrupt and name == "profile.json":
            digest = "0" * 64
        entries.append({"path": name, "sha256": digest, "row_count": 1})

    manifest = {
        "tool": "dbprofiler",
        "tool_version": dbprofiler.VERSION,
        "contract_version": profile["contract_version"],
        "created_at": "2026-01-01T00:00:00Z",
        "source": profile["source"],
        "schema_fingerprint": "f" * 64,
        "payloads": entries,
        "warnings": [],
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return directory


class TestKitBundleReader(unittest.TestCase):
    def test_reads_a_directory_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_kit_bundle(tmp)
            profile = dbprofiler.read_bundle_profile(Path(tmp))
        self.assertEqual(profile["source"]["database"], DATABASE)

    def test_reads_a_zip_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = write_kit_bundle(Path(tmp) / "bundle")
            archive = Path(tmp) / "bundle.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                for path in sorted(source.rglob("*")):
                    if path.is_file():
                        zf.write(path, path.relative_to(source).as_posix())
            profile = dbprofiler.read_bundle_profile(archive)
        self.assertEqual(profile["source"]["database"], DATABASE)

    def test_refuses_a_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_kit_bundle(tmp, corrupt=True)
            with self.assertRaises(dbprofiler.BundleError) as caught:
                dbprofiler.read_bundle_profile(Path(tmp))
        self.assertIn("profile.json", str(caught.exception))

    def test_refuses_an_unsupported_contract_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_kit_bundle(tmp, profile=kit_profile(contract_version="1.0"))
            with self.assertRaises(dbprofiler.BundleError) as caught:
                dbprofiler.read_bundle_profile(Path(tmp))
        message = str(caught.exception)
        self.assertIn("1.0", message)
        self.assertIn(dbprofiler.CONTRACT_VERSION, message)


class TestKitTypeMapping(unittest.TestCase):
    def generator(self, data_type, **overrides):
        return dbprofiler.column_generator(kit_column("c", data_type, **overrides))

    def test_maps_the_observed_type_vocabulary(self):
        cases = {
            "timestamp with time zone": "timestamp",
            "timestamp without time zone": "timestamp",
            "date": "date",
            "integer": "integer",
            "bigint": "integer",
            "numeric(38,20)": "float",
            "character varying(255)": "string",
            "text": "string",
            "uuid": "uuid",
            "boolean": "bool",
            "jsonb": "json",
            "bytea": "bytes",
        }
        for data_type, expected in cases.items():
            with self.subTest(data_type=data_type):
                kind, _ = self.generator(data_type)
                self.assertEqual(kind, expected)

    def test_declared_width_bounds_a_string(self):
        _, args = self.generator("character varying(64)")
        self.assertLessEqual(args["max"], 64)

    def test_histogram_bounds_become_a_timestamp_window(self):
        _, args = self.generator(
            "timestamp with time zone",
            histogram_bounds=["2024-01-01 00:00:00+00", "2024-06-01 00:00:00+00"],
        )
        self.assertTrue(args["start"].startswith("2024-01-01"))
        self.assertTrue(args["end"].startswith("2024-06-01"))

    def test_most_common_values_force_a_choice(self):
        kind, args = self.generator(
            "character varying(20)",
            most_common_values=["alpha", "beta"],
            most_common_freqs=[0.75, 0.25],
        )
        self.assertEqual(kind, "choice")
        self.assertEqual(args["population"][:2], ["alpha", "beta"])

    def test_null_fraction_becomes_null_pct(self):
        _, args = self.generator("uuid", null_fraction=0.25)
        self.assertAlmostEqual(args["null_pct"], 0.25)

    def test_every_generator_is_seeded(self):
        for data_type in ("uuid", "integer", "text", "timestamp with time zone"):
            with self.subTest(data_type=data_type):
                _, args = self.generator(data_type)
                self.assertIn("seed", args)

    def test_seeds_are_stable_across_runs(self):
        column = kit_column("c", "uuid")
        self.assertEqual(
            dbprofiler.column_generator(column)[1]["seed"],
            dbprofiler.column_generator(column)[1]["seed"],
        )

    def test_distinct_columns_get_distinct_seeds(self):
        first = dbprofiler.column_generator(kit_column("a", "uuid"))[1]["seed"]
        second = dbprofiler.column_generator(kit_column("b", "uuid"))[1]["seed"]
        self.assertNotEqual(first, second)


class TestKitChoiceWeights(unittest.TestCase):
    def test_weights_sum_to_one(self):
        weights = dbprofiler.choice_weights([0.5, 0.25], 4, 0.0)
        self.assertAlmostEqual(sum(weights), 1.0, places=6)

    def test_residue_is_spread_over_unlisted_values(self):
        weights = dbprofiler.choice_weights([0.5, 0.25], 4, 0.0)
        self.assertEqual(len(weights), 4)
        self.assertGreater(weights[2], 0.0)
        self.assertAlmostEqual(weights[2], weights[3])

    def test_frequencies_are_renormalized_over_non_null_rows(self):
        # most_common_freqs are fractions of all rows including nulls, but the
        # generator applies null_pct independently.
        weights = dbprofiler.choice_weights([0.4, 0.4], 2, 0.2)
        self.assertAlmostEqual(sum(weights), 1.0, places=6)
        self.assertAlmostEqual(weights[0], 0.5, places=6)

    def test_exhaustive_frequencies_leave_unlisted_values_rarest(self):
        weights = dbprofiler.choice_weights([0.6, 0.4], 3, 0.0)
        self.assertAlmostEqual(sum(weights), 1.0, places=6)
        self.assertGreater(weights[2], 0.0)
        self.assertLess(weights[2], min(weights[0], weights[1]))


class TestKitConstantGuard(unittest.TestCase):
    def test_never_emits_constant_with_a_fractional_null_pct(self):
        # SimpleFaker's dispatcher discards `seed` for `constant`, so such a
        # column would reseed from OS entropy and change on every run.
        kind, args = dbprofiler.column_generator(
            kit_column(
                "c",
                "character varying(20)",
                most_common_values=["only"],
                most_common_freqs=[0.6],
                null_fraction=0.4,
            )
        )
        self.assertNotEqual(kind, "constant")
        self.assertIn("seed", args)

    def test_no_emitted_yaml_pairs_constant_with_a_fractional_null_pct(self):
        profile = kit_profile(
            tables=[
                kit_table(
                    "only",
                    [
                        kit_column(
                            "c",
                            "text",
                            table="only",
                            most_common_values=["x"],
                            most_common_freqs=[0.5],
                            null_fraction=0.5,
                        )
                    ],
                )
            ],
            relationships=[],
        )
        kit = dbprofiler.build_kit(profile, scale=1, procs=8)
        for name, body in kit.files.items():
            if name.endswith(".yaml"):
                self.assertNotIn("type: constant", body)


class TestKitRowCounts(unittest.TestCase):
    def test_counts_land_on_a_multiple_of_procs(self):
        for estimate in (1, 7, 999, 1_000_000):
            with self.subTest(estimate=estimate):
                self.assertEqual(dbprofiler.scaled_row_count(estimate, 1, 8) % 8, 0)

    def test_scale_divides_the_estimate(self):
        self.assertEqual(dbprofiler.scaled_row_count(80_000, 1000, 8), 80)

    def test_never_returns_zero(self):
        self.assertGreaterEqual(dbprofiler.scaled_row_count(1, 1_000_000, 8), 8)


class TestKitLoadOrder(unittest.TestCase):
    def test_parents_precede_children(self):
        profile = kit_profile()
        order = dbprofiler.table_load_order(profile["tables"], profile["relationships"])
        self.assertLess(order.index("parent"), order.index("child"))

    def test_unrelated_tables_are_included(self):
        profile = kit_profile(
            tables=[kit_table("solo", [kit_column("id", "uuid", table="solo")])],
            relationships=[],
        )
        order = dbprofiler.table_load_order(profile["tables"], profile["relationships"])
        self.assertEqual(order, ["solo"])

    def test_self_reference_does_not_deadlock(self):
        profile = kit_profile(
            tables=[kit_table("node", [kit_column("id", "uuid", table="node")])],
            relationships=[kit_relationship("node", "node")],
        )
        order = dbprofiler.table_load_order(profile["tables"], profile["relationships"])
        self.assertEqual(order, ["node"])

    def test_a_cycle_is_reported_not_broken_silently(self):
        profile = kit_profile(
            tables=[
                kit_table("a", [kit_column("id", "uuid", table="a")]),
                kit_table("b", [kit_column("id", "uuid", table="b")]),
            ],
            relationships=[kit_relationship("a", "b"), kit_relationship("b", "a")],
        )
        with self.assertRaises(dbprofiler.BundleError) as caught:
            dbprofiler.table_load_order(profile["tables"], profile["relationships"])
        self.assertIn("cycle", str(caught.exception).lower())


class TestKitEmission(unittest.TestCase):
    def build(self, profile=None, scale=1, procs=8):
        return dbprofiler.build_kit(profile or kit_profile(), scale=scale, procs=procs)

    def test_emits_the_expected_file_set(self):
        kit = self.build()
        self.assertEqual(
            set(kit.files),
            {
                f"{KIT_SCHEMA}.yaml",
                "schema.crdb.sql",
                "kit.json",
                "gen_yaml.py",
                "keys.py",
                "workload.py",
                "gen_import.py",
                "reproduce.sh",
                "README.md",
            },
        )

    def test_names_come_from_the_bundle(self):
        kit = self.build()
        yaml_body = kit.files[f"{KIT_SCHEMA}.yaml"]
        self.assertIn(f"{KIT_SCHEMA}.parent:", yaml_body)
        self.assertIn(f"{KIT_SCHEMA}.child:", yaml_body)

    def test_load_order_is_recorded_in_fk_order(self):
        kit = self.build()
        self.assertLess(
            kit.files["gen_import.py"].index("parent"),
            kit.files["gen_import.py"].index("child"),
        )

    def test_procs_is_carried_into_the_driver(self):
        kit = self.build(procs=4)
        self.assertIn("4", kit.files["reproduce.sh"])

    def test_readme_records_what_needs_judgment(self):
        readme = self.build().files["README.md"]
        self.assertIn("TODO", readme)

    def test_stubs_are_marked_todo(self):
        kit = self.build()
        for name in ("keys.py", "workload.py"):
            with self.subTest(name=name):
                self.assertIn("TODO", kit.files[name])

    def test_written_to_disk_under_the_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "kit"
            dbprofiler.write_kit(self.build(), out)
            written = {p.name for p in out.iterdir()}
        self.assertIn("reproduce.sh", written)
        self.assertIn("README.md", written)

    def test_the_driver_is_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "kit"
            dbprofiler.write_kit(self.build(), out)
            self.assertTrue(os.access(out / "reproduce.sh", os.X_OK))


class TestKitSafety(unittest.TestCase):
    """The generate path must not weaken the collector's safety boundary."""

    def emitted_text(self):
        kit = dbprofiler.build_kit(kit_profile(), scale=1, procs=8)
        return "\n".join(kit.files.values())

    def test_check_safety_still_passes(self):
        self.assertEqual(dbprofiler.check_safety(), 0)

    def test_emit_templates_carry_no_credentialed_url(self):
        for name, value in sorted(vars(dbprofiler).items()):
            if name.startswith("EMIT_") and isinstance(value, str):
                with self.subTest(name=name):
                    self.assertIsNone(dbprofiler.CREDENTIALED_URL.search(value))

    def test_no_emitted_file_contains_a_forbidden_scan(self):
        # ANALYZE is permitted in a target-side artifact; a table scan is not.
        self.assertNotIn("COUNT(", self.emitted_text().upper())

    def test_the_generate_path_starts_no_child_process(self):
        source = ast.parse(dbprofiler.own_source())
        generate = next(
            node
            for node in ast.walk(source)
            if isinstance(node, ast.FunctionDef) and node.name == "run_generate"
        )
        for node in ast.walk(generate):
            if isinstance(node, ast.Call):
                func = node.func
                self.assertFalse(
                    isinstance(func, ast.Attribute)
                    and dbprofiler._is_name(func.value, "subprocess"),
                    "run_generate must not start a child process",
                )

    def test_the_generate_path_opens_no_connection(self):
        source = ast.parse(dbprofiler.own_source())
        generate = next(
            node
            for node in ast.walk(source)
            if isinstance(node, ast.FunctionDef) and node.name == "run_generate"
        )
        called = {
            node.func.id
            for node in ast.walk(generate)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertEqual(called & {"run_psql", "run_pg_dump", "build_postgres_config"}, set())

    def test_no_name_from_one_bundle_reaches_another_kit(self):
        # Every name in a kit must be read out of the bundle it was built from.
        # A schema, table or column name hard-coded in a template would pass
        # every other test here, so the check is that building from a second
        # bundle leaves no trace of the first. The fixture names are deliberately
        # unlike any English word that appears in the templates.
        def profile_named(tag):
            tables = [
                kit_table(f"{tag}tbl", [kit_column(f"{tag}col", "uuid", table=f"{tag}tbl")])
            ]
            for table in tables:
                table["schema"] = f"{tag}schema"
                for column in table["columns"]:
                    column["schema"] = f"{tag}schema"
            return kit_profile(tables=tables, relationships=[])

        first_tag, second_tag = "qqaa_", "wwbb_"
        first = dbprofiler.build_kit(profile_named(first_tag), scale=1, procs=8)
        second = dbprofiler.build_kit(profile_named(second_tag), scale=1, procs=8)

        first_body = "\n".join(list(first.files) + list(first.files.values()))
        second_body = "\n".join(list(second.files) + list(second.files.values()))

        self.assertIn(f"{first_tag}tbl", first_body)
        self.assertIn(f"{second_tag}tbl", second_body)
        self.assertNotIn(first_tag, second_body)
        self.assertNotIn(second_tag, first_body)


class TestKitCli(unittest.TestCase):
    def test_generate_writes_a_kit_and_prints_only_the_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = write_kit_bundle(Path(tmp) / "bundle")
            out = Path(tmp) / "kit"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = dbprofiler.main(
                    ["generate", "--bundle", str(bundle), "--output", str(out)]
                )
            self.assertEqual(status, 0)
            self.assertEqual(stdout.getvalue().strip(), str(out))
            self.assertTrue((out / "README.md").exists())

    def test_generate_reports_a_bad_bundle_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = dbprofiler.main(
                    ["generate", "--bundle", str(Path(tmp) / "absent"),
                     "--output", str(Path(tmp) / "k")]
                )
        self.assertEqual(status, 2)
        self.assertIn(dbprofiler.PROG, stderr.getvalue())

    def test_scale_and_procs_reach_the_kit(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = write_kit_bundle(Path(tmp) / "bundle")
            out = Path(tmp) / "kit"
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                dbprofiler.main(
                    ["generate", "--bundle", str(bundle), "--output", str(out),
                     "--scale", "10", "--procs", "4"]
                )
            self.assertIn("4", (out / "reproduce.sh").read_text())


# PyYAML resolves a scalar to a float only when the mantissa carries a decimal
# point and any exponent carries a sign. Anything else loads as a string, which
# is how a weight reaches random.choices as text.
YAML_11_FLOAT = re.compile(r"^[-+]?(?:[0-9][0-9_]*\.[0-9_]*|\.[0-9_]+)(?:[eE][-+][0-9]+)?$")


class TestKitYamlFloats(unittest.TestCase):
    def test_small_magnitudes_round_trip_as_floats(self):
        # repr(5e-05) is "5e-05", which YAML 1.1 reads as a string.
        self.assertEqual(dbprofiler._yaml_float(5e-05), "5.0e-05")

    def test_rendered_floats_match_the_yaml_float_grammar(self):
        for value in (0.5, 5e-05, 1e-08, 1.7e-05, 4.2e-09, 123.0, 1e20, 0.0):
            with self.subTest(value=value):
                self.assertRegex(dbprofiler._yaml_float(value), YAML_11_FLOAT)

    def test_integers_stay_integers(self):
        self.assertEqual(dbprofiler._yaml_scalar(8), "8")

    def test_every_emitted_weight_is_a_yaml_float(self):
        profile = kit_profile(
            tables=[
                kit_table(
                    "t",
                    [
                        kit_column(
                            "c",
                            "text",
                            table="t",
                            most_common_values=["a", "b", "c"],
                            most_common_freqs=[0.9999, 0.00005, 0.00005],
                        )
                    ],
                )
            ],
            relationships=[],
        )
        kit = dbprofiler.build_kit(profile, scale=1, procs=8)
        body = kit.files[f"{KIT_SCHEMA}.yaml"]
        weights = re.search(r"weights: \[([^\]]*)\]", body).group(1)
        for token in weights.split(","):
            with self.subTest(token=token):
                self.assertRegex(token.strip(), YAML_11_FLOAT)


class TestKitWeightFloor(unittest.TestCase):
    def test_a_positive_weight_never_rounds_away_to_zero(self):
        self.assertGreater(dbprofiler._readable_weight(4.2e-12), 0.0)

    def test_an_ordinary_weight_is_rounded_for_legibility(self):
        self.assertEqual(dbprofiler._readable_weight(0.123456789123), 0.12345679)

    def test_a_rare_value_survives_into_the_emitted_weights(self):
        weights = dbprofiler.column_generator(
            kit_column(
                "c",
                "text",
                most_common_values=["common", "vanishing"],
                most_common_freqs=[0.999999999, 1e-11],
            )
        )[1]["weights"]
        self.assertTrue(all(w > 0 for w in weights), weights)

class TestEmittedTemplateAudit(unittest.TestCase):
    def test_every_emit_constant_is_audited(self):
        names = {name for name, _ in dbprofiler.iter_emit_constants()}
        self.assertIn("EMIT_REPRODUCE", names)
        self.assertGreaterEqual(len(names), 5)

    def test_a_credentialed_url_is_caught(self):
        problems = dbprofiler.audit_emitted(f"DSN='postgres://{USER}:{PASSWORD}@{HOST}/db'")
        self.assertTrue(any("credential" in p for p in problems), problems)

    def test_a_table_scan_is_caught(self):
        problems = dbprofiler.audit_emitted("SELECT COUNT(*) FROM t")
        self.assertTrue(any("COUNT(" in p for p in problems), problems)

    def test_spacing_cannot_evade_the_scan_check(self):
        problems = dbprofiler.audit_emitted("SELECT COUNT (*) FROM t")
        self.assertTrue(any("COUNT(" in p for p in problems), problems)

    def test_analyze_is_permitted_in_an_emitted_artifact(self):
        # A generated script refreshes the planner statistics of the
        # reproduction database it just loaded. That is not a source read.
        self.assertEqual(dbprofiler.audit_emitted('psql -c "ANALYZE"'), [])

    def test_the_shipped_driver_refreshes_statistics(self):
        self.assertIn("ANALYZE", dbprofiler.EMIT_REPRODUCE)

    def test_the_shipped_driver_validates_foreign_keys(self):
        self.assertIn("VALIDATE CONSTRAINT", dbprofiler.EMIT_REPRODUCE)

class TestKitZipLayouts(unittest.TestCase):
    """A bundle that has been extracted and re-zipped keeps working."""

    def archive(self, tmp, prefix="", extra=()):
        source = write_kit_bundle(Path(tmp) / "src")
        target = Path(tmp) / "bundle.zip"
        with zipfile.ZipFile(target, "w") as zf:
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    zf.writestr(prefix + path.relative_to(source).as_posix(), path.read_bytes())
            for name in extra:
                zf.writestr(name, b"junk")
        return target

    def test_payloads_at_the_archive_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = dbprofiler.read_bundle_profile(self.archive(tmp))
        self.assertEqual(profile["source"]["database"], DATABASE)

    def test_payloads_under_a_single_directory_prefix(self):
        # `zip -r bundle.zip bundle/` stores the directory name as a prefix.
        with tempfile.TemporaryDirectory() as tmp:
            profile = dbprofiler.read_bundle_profile(self.archive(tmp, prefix="some-bundle/"))
        self.assertEqual(profile["source"]["database"], DATABASE)

    def test_macos_resource_fork_entries_are_ignored(self):
        # The macOS compressor writes a parallel __MACOSX tree beside the real one.
        with tempfile.TemporaryDirectory() as tmp:
            archive = self.archive(
                tmp,
                prefix="some-bundle/",
                extra=("__MACOSX/", "__MACOSX/some-bundle/._manifest.json"),
            )
            profile = dbprofiler.read_bundle_profile(archive)
        self.assertEqual(profile["source"]["database"], DATABASE)

    def test_two_bundles_in_one_archive_is_refused_not_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = write_kit_bundle(Path(tmp) / "src")
            target = Path(tmp) / "bundle.zip"
            with zipfile.ZipFile(target, "w") as zf:
                for prefix in ("first/", "second/"):
                    for path in sorted(source.rglob("*")):
                        if path.is_file():
                            zf.writestr(
                                prefix + path.relative_to(source).as_posix(), path.read_bytes()
                            )
            with self.assertRaises(dbprofiler.BundleError) as caught:
                dbprofiler.read_bundle_profile(target)
        message = str(caught.exception)
        self.assertIn("first", message)
        self.assertIn("second", message)

    def test_an_archive_with_no_manifest_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bundle.zip"
            with zipfile.ZipFile(target, "w") as zf:
                zf.writestr("readme.txt", b"not a bundle")
            with self.assertRaises(dbprofiler.BundleError) as caught:
                dbprofiler.read_bundle_profile(target)
        self.assertIn("manifest.json", str(caught.exception))

    def test_a_path_that_is_not_an_archive_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bundle.zip"
            target.write_bytes(b"this is not a zip")
            with self.assertRaises(dbprofiler.BundleError) as caught:
                dbprofiler.read_bundle_profile(target)
        self.assertIn("readable bundle", str(caught.exception))

class TestKitRegeneration(unittest.TestCase):
    """A kit is regenerated in place without destroying the work in it."""

    def kit(self, scale=1):
        return dbprofiler.build_kit(kit_profile(), scale=scale, procs=8)

    def test_an_edited_stub_survives_a_regeneration(self):
        marker = "# an implemented generator\n"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "kit"
            dbprofiler.write_kit(self.kit(), out)
            (out / "keys.py").write_text((out / "keys.py").read_text() + marker)

            preserved = dbprofiler.write_kit(self.kit(scale=10), out)

            self.assertIn("keys.py", preserved)
            self.assertIn(marker, (out / "keys.py").read_text())

    def test_derived_files_are_refreshed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "kit"
            dbprofiler.write_kit(self.kit(scale=1), out)
            before = (out / f"{KIT_SCHEMA}.yaml").read_text()
            dbprofiler.write_kit(self.kit(scale=10), out)
            after = (out / f"{KIT_SCHEMA}.yaml").read_text()
        self.assertNotEqual(before, after)

    def test_a_pristine_stub_is_not_reported_as_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "kit"
            dbprofiler.write_kit(self.kit(), out)
            self.assertEqual(dbprofiler.write_kit(self.kit(), out), ())

    def test_force_replaces_an_edited_stub(self):
        marker = "# an implemented generator\n"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "kit"
            dbprofiler.write_kit(self.kit(), out)
            (out / "keys.py").write_text((out / "keys.py").read_text() + marker)
            preserved = dbprofiler.write_kit(self.kit(), out, force=True)
            self.assertEqual(preserved, ())
            self.assertNotIn(marker, (out / "keys.py").read_text())

    def test_both_stubs_are_protected(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "kit"
            dbprofiler.write_kit(self.kit(), out)
            for name in ("keys.py", "workload.py"):
                (out / name).write_text("edited\n")
            preserved = dbprofiler.write_kit(self.kit(), out)
        self.assertEqual(set(preserved), {"keys.py", "workload.py"})

    def test_the_cli_reports_what_it_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = write_kit_bundle(Path(tmp) / "bundle")
            out = Path(tmp) / "kit"
            argv = ["generate", "--bundle", str(bundle), "--output", str(out)]
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                dbprofiler.main(argv)
            (out / "workload.py").write_text("edited\n")

            stderr = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                status = dbprofiler.main(argv)
            self.assertEqual(status, 0)
            self.assertIn("workload.py", stderr.getvalue())
            self.assertIn("edited\n", (out / "workload.py").read_text())


class TestKitDefaultOutput(unittest.TestCase):
    def test_a_zip_bundle_puts_the_kit_beside_itself(self):
        self.assertEqual(
            dbprofiler.default_kit_output(Path("/srv/bundles/shop.zip")).name, "shop-kit"
        )
        self.assertEqual(
            dbprofiler.default_kit_output(Path("/srv/bundles/shop.zip")).parent,
            Path("/srv/bundles"),
        )

    def test_a_directory_bundle_gets_a_sibling(self):
        self.assertEqual(
            dbprofiler.default_kit_output(Path("/srv/bundles/shop")).name, "shop-kit"
        )

    def test_an_uppercase_extension_is_handled(self):
        self.assertEqual(
            dbprofiler.default_kit_output(Path("/srv/bundles/SHOP.ZIP")).name, "SHOP-kit"
        )

    def test_the_cli_uses_it_when_output_is_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = write_kit_bundle(Path(tmp) / "bundle")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                status = dbprofiler.main(["generate", "--bundle", str(bundle)])
            self.assertEqual(status, 0)
            self.assertEqual(stdout.getvalue().strip(), str(Path(tmp) / "bundle-kit"))
            self.assertTrue((Path(tmp) / "bundle-kit" / "README.md").exists())

class TestKitGeneratorArguments(unittest.TestCase):
    """Emitted args must match the generator signatures dbworkload actually has."""

    def gen(self, data_type, **kw):
        return dbprofiler.column_generator(kit_column("c", data_type, **kw))

    def test_bytea_uses_size_not_n(self):
        kind, args = self.gen("bytea", avg_width_bytes=32)
        self.assertEqual(kind, "bytes")
        self.assertIn("size", args)
        self.assertNotIn("n", args)

    def test_an_array_column_generates_a_real_array(self):
        kind, args = self.gen("text[]")
        self.assertEqual(kind, "string")
        self.assertGreater(args.get("array", 0), 0)

    def test_an_array_uses_its_element_type(self):
        self.assertEqual(self.gen("integer[]")[0], "integer")
        self.assertEqual(self.gen("uuid[]")[0], "uuid")
        self.assertEqual(self.gen("timestamp with time zone[]")[0], "timestamp")

    def test_an_array_with_most_common_values_keeps_them_verbatim(self):
        # pg_stats records the whole array value, so the literals are already
        # arrays and must not be wrapped a second time.
        kind, args = self.gen(
            "text[]", most_common_values=["{a,b}", "{c}"], most_common_freqs=[0.7, 0.3]
        )
        self.assertEqual(kind, "choice")
        self.assertEqual(args["population"], ["{a,b}", "{c}"])
        self.assertNotIn("array", args)

    def test_a_scalar_column_asks_for_no_array(self):
        for data_type in ("text", "uuid", "integer", "boolean", "jsonb", "bytea"):
            with self.subTest(data_type=data_type):
                self.assertNotIn("array", self.gen(data_type)[1])

    def test_every_emitted_argument_is_accepted_by_its_generator(self):
        """The real guard: emitted args must bind to SimpleFaker's signatures.

        Skipped where dbworkload is absent, since the tool has no runtime
        dependencies; it is the check that catches an argument renamed or
        invented, which no amount of YAML validation would.
        """
        try:
            import inspect

            from dbworkload.utils.simplefaker import SimpleFaker
        except ImportError:
            self.skipTest("dbworkload is not installed")

        classes = {
            "string": SimpleFaker.String, "integer": SimpleFaker.Integer,
            "float": SimpleFaker.Float, "choice": SimpleFaker.Choice,
            "timestamp": SimpleFaker.Timestamp, "date": SimpleFaker.Date,
            "uuid": SimpleFaker.UUIDv4, "bool": SimpleFaker.Bool,
            "json": SimpleFaker.Json, "bytes": SimpleFaker.Bytes,
        }
        types = [
            "timestamp with time zone", "timestamp without time zone", "date",
            "integer", "bigint", "numeric(38,20)", "character varying(255)", "text",
            "uuid", "boolean", "jsonb", "bytea", "text[]", "integer[]",
        ]
        for data_type in types:
            with self.subTest(data_type=data_type):
                kind, args = self.gen(data_type, null_fraction=0.1)
                inspect.signature(classes[kind].__init__).bind(None, **args)

    def test_arguments_bind_for_a_most_common_value_column(self):
        try:
            import inspect

            from dbworkload.utils.simplefaker import SimpleFaker
        except ImportError:
            self.skipTest("dbworkload is not installed")
        _, args = self.gen(
            "text", most_common_values=["a", "b"], most_common_freqs=[0.6, 0.3],
            null_fraction=0.1,
        )
        inspect.signature(SimpleFaker.Choice.__init__).bind(None, **args)

class TestCrdbTypeMapping(unittest.TestCase):
    def test_maps_the_observed_vocabulary(self):
        cases = {
            "smallint": "INT2", "integer": "INT4", "bigint": "INT8",
            "numeric(38,20)": "DECIMAL(38,20)", "numeric": "DECIMAL",
            "real": "FLOAT4", "double precision": "FLOAT8",
            "character varying(255)": "VARCHAR(255)", "character(3)": "CHAR(3)",
            "text": "STRING", "boolean": "BOOL", "bytea": "BYTES",
            "jsonb": "JSONB", "json": "JSONB", "uuid": "UUID", "date": "DATE",
            "timestamp without time zone": "TIMESTAMP",
            "timestamp with time zone": "TIMESTAMPTZ",
            "interval": "INTERVAL", "inet": "INET",
        }
        for pg, crdb in cases.items():
            with self.subTest(pg=pg):
                self.assertEqual(dbprofiler.crdb_type(pg), crdb)

    def test_integer_does_not_widen_to_eight_bytes(self):
        # CockroachDB's bare INT is 8-byte; mapping `integer` to it would
        # silently change the column's width.
        self.assertEqual(dbprofiler.crdb_type("integer"), "INT4")
        self.assertNotEqual(dbprofiler.crdb_type("integer"), "INT")

    def test_arrays_map_their_element_type(self):
        self.assertEqual(dbprofiler.crdb_type("text[]"), "STRING[]")
        self.assertEqual(dbprofiler.crdb_type("integer[]"), "INT4[]")

    def test_an_unknown_type_is_passed_through_not_guessed(self):
        self.assertIn("tsvector", dbprofiler.crdb_type("tsvector"))


def schema_profile():
    """A profile with indexes, a foreign key, and things worth recommending."""
    customer = kit_table("customer", [
        kit_column("id", "uuid", table="customer", is_nullable=False),
        kit_column("status", "character varying(20)", table="customer", ordinal=2),
        kit_column("created_at", "timestamp with time zone", table="customer", ordinal=3),
    ], row_count_estimate=50_000)
    orders = kit_table("orders", [
        kit_column("id", "bigint", table="orders", is_nullable=False, identity="always"),
        kit_column("customer_id", "uuid", table="orders", ordinal=2),
        kit_column("note", "text", table="orders", ordinal=3),
    ], row_count_estimate=900_000)
    return kit_profile(
        tables=[customer, orders],
        relationships=[kit_relationship("orders", "customer",
                                        child_columns=("customer_id",), parent_columns=("id",))],
        indexes=[
            kit_index("customer", "customer_pkey", ["id"], is_primary=True),
            kit_index("customer", "customer_status_idx", ["status"]),
            kit_index("orders", "orders_pkey", ["id"], is_primary=True),
        ],
    )


def render(profile):
    tables = profile["tables"]
    order = dbprofiler.table_load_order(tables, profile["relationships"])
    return dbprofiler.render_crdb_schema(
        KIT_SCHEMA, tables, profile["indexes"], profile["relationships"],
        profile["sequences"], order,
    )


class TestCrdbSchemaGrouping(unittest.TestCase):
    """Everything about one table lives in that table's section."""

    def section(self, body, table):
        marker = f"-- {KIT_SCHEMA}.{table}"
        start = body.index(marker)
        rest = body[start + len(marker):]
        nxt = min(
            (rest.index(f"-- {KIT_SCHEMA}.{o}") for o in ("customer", "orders")
             if o != table and f"-- {KIT_SCHEMA}.{o}" in rest),
            default=len(rest),
        )
        return rest[:nxt]

    def test_a_tables_index_sits_in_its_own_section(self):
        body = render(schema_profile())
        self.assertIn("customer_status_idx", self.section(body, "customer"))
        self.assertNotIn("customer_status_idx", self.section(body, "orders"))

    def test_a_tables_foreign_key_sits_in_its_own_section(self):
        body = render(schema_profile())
        self.assertIn("fk_orders_customer", self.section(body, "orders"))
        self.assertNotIn("fk_orders_customer", self.section(body, "customer"))

    def test_create_table_is_in_the_section_too(self):
        body = render(schema_profile())
        self.assertIn(f"CREATE TABLE {KIT_SCHEMA}.orders", self.section(body, "orders"))

    def test_a_parent_is_created_before_its_child(self):
        body = render(schema_profile())
        self.assertLess(
            body.index(f"CREATE TABLE {KIT_SCHEMA}.customer"),
            body.index(f"CREATE TABLE {KIT_SCHEMA}.orders"),
        )

    def test_the_primary_key_is_inline_on_the_table(self):
        self.assertIn("PRIMARY KEY", self.section(render(schema_profile()), "customer"))

    def test_not_null_is_carried(self):
        self.assertIn("NOT NULL", self.section(render(schema_profile()), "customer"))

    def test_a_descending_key_keeps_its_direction(self):
        profile = schema_profile()
        profile["indexes"].append(
            kit_index("customer", "customer_created_idx", ["created_at"],
                      descending=("created_at",))
        )
        self.assertIn("created_at DESC", render(profile))

    def test_an_include_column_becomes_storing(self):
        profile = schema_profile()
        profile["indexes"].append(
            kit_index("customer", "customer_cover_idx", ["status"], storing=("created_at",))
        )
        self.assertIn("STORING (created_at)", render(profile))


class TestCrdbSchemaCaveats(unittest.TestCase):
    """What the contract cannot express is flagged, never dropped silently."""

    def test_a_partial_index_is_commented_out_and_named(self):
        profile = schema_profile()
        profile["indexes"].append(
            kit_index("customer", "customer_live_idx", ["status"], is_partial=True)
        )
        body = render(profile)
        self.assertIn("customer_live_idx", body)
        line = next(x for x in body.splitlines()
                    if "customer_live_idx" in x and "CREATE" in x)
        self.assertTrue(line.lstrip().startswith("--"), line)

    def test_an_expression_index_is_commented_out_and_named(self):
        profile = schema_profile()
        profile["indexes"].append(
            kit_index("customer", "customer_lower_idx", ["status"], has_expressions=True)
        )
        body = render(profile)
        line = next(x for x in body.splitlines()
                    if "customer_lower_idx" in x and "CREATE" in x)
        self.assertTrue(line.lstrip().startswith("--"), line)

    def test_the_header_says_what_is_missing(self):
        body = render(schema_profile())
        head = body[:body.index("CREATE TABLE")].upper()
        self.assertIn("CHECK", head)
        self.assertIn("SCHEMA.SQL", head)

    def test_the_schema_creates_its_own_namespace_first(self):
        # Applied to a freshly created database, the first CREATE TABLE fails
        # unless the schema exists.
        body = render(schema_profile())
        self.assertIn(f"CREATE SCHEMA IF NOT EXISTS {KIT_SCHEMA};", body)
        self.assertLess(body.index("CREATE SCHEMA"), body.index("CREATE TABLE"))

    def test_no_table_scan_is_taught(self):
        self.assertNotIn("COUNT(", render(schema_profile()).upper())


class TestIndexRecommendations(unittest.TestCase):
    def recs(self, profile, table):
        by_name = {t["name"]: t for t in profile["tables"]}
        return dbprofiler.index_recommendations(
            by_name[table], profile["indexes"], profile["relationships"]
        )

    def test_an_unindexed_foreign_key_is_reported(self):
        text = " ".join(self.recs(schema_profile(), "orders"))
        self.assertIn("customer_id", text)

    def test_an_indexed_foreign_key_is_not_reported(self):
        profile = schema_profile()
        profile["indexes"].append(kit_index("orders", "orders_customer_idx", ["customer_id"]))
        text = " ".join(self.recs(profile, "orders"))
        self.assertNotIn("customer_id", text)

    def test_a_redundant_prefix_index_is_reported(self):
        profile = schema_profile()
        profile["indexes"] += [
            kit_index("customer", "cust_a", ["status"]),
            kit_index("customer", "cust_ab", ["status", "created_at"]),
        ]
        found = self.recs(profile, "customer")
        self.assertTrue(any("cust_a" in r and "cust_ab" in r for r in found))

    def test_a_duplicate_index_is_reported(self):
        profile = schema_profile()
        profile["indexes"].append(kit_index("customer", "customer_status_dup", ["status"]))
        self.assertTrue(any("duplicat" in r.lower() for r in self.recs(profile, "customer")))

    def test_a_sequential_primary_key_is_flagged_as_a_hotspot(self):
        text = " ".join(self.recs(schema_profile(), "orders")).lower()
        self.assertIn("hash", text)

    def test_a_uuid_primary_key_is_not_flagged_as_a_hotspot(self):
        text = " ".join(self.recs(schema_profile(), "customer")).lower()
        self.assertNotIn("hash", text)

    def test_an_always_null_indexed_column_is_reported(self):
        profile = schema_profile()
        for t in profile["tables"]:
            if t["name"] == "customer":
                t["columns"][1]["null_fraction"] = 1.0
        self.assertTrue(any("null" in r.lower() for r in self.recs(profile, "customer")))

    def test_a_weak_leading_column_is_reported(self):
        profile = schema_profile()
        for t in profile["tables"]:
            if t["name"] == "customer":
                t["columns"][1]["distinct_estimate"] = 2.0
        self.assertTrue(any("distinct" in r.lower() for r in self.recs(profile, "customer")))

    def test_a_clean_table_gets_no_recommendation_block(self):
        profile = kit_profile(
            tables=[kit_table("solo", [kit_column("id", "uuid", table="solo", is_nullable=False)])],
            relationships=[],
            indexes=[kit_index("solo", "solo_pkey", ["id"], is_primary=True)],
        )
        self.assertEqual(self.recs(profile, "solo"), [])
        self.assertNotIn("Index recommendations", render(profile))


class TestCrdbSchemaInKit(unittest.TestCase):
    def test_the_schema_joins_the_kit_file_set(self):
        kit = dbprofiler.build_kit(schema_profile(), scale=1, procs=8)
        self.assertIn("schema.crdb.sql", kit.files)

    def test_the_driver_defaults_to_it(self):
        kit = dbprofiler.build_kit(schema_profile(), scale=1, procs=8)
        driver = kit.files["reproduce.sh"]
        self.assertIn("schema.crdb.sql", driver)
        # ... and only when --schema-file was not given.
        self.assertIn('[[ -n "$SCHEMA_FILE"', driver)

class TestRecommendationsIgnoreUndescribedIndexes(unittest.TestCase):
    """A partial or expression index must not be judged by its column list."""

    def recs(self, profile, table):
        by_name = {t["name"]: t for t in profile["tables"]}
        return dbprofiler.index_recommendations(
            by_name[table], profile["indexes"], profile["relationships"]
        )

    def test_a_partial_index_is_not_called_a_duplicate(self):
        profile = schema_profile()
        profile["indexes"].append(
            kit_index("customer", "customer_live_idx", ["status"], is_partial=True)
        )
        joined = " ".join(self.recs(profile, "customer"))
        self.assertNotIn("customer_live_idx", joined)

    def test_an_expression_index_is_not_called_a_duplicate(self):
        profile = schema_profile()
        profile["indexes"].append(
            kit_index("customer", "customer_expr_idx", ["status"], has_expressions=True)
        )
        joined = " ".join(self.recs(profile, "customer"))
        self.assertNotIn("customer_expr_idx", joined)

    def test_a_partial_index_does_not_count_as_covering_a_foreign_key(self):
        profile = schema_profile()
        profile["indexes"].append(
            kit_index("orders", "orders_cust_partial", ["customer_id"], is_partial=True)
        )
        self.assertTrue(any("customer_id" in r for r in self.recs(profile, "orders")))

class TestTargetUrl(unittest.TestCase):
    """A target URL is recorded for the driver, never with its credentials.

    The kit is a directory of files that gets copied, archived and shared. A
    connection string written into it is a credential at rest, so the userinfo
    is stripped before anything reaches disk and the identity comes from PGUSER
    and PGPASSWORD at run time -- the pattern reproduce.sh already documents.
    """

    TARGET = f"postgresql://{HOST}:26257/example-db?sslmode=verify-full"
    WITH_CREDS = f"postgresql://{USER}:{PASSWORD}@{HOST}:26257/example-db?sslmode=verify-full"

    def test_the_env_var_is_named_for_the_tool(self):
        self.assertEqual(dbprofiler.TARGET_URL_ENV_VAR, "DBPROFILER_TARGET_URL")

    def test_a_clean_url_survives_intact(self):
        dsn, had = dbprofiler.target_dsn(self.TARGET)
        self.assertFalse(had)
        self.assertIn(HOST, dsn)
        self.assertIn("26257", dsn)
        self.assertIn("example-db", dsn)
        self.assertIn("sslmode=verify-full", dsn)

    def test_a_password_never_survives(self):
        dsn, had = dbprofiler.target_dsn(self.WITH_CREDS)
        self.assertTrue(had)
        self.assertNotIn(PASSWORD, dsn)

    def test_a_username_is_stripped_too(self):
        dsn, _ = dbprofiler.target_dsn(self.WITH_CREDS)
        self.assertNotIn(USER, dsn)
        self.assertNotIn("@", dsn)

    def test_the_stripped_url_keeps_everything_that_is_not_secret(self):
        dsn, _ = dbprofiler.target_dsn(self.WITH_CREDS)
        for part in (HOST, "26257", "example-db", "sslmode=verify-full"):
            with self.subTest(part=part):
                self.assertIn(part, dsn)

    def test_a_bad_scheme_is_refused(self):
        with self.assertRaises(dbprofiler.ConfigError):
            dbprofiler.target_dsn("mysql://" + HOST + "/example-db")

    def test_an_error_never_quotes_the_url(self):
        with self.assertRaises(dbprofiler.ConfigError) as caught:
            dbprofiler.target_dsn("mysql://" + USER + ":" + PASSWORD + "@" + HOST + "/x")
        message = str(caught.exception)
        for secret in (PASSWORD, USER, HOST):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, message)

    def test_a_url_with_no_host_is_refused(self):
        with self.assertRaises(dbprofiler.ConfigError):
            dbprofiler.target_dsn("postgresql:///example-db")


class TestTargetUrlInKit(unittest.TestCase):
    TARGET = f"postgresql://{HOST}:26257/example-db"
    WITH_CREDS = f"postgresql://{USER}:{PASSWORD}@{HOST}:26257/example-db"

    def kit(self, target=None):
        return dbprofiler.build_kit(kit_profile(), scale=1, procs=8, target_url=target)

    def test_the_driver_records_the_target(self):
        driver = self.kit(self.TARGET).files["reproduce.sh"]
        self.assertIn(self.TARGET, driver)

    def test_no_credential_reaches_any_file(self):
        for name, body in self.kit(self.WITH_CREDS).entries:
            with self.subTest(name=name):
                self.assertNotIn(PASSWORD, body)
                self.assertNotIn(USER + ":", body)

    def test_the_recorded_target_is_not_a_credentialed_url(self):
        driver = self.kit(self.WITH_CREDS).files["reproduce.sh"]
        self.assertIsNone(dbprofiler.CREDENTIALED_URL.search(driver))

    def test_the_environment_still_overrides_at_run_time(self):
        driver = self.kit(self.TARGET).files["reproduce.sh"]
        self.assertIn("DBPROFILER_TARGET_URL", driver)
        self.assertIn('${DSN:-', driver)

    def test_without_a_target_the_driver_still_demands_one(self):
        driver = self.kit().files["reproduce.sh"]
        self.assertIn("DSN is not set", driver)

    def test_the_cli_accepts_the_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = write_kit_bundle(Path(tmp) / "bundle")
            out = Path(tmp) / "kit"
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                status = dbprofiler.main([
                    "generate", "--bundle", str(bundle), "--output", str(out),
                    "--target-url", self.TARGET,
                ])
            self.assertEqual(status, 0)
            self.assertIn(self.TARGET, (out / "reproduce.sh").read_text())

    def test_the_cli_reads_the_environment_variable(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = write_kit_bundle(Path(tmp) / "bundle")
            out = Path(tmp) / "kit"
            env = {dbprofiler.TARGET_URL_ENV_VAR: self.TARGET}
            with mock.patch.dict(os.environ, env, clear=False):
                with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                    status = dbprofiler.main(
                        ["generate", "--bundle", str(bundle), "--output", str(out)]
                    )
            self.assertEqual(status, 0)
            self.assertIn(self.TARGET, (out / "reproduce.sh").read_text())

    def test_the_cli_says_when_it_dropped_a_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = write_kit_bundle(Path(tmp) / "bundle")
            out = Path(tmp) / "kit"
            stderr = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                dbprofiler.main([
                    "generate", "--bundle", str(bundle), "--output", str(out),
                    "--target-url", self.WITH_CREDS,
                ])
            message = stderr.getvalue()
            self.assertIn("PGPASSWORD", message)
            self.assertNotIn(PASSWORD, message)

class TestKitManifest(unittest.TestCase):
    """The kit records what it is, so the driver need not parse shell."""

    def test_the_kit_carries_a_manifest(self):
        kit = dbprofiler.build_kit(kit_profile(), scale=7, procs=4)
        self.assertIn("kit.json", kit.files)
        manifest = json.loads(kit.files["kit.json"])
        self.assertEqual(manifest["schema"], KIT_SCHEMA)
        self.assertEqual(manifest["procs"], 4)
        self.assertEqual(manifest["scale"], 7)

    def test_the_manifest_lists_tables_in_foreign_key_order(self):
        manifest = json.loads(dbprofiler.build_kit(kit_profile()).files["kit.json"])
        self.assertEqual(manifest["tables"], ["parent", "child"])

    def test_the_manifest_names_the_generated_files(self):
        manifest = json.loads(dbprofiler.build_kit(kit_profile()).files["kit.json"])
        self.assertEqual(manifest["yaml"], f"{KIT_SCHEMA}.yaml")
        self.assertEqual(manifest["schema_sql"], "schema.crdb.sql")

    def test_read_kit_manifest_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "kit"
            dbprofiler.write_kit(dbprofiler.build_kit(kit_profile(), scale=3, procs=8), out)
            manifest = dbprofiler.read_kit_manifest(out)
            self.assertEqual(manifest["procs"], 8)

    def test_a_directory_that_is_not_a_kit_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(dbprofiler.ConfigError) as caught:
                dbprofiler.read_kit_manifest(Path(tmp))
        self.assertIn("kit.json", str(caught.exception))


class TestTargetSqlAudit(unittest.TestCase):
    """Statements issued against a reproduction target are a third category."""

    def test_target_constants_are_enumerated(self):
        names = {name for name, _ in dbprofiler.iter_target_sql_constants()}
        self.assertTrue(names)
        self.assertTrue(all(n.startswith("TARGET_SQL_") for n in names))

    def test_analyze_is_allowed_against_a_target(self):
        # The reproduction was just bulk loaded; the planner has nothing until
        # its statistics are built. That is not a read of anyone's source.
        self.assertEqual(dbprofiler.audit_target_sql("ANALYZE"), [])

    def test_a_table_scan_is_still_refused(self):
        self.assertTrue(dbprofiler.audit_target_sql("SELECT COUNT(*) FROM t"))

    def test_create_statistics_is_still_refused(self):
        self.assertTrue(dbprofiler.audit_target_sql("CREATE STATISTICS s ON a FROM t"))

    def test_a_credentialed_url_is_refused(self):
        self.assertTrue(
            dbprofiler.audit_target_sql(f"-- postgres://{USER}:{PASSWORD}@{HOST}/db")
        )

    def test_no_shipped_target_constant_violates_the_rule(self):
        for name, sql in dbprofiler.iter_target_sql_constants():
            with self.subTest(name=name):
                self.assertEqual(dbprofiler.audit_target_sql(sql), [])

    def test_source_constants_still_ban_analyze(self):
        self.assertTrue(dbprofiler.audit_sql("ANALYZE"))

    def test_check_safety_reports_all_three_categories(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(dbprofiler.check_safety(), 0)
        line = stdout.getvalue()
        self.assertIn("SQL constant", line)
        self.assertIn("target", line)
        self.assertIn("emitted template", line)


class TestReproduceConfig(unittest.TestCase):
    TARGET = f"postgresql://{HOST}:26257/example-db"

    def args(self, **kw):
        base = dict(target_url=self.TARGET, psql_path="psql",
                    dbworkload_path="dbworkload", timeout=3600)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_the_target_url_becomes_libpq_environment(self):
        config = dbprofiler.build_target_config(self.args(), env={})
        self.assertEqual(config.env["PGHOST"], HOST)
        self.assertEqual(config.env["PGDATABASE"], "example-db")

    def test_the_environment_variable_is_the_default(self):
        config = dbprofiler.build_target_config(
            self.args(target_url=None), env={dbprofiler.TARGET_URL_ENV_VAR: self.TARGET}
        )
        self.assertEqual(config.env["PGHOST"], HOST)

    def test_a_missing_target_names_the_variable(self):
        with self.assertRaises(dbprofiler.ConfigError) as caught:
            dbprofiler.build_target_config(self.args(target_url=None), env={})
        self.assertIn(dbprofiler.TARGET_URL_ENV_VAR, str(caught.exception))

    def test_the_config_never_prints_its_password(self):
        config = dbprofiler.build_target_config(
            self.args(target_url=f"postgresql://{USER}:{PASSWORD}@{HOST}/example-db"), env={}
        )
        self.assertNotIn(PASSWORD, repr(config))

    def test_the_timeout_is_generous_enough_for_a_load(self):
        # A bulk load is not a catalog query; the collector's 300s would abort it.
        self.assertGreaterEqual(dbprofiler.DEFAULT_REPRODUCE_TIMEOUT, 3600)


class TestReproduceSteps(unittest.TestCase):
    def test_the_steps_are_in_dependency_order(self):
        self.assertEqual(
            list(dbprofiler.REPRODUCE_STEPS),
            ["schema", "generate", "load", "validate", "analyze"],
        )

    def test_an_unknown_step_is_refused(self):
        with self.assertRaises(dbprofiler.ConfigError):
            dbprofiler.selected_steps("schema,nonsense")

    def test_a_subset_keeps_dependency_order(self):
        self.assertEqual(dbprofiler.selected_steps("analyze,schema"), ["schema", "analyze"])

    def test_no_selection_means_everything(self):
        self.assertEqual(dbprofiler.selected_steps(None), list(dbprofiler.REPRODUCE_STEPS))


class TestReproduceDrivesChildren(unittest.TestCase):
    """What reproduce actually runs, without running anything."""

    def kit_dir(self, tmp):
        out = Path(tmp) / "kit"
        dbprofiler.write_kit(dbprofiler.build_kit(kit_profile(), scale=1, procs=8), out)
        (out / "csv").mkdir()
        for table in ("parent", "child"):
            (out / "csv" / f"{KIT_SCHEMA}.{table}.0_0_0.tsv").write_text("x\n")
        return out

    def run_with_spy(self, tmp, steps, regenerate=False):
        calls = []

        def spy(argv, config, what):
            script = ""
            if "-f" in argv:
                path = Path(argv[argv.index("-f") + 1])
                if path.is_file():
                    script = path.read_text()
            calls.append((what, list(argv), script))
            return ""

        args = argparse.Namespace(
            kit=str(self.kit_dir(tmp)), target_url=f"postgresql://{HOST}:26257/example-db",
            psql_path="psql", dbworkload_path="dbworkload",
            timeout=dbprofiler.DEFAULT_REPRODUCE_TIMEOUT, steps=steps,
            regenerate=regenerate,
        )
        with mock.patch.object(dbprofiler, "run_command", spy):
            dbprofiler.run_reproduce(args)
        return calls

    def test_the_schema_step_applies_the_generated_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = self.run_with_spy(tmp, "schema")
            self.assertEqual(len(calls), 1)
            what, argv, _ = calls[0]
            self.assertEqual(what, "psql")
            self.assertIn("-f", argv)
            self.assertTrue(any(a.endswith("schema.crdb.sql") for a in argv))

    def test_the_generate_step_invokes_dbworkload_with_the_kit_procs(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = self.run_with_spy(tmp, "generate", regenerate=True)
            what, argv, _ = calls[0]
            self.assertEqual(what, "dbworkload")
            self.assertIn("csv", argv)
            self.assertIn("-x", argv)
            self.assertEqual(argv[argv.index("-x") + 1], "8")

    def test_the_load_step_runs_one_psql_per_table_in_fk_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = self.run_with_spy(tmp, "load")
            self.assertEqual([what for what, _, _ in calls], ["psql", "psql"])
            scripts = "\n".join(script for _, _, script in calls)
            self.assertIn("\\copy", scripts)
            self.assertLess(scripts.index("parent"), scripts.index("child"))

    def test_nothing_puts_a_credential_on_a_command_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            for _, argv, _ in self.run_with_spy(tmp, "schema,generate,load"):
                for arg in argv:
                    with self.subTest(arg=arg):
                        self.assertIsNone(dbprofiler.CREDENTIALED_URL.search(arg))
                        self.assertNotIn(PASSWORD, arg)

    def test_the_load_step_never_uses_stdin(self):
        # run_command passes stdin=DEVNULL, so a \\copy FROM STDIN would hang.
        with tempfile.TemporaryDirectory() as tmp:
            for _, argv, script in self.run_with_spy(tmp, "load"):
                self.assertNotIn("STDIN", (" ".join(argv) + script).upper())

class TestLoadFailureExplanation(unittest.TestCase):
    def test_a_foreign_key_violation_names_the_stub(self):
        raw = dbprofiler.CommandError(
            'psql exited with status 3: ERROR: insert on table "orders" violates '
            'foreign key constraint "fk_orders_customer"'
        )
        explained = str(dbprofiler._explain_load_failure(raw, "orders"))
        self.assertIn("keys.py", explained)
        self.assertIn("expected", explained)

    def test_the_original_error_is_kept(self):
        raw = dbprofiler.CommandError("ERROR: violates foreign key constraint \"fk_x\"")
        self.assertIn("fk_x", str(dbprofiler._explain_load_failure(raw, "t")))

    def test_an_unrelated_failure_is_passed_through_untouched(self):
        raw = dbprofiler.CommandError("psql: could not connect to server")
        self.assertIs(dbprofiler._explain_load_failure(raw, "t"), raw)

class TestUniqueColumnWarnings(unittest.TestCase):
    def readme(self, profile):
        return dbprofiler.build_kit(profile, scale=1, procs=8).files["README.md"]

    def test_an_integer_primary_key_is_flagged(self):
        readme = self.readme(schema_profile())
        self.assertIn("orders.id", readme)
        self.assertIn("duplicate key", readme.lower())

    def test_a_uuid_primary_key_is_not_flagged(self):
        readme = self.readme(schema_profile())
        section = readme[readme.index("Unique columns"):] if "Unique columns" in readme else ""
        self.assertNotIn("customer.id", section)

    def test_a_unique_index_counts_too(self):
        profile = schema_profile()
        profile["indexes"].append(
            kit_index("customer", "customer_status_uq", ["status"], is_unique=True)
        )
        self.assertIn("customer.status", self.readme(profile))

    def test_a_duplicate_key_failure_names_the_stub(self):
        raw = dbprofiler.CommandError(
            'ERROR: duplicate key value violates unique constraint "orders_pkey"'
        )
        explained = str(dbprofiler._explain_load_failure(raw, "orders"))
        self.assertIn("keys.py", explained)
        self.assertIn("unique", explained.lower())

class TestAnalyzeStep(unittest.TestCase):
    def test_analyze_names_a_table(self):
        # CockroachDB rejects a bare ANALYZE; PostgreSQL accepts either form.
        self.assertIn("{table}", dbprofiler.TARGET_SQL_ANALYZE)
        rendered = dbprofiler.TARGET_SQL_ANALYZE.format(table="s.t")
        self.assertEqual(rendered.strip(), "ANALYZE s.t")

    def test_one_analyze_per_table(self):
        calls = []
        config = dbprofiler.PostgresConfig(env={}, output=Path("."))
        with mock.patch.object(dbprofiler, "run_psql", lambda sql, c: calls.append(sql) or []):
            dbprofiler._reproduce_analyze(
                {"schema": "shop", "tables": ["a", "b"]}, config
            )
        self.assertEqual(calls, ["ANALYZE shop.a", "ANALYZE shop.b"])

class TestReproduceEntryPoints(unittest.TestCase):
    """How much you supply decides where the one command starts."""

    def test_a_kit_is_driven_directly(self):
        self.assertEqual(dbprofiler.reproduce_start(kit="k", bundle=None), "kit")

    def test_a_bundle_is_generated_then_driven(self):
        self.assertEqual(dbprofiler.reproduce_start(kit=None, bundle="b.zip"), "bundle")

    def test_neither_means_collect_first(self):
        self.assertEqual(dbprofiler.reproduce_start(kit=None, bundle=None), "source")

    def test_both_is_refused_rather_than_ranked(self):
        with self.assertRaises(dbprofiler.ConfigError) as caught:
            dbprofiler.reproduce_start(kit="k", bundle="b.zip")
        self.assertIn("--kit", str(caught.exception))


class TestReproduceFullPipeline(unittest.TestCase):
    def args(self, tmp, **kw):
        base = dict(
            kit=None, bundle=None, workdir=str(tmp), scale=1, procs=8, schema=None,
            steps="schema", regenerate=False, force=False,
            target_url=f"postgresql://{HOST}:26257/example-db", url=None,
            psql_path="psql", pg_dump_path="pg_dump", dbworkload_path="dbworkload",
            timeout=dbprofiler.DEFAULT_REPRODUCE_TIMEOUT,
            schema_include=None, schema_exclude=None, output=None,
        )
        base.update(kw)
        return argparse.Namespace(**base)

    def test_a_bundle_is_turned_into_a_kit_in_the_workdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = write_kit_bundle(Path(tmp) / "bundle")
            calls = []
            with mock.patch.object(dbprofiler, "run_command",
                                   lambda a, c, w: calls.append(w) or ""):
                with contextlib.redirect_stdout(io.StringIO()), \
                     contextlib.redirect_stderr(io.StringIO()):
                    dbprofiler.run_reproduce(self.args(tmp, bundle=str(bundle)))
            self.assertTrue((Path(tmp) / "bundle-kit" / "kit.json").exists())
            self.assertEqual(calls, ["psql"])

    def test_collection_runs_when_nothing_is_supplied(self):
        with tempfile.TemporaryDirectory() as tmp:
            collected = []

            def fake_collect(args):
                collected.append(Path(args.output))
                write_kit_bundle(Path(tmp) / "src")
                shutil.make_archive(str(Path(tmp) / "source-profile"), "zip",
                                    str(Path(tmp) / "src"))
                return 0

            with mock.patch.object(dbprofiler, "run_postgres", fake_collect), \
                 mock.patch.object(dbprofiler, "run_command", lambda a, c, w: ""):
                with contextlib.redirect_stdout(io.StringIO()), \
                     contextlib.redirect_stderr(io.StringIO()):
                    dbprofiler.run_reproduce(self.args(tmp))
            self.assertEqual(len(collected), 1)
            self.assertEqual(collected[0].suffix, ".zip")
            self.assertEqual(collected[0].parent, Path(tmp))

    def test_the_workdir_defaults_to_the_current_directory(self):
        self.assertEqual(dbprofiler.reproduce_workdir(None), Path.cwd())

    def test_a_named_workdir_is_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(dbprofiler.reproduce_workdir(tmp), Path(tmp))

    def test_stdout_is_the_kit_path_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = write_kit_bundle(Path(tmp) / "bundle")
            out = io.StringIO()
            with mock.patch.object(dbprofiler, "run_command", lambda a, c, w: ""):
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    dbprofiler.run_reproduce(self.args(tmp, bundle=str(bundle)))
            self.assertEqual(out.getvalue().strip(), str(Path(tmp) / "bundle-kit"))


class TestReproduceCliSurface(unittest.TestCase):
    def parse(self, argv):
        return dbprofiler.build_parser().parse_args(argv)

    def test_kit_is_no_longer_required(self):
        args = self.parse(["reproduce"])
        self.assertIsNone(args.kit)
        self.assertIsNone(args.bundle)

    def test_the_whole_pipeline_has_the_flags_it_needs(self):
        args = self.parse(["reproduce", "--scale", "70", "--procs", "4",
                           "--schema", "s", "--workdir", "/srv/work"])
        self.assertEqual((args.scale, args.procs, args.schema), (70, 4, "s"))
        self.assertEqual(args.workdir, "/srv/work")
# --- continuous integration -------------------------------------------------
#
# The integration suite is the only thing in this repository that exercises a
# real server: subprocess handling, CSV parsing, pg_stat_statements, the whole
# bundle. It is also opt-in, which means a CI job that forgets to configure it
# reports success having run nothing at all. These tests read ci.yaml as text
# and keep that from being possible.

CI_WORKFLOW = REPO / ".github" / "workflows" / "ci.yaml"


class TestCIWorkflow(unittest.TestCase):
    def setUp(self):
        self.text = CI_WORKFLOW.read_text()
        self.lines = self.text.splitlines()

    def index_of(self, needle):
        for number, line in enumerate(self.lines):
            if needle in line:
                return number
        raise AssertionError(f"{needle!r} not found in {CI_WORKFLOW.name}")

    def shell_text(self):
        """Every line a runner executes as a shell command, and nothing else.

        A `run:` opens a block that ends where the indentation comes back, so
        this separates what lands in a process's argv from what stays a YAML
        value. Cheaper than a parser, and this repository has no YAML parser.
        """
        collected = []
        depth = None
        for line in self.lines:
            indent = len(line) - len(line.lstrip())
            if depth is not None and line.strip() and indent <= depth:
                depth = None
            if depth is not None:
                collected.append(line)
            match = re.match(r"(\s*)-?\s*run:(.*)", line)
            if match:
                collected.append(match.group(2))
                depth = len(match.group(1))
        return "\n".join(collected)

    def test_the_integration_suite_actually_runs(self):
        """79 tests that only ever run on a laptop are 79 tests nobody has to
        keep passing."""
        self.assertRegex(self.text, r"(?m)^  integration:\s*$")
        self.assertIn("unittest integration_test", self.text)

    def test_a_job_that_skips_every_test_cannot_pass(self):
        """The most important assertion here. Every class in integration_test is
        skipUnless(CONFIGURED), so an unset or misspelled URL variable skips all
        79 and turns the job green having tested nothing. The guard asserts the
        module's own gate rather than re-reading the variable by name, so it
        cannot drift away from the thing it guards.
        """
        self.assertIn("integration_test", self.text)
        self.assertIn("CONFIGURED", self.text)
        self.assertLess(
            self.index_of("CONFIGURED"), self.index_of("unittest integration_test")
        )

    def test_the_server_is_the_committed_compose_file(self):
        """CI and a laptop must start the same server. A services: container
        cannot override the image command, so it could not preload
        pg_stat_statements, and the suite would quietly exercise the profiler's
        degradation path instead. --wait blocks on the health check, so the
        first connection cannot race the server.
        """
        self.assertIn(f"-f {COMPOSE_FILE.name} up -d --wait", self.text)

    def test_the_server_is_destroyed_even_when_the_suite_fails(self):
        """A kept volume is how a fixture from an earlier run reaches a later
        assertion, and a failing suite is exactly when one gets left behind."""
        teardown = self.index_of("down -v")
        self.assertIn("if: always()", "\n".join(self.lines[teardown - 4:teardown]))

    def test_the_client_is_checked_against_the_pinned_server(self):
        """pg_dump refuses to dump from a server newer than itself, so bumping
        the image without a client to match has to fail here rather than inside
        an unexplained dump error."""
        major = re.search(r"image:\s*postgres:(\d+)", COMPOSE_FILE.read_text()).group(1)
        self.assertIn("pg_dump --version", self.text)
        self.assertIn(f"-lt {major}", self.text)

    def test_no_credential_reaches_a_command_line(self):
        """Credentials reach children through env=, never argv: an argument is
        visible in the process table to anything that can read it."""
        for line in self.lines:
            if re.search(r"://[^/\s]*:[^/\s]*@", line):
                self.assertRegex(line, r"^\s*[A-Z_]+:\s")
        shell = self.shell_text()
        self.assertNotRegex(shell, r"://[^/\s]*:[^/\s]*@")
        self.assertNotIn("example-password", shell)

    def test_it_uses_no_secret(self):
        """Nothing here is worth a secret: the server is disposable and its
        credentials are the synthetic ones the repository documents."""
        self.assertNotIn("secrets.", self.text)

    def test_it_never_asks_for_write_permission(self):
        jobs = self.index_of("jobs:")
        self.assertIn("contents: read", "\n".join(self.lines[:jobs]))
        self.assertNotIn("contents: write", self.text)

    def test_every_action_is_pinned_to_a_major_version(self):
        for match in re.finditer(r"uses:\s*(\S+)", self.text):
            with self.subTest(action=match.group(1)):
                self.assertRegex(match.group(1), r"@v\d+$")


if __name__ == "__main__":
    unittest.main()
