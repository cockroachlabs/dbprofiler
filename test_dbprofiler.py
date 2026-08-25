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

import contextlib
import dataclasses
import io
import subprocess
import unittest
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
        with mock.patch(
            "subprocess.run", return_value=completed(stdout="pg_dump (PostgreSQL) 16.2\n")
        ) as run:
            self.assertEqual(dbprofiler.probe_pg_dump_major(a_config()), 16)
        self.assertEqual(run.call_args.args[0], ["pg_dump", "-w", "--version"])

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
        self.assertEqual(argvs[0], ["pg_dump", "-w", "--version"])
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

    def test_collection_is_not_implemented_yet(self):
        # Replace with a real orchestration test in task 10.
        with mock.patch.dict("os.environ", {"DBPROFILER_POSTGRES_URL": URL}, clear=True):
            with self.assertRaises(NotImplementedError):
                dbprofiler.main(["postgres", "--output", "profile.zip"])


if __name__ == "__main__":
    unittest.main()
