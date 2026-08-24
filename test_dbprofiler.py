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
