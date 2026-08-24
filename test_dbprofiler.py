# Copyright (c) 2026 Cockroach Labs, Inc.
# SPDX-License-Identifier: MIT
"""Unit tests for dbprofiler.

Run with:  python3 -m unittest -v

These tests never open a network connection and never reference a real
connection string. Anything resembling a credential in this file is synthetic.
"""

import contextlib
import io
import unittest
from unittest import mock

import dbprofiler


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
        """The guard must actually fail on a violation, not just pass vacuously.

        Without this, --check-safety returning 0 would prove nothing while the
        set of SQL_* constants is still empty.
        """
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

    def test_postgres_subcommand_is_not_implemented_yet(self):
        # Replace with a real orchestration test in task 10.
        with self.assertRaises(NotImplementedError):
            dbprofiler.main(["postgres", "--output", "profile.zip"])


if __name__ == "__main__":
    unittest.main()
