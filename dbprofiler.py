#!/usr/bin/env python3
# Copyright (c) 2026 Cockroach Labs, Inc.
# SPDX-License-Identifier: MIT
"""dbprofiler — source-profile collection for CockroachDB migration planning.

Connects to a source database, collects a schema and a catalog-derived data-shape
profile, and publishes a checksummed ZIP bundle suitable for sharing with a
migration team.

SAFETY BOUNDARY
===============

This tool does not read your data. Concretely, and enforced mechanically by
``python3 dbprofiler.py --check-safety``:

  * No ``COUNT(*)`` and no scans over user tables. Row counts come from the
    planner's own estimates (``pg_class.reltuples``).
  * No ``ANALYZE`` against customer data. Statistics are read as PostgreSQL
    already computed them.
  * No ``CREATE STATISTICS``. Extended statistics are read only if they already
    exist.
  * Queries touch only catalog and statistics views (``pg_catalog.*``,
    ``pg_stat_*``, ``pg_stats``, ``pg_stats_ext``, ``pg_stat_statements``).
  * Credentials are never placed on a child process command line and never
    appear in logs, errors, or the published bundle.

Catalog statistics can still embed literal user values -- ``pg_stats`` most-common
values and histogram bounds, and query text in ``pg_stat_statements``. Every such
value is replaced by an HMAC-SHA-256 token before it reaches the filesystem. Equal
values tokenize equally within a domain, which preserves the join and skew shape a
migration needs without disclosing the values themselves.

Everything the tool does lives in this one file, so that a reviewer can read it
end to end before running it against a production database.

USAGE
=====

    export DBPROFILER_POSTGRES_URL='postgres://...'
    export DBPROFILER_TOKEN_KEY='...'

    python3 dbprofiler.py postgres --output source-profile.zip
    python3 dbprofiler.py --check-safety
    python3 dbprofiler.py --version
"""

from __future__ import annotations

import argparse
import sys

VERSION = "dev"

# Version of the normalized profile contract written to profile.json. Any change
# to field names or semantics in the contract dataclasses must bump this.
CONTRACT_VERSION = "1.0"

PROG = "dbprofiler"


# ---------------------------------------------------------------------------
# Safety boundary
# ---------------------------------------------------------------------------

# Tokens that must never appear in any SQL_* constant. Matched case-insensitively
# against whitespace-normalized SQL by check_safety().
SAFETY_FORBIDDEN = (
    "COUNT(",
    "ANALYZE",
    "CREATE STATISTICS",
)


def iter_sql_constants():
    """Yield (name, sql) for every module-level SQL_* constant.

    Every query this tool issues is declared as a module-level constant named
    SQL_* precisely so that check_safety() can enumerate them without executing
    anything.
    """
    for name, value in sorted(globals().items()):
        if name.startswith("SQL_") and isinstance(value, str):
            yield name, value


def check_safety() -> int:
    """Audit this file's own SQL against the safety boundary.

    Returns a process exit status: 0 when clean, 1 when any violation is found.
    Run in CI against every commit.
    """
    violations = []

    for name, sql in iter_sql_constants():
        # Collapse whitespace and close the "COUNT (*)" gap so the token match
        # cannot be evaded by formatting.
        normalized = " ".join(sql.split()).upper().replace(" (", "(")
        for token in SAFETY_FORBIDDEN:
            if token in normalized:
                violations.append(f"{name}: contains forbidden token {token!r}")

    # TODO(task-3): extend with the relation allowlist and a scan for connection
    # strings passed on a subprocess command line.

    checked = sum(1 for _ in iter_sql_constants())
    if violations:
        print(f"{PROG} --check-safety: FAIL ({len(violations)} violation(s))", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1

    print(f"{PROG} --check-safety: OK ({checked} SQL constant(s) checked)")
    return 0


# ---------------------------------------------------------------------------
# SQL constants
# ---------------------------------------------------------------------------
# (task 2 onward) Every query lives here, named SQL_*, so --check-safety can find it.


# ---------------------------------------------------------------------------
# Contract types
# ---------------------------------------------------------------------------
# (task 2) Profile, Source, Table, Column, Relationship, FanOut, Manifest,
# Observation, Warning.


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------
# (task 3) SafeEnv, redact_error(), run_psql(), run_pg_dump().


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------
# (tasks 4-6) collect_schema(), collect_catalog(), collect_workload(), fingerprint().


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------
# (task 7) tokenize(value, domain).


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
# (task 8) normalize_columns(), normalize_fk_fanout().


# ---------------------------------------------------------------------------
# Bundle publication
# ---------------------------------------------------------------------------
# (task 9) write_bundle().


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_postgres(args: argparse.Namespace) -> int:
    """Collect a profile from a PostgreSQL source and publish the bundle."""
    # (task 10) validate config -> probe version -> fingerprint-before -> pg_dump
    # -> catalog -> workload -> tokenize -> normalize -> fingerprint-after -> publish.
    raise NotImplementedError("the postgres subcommand is not implemented yet")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Collect a shareable source profile for CockroachDB migration planning.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=VERSION,
        help="print the version and exit",
    )
    parser.add_argument(
        "--check-safety",
        action="store_true",
        help="audit this file's own SQL against the safety boundary and exit",
    )

    # Not required: --check-safety and --version are valid without a subcommand.
    subparsers = parser.add_subparsers(dest="command", metavar="SOURCE")

    postgres = subparsers.add_parser("postgres", help="profile a PostgreSQL 16 source")
    postgres.add_argument(
        "--output",
        required=True,
        help="path to write the profile bundle (must end in .zip)",
    )
    # (task 2) --url, --schema-include, --schema-exclude, --pg-dump-path,
    # --psql-path, --timeout.

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.check_safety:
        return check_safety()

    if args.command == "postgres":
        return run_postgres(args)

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
