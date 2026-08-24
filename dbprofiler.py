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
import os
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

VERSION = "dev"

# Version of the normalized profile contract written to profile.json. Any change
# to field names or semantics in the contract dataclasses must bump this.
CONTRACT_VERSION = "1.0"

PROG = "dbprofiler"

URL_ENV_VAR = "DBPROFILER_POSTGRES_URL"
# The name of the variable, not a key. The key itself is only ever read from the
# environment at runtime and is never stored in a module constant.
TOKEN_KEY_ENV_VAR = "DBPROFILER_TOKEN_KEY"  # noqa: S105

DEFAULT_TIMEOUT_SECONDS = 300

# MVP supports PostgreSQL 16 only. The catalog and statistics views this tool
# reads change shape between majors, so a wrong guess yields confidently wrong
# numbers -- worse than refusing to run.
SUPPORTED_MAJOR = 16
MIN_SERVER_VERSION_NUM = 160000
MAX_SERVER_VERSION_NUM = 170000

REDACTED = "***"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class DbprofilerError(Exception):
    """Base for errors reported to the user without a traceback.

    Messages must never contain a connection string, a credential, or any part
    of one. Assume every message is printed and pasted into a support ticket.
    """


class ConfigError(DbprofilerError):
    """Invalid or missing configuration."""


class UnsupportedServerVersion(DbprofilerError):
    """The source server is not a PostgreSQL major this release supports."""


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
# Every query lives here, named SQL_*, so --check-safety can find it by reflection.
# A query built inline is a query the audit cannot see.

SQL_SERVER_VERSION = "SELECT current_setting('server_version_num')::int"


# ---------------------------------------------------------------------------
# Contract types
# ---------------------------------------------------------------------------
# The shape of profile.json and manifest.json. Frozen so a collector cannot
# mutate a record after another has read it, and tuple-valued so "frozen" means
# what it says. No dict or Any: an untyped mapping here is a hole in the
# contract, and contract drift is exactly what code review is meant to catch.


@dataclass(frozen=True)
class ProfileWarning:
    """A degradation that did not stop collection.

    Named ProfileWarning rather than Warning: the plan says Warning, but that
    shadows the builtin exception class, so an `except Warning:` anywhere in
    this file would silently become a TypeError.
    """

    code: str  # machine-readable, e.g. "pg_stat_statements_missing"
    message: str  # human-readable; never contains a credential
    relation: str = ""  # the object it concerns, when applicable


@dataclass(frozen=True)
class Source:
    """Identity of the profiled server."""

    kind: str  # "postgres"
    server_version_num: int  # e.g. 160002
    server_version: str  # e.g. "16.2"
    database: str
    collected_schemas: tuple[str, ...] = ()


@dataclass(frozen=True)
class Column:
    schema: str
    table: str
    name: str
    ordinal: int
    data_type: str  # PostgreSQL type name, as declared
    is_nullable: bool
    is_supported: bool  # type has a CockroachDB equivalent
    null_fraction: float | None = None
    avg_width_bytes: int | None = None
    # Absolute distinct-value estimate. PostgreSQL stores a negative n_distinct
    # to mean "fraction of rows"; normalization resolves that to a count here so
    # consumers never have to know the encoding.
    distinct_estimate: float | None = None
    most_common_tokens: tuple[str, ...] = ()  # HMAC tokens, never raw values
    most_common_freqs: tuple[float, ...] = ()
    histogram_token_bounds: tuple[str, ...] = ()  # HMAC tokens, never raw bounds
    provenance: str = ""  # PostgreSQL-native semantics behind the normalized values


@dataclass(frozen=True)
class Table:
    schema: str
    name: str
    row_count_estimate: float  # pg_class.reltuples -- an estimate, never a COUNT(*)
    size_bytes: int
    columns: tuple[Column, ...] = ()
    provenance: str = ""


@dataclass(frozen=True)
class FanOut:
    """Estimated children per parent across a foreign key."""

    status: str  # "estimated" | "insufficient_statistics"
    basis: str  # "single_column" | "extended_statistics" | "composite"
    mean: float | None = None
    p99: float | None = None


@dataclass(frozen=True)
class Relationship:
    constraint_name: str
    child_schema: str
    child_table: str
    child_columns: tuple[str, ...]  # ordered as declared
    parent_schema: str
    parent_table: str
    parent_columns: tuple[str, ...]
    on_update: str = ""
    on_delete: str = ""
    fan_out: FanOut | None = None


@dataclass(frozen=True)
class Observation:
    """One payload file in the bundle, with the hash recorded in the manifest."""

    path: str  # e.g. "observations/pg_class.csv"
    sha256: str  # over uncompressed payload bytes
    row_count: int


@dataclass(frozen=True)
class Profile:
    source: Source
    contract_version: str = CONTRACT_VERSION
    tables: tuple[Table, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    warnings: tuple[ProfileWarning, ...] = ()


@dataclass(frozen=True)
class Manifest:
    tool: str
    tool_version: str
    contract_version: str
    created_at: str  # RFC 3339, UTC
    source: Source
    schema_fingerprint: str  # catalog fingerprint, matched before and after collection
    payloads: tuple[Observation, ...] = ()
    warnings: tuple[ProfileWarning, ...] = ()
    stats_reset: str | None = None  # pg_stat_statements_info, when available


# ---------------------------------------------------------------------------
# Connection configuration
# ---------------------------------------------------------------------------

POSTGRES_URL_SCHEMES = ("postgres", "postgresql")

# libpq connection parameters accepted as URL query parameters, mapped to the
# environment variable that carries each to a child process. Anything outside
# this map is rejected rather than dropped: silently discarding sslmode would
# downgrade a connection the customer asked to encrypt.
LIBPQ_QUERY_PARAMS = {
    "dbname": "PGDATABASE",
    "user": "PGUSER",
    "password": "PGPASSWORD",
    "host": "PGHOST",
    "port": "PGPORT",
    "sslmode": "PGSSLMODE",
    "sslrootcert": "PGSSLROOTCERT",
    "sslcert": "PGSSLCERT",
    "sslkey": "PGSSLKEY",
    "connect_timeout": "PGCONNECT_TIMEOUT",
    "application_name": "PGAPPNAME",
    "options": "PGOPTIONS",
}

# Environment keys whose values must never be rendered.
SECRET_ENV_MARKERS = ("PASSWORD", "PASSFILE", "KEY")

MIN_PORT = 1
MAX_PORT = 65535


def redact_env(env: dict[str, str]) -> dict[str, str]:
    """Return a copy of env with secret values masked, safe to print."""
    return {
        key: (REDACTED if any(marker in key.upper() for marker in SECRET_ENV_MARKERS) else value)
        for key, value in env.items()
    }


def parse_connection_url(url: str) -> dict[str, str]:
    """Parse a PostgreSQL connection URL into libpq environment variables.

    Credentials travel to child processes through the environment, never on a
    command line, where any user on the box could read them out of the process
    list. Absent components are omitted rather than defaulted, so libpq's own
    defaults and the customer's existing PG* settings still apply.

    Raises ConfigError. No error message quotes any part of the URL.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        raise ConfigError("the connection URL could not be parsed") from None

    if parts.scheme not in POSTGRES_URL_SCHEMES:
        raise ConfigError(
            "the connection URL must begin with postgres:// or postgresql://"
        ) from None

    env = {}

    # Query parameters first, so explicit URL components win over them.
    for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        if key not in LIBPQ_QUERY_PARAMS:
            raise ConfigError(
                f"the connection URL sets an unsupported parameter {key!r}; "
                f"supported: {', '.join(sorted(LIBPQ_QUERY_PARAMS))}"
            )
        env[LIBPQ_QUERY_PARAMS[key]] = value

    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise ConfigError("the connection URL has an invalid port") from None

    if hostname:
        env["PGHOST"] = hostname
    if port is not None:
        if not MIN_PORT <= port <= MAX_PORT:
            raise ConfigError(f"the connection URL port must be {MIN_PORT}-{MAX_PORT}") from None
        env["PGPORT"] = str(port)

    # urlsplit does not percent-decode userinfo; a password containing @ : or /
    # must be encoded in the URL and decoded here.
    if parts.username:
        env["PGUSER"] = urllib.parse.unquote(parts.username)
    if parts.password:
        env["PGPASSWORD"] = urllib.parse.unquote(parts.password)

    database = urllib.parse.unquote(parts.path.lstrip("/"))
    if database:
        env["PGDATABASE"] = database
    if not env.get("PGDATABASE"):
        raise ConfigError(
            "the connection URL must name a database, as a path or a dbname parameter"
        )

    return env


@dataclass(repr=False)
class PostgresConfig:
    """Everything a postgres run needs. Never printed without redaction."""

    env: dict[str, str]  # libpq environment for child processes; holds PGPASSWORD
    output: Path
    schema_include: tuple[str, ...] = ()
    schema_exclude: tuple[str, ...] = ()
    psql_path: str = "psql"
    pg_dump_path: str = "pg_dump"
    timeout: int = DEFAULT_TIMEOUT_SECONDS

    def __repr__(self) -> str:
        # Default dataclass repr would print PGPASSWORD. This class is likely to
        # end up in a log line or an exception someday; make that safe now.
        return (
            f"PostgresConfig(env={redact_env(self.env)!r}, output={str(self.output)!r}, "
            f"schema_include={self.schema_include!r}, schema_exclude={self.schema_exclude!r}, "
            f"psql_path={self.psql_path!r}, pg_dump_path={self.pg_dump_path!r}, "
            f"timeout={self.timeout!r})"
        )


def _dedupe(values) -> tuple[str, ...]:
    """Order-preserving deduplication."""
    return tuple(dict.fromkeys(values or ()))


def build_postgres_config(
    args: argparse.Namespace, env: dict[str, str] | None = None
) -> PostgresConfig:
    """Validate CLI arguments and the environment into a PostgresConfig."""
    env = os.environ if env is None else env

    url = args.url or env.get(URL_ENV_VAR)
    if not url:
        raise ConfigError(f"no connection URL: set {URL_ENV_VAR} or pass --url")

    output = Path(args.output).expanduser()
    if output.suffix != ".zip":
        raise ConfigError("--output must name a .zip file")

    schema_include = _dedupe(args.schema_include)
    schema_exclude = _dedupe(args.schema_exclude)
    if schema_include and schema_exclude:
        raise ConfigError("--schema-include and --schema-exclude cannot be combined")

    if args.timeout <= 0:
        raise ConfigError("--timeout must be a positive number of seconds")

    return PostgresConfig(
        env=parse_connection_url(url),
        output=output.resolve(),
        schema_include=schema_include,
        schema_exclude=schema_exclude,
        psql_path=args.psql_path,
        pg_dump_path=args.pg_dump_path,
        timeout=args.timeout,
    )


# ---------------------------------------------------------------------------
# Server version gate
# ---------------------------------------------------------------------------


def format_server_version(version_num: int) -> str:
    """Render a server_version_num as a human major.minor, e.g. 160002 -> 16.2."""
    return f"{version_num // 10000}.{version_num % 10000}"


def require_supported_version(version_num: int) -> None:
    """Raise unless the server is a PostgreSQL major this release supports."""
    if not MIN_SERVER_VERSION_NUM <= version_num < MAX_SERVER_VERSION_NUM:
        raise UnsupportedServerVersion(
            f"source server is PostgreSQL {format_server_version(version_num)}; "
            f"this release of {PROG} supports PostgreSQL {SUPPORTED_MAJOR} only"
        )


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
    build_postgres_config(args)
    # (task 10) probe version -> fingerprint-before -> pg_dump -> catalog ->
    # workload -> tokenize -> normalize -> fingerprint-after -> publish.
    raise NotImplementedError("collection is not implemented yet")


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

    postgres = subparsers.add_parser(
        "postgres",
        help=f"profile a PostgreSQL {SUPPORTED_MAJOR} source",
        description=(
            f"Profile a PostgreSQL {SUPPORTED_MAJOR} source. Set {URL_ENV_VAR} to the "
            f"connection string and {TOKEN_KEY_ENV_VAR} to the tokenization key."
        ),
    )
    postgres.add_argument(
        "--output",
        required=True,
        metavar="PATH",
        help="path to write the profile bundle (must end in .zip)",
    )
    postgres.add_argument(
        "--url",
        metavar="URL",
        help=(
            f"connection string; defaults to {URL_ENV_VAR}. Prefer the environment "
            "variable: a URL passed here is visible to other users in the process list"
        ),
    )
    postgres.add_argument(
        "--schema-include",
        action="append",
        metavar="NAME",
        help="collect only this schema; repeatable",
    )
    postgres.add_argument(
        "--schema-exclude",
        action="append",
        metavar="NAME",
        help="skip this schema; repeatable",
    )
    postgres.add_argument(
        "--psql-path",
        default="psql",
        metavar="PATH",
        help="psql executable to use (default: found on PATH)",
    )
    postgres.add_argument(
        "--pg-dump-path",
        default="pg_dump",
        metavar="PATH",
        help="pg_dump executable to use (default: found on PATH)",
    )
    postgres.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=f"per-command timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS})",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.check_safety:
        return check_safety()

    if args.command == "postgres":
        try:
            return run_postgres(args)
        except DbprofilerError as error:
            # Expected failures are reported as a message, not a traceback: a
            # traceback here would be noise, and stack frames can carry values
            # we have promised not to print.
            print(f"{PROG}: {error}", file=sys.stderr)
            return 2

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
