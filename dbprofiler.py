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
import ast
import csv
import io
import os
import re
import subprocess
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


class CommandError(DbprofilerError):
    """A psql or pg_dump invocation failed. Any stderr here is already redacted."""


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

# Every relation this tool is permitted to read, enumerated one by one. There is
# deliberately no "pg_catalog.*" wildcard: pg_catalog holds role password hashes
# (pg_authid, pg_shadow), actual user data (pg_largeobject), and raw statistic
# values that the pg_stats view would otherwise filter by permission
# (pg_statistic). A relation earns its place here in the same change as the
# collector that reads it, together with a test.
ALLOWED_RELATIONS = frozenset(
    {
        "pg_attrdef",
        "pg_attribute",
        "pg_class",
        "pg_constraint",
        "pg_description",
        "pg_index",
        "pg_namespace",
        "pg_sequence",
        "pg_stat_statements",
        "pg_stat_statements_info",
        "pg_stat_user_indexes",
        "pg_stat_user_tables",
        "pg_statio_user_indexes",
        "pg_stats",
        "pg_stats_ext",
        "pg_type",
    }
)

# Catalog relations that look plausible but must never be read, each with the
# reason it is out of bounds. Reported by name so a reviewer sees the "why".
DENIED_RELATIONS = {
    "pg_authid": "contains role password hashes",
    "pg_shadow": "contains role password hashes",
    "pg_largeobject": "contains user data",
    "pg_largeobject_metadata": "enumerates user large objects",
    "pg_statistic": "exposes raw statistic values without the pg_stats permission filter",
    "pg_subscription": "subconninfo contains a connection password",
    "pg_user_mapping": "umoptions can contain a password",
}

# Set-returning functions permitted in a FROM clause. These read their arguments,
# not the database.
ALLOWED_FUNCTIONS = frozenset({"unnest", "generate_series", "generate_subscripts"})

# The only schema a relation may be qualified with.
ALLOWED_SCHEMA = "pg_catalog"

# Matches the relation or set-returning function named by a FROM or JOIN clause.
# A trailing "(" distinguishes a function call from a relation reference.
RELATION_REFERENCE = re.compile(
    r"\b(?:FROM|JOIN)\s+(?:LATERAL\s+|ONLY\s+)*"
    r"([A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)*)"
    r"\s*(\()?",
    re.IGNORECASE,
)

# A connection URL carrying userinfo, i.e. one with an "@" before the host. A
# bare "postgres://..." placeholder in a docstring is fine; a credentialed one
# checked into the source is not.
CREDENTIALED_URL = re.compile(r"postgres(?:ql)?://[^\s'\"]*@", re.IGNORECASE)


def iter_sql_constants():
    """Yield (name, sql) for every module-level SQL_* constant.

    Every query this tool issues is declared as a module-level constant named
    SQL_* precisely so that check_safety() can enumerate them without executing
    anything.
    """
    for name, value in sorted(globals().items()):
        if name.startswith("SQL_") and isinstance(value, str):
            yield name, value


def own_source() -> str:
    """Return this script's own source text, for the static audit below."""
    return Path(__file__).read_text(encoding="utf-8")


def audit_relation_reference(name: str, is_function: bool) -> str:
    """Return a violation message for one FROM/JOIN target, or "" if allowed."""
    parts = name.lower().split(".")
    schema = parts[0] if len(parts) > 1 else ""
    base = parts[-1]

    if is_function:
        if schema and schema != ALLOWED_SCHEMA:
            return f"calls set-returning function {name} outside {ALLOWED_SCHEMA}"
        if base not in ALLOWED_FUNCTIONS:
            return f"calls set-returning function {name}, which is not on the allowlist"
        return ""

    if base in DENIED_RELATIONS:
        return f"reads {base}, which is explicitly denied: {DENIED_RELATIONS[base]}"
    if schema and schema != ALLOWED_SCHEMA:
        return f"reads {name}, which is outside {ALLOWED_SCHEMA}"
    if base not in ALLOWED_RELATIONS:
        return f"reads {name}, which is not on the relation allowlist"
    return ""


def audit_sql(sql: str) -> list[str]:
    """Return every safety violation in one SQL statement."""
    violations = []

    # Collapse whitespace and close the "COUNT (*)" gap so the token match
    # cannot be evaded by formatting.
    normalized = " ".join(sql.split()).upper().replace(" (", "(")
    for token in SAFETY_FORBIDDEN:
        if token in normalized:
            violations.append(f"contains forbidden token {token!r}")

    for match in RELATION_REFERENCE.finditer(sql):
        problem = audit_relation_reference(match.group(1), bool(match.group(2)))
        if problem:
            violations.append(problem)

    return violations


def audit_subprocess_usage(source: str) -> list[str]:
    """Statically audit source text for unsafe child-process usage.

    Parses rather than greps, so a violation cannot hide behind formatting. The
    rules: exactly one subprocess call site in the whole file, every call passes
    an explicit env=, none passes shell=, and no string literal anywhere carries
    a credentialed connection URL.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        return [f"source does not parse: {error.msg}"]

    violations = []
    call_sites = 0

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if CREDENTIALED_URL.search(node.value):
                violations.append("a string literal contains a credentialed connection URL")
            continue

        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and _is_name(func.value, "subprocess")):
            continue

        call_sites += 1
        keywords = {keyword.arg for keyword in node.keywords}
        if "shell" in keywords:
            violations.append(f"subprocess.{func.attr} on line {node.lineno} passes shell=")
        if "env" not in keywords:
            violations.append(f"subprocess.{func.attr} on line {node.lineno} has no env= argument")

    if call_sites > 1:
        violations.append(
            f"{call_sites} subprocess call sites; exactly one call site keeps "
            "credential handling auditable"
        )

    return violations


def _is_name(node, name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == name


def check_safety() -> int:
    """Audit this file's own SQL and child-process usage against the safety boundary.

    Returns a process exit status: 0 when clean, 1 when any violation is found.
    Run in CI against every commit.
    """
    violations = []

    for name, sql in iter_sql_constants():
        violations.extend(f"{name}: {problem}" for problem in audit_sql(sql))

    violations.extend(f"source: {problem}" for problem in audit_subprocess_usage(own_source()))

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
# Credentials reach psql and pg_dump through the environment only. Nothing here
# ever places one on a command line: argv is visible to every other user on the
# box, the environment of a running process is not.

# -X ignores ~/.psqlrc, so a customer's local settings cannot change our output
# format. -w never prompts for a password: without it psql blocks on a terminal
# read and we would fail by timeout instead of immediately. --csv gives quoting
# we can parse unambiguously; note that -A would override it, so it is absent
# deliberately. -t drops the header row. ON_ERROR_STOP turns a SQL error into a
# nonzero exit rather than a silent empty result.
PSQL_ARGS = ("-X", "-w", "--csv", "-t", "-v", "ON_ERROR_STOP=1")

# pg_dump has no --csv/-t equivalent; -w is the same no-prompt guarantee.
PG_DUMP_ARGS = ("-w",)

# Connection strings in any form, and password assignments in libpq or shell
# syntax. Applied to child-process stderr before it is shown or logged.
URL_IN_TEXT = re.compile(r"postgres(?:ql)?://[^\s'\"]+", re.IGNORECASE)
# The value stops at a delimiter rather than at whitespace, so a password quoted
# or parenthesised in the message does not swallow the punctuation around it. A
# password that itself contains a delimiter is still caught by the env-value pass
# below.
PASSWORD_ASSIGNMENT = re.compile(r"\b(?:pg)?password\s*=\s*[^\s'\"();,]+", re.IGNORECASE)

# Env values worth scrubbing out of an error message. PGPASSWORD always goes,
# however short. The rest are identifiers, not secrets, but they are still the
# customer's infrastructure, so they go too when they are long enough to be
# distinctive. Below that length a blind replace would shred unrelated words in
# the message and destroy the diagnostic. PGPORT is deliberately absent: a bare
# port number matches far too much text.
ALWAYS_REDACTED_ENV = ("PGPASSWORD",)
REDACTED_IF_DISTINCTIVE_ENV = (
    "PGUSER",
    "PGHOST",
    "PGDATABASE",
    "PGOPTIONS",
    "PGAPPNAME",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGSSLROOTCERT",
)
MIN_DISTINCTIVE_LENGTH = 4


def safe_env(config: PostgresConfig) -> dict[str, str]:
    """Build the environment for a child process.

    Starts from our own environment so the customer's PGSSLMODE, PGSSLROOTCERT
    and friends keep working, drops every DBPROFILER_* variable so no child ever
    sees the raw URL or the token key, then lets the parsed connection settings
    win. LC_ALL is pinned so error text and number formatting do not depend on
    the operator's locale.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith("DBPROFILER_")}
    env.update(config.env)
    env["LC_ALL"] = "C"
    return env


def redact_error(text: str | None, env: dict[str, str] | None = None) -> str:
    """Scrub connection details out of child-process output."""
    if not text:
        return ""

    redacted = URL_IN_TEXT.sub(REDACTED, text)
    redacted = PASSWORD_ASSIGNMENT.sub(f"password={REDACTED}", redacted)

    env = env or {}
    secrets = [env[key] for key in ALWAYS_REDACTED_ENV if env.get(key)]
    secrets += [
        env[key]
        for key in REDACTED_IF_DISTINCTIVE_ENV
        if env.get(key) and len(env[key]) >= MIN_DISTINCTIVE_LENGTH
    ]
    # Longest first, so a value that contains another is not partly rewritten.
    for secret in sorted(secrets, key=len, reverse=True):
        redacted = redacted.replace(secret, REDACTED)

    return redacted.strip()


def run_command(argv: list[str], config: PostgresConfig, what: str) -> str:
    """Run one child process and return its stdout.

    The single subprocess call site in this file; audit_subprocess_usage()
    enforces that. Every failure path raises CommandError with redacted text.
    """
    env = safe_env(config)
    try:
        completed = subprocess.run(
            argv,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=config.timeout,
            check=False,
        )
    except FileNotFoundError:
        raise CommandError(f"{what} not found on PATH: {argv[0]}") from None
    except subprocess.TimeoutExpired:
        raise CommandError(f"{what} timed out after {config.timeout}s") from None

    if completed.returncode != 0:
        detail = redact_error(completed.stderr, env)
        raise CommandError(f"{what} exited with status {completed.returncode}: {detail}")

    return completed.stdout


def run_psql(sql: str, config: PostgresConfig) -> list[list[str]]:
    """Run one SQL statement and return its rows, header excluded."""
    argv = [config.psql_path, *PSQL_ARGS, "-c", sql]
    output = run_command(argv, config, "psql")
    return list(csv.reader(io.StringIO(output)))


def run_psql_scalar(sql: str, config: PostgresConfig) -> str:
    """Run a statement expected to yield exactly one row of one column."""
    rows = run_psql(sql, config)
    if len(rows) != 1 or len(rows[0]) != 1:
        raise CommandError(
            f"expected a single value from psql, got {len(rows)} row(s) of an unexpected shape"
        )
    return rows[0][0].strip()


def run_pg_dump(extra_args, config: PostgresConfig) -> str:
    """Run pg_dump with the given arguments and return its stdout."""
    argv = [config.pg_dump_path, *PG_DUMP_ARGS, *extra_args]
    return run_command(argv, config, "pg_dump")


def probe_server_version(config: PostgresConfig) -> int:
    """Read server_version_num from the source and enforce the supported major."""
    raw = run_psql_scalar(SQL_SERVER_VERSION, config)
    try:
        version_num = int(raw)
    except ValueError:
        raise CommandError("the source server did not report a usable server_version_num") from None
    require_supported_version(version_num)
    return version_num


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
