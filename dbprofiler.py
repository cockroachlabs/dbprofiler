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
import datetime
import decimal
import hashlib
import hmac
import io
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import uuid
import zipfile
from dataclasses import dataclass, fields
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


class UnsupportedClientVersion(DbprofilerError):
    """The local psql or pg_dump is too old for the source server."""


class UnsupportedObject(DbprofilerError):
    """The source contains an object shape this release does not model."""


class CommandError(DbprofilerError):
    """A psql or pg_dump invocation failed. Any stderr here is already redacted."""


class SchemaDrift(DbprofilerError):
    """The source schema changed while it was being collected."""


class BundleError(DbprofilerError):
    """The bundle about to be written violates its own rules.

    Raised for entry paths a ZIP extractor could resolve outside its target,
    for values whose type is not part of the serialized contract, and for a
    manifest that does not describe exactly the payloads beside it. Every one
    of these is an internal invariant: if a user can trigger it, that is a bug.
    """


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


def _forbidden_pattern(token: str) -> re.Pattern[str]:
    """Compile one forbidden token, anchored at word boundaries where they apply.

    A plain substring match would reject `pg_stat_user_tables.last_analyze`,
    `analyze_count`, `autoanalyze_count` and `n_mod_since_analyze` -- exactly the
    columns that say whether the source statistics are stale enough to make the
    rest of this profile untrustworthy. Dropping them to satisfy the check would
    trade real signal for a false sense of rigour. A word boundary keeps
    `ANALYZE` as a statement forbidden while letting the column names through;
    `COUNT(` still matches `pg_catalog.count(*)`, because `.` is not a word
    character, and no longer matches the tail of `autovacuum_count`.
    """
    prefix = r"\b" if token[:1].isalnum() or token[:1] == "_" else ""
    suffix = r"\b" if token[-1:].isalnum() or token[-1:] == "_" else ""
    return re.compile(prefix + re.escape(token) + suffix)


SAFETY_FORBIDDEN_PATTERNS = tuple((token, _forbidden_pattern(token)) for token in SAFETY_FORBIDDEN)

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
        "pg_database",
        "pg_description",
        "pg_extension",
        "pg_index",
        "pg_inherits",
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
    for token, pattern in SAFETY_FORBIDDEN_PATTERNS:
        if pattern.search(normalized):
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

# One row per user relation, for the catalog fingerprint. Reads names and kinds
# only -- no column contents, no statistics, nothing from inside a table. The
# left() test excludes pg_catalog, pg_toast, pg_temp_N and pg_toast_temp_N in one
# comparison, and avoids the backslash escaping a LIKE pattern would need.
SQL_SCHEMA_FINGERPRINT = """
SELECT n.nspname, c.relname, c.relkind
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE left(n.nspname, 3) <> 'pg_' AND n.nspname <> 'information_schema'
"""

# Row-count and size estimates. reltuples is the planner's estimate, maintained
# by autovacuum -- reading it is what makes profiling a large table free. The
# relkind filter includes 'p' and 'I' deliberately: the layout check below has
# to see a partitioned object in order to reject it.
SQL_TABLES = """
SELECT n.nspname, c.relname, c.relkind, c.reltuples,
       pg_catalog.pg_total_relation_size(c.oid)
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'm', 'p', 'I')
  AND left(n.nspname, 3) <> 'pg_' AND n.nspname <> 'information_schema'
"""

# Inheritance children, for the same layout check.
SQL_INHERITED = """
SELECT n.nspname, c.relname
FROM pg_catalog.pg_inherits inh
JOIN pg_catalog.pg_class c ON c.oid = inh.inhrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE left(n.nspname, 3) <> 'pg_' AND n.nspname <> 'information_schema'
"""

# Column shape. format_type gives the declared type as an operator would write
# it; typname, typtype and typcategory give the classifier something stable to
# match on, since "character varying(50)" and "varchar" are the same type.
SQL_COLUMNS = """
SELECT n.nspname, c.relname, a.attname, a.attnum,
       pg_catalog.format_type(a.atttypid, a.atttypmod),
       t.typname, t.typtype, t.typcategory, a.attnotnull
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
WHERE a.attnum > 0 AND NOT a.attisdropped
  AND c.relkind IN ('r', 'm')
  AND left(n.nspname, 3) <> 'pg_' AND n.nspname <> 'information_schema'
"""

# Per-column statistics as PostgreSQL already computed them. pg_stats is a view
# over pg_statistic that shows a row only where the caller could read the table
# itself, which is why this reads the view and never the underlying catalog.
# most_common_vals and histogram_bounds are raw customer values; they are held in
# memory here and tokenized before anything is written.
SQL_COLUMN_STATS = """
SELECT s.schemaname, s.tablename, s.attname, s.null_frac, s.avg_width, s.n_distinct,
       s.most_common_vals::text, s.most_common_freqs::text, s.histogram_bounds::text
FROM pg_catalog.pg_stats s
WHERE left(s.schemaname, 3) <> 'pg_' AND s.schemaname <> 'information_schema'
"""

# Multicolumn statistics, where the operator has already created them. Only the
# n-distinct estimate and the existence of an MCV list are read: the MCV entries
# themselves are raw values, and their presence is all a migration plan needs.
SQL_EXTENDED_STATS = """
SELECT e.schemaname, e.tablename, e.statistics_name, e.attnames::text,
       e.n_distinct::text, (e.most_common_freqs IS NOT NULL)
FROM pg_catalog.pg_stats_ext e
WHERE left(e.schemaname, 3) <> 'pg_' AND e.schemaname <> 'information_schema'
"""

# One row per foreign-key column, ordered by position within the key. unnest
# pairs each child attnum with its parent attnum so composite keys keep their
# declared order; Python reassembles the rows into one record per constraint.
SQL_FOREIGN_KEYS = """
SELECT con.conname, cn.nspname, cc.relname, pn.nspname, pc.relname,
       ca.attname, pa.attname, k.ord, con.confupdtype, con.confdeltype
FROM pg_catalog.pg_constraint con
JOIN pg_catalog.pg_class cc ON cc.oid = con.conrelid
JOIN pg_catalog.pg_namespace cn ON cn.oid = cc.relnamespace
JOIN pg_catalog.pg_class pc ON pc.oid = con.confrelid
JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace
JOIN LATERAL unnest(con.conkey, con.confkey) WITH ORDINALITY AS k(child, parent, ord)
  ON true
JOIN pg_catalog.pg_attribute ca ON ca.attrelid = con.conrelid AND ca.attnum = k.child
JOIN pg_catalog.pg_attribute pa ON pa.attrelid = con.confrelid AND pa.attnum = k.parent
WHERE con.contype = 'f'
  AND left(cn.nspname, 3) <> 'pg_' AND cn.nspname <> 'information_schema'
ORDER BY con.conname, k.ord
"""

# Index inventory. The DDL is already in schema.sql; this is the machine-readable
# form that pairs with the Tier 1 usage counters.
SQL_TABLE_ACTIVITY = """
SELECT s.schemaname, s.relname, s.seq_scan, s.seq_tup_read, s.idx_scan,
       s.idx_tup_fetch, s.n_tup_ins, s.n_tup_upd, s.n_tup_del, s.n_tup_hot_upd,
       s.n_live_tup, s.n_dead_tup, s.n_mod_since_analyze,
       s.last_vacuum::text, s.last_autovacuum::text,
       s.last_analyze::text, s.last_autoanalyze::text,
       s.vacuum_count, s.autovacuum_count, s.analyze_count, s.autoanalyze_count
FROM pg_catalog.pg_stat_user_tables s
"""

SQL_INDEX_ACTIVITY = """
SELECT s.schemaname, s.relname, s.indexrelname, s.idx_scan, s.idx_tup_read,
       s.idx_tup_fetch, pg_catalog.pg_relation_size(s.indexrelid)
FROM pg_catalog.pg_stat_user_indexes s
"""

SQL_STATEMENTS_INSTALLED = """
SELECT e.extversion
FROM pg_catalog.pg_extension e
WHERE e.extname = 'pg_stat_statements'
"""

# pg_stat_statements and pg_stat_statements_info live in whatever schema the
# extension was installed into, so they are referenced unqualified and resolved
# through search_path. That is the one place this tool relies on search_path;
# if resolution fails the collector degrades to a warning rather than failing.
SQL_STATEMENTS_RESET = """
SELECT i.stats_reset::text
FROM pg_stat_statements_info i
"""

# Ranked in SQL, not fetched and sorted here: the view is backed by a
# shared-memory hash that can hold tens of thousands of entries, and pulling all
# of them across the wire to keep 400 would be the largest transfer this tool
# performs. Two rankings, because the slowest statements and the most frequent
# ones are different questions and a migration plan needs both.
SQL_STATEMENTS = """
SELECT t.queryid::text, t.query, t.calls, t.total_exec_time, t.mean_exec_time,
       t.stddev_exec_time, t.rows, t.shared_blks_hit, t.shared_blks_read,
       t.shared_blks_dirtied, t.shared_blks_written, t.temp_blks_read,
       t.temp_blks_written
FROM (
    SELECT s.*,
           row_number() OVER (ORDER BY s.total_exec_time DESC NULLS LAST) AS by_time,
           row_number() OVER (ORDER BY s.calls DESC NULLS LAST) AS by_calls
    FROM pg_stat_statements s
    WHERE s.dbid = (
        SELECT d.oid FROM pg_catalog.pg_database d
        WHERE d.datname = pg_catalog.current_database()
    )
) t
WHERE t.by_time <= 200 OR t.by_calls <= 200
ORDER BY t.by_time
"""

SQL_INDEXES = """
SELECT n.nspname, c.relname, ic.relname, i.indisunique, i.indisprimary
FROM pg_catalog.pg_index i
JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE left(n.nspname, 3) <> 'pg_' AND n.nspname <> 'information_schema'
"""


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


# PostgreSQL reserves the pg_ prefix for system schemas, which covers pg_catalog,
# pg_toast, and the per-session pg_temp_N and pg_toast_temp_N.
RESERVED_SCHEMA_PREFIX = "pg_"
RESERVED_SCHEMAS = ("information_schema",)


def require_user_schema(name: str) -> None:
    """Reject a system schema given to --schema-include.

    Dumping one is never what the operator meant, and a pg_temp_N schema would
    make the bundle depend on a live session.
    """
    lowered = name.lower()
    if lowered.startswith(RESERVED_SCHEMA_PREFIX) or lowered in RESERVED_SCHEMAS:
        raise ConfigError(
            f"--schema-include {name}: system schemas cannot be profiled; PostgreSQL "
            f"reserves the {RESERVED_SCHEMA_PREFIX} prefix and information_schema"
        )


def schema_is_selected(name: str, config: PostgresConfig) -> bool:
    """Report whether a schema is in scope for this run."""
    if config.schema_include:
        return name in config.schema_include
    return name not in config.schema_exclude


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
    # Resolve the directory, never the file. Path.resolve() on the whole path
    # follows a symlinked destination, which would hide it from the symlink
    # check at publication time -- publishing through a symlink is refused, not
    # quietly redirected.
    output = output.parent.resolve() / output.name

    schema_include = _dedupe(args.schema_include)
    schema_exclude = _dedupe(args.schema_exclude)
    for name in schema_include:
        require_user_schema(name)
    if schema_include and schema_exclude:
        raise ConfigError("--schema-include and --schema-exclude cannot be combined")

    if args.timeout <= 0:
        raise ConfigError("--timeout must be a positive number of seconds")

    return PostgresConfig(
        env=parse_connection_url(url),
        output=output,
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


# The first run of digits in "pg_dump (PostgreSQL) 16.2" and its packaged
# variants. Only the major matters here.
PG_DUMP_VERSION = re.compile(r"(\d+)")


def probe_pg_dump_major(config: PostgresConfig) -> int:
    """Read the local pg_dump major version. Makes no connection."""
    output = run_command([config.pg_dump_path, *PG_DUMP_ARGS, "--version"], config, "pg_dump")
    match = PG_DUMP_VERSION.search(output)
    if not match:
        raise CommandError("pg_dump did not report a usable version")
    return int(match.group(1))


def require_compatible_pg_dump(pg_dump_major: int, server_version_num: int) -> None:
    """Raise unless the local pg_dump is at least as new as the source server.

    An older pg_dump does not refuse a newer server outright in every case; it
    can emit a dump that is quietly wrong. Checking first is cheaper than
    discovering that during a migration.
    """
    server_major = server_version_num // 10000
    if pg_dump_major < server_major:
        raise UnsupportedClientVersion(
            f"local pg_dump is version {pg_dump_major} but the source server is "
            f"PostgreSQL {server_major}; use a pg_dump of {server_major} or newer"
        )


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------
# (tasks 5-6) collect_catalog(), collect_workload().

# --no-owner and --no-privileges drop role names and grants: they are the
# customer's access control, not schema shape a migration needs.
PG_DUMP_SCHEMA_ARGS = ("--schema-only", "--no-owner", "--no-privileges")

# Field and record separators for the fingerprint's canonical form. ASCII unit
# and record separators cannot occur in a PostgreSQL identifier, so no relation
# name can forge a boundary and collide with a different set of relations.
FIELD_SEPARATOR = "\x1f"
RECORD_SEPARATOR = "\x1e"


def build_pg_dump_args(config: PostgresConfig) -> list[str]:
    """Build the pg_dump arguments for this run. Never includes a credential."""
    args = list(PG_DUMP_SCHEMA_ARGS)
    for name in config.schema_include:
        args += ["-n", name]
    for name in config.schema_exclude:
        args += ["-N", name]
    return args


def schema_fingerprint(config: PostgresConfig) -> str:
    """Fingerprint the catalog objects in scope, for drift detection.

    Each psql invocation is its own transaction, so the collection as a whole is
    not isolated. Comparing this fingerprint before and after collection turns
    concurrent DDL into a detected, fatal condition rather than a bundle that
    silently mixes two versions of a schema.

    Scope filtering happens here rather than in SQL: the query stays a fixed
    module constant that --check-safety can audit, and a schema the operator
    excluded cannot abort the run by changing underneath it.
    """
    rows = [
        tuple(row)
        for row in run_psql(SQL_SCHEMA_FINGERPRINT, config)
        if len(row) == 3 and schema_is_selected(row[0], config)
    ]
    canonical = "".join(FIELD_SEPARATOR.join(row) + RECORD_SEPARATOR for row in sorted(rows))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def collect_schema(config: PostgresConfig, server_version_num: int) -> tuple[str, str]:
    """Return (schema DDL, catalog fingerprint taken before the dump).

    The client check runs first so a too-old pg_dump fails before it produces
    anything. The fingerprint is taken before the dump so that the
    after-collection recheck also covers drift during the dump itself.
    """
    require_compatible_pg_dump(probe_pg_dump_major(config), server_version_num)
    digest = schema_fingerprint(config)
    schema_sql = run_pg_dump(build_pg_dump_args(config), config)
    return schema_sql, digest


# --- catalog value parsing -------------------------------------------------
# psql --csv renders NULL as an empty field, booleans as t/f, and arrays as
# their PostgreSQL text form. These turn that back into Python.


def pg_bool(text: str) -> bool:
    return text == "t"


def pg_int(text: str, default: int = 0) -> int:
    try:
        return int(float(text))
    except ValueError:
        return default


def pg_float(text: str) -> float | None:
    try:
        return float(text)
    except ValueError:
        return None


def parse_pg_array(text: str) -> tuple[str, ...]:
    """Parse a PostgreSQL array literal into its elements.

    Elements containing a comma, brace, quote or backslash arrive quoted and
    escaped. Splitting on "," would corrupt exactly the values -- keys with
    embedded commas, text with punctuation -- that matter most for join shape.
    """
    if not text.startswith("{") or not text.endswith("}"):
        return ()
    body = text[1:-1]
    if not body:
        return ()

    items: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in body:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            items.append("".join(current))
            current = []
        else:
            current.append(char)
    items.append("".join(current))
    return tuple(items)


def parse_pg_float_array(text: str) -> tuple[float, ...]:
    parsed = (pg_float(item) for item in parse_pg_array(text))
    return tuple(value for value in parsed if value is not None)


# --- type support ----------------------------------------------------------

# PostgreSQL base types with a direct CockroachDB equivalent. Anything absent is
# reported unsupported: for a migration plan a false negative costs an
# investigation, while a false positive costs a failed cutover.
SUPPORTED_TYPE_NAMES = frozenset(
    {
        "bit",
        "bool",
        "bpchar",
        "bytea",
        "char",
        "date",
        "float4",
        "float8",
        "inet",
        "int2",
        "int4",
        "int8",
        "interval",
        "json",
        "jsonb",
        "name",
        "numeric",
        "oid",
        "text",
        "time",
        "timestamp",
        "timestamptz",
        "timetz",
        "uuid",
        "varbit",
        "varchar",
    }
)

# pg_type.typtype values with no CockroachDB equivalent: composite, domain,
# range, multirange. Enums ('e') are supported and handled separately.
UNSUPPORTED_TYPE_KINDS = frozenset({"c", "d", "r", "m"})

ENUM_TYPE_KIND = "e"
ARRAY_TYPE_CATEGORY = "A"


def is_supported_type(type_name: str, type_kind: str, type_category: str) -> bool:
    """Report whether a column type has a CockroachDB equivalent."""
    if type_kind == ENUM_TYPE_KIND:
        return True
    if type_kind in UNSUPPORTED_TYPE_KINDS:
        return False
    if type_category == ARRAY_TYPE_CATEGORY:
        # An array's element type is its own type name with a leading underscore.
        return type_name.lstrip("_") in SUPPORTED_TYPE_NAMES
    return type_name in SUPPORTED_TYPE_NAMES


# --- collected records -----------------------------------------------------
# Raw catalog rows, one dataclass per query. Deliberately separate from the
# contract types above: these hold PostgreSQL's own encodings, including raw
# statistic values, and nothing here is serialized directly.


@dataclass(frozen=True)
class CatalogTable:
    schema: str
    name: str
    relkind: str
    reltuples: float
    size_bytes: int


@dataclass(frozen=True)
class CatalogColumn:
    schema: str
    table: str
    name: str
    ordinal: int
    data_type: str
    type_name: str
    is_nullable: bool
    is_supported: bool


@dataclass(frozen=True)
class ColumnStatistics:
    """One pg_stats row. most_common_vals and histogram_bounds are raw values."""

    schema: str
    table: str
    column: str
    null_frac: float
    avg_width: int
    n_distinct: float  # negative means "fraction of rows"; resolved in normalization
    most_common_vals: tuple[str, ...]
    most_common_freqs: tuple[float, ...]
    histogram_bounds: tuple[str, ...]


@dataclass(frozen=True)
class ExtendedStatistics:
    schema: str
    table: str
    name: str
    columns: tuple[str, ...]
    # Column-set -> distinct estimate. A mapping rather than a tuple because
    # composite fan-out looks up an exact column set; this is a collection
    # record, not part of the serialized contract.
    n_distinct: dict
    has_most_common_values: bool


@dataclass(frozen=True)
class CatalogForeignKey:
    constraint_name: str
    child_schema: str
    child_table: str
    child_columns: tuple[str, ...]
    parent_schema: str
    parent_table: str
    parent_columns: tuple[str, ...]
    on_update: str
    on_delete: str


@dataclass(frozen=True)
class CatalogIndex:
    schema: str
    table: str
    name: str
    is_unique: bool
    is_primary: bool


@dataclass(frozen=True)
class CatalogObservations:
    tables: tuple[CatalogTable, ...] = ()
    columns: tuple[CatalogColumn, ...] = ()
    column_stats: tuple[ColumnStatistics, ...] = ()
    extended_stats: tuple[ExtendedStatistics, ...] = ()
    foreign_keys: tuple[CatalogForeignKey, ...] = ()
    indexes: tuple[CatalogIndex, ...] = ()


# pg_constraint stores referential actions as single characters.
REFERENTIAL_ACTIONS = {
    "a": "NO ACTION",
    "r": "RESTRICT",
    "c": "CASCADE",
    "n": "SET NULL",
    "d": "SET DEFAULT",
}

# Relation kinds this release cannot model. Partitioning and inheritance change
# row-count and fan-out arithmetic -- a parent's reltuples is not the sum of its
# children, and a fan-out computed as though it were would be silently wrong.
UNSUPPORTED_RELKINDS = {"p": "partitioned table", "I": "partitioned index"}


def collect_catalog(config: PostgresConfig) -> CatalogObservations:
    """Read the catalog and statistics views. Reads no user table.

    Ordering is deliberate: tables and inheritance come first so an unsupported
    layout aborts before five more queries run against a database that cannot
    produce a usable profile anyway.
    """
    def in_scope(schema: str) -> bool:
        return schema_is_selected(schema, config)

    tables = tuple(
        CatalogTable(
            schema=row[0],
            name=row[1],
            relkind=row[2],
            reltuples=pg_float(row[3]) or 0.0,
            size_bytes=pg_int(row[4]),
        )
        for row in run_psql(SQL_TABLES, config)
        if len(row) == 5 and in_scope(row[0])
    )
    inherited = tuple(
        (row[0], row[1]) for row in run_psql(SQL_INHERITED, config) if row and in_scope(row[0])
    )
    require_supported_layout(tables, inherited)

    columns = tuple(
        CatalogColumn(
            schema=row[0],
            table=row[1],
            name=row[2],
            ordinal=pg_int(row[3]),
            data_type=row[4],
            type_name=row[5],
            is_nullable=not pg_bool(row[8]),
            is_supported=is_supported_type(row[5], row[6], row[7]),
        )
        for row in run_psql(SQL_COLUMNS, config)
        if len(row) == 9 and in_scope(row[0])
    )

    column_stats = tuple(
        ColumnStatistics(
            schema=row[0],
            table=row[1],
            column=row[2],
            null_frac=pg_float(row[3]) or 0.0,
            avg_width=pg_int(row[4]),
            n_distinct=pg_float(row[5]) or 0.0,
            most_common_vals=parse_pg_array(row[6]),
            most_common_freqs=parse_pg_float_array(row[7]),
            histogram_bounds=parse_pg_array(row[8]),
        )
        for row in run_psql(SQL_COLUMN_STATS, config)
        if len(row) == 9 and in_scope(row[0])
    )

    attnums = {(c.schema, c.table, c.ordinal): c.name for c in columns}
    extended_stats = tuple(
        ExtendedStatistics(
            schema=row[0],
            table=row[1],
            name=row[2],
            columns=parse_pg_array(row[3]),
            n_distinct=parse_extended_n_distinct(row[4], row[0], row[1], attnums),
            has_most_common_values=pg_bool(row[5]),
        )
        for row in run_psql(SQL_EXTENDED_STATS, config)
        if len(row) == 6 and in_scope(row[0])
    )

    foreign_keys = assemble_foreign_keys(
        [row for row in run_psql(SQL_FOREIGN_KEYS, config) if len(row) == 10 and in_scope(row[1])]
    )

    indexes = tuple(
        CatalogIndex(
            schema=row[0],
            table=row[1],
            name=row[2],
            is_unique=pg_bool(row[3]),
            is_primary=pg_bool(row[4]),
        )
        for row in run_psql(SQL_INDEXES, config)
        if len(row) == 5 and in_scope(row[0])
    )

    return CatalogObservations(
        tables=tuple(t for t in tables if t.relkind not in UNSUPPORTED_RELKINDS),
        columns=columns,
        column_stats=column_stats,
        extended_stats=extended_stats,
        foreign_keys=foreign_keys,
        indexes=indexes,
    )


def require_supported_layout(tables, inherited) -> None:
    """Reject partitioned and inherited tables before anything else is read."""
    for table in tables:
        if table.relkind in UNSUPPORTED_RELKINDS:
            raise UnsupportedObject(
                f"{table.schema}.{table.name} is a {UNSUPPORTED_RELKINDS[table.relkind]}; "
                f"this release of {PROG} does not model partitioning, and a row-count or "
                "fan-out estimate derived from a partitioned parent would be wrong"
            )
    if inherited:
        schema, name = inherited[0]
        raise UnsupportedObject(
            f"{schema}.{name} inherits from another table; this release of {PROG} does not "
            "model inheritance, and estimates derived from it would be wrong"
        )


def parse_extended_n_distinct(text: str, schema: str, table: str, attnums: dict) -> dict:
    """Resolve pg_ndistinct's attnum-keyed JSON into column-name keys.

    PostgreSQL renders it as {"2, 3": 4200}, where the key is a comma-separated
    list of attribute numbers. Consumers should not have to know that.
    """
    if not text:
        return {}
    try:
        raw = json.loads(text)
    except ValueError:
        return {}

    resolved = {}
    for key, value in raw.items():
        names = tuple(attnums.get((schema, table, pg_int(part))) for part in key.split(","))
        if all(names):
            resolved[names] = float(value)
    return resolved


def assemble_foreign_keys(rows) -> tuple[CatalogForeignKey, ...]:
    """Group one-row-per-column output into one record per constraint."""
    grouped: dict = {}
    for row in rows:
        key = (row[0], row[1], row[2])
        grouped.setdefault(key, []).append(row)

    keys = []
    for (name, child_schema, child_table), members in grouped.items():
        members.sort(key=lambda row: pg_int(row[7]))
        first = members[0]
        keys.append(
            CatalogForeignKey(
                constraint_name=name,
                child_schema=child_schema,
                child_table=child_table,
                child_columns=tuple(row[5] for row in members),
                parent_schema=first[3],
                parent_table=first[4],
                parent_columns=tuple(row[6] for row in members),
                on_update=REFERENTIAL_ACTIONS.get(first[8], ""),
                on_delete=REFERENTIAL_ACTIONS.get(first[9], ""),
            )
        )
    return tuple(sorted(keys, key=lambda fk: (fk.child_schema, fk.child_table, fk.constraint_name)))


# --- workload telemetry ----------------------------------------------------
# Tier 1: what the source actually does, as opposed to what it contains. All of
# it is best-effort. A role with catalog access but no statistics access still
# gets a bundle -- an omitted section with a warning beside it is more useful
# than a failed run, and the operator is often not the person who can grant the
# missing privilege.


@dataclass(frozen=True)
class TableActivity:
    schema: str
    table: str
    seq_scan: int
    seq_tup_read: int
    idx_scan: int
    idx_tup_fetch: int
    n_tup_ins: int
    n_tup_upd: int
    n_tup_del: int
    n_tup_hot_upd: int
    n_live_tup: int
    n_dead_tup: int
    n_mod_since_analyze: int
    # Timestamps stay as the server rendered them. Empty means never.
    last_vacuum: str
    last_autovacuum: str
    last_analyze: str
    last_autoanalyze: str
    vacuum_count: int
    autovacuum_count: int
    analyze_count: int
    autoanalyze_count: int


@dataclass(frozen=True)
class IndexActivity:
    schema: str
    table: str
    index: str
    idx_scan: int
    idx_tup_read: int
    idx_tup_fetch: int
    size_bytes: int


@dataclass(frozen=True)
class StatementActivity:
    """One pg_stat_statements entry. query_text is raw and is never serialized."""

    queryid: str
    query_text: str
    calls: int
    total_exec_time: float
    mean_exec_time: float
    stddev_exec_time: float
    rows: int
    shared_blks_hit: int
    shared_blks_read: int
    shared_blks_dirtied: int
    shared_blks_written: int
    temp_blks_read: int
    temp_blks_written: int


@dataclass(frozen=True)
class WorkloadObservations:
    table_activity: tuple[TableActivity, ...] = ()
    index_activity: tuple[IndexActivity, ...] = ()
    statements: tuple[StatementActivity, ...] = ()
    stats_reset: str | None = None
    warnings: tuple[ProfileWarning, ...] = ()


def collect_workload(config: PostgresConfig) -> WorkloadObservations:
    """Read the statistics views. Reads no user table.

    Every source is independently optional: one unreadable view costs its own
    section and nothing else.
    """
    warnings: list[ProfileWarning] = []

    table_activity = tuple(
        TableActivity(
            schema=row[0],
            table=row[1],
            seq_scan=pg_int(row[2]),
            seq_tup_read=pg_int(row[3]),
            idx_scan=pg_int(row[4]),
            idx_tup_fetch=pg_int(row[5]),
            n_tup_ins=pg_int(row[6]),
            n_tup_upd=pg_int(row[7]),
            n_tup_del=pg_int(row[8]),
            n_tup_hot_upd=pg_int(row[9]),
            n_live_tup=pg_int(row[10]),
            n_dead_tup=pg_int(row[11]),
            n_mod_since_analyze=pg_int(row[12]),
            last_vacuum=row[13],
            last_autovacuum=row[14],
            last_analyze=row[15],
            last_autoanalyze=row[16],
            vacuum_count=pg_int(row[17]),
            autovacuum_count=pg_int(row[18]),
            analyze_count=pg_int(row[19]),
            autoanalyze_count=pg_int(row[20]),
        )
        for row in optional_rows(
            SQL_TABLE_ACTIVITY, config, "pg_stat_user_tables", warnings, width=21
        )
        if schema_is_selected(row[0], config)
    )

    index_activity = tuple(
        IndexActivity(
            schema=row[0],
            table=row[1],
            index=row[2],
            idx_scan=pg_int(row[3]),
            idx_tup_read=pg_int(row[4]),
            idx_tup_fetch=pg_int(row[5]),
            size_bytes=pg_int(row[6]),
        )
        for row in optional_rows(
            SQL_INDEX_ACTIVITY, config, "pg_stat_user_indexes", warnings, width=7
        )
        if schema_is_selected(row[0], config)
    )

    statements, stats_reset = collect_statements(config, warnings)

    return WorkloadObservations(
        table_activity=table_activity,
        index_activity=index_activity,
        statements=statements,
        stats_reset=stats_reset,
        warnings=tuple(warnings),
    )


def optional_rows(sql, config, relation, warnings, width):
    """Run one statistics query, degrading a failure to a warning.

    The CommandError message is already redacted by run_command, so it is safe
    to carry into a warning that ends up in the manifest.
    """
    try:
        rows = run_psql(sql, config)
    except CommandError as error:
        warnings.append(
            ProfileWarning(
                code=f"{relation}_unavailable",
                message=f"{relation} could not be read, so its section is omitted: {error}",
                relation=relation,
            )
        )
        return []
    return [row for row in rows if len(row) == width]


def collect_statements(config, warnings):
    """Return (statements, stats_reset), warning instead of failing.

    The extension probe comes first: on a database without pg_stat_statements
    -- the common case, since it is not installed by default -- this costs one
    query rather than two failures.
    """
    try:
        installed = run_psql(SQL_STATEMENTS_INSTALLED, config)
    except CommandError as error:
        warnings.append(
            ProfileWarning(
                code="pg_stat_statements_unavailable",
                message=f"could not determine whether pg_stat_statements is installed: {error}",
                relation="pg_stat_statements",
            )
        )
        return (), None

    if not any(row and row[0].strip() for row in installed):
        warnings.append(
            ProfileWarning(
                code="pg_stat_statements_missing",
                message=(
                    "pg_stat_statements is not installed, so no workload telemetry was "
                    "collected; the profile describes the schema but not how it is used"
                ),
                relation="pg_stat_statements",
            )
        )
        return (), None

    stats_reset = None
    try:
        raw = run_psql_scalar(SQL_STATEMENTS_RESET, config)
        stats_reset = raw or None
    except CommandError as error:
        warnings.append(
            ProfileWarning(
                code="pg_stat_statements_info_unavailable",
                message=(
                    "pg_stat_statements_info could not be read, so the age of the "
                    f"statement counters is unknown: {error}"
                ),
                relation="pg_stat_statements_info",
            )
        )

    rows = optional_rows(SQL_STATEMENTS, config, "pg_stat_statements", warnings, width=13)
    return dedupe_statements(rows), stats_reset


def dedupe_statements(rows) -> tuple[StatementActivity, ...]:
    """One record per queryid, keeping the first occurrence.

    pg_stat_statements holds a separate entry per (userid, dbid, queryid), so
    the same statement appears once per role that ran it. The query arrives
    ordered by total execution time, so "first" is the most expensive
    occurrence -- the one a migration plan should be sized against.
    """
    seen = set()
    statements = []
    for row in rows:
        queryid = row[0]
        if queryid in seen:
            continue
        seen.add(queryid)
        statements.append(
            StatementActivity(
                queryid=queryid,
                query_text=row[1],
                calls=pg_int(row[2]),
                total_exec_time=pg_float(row[3]) or 0.0,
                mean_exec_time=pg_float(row[4]) or 0.0,
                stddev_exec_time=pg_float(row[5]) or 0.0,
                rows=pg_int(row[6]),
                shared_blks_hit=pg_int(row[7]),
                shared_blks_read=pg_int(row[8]),
                shared_blks_dirtied=pg_int(row[9]),
                shared_blks_written=pg_int(row[10]),
                temp_blks_read=pg_int(row[11]),
                temp_blks_written=pg_int(row[12]),
            )
        )
    return tuple(statements)


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------
# Catalog statistics embed literal customer values: pg_stats most-common values
# and histogram bounds are actual rows. Every one of them is replaced by an
# HMAC-SHA-256 token before anything is written.
#
# The property that has to survive is equality within a domain. A foreign key is
# only visible in the profile if the same value on the child and the parent
# tokenizes identically, and skew is only visible if a hot value stays a single
# distinct token. Everything below exists to preserve that equality and nothing
# more: no ordering, no length, no prefix.

# Shorter than this and the tokens are reversible by brute force over a small
# value space -- a hundred-row lookup table falls in seconds. There is
# deliberately no default: one would tokenize every deployment identically,
# which is the same as not tokenizing at all.
MIN_TOKEN_KEY_LENGTH = 16

# Separates domain from value in the hashed material. Without it, domain "ab"
# with value "c" and domain "a" with value "bc" would produce the same token,
# and a value could be made to impersonate one from another column.
DOMAIN_SEPARATOR = "\x00"

# Distinguishes SQL NULL from the empty string, which are different values that
# would otherwise hash identically.
NULL_SENTINEL = "\x00NULL"

# Types whose tokens are reshaped to stay loadable as that type. The profile is
# meant to be replayed into a CockroachDB schema for sizing; a 64-character hex
# string in a uuid column would force the migration team to retype it, at which
# point the shape under test is no longer the shape being migrated.
UUID_TYPE_NAMES = frozenset({"uuid"})

# Types whose text form is canonicalized numerically before hashing. PostgreSQL
# permits a foreign key across int4 and int8, and renders 42 and 42.0 for the
# same number; both sides have to hash alike. Text is deliberately excluded:
# "0001" and "1" are different strings, and collapsing them would merge two
# most-common values into one token and corrupt the frequency it carries.
NUMERIC_TYPE_NAMES = frozenset(
    {"float4", "float8", "int2", "int4", "int8", "numeric", "oid"}
)


def load_token_key(env: dict[str, str] | None = None) -> bytes:
    """Read the tokenization key from the environment, once, at startup.

    Read from the environment rather than an argument so it never appears in a
    process listing. No error below echoes the value.
    """
    raw = (env if env is not None else os.environ).get(TOKEN_KEY_ENV_VAR, "")
    if not raw.strip():
        raise ConfigError(
            f"{TOKEN_KEY_ENV_VAR} is not set; it is the key that tokenizes statistic "
            "values, and there is no default because a default would tokenize every "
            "deployment identically"
        )
    if len(raw) < MIN_TOKEN_KEY_LENGTH:
        raise ConfigError(
            f"{TOKEN_KEY_ENV_VAR} is shorter than {MIN_TOKEN_KEY_LENGTH} characters; a "
            "short key makes the tokens reversible by brute force"
        )
    return raw.encode("utf-8")


def token_domain(schema: str, table: str, column: str) -> str:
    """The tokenization domain for one column.

    Separated by the same NUL as the value, because PostgreSQL permits a dot
    inside a quoted identifier and a dotted join would let one column's values
    impersonate another's.
    """
    return DOMAIN_SEPARATOR.join((schema, table, column))


def canonical_number(text: str) -> str | None:
    """Return the canonical decimal form of text, or None if it is not one."""
    try:
        number = decimal.Decimal(text)
    except (decimal.InvalidOperation, ValueError):
        return None
    if not number.is_finite():  # NaN and Infinity are legal float8 values.
        return None
    return format(number.normalize(), "f")


def canonical_uuid(text: str) -> str | None:
    """Return the canonical uuid form of text, or None if it is not one."""
    try:
        return str(uuid.UUID(text))
    except (ValueError, AttributeError):
        return None


def repr_typed(value: str | None, type_name: str = "") -> str:
    """Canonical text of a source value, for hashing.

    The type name steers canonicalization but is never itself hashed: a foreign
    key may cross int4 and int8, and folding the type into the material would
    break exactly the equality these tokens exist to preserve.
    """
    if value is None:
        return NULL_SENTINEL

    lowered = type_name.lower()
    if lowered in NUMERIC_TYPE_NAMES:
        canonical = canonical_number(value.strip())
        if canonical is not None:
            return canonical
    elif lowered in UUID_TYPE_NAMES:
        canonical = canonical_uuid(value.strip())
        if canonical is not None:
            return canonical

    # Not canonicalizable, or a type where the text is the value. Returned
    # unstripped: trailing whitespace in a text column is part of the value.
    return value


@dataclass(frozen=True, repr=False)
class Tokenizer:
    """Replaces source values with HMAC tokens.

    Holds the key, so the key lives in one object with a repr that cannot leak
    it. A module-level key would end up in a traceback the first time an
    unrelated function was called with one in scope.
    """

    key: bytes

    def __repr__(self) -> str:
        return f"{type(self).__name__}(key={REDACTED})"

    def token(self, value: str | None, domain: str, type_name: str = "") -> str:
        """Return the token for one value in one domain."""
        material = domain + DOMAIN_SEPARATOR + repr_typed(value, type_name)
        digest = hmac.new(self.key, material.encode("utf-8"), hashlib.sha256).hexdigest()
        if type_name.lower() in UUID_TYPE_NAMES:
            return shape_as_uuid(digest)
        return digest

    def tokens(self, values, domain: str, type_name: str = "") -> tuple[str, ...]:
        """Tokenize a sequence elementwise, preserving order.

        Order is preserved because the caller's parallel array of frequencies is
        positional; the tokens themselves carry no ordering information.
        """
        return tuple(self.token(value, domain, type_name) for value in values)


def shape_as_uuid(digest: str) -> str:
    """Format the first 128 bits of a digest as a uuid.

    Not a version-4 uuid: the version and variant bits are left as digest bits
    rather than overwritten, because a token that advertised itself as random
    would be a lie about where it came from. Any 128-bit value is a valid uuid
    to both PostgreSQL and CockroachDB.
    """
    head = digest[:32]
    return "-".join((head[:8], head[8:12], head[12:16], head[16:20], head[20:32]))


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
# Turns collected catalog rows into the contract. Two rules govern this section.
#
# PostgreSQL-native names stay out of the contract and live in `provenance`
# instead. A consumer reading profile.json should not have to know that
# reltuples is an estimate, or that n_distinct is negative when it means a
# fraction. The native encodings are recorded rather than discarded, because a
# number without its derivation is not auditable.
#
# Nothing is invented. Where PostgreSQL has no estimate, the contract carries
# None and a fan-out says insufficient_statistics. A plausible number is worse
# than a gap: a gap gets investigated.

# pg_stats.most_common_freqs are fractions of all rows in the table, nulls
# included -- not fractions of the non-null rows, and not of the distinct values.
FREQ_BASIS = "all rows, nulls included"

FAN_OUT_ESTIMATED = "estimated"
FAN_OUT_INSUFFICIENT = "insufficient_statistics"
BASIS_SINGLE_COLUMN = "single_column"
BASIS_EXTENDED_STATISTICS = "extended_statistics"
BASIS_COMPOSITE = "composite"

# The percentile reported alongside the mean. The mean alone hides skew, and
# skew is the thing that breaks a migration: a table whose average parent has
# ten children can still have one parent with half a million.
FAN_OUT_PERCENTILE = 0.99


def resolve_distinct(n_distinct: float, row_count: float) -> float | None:
    """Resolve pg_stats.n_distinct into an absolute count.

    PostgreSQL stores a positive value as a count and a negative one as a
    fraction of the table's rows -- the second form is how it expresses "this
    column stays unique as the table grows". Zero means it has no estimate.
    """
    if n_distinct == 0:
        return None
    if n_distinct < 0:
        return abs(n_distinct) * row_count
    return n_distinct


def describe_distinct(n_distinct: float, row_count: float) -> str:
    """Record the native encoding behind a resolved distinct estimate."""
    if n_distinct == 0:
        return "pg_stats.n_distinct=0: PostgreSQL has no distinct estimate for this column"
    if n_distinct < 0:
        return (
            f"pg_stats.n_distinct={format_number(n_distinct)} is a fraction of rows, "
            f"resolved against pg_class.reltuples={format_number(row_count)}"
        )
    return f"pg_stats.n_distinct={format_number(n_distinct)} is an absolute count"


def format_number(value: float) -> str:
    """Render a float without a trailing .0, so provenance reads like the catalog."""
    return str(int(value)) if float(value).is_integer() else str(value)


def build_token_domains(columns, foreign_keys) -> dict:
    """Map every column to the (domain, type) its values tokenize under.

    A foreign key is only visible in the profile if the same value tokenizes
    identically on the child and the parent, so a child column borrows its
    parent's domain. Chains are followed to their root: with A.x -> B.y and
    B.y -> C.z, A.x tokenizing under B.y while B.y tokenizes under C.z would
    make the A-to-B join invisible, which is the exact failure this prevents.

    The root column's type also wins, so a text column referencing a uuid one
    canonicalizes and shapes the same way on both sides.
    """
    parent_of: dict = {}
    for fk in foreign_keys:
        for child, parent in zip(fk.child_columns, fk.parent_columns):
            key = (fk.child_schema, fk.child_table, child)
            parent_of.setdefault(key, (fk.parent_schema, fk.parent_table, parent))

    types = {(c.schema, c.table, c.name): c.type_name for c in columns}
    domains = {}
    for column in columns:
        key = (column.schema, column.table, column.name)
        root = resolve_domain_root(key, parent_of)
        domains[key] = (token_domain(*root), types.get(root, column.type_name))
    return domains


def resolve_domain_root(key, parent_of):
    """Follow a foreign-key chain to its root, stopping on a cycle.

    Self-referential and mutually referential keys are legal in PostgreSQL, so
    this cannot assume termination.
    """
    seen = {key}
    while key in parent_of:
        key = parent_of[key]
        if key in seen:
            break
        seen.add(key)
    return key


def normalize_columns(catalog: CatalogObservations, tokenizer: Tokenizer) -> dict:
    """Return (schema, table) -> ordered tuple of contract Columns."""
    row_counts = {(t.schema, t.name): t.reltuples for t in catalog.tables}
    stats = {(s.schema, s.table, s.column): s for s in catalog.column_stats}
    domains = build_token_domains(catalog.columns, catalog.foreign_keys)

    by_table: dict = {}
    for column in sorted(catalog.columns, key=lambda c: (c.schema, c.table, c.ordinal)):
        key = (column.schema, column.table, column.name)
        domain, type_name = domains[key]
        by_table.setdefault((column.schema, column.table), []).append(
            normalize_column(
                column,
                stats.get(key),
                row_counts.get((column.schema, column.table), 0.0),
                tokenizer,
                domain,
                type_name,
            )
        )
    return {table: tuple(columns) for table, columns in by_table.items()}


def normalize_column(column, statistic, row_count, tokenizer, domain, type_name) -> Column:
    """Build one contract Column, tokenizing every value it carries."""
    if statistic is None:
        return Column(
            schema=column.schema,
            table=column.table,
            name=column.name,
            ordinal=column.ordinal,
            data_type=column.data_type,
            is_nullable=column.is_nullable,
            is_supported=column.is_supported,
            provenance=(
                "no pg_stats row: the column has never been analyzed, so PostgreSQL "
                "has no distribution for it"
            ),
        )

    return Column(
        schema=column.schema,
        table=column.table,
        name=column.name,
        ordinal=column.ordinal,
        data_type=column.data_type,
        is_nullable=column.is_nullable,
        is_supported=column.is_supported,
        null_fraction=statistic.null_frac,
        avg_width_bytes=statistic.avg_width,
        distinct_estimate=resolve_distinct(statistic.n_distinct, row_count),
        most_common_tokens=tokenizer.tokens(statistic.most_common_vals, domain, type_name),
        most_common_freqs=statistic.most_common_freqs,
        histogram_token_bounds=tokenizer.tokens(statistic.histogram_bounds, domain, type_name),
        provenance=(
            f"{describe_distinct(statistic.n_distinct, row_count)}; "
            f"pg_stats.most_common_freqs are fractions of {FREQ_BASIS}; "
            "values are HMAC tokens, equal within a foreign-key domain"
        ),
    )


def normalize_tables(catalog: CatalogObservations, tokenizer: Tokenizer) -> tuple[Table, ...]:
    """Return the contract Tables, sorted, each with its columns in ordinal order."""
    columns = normalize_columns(catalog, tokenizer)
    return tuple(
        Table(
            schema=table.schema,
            name=table.name,
            row_count_estimate=table.reltuples,
            size_bytes=table.size_bytes,
            columns=columns.get((table.schema, table.name), ()),
            provenance=(
                "row_count_estimate is pg_class.reltuples, an estimate maintained by "
                "the autovacuum daemon and never a row count; size_bytes is "
                "pg_total_relation_size, including indexes and TOAST"
            ),
        )
        for table in sorted(catalog.tables, key=lambda t: (t.schema, t.name))
    )


def normalize_relationships(catalog: CatalogObservations) -> tuple[Relationship, ...]:
    """Return the contract Relationships, each with a fan-out estimate."""
    row_counts = {(t.schema, t.name): t.reltuples for t in catalog.tables}
    stats = {(s.schema, s.table, s.column): s for s in catalog.column_stats}
    extended: dict = {}
    for entry in catalog.extended_stats:
        for columns, value in entry.n_distinct.items():
            extended[(entry.schema, entry.table, frozenset(columns))] = value

    return tuple(
        Relationship(
            constraint_name=fk.constraint_name,
            child_schema=fk.child_schema,
            child_table=fk.child_table,
            child_columns=fk.child_columns,
            parent_schema=fk.parent_schema,
            parent_table=fk.parent_table,
            parent_columns=fk.parent_columns,
            on_update=fk.on_update,
            on_delete=fk.on_delete,
            fan_out=estimate_fan_out(fk, row_counts, stats, extended),
        )
        for fk in sorted(
            catalog.foreign_keys,
            key=lambda fk: (fk.child_schema, fk.child_table, fk.constraint_name),
        )
    )


def estimate_fan_out(fk, row_counts, stats, extended) -> FanOut:
    """Estimate children per parent across one foreign key.

    Children per parent is the number of child rows that actually reference a
    parent, divided by how many distinct parents they reference.
    """
    child_rows = row_counts.get((fk.child_schema, fk.child_table), 0.0)
    if len(fk.child_columns) > 1:
        return composite_fan_out(fk, child_rows, stats, extended)
    return single_column_fan_out(fk, child_rows, stats)


def single_column_fan_out(fk, child_rows, stats) -> FanOut:
    statistic = stats.get((fk.child_schema, fk.child_table, fk.child_columns[0]))
    if statistic is None:
        return FanOut(status=FAN_OUT_INSUFFICIENT, basis=BASIS_SINGLE_COLUMN)

    distinct = resolve_distinct(statistic.n_distinct, child_rows)
    if not distinct:
        return FanOut(status=FAN_OUT_INSUFFICIENT, basis=BASIS_SINGLE_COLUMN)

    # A null foreign key references no parent, so those rows are not children to
    # distribute. Counting them would inflate every estimate on a nullable key.
    referencing = child_rows * (1.0 - statistic.null_frac)
    return FanOut(
        status=FAN_OUT_ESTIMATED,
        basis=BASIS_SINGLE_COLUMN,
        mean=referencing / distinct,
        p99=estimate_p99(statistic.most_common_freqs, child_rows, distinct),
    )


def composite_fan_out(fk, child_rows, stats, extended) -> FanOut:
    """Estimate a multi-column key, or decline to.

    The distinct count of a column pair is not the product of the columns'
    distinct counts unless the columns are independent, and foreign-key columns
    almost never are. Multiplying would understate fan-out by orders of
    magnitude and size a migration against a workload that does not exist, so
    this reports insufficient_statistics unless PostgreSQL has extended
    statistics covering exactly this column set. The remedy is in the operator's
    hands -- declare extended statistics on the source, re-analyze, re-run -- and
    is theirs to take, because this tool does not write to the source.
    """
    key = (fk.child_schema, fk.child_table, frozenset(fk.child_columns))
    if key not in extended:
        return FanOut(status=FAN_OUT_INSUFFICIENT, basis=BASIS_COMPOSITE)

    distinct = resolve_distinct(extended[key], child_rows)
    if not distinct:
        return FanOut(status=FAN_OUT_INSUFFICIENT, basis=BASIS_COMPOSITE)

    # A composite key references a parent only when every column is non-null, and
    # PostgreSQL has no joint null fraction. The most-null column is the tightest
    # bound available, so the estimate errs high rather than low.
    null_fracs = [
        stats[(fk.child_schema, fk.child_table, name)].null_frac
        for name in fk.child_columns
        if (fk.child_schema, fk.child_table, name) in stats
    ]
    referencing = child_rows * (1.0 - max(null_fracs, default=0.0))
    return FanOut(
        status=FAN_OUT_ESTIMATED,
        basis=BASIS_EXTENDED_STATISTICS,
        mean=referencing / distinct,
    )


def estimate_p99(most_common_freqs, child_rows, distinct) -> float | None:
    """Estimate children per parent at the 99th percentile of parents.

    Only the most common values are known individually, so this ranks those and
    reads off the percentile. When the MCV list is shorter than the percentile's
    rank -- the usual case, since PostgreSQL keeps at most a few hundred -- every
    parent past the list has no more children than the last MCV, so the last
    MCV's count is returned as an upper bound. Erring high is the right
    direction: an under-reported hot parent is discovered during the migration.
    """
    if not most_common_freqs or not distinct:
        return None
    counts = sorted((freq * child_rows for freq in most_common_freqs), reverse=True)
    rank = max(1, math.ceil((1.0 - FAN_OUT_PERCENTILE) * distinct))
    return counts[rank - 1] if rank <= len(counts) else counts[-1]


def build_profile(
    source: Source,
    catalog: CatalogObservations,
    workload: WorkloadObservations,
    tokenizer: Tokenizer,
) -> Profile:
    """Assemble the normalized contract from everything collected."""
    return Profile(
        source=source,
        tables=normalize_tables(catalog, tokenizer),
        relationships=normalize_relationships(catalog),
        warnings=workload.warnings,
    )


# ---------------------------------------------------------------------------
# Bundle publication
# ---------------------------------------------------------------------------
# The only code in this file that writes to disk. Two properties matter, and
# both are enforced here rather than trusted:
#
#   Nothing raw escapes. Serialization is by allowlist -- only the contract
#   dataclasses become JSON, and every CSV is shaped from already-tokenized
#   records. The collector records holding raw statistics values and raw query
#   text are dataclasses too, so a structural serializer would have written
#   them out; to_jsonable() refuses them by name.
#
#   Publication is all-or-nothing. The archive is built in a temporary file
#   beside the destination, fsynced, and moved into place with os.replace().
#   A crash or an error leaves either the previous bundle or nothing at all --
#   never a truncated archive that looks complete.

BUNDLE_MANIFEST = "manifest.json"
BUNDLE_SCHEMA = "schema.sql"
BUNDLE_PROFILE = "profile.json"

OBSERVATION_TABLES = "observations/pg_class.csv"
OBSERVATION_COLUMNS = "observations/pg_stats.csv"
OBSERVATION_EXTENDED = "observations/pg_stats_ext.csv"
OBSERVATION_FOREIGN_KEYS = "observations/foreign_keys.csv"
OBSERVATION_INDEX_ACTIVITY = "observations/pg_stat_indexes.csv"
OBSERVATION_TABLE_ACTIVITY = "observations/pg_stat_tables.csv"
OBSERVATION_STATEMENTS = "observations/pg_stat_statements.csv"

# Every path the bundle may contain, besides the manifest. An entry outside
# this set is rejected rather than written: the bundle's contents are part of
# the contract, and a reviewer should be able to read the whole list here.
BUNDLE_PAYLOAD_PATHS = (
    BUNDLE_PROFILE,
    BUNDLE_SCHEMA,
    OBSERVATION_FOREIGN_KEYS,
    OBSERVATION_TABLES,
    OBSERVATION_COLUMNS,
    OBSERVATION_EXTENDED,
    OBSERVATION_INDEX_ACTIVITY,
    OBSERVATION_TABLE_ACTIVITY,
    OBSERVATION_STATEMENTS,
)

BUNDLE_ALLOWED_PATHS = frozenset(BUNDLE_PAYLOAD_PATHS)

# The entries that make a bundle worth publishing. The statistics sections are
# allowed to degrade to a warning; these are not -- a bundle missing one of
# them looks complete and is not.
REQUIRED_BUNDLE_PATHS = frozenset(
    {
        BUNDLE_PROFILE,
        BUNDLE_SCHEMA,
        OBSERVATION_TABLES,
        OBSERVATION_COLUMNS,
        OBSERVATION_FOREIGN_KEYS,
    }
)

# A section is omitted when the collector that feeds it degraded, and the
# manifest warning says why. Omission is keyed off the warning rather than off
# an empty record set so that "the role could not read this view" stays
# distinguishable from "this database has no user tables".
OMITTED_BY_WARNING = {
    OBSERVATION_TABLE_ACTIVITY: ("pg_stat_user_tables_unavailable",),
    OBSERVATION_INDEX_ACTIVITY: ("pg_stat_user_indexes_unavailable",),
    OBSERVATION_STATEMENTS: (
        "pg_stat_statements_missing",
        "pg_stat_statements_unavailable",
    ),
}

# Lowercase, slash-separated, each segment starting with a letter or digit.
# This rejects, by construction: absolute paths, `..` and `.` segments, empty
# segments, backslashes, drive letters, whitespace, control characters, and
# anything non-ASCII. A ZIP extractor honours what the entry name says, so the
# entry name is not allowed to say anything but "a file under here".
SAFE_ENTRY_PATH = re.compile(r"[a-z0-9][a-z0-9_.-]*(?:/[a-z0-9][a-z0-9_.-]*)*\Z")

# Fixed so two runs over the same input produce byte-identical archives, which
# makes a bundle diffable and a hash reproducible. 1980-01-01 is the earliest
# timestamp the ZIP format can represent.
BUNDLE_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

# S_IFREG | 0644, set on every entry. Left to zipfile's default the mode is
# zero, and some extractors then fall back to the umask; set explicitly, no
# entry can carry a symlink, setuid, or executable bit for an extractor to act
# on.
BUNDLE_FILE_MODE = 0o100644
BUNDLE_CREATE_SYSTEM = 3  # Unix, so the mode above is read as a unix mode.

TEMP_SUFFIX = ".zip.tmp"

# Tokens are hex and identifiers cannot contain it, so a pipe separates the
# repeated values inside one CSV cell without needing an escape.
CELL_SEPARATOR = "|"

# pg_stat_statements is cluster-wide and its text is not attributable to one
# column, so query text gets its own domain rather than a column's.
STATEMENT_DOMAIN = token_domain("pg_stat_statements", "", "query")

# The dataclasses that may be serialized. Everything else -- including the
# collector records that hold raw most-common values and raw query text -- is
# refused. See the section note above.
CONTRACT_TYPES = (
    Column,
    FanOut,
    Manifest,
    Observation,
    Profile,
    ProfileWarning,
    Relationship,
    Source,
    Table,
)


@dataclass(frozen=True)
class BundleEntry:
    """One payload file, fully serialized, before it is written."""

    path: str
    data: bytes
    row_count: int = 0


def require_safe_entry_path(path: str) -> None:
    """Reject any entry name an extractor could resolve outside its target."""
    if not SAFE_ENTRY_PATH.match(path):
        raise BundleError(f"unsafe bundle entry path: {path!r}")


# --- serialization ---------------------------------------------------------


def to_jsonable(value):
    """Convert a contract record to JSON-native types, refusing anything else.

    Deliberately not dataclasses.asdict(): that walks any dataclass, and the
    records holding raw values are dataclasses. Membership in CONTRACT_TYPES is
    the check, so adding a serializable record is a visible edit here.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, CONTRACT_TYPES):
        return {field.name: to_jsonable(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, (tuple, list)):
        return [to_jsonable(item) for item in value]
    raise BundleError(
        f"refusing to serialize {type(value).__name__}: "
        "only the contract types are written to the bundle"
    )


def json_bytes(record) -> bytes:
    """Serialize a contract record. allow_nan is off: NaN is not JSON."""
    text = json.dumps(to_jsonable(record), indent=2, ensure_ascii=False, allow_nan=False)
    return (text + "\n").encode("utf-8")


def cell(value) -> str:
    """Render one CSV field. None is an absent measurement, not the string None."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def joined(values) -> str:
    return CELL_SEPARATOR.join(cell(value) for value in values)


def csv_entry(path: str, header, rows) -> BundleEntry:
    """Shape one observation CSV. row_count excludes the header."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)
    count = 0
    for row in rows:
        writer.writerow([cell(value) for value in row])
        count += 1
    return BundleEntry(path=path, data=buffer.getvalue().encode("utf-8"), row_count=count)


# --- observation shaping ---------------------------------------------------


def observation_tables(profile: Profile) -> BundleEntry:
    return csv_entry(
        OBSERVATION_TABLES,
        ("schema", "table", "row_count_estimate", "size_bytes", "column_count", "provenance"),
        (
            (table.schema, table.name, table.row_count_estimate, table.size_bytes,
             len(table.columns), table.provenance)
            for table in profile.tables
        ),
    )


def observation_columns(profile: Profile) -> BundleEntry:
    return csv_entry(
        OBSERVATION_COLUMNS,
        ("schema", "table", "column", "ordinal", "data_type", "is_nullable", "is_supported",
         "null_fraction", "avg_width_bytes", "distinct_estimate", "most_common_tokens",
         "most_common_freqs", "histogram_token_bounds", "provenance"),
        (
            (column.schema, column.table, column.name, column.ordinal, column.data_type,
             column.is_nullable, column.is_supported, column.null_fraction,
             column.avg_width_bytes, column.distinct_estimate,
             joined(column.most_common_tokens), joined(column.most_common_freqs),
             joined(column.histogram_token_bounds), column.provenance)
            for table in profile.tables
            for column in table.columns
        ),
    )


def observation_extended_stats(catalog: CatalogObservations) -> BundleEntry:
    """One row per column combination the source has a distinct estimate for.

    Only the estimates are published. The extended most-common-value lists hold
    literals, so the bundle records that they exist and nothing more.
    """
    return csv_entry(
        OBSERVATION_EXTENDED,
        ("schema", "table", "statistics_name", "declared_columns", "combination",
         "distinct_estimate", "has_most_common_values"),
        (
            (statistic.schema, statistic.table, statistic.name, joined(statistic.columns),
             joined(combination), estimate, statistic.has_most_common_values)
            for statistic in catalog.extended_stats
            for combination, estimate in sorted(statistic.n_distinct.items())
        ),
    )


def observation_foreign_keys(profile: Profile) -> BundleEntry:
    return csv_entry(
        OBSERVATION_FOREIGN_KEYS,
        ("constraint_name", "child_schema", "child_table", "child_columns", "parent_schema",
         "parent_table", "parent_columns", "on_update", "on_delete", "fan_out_status",
         "fan_out_basis", "fan_out_mean", "fan_out_p99"),
        (
            (rel.constraint_name, rel.child_schema, rel.child_table, joined(rel.child_columns),
             rel.parent_schema, rel.parent_table, joined(rel.parent_columns),
             rel.on_update, rel.on_delete,
             rel.fan_out.status if rel.fan_out else None,
             rel.fan_out.basis if rel.fan_out else None,
             rel.fan_out.mean if rel.fan_out else None,
             rel.fan_out.p99 if rel.fan_out else None)
            for rel in profile.relationships
        ),
    )


def observation_table_activity(workload: WorkloadObservations) -> BundleEntry:
    return csv_entry(
        OBSERVATION_TABLE_ACTIVITY,
        tuple(field.name for field in fields(TableActivity)),
        (
            tuple(getattr(activity, field.name) for field in fields(TableActivity))
            for activity in workload.table_activity
        ),
    )


def observation_index_activity(
    workload: WorkloadObservations, catalog: CatalogObservations
) -> BundleEntry:
    """Index usage, joined with the catalog for uniqueness.

    idx_scan == 0 marks an index as a drop candidate, but whether it can be
    dropped depends on whether it backs a constraint, and only the catalog
    knows that. Both facts are already collected; separating them across two
    files would make every reader join them again.
    """
    described = {(index.schema, index.table, index.name): index for index in catalog.indexes}
    rows = []
    for activity in workload.index_activity:
        index = described.get((activity.schema, activity.table, activity.index))
        rows.append(
            (activity.schema, activity.table, activity.index, activity.idx_scan,
             activity.idx_tup_read, activity.idx_tup_fetch, activity.size_bytes,
             index.is_unique if index else None,
             index.is_primary if index else None)
        )
    return csv_entry(
        OBSERVATION_INDEX_ACTIVITY,
        ("schema", "table", "index", "idx_scan", "idx_tup_read", "idx_tup_fetch", "size_bytes",
         "is_unique", "is_primary"),
        rows,
    )


def observation_statements(
    workload: WorkloadObservations, tokenizer: Tokenizer
) -> BundleEntry:
    """Statement counters, with the query text replaced by a token.

    pg_stat_statements normally normalizes literals to $1 placeholders, but not
    for utility statements and not for constants the parser folds, so the text
    cannot be published. The token still separates one statement's counters
    from another's, and queryid remains for correlating with the source server.
    """
    return csv_entry(
        OBSERVATION_STATEMENTS,
        ("queryid", "query_token", "calls", "rows", "total_exec_time", "mean_exec_time",
         "stddev_exec_time", "shared_blks_hit", "shared_blks_read", "shared_blks_dirtied",
         "shared_blks_written", "temp_blks_read", "temp_blks_written"),
        (
            (statement.queryid,
             tokenizer.token(statement.query_text, STATEMENT_DOMAIN),
             statement.calls, statement.rows, statement.total_exec_time,
             statement.mean_exec_time, statement.stddev_exec_time, statement.shared_blks_hit,
             statement.shared_blks_read, statement.shared_blks_dirtied,
             statement.shared_blks_written, statement.temp_blks_read,
             statement.temp_blks_written)
            for statement in workload.statements
        ),
    )


def build_payloads(
    profile: Profile,
    catalog: CatalogObservations,
    workload: WorkloadObservations,
    tokenizer: Tokenizer,
    schema_sql: str,
) -> tuple[BundleEntry, ...]:
    """Serialize everything collected, dropping the sections that degraded."""
    entries = [
        BundleEntry(BUNDLE_SCHEMA, schema_sql.encode("utf-8"), schema_sql.count("\n")),
        BundleEntry(BUNDLE_PROFILE, json_bytes(profile), len(profile.tables)),
        observation_tables(profile),
        observation_columns(profile),
        observation_extended_stats(catalog),
        observation_foreign_keys(profile),
        observation_table_activity(workload),
        observation_index_activity(workload, catalog),
        observation_statements(workload, tokenizer),
    ]
    reported = {warning.code for warning in workload.warnings}
    kept = [
        entry
        for entry in entries
        if not reported.intersection(OMITTED_BY_WARNING.get(entry.path, ()))
    ]
    return tuple(sorted(kept, key=lambda entry: entry.path))


# --- manifest --------------------------------------------------------------


def utc_now() -> str:
    """Now, as RFC 3339 in UTC. Whole seconds: nothing here needs finer."""
    stamp = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    return stamp.isoformat().replace("+00:00", "Z")


def describe_payloads(payloads) -> tuple[Observation, ...]:
    """Hash the uncompressed payload bytes -- what a reader gets after extraction."""
    return tuple(
        Observation(
            path=entry.path,
            sha256=hashlib.sha256(entry.data).hexdigest(),
            row_count=entry.row_count,
        )
        for entry in sorted(payloads, key=lambda entry: entry.path)
    )


def build_manifest(
    source: Source,
    schema_fingerprint: str,
    payloads,
    warnings=(),
    stats_reset: str | None = None,
    created_at: str | None = None,
) -> Manifest:
    return Manifest(
        tool=PROG,
        tool_version=VERSION,
        contract_version=CONTRACT_VERSION,
        created_at=created_at or utc_now(),
        source=source,
        schema_fingerprint=schema_fingerprint,
        payloads=describe_payloads(payloads),
        warnings=tuple(warnings),
        stats_reset=stats_reset,
    )


# --- publication -----------------------------------------------------------


def validate_payloads(payloads, manifest: Manifest) -> tuple[BundleEntry, ...]:
    """Check every rule the archive must satisfy before a byte is written."""
    entries = tuple(sorted(payloads, key=lambda entry: entry.path))
    seen: set[str] = set()
    for entry in entries:
        require_safe_entry_path(entry.path)
        if entry.path == BUNDLE_MANIFEST:
            raise BundleError(
                "manifest.json is written by write_bundle, not supplied as a payload"
            )
        if entry.path not in BUNDLE_ALLOWED_PATHS:
            raise BundleError(f"unexpected bundle entry: {entry.path!r}")
        if entry.path in seen:
            raise BundleError(f"duplicate bundle entry: {entry.path!r}")
        seen.add(entry.path)

    described = {observation.path: observation for observation in manifest.payloads}
    if set(described) != seen:
        raise BundleError("the manifest does not describe exactly the payloads being written")
    for entry in entries:
        if described[entry.path].sha256 != hashlib.sha256(entry.data).hexdigest():
            raise BundleError(f"manifest hash does not match payload {entry.path!r}")
    return entries


def require_publishable_destination(destination: Path) -> None:
    """Refuse to publish anywhere os.replace would surprise the operator."""
    if destination.is_symlink():
        raise BundleError(f"refusing to publish through a symlink: {destination}")
    if destination.exists() and not destination.is_file():
        raise BundleError(f"destination exists and is not a regular file: {destination}")


def write_entry(archive: zipfile.ZipFile, path: str, data: bytes) -> None:
    info = zipfile.ZipInfo(filename=path, date_time=BUNDLE_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = BUNDLE_CREATE_SYSTEM
    info.external_attr = BUNDLE_FILE_MODE << 16
    archive.writestr(info, data)


def sync_directory(path: Path) -> None:
    """Flush the rename itself, so a crash cannot lose a bundle we reported.

    Best effort: not every platform or filesystem allows opening a directory,
    and failing to publish because the durability flush failed would be worse
    than the durability gap.
    """
    try:
        handle = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(handle)
    except OSError:
        pass
    finally:
        os.close(handle)


def write_bundle(destination, payloads, manifest: Manifest) -> Path:
    """Publish the bundle atomically. Returns the destination.

    The manifest is serialized and stored last, after the payloads it hashes.
    Nothing appears at the destination until the whole archive is on disk and
    fsynced; any failure removes the temporary file and leaves whatever was
    there before untouched.
    """
    entries = validate_payloads(payloads, manifest)
    destination = Path(destination)
    require_publishable_destination(destination)

    parent = destination.parent if str(destination.parent) else Path(".")
    parent.mkdir(parents=True, exist_ok=True)
    # delete=False because the file is closed before os.replace moves it; the
    # except below is what removes it if anything goes wrong. A unique name
    # rather than a fixed one so two concurrent runs cannot clobber each other.
    handle = tempfile.NamedTemporaryFile(
        dir=str(parent), prefix=destination.name + ".", suffix=TEMP_SUFFIX, delete=False
    )
    temporary = Path(handle.name)
    try:
        with handle:
            with zipfile.ZipFile(handle, "w", zipfile.ZIP_DEFLATED) as archive:
                for entry in entries:
                    write_entry(archive, entry.path, entry.data)
                write_entry(archive, BUNDLE_MANIFEST, json_bytes(manifest))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(destination))
    except BaseException:
        # Including KeyboardInterrupt: a half-written archive beside the
        # destination is litter that looks like a bundle.
        try:
            temporary.unlink()
        except OSError:
            pass
        raise

    sync_directory(parent)
    return destination


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def progress(message: str) -> None:
    """Report a step. stderr, so stdout stays the bundle path and nothing else.

    Every message here is composed from constants and from values the source
    itself reported; nothing derived from the connection string reaches it.
    """
    print(f"{PROG}: {message}", file=sys.stderr)


def collected_schemas(catalog: CatalogObservations) -> tuple[str, ...]:
    """The schemas the run actually read, not the ones it was asked for.

    --schema-include names an intent; this records the outcome, so a bundle
    that silently covered less than the operator expected says so.
    """
    return tuple(sorted({table.schema for table in catalog.tables}))


def require_complete_bundle(payloads) -> None:
    missing = REQUIRED_BUNDLE_PATHS.difference(entry.path for entry in payloads)
    if missing:
        raise BundleError(
            "refusing to publish an incomplete bundle, missing: " + ", ".join(sorted(missing))
        )


def require_stable_schema(before: str, after: str) -> None:
    """Fail on concurrent DDL rather than publish two versions of one schema.

    Each psql invocation is its own transaction, so the collection is not
    isolated. Comparing the catalog fingerprint on either side of it turns
    that relaxation into a detected condition instead of a silent one.
    """
    if before != after:
        raise SchemaDrift(
            "the source schema changed during collection, so the bundle would mix two "
            "versions of it; re-run when no migration is in flight"
        )


def run_postgres(args: argparse.Namespace) -> int:
    """Collect a profile from a PostgreSQL source and publish the bundle."""
    config = build_postgres_config(args)

    # Both of these fail before a connection is opened. A tokenization key that
    # turns out to be missing after collection, or a destination that cannot be
    # written to, costs the operator a full pass over the catalog to discover.
    tokenizer = Tokenizer(load_token_key())
    require_publishable_destination(config.output)

    progress("checking the source server version")
    server_version_num = probe_server_version(config)
    server_version = format_server_version(server_version_num)

    progress(f"reading the schema of PostgreSQL {server_version}")
    schema_sql, fingerprint = collect_schema(config, server_version_num)
    if not schema_sql.strip():
        raise CommandError("pg_dump produced no schema; the role may not see any objects")

    progress("reading the catalog")
    catalog = collect_catalog(config)

    progress("reading the statistics views")
    workload = collect_workload(config)
    for warning in workload.warnings:
        progress(f"warning: {warning.code}: {warning.message}")

    progress("checking the schema did not change during collection")
    require_stable_schema(fingerprint, schema_fingerprint(config))

    source = Source(
        kind="postgres",
        server_version_num=server_version_num,
        server_version=server_version,
        database=config.env.get("PGDATABASE", ""),
        collected_schemas=collected_schemas(catalog),
    )
    profile = build_profile(source, catalog, workload, tokenizer)
    payloads = build_payloads(profile, catalog, workload, tokenizer, schema_sql)
    require_complete_bundle(payloads)
    manifest = build_manifest(
        source=source,
        schema_fingerprint=fingerprint,
        payloads=payloads,
        warnings=workload.warnings,
        stats_reset=workload.stats_reset,
    )

    progress("publishing the bundle")
    write_bundle(config.output, payloads, manifest)
    print(config.output)
    return 0


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
        except KeyboardInterrupt:
            # write_bundle removes its own temporary file on the way out, so
            # there is nothing to clean up here -- only something to say.
            print(f"{PROG}: cancelled; no bundle was written", file=sys.stderr)
            return 130

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
