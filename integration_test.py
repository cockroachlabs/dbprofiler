# Copyright (c) 2026 Cockroach Labs, Inc.
# SPDX-License-Identifier: MIT
"""End-to-end integration test for dbprofiler.

Runs the shipped script, as a subprocess, against a real PostgreSQL 16, and
checks the bundle it produces. Skipped unless DBPROFILER_POSTGRES_TEST_URL is
set, so a plain `python3 -m unittest` stays offline. See docs/TESTING.md for
the disposable server.

    python3 -m unittest integration_test -v

Its value is never printed. The connection string reaches psql and the profiler
through the environment only, as it does in production, and child-process
stderr goes through dbprofiler.redact_error before it can reach an assertion
message.

This file issues DDL, DML, ANALYZE, and CREATE STATISTICS. Those are forbidden
to dbprofiler.py and enforced against it by --check-safety, which reflects over
that module's SQL_* constants; nothing here is reachable from the tool. They
are permitted here, and only here, because every object involved lives in a
schema this test creates under a name nobody else uses and drops on the way
out. The point of the exercise is to hand the profiler statistics PostgreSQL
computed, which means something has to compute them first.
"""

from __future__ import annotations

import collections
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import zipfile
from pathlib import Path

import dbprofiler

REPO = Path(__file__).resolve().parent
SCRIPT = REPO / "dbprofiler.py"

TEST_URL_ENV_VAR = "DBPROFILER_POSTGRES_TEST_URL"

# Read as a boolean. The value is never held in a module constant, never
# logged, and never quoted into a failure message.
CONFIGURED = bool(os.getenv(TEST_URL_ENV_VAR))
WHY_SKIPPED = f"set {TEST_URL_ENV_VAR} to run"

PSQL = os.getenv("DBPROFILER_TEST_PSQL", "psql")

# One schema per run, so two people testing against the same server -- or one
# person whose previous run died before its teardown -- cannot collide or
# inherit each other's fixtures.
SCHEMA = f"dbprofiler_it_{int(time.time())}_{uuid.uuid4().hex[:8]}"

# Values planted in the fixture data so the bundle can be searched for them.
# Each takes a different route into the statistics the profiler reads:
#
#   REGION_CODE   a most-common value in pg_stats
#   EMAIL_DOMAIN  a histogram bound in pg_stats
#   TENANT_LABEL  a most-common value on the composite parent
#   UTILITY_TEXT  a literal in a utility statement, which pg_stat_statements
#                 records verbatim rather than normalizing to $1
#
# None appears in an identifier, a default, or a comment, so a value found in
# the bundle got there through the statistics and not through schema.sql.
PLANTED = {
    "REGION_CODE": "planted-region-6b1d4f9c",
    "EMAIL_DOMAIN": "planted-mail-2a7e83d5.invalid",
    "TENANT_LABEL": "planted-tenant-c94f10ab",
    "UTILITY_TEXT": "planted-utility-77e2b3da",
}

BUNDLE_ENTRIES = frozenset({
    "manifest.json",
    "schema.sql",
    "schema_by_table.sql",
    "profile.json",
    "observations/pg_class.csv",
    "observations/pg_index.csv",
    "observations/pg_sequence.csv",
    "observations/pg_stats.csv",
    "observations/pg_stats_ext.csv",
    "observations/foreign_keys.csv",
    "observations/pg_stat_indexes.csv",
    "observations/pg_stat_tables.csv",
    "observations/pg_stat_statements.csv",
})

ROWS_CUSTOMERS = 500
ROWS_ORDERS = 5000

# Every relation create_fixtures() leaves behind, as the collectors name them.
# Kept in one place because four assertions compare against the whole set, and
# adding a fixture without updating all four is otherwise an easy miss.
FIXTURE_TABLES = frozenset({
    "regions", "tenants", "customers", "orders", "exotic", "receipts",
    "reservations", "maintenance_windows", "audit_full", "audit_nothing",
    "audit_indexed", "customer_order_totals",
})

# How orders are spread over customers, chosen so the fan-out estimate has an
# exactly predictable right answer rather than one this test has to guess.
#
# Every HOT_EVERY'th order goes to one of HOT_CUSTOMERS ids starting at
# FIRST_HOT_CUSTOMER; the rest spread evenly over customers 1..UNIFORM_CUSTOMERS.
# HOT_EVERY is coprime with UNIFORM_CUSTOMERS, so carving the hot rows out does
# not knock any id out of the even spread: every one of the
# UNIFORM_CUSTOMERS + HOT_CUSTOMERS ids below is referenced, and no other is.
UNIFORM_CUSTOMERS = 400
HOT_CUSTOMERS = 5
FIRST_HOT_CUSTOMER = 401
HOT_EVERY = 7
REFERENCED_CUSTOMERS = UNIFORM_CUSTOMERS + HOT_CUSTOMERS

# One hot id: it is one of the five most common values of orders.customer_id,
# so it is certain to reach the published most-common-values list.
HOT_CUSTOMER = str(FIRST_HOT_CUSTOMER)

# Distinct (org_id, site_id) pairs the orders carry. Fewer than the five site
# ids times the two org ids, because the two columns are correlated -- which is
# what makes multiplying their distinct counts the wrong answer, and extended
# statistics the right one.
COMPOSITE_PAIRS = 5

# Populated by setUpModule, torn down by tearDownModule. Module scope rather
# than setUpClass: the fixtures cost seconds to build, nothing below mutates
# the source, and per-class setup would rebuild them once per test class.
WORKDIR: Path | None = None
BUNDLES: dict[str, Path] = {}
RUNS: dict[str, subprocess.CompletedProcess] = {}


def fixture_env() -> dict[str, str]:
    """The libpq environment for the fixture psql calls.

    Built by the tool's own URL parser and its own environment builder, so this
    file cannot drift from the connection handling it exercises -- and so the
    URL becomes PG* variables here too, rather than a command line the process
    list would expose.
    """
    args = dbprofiler.build_parser().parse_args(["postgres", "--output", "unused.zip"])
    args.url = os.environ[TEST_URL_ENV_VAR]
    return dbprofiler.safe_env(dbprofiler.build_postgres_config(args, os.environ))


def execute(sql: str) -> str:
    """Run fixture SQL, returning unaligned tuple-only stdout.

    Raises with redacted stderr on failure: this runs against whatever server
    the operator pointed it at, and an assertion message is printed.
    """
    done = subprocess.run(
        [PSQL, "-X", "-w", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", sql],
        env=fixture_env(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if done.returncode != 0:
        raise AssertionError(
            "fixture SQL failed: " + dbprofiler.redact_error(done.stderr, fixture_env())
        )
    return done.stdout


def create_fixtures() -> None:
    """Build the disposable schema.

    Shapes chosen so every collector has something to find: ordinary tables of
    different widths, a spread of supported types, types with no CockroachDB
    equivalent, a unique index, an index nothing ever scans, a descending key
    with an INCLUDE payload, a partial index, an expression index, an identity
    column and the sequence behind it, a non-default collation, a raised
    statistics target, a clustered heap, a single-column foreign key, and a
    composite one with extended statistics behind it.

    A second group exists for the regrouped schema rendering rather than for
    the collectors: a materialized view with an index, plain and partial
    exclusion constraints, and all three explicit replica identities. pg_dump
    emits each through a different path, and each lands somewhere different
    in schema_by_table.sql.
    """
    execute(f"CREATE SCHEMA {SCHEMA}")

    execute(f"""
        CREATE TABLE {SCHEMA}.regions (
            id integer PRIMARY KEY,
            code text NOT NULL,
            name text
        );

        CREATE TABLE {SCHEMA}.tenants (
            org_id integer NOT NULL,
            site_id integer NOT NULL,
            label text,
            PRIMARY KEY (org_id, site_id)
        );

        CREATE TABLE {SCHEMA}.customers (
            id bigint PRIMARY KEY,
            region_id integer NOT NULL
                REFERENCES {SCHEMA}.regions (id) ON DELETE CASCADE ON UPDATE RESTRICT,
            email text NOT NULL,
            signed_up_on date,
            lifetime_value numeric(12, 2),
            is_active boolean NOT NULL,
            external_ref uuid,
            preferences jsonb,
            tags text[]
        );

        CREATE TABLE {SCHEMA}.orders (
            id bigint PRIMARY KEY,
            customer_id bigint NOT NULL REFERENCES {SCHEMA}.customers (id),
            org_id integer NOT NULL,
            site_id integer NOT NULL,
            placed_at timestamptz NOT NULL,
            total numeric(12, 2),
            CONSTRAINT orders_tenant_fkey FOREIGN KEY (org_id, site_id)
                REFERENCES {SCHEMA}.tenants (org_id, site_id)
        );
    """)

    # An identity column, an explicit collation and a column default, none of
    # which appear anywhere else. The identity brings its own sequence, which
    # is what pg_sequence.csv has to find.
    execute(f"""
        CREATE TABLE {SCHEMA}.receipts (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            order_id bigint NOT NULL,
            note text COLLATE "C",
            issued_on date DEFAULT CURRENT_DATE
        );
    """)

    # Types with no CockroachDB equivalent, kept in their own table so a
    # misclassification cannot disturb the shape assertions elsewhere. A range
    # and a domain: jsonb and text[] read like exotic types but both map
    # cleanly, so they would not exercise this path at all.
    execute(f"""
        CREATE DOMAIN {SCHEMA}.positive_int AS integer CHECK (VALUE > 0);
        CREATE TABLE {SCHEMA}.exotic (
            id integer PRIMARY KEY,
            during int4range,
            quantity {SCHEMA}.positive_int
        );
    """)

    execute(f"""
        CREATE UNIQUE INDEX customers_email_key ON {SCHEMA}.customers (email);
        CREATE INDEX orders_customer_id_idx ON {SCHEMA}.orders (customer_id);
        CREATE INDEX orders_placed_at_idx ON {SCHEMA}.orders (placed_at);
    """)

    # The index shapes a downstream generator cannot infer from a column list:
    # a descending key with nulls first and a payload that is stored but not
    # ordered on, a predicate that excludes most of the table, and a key that
    # is an expression rather than a column.
    execute(f"""
        CREATE INDEX orders_recent_first_idx
            ON {SCHEMA}.orders (placed_at DESC NULLS FIRST) INCLUDE (total);
        CREATE INDEX orders_large_idx
            ON {SCHEMA}.orders (customer_id) WHERE total > 400;
        CREATE INDEX customers_lower_email_idx
            ON {SCHEMA}.customers (lower(email));
    """)

    # A raised per-column target changes how many buckets ANALYZE builds, so a
    # consumer reproducing the distribution has to know it was not the default.
    execute(f"ALTER TABLE {SCHEMA}.orders ALTER COLUMN placed_at SET STATISTICS 250")

    # org_id and site_id are correlated, so multiplying the per-column distinct
    # estimates overshoots badly. This is what gives composite fan-out a real
    # multicolumn estimate to prefer over the product of two independent ones.
    execute(f"""
        CREATE STATISTICS {SCHEMA}.orders_tenant_stats (ndistinct, mcv)
            ON org_id, site_id FROM {SCHEMA}.orders
    """)

    # Exclusion constraints, plain and partial. Both are CONSTRAINT entries
    # that carry their own index, so they must sort with the primary key
    # rather than with the plain indexes. A range with && needs no extension;
    # a multi-column form would drag in btree_gist and a superuser.
    #
    # A declarative partition hierarchy is deliberately absent here.
    # require_supported_layout rejects a source that contains one, so a
    # partitioned table in this schema would fail the run before any
    # assertion. The regrouping of partitioned DDL is covered against a
    # recorded dump in test_dbprofiler.py instead, where the renderer can be
    # exercised without the profiler having to reach the database.
    execute(f"""
        CREATE TABLE {SCHEMA}.reservations (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            during tstzrange NOT NULL,
            EXCLUDE USING gist (during WITH &&)
        );

        CREATE TABLE {SCHEMA}.maintenance_windows (
            id integer PRIMARY KEY,
            during tstzrange NOT NULL,
            cancelled boolean NOT NULL DEFAULT false,
            CONSTRAINT maintenance_windows_no_overlap
                EXCLUDE USING gist (during WITH &&) WHERE (NOT cancelled)
        );
    """)

    # A materialized view and an index on it. It reads like a table to
    # pg_class and like a view to pg_dump, which is the combination most
    # likely to strand its index in the wrong section.
    execute(f"""
        CREATE MATERIALIZED VIEW {SCHEMA}.customer_order_totals AS
            SELECT c.id AS customer_id,
                   count(o.id) AS order_count,
                   sum(o.total) AS total_value
            FROM {SCHEMA}.customers c
            LEFT JOIN {SCHEMA}.orders o ON o.customer_id = c.id
            GROUP BY c.id
            WITH NO DATA;

        CREATE UNIQUE INDEX customer_order_totals_pk
            ON {SCHEMA}.customer_order_totals (customer_id);
    """)

    # The three explicit replica identities. DEFAULT is left implicit
    # everywhere else and emits nothing, which is its own case. Only the
    # USING INDEX form names an index, and that ALTER has to stay beside it.
    execute(f"""
        CREATE TABLE {SCHEMA}.audit_full (
            id integer PRIMARY KEY,
            payload text
        );
        ALTER TABLE {SCHEMA}.audit_full REPLICA IDENTITY FULL;

        CREATE TABLE {SCHEMA}.audit_nothing (
            id integer PRIMARY KEY,
            payload text
        );
        ALTER TABLE {SCHEMA}.audit_nothing REPLICA IDENTITY NOTHING;

        CREATE TABLE {SCHEMA}.audit_indexed (
            id integer PRIMARY KEY,
            tracking_code text NOT NULL,
            payload text
        );
        CREATE UNIQUE INDEX audit_indexed_replica_idx
            ON {SCHEMA}.audit_indexed (tracking_code);
        ALTER TABLE {SCHEMA}.audit_indexed
            REPLICA IDENTITY USING INDEX audit_indexed_replica_idx;
    """)


def seed_fixtures() -> None:
    """Insert synthetic rows, then let PostgreSQL compute statistics over them."""
    execute(f"""
        INSERT INTO {SCHEMA}.regions (id, code, name)
        SELECT g, '{PLANTED["REGION_CODE"]}-' || g, 'region ' || g
        FROM generate_series(1, 5) AS g;

        INSERT INTO {SCHEMA}.tenants (org_id, site_id, label)
        SELECT o, s, '{PLANTED["TENANT_LABEL"]}-' || o || '-' || s
        FROM generate_series(1, 2) AS o, generate_series(1, 5) AS s;
    """)

    # Deliberately skewed: half the customers land in region 1, so the
    # frequency list has something to say and the migration plan can see the
    # hot range coming. A uniform distribution would make the assertion
    # meaningless.
    execute(f"""
        INSERT INTO {SCHEMA}.customers
            (id, region_id, email, signed_up_on, lifetime_value, is_active,
             external_ref, preferences, tags)
        SELECT g,
               CASE WHEN g % 2 = 0 THEN 1 ELSE 2 + (g % 4) END,
               'user' || g || '@{PLANTED["EMAIL_DOMAIN"]}',
               DATE '2024-01-01' + (g % 365),
               (g % 900)::numeric + 0.25,
               (g % 7) <> 0,
               gen_random_uuid(),
               jsonb_build_object('tier', g % 3),
               ARRAY['tag' || (g % 5)]
        FROM generate_series(1, {ROWS_CUSTOMERS}) AS g;

        INSERT INTO {SCHEMA}.orders
            (id, customer_id, org_id, site_id, placed_at, total)
        SELECT g,
               CASE WHEN g % {HOT_EVERY} = 0
                    THEN {FIRST_HOT_CUSTOMER} + (g % {HOT_CUSTOMERS})
                    ELSE 1 + (g % {UNIFORM_CUSTOMERS}) END,
               1 + ((g % 5) % 2),
               1 + (g % 5),
               TIMESTAMPTZ '2025-01-01 00:00:00+00' + (g || ' minutes')::interval,
               (g % 500)::numeric + 0.50
        FROM generate_series(1, {ROWS_ORDERS}) AS g;

        INSERT INTO {SCHEMA}.exotic (id, during, quantity)
        SELECT g, int4range(g, g + 10), g
        FROM generate_series(1, 50) AS g;

        INSERT INTO {SCHEMA}.receipts (order_id, note)
        SELECT g, 'note ' || g
        FROM generate_series(1, 100) AS g;
    """)

    # Rows for the shapes added for the schema rendering. The reservation
    # windows are disjoint so the exclusion constraints admit them.
    execute(f"""
        INSERT INTO {SCHEMA}.reservations (during)
        SELECT tstzrange(TIMESTAMPTZ '2026-01-01 00:00:00+00' + (g || ' days')::interval,
                         TIMESTAMPTZ '2026-01-01 00:00:00+00' + (g || ' days')::interval
                             + INTERVAL '12 hours')
        FROM generate_series(1, 40) AS g;

        INSERT INTO {SCHEMA}.maintenance_windows (id, during, cancelled)
        SELECT g,
               tstzrange(TIMESTAMPTZ '2026-03-01 00:00:00+00' + (g || ' days')::interval,
                         TIMESTAMPTZ '2026-03-01 00:00:00+00' + (g || ' days')::interval
                             + INTERVAL '6 hours'),
               false
        FROM generate_series(1, 30) AS g;

        INSERT INTO {SCHEMA}.audit_full (id, payload)
        SELECT g, 'payload ' || g FROM generate_series(1, 25) AS g;

        INSERT INTO {SCHEMA}.audit_nothing (id, payload)
        SELECT g, 'payload ' || g FROM generate_series(1, 25) AS g;

        INSERT INTO {SCHEMA}.audit_indexed (id, tracking_code, payload)
        SELECT g, 'track-' || g, 'payload ' || g FROM generate_series(1, 25) AS g;
    """)

    # The view was created WITH NO DATA so it could be built before the rows
    # existed. Populate it now, so pg_class reports a real heap for it.
    execute(f"REFRESH MATERIALIZED VIEW {SCHEMA}.customer_order_totals")

    # Sort the heap so pg_stats.correlation over customers.id comes back at 1
    # and says so. Without it the number would be an accident of insertion
    # order, which is exactly what the statistic is supposed to distinguish.
    execute(f"CLUSTER {SCHEMA}.customers USING customers_pkey")

    # The one ANALYZE in this repository, against the fixtures created above.
    # The profiler reads statistics rather than computing them; without this
    # there would be none to read and every distribution assertion below would
    # pass vacuously against nulls.
    execute(f"""
        ANALYZE {SCHEMA}.regions, {SCHEMA}.tenants, {SCHEMA}.customers,
                {SCHEMA}.orders, {SCHEMA}.exotic, {SCHEMA}.receipts,
                {SCHEMA}.reservations, {SCHEMA}.maintenance_windows,
                {SCHEMA}.audit_full, {SCHEMA}.audit_nothing,
                {SCHEMA}.audit_indexed, {SCHEMA}.customer_order_totals
    """)


def seed_activity() -> None:
    """Give the statistics views something to report.

    orders_placed_at_idx is deliberately never scanned: an index with
    idx_scan = 0 that backs no constraint is exactly the drop candidate the
    index CSV exists to surface, and the bundle has to be able to say so.
    """
    for _ in range(3):
        execute(f"""
            SELECT max(id) FROM {SCHEMA}.orders WHERE customer_id = 42;
            SELECT sum(total) FROM {SCHEMA}.orders WHERE org_id = 1 AND site_id = 2;
            SELECT c.id FROM {SCHEMA}.customers c
                JOIN {SCHEMA}.regions r ON r.id = c.region_id
                WHERE c.is_active LIMIT 10;
            SELECT id FROM {SCHEMA}.regions;
        """)

    # A utility statement. pg_stat_statements stores these verbatim instead of
    # normalizing their literals to $1, which puts a raw planted string into
    # the view the profiler is about to read.
    execute(f"DO $$ BEGIN PERFORM '{PLANTED['UTILITY_TEXT']}'; END $$")


def drop_fixtures() -> None:
    """Drop the disposable schema and nothing else.

    The name is checked here as well as generated above. This is the one
    statement in the repository that destroys anything, it runs against
    whatever server the operator configured, and a CASCADE aimed at the wrong
    schema is not recoverable -- so it does not rely on a constant twenty lines
    away still saying what it said when this was written.
    """
    if not SCHEMA.startswith("dbprofiler_it_"):
        raise AssertionError("refusing to drop a schema that is not a fixture schema")
    execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")


def run_profiler(output: Path) -> subprocess.CompletedProcess:
    """Run the shipped script the way a customer does: as a subprocess, with
    the connection string supplied only through the environment."""
    env = dict(os.environ)
    env[dbprofiler.URL_ENV_VAR] = os.environ[TEST_URL_ENV_VAR]
    env.pop(TEST_URL_ENV_VAR, None)
    return subprocess.run(
        [sys.executable, str(SCRIPT), "postgres",
         "--output", str(output), "--schema-include", SCHEMA],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=600,
    )


def setUpModule():
    """Build the fixtures and run the profiler twice, once."""
    global WORKDIR
    if not CONFIGURED:
        return

    WORKDIR = Path(tempfile.mkdtemp(prefix="dbprofiler-it-"))
    created = False
    try:
        create_fixtures()
        created = True
        seed_fixtures()
        seed_activity()
        for name in ("first", "again"):
            output = WORKDIR / f"{name}.zip"
            done = run_profiler(output)
            if done.returncode != 0:
                raise AssertionError(
                    f"profiler exited {done.returncode}: "
                    + dbprofiler.redact_error(done.stderr, fixture_env())
                )
            BUNDLES[name] = output
            RUNS[name] = done
    except BaseException:
        # Including KeyboardInterrupt: leaving a schema behind on a shared
        # server is worse than a slow exit.
        if created:
            drop_fixtures()
        shutil.rmtree(WORKDIR, ignore_errors=True)
        raise


def tearDownModule():
    if not CONFIGURED:
        return
    try:
        drop_fixtures()
    finally:
        shutil.rmtree(WORKDIR, ignore_errors=True)


def read_rows(archive: zipfile.ZipFile, path: str) -> list[dict]:
    """One dict per data row of a bundle CSV, keyed by its header."""
    return list(csv.DictReader(io.StringIO(archive.read(path).decode("utf-8"))))


def bundle_bytes(path: Path) -> bytes:
    """The archive as stored, plus every member decompressed.

    A planted literal inside a DEFLATE stream does not appear in the file's
    bytes, so searching the raw file alone would pass while the value sat in
    the bundle.
    """
    raw = path.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = b"".join(archive.read(name) for name in archive.namelist())
    return raw + members


@unittest.skipUnless(CONFIGURED, WHY_SKIPPED)
class IntegrationCase(unittest.TestCase):
    """Shared accessors over the first of the two bundles."""

    def setUp(self):
        self.archive = zipfile.ZipFile(BUNDLES["first"])
        self.addCleanup(self.archive.close)
        self.manifest = json.loads(self.archive.read("manifest.json"))
        self.profile = json.loads(self.archive.read("profile.json"))

    def table(self, name: str) -> dict:
        for table in self.profile["tables"]:
            if table["schema"] == SCHEMA and table["name"] == name:
                return table
        raise AssertionError(f"{name} missing from profile.json")

    def column(self, table: str, name: str) -> dict:
        for column in self.table(table)["columns"]:
            if column["name"] == name:
                return column
        raise AssertionError(f"{table}.{name} missing from profile.json")

    def relationship(self, constraint: str) -> dict:
        for rel in self.profile["relationships"]:
            if rel["constraint_name"] == constraint:
                return rel
        raise AssertionError(f"{constraint} missing from profile.json")


class TestBundleStructure(IntegrationCase):
    def test_every_entry_is_present(self):
        self.assertEqual(set(self.archive.namelist()), set(BUNDLE_ENTRIES))

    def test_stdout_is_the_bundle_path_and_nothing_else(self):
        printed = Path(RUNS["first"].stdout.strip())
        self.assertEqual(printed.resolve(), BUNDLES["first"].resolve())

    def test_progress_went_to_stderr(self):
        self.assertIn("publishing the bundle", RUNS["first"].stderr)

    def test_the_json_payloads_parse(self):
        self.assertEqual(self.profile["contract_version"], self.manifest["contract_version"])
        self.assertEqual(self.manifest["tool"], "dbprofiler")

    def test_every_checksum_verifies(self):
        recorded = {entry["path"]: entry for entry in self.manifest["payloads"]}
        self.assertEqual(set(recorded), set(BUNDLE_ENTRIES) - {"manifest.json"})
        for path, entry in recorded.items():
            with self.subTest(path=path):
                self.assertEqual(
                    hashlib.sha256(self.archive.read(path)).hexdigest(), entry["sha256"]
                )

    def test_the_source_is_postgres_16(self):
        source = self.manifest["source"]
        self.assertEqual(source["kind"], "postgres")
        self.assertGreaterEqual(source["server_version_num"], 160000)
        self.assertLess(source["server_version_num"], 170000)
        self.assertEqual(source["collected_schemas"], [SCHEMA])

    def test_the_run_produced_no_warnings(self):
        """Against a server configured as docs/TESTING.md describes, every
        statistics source is readable. A warning here means the environment
        drifted -- degradation itself has unit coverage."""
        self.assertEqual(self.manifest["warnings"], [])
        self.assertEqual(self.profile["warnings"], [])

    def test_stats_reset_was_captured(self):
        self.assertTrue(self.manifest["stats_reset"])

    def test_the_schema_fingerprint_is_recorded(self):
        self.assertRegex(self.manifest["schema_fingerprint"], r"\A[0-9a-f]{64}\Z")


class TestScope(IntegrationCase):
    def test_only_the_disposable_schema_was_collected(self):
        self.assertEqual({table["schema"] for table in self.profile["tables"]}, {SCHEMA})

    def test_the_schema_sql_covers_the_fixtures(self):
        schema_sql = self.archive.read("schema.sql").decode("utf-8")
        for name in sorted(FIXTURE_TABLES):
            with self.subTest(name=name):
                self.assertIn(f"{SCHEMA}.{name}", schema_sql)

    def test_the_schema_sql_carries_no_owner_or_grant(self):
        schema_sql = self.archive.read("schema.sql").decode("utf-8")
        self.assertNotIn("OWNER TO", schema_sql)
        self.assertNotIn("GRANT ", schema_sql)


class TestRegroupedSchema(IntegrationCase):
    """schema_by_table.sql, against DDL a live PostgreSQL really emitted.

    The renderer has unit coverage over recorded dumps. What only a live
    server can show is that pg_dump still emits the shapes those goldens were
    recorded from, in the form the renderer expects.
    """

    def regrouped(self):
        return self.archive.read("schema_by_table.sql").decode("utf-8")

    def block(self, table):
        """The regrouped section for one fixture table."""
        text = self.regrouped()
        banners = [m.start() for m in re.finditer(r"(?m)^-- =+ (?:TABLE|SECTION): ", text)]
        start = text.index(f"TABLE: {SCHEMA}.{table} ")
        opens = max(position for position in banners if position <= start)
        later = [position for position in banners if position > start]
        return text[opens: later[0] if later else len(text)]

    def test_it_carries_exactly_the_sql_of_the_flat_dump(self):
        """Regrouping moves statements; it must never add or drop one."""
        def statements(payload):
            text = self.archive.read(payload).decode("utf-8")
            return collections.Counter(
                " ".join(line.split())
                for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith("--")
            )

        self.assertEqual(statements("schema.sql"), statements("schema_by_table.sql"))

    def test_every_fixture_table_gets_a_block(self):
        text = self.regrouped()
        for name in sorted(FIXTURE_TABLES - {"customer_order_totals"}):
            with self.subTest(name=name):
                self.assertIn(f"TABLE: {SCHEMA}.{name} ", text)

    def test_an_exclusion_constraint_sorts_with_the_primary_key(self):
        """It is a CONSTRAINT carrying its own index, so it belongs with the
        key inside the table's own block rather than stranded cross-table."""
        text = self.regrouped()
        cross_table = text.index("SECTION: CROSS-TABLE OBJECTS")
        for table, constraint in (
            ("reservations", "reservations_during_excl"),
            ("maintenance_windows", "maintenance_windows_no_overlap"),
        ):
            with self.subTest(table=table):
                body = self.block(table)
                self.assertIn(f"ADD CONSTRAINT {constraint} EXCLUDE USING gist", body)
                self.assertLess(body.index("CREATE TABLE"), body.index("ADD CONSTRAINT"))
                self.assertLess(text.index(f"ADD CONSTRAINT {constraint}"), cross_table)

    def test_a_partial_exclusion_constraint_keeps_its_predicate(self):
        self.assertIn(
            "EXCLUDE USING gist (during WITH &&) WHERE ((NOT cancelled))",
            self.block("maintenance_windows"),
        )

    def test_replica_identity_full_and_nothing_stay_with_their_table(self):
        for table, clause in (("audit_full", "FULL"), ("audit_nothing", "NOTHING")):
            with self.subTest(table=table):
                body = self.block(table)
                self.assertIn(f"REPLICA IDENTITY {clause};", body)
                self.assertLess(body.index("CREATE TABLE"), body.index("REPLICA IDENTITY"))

    def test_replica_identity_using_index_follows_the_index_it_names(self):
        """The one form that names another object. Separating the two would
        leave an ALTER referring to an index that does not exist yet."""
        body = self.block("audit_indexed")
        index = body.index("CREATE UNIQUE INDEX audit_indexed_replica_idx")
        alter = body.index("REPLICA IDENTITY USING INDEX audit_indexed_replica_idx")
        self.assertLess(index, alter)
        between = body[body.index(";", index) + 1: alter]
        self.assertEqual(between.strip(), "ALTER TABLE ONLY " + SCHEMA + ".audit_indexed")

    def test_a_table_left_on_the_default_replica_identity_says_nothing(self):
        self.assertNotIn("REPLICA IDENTITY", self.block("customers"))

    def test_the_materialized_view_and_its_index_are_cross_table(self):
        """A materialized view reads like a table to pg_class and like a view
        to pg_dump. It has no table block, so both it and its index belong in
        the section that replays last."""
        text = self.regrouped()
        cross_table = text.index("SECTION: CROSS-TABLE OBJECTS")
        view = text.index(f"CREATE MATERIALIZED VIEW {SCHEMA}.customer_order_totals")
        index = text.index("CREATE UNIQUE INDEX customer_order_totals_pk")
        self.assertGreater(view, cross_table)
        self.assertGreater(index, view)


class TestShape(IntegrationCase):
    def test_every_fixture_table_is_reported(self):
        found = {table["name"] for table in self.profile["tables"]}
        self.assertEqual(found, set(FIXTURE_TABLES))

    def test_row_counts_are_estimates_of_the_right_magnitude(self):
        """reltuples after ANALYZE, not a COUNT(*): close, but never promised
        exact, so this asserts the magnitude rather than equality."""
        self.assertAlmostEqual(
            self.table("orders")["row_count_estimate"], ROWS_ORDERS, delta=ROWS_ORDERS * 0.05
        )
        self.assertAlmostEqual(
            self.table("customers")["row_count_estimate"],
            ROWS_CUSTOMERS,
            delta=ROWS_CUSTOMERS * 0.05,
        )

    def test_tables_have_a_size(self):
        self.assertGreater(self.table("orders")["size_bytes"], 0)

    def test_columns_are_reported_in_declaration_order(self):
        columns = self.table("orders")["columns"]
        self.assertEqual(
            [column["name"] for column in columns],
            ["id", "customer_id", "org_id", "site_id", "placed_at", "total"],
        )
        ordinals = [column["ordinal"] for column in columns]
        self.assertEqual(ordinals, sorted(ordinals))

    def test_declared_types_survive(self):
        """format_type output, as an operator would write the declaration --
        including the modifier, which decides whether a numeric fits."""
        self.assertEqual(
            self.column("orders", "placed_at")["data_type"], "timestamp with time zone"
        )
        self.assertEqual(self.column("customers", "lifetime_value")["data_type"], "numeric(12,2)")
        self.assertEqual(self.column("customers", "external_ref")["data_type"], "uuid")
        self.assertEqual(self.column("customers", "tags")["data_type"], "text[]")

    def test_nullability_is_reported(self):
        self.assertFalse(self.column("customers", "email")["is_nullable"])
        self.assertTrue(self.column("customers", "signed_up_on")["is_nullable"])

    def test_supported_types_are_marked_supported(self):
        for table, column in (
            ("customers", "email"), ("customers", "preferences"),
            ("customers", "tags"), ("customers", "external_ref"),
            ("orders", "placed_at"),
        ):
            with self.subTest(column=f"{table}.{column}"):
                self.assertTrue(self.column(table, column)["is_supported"])

    def test_types_without_an_equivalent_are_marked_unsupported(self):
        self.assertFalse(self.column("exotic", "during")["is_supported"])
        self.assertFalse(self.column("exotic", "quantity")["is_supported"])

    def test_statistics_reached_the_profile(self):
        region_id = self.column("customers", "region_id")
        self.assertIsNotNone(region_id["distinct_estimate"])
        self.assertGreater(region_id["distinct_estimate"], 1)
        self.assertEqual(self.column("customers", "email")["null_fraction"], 0.0)
        self.assertGreater(self.column("customers", "email")["avg_width_bytes"], 0)

    def test_skew_is_visible(self):
        """Half the customers are in region 1, and the frequency list has to
        show it."""
        freqs = self.column("customers", "region_id")["most_common_freqs"]
        self.assertTrue(freqs)
        self.assertGreater(max(freqs), 0.4)

    def test_the_table_csv_matches_the_profile(self):
        rows = {row["table"]: row for row in read_rows(
            self.archive, "observations/pg_class.csv"
        )}
        self.assertEqual(set(rows), set(FIXTURE_TABLES))
        self.assertEqual(int(rows["orders"]["column_count"]), 6)


class TestRelationships(IntegrationCase):
    def test_the_single_column_foreign_key_is_reported(self):
        rel = self.relationship("orders_customer_id_fkey")
        self.assertEqual(rel["child_columns"], ["customer_id"])
        self.assertEqual(rel["parent_table"], "customers")
        self.assertEqual(rel["parent_columns"], ["id"])

    def test_referential_actions_survive(self):
        rel = self.relationship("customers_region_id_fkey")
        self.assertEqual(rel["on_delete"], "CASCADE")
        self.assertEqual(rel["on_update"], "RESTRICT")

    def test_the_composite_foreign_key_keeps_its_column_order(self):
        rel = self.relationship("orders_tenant_fkey")
        self.assertEqual(rel["child_columns"], ["org_id", "site_id"])
        self.assertEqual(rel["parent_columns"], ["org_id", "site_id"])

    def test_single_column_fan_out_is_estimated(self):
        """Children per *referenced* parent -- 405 of the 500 customers have an
        order -- so the answer is not orders over customers. The seed makes the
        referenced count exact, and the estimate has to land on it."""
        fan_out = self.relationship("orders_customer_id_fkey")["fan_out"]
        self.assertEqual(fan_out["status"], "estimated")
        self.assertEqual(fan_out["basis"], "single_column")
        self.assertAlmostEqual(fan_out["mean"], ROWS_ORDERS / REFERENCED_CUSTOMERS, delta=1)

    def test_the_hot_customers_lift_the_tail_above_the_mean(self):
        """Five customers take one order in seven between them. If p99 came
        back at the mean, the estimate would be describing a uniform
        distribution that is not there, and the migration would be sized for a
        workload nobody runs."""
        fan_out = self.relationship("orders_customer_id_fkey")["fan_out"]
        expected = ROWS_ORDERS / HOT_EVERY / HOT_CUSTOMERS
        self.assertGreater(fan_out["p99"], fan_out["mean"])
        self.assertAlmostEqual(fan_out["p99"], expected, delta=expected * 0.2)

    def test_composite_fan_out_is_estimated_from_extended_statistics(self):
        """org_id and site_id are correlated: two orgs and five sites, but only
        five pairs. Multiplying the per-column distinct counts would say ten and
        halve the fan-out; reading the multicolumn statistics says five."""
        fan_out = self.relationship("orders_tenant_fkey")["fan_out"]
        self.assertEqual(fan_out["status"], "estimated")
        self.assertEqual(fan_out["basis"], "extended_statistics")
        self.assertAlmostEqual(
            fan_out["mean"], ROWS_ORDERS / COMPOSITE_PAIRS, delta=ROWS_ORDERS * 0.02
        )

    def test_the_foreign_key_csv_matches_the_profile(self):
        rows = {row["constraint_name"]: row for row in read_rows(
            self.archive, "observations/foreign_keys.csv"
        )}
        self.assertEqual(
            set(rows),
            {"customers_region_id_fkey", "orders_customer_id_fkey", "orders_tenant_fkey"},
        )
        self.assertEqual(rows["orders_tenant_fkey"]["child_columns"], "org_id|site_id")

    def test_the_extended_statistics_were_read(self):
        rows = [row for row in read_rows(self.archive, "observations/pg_stats_ext.csv")
                if row["statistics_name"] == "orders_tenant_stats"]
        self.assertTrue(rows, "expected the multicolumn statistics object")
        self.assertTrue(any(row["distinct_estimate"] for row in rows))

    def test_extended_most_common_values_are_published(self):
        """The MCV list over (org_id, site_id) is the dependence itself: the
        observed frequency of a pair against the frequency independence would
        have predicted. An n-distinct count alone cannot say which pairs are
        hot, only how many there are."""
        rows = [row for row in read_rows(self.archive, "observations/pg_stats_ext.csv")
                if row["statistics_name"] == "orders_tenant_stats"]
        self.assertTrue(all(row["most_common_values"] for row in rows))
        self.assertTrue(all(row["most_common_freqs"] for row in rows))
        self.assertTrue(all(row["most_common_base_freqs"] for row in rows))


class TestTier1Telemetry(IntegrationCase):
    def table_activity(self):
        return {row["table"]: row for row in read_rows(
            self.archive, "observations/pg_stat_tables.csv"
        )}

    def index_activity(self):
        return {row["index"]: row for row in read_rows(
            self.archive, "observations/pg_stat_indexes.csv"
        )}

    def test_table_activity_is_populated(self):
        rows = self.table_activity()
        self.assertEqual(set(rows), set(FIXTURE_TABLES))
        self.assertEqual(int(rows["orders"]["n_tup_ins"]), ROWS_ORDERS)
        self.assertTrue(rows["orders"]["last_analyze"])

    def test_index_activity_is_joined_with_the_catalog(self):
        rows = self.index_activity()
        self.assertEqual(rows["orders_pkey"]["is_primary"], "true")
        self.assertEqual(rows["customers_email_key"]["is_unique"], "true")
        self.assertEqual(rows["customers_email_key"]["is_primary"], "false")
        self.assertEqual(rows["orders_customer_id_idx"]["is_unique"], "false")

    def test_an_unscanned_index_is_visible_as_a_drop_candidate(self):
        rows = self.index_activity()
        self.assertEqual(int(rows["orders_placed_at_idx"]["idx_scan"]), 0)
        self.assertEqual(rows["orders_placed_at_idx"]["is_primary"], "false")
        self.assertEqual(rows["orders_placed_at_idx"]["is_unique"], "false")

    def test_statements_are_populated(self):
        rows = read_rows(self.archive, "observations/pg_stat_statements.csv")
        self.assertTrue(rows)
        self.assertTrue(all(row["queryid"] for row in rows))
        self.assertTrue(any(int(row["calls"]) >= 3 for row in rows))

    def test_every_statement_carries_the_text_postgresql_normalized(self):
        rows = read_rows(self.archive, "observations/pg_stat_statements.csv")
        self.assertTrue(all(row["query_text"] for row in rows))
        self.assertTrue(any("$1" in row["query_text"] for row in rows))

    def test_each_queryid_appears_once(self):
        ids = [row["queryid"] for row in read_rows(
            self.archive, "observations/pg_stat_statements.csv"
        )]
        self.assertEqual(len(ids), len(set(ids)))


class TestPublishedStatistics(IntegrationCase):
    """The values themselves, and the properties a generator replays from them."""

    @staticmethod
    def stats_map(path: Path) -> dict:
        with zipfile.ZipFile(path) as archive:
            return {
                (row["schema"], row["table"], row["column"]): row
                for row in read_rows(archive, "observations/pg_stats.csv")
            }

    def test_a_column_with_skew_publishes_its_most_common_values(self):
        region_id = self.column("customers", "region_id")
        self.assertTrue(region_id["most_common_values"])
        self.assertIn("1", region_id["most_common_values"])

    def test_values_and_frequencies_stay_positionally_paired(self):
        column = self.column("customers", "region_id")
        self.assertEqual(len(column["most_common_values"]), len(column["most_common_freqs"]))

    def test_a_high_cardinality_column_publishes_an_ascending_histogram(self):
        """The spacing between bounds is the distribution. A consumer that
        cannot rely on the order cannot reproduce a range scan."""
        bounds = self.column("orders", "id")["histogram_bounds"]
        self.assertTrue(bounds)
        self.assertEqual([int(bound) for bound in bounds],
                         sorted(int(bound) for bound in bounds))

    def test_a_text_histogram_is_ordered_under_the_database_collation(self):
        bounds = self.column("customers", "email")["histogram_bounds"]
        self.assertTrue(bounds)
        self.assertEqual(bounds, sorted(bounds))

    def test_the_database_collation_is_recorded_beside_the_bundle(self):
        """Text bounds are only sorted with respect to a collation, so the
        bundle has to say which one."""
        self.assertTrue(self.manifest["source"]["collate"])
        self.assertTrue(self.manifest["source"]["ctype"])

    def test_a_clustered_heap_reports_a_correlation_of_one(self):
        """CLUSTER sorted the heap on the primary key. If correlation came back
        near zero, a consumer would size the migration for random I/O on a
        table that reads sequentially."""
        self.assertAlmostEqual(self.column("customers", "id")["correlation"], 1.0, places=2)

    def test_an_alternating_column_has_a_correlation_well_below_one(self):
        # region_id alternates between 1 and a rotating value, so physical
        # order says nothing about logical order.
        self.assertLess(abs(self.column("customers", "region_id")["correlation"]), 0.9)

    def test_two_runs_of_one_source_publish_the_same_statistics(self):
        """A migration's before and after are only comparable if a run that
        changed nothing produces the same numbers."""
        self.assertEqual(self.stats_map(BUNDLES["first"]), self.stats_map(BUNDLES["again"]))

    def test_a_hot_parent_value_is_published_as_itself(self):
        """The five hot customer ids take one order in seven between them.
        Publishing the id is what lets a generator place the skew on the same
        key rather than on an arbitrary one."""
        self.assertIn(HOT_CUSTOMER, self.column("orders", "customer_id")["most_common_values"])

    def test_the_raised_statistics_target_is_reported(self):
        self.assertEqual(self.column("orders", "placed_at")["statistics_target"], 250)
        self.assertIsNone(self.column("orders", "total")["statistics_target"])


class TestColumnDeclarations(IntegrationCase):
    def test_an_identity_column_reports_its_kind(self):
        self.assertEqual(self.column("receipts", "id")["identity"], "always")
        self.assertIsNone(self.column("orders", "id")["identity"])

    def test_a_column_default_is_carried_as_its_expression(self):
        self.assertIn("CURRENT_DATE", self.column("receipts", "issued_on")["default_expression"])
        self.assertIsNone(self.column("receipts", "order_id")["default_expression"])

    def test_a_non_default_collation_is_reported(self):
        """A text column collated C sorts by byte. Recreating it under the
        database default would reorder every range scan over it."""
        self.assertEqual(self.column("receipts", "note")["collation"], "C")
        self.assertNotEqual(self.column("customers", "email")["collation"], "C")

    def test_a_table_reports_its_page_count_and_toast(self):
        customers = self.table("customers")
        self.assertGreater(customers["page_count"], 0)
        self.assertLessEqual(customers["page_count"] * 8192, customers["size_bytes"])
        self.assertTrue(customers["has_toast"])


class TestIndexShape(IntegrationCase):
    def indexes(self):
        rows = read_rows(self.archive, "observations/pg_index.csv")
        by_index = {}
        for row in rows:
            by_index.setdefault(row["index"], []).append(row)
        for keys in by_index.values():
            keys.sort(key=lambda row: int(row["position"]))
        return by_index

    def test_every_fixture_index_is_reported(self):
        self.assertEqual(
            set(self.indexes()),
            {
                "regions_pkey", "tenants_pkey", "customers_pkey", "orders_pkey",
                "exotic_pkey", "receipts_pkey", "customers_email_key",
                "orders_customer_id_idx", "orders_placed_at_idx",
                "orders_recent_first_idx", "orders_large_idx",
                "customers_lower_email_idx",
                # The shapes added for the schema rendering. The two
                # exclusion constraints appear here because each one is
                # backed by a gist index, which is what makes them sort
                # with the constraints rather than with the plain indexes.
                "reservations_pkey", "reservations_during_excl",
                "maintenance_windows_pkey", "maintenance_windows_no_overlap",
                "audit_full_pkey", "audit_nothing_pkey", "audit_indexed_pkey",
                "audit_indexed_replica_idx", "customer_order_totals_pk",
            },
        )

    def test_a_composite_key_keeps_its_declared_order(self):
        keys = self.indexes()["tenants_pkey"]
        self.assertEqual([row["column"] for row in keys], ["org_id", "site_id"])

    def test_a_descending_key_reports_its_direction_and_null_placement(self):
        """DESC NULLS FIRST is the index's whole reason for existing: it serves
        a newest-first scan without a sort. Recreated ascending it would not."""
        first = self.indexes()["orders_recent_first_idx"][0]
        self.assertEqual(first["column"], "placed_at")
        self.assertEqual(first["descending"], "true")
        self.assertEqual(first["nulls_first"], "true")

    def test_an_include_column_is_payload_and_not_a_key(self):
        keys = self.indexes()["orders_recent_first_idx"]
        self.assertEqual([row["column"] for row in keys], ["placed_at", "total"])
        self.assertEqual([row["is_key"] for row in keys], ["true", "false"])

    def test_a_partial_index_is_flagged(self):
        self.assertTrue(all(row["is_partial"] == "true"
                            for row in self.indexes()["orders_large_idx"]))
        self.assertTrue(all(row["is_partial"] == "false"
                            for row in self.indexes()["orders_pkey"]))

    def test_the_predicate_itself_is_in_the_schema_and_not_the_csv(self):
        schema_sql = self.archive.read("schema.sql").decode("utf-8")
        self.assertIn("orders_large_idx", schema_sql)
        self.assertIn("total > ", schema_sql)

    def test_an_expression_key_has_no_column_name(self):
        keys = self.indexes()["customers_lower_email_idx"]
        self.assertEqual(keys[0]["column"], "")
        self.assertEqual(keys[0]["has_expressions"], "true")

    def test_the_clustered_index_is_identified(self):
        self.assertTrue(all(row["is_clustered"] == "true"
                            for row in self.indexes()["customers_pkey"]))
        self.assertTrue(all(row["is_clustered"] == "false"
                            for row in self.indexes()["orders_pkey"]))

    def test_operator_classes_are_reported(self):
        self.assertEqual(self.indexes()["orders_pkey"][0]["operator_class"], "int8_ops")

    def test_uniqueness_and_primacy_come_from_the_catalog(self):
        self.assertEqual(self.indexes()["customers_email_key"][0]["is_unique"], "true")
        self.assertEqual(self.indexes()["customers_email_key"][0]["is_primary"], "false")
        self.assertEqual(self.indexes()["orders_pkey"][0]["is_primary"], "true")


class TestSequences(IntegrationCase):
    def sequences(self):
        return {row["sequence"]: row
                for row in read_rows(self.archive, "observations/pg_sequence.csv")}

    def test_the_identity_sequence_is_reported(self):
        """An identity column has no pg_attrdef row. Without the sequence, a
        consumer would have no way to know the column allocates keys at all."""
        self.assertIn("receipts_id_seq", self.sequences())

    def test_sequence_parameters_are_carried_through(self):
        sequence = self.sequences()["receipts_id_seq"]
        self.assertEqual(int(sequence["start"]), 1)
        self.assertEqual(int(sequence["increment"]), 1)
        self.assertEqual(sequence["cycles"], "false")

    def test_the_bigint_upper_bound_survives_exactly(self):
        """9223372036854775807 does not fit a float64. A bound that came back
        one larger would be a value the sequence can never reach."""
        self.assertEqual(int(self.sequences()["receipts_id_seq"]["maximum"]),
                         9223372036854775807)

    def test_the_current_value_is_not_read(self):
        """Reading it would mean selecting from the sequence itself, which is
        outside the catalog-only boundary and tells a migration plan nothing
        that the parameters do not."""
        self.assertNotIn("last_value", self.sequences()["receipts_id_seq"])


class TestWhatEscapes(IntegrationCase):
    """What the bundle carries out, and what it must not.

    The statistics are published as PostgreSQL computed them, so each planted
    value is expected to appear. The negative assertion is reserved for the
    credentials, which have no route into a bundle at all.
    """

    def test_every_planted_value_appears_in_the_bundle(self):
        """Each took a different route into the statistics, and the bundle
        carries all four. This is the posture the README documents: treat a
        bundle as holding a sample of the source data."""
        for name, value in PLANTED.items():
            with self.subTest(planted=name):
                self.assertIn(value.encode("utf-8"), bundle_bytes(BUNDLES["first"]))

    def test_the_plants_really_are_in_the_source(self):
        """Guards the test above. If a fixture silently failed to insert, every
        assertion of absence would pass for the wrong reason."""
        found = execute(f"""
            SELECT (SELECT count(*) FROM {SCHEMA}.regions
                    WHERE code LIKE '{PLANTED["REGION_CODE"]}%'),
                   (SELECT count(*) FROM {SCHEMA}.customers
                    WHERE email LIKE '%{PLANTED["EMAIL_DOMAIN"]}'),
                   (SELECT count(*) FROM {SCHEMA}.tenants
                    WHERE label LIKE '{PLANTED["TENANT_LABEL"]}%')
        """)
        self.assertEqual(
            [int(value) for value in found.strip().split("|")], [5, ROWS_CUSTOMERS, 10]
        )

    def test_the_utility_statement_really_is_in_pg_stat_statements(self):
        """The same guard, for the one plant that lives in a statistics view
        rather than in a table."""
        found = execute(
            "SELECT count(*) FROM pg_stat_statements "
            f"WHERE query LIKE '%{PLANTED['UTILITY_TEXT']}%'"
        )
        self.assertGreater(int(found.strip()), 0)

    def test_no_credential_appears_in_any_bundle(self):
        """The password is the credential, and it has no route into a bundle.

        PGUSER is deliberately not checked here. It is a name rather than a
        secret, and the bundle records identity on purpose -- source.database
        and source.kind are both published fields. Searching a bundle for a
        role name therefore reports a collision rather than a leak: a role
        named for its database matches source.database, and the far more
        likely `postgres` matches `"kind": "postgres"` in every bundle the
        tool can produce. stderr is a different matter, and
        test_no_credential_appears_on_stderr still covers the user there.
        """
        env = fixture_env()
        secret = env.get("PGPASSWORD")
        self.assertTrue(secret, "expected the test URL to carry a password")
        for label, path in BUNDLES.items():
            with self.subTest(bundle=label):
                self.assertNotIn(
                    secret.encode("utf-8"),
                    bundle_bytes(path),
                    f"the password reached the {label} bundle",
                )

    def test_no_credential_appears_on_stderr(self):
        env = fixture_env()
        for key in ("PGPASSWORD", "PGUSER", "PGHOST"):
            value = env.get(key)
            if value:
                for label, run in RUNS.items():
                    with self.subTest(variable=key, run=label):
                        self.assertNotIn(value, run.stderr)


if __name__ == "__main__":
    unittest.main()
