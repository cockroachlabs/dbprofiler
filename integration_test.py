# Copyright (c) 2026 Cockroach Labs, Inc.
# SPDX-License-Identifier: MIT
"""End-to-end integration test for dbprofiler.

Runs the shipped script, as a subprocess, against a real PostgreSQL 16, and
checks the bundle it produces. Skipped unless both DBPROFILER_POSTGRES_TEST_URL
and DBPROFILER_TOKEN_KEY are set, so a plain `python3 -m unittest` stays
offline. See docs/TESTING.md for the disposable server.

    python3 -m unittest integration_test -v

Neither variable's value is ever printed. The connection string reaches psql
and the profiler through the environment only, as it does in production, and
child-process stderr goes through dbprofiler.redact_error before it can reach
an assertion message.

This file issues DDL, DML, ANALYZE, and CREATE STATISTICS. Those are forbidden
to dbprofiler.py and enforced against it by --check-safety, which reflects over
that module's SQL_* constants; nothing here is reachable from the tool. They
are permitted here, and only here, because every object involved lives in a
schema this test creates under a name nobody else uses and drops on the way
out. The point of the exercise is to hand the profiler statistics PostgreSQL
computed, which means something has to compute them first.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
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

# Read as booleans. The values are never held in a module constant, never
# logged, and never quoted into a failure message.
CONFIGURED = bool(os.getenv(TEST_URL_ENV_VAR)) and bool(os.getenv(dbprofiler.TOKEN_KEY_ENV_VAR))
WHY_SKIPPED = f"set {TEST_URL_ENV_VAR} and {dbprofiler.TOKEN_KEY_ENV_VAR} to run"

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
# None appears in an identifier, a default, or a comment, so none can reach
# schema.sql by a route that has nothing to do with tokenization.
PLANTED = {
    "REGION_CODE": "planted-region-6b1d4f9c",
    "EMAIL_DOMAIN": "planted-mail-2a7e83d5.invalid",
    "TENANT_LABEL": "planted-tenant-c94f10ab",
    "UTILITY_TEXT": "planted-utility-77e2b3da",
}

BUNDLE_ENTRIES = frozenset({
    "manifest.json",
    "schema.sql",
    "profile.json",
    "observations/pg_class.csv",
    "observations/pg_stats.csv",
    "observations/pg_stats_ext.csv",
    "observations/foreign_keys.csv",
    "observations/pg_stat_indexes.csv",
    "observations/pg_stat_tables.csv",
    "observations/pg_stat_statements.csv",
})

# The synthetic keys fixed by .claude/rules/development.md, long enough to pass
# MIN_TOKEN_KEY_LENGTH. Two runs under KEY_A prove tokens are reproducible; one
# under KEY_B proves two bundles cannot be correlated.
KEY_A = "example-token-key-0123456789"
KEY_B = "example-token-key-9876543210"

ROWS_CUSTOMERS = 500
ROWS_ORDERS = 5000

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

# One hot id, for the token assertion: it is one of the five most common values
# of orders.customer_id, so it is certain to reach the most-common-token list.
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
    equivalent, a unique index, an index nothing ever scans, a single-column
    foreign key, and a composite one with extended statistics behind it.
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

    # org_id and site_id are correlated, so multiplying the per-column distinct
    # estimates overshoots badly. This is what gives composite fan-out a real
    # multicolumn estimate to prefer over the product of two independent ones.
    execute(f"""
        CREATE STATISTICS {SCHEMA}.orders_tenant_stats (ndistinct, mcv)
            ON org_id, site_id FROM {SCHEMA}.orders
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
    """)

    # The one ANALYZE in this repository, against the fixtures created above.
    # The profiler reads statistics rather than computing them; without this
    # there would be none to read and every distribution assertion below would
    # pass vacuously against nulls.
    execute(f"""
        ANALYZE {SCHEMA}.regions, {SCHEMA}.tenants, {SCHEMA}.customers,
                {SCHEMA}.orders, {SCHEMA}.exotic
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


def run_profiler(output: Path, token_key: str) -> subprocess.CompletedProcess:
    """Run the shipped script the way a customer does: as a subprocess, with
    the connection string and the key supplied only through the environment."""
    env = dict(os.environ)
    env[dbprofiler.URL_ENV_VAR] = os.environ[TEST_URL_ENV_VAR]
    env[dbprofiler.TOKEN_KEY_ENV_VAR] = token_key
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
    """Build the fixtures and run the profiler three times, once."""
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
        for name, key in (("first", KEY_A), ("again", KEY_A), ("other", KEY_B)):
            output = WORKDIR / f"{name}.zip"
            done = run_profiler(output, key)
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
    """Shared accessors over the bundle produced under KEY_A."""

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
        for name in ("regions", "tenants", "customers", "orders", "exotic"):
            with self.subTest(name=name):
                self.assertIn(f"{SCHEMA}.{name}", schema_sql)

    def test_the_schema_sql_carries_no_owner_or_grant(self):
        schema_sql = self.archive.read("schema.sql").decode("utf-8")
        self.assertNotIn("OWNER TO", schema_sql)
        self.assertNotIn("GRANT ", schema_sql)


class TestShape(IntegrationCase):
    def test_every_fixture_table_is_reported(self):
        found = {table["name"] for table in self.profile["tables"]}
        self.assertEqual(found, {"regions", "tenants", "customers", "orders", "exotic"})

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
        self.assertEqual(
            set(rows), {"regions", "tenants", "customers", "orders", "exotic"}
        )
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

    def test_extended_most_common_values_are_recorded_but_not_published(self):
        """The extended MCV list holds literals, so the bundle records only
        that it exists."""
        rows = read_rows(self.archive, "observations/pg_stats_ext.csv")
        mine = [row for row in rows if row["statistics_name"] == "orders_tenant_stats"]
        self.assertTrue(all(row["has_most_common_values"] == "true" for row in mine))
        self.assertNotIn("most_common_values", rows[0])


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
        self.assertEqual(set(rows), {"regions", "tenants", "customers", "orders", "exotic"})
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

    def test_every_statement_carries_a_token_instead_of_its_text(self):
        rows = read_rows(self.archive, "observations/pg_stat_statements.csv")
        self.assertNotIn("query", rows[0])
        self.assertNotIn("query_text", rows[0])
        self.assertTrue(all(row["query_token"] for row in rows))

    def test_each_queryid_appears_once(self):
        ids = [row["queryid"] for row in read_rows(
            self.archive, "observations/pg_stat_statements.csv"
        )]
        self.assertEqual(len(ids), len(set(ids)))


class TestTokens(IntegrationCase):
    """Tokens have to be stable enough to join on and useless without the key."""

    @staticmethod
    def token_map(path: Path) -> dict:
        with zipfile.ZipFile(path) as archive:
            return {
                (row["schema"], row["table"], row["column"]):
                    (row["most_common_tokens"], row["histogram_token_bounds"])
                for row in read_rows(archive, "observations/pg_stats.csv")
            }

    def test_a_column_with_skew_has_most_common_tokens(self):
        self.assertTrue(self.column("customers", "region_id")["most_common_tokens"])

    def test_a_high_cardinality_column_has_histogram_bounds(self):
        self.assertTrue(self.column("customers", "email")["histogram_token_bounds"])

    def test_tokens_and_frequencies_stay_aligned(self):
        column = self.column("customers", "region_id")
        self.assertEqual(len(column["most_common_tokens"]), len(column["most_common_freqs"]))

    def test_the_same_key_produces_the_same_tokens(self):
        """Two runs of one source must be comparable, or nobody can tell a
        migration's before from its after."""
        self.assertEqual(self.token_map(BUNDLES["first"]), self.token_map(BUNDLES["again"]))

    def test_a_different_key_produces_different_tokens(self):
        """Two engagements must not be correlatable."""
        mine = self.token_map(BUNDLES["first"])
        theirs = self.token_map(BUNDLES["other"])
        self.assertEqual(set(mine), set(theirs))
        shared = [key for key in mine if any(mine[key]) and mine[key] == theirs[key]]
        self.assertEqual(shared, [])

    def test_a_child_column_tokenizes_under_its_parents_domain(self):
        """The property the whole scheme exists for: equal values tokenize
        equally across a foreign key, so a join on the tokens is still a join.

        Asserted against a token computed here from the key rather than against
        an overlap between two lists, because an overlap could also be produced
        by tokenizing both sides under a domain that happens to match.
        """
        tokenizer = dbprofiler.Tokenizer(KEY_A.encode("utf-8"))
        parent_domain = dbprofiler.token_domain(SCHEMA, "customers", "id")
        expected = tokenizer.token(HOT_CUSTOMER, parent_domain, "int8")
        self.assertIn(expected, self.column("orders", "customer_id")["most_common_tokens"])

    def test_that_token_is_not_what_the_childs_own_domain_would_give(self):
        """Guards the test above: if the domains were wrong in the same way on
        both sides, the assertion there could still pass."""
        tokenizer = dbprofiler.Tokenizer(KEY_A.encode("utf-8"))
        child_domain = dbprofiler.token_domain(SCHEMA, "orders", "customer_id")
        wrong = tokenizer.token(HOT_CUSTOMER, child_domain, "int8")
        self.assertNotIn(wrong, self.column("orders", "customer_id")["most_common_tokens"])


class TestNothingRawEscapes(IntegrationCase):
    """The negative assertion. Each planted value took a different route into
    the statistics; none may reach the bytes on disk."""

    def test_no_planted_value_appears_in_any_bundle(self):
        for name, value in PLANTED.items():
            for label, path in BUNDLES.items():
                with self.subTest(planted=name, bundle=label):
                    self.assertNotIn(value.encode("utf-8"), bundle_bytes(path))

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
        env = fixture_env()
        secrets = [env[key] for key in ("PGPASSWORD", "PGUSER") if env.get(key)]
        self.assertTrue(secrets, "expected the test URL to carry a user")
        for label, path in BUNDLES.items():
            payload = bundle_bytes(path)
            for secret in secrets:
                with self.subTest(bundle=label):
                    self.assertNotIn(secret.encode("utf-8"), payload)

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
