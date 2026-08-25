# dbprofiler MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `dbprofiler.py`, a single-file open-source Python 3 script (stdlib only) that connects to a customer's PostgreSQL 16 server from a laptop or jumpbox and produces a shareable, checksummed source-profile bundle for CockroachDB migration planning — without scanning production user tables. The `postgres` subcommand handles PostgreSQL; the script's structure leaves room for future source subcommands (`mysql`, `oracle`, …) without restructuring.

**Distribution:** one `.py` file on GitHub Releases with a companion `dbprofiler.py.sha256`. Customers download, verify, and run: `python3 dbprofiler.py postgres --output source-profile.zip`.

**Assumptions (confirmed with customer):**

- PostgreSQL server major version is **16**.
- Customer has `psql` and `pg_dump` **16** clients on `PATH` where they will run the script.
- Customer has Python **3.9+** on the runner box (laptop or jumpbox).

**Tech Stack:** Python 3.9+ stdlib only (`subprocess`, `csv`, `zipfile`, `hmac`, `hashlib`, `json`, `dataclasses`, `argparse`, `os`, `sys`, `pathlib`, `tempfile`, `contextlib`). External tools: `psql`, `pg_dump`, PostgreSQL 16. Docker Compose for the local test environment.

**Guidance:** Follow the new repo's `.claude/rules/development.md` (seeded fresh for a Python single-script project). Do not commit unless the user explicitly authorizes it.

---

## Deliberate simplifications vs. earlier Go plan

- **`REPEATABLE READ` across collection is dropped.** Each `psql` invocation is its own transaction. Concurrent DDL is still detected by comparing catalog-object fingerprints captured before and after collection; mismatch is fatal at publish time. Observable safety at the bundle boundary is unchanged; only the intra-collection isolation guarantee is relaxed.
- **Contract format is JSON, not YAML.** Python stdlib has no YAML. `profile.json` and `manifest.json` replace the earlier YAML files. Contents and field names are unchanged.
- **Distribution is a signed `.py` file, not a compiled binary.** No GoReleaser, no cosign. GitHub Release ships `dbprofiler.py` + `dbprofiler.py.sha256`; auditors read every line before running.
- **Type "safety" is `@dataclass` + convention, not compile-time.** Contract drift is a code-review concern.

## MVP boundary

Included: PostgreSQL 16 direct collection via `psql`; `pg_dump` schema extraction; `pg_class.reltuples`; supported `pg_stats`; declared FKs; existing extended n-distinct/MCV statistics; single/composite FK fan-out; deterministic HMAC-SHA-256 tokenization of MCVs / histograms / query text; Tier 1 workload telemetry (`pg_stat_user_indexes`, `pg_stat_user_tables`, `pg_stat_statements`); and a checksummed ZIP containing the normalized contract and sanitized observations.

Deferred: configurable privacy policies, `--schema-file`, `--exclude-code`, validation artifacts, detailed unsupported-object classification, partial-collector recovery, PostgreSQL versions other than 16, non-Tier-1 workload telemetry (per-block I/O, replication, bgwriter/WAL, function stats), non-PostgreSQL source types.

## Safety boundary — enforced by a self-check mode

- No `COUNT(*)` or scans over user tables.
- No `ANALYZE` on customer data (only allowed on disposable integration fixtures).
- No `CREATE STATISTICS`.
- Only catalog views (`pg_catalog.*`, `pg_stat_*`, `pg_class`, `pg_namespace`, `pg_attribute`, `pg_type`, `pg_constraint`, `pg_index`, `pg_stats`, `pg_stats_ext`, `pg_stat_statements`, `pg_stat_statements_info`).
- No credentials on argv or in log/error output.

Every SQL statement lives in a module-level constant named `SQL_*`. `python3 dbprofiler.py --check-safety` reads its own source, greps every `SQL_*` constant for the forbidden tokens above, greps the whole file for `subprocess.*"...URL..."` patterns, and exits non-zero on any hit. CI runs this mode against every commit.

## Workload telemetry scope (Tier 1)

Rationale unchanged from prior iteration: three PG runtime signals materially drive PG→CRDB sizing, index strategy, and compatibility-testing scope. Cache-hit ratios, per-block I/O, replication, bgwriter/WAL, and function stats are omitted.

- **`observations/pg_stat_indexes.csv`** — one row per user index, joining `pg_stat_user_indexes` with `pg_class` for size: `schema`, `table`, `index`, `idx_scan`, `idx_tup_read`, `idx_tup_fetch`, `size_bytes`. Surfaces unused indexes (`idx_scan == 0`).
- **`observations/pg_stat_tables.csv`** — one row per user table from `pg_stat_user_tables`: `schema`, `table`, `seq_scan`, `seq_tup_read`, `idx_scan`, `idx_tup_fetch`, `n_tup_ins`, `n_tup_upd`, `n_tup_del`, `n_tup_hot_upd`, `n_live_tup`, `n_dead_tup`, `last_vacuum`, `last_autovacuum`, `last_analyze`, `last_autoanalyze`.
- **`observations/pg_stat_statements.csv`** — top-N fingerprints (N=200 by `total_exec_time`, unioned with top-200 by `calls`, deduped by `queryid`): `queryid`, tokenized normalized query text, `calls`, `rows`, `total_exec_time`, `mean_exec_time`, `shared_blks_hit`, `shared_blks_read`, `shared_blks_dirtied`, `shared_blks_written`, `wal_bytes`. Query text is HMAC-tokenized. `manifest.json` records `stats_reset` from `pg_stat_statements_info`.

Graceful degradation:

- `pg_stat_statements` extension not installed or user lacks privilege → emit a `warning` in `manifest.json`, omit the CSV, continue.
- Permission failure on `pg_stat_user_*` → warning + omit, not fatal.

## Bundle layout

```text
source-profile.zip
├── manifest.json                      # written last; holds SHA-256 of all other payload bytes
├── schema.sql                         # pg_dump --schema-only --no-owner --no-privileges
├── profile.json                       # normalized contract (ContractVersion "1.0")
└── observations/
    ├── pg_class.csv
    ├── pg_stats.csv
    ├── pg_stats_ext.csv
    ├── foreign_keys.csv
    ├── pg_stat_indexes.csv
    ├── pg_stat_tables.csv
    └── pg_stat_statements.csv         # omitted with warning if extension absent
```

## Repo layout

```text
.
├── dbprofiler.py                       # the entire tool: ~800–1200 lines
├── test_dbprofiler.py                  # stdlib unittest — unit tests, guard test, golden files
├── integration_test.py                # stdlib unittest — Docker PG 16 end-to-end (opt-in)
├── testdata/
│   └── golden/                        # sanitized expected fixtures for normalize/tokenize
├── docker-compose.postgres-test.yml
├── .env.test.local                    # gitignored, never committed
├── .github/workflows/
│   ├── ci.yaml                        # python -m unittest, --check-safety, optional ruff
│   └── release.yaml                   # publish dbprofiler.py + .sha256 on tag
├── docs/
│   ├── SCOPE.md                       # contract description
│   ├── SAFETY.md                      # safety boundary + audit walkthrough
│   └── TESTING.md                     # docker start/stop, running integration tests
├── README.md
├── LICENSE                            # MIT
└── .claude/rules/development.md
```

Everything the tool does lives in `dbprofiler.py`. Auditors read one file. Tests are separate so the main file stays focused.

## Structure inside `dbprofiler.py`

Organized top-to-bottom for readability by auditors:

1. Module header — license, contract version, safety-boundary comment block.
2. `SAFETY_FORBIDDEN` = list of forbidden SQL tokens; used by `--check-safety`.
3. `SQL_*` = every query as a module-level constant. Named so `--check-safety` can enumerate them by reflection.
4. `@dataclass` contract types: `Profile`, `Source`, `Table`, `Column`, `Relationship`, `FanOut`, `Manifest`, `Observation`, `Warning`.
5. `SafeEnv`, `redact_error()`, `run_psql()`, `run_pg_dump()` — subprocess helpers that pass credentials only via `env=` and redact stderr.
6. Collectors: `collect_catalog()`, `collect_workload()`, `collect_schema()`, `fingerprint()`.
7. `tokenize(value, domain)` — HMAC-SHA-256 with key from `DBPROFILER_TOKEN_KEY`.
8. `normalize_columns()`, `normalize_fk_fanout()` — post-processing on collected rows.
9. `write_bundle()` — atomic ZIP publication with per-payload SHA-256 and manifest-last serialization.
10. `run_postgres()` — the orchestration entry point registered under the `postgres` subcommand.
11. `main()` — `argparse` with subparsers: `postgres`, `--check-safety`, `--version`.

No connection string or credential may appear in the source, committed fixtures, docs, output, logs, or errors. Runtime code reads env vars; Compose substitutes values from `.env.test.local`.

## CLI shape

```bash
export DBPROFILER_POSTGRES_URL='postgres://...'   # customer-set locally; parsed once, never logged
export DBPROFILER_TOKEN_KEY='...'                 # HMAC key for tokenization

python3 dbprofiler.py postgres \
  --output ./source-profile.zip \
  [--url <conn-string>] \                          # alternative to DBPROFILER_POSTGRES_URL
  [--schema-include <name>]... \
  [--schema-exclude <name>]... \
  [--pg-dump-path /usr/bin/pg_dump] \
  [--psql-path /usr/bin/psql] \
  [--timeout 300]                                  # seconds

python3 dbprofiler.py --check-safety                # audit self-test; exit 0 = clean
python3 dbprofiler.py --version                     # prints VERSION constant
```

`--url` is parsed into `PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD`/`PGDATABASE` env for child processes; never appears on argv of `psql` or `pg_dump`.

---

### Task 1: Repo bootstrap

**Files:** create `dbprofiler.py` (skeleton with `VERSION`, `main()`, `--version`, `--check-safety` stubs), `test_dbprofiler.py` (one passing sanity test), `LICENSE` (MIT), `README.md` skeleton, `.gitignore`, `.claude/rules/development.md`, `.github/workflows/ci.yaml`, optional `ruff.toml`.

- [x] Confirm GitHub org / repo owner for the `dbprofiler` repository. → `cockroachlabs/dbprofiler`, public, `origin` already configured.
- [x] Write `LICENSE` with MIT text (current year, copyright holder). → MIT, 2026, Cockroach Labs, Inc.
- [x] `.gitignore`: `.env.test.local`, `*.zip`, `__pycache__/`, `.pytest_cache/`, `dist/`.
- [x] Seed `.claude/rules/development.md` fresh for a Python single-script project: describe `python -m unittest`, `--check-safety`, no pip deps, single-file discipline.
- [x] CI workflow: matrix on `python-3.9`, `3.10`, `3.11`, `3.12`; run `python -m unittest -v`, `python3 dbprofiler.py --check-safety`, `python3 dbprofiler.py --version`, optional `ruff check`. → matrix extended to `3.13` and `3.14`; developer machines are on 3.14, so the matrix must cover it.
- [x] Verify `python3 dbprofiler.py --version` prints `dev`.

**Naming decision (2026-08-24):** the tool is named for the repo — `dbprofiler.py`,
`DBPROFILER_POSTGRES_URL`, `DBPROFILER_TOKEN_KEY`, release assets `dbprofiler.py` and
`dbprofiler.py.sha256`. Earlier revisions of this plan said `dbprofile`; all occurrences
have been updated.

**Deviation from "stubs":** `--check-safety` is implemented for real rather than stubbed,
because a stub returning 0 makes the CI step meaningless while no `SQL_*` constants exist
yet. The token scan and its guard tests are live; the relation allowlist and the
connection-string scan remain for task 3.

### Task 2: Config, argparse, and version enforcement

**Files:** extend `dbprofiler.py`, `test_dbprofiler.py`.

- [x] Write failing tests for: env-sourced connection config (`DBPROFILER_POSTGRES_URL` and `--url`), URL parsing into `PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD`/`PGDATABASE`, `.zip` output validation, PostgreSQL major 16 assertion, schema include/exclude flag conflicts, `ContractVersion == "1.0"`. Use `unittest.mock.patch.dict(os.environ, ...)`; never embed a URL. → 36 new tests, confirmed red before implementation.
- [x] Implement `argparse` with `postgres` subparser, `--check-safety`, `--version`.
- [x] Implement URL parser (stdlib `urllib.parse`) → dict of libpq env vars; strip password before any log/repr.
- [x] Implement server-version probe via `SELECT current_setting('server_version_num')::int`; require `>= 160000 AND < 170000` for MVP; error message must not leak connection details. → `SQL_SERVER_VERSION` and `require_supported_version()` are in; issuing the query waits on `run_psql` in task 3.
- [x] Define `@dataclass` contract types (Profile, Source, Table, Column, Relationship, FanOut, Manifest, Warning, Observation). No `dict[str, Any]` in the public contract.
- [x] Run focused tests; expect PASS. → 47 tests pass, `--check-safety` exit 0, `ruff check` clean.

**Additions beyond the checklist:**

- **The URL parser rejects unknown query parameters.** The plan named five libpq
  variables. A URL carrying `?sslmode=require` would have had that silently dropped,
  downgrading a connection the customer asked to encrypt. Twelve libpq parameters are
  now mapped to their `PG*` equivalents (`sslmode`, the three `ssl*` file paths,
  `connect_timeout`, `application_name`, `options`, and the five originals) and anything
  outside the map is a hard error rather than a silent omission.
- **Absent URL components are omitted, not defaulted.** Inventing `PGPORT=5432` would
  override a customer's own environment. libpq's defaults are better than ours.
- **Ports and the database name are validated.** Port must be 1-65535 (`urlsplit`
  accepts 0); a URL with no database is an error rather than a libpq fallback to the
  username.
- **`Warning` is named `ProfileWarning`.** The plan's name shadows the builtin exception
  class, which would turn any `except Warning:` in this file into a `TypeError`.
- **Contract collections are tuples, not lists.** A frozen dataclass holding a list is
  still mutable through that list.
- **`DbprofilerError` base class**, caught in `main()` and printed as a message rather
  than a traceback — stack frames can carry values we have promised not to print.

**Test convention adopted:** tests that must exercise connection strings use only
`db.invalid` / `example-user` / `example-password` / `example-db`. `.invalid` is reserved
by RFC 2606 and can never resolve, so a reviewer grepping for a leak can tell test data
from a real credential at a glance. Recorded in `.claude/rules/development.md`, which
previously banned connection strings in tests outright — a rule this task could not have
satisfied while still testing the parser.

### Task 3: Safe subprocess helpers and `--check-safety`

**Files:** extend `dbprofiler.py`, `test_dbprofiler.py`.

- [x] Write failing tests for: `run_psql(sql, env)` never places SQL or credentials on argv beyond `-X -A -F, --csv -t -c <sql>`; credentials always flow through `env=`; stderr is redacted (URL-like strings, `password=` fragments, and libpq env values scrubbed); nonzero exit raises a wrapped exception without raw stderr.
- [x] Write failing tests for `--check-safety`: enumerate every `SQL_*` constant via `inspect`/reflection; assert none contains `COUNT(`, `ANALYZE`, `CREATE STATISTICS`, or references to non-allowed relations (allowlist: ~~`pg_catalog.*`,~~ `pg_class`, `pg_namespace`, `pg_attribute`, `pg_type`, `pg_constraint`, `pg_index`, `pg_stats`, `pg_stats_ext`, `pg_stat_user_indexes`, `pg_stat_user_tables`, `pg_statio_user_indexes`, `pg_stat_statements`, `pg_stat_statements_info`, `pg_attrdef`, `pg_sequence`, `pg_description`).
- [x] Implement `SafeEnv` builder, `run_psql`, `run_pg_dump`, `redact_error` with a deterministic redaction pattern list. → `safe_env()`, `run_psql()`, `run_psql_scalar()`, `run_pg_dump()`, `redact_error()`, all funnelling through a single `run_command()`.
- [x] Implement `--check-safety` mode.
- [x] Run tests; expect PASS. → 92 tests, `ruff check` clean, 3.9 grammar verified.

**Deviations and additions beyond the checklist**

- **Dropped `pg_catalog.*` from the allowlist.** A blanket wildcard over `pg_catalog`
  is not a safety boundary: it admits `pg_authid` and `pg_shadow` (role password
  hashes), `pg_largeobject` (actual user data), `pg_statistic` (raw statistic values
  *without* the per-permission filtering the `pg_stats` view applies),
  `pg_subscription` (`subconninfo` carries a password) and `pg_user_mapping`
  (`umoptions` can carry a password). `ALLOWED_RELATIONS` now enumerates names one by
  one, and a `DENIED_RELATIONS` map records a reason per trap so a reviewer sees the
  "why". A schema qualifier other than `pg_catalog` is itself a violation, so
  `evil.pg_class` is rejected even though `pg_class` is allowed.
- **Dropped `-A` and `-F,` from the psql arguments.** `--csv` is its own output format;
  `-A` placed after it overrides it. Keeping both would have made the parse
  order-dependent. Final set: `PSQL_ARGS = ("-X", "-w", "--csv", "-t", "-v",
  "ON_ERROR_STOP=1")`.
- **Added `-w` (`--no-password`) to both psql and pg_dump.** Without it, a missing
  password makes the child block on a terminal read; the run would then fail by
  timeout instead of immediately. `stdin=DEVNULL` backs it up.
- **Added `-v ON_ERROR_STOP=1`,** so a SQL error is a nonzero exit rather than a
  silently empty result set.
- **Set-returning functions are allowlisted separately** (`unnest`, `generate_series`,
  `generate_subscripts`). The relation scanner distinguishes `FROM name(` from
  `FROM name`, so `FROM pg_read_file(...)` is rejected while `FROM unnest(...)` passes.
- **`--check-safety` now also statically audits this file's own source** via `ast`, not
  grep: exactly one `subprocess.*` call site, every call passes `env=`, none passes
  `shell=`, and no string literal anywhere carries a credentialed connection URL. The
  one-call-site rule is what makes the credential handling reviewable at a glance.
- **`redact_error` scrubs short values only when they are secrets.** `PGPASSWORD` is
  replaced however short; other libpq values are replaced only at length >= 4, because
  a blind replace of a two-character `PGUSER` shreds unrelated words and destroys the
  diagnostic. `PGPORT` is never replaced — a bare port number matches too much text.
- **`probe_server_version(cfg)`** was added here rather than in task 10, so the version
  gate from task 2 has a caller and is exercised end to end.
- **`pg_inherits` was deliberately not added to the allowlist.** Task 5 needs it; the
  house rule is that a relation is allowlisted in the same change as the collector that
  reads it.
- **`ruff.toml`:** added `S608` to the test per-file ignores. The safety tests plant
  deliberately unsafe SQL to prove the guard rejects it.

### Task 4: Schema extraction via `pg_dump`

**Files:** extend `dbprofiler.py`, `test_dbprofiler.py`.

- [x] Write failing tests for: `pg_dump` discovery on `PATH` + `--pg-dump-path` override; `pg_dump` major must be >= server major (both 16 in MVP); command args contain `--schema-only --no-owner --no-privileges` and schema filters but no URL, username, or password; system-schema names rejected in `--schema-include` (catalog, toast, temporary); DDL captured to in-memory string; redacted errors on failure; deterministic schema-object fingerprint (SHA-256 over sorted `(schemaname, relname, relkind)` tuples from `pg_class` join `pg_namespace`, filtered to user schemas).
- [x] Implement `collect_schema(cfg)` returning `(schema_sql: str, fingerprint: str)`; `collect_schema` runs `pg_dump` once and one fingerprint query.
- [x] Implement separate `fingerprint(cfg)` for the after-collection recheck. → `schema_fingerprint(config)`.
- [x] Run tests; expect PASS. → 125 tests, `ruff check` clean, 3.9 grammar verified.

**Deviations and additions beyond the checklist**

- **`collect_schema` takes the server version:** `collect_schema(config,
  server_version_num)`. It checks the client itself rather than trusting the
  orchestrator to remember, so a too-old `pg_dump` fails before it produces anything.
  That means three child processes per call, not two — `pg_dump --version`, the
  fingerprint query, then the dump. The version probe opens no connection.
- **The fingerprint is taken before the dump,** so the after-collection recheck also
  covers DDL drift during the dump itself.
- **Scope filtering happens in Python, not in SQL.** `SQL_SCHEMA_FINGERPRINT` stays a
  fixed module constant that `--check-safety` can audit — building the `WHERE` clause
  from `--schema-include` would have meant assembling SQL inline, which the house rule
  forbids for exactly this reason. Filtering the returned rows also means a schema the
  operator excluded cannot abort the run by changing underneath it.
- **The canonical form uses ASCII unit and record separators** (`\x1f`, `\x1e`) between
  fields and rows. Neither can occur in a PostgreSQL identifier, so no pair of relation
  names can forge a field boundary and collide. There is a test for that.
- **User schemas are selected with `left(nspname, 3) <> 'pg_'`** rather than a `LIKE`
  pattern. One comparison covers `pg_catalog`, `pg_toast`, `pg_temp_N` and
  `pg_toast_temp_N`, and it needs no backslash escaping inside a Python string.
- **No `relkind` filter.** Every relation kind is fingerprinted; TOAST relations are
  already excluded by the schema test. A narrower filter would only create blind spots.
- **`--schema-include` validation moved to config time,** in `build_postgres_config`,
  so the operator finds out before we connect. `pg_` prefixed names and
  `information_schema` are rejected; the prefix is reserved by PostgreSQL, so
  `pg_myschema` cannot be a real user schema either. `--schema-exclude` is not
  validated: excluding something already out of scope is harmless.
- **New error type `UnsupportedClientVersion`,** distinct from
  `UnsupportedServerVersion`. The remedy is different — upgrade the local client, not
  the server.

### Task 5: Catalog-only observations

**Files:** extend `dbprofiler.py`, `test_dbprofiler.py`, `testdata/golden/`.

- [x] Write failing golden tests for typed rows from `pg_class`, `pg_namespace`, `pg_attribute`, `pg_type`, `pg_constraint`, `pg_index`, `pg_stats`, `pg_stats_ext` using recorded `psql --csv` output as fixtures. Each fixture is sanitized: no real customer identifiers.
- [x] Assert `SQL_*` constants for these collectors pass `--check-safety`.
- [x] Implement `collect_catalog(cfg)` returning typed lists: tables (row/size estimates), columns (supported stats), FKs (ordered columns + actions), extended stats (multicolumn n-distinct/MCV).
- [x] Detect partitioned/inherited tables (`relkind IN ('p','I')` or `pg_inherits` membership); fail with an unsupported-MVP error before any normalized output.
- [x] Run tests; expect PASS. → 157 tests, `ruff check` clean, 3.9 grammar verified.

**Deviations and additions beyond the checklist**

- **The layout check runs after two queries, not after all seven.** `SQL_TABLES` and
  `SQL_INHERITED` are issued first and `require_supported_layout` raises immediately, so
  an unsupported database does not pay for five more round trips. The error names the
  offending relation and says why the estimate would be wrong rather than just that the
  feature is unimplemented: a partitioned parent's `reltuples` is not the sum of its
  children, so a fan-out derived from it is silently incorrect, which is worse than
  refusing.
- **Collector records are separate types from the contract dataclasses.** `CatalogTable`,
  `CatalogColumn`, `ColumnStatistics`, `ExtendedStatistics`, `CatalogForeignKey`,
  `CatalogIndex` hold PostgreSQL's own encodings — including raw MCVs and histogram
  bounds — and none of them is serialized. Normalization (task 8) maps them onto the
  contract types after tokenization (task 7). Keeping raw values in a type that is never
  written is the structural half of the guarantee; the negative assertions are the other.
- **`parse_pg_array` is a real parser, not a `split(",")`.** PostgreSQL quotes and
  backslash-escapes elements containing a comma, brace, quote or backslash. Splitting
  would corrupt exactly the values that matter most — keys with embedded punctuation —
  and would do it silently.
- **`pg_ndistinct` keys are resolved to column names at collection time.** PostgreSQL
  renders extended n-distinct as `{"2, 3": 4200}`, keyed by comma-separated attnums.
  `parse_extended_n_distinct` maps those through the collected `pg_attribute` rows to
  `{("user_id", "placed_at"): 4200.0}`. Downstream code should not have to carry attnum
  arithmetic, and the mapping is only available while the column rows are in hand.
- **Foreign keys are assembled from one row per column.** `SQL_FOREIGN_KEYS` uses
  `unnest(conkey, confkey) WITH ORDINALITY`, and `assemble_foreign_keys` groups by
  constraint and sorts by the ordinal, so composite keys keep their declared column
  order. Referential action characters are expanded to their SQL spelling via
  `REFERENTIAL_ACTIONS`; an unrecognized character maps to `""` rather than raising.
- **Type support is decided by an allowlist, not a denylist.** `SUPPORTED_TYPE_NAMES`
  enumerates base types with a CockroachDB equivalent; anything absent is reported
  unsupported. For a migration plan a false negative costs an investigation, while a
  false positive costs a failed cutover. Enums (`typtype = 'e'`) are supported;
  composites, domains, ranges and multiranges are not. Arrays are resolved by stripping
  the element type's leading underscore.
- **`pg_inherits` was added to `ALLOWED_RELATIONS`** in this change, per the house rule
  that a relation is allowlisted alongside the collector that reads it.
- **New error type `UnsupportedObject`,** distinct from the version errors: the remedy is
  to narrow `--schema-include`, not to upgrade anything.
- **`testdata/golden/README.md`** records the fixture conventions — `-t` means no header
  row, NULL is an empty field, booleans are `t`/`f`, arrays cast to text arrive as
  `{a,b,c}` — so a later contributor can add a fixture without re-deriving them from
  `psql`.

### Task 6: Tier 1 workload telemetry

**Files:** extend `dbprofiler.py`, `test_dbprofiler.py`, `testdata/golden/`.

- [x] Write failing tests for: `pg_stat_user_indexes` join with `pg_class` size; `pg_stat_user_tables` full column set; `pg_stat_statements` extension probe (installed vs. missing → warning + omit, never fatal); top-N selection (200 by `total_exec_time` unioned with 200 by `calls`, deduped by `queryid`); `pg_stat_statements_info.stats_reset` captured into manifest; HMAC tokenization of normalized query text — assert no raw literal from a fixture reaches disk.
- [x] Extend `--check-safety` allowlist to include `pg_stat_statements` / `pg_stat_statements_info` and re-run the guard test.
- [x] Implement `collect_workload(cfg)` returning three CSV-ready row lists plus a list of warnings.
- [x] Assert permission errors on any of the three sources degrade to a manifest warning + omitted CSV, not a bundle failure.
- [x] Run tests; expect PASS. → 185 tests, `ruff check` clean, 3.9 grammar verified.

**Deviations and additions beyond the checklist**

- **The forbidden-token check now matches on word boundaries.** `pg_stat_user_tables`
  exposes `last_analyze`, `analyze_count`, `autoanalyze_count` and
  `n_mod_since_analyze`, and a substring match on `ANALYZE` rejected all four. Dropping
  those columns to satisfy the check would have been the wrong trade: they are how a
  reader knows whether the source statistics are stale enough to make the rest of the
  profile untrustworthy. `\bANALYZE\b` still rejects `ANALYZE public.users` and
  `VACUUM ANALYZE`; `\bCOUNT\(` still catches `pg_catalog.count(*)` and now correctly
  ignores the tail of `autovacuum_count`. Six guard tests cover both directions.
- **Top-N is ranked with two window functions in one pass,** not a `UNION` of two
  `LIMIT 200` subqueries. Same 400-row bound, one scan instead of two, and no duplicated
  thirteen-column select list to keep in sync. `WHERE by_time <= 200 OR by_calls <= 200`
  is the union; `ORDER BY by_time` makes "first" mean "most expensive".
- **Dedup by `queryid` happens in Python.** `pg_stat_statements` keys on
  `(userid, dbid, queryid)`, so one statement appears once per role that ran it. The
  first occurrence wins, which given the ordering is the most expensive one. Summing the
  counters across roles was considered and rejected: a mean execution time summed across
  roles is not a mean of anything.
- **The statement query is scoped to the profiled database.** `pg_stat_statements` is
  cluster-wide; without the `dbid` filter the profile would report a workload that never
  touched the target. This is why `pg_database` joins the allowlist.
- **Index size comes from `pg_relation_size(indexrelid)`,** not a join to `pg_class`.
  Same number, one fewer relation inside the safety boundary.
- **`pg_stat_statements` and `pg_stat_statements_info` are referenced unqualified.** They
  live in whatever schema the extension was installed into, and the house rule forbids
  building the schema name into the SQL at runtime. This is the only place the tool
  relies on `search_path`; if resolution fails, the collector degrades to a warning
  rather than failing, so the cost of being wrong is bounded.
- **The extension probe runs before the two statement queries,** so a database without
  `pg_stat_statements` — the default, since it needs `shared_preload_libraries` — costs
  one query rather than two failures. `pg_extension` joins the allowlist for it. There is
  a test asserting the call count is exactly three in that case.
- **Four distinct warning codes, not one.** `pg_stat_statements_missing` (not installed)
  is a different finding from `pg_stat_statements_unavailable` (installed, unreadable):
  the first is a fact about the source, the second is a fact about the role the profile
  ran as, and only the second is worth retrying with more privilege.
- **`pg_stat_statements_info` failing does not lose the statements.** The reset timestamp
  and the counters are read separately, so an unreadable timestamp costs the timestamp.
- **Typed records rather than raw row lists,** matching task 5: `TableActivity`,
  `IndexActivity`, `StatementActivity`, gathered in `WorkloadObservations`. The plan said
  "CSV-ready row lists"; the CSV shaping belongs in task 9 with the rest of bundle
  publication, and a typed record is what the normalizer needs anyway.
- **Query text is collected raw and tokenized in task 7,** where the HMAC primitive and
  the key handling live. `StatementActivity.query_text` is deliberately in a record that
  is never serialized — the same structural argument as the task 5 statistics records —
  and the "no raw literal reaches disk" assertion lands with the code that writes to
  disk. The `statements.csv` fixture carries an unnormalized literal specifically so that
  assertion has something to catch.
- **Scope filters apply to table and index activity** via `schema_is_selected`, so
  `--schema-exclude` means the same thing for telemetry as it does for the catalog.

### Task 7: Tokenization

**Files:** extend `dbprofiler.py`, `test_dbprofiler.py`.

- [x] Write failing tests proving equal typed source values in one FK domain produce equal tokens, different domains do not collide, UUIDs remain UUID-typed after tokenization (retain type provenance), and originals never serialize. Key read only from `DBPROFILER_TOKEN_KEY`; test asserts key is never present in captured stderr, stdout, exceptions, or bundle bytes.
- [x] Implement `tokenize(value, domain)` using `hmac.new(key, f"{domain}\x00{repr_typed(value)}".encode(), hashlib.sha256).hexdigest()`. Key loaded once at process start; never logged, never written.
- [x] Run tests; expect PASS. → 215 tests, `ruff check` clean, 3.9 grammar verified.

**Deviations and additions beyond the checklist**

- **`tokenize` is a method on a `Tokenizer` object, not a free function.** The key lives
  in one object whose `repr` redacts it. A module-level key would end up in a traceback
  the first time any unrelated function was called with one in scope — and every error
  path in this tool is assumed to be printed.
- **The domain separator is also used inside the domain.** `token_domain` joins schema,
  table and column with the same NUL rather than dots, because PostgreSQL permits a dot
  inside a quoted identifier: with a dotted join, `("public", "users.id", "x")` and
  `("public", "users", "id.x")` would be the same domain and one column's values could
  impersonate another's. There is a test for that, and one for the analogous
  domain/value boundary.
- **`repr_typed` takes the type name but never hashes it.** The type steers
  canonicalization only. Folding it into the material would break the equality the tokens
  exist to preserve, because PostgreSQL permits a foreign key across `int4` and `int8`.
  There is a test asserting `int4 7` and `int8 7` tokenize identically.
- **Canonicalization is opt-in by type, not applied to everything.** Numeric types go
  through `Decimal.normalize()` so `42`, `42.0` and `4.2e1` agree; `uuid` goes through
  `uuid.UUID` so case and hyphenation agree. Text is deliberately excluded: `"0001"` and
  `"1"` are different strings, and collapsing them would merge two most-common values
  into one token and corrupt the frequency it carries. Trailing whitespace in text is
  preserved for the same reason.
- **`NaN` and `Infinity` fall back to their text form.** Both are legal `float8` values
  and neither has a canonical decimal; the fallback is tested rather than left to chance.
- **"UUIDs remain UUID-typed" is implemented as output shaping.** A uuid value's token is
  the first 128 bits of the digest, formatted `8-4-4-4-12`. The profile is meant to be
  replayed into a CockroachDB schema for sizing, and a 64-character hex string in a uuid
  column would force the migration team to retype it — at which point the shape under
  test is no longer the shape being migrated. The version and variant bits are left as
  digest bits rather than overwritten to fake a v4: any 128-bit value is a valid uuid to
  both PostgreSQL and CockroachDB, and a token advertising itself as random would be a
  lie about where it came from.
- **`load_token_key` enforces a 16-character minimum.** Below that the tokens are
  reversible by brute force over a small value space. Neither rejection message echoes
  the value.
- **An explicitly passed environment is never topped up from `os.environ`,** so a caller
  handing in a deliberately restricted environment cannot silently pick up the ambient
  key. Tested in both directions.
- **`Tokenizer.tokens()` for sequences,** since most-common values and histogram bounds
  arrive as parallel arrays and the frequencies beside them are positional.
- **`.claude/rules/development.md` gained the token-key test convention**
  (`example-token-key-0123456789`) and a short statement of the key-handling rules, so a
  future contributor does not invent a second synthetic key.
- **README documents why there is no default key** and why the key is worth keeping:
  re-running with the same key produces comparable tokens, and a different key makes two
  bundles impossible to correlate.

### Task 8: Normalization

**Files:** extend `dbprofiler.py`, `test_dbprofiler.py`, `testdata/golden/`.

- [x] Write failing golden tests for: reltuples, absolute vs. relative n-distinct (`n_distinct` negative → `abs(n_distinct) * row_count_estimate`), null fraction, width, MCV/frequency, histogram bounds, supported/unsupported types, extended n-distinct/MCV.
- [x] Write failing single-FK fan-out tests using non-null child rows divided by distinct FK values; assert tokenized MCV frequencies preserve hot-parent shape.
- [x] Write failing composite-FK fan-out tests requiring matching extended n-distinct; otherwise emit `insufficient_statistics`. Never multiply independent single-column estimates.
- [x] Sort all output deterministically. Reserve PostgreSQL-native names for provenance/observations.
- [x] Retain PostgreSQL semantics in `provenance` fields on every normalized record.
- [x] Run tests; expect PASS. → 253 tests, `ruff check` clean, 3.9 grammar verified.

**Deviations and additions beyond the checklist**

- **Token domains follow foreign-key chains to their root.** A child column borrows its
  parent's domain so both sides of a key tokenize alike — but with `A.x → B.y` and
  `B.y → C.z`, resolving only one hop would have `A.x` tokenize under `B.y` while `B.y`
  tokenized under `C.z`, making the A-to-B join invisible: the exact failure the domains
  exist to prevent. `resolve_domain_root` walks to the root and stops on a cycle, because
  self-referential and mutually referential keys are legal. The root column's type also
  wins, so a `text` column referencing a `uuid` one canonicalizes and shapes the same way
  on both sides. Tested with the fixture's `invoices.order_id → orders.id` chain.
- **`n_distinct = 0` is "no estimate", not zero distinct values.** PostgreSQL writes 0
  when it has none. Resolving it as a count would put a zero in the denominator of every
  fan-out; the contract carries `None` and the fan-out says `insufficient_statistics`.
- **Nulls are excluded from the fan-out numerator.** A null foreign key references no
  parent, so those rows are not children to distribute. On a nullable key, counting them
  inflates every estimate — the fixture's half-null variant is a test.
- **A composite key uses the most-null column's fraction.** It references a parent only
  when every column is non-null, and PostgreSQL has no joint null fraction. The
  most-null column is the tightest bound available, so the estimate errs high. That
  direction is deliberate and is stated in the code: an under-reported hot parent is
  discovered during the migration, which is the expensive place to discover it.
- **`p99` is computed from the most-common-value frequencies,** which is what makes the
  hot-parent shape survive tokenization. Only the MCVs are known individually, so the
  estimator ranks those and reads off the percentile; when the MCV list is shorter than
  the percentile's rank — the usual case, since PostgreSQL keeps at most a few hundred —
  every parent past the list has no more children than the last MCV, so the last MCV's
  count is returned as an upper bound. The fixture's `orders.user_id` has a mean of 10
  and a p99 of 100: a migration sized on the mean alone would be wrong by an order of
  magnitude, which is the entire reason this field exists.
- **Extended-statistics lookup is by column *set*, not sequence.** N-distinct over a
  column set is order-independent, and `pg_stats_ext` lists attnums in catalog order,
  which need not match the key's declared order. Keyed on `frozenset`, with a test that
  reversing the key's columns still finds the statistic and that a statistic covering a
  *different* set does not count.
- **`build_profile(source, catalog, workload, tokenizer)`** composes the three
  normalizers and carries the workload warnings onto the profile, so task 10's
  orchestration stays thin.
- **A test asserts the contract reserves PostgreSQL-native names.** `reltuples`,
  `n_distinct`, `null_frac`, `attnum` and `relkind` appear in no field name on `Table`,
  `Column` or `Relationship` — they appear in `provenance`, where the derivation is
  recorded rather than discarded. A number without its derivation is not auditable.
- **Determinism is asserted directly** (`repr(build()) == repr(build())`) rather than
  only through per-collection sort tests, so a future dict-ordering regression fails
  loudly.
- **The negative assertion is in place:** a planted email from the statistics fixture is
  proven absent from the normalized records.

### Task 9: Atomic bundle publication

**Files:** extend `dbprofiler.py`, `test_dbprofiler.py`.

- [x] Write failing tests for: required entries present, sanitized CSVs (no raw literals), sorted safe entry paths, per-payload SHA-256 (excluding `manifest.json`) written into manifest, cleanup of temp ZIP on failure, atomic publication via `os.replace`, rejection of absolute paths / `..` / duplicates / symlinks / unexpected entries.
- [x] Put a unique raw secret into an in-memory observation before serialization; assert it appears in neither the temp file nor the final ZIP bytes.
- [x] Serialize only sanitized types. Hash uncompressed payload bytes. Serialize `manifest.json` last. Write to a temporary `.zip.tmp` file adjacent to destination; `close()`, `os.fsync()`, then `os.replace()`.
- [x] Run tests; expect PASS. → 317 tests, `--check-safety` OK, `ruff check` clean, 3.9 grammar verified.

**Deviations and additions beyond the checklist**

- **Serialization is by allowlist of contract types, not by structure.** The obvious
  implementation is `dataclasses.asdict()`, and it would have been a hole: the collector
  records holding raw most-common values (`ColumnStatistics`) and raw query text
  (`StatementActivity`) are dataclasses too, so a structural walker serializes them
  happily. `to_jsonable()` checks membership in `CONTRACT_TYPES` and raises otherwise, so
  making a record serializable is a visible edit in one place. Mappings and `bytes` are
  refused for the same reason. `allow_nan=False`, because `json.dumps` writes a bare
  `NaN` by default and that is not JSON.
- **Omission is keyed off the warning, not off an empty record set.** `pg_stat_tables.csv`
  is dropped when `pg_stat_user_tables_unavailable` is present, not when the tuple is
  empty. Otherwise a database that genuinely has no user tables is indistinguishable from
  one whose role could not read the view — the first should ship an empty CSV, the second
  should ship nothing and say why.
- **The negative assertions search decompressed members, not just the stored bytes.** The
  archive is DEFLATE-compressed, so `assertNotIn(planted, zip_bytes)` over the raw file
  would pass while the literal sat inside the archive. `zip_bytes()` in the test file
  returns the stored bytes *plus* every member decompressed, and the temporary file's
  bytes are captured by wrapping `os.replace` so the pre-rename artifact is searched too.
  Three literals are planted — an unnormalized query literal, a most-common value, and a
  histogram bound — plus the tokenization key and every connection detail.
- **The safety properties were mutation-tested.** Publishing raw query text, replacing the
  type allowlist with a structural dataclass check, replacing `os.replace` with a
  non-atomic copy, and dropping the temp-file cleanup were each applied in turn; every one
  is caught by the suite. A negative assertion that cannot fail is decoration.
- **`pg_stat_indexes.csv` gains `is_unique` and `is_primary`** from `CatalogIndex`, which
  task 5 collected and nothing had consumed. `idx_scan == 0` marks a drop candidate, but
  whether it *can* be dropped depends on whether it backs a constraint. Both facts were
  already in hand; splitting them across two files would make every reader re-join them.
- **`wal_bytes` is not in `pg_stat_statements.csv`.** The plan's column list named it, but
  `SQL_STATEMENTS` does not select it, so it was never collected. The CSV carries what was
  collected — including `stddev_exec_time`, `temp_blks_read` and `temp_blks_written`,
  which the plan's list omitted.
- **Query text is tokenized whole,** which costs the text's analytical value and leaves
  `queryid` as the correlation handle. `pg_stat_statements` normalizes literals to `$1`
  for most statements but not for utility statements or parser-folded constants, so there
  is no subset of the text that is safe by construction, and a partial redaction would be
  a guess dressed up as a guarantee.
- **Entry paths are validated against one regex that rejects by construction.** Lowercase
  ASCII segments, each starting with a letter or digit, slash-separated. That excludes
  absolute paths, `..` and `.` segments, empty segments, backslashes, drive letters,
  whitespace and control characters without a chain of special cases — and the allowlist
  of the nine legal payload paths is checked on top of it.
- **Symlink defence is applied at both ends.** Every `ZipInfo` gets an explicit
  `S_IFREG | 0644` external attribute, since zipfile's default mode is zero and some
  extractors then fall back to the umask; and `write_bundle` refuses a destination that is
  a symlink or a non-regular file, rather than letting `os.replace` resolve it somewhere
  unexpected.
- **Archives are byte-reproducible.** Entry timestamps are fixed at the ZIP epoch and
  entries are stored in sorted order with `manifest.json` last, so two runs over the same
  input produce identical bytes and a bundle can be diffed.
- **`except BaseException` around the write, not `except Exception`.** A `KeyboardInterrupt`
  mid-archive otherwise leaves a half-written `.zip.tmp` beside the destination that looks
  like a bundle.
- **The containing directory is fsynced after the rename,** best-effort: opening a
  directory is not portable, and failing a publication because a durability flush failed
  would be worse than the durability gap.
- **CSV formula injection is noted and not addressed.** A schema or table name beginning
  with `=`, `+`, `-` or `@` is a live cell when a spreadsheet opens the CSV. Prefixing such
  cells would desynchronize the CSVs from `profile.json`, which carries the same
  identifiers unquoted, so the fix belongs to a decision about the whole contract rather
  than to this task.

### Task 10: Orchestration and `postgres` subcommand

**Files:** extend `dbprofiler.py`, `test_dbprofiler.py`.

- [x] Write a failing orchestration test asserting the sequence: validate config → probe version → fingerprint-before → `pg_dump` → catalog collection → workload telemetry → tokenize → normalize → fingerprint-after → publish. Fingerprint mismatch, catalog failure, cancellation (SIGINT via `KeyboardInterrupt`), or any missing core artifact must prevent publication (no partial `.zip` on disk, no `.zip.tmp` leak).
- [x] Assert no connection data (URL, `PGPASSWORD`, `PGUSER`) appears in `sys.stderr` capture, exception messages, or bundle contents across the full flow.
- [x] Implement `run_postgres(args)` invoked from `main()` under the `postgres` subparser.
- [x] Run tests; expect PASS. → 354 tests, `--check-safety` OK, `ruff check` clean, 3.9 grammar verified.

**Deviations and additions beyond the checklist**

- **A bug was found and fixed: `Path.resolve()` was following a symlinked destination.**
  `build_postgres_config` resolved the whole output path, so by the time task 9's
  symlink check ran there was no symlink left to see and the tool would have published
  straight through it. The config now resolves the *parent* and keeps the final component
  as given. Two regression tests cover it: the symlink survives into the config, and a
  `..` in the directory part is still normalized away.
- **The child-process fake dispatches on the query, not on call position.** A positional
  `side_effect` list would need renumbering every time a step moves, and asserting
  "17 calls happened" proves nothing about their order. `FakePostgres` keys off the
  `SQL_*` constant on the command line and records a step name, so the order assertion is
  a single comparison against `FULL_RUN` and an override names the step it replaces.
  A list-valued override is consumed one entry per call, which is how the two fingerprint
  reads are given different answers to simulate concurrent DDL.
- **The tokenization key and the destination are both validated before a connection is
  opened.** Neither was called for by the checklist, and both are worth a few lines: a
  missing `DBPROFILER_TOKEN_KEY` discovered after collection costs the operator a full
  pass over a production catalog, and so does a destination that cannot be written to.
  Two tests assert the failure happens with zero child processes spawned.
- **`Source.collected_schemas` records the outcome, not the intent.** It is derived from
  the schemas the catalog actually returned rather than from `--schema-include`, so a
  bundle that covered less than the operator expected says so on its face.
- **An empty `pg_dump` is fatal.** `pg_dump` exits zero when the role can see no objects,
  which would otherwise publish a bundle with an empty `schema.sql` and no other
  complaint. `REQUIRED_BUNDLE_PATHS` covers the same class of failure for the profile and
  the three catalog CSVs: those may not degrade, and a bundle missing one of them looks
  complete and is not.
- **`SchemaDrift` is its own error class,** so the concurrent-DDL failure is distinguishable
  from a command failure by a caller and not only by its message text.
- **`KeyboardInterrupt` is handled in `main()` and exits 130,** the conventional code for
  SIGINT. `write_bundle` already removes its own temporary file on the way out, so the
  handler only has something to say, not something to clean up.
- **Progress goes to stderr; stdout is the bundle path and nothing else,** so the run can
  be used in a shell substitution. Every progress line is composed from constants and
  from values the server itself reported.
- **Secrecy is asserted across the whole flow, not only in the bundle.** Five values --
  the URL, password, user, host, and tokenization key -- are checked against stdout,
  stderr, and the bundle bytes, on the success path and on two failure paths where a
  server error deliberately echoes the URL and the password back. Two further tests
  assert the credentials reach the child through `env=` and never through `argv`, and that
  neither `DBPROFILER_*` variable is passed down.
- **The orchestration guarantees were mutation-tested,** as in task 9: dropping the
  after-collection fingerprint comparison, neutering the comparison itself, publishing an
  incomplete bundle, and deferring the key load until after collection are each caught by
  the suite.
- **Two fixtures were added,** `server_version.csv` and `schema_fingerprint.csv`, since an
  end-to-end run needs a reply for every query. The fixture README says what they are for.
- **The obsolete `test_collection_is_not_implemented_yet` was replaced** by a test that
  `--output` must name a `.zip`.

### Task 11: Docker PostgreSQL 16 test environment

**Files:** `docker-compose.postgres-test.yml`, local `.env.test.local`, `docs/TESTING.md`.

- [x] Ignore `.env.test.local` before creating it; verify `git check-ignore .env.test.local` exits 0.
- [x] Define `postgres:16` service with named volume, localhost-only configured port, health check, `shared_preload_libraries=pg_stat_statements`. User/database/password/port fields must be `${...}` substitutions from `.env.test.local`; Compose contains no literal credentials or URL.
- [x] Create local `.env.test.local` with Compose variables, `DBPROFILER_POSTGRES_URL`, `DBPROFILER_POSTGRES_TEST_URL`, and `DBPROFILER_TOKEN_KEY`. Never display or commit it.
- [x] Start with `docker compose --env-file .env.test.local -f docker-compose.postgres-test.yml up -d --wait`; verify health without echoing env values.
- [x] Post-start SQL: `CREATE EXTENSION pg_stat_statements;` in the target database.
- [x] Document safe start, stop, reset, and test commands. Do not add a committed example env file containing a URL.

**Deviations and additions beyond the checklist**

- **The environment file is checked by the unit suite, not just by hand.** A committed
  Compose file that quietly grew a default password would be the kind of thing nobody
  notices in review, so `TestComposeSecrecy` asserts the properties directly: no `://`
  anywhere in the Compose file, no `DBPROFILER_TOKEN_KEY`, every credential field a bare
  `${...}`, every published port prefixed `127.0.0.1:`, `shared_preload_libraries`
  present, `.env.test.local` gitignored, no tracked file whose name starts with `.env`,
  and no credentialed URL in `docs/TESTING.md`. Each of those was mutation-tested:
  rebinding to `0.0.0.0`, hardcoding a password, dropping the preload, and pasting a URL
  into a comment all turn the suite red.
- **Substitutions use `${VAR:?message}`, never `${VAR:-default}`,** and a test enforces
  it. A default value means a typo in the env file starts a server with credentials
  nobody chose, and the failure then surfaces somewhere less obvious than the point of
  the mistake.
- **`CREATE EXTENSION` moved into `testdata/postgres-test-init.sql`,** mounted read-only
  at `/docker-entrypoint-initdb.d/`, rather than being a documented manual step after
  start. A manual post-start step is one a tired person skips, and the resulting failure
  looks like a profiler bug — the tool degrades gracefully when `pg_stat_statements` is
  absent, so the integration test would silently exercise the degraded path instead of
  the one it means to cover. The tradeoff is that the script only runs against an empty
  volume, which is why `docs/TESTING.md` gives `down -v` its own section.
- **Found and fixed a real bug in `probe_pg_dump_major`.** The first run against the live
  container failed at `pg_dump exited with status 1`. `PG_DUMP_ARGS` was being spliced in
  ahead of `--version`, producing `pg_dump -w --version` — and pg_dump handles
  `--version` by comparing `argv[1]` before getopt runs, with no entry for it in the
  long-option table. Anything ahead of it, even a harmless `-w`, makes it an unrecognized
  option and pg_dump exits 1 with nothing but a "try --help" hint. The unit test had
  asserted the wrong argv and the fake matched on `"--version" in argv`, so neither
  noticed. Now `[pg_dump, "--version"]` exactly, with both tests corrected. This is the
  bug the Docker environment exists to catch, arriving before the integration suite that
  was meant to catch it.
- **Every Compose subcommand needs `--env-file`, not just `up`.** Interpolation runs for
  `ps`, `exec`, and `down` too, and `${VAR:?}` turns a missing one into an error rather
  than a silent empty value. `docs/TESTING.md` defines a `pgtest` alias so it is not
  something the reader has to remember five times.
- **Health verified without echoing a value.** `pgtest exec` runs `psql -U "$POSTGRES_USER"`
  with the expansion performed by the shell inside the container, against the environment
  the server already has, so no credential enters shell history or a host process's
  command line. The documented check is the one that was actually run.
- **Verified end to end by hand before writing the integration suite.** Against the live
  container the tool produced a bundle with all nine entries, no warnings, `server_version_num`
  160015, and a captured `stats_reset`. Confirmed the host listener is `127.0.0.1.55432`
  only — a connection to the machine's LAN address is refused. Runtime was Podman 5.8.1
  behind a `docker` CLI shim with `podman-compose`; the Compose file uses no
  Docker-specific extension, and `docs/TESTING.md` says so rather than assuming Docker
  Desktop.
- **Considered and rejected: a committed `.env.test.example`.** It is the conventional
  thing to add, and it is where a real connection string eventually gets pasted — at
  which point no reviewer reading the diff can tell that the value in it was supposed to
  be fake. `docs/TESTING.md` lists the variable names in a table instead, and a test
  fails if any `.env*` file becomes tracked.

### Task 12: End-to-end integration test

**Files:** `integration_test.py`, `README.md`.

- [x] Skip the test unless `DBPROFILER_POSTGRES_TEST_URL` and `DBPROFILER_TOKEN_KEY` are both set (use `unittest.skipUnless`). Read only via `os.getenv`; never print their values.
- [x] Create a uniquely named disposable schema (e.g. `dbprofiler_it_<epoch>`) with synthetic ordinary tables, scalar types, unsupported JSON/array columns, indexes, single/composite FKs, and multicolumn statistics. `ANALYZE` allowed only on these disposable fixtures.
- [x] Seed enough activity (a few `SELECT`s repeated) to make `pg_stat_statements` non-empty for assertions.
- [x] Run the profiler and validate: entries present, JSON well-formed, checksums verify, row/column shape correct, deterministic tokens present, no raw source values present, single/composite fan-out present, Tier 1 CSVs populated, `stats_reset` captured. Drop only the disposable schema in cleanup (`try/finally`).
- [x] Update `README.md` with environment-only usage, PostgreSQL 16 / `pg_dump` prerequisites, safety boundary, `--check-safety` mode, bundle contents, and deferred features — without a literal URL.

**Deviations and additions beyond the checklist**

- **50 integration tests, all green against PostgreSQL 16.15, and 8 new unit guards** —
  371 unit tests total. Three assertions in the first draft were wrong about the tool
  rather than the tool being wrong, and each correction is a fact worth recording:
  `data_type` is `format_type` output (`timestamp with time zone`, `numeric(12,2)`), not
  the internal type name; fan-out is children per *referenced* parent, so it divides by
  the child column's distinct count and not by the parent's row count; and p99 is read at
  the rank the distinct count implies, so a single hot parent among 376 sits past the
  99th percentile and does not lift it.
- **The seed was rebuilt so the right answer is computable, not guessed.** Hot orders go
  to five ids disjoint from the evenly spread range, and `HOT_EVERY` is coprime with the
  uniform range so carving them out knocks no id out of the spread — the referenced
  parent count is exactly 405 by construction. Likewise `org_id` and `site_id` are now
  genuinely correlated (five pairs, from two orgs and five sites), so reading the
  extended statistics gives 5 where assuming independence would give 10. Before that
  change the composite test would have passed either way.
- **The checklist's "unsupported JSON/array columns" is wrong.** `jsonb` and `text[]` are
  both supported — `jsonb` by name, arrays by their element type — so a fixture built
  from them would have asserted nothing. The genuinely unsupported kinds are ranges,
  domains, composites and multiranges; the `exotic` table carries an `int4range` and a
  `CREATE DOMAIN` column, and the suite asserts both directions.
- **Module-level setup, not `setUpClass`.** A shared base class's `setUpClass` runs once
  per subclass, which would have meant six `CREATE SCHEMA` attempts and eighteen profiler
  runs. `setUpModule` builds the fixtures once and runs the profiler three times: twice
  under one key to prove tokens reproduce, once under another to prove two bundles cannot
  be correlated.
- **Cleanup catches `BaseException`, and `drop_fixtures` re-checks the name.** This is the
  only statement in the repository that destroys anything and it runs against whatever
  server the operator configured, so it does not trust a constant twenty lines away to
  still say what it said. Leaving a schema behind on a shared server is worse than a slow
  Ctrl-C, so the interrupt path drops it too.
- **Guard tests over the integration suite itself** (`TestIntegrationSuiteScope`). It
  parses `integration_test.py` with `ast` and fails if any mutating statement does not
  name `{SCHEMA}`, if the schema name stops being unique per run, if `drop_fixtures` stops
  being called from both `setUpModule` and `tearDownModule`, if a credentialed URL or a
  new token key appears, or if the file ever becomes discoverable by `python3 -m unittest`.
  Mutation-tested: pointing one `DROP SCHEMA` at `public` turns the unit suite red without
  a server present.
- **Mutation testing of the integration suite.** Making the tokenizer return raw values
  fails 14 tests including every negative assertion; making a child column tokenize under
  its own domain instead of its parent's fails exactly the two tests written for that
  property and nothing else; making composite fan-out assume independence fails exactly
  the composite test.
- **A second token test that guards the first.** Asserting an overlap between the parent's
  and the child's token lists would also pass if both sides were tokenized under a domain
  that merely happened to match. The suite instead computes the expected token from the
  key and asserts it is present, then asserts the token the child's *own* domain would
  produce is absent.
- **Four plants, four routes, plus liveness guards.** The planted values reach a
  most-common value, a histogram bound, a most-common value on a composite parent, and a
  utility statement's verbatim text in `pg_stat_statements`. Two further tests prove each
  plant really is in the source, so a fixture that silently failed to insert cannot make
  every assertion of absence pass for the wrong reason. Absence is checked over the
  archive as stored *and* every member decompressed.
- **`.claude/rules/development.md` extended in the same change.** The rule exempted only
  `ANALYZE` for disposable fixtures, but the checklist requires multicolumn statistics,
  which needs `CREATE STATISTICS`. The exemption now names the DDL, DML, `ANALYZE`,
  `CREATE STATISTICS`, and `COUNT(*)` this file needs, scopes it to `integration_test.py`
  and the disposable schema, and says why — with the standing prohibition on comparing the
  profiler's estimates against a count queried at assertion time, since such a count would
  agree with an estimator that was broken in the same direction.
- **A real bug in the test fixtures, caught before it ran.** A mutation-testing step left
  `DROP SCHEMA IF EXISTS public CASCADE` in the file. The new guard test caught it from a
  static parse, with no server involved; the `public` schema of the test database was
  verified intact afterwards. That is the argument for the guard.
- **`README.md` gained a "What this release does not do" section** listing the deferred
  scope from line 32 of this plan, so a reader can tell an absent feature from an
  oversight.

### Task 13: Release plumbing

**Files:** `.github/workflows/release.yaml`.

- [ ] Trigger on `v*` tags.
- [ ] Compute `sha256sum dbprofiler.py > dbprofiler.py.sha256`.
- [ ] Upload `dbprofiler.py` + `dbprofiler.py.sha256` to the GitHub Release for that tag.
- [ ] README documents the download-and-verify flow: `curl -O <url>/dbprofiler.py`, `curl -O <url>/dbprofiler.py.sha256`, `sha256sum -c dbprofiler.py.sha256`.
- [ ] Optional: also publish a signed provenance attestation via GitHub's built-in `actions/attest-build-provenance` — cheap to add, meaningful for security reviewers.

### Task 14: Verification and uncommitted handoff

- [ ] Run `python -m unittest -v` (unit tests).
- [ ] Run `python3 dbprofiler.py --check-safety`; expect exit 0.
- [ ] Run `python3 dbprofiler.py --version`.
- [ ] Bring up Docker PG 16; run `python -m unittest -v integration_test` against it; expect PASS.
- [ ] Optional: `ruff check` / `mypy --strict dbprofiler.py` if adopted.
- [ ] Run `git diff --check`, inspect status, and search tracked changes for credentials, URLs, debug prints, forbidden SQL tokens, and stray `print(env)` calls.
- [ ] Confirm `.env.test.local` is ignored and absent from diffs, logs, ZIPs, and reports.
- [ ] Report exact results, bundle contents, PostgreSQL 16 target, deferred features, and uncommitted files. Do not claim success if a required check fails.

## Completion criteria

- `python3 dbprofiler.py postgres` produces the approved bundle from a PostgreSQL 16 source.
- `python3 dbprofiler.py --check-safety` exits 0 against every commit in CI.
- Every FK has a fan-out estimate or explicit `insufficient_statistics`.
- Raw value statistics are tokenized before filesystem access.
- Query text in `pg_stat_statements.csv` is tokenized; `stats_reset` captured in `manifest.json`.
- Missing `pg_stat_statements` extension warns and omits the CSV; permission errors on stat views warn and omit; neither is fatal.
- Fingerprint mismatch or core failure prevents publication.
- No connection string or credential exists in source, committed configuration, docs, output, logs, or errors.
- Unit tests, `--check-safety`, and Docker PG 16 integration test all pass.
- Signed `dbprofiler.py` + SHA-256 published on tag via GitHub Releases.
- Adding a future source subcommand (e.g. `mysql`) requires only adding a new subparser + new `run_*()` function; shared helpers (`run_psql`, `tokenize`, `write_bundle`) stay reusable.
