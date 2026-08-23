# dbprofile MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `dbprofile.py`, a single-file open-source Python 3 script (stdlib only) that connects to a customer's PostgreSQL 16 server from a laptop or jumpbox and produces a shareable, checksummed source-profile bundle for CockroachDB migration planning — without scanning production user tables. The `postgres` subcommand handles PostgreSQL; the script's structure leaves room for future source subcommands (`mysql`, `oracle`, …) without restructuring.

**Distribution:** one `.py` file on GitHub Releases with a companion `dbprofile.py.sha256`. Customers download, verify, and run: `python3 dbprofile.py postgres --output source-profile.zip`.

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
- **Distribution is a signed `.py` file, not a compiled binary.** No GoReleaser, no cosign. GitHub Release ships `dbprofile.py` + `dbprofile.py.sha256`; auditors read every line before running.
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

Every SQL statement lives in a module-level constant named `SQL_*`. `python3 dbprofile.py --check-safety` reads its own source, greps every `SQL_*` constant for the forbidden tokens above, greps the whole file for `subprocess.*"...URL..."` patterns, and exits non-zero on any hit. CI runs this mode against every commit.

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
├── dbprofile.py                       # the entire tool: ~800–1200 lines
├── test_dbprofile.py                  # stdlib unittest — unit tests, guard test, golden files
├── integration_test.py                # stdlib unittest — Docker PG 16 end-to-end (opt-in)
├── testdata/
│   └── golden/                        # sanitized expected fixtures for normalize/tokenize
├── docker-compose.postgres-test.yml
├── .env.test.local                    # gitignored, never committed
├── .github/workflows/
│   ├── ci.yaml                        # python -m unittest, --check-safety, optional ruff
│   └── release.yaml                   # publish dbprofile.py + .sha256 on tag
├── docs/
│   ├── SCOPE.md                       # contract description
│   ├── SAFETY.md                      # safety boundary + audit walkthrough
│   └── TESTING.md                     # docker start/stop, running integration tests
├── README.md
├── LICENSE                            # MIT
└── .claude/rules/development.md
```

Everything the tool does lives in `dbprofile.py`. Auditors read one file. Tests are separate so the main file stays focused.

## Structure inside `dbprofile.py`

Organized top-to-bottom for readability by auditors:

1. Module header — license, contract version, safety-boundary comment block.
2. `SAFETY_FORBIDDEN` = list of forbidden SQL tokens; used by `--check-safety`.
3. `SQL_*` = every query as a module-level constant. Named so `--check-safety` can enumerate them by reflection.
4. `@dataclass` contract types: `Profile`, `Source`, `Table`, `Column`, `Relationship`, `FanOut`, `Manifest`, `Observation`, `Warning`.
5. `SafeEnv`, `redact_error()`, `run_psql()`, `run_pg_dump()` — subprocess helpers that pass credentials only via `env=` and redact stderr.
6. Collectors: `collect_catalog()`, `collect_workload()`, `collect_schema()`, `fingerprint()`.
7. `tokenize(value, domain)` — HMAC-SHA-256 with key from `DBPROFILE_TOKEN_KEY`.
8. `normalize_columns()`, `normalize_fk_fanout()` — post-processing on collected rows.
9. `write_bundle()` — atomic ZIP publication with per-payload SHA-256 and manifest-last serialization.
10. `run_postgres()` — the orchestration entry point registered under the `postgres` subcommand.
11. `main()` — `argparse` with subparsers: `postgres`, `--check-safety`, `--version`.

No connection string or credential may appear in the source, committed fixtures, docs, output, logs, or errors. Runtime code reads env vars; Compose substitutes values from `.env.test.local`.

## CLI shape

```bash
export DBPROFILE_POSTGRES_URL='postgres://...'   # customer-set locally; parsed once, never logged
export DBPROFILE_TOKEN_KEY='...'                 # HMAC key for tokenization

python3 dbprofile.py postgres \
  --output ./source-profile.zip \
  [--url <conn-string>] \                          # alternative to DBPROFILE_POSTGRES_URL
  [--schema-include <name>]... \
  [--schema-exclude <name>]... \
  [--pg-dump-path /usr/bin/pg_dump] \
  [--psql-path /usr/bin/psql] \
  [--timeout 300]                                  # seconds

python3 dbprofile.py --check-safety                # audit self-test; exit 0 = clean
python3 dbprofile.py --version                     # prints VERSION constant
```

`--url` is parsed into `PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD`/`PGDATABASE` env for child processes; never appears on argv of `psql` or `pg_dump`.

---

### Task 1: Repo bootstrap

**Files:** create `dbprofile.py` (skeleton with `VERSION`, `main()`, `--version`, `--check-safety` stubs), `test_dbprofile.py` (one passing sanity test), `LICENSE` (MIT), `README.md` skeleton, `.gitignore`, `.claude/rules/development.md`, `.github/workflows/ci.yaml`, optional `ruff.toml`.

- [ ] Confirm GitHub org / repo owner for the `dbprofile` repository.
- [ ] Write `LICENSE` with MIT text (current year, copyright holder).
- [ ] `.gitignore`: `.env.test.local`, `*.zip`, `__pycache__/`, `.pytest_cache/`, `dist/`.
- [ ] Seed `.claude/rules/development.md` fresh for a Python single-script project: describe `python -m unittest`, `--check-safety`, no pip deps, single-file discipline.
- [ ] CI workflow: matrix on `python-3.9`, `3.10`, `3.11`, `3.12`; run `python -m unittest -v`, `python3 dbprofile.py --check-safety`, `python3 dbprofile.py --version`, optional `ruff check`.
- [ ] Verify `python3 dbprofile.py --version` prints `dev`.

### Task 2: Config, argparse, and version enforcement

**Files:** extend `dbprofile.py`, `test_dbprofile.py`.

- [ ] Write failing tests for: env-sourced connection config (`DBPROFILE_POSTGRES_URL` and `--url`), URL parsing into `PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD`/`PGDATABASE`, `.zip` output validation, PostgreSQL major 16 assertion, schema include/exclude flag conflicts, `ContractVersion == "1.0"`. Use `unittest.mock.patch.dict(os.environ, ...)`; never embed a URL.
- [ ] Implement `argparse` with `postgres` subparser, `--check-safety`, `--version`.
- [ ] Implement URL parser (stdlib `urllib.parse`) → dict of libpq env vars; strip password before any log/repr.
- [ ] Implement server-version probe via `SELECT current_setting('server_version_num')::int`; require `>= 160000 AND < 170000` for MVP; error message must not leak connection details.
- [ ] Define `@dataclass` contract types (Profile, Source, Table, Column, Relationship, FanOut, Manifest, Warning, Observation). No `dict[str, Any]` in the public contract.
- [ ] Run focused tests; expect PASS.

### Task 3: Safe subprocess helpers and `--check-safety`

**Files:** extend `dbprofile.py`, `test_dbprofile.py`.

- [ ] Write failing tests for: `run_psql(sql, env)` never places SQL or credentials on argv beyond `-X -A -F, --csv -t -c <sql>`; credentials always flow through `env=`; stderr is redacted (URL-like strings, `password=` fragments, and libpq env values scrubbed); nonzero exit raises a wrapped exception without raw stderr.
- [ ] Write failing tests for `--check-safety`: enumerate every `SQL_*` constant via `inspect`/reflection; assert none contains `COUNT(`, `ANALYZE`, `CREATE STATISTICS`, or references to non-allowed relations (allowlist: `pg_catalog.*`, `pg_class`, `pg_namespace`, `pg_attribute`, `pg_type`, `pg_constraint`, `pg_index`, `pg_stats`, `pg_stats_ext`, `pg_stat_user_indexes`, `pg_stat_user_tables`, `pg_statio_user_indexes`, `pg_stat_statements`, `pg_stat_statements_info`, `pg_attrdef`, `pg_sequence`, `pg_description`).
- [ ] Implement `SafeEnv` builder, `run_psql`, `run_pg_dump`, `redact_error` with a deterministic redaction pattern list.
- [ ] Implement `--check-safety` mode.
- [ ] Run tests; expect PASS.

### Task 4: Schema extraction via `pg_dump`

**Files:** extend `dbprofile.py`, `test_dbprofile.py`.

- [ ] Write failing tests for: `pg_dump` discovery on `PATH` + `--pg-dump-path` override; `pg_dump` major must be >= server major (both 16 in MVP); command args contain `--schema-only --no-owner --no-privileges` and schema filters but no URL, username, or password; system-schema names rejected in `--schema-include` (catalog, toast, temporary); DDL captured to in-memory string; redacted errors on failure; deterministic schema-object fingerprint (SHA-256 over sorted `(schemaname, relname, relkind)` tuples from `pg_class` join `pg_namespace`, filtered to user schemas).
- [ ] Implement `collect_schema(cfg)` returning `(schema_sql: str, fingerprint: str)`; `collect_schema` runs `pg_dump` once and one fingerprint query.
- [ ] Implement separate `fingerprint(cfg)` for the after-collection recheck.
- [ ] Run tests; expect PASS.

### Task 5: Catalog-only observations

**Files:** extend `dbprofile.py`, `test_dbprofile.py`, `testdata/golden/`.

- [ ] Write failing golden tests for typed rows from `pg_class`, `pg_namespace`, `pg_attribute`, `pg_type`, `pg_constraint`, `pg_index`, `pg_stats`, `pg_stats_ext` using recorded `psql --csv` output as fixtures. Each fixture is sanitized: no real customer identifiers.
- [ ] Assert `SQL_*` constants for these collectors pass `--check-safety`.
- [ ] Implement `collect_catalog(cfg)` returning typed lists: tables (row/size estimates), columns (supported stats), FKs (ordered columns + actions), extended stats (multicolumn n-distinct/MCV).
- [ ] Detect partitioned/inherited tables (`relkind IN ('p','I')` or `pg_inherits` membership); fail with an unsupported-MVP error before any normalized output.
- [ ] Run tests; expect PASS.

### Task 6: Tier 1 workload telemetry

**Files:** extend `dbprofile.py`, `test_dbprofile.py`, `testdata/golden/`.

- [ ] Write failing tests for: `pg_stat_user_indexes` join with `pg_class` size; `pg_stat_user_tables` full column set; `pg_stat_statements` extension probe (installed vs. missing → warning + omit, never fatal); top-N selection (200 by `total_exec_time` unioned with 200 by `calls`, deduped by `queryid`); `pg_stat_statements_info.stats_reset` captured into manifest; HMAC tokenization of normalized query text — assert no raw literal from a fixture reaches disk.
- [ ] Extend `--check-safety` allowlist to include `pg_stat_statements` / `pg_stat_statements_info` and re-run the guard test.
- [ ] Implement `collect_workload(cfg)` returning three CSV-ready row lists plus a list of warnings.
- [ ] Assert permission errors on any of the three sources degrade to a manifest warning + omitted CSV, not a bundle failure.
- [ ] Run tests; expect PASS.

### Task 7: Tokenization

**Files:** extend `dbprofile.py`, `test_dbprofile.py`.

- [ ] Write failing tests proving equal typed source values in one FK domain produce equal tokens, different domains do not collide, UUIDs remain UUID-typed after tokenization (retain type provenance), and originals never serialize. Key read only from `DBPROFILE_TOKEN_KEY`; test asserts key is never present in captured stderr, stdout, exceptions, or bundle bytes.
- [ ] Implement `tokenize(value, domain)` using `hmac.new(key, f"{domain}\x00{repr_typed(value)}".encode(), hashlib.sha256).hexdigest()`. Key loaded once at process start; never logged, never written.
- [ ] Run tests; expect PASS.

### Task 8: Normalization

**Files:** extend `dbprofile.py`, `test_dbprofile.py`, `testdata/golden/`.

- [ ] Write failing golden tests for: reltuples, absolute vs. relative n-distinct (`n_distinct` negative → `abs(n_distinct) * row_count_estimate`), null fraction, width, MCV/frequency, histogram bounds, supported/unsupported types, extended n-distinct/MCV.
- [ ] Write failing single-FK fan-out tests using non-null child rows divided by distinct FK values; assert tokenized MCV frequencies preserve hot-parent shape.
- [ ] Write failing composite-FK fan-out tests requiring matching extended n-distinct; otherwise emit `insufficient_statistics`. Never multiply independent single-column estimates.
- [ ] Sort all output deterministically. Reserve PostgreSQL-native names for provenance/observations.
- [ ] Retain PostgreSQL semantics in `provenance` fields on every normalized record.
- [ ] Run tests; expect PASS.

### Task 9: Atomic bundle publication

**Files:** extend `dbprofile.py`, `test_dbprofile.py`.

- [ ] Write failing tests for: required entries present, sanitized CSVs (no raw literals), sorted safe entry paths, per-payload SHA-256 (excluding `manifest.json`) written into manifest, cleanup of temp ZIP on failure, atomic publication via `os.replace`, rejection of absolute paths / `..` / duplicates / symlinks / unexpected entries.
- [ ] Put a unique raw secret into an in-memory observation before serialization; assert it appears in neither the temp file nor the final ZIP bytes.
- [ ] Serialize only sanitized types. Hash uncompressed payload bytes. Serialize `manifest.json` last. Write to a temporary `.zip.tmp` file adjacent to destination; `close()`, `os.fsync()`, then `os.replace()`.
- [ ] Run tests; expect PASS.

### Task 10: Orchestration and `postgres` subcommand

**Files:** extend `dbprofile.py`, `test_dbprofile.py`.

- [ ] Write a failing orchestration test asserting the sequence: validate config → probe version → fingerprint-before → `pg_dump` → catalog collection → workload telemetry → tokenize → normalize → fingerprint-after → publish. Fingerprint mismatch, catalog failure, cancellation (SIGINT via `KeyboardInterrupt`), or any missing core artifact must prevent publication (no partial `.zip` on disk, no `.zip.tmp` leak).
- [ ] Assert no connection data (URL, `PGPASSWORD`, `PGUSER`) appears in `sys.stderr` capture, exception messages, or bundle contents across the full flow.
- [ ] Implement `run_postgres(args)` invoked from `main()` under the `postgres` subparser.
- [ ] Run tests; expect PASS.

### Task 11: Docker PostgreSQL 16 test environment

**Files:** `docker-compose.postgres-test.yml`, local `.env.test.local`, `docs/TESTING.md`.

- [ ] Ignore `.env.test.local` before creating it; verify `git check-ignore .env.test.local` exits 0.
- [ ] Define `postgres:16` service with named volume, localhost-only configured port, health check, `shared_preload_libraries=pg_stat_statements`. User/database/password/port fields must be `${...}` substitutions from `.env.test.local`; Compose contains no literal credentials or URL.
- [ ] Create local `.env.test.local` with Compose variables, `DBPROFILE_POSTGRES_URL`, `DBPROFILE_POSTGRES_TEST_URL`, and `DBPROFILE_TOKEN_KEY`. Never display or commit it.
- [ ] Start with `docker compose --env-file .env.test.local -f docker-compose.postgres-test.yml up -d --wait`; verify health without echoing env values.
- [ ] Post-start SQL: `CREATE EXTENSION pg_stat_statements;` in the target database.
- [ ] Document safe start, stop, reset, and test commands. Do not add a committed example env file containing a URL.

### Task 12: End-to-end integration test

**Files:** `integration_test.py`, `README.md`.

- [ ] Skip the test unless `DBPROFILE_POSTGRES_TEST_URL` and `DBPROFILE_TOKEN_KEY` are both set (use `unittest.skipUnless`). Read only via `os.getenv`; never print their values.
- [ ] Create a uniquely named disposable schema (e.g. `dbprofile_it_<epoch>`) with synthetic ordinary tables, scalar types, unsupported JSON/array columns, indexes, single/composite FKs, and multicolumn statistics. `ANALYZE` allowed only on these disposable fixtures.
- [ ] Seed enough activity (a few `SELECT`s repeated) to make `pg_stat_statements` non-empty for assertions.
- [ ] Run the profiler and validate: entries present, JSON well-formed, checksums verify, row/column shape correct, deterministic tokens present, no raw source values present, single/composite fan-out present, Tier 1 CSVs populated, `stats_reset` captured. Drop only the disposable schema in cleanup (`try/finally`).
- [ ] Update `README.md` with environment-only usage, PostgreSQL 16 / `pg_dump` prerequisites, safety boundary, `--check-safety` mode, bundle contents, and deferred features — without a literal URL.

### Task 13: Release plumbing

**Files:** `.github/workflows/release.yaml`.

- [ ] Trigger on `v*` tags.
- [ ] Compute `sha256sum dbprofile.py > dbprofile.py.sha256`.
- [ ] Upload `dbprofile.py` + `dbprofile.py.sha256` to the GitHub Release for that tag.
- [ ] README documents the download-and-verify flow: `curl -O <url>/dbprofile.py`, `curl -O <url>/dbprofile.py.sha256`, `sha256sum -c dbprofile.py.sha256`.
- [ ] Optional: also publish a signed provenance attestation via GitHub's built-in `actions/attest-build-provenance` — cheap to add, meaningful for security reviewers.

### Task 14: Verification and uncommitted handoff

- [ ] Run `python -m unittest -v` (unit tests).
- [ ] Run `python3 dbprofile.py --check-safety`; expect exit 0.
- [ ] Run `python3 dbprofile.py --version`.
- [ ] Bring up Docker PG 16; run `python -m unittest -v integration_test` against it; expect PASS.
- [ ] Optional: `ruff check` / `mypy --strict dbprofile.py` if adopted.
- [ ] Run `git diff --check`, inspect status, and search tracked changes for credentials, URLs, debug prints, forbidden SQL tokens, and stray `print(env)` calls.
- [ ] Confirm `.env.test.local` is ignored and absent from diffs, logs, ZIPs, and reports.
- [ ] Report exact results, bundle contents, PostgreSQL 16 target, deferred features, and uncommitted files. Do not claim success if a required check fails.

## Completion criteria

- `python3 dbprofile.py postgres` produces the approved bundle from a PostgreSQL 16 source.
- `python3 dbprofile.py --check-safety` exits 0 against every commit in CI.
- Every FK has a fan-out estimate or explicit `insufficient_statistics`.
- Raw value statistics are tokenized before filesystem access.
- Query text in `pg_stat_statements.csv` is tokenized; `stats_reset` captured in `manifest.json`.
- Missing `pg_stat_statements` extension warns and omits the CSV; permission errors on stat views warn and omit; neither is fatal.
- Fingerprint mismatch or core failure prevents publication.
- No connection string or credential exists in source, committed configuration, docs, output, logs, or errors.
- Unit tests, `--check-safety`, and Docker PG 16 integration test all pass.
- Signed `dbprofile.py` + SHA-256 published on tag via GitHub Releases.
- Adding a future source subcommand (e.g. `mysql`) requires only adding a new subparser + new `run_*()` function; shared helpers (`run_psql`, `tokenize`, `write_bundle`) stay reusable.
