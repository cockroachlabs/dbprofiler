# PostgreSQL Profile MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `workload-exporter postgres profile`, exporting a PostgreSQL 16 schema and catalog-derived data-shape profile without scanning production tables.

**Architecture:** Preserve the existing CockroachDB exporter. Add one `pkg/postgresprofile` package for collection, normalization, tokenization, and ZIP publication, with compact wiring in `cmd/export.go`. Verify it against Docker PostgreSQL 16 configured only through a gitignored `.env.test.local`.

**Tech Stack:** Go 1.23, Cobra, pgx v4, YAML v3, standard-library CSV/ZIP/SHA-256, Docker Compose, PostgreSQL 16, external `pg_dump`.

**Guidance:** Follow `.claude/rules/development.md`. Keeping the command in `cmd/export.go` is the approved exception to its new-command file convention. Do not commit unless the user explicitly authorizes it.

---

## MVP boundary

Included: PostgreSQL 16 direct collection; `postgres profile`; pg_dump schema extraction; `pg_class.reltuples`; supported `pg_stats`; declared FKs; existing extended n-distinct/MCV statistics; single/composite FK fan-out; deterministic MCV tokenization; migration-relevant workload telemetry (Tier 1 below); and a checksummed ZIP containing the normalized contract and sanitized observations.

Deferred: configurable privacy policies, `--schema-file`, `--exclude-code`, validation artifacts, detailed unsupported-object classification, partial-collector recovery, PostgreSQL versions other than 16, non-Tier-1 workload telemetry (see below), and `pkg/artifact` refactoring.

### Workload telemetry scope (Tier 1, included in MVP)

Rationale: migrating to CockroachDB, three PG runtime signals materially drive sizing, index strategy, and compatibility-testing scope. Cache-hit ratios, per-block I/O, replication, bgwriter/WAL, and per-function stats are omitted — CRDB's storage/caching/distribution model makes them noise for planning.

- **`observations/pg_stat_indexes.csv`** — one row per user index, joining `pg_stat_user_indexes` with `pg_class` for size: `schema`, `table`, `index`, `idx_scan`, `idx_tup_read`, `idx_tup_fetch`, `size_bytes`. Purpose: surface unused indexes (`idx_scan == 0`) that should not be ported, since every CRDB index costs writes and range space.
- **`observations/pg_stat_tables.csv`** — one row per user table from `pg_stat_user_tables`: `schema`, `table`, `seq_scan`, `seq_tup_read`, `idx_scan`, `idx_tup_fetch`, `n_tup_ins`, `n_tup_upd`, `n_tup_del`, `n_tup_hot_upd`, `n_live_tup`, `n_dead_tup`, `last_vacuum`, `last_autovacuum`, `last_analyze`, `last_autoanalyze`. Purpose: identify full-scan hot spots (CRDB penalizes large seq scans harder than PG) and write mix for range-split/contention prediction.
- **`observations/pg_stat_statements.csv`** — top-N fingerprints (N=200 by `total_exec_time`, unioned with top-200 by `calls`) from `pg_stat_statements`: `queryid`, tokenized normalized query text, `calls`, `rows`, `total_exec_time`, `mean_exec_time`, `shared_blks_hit`, `shared_blks_read`, `shared_blks_dirtied`, `shared_blks_written`, `wal_bytes`. Query text is HMAC-tokenized under the same policy as MCVs — never raw literals. `manifest.yaml` records the `stats_reset` timestamp from `pg_stat_statements_info` so the consumer knows the observation window.

Behavior when extensions/views are unavailable:
- `pg_stat_statements` extension not installed or user lacks privileges → emit a `warning` entry in `manifest.yaml`, omit the CSV, continue. Never fatal.
- `pg_stat_user_indexes` / `pg_stat_user_tables` are core views and always present; permission failure on either is a warning + omit, not fatal.

Safety boundary is unchanged: these are catalog/stat views only, no user-table scans, no `ANALYZE`, no `COUNT(*)`.

No profiler query may run `COUNT(*)`, scan user tables, run `ANALYZE`, or support partitions/inheritance.

## Source layout

```text
cmd/export.go
pkg/postgresprofile/
├── profile.go          # orchestration and public API
├── model.go            # profile/manifest/observation structs
├── schema.go           # pg_dump and schema fingerprint
├── catalog.go          # catalog-only collection
├── normalize.go        # normalized statistics and fan-out
├── tokenize.go         # deterministic safe tokens
├── bundle.go           # CSV/YAML/checksums/atomic ZIP
└── *_test.go
docker-compose.postgres-test.yml
.env.test.local         # ignored, never committed
docs/TESTING.md
README.md
```

No connection string or credential may appear in Go source, committed fixtures, documentation examples, or Compose. Runtime code reads environment variables; Compose substitutes values from `.env.test.local`.

---

### Task 1: Contract types and configuration

**Files:** Create `pkg/postgresprofile/model.go`, `profile.go`, and `profile_test.go`; modify `go.mod`/`go.sum`.

- [ ] Write failing tests for environment-sourced connection configuration, `.zip` output validation, PostgreSQL major 16, schema include/exclude conflicts, and contract version `1.0`. Use `t.Setenv`; never embed a URL.
- [ ] Run `go test ./pkg/postgresprofile -run 'TestConfig|TestVersion' -count=1`; expect compile failure.
- [ ] Define explicit YAML structs for profile, source, tables, columns, relationships, fan-out, column groups, provenance, manifest, artifacts, warnings, and observations. Avoid `map[string]any` in the public contract.
- [ ] Add YAML with `go get gopkg.in/yaml.v3@v3.0.1 && go mod tidy`.
- [ ] Implement `Config`, validation, `New(ctx, config)`, `Run(ctx)`, and idempotent `Close(ctx)` signatures with injectable dependencies.
- [ ] Run the focused tests; expect PASS. Compare fields with `docs/source-profile-scope.md`.

```go
const ContractVersion = "1.0"
func New(ctx context.Context, config Config) (*Profiler, error)
func (p *Profiler) Run(ctx context.Context) error
func (p *Profiler) Close(ctx context.Context) error
```

### Task 2: Safe pg_dump schema extraction

**Files:** Create `pkg/postgresprofile/schema.go` and `schema_test.go`.

- [ ] Write failing tests for executable discovery, pg_dump major >= server major, PostgreSQL 16 enforcement, system-schema rejection, schema arguments, redacted errors, and deterministic fingerprints.
- [ ] Assert command arguments contain `--schema-only --no-owner --no-privileges` and schema filters but no URL, username, password, or environment value.
- [ ] Run `go test ./pkg/postgresprofile -run 'TestPGDump|TestSchema' -count=1`; expect failure.
- [ ] Implement an injected `CommandRunner`, locate pg_dump, pass libpq settings only through child environment, capture DDL in memory, and redact child errors.
- [ ] Select all non-system schemas by default and support repeatable include/exclude filters. Reject catalog, toast, and temporary schemas.
- [ ] Calculate SHA-256 fingerprints from sorted catalog schema-object identities before and after collection; mismatch is fatal.
- [ ] Run focused tests; expect PASS and no credentials in output.

### Task 3: Catalog-only observations

**Files:** Create `pkg/postgresprofile/catalog.go` and `catalog_test.go`.

- [ ] Write failing mock tests expecting a read-only `REPEATABLE READ` transaction, local statement/lock timeouts, fixed catalog queries, commit, and rollback on error.
- [ ] Implement typed collection from `pg_class`, `pg_namespace`, `pg_attribute`, `pg_type`, `pg_constraint`, `pg_index`, `pg_stats`, and `pg_stats_ext`.
- [ ] Collect table row/size estimates, supported column statistics, ordered FK columns/actions, and existing multicolumn n-distinct/MCV statistics.
- [ ] Detect partitioned/inherited tables and fail with an unsupported-MVP error before normalized output.
- [ ] Add a guard test asserting query constants contain no `COUNT(`, `ANALYZE`, `CREATE STATISTICS`, or non-catalog relation reads.
- [ ] Run `go test ./pkg/postgresprofile -run TestCatalog -count=1`; expect PASS.

### Task 3b: Tier 1 workload telemetry

**Files:** Create `pkg/postgresprofile/workload.go` and `workload_test.go`; extend `catalog.go`/`bundle.go` wiring.

- [ ] Write failing tests for: `pg_stat_user_indexes` join with `pg_class` size; `pg_stat_user_tables` full column set; `pg_stat_statements` extension probe (installed vs. missing → warning + omit, never fatal); top-N selection (200 by `total_exec_time` unioned with 200 by `calls`, deduped by `queryid`); `pg_stat_statements_info.stats_reset` captured into manifest; HMAC tokenization of normalized query text with no raw literal reaching disk.
- [ ] Assert queries touch only `pg_stat_*` and `pg_class`/`pg_namespace` catalog views — no user relations, no `ANALYZE`, no `COUNT(*)`.
- [ ] Assert permission errors on any of the three sources degrade to a manifest warning and omitted CSV, not a bundle failure.
- [ ] Run `go test ./pkg/postgresprofile -run 'TestWorkload|TestStatStatements' -count=1`; expect PASS.

### Task 4: Tokenization and normalization

**Files:** Create `tokenize.go`, `tokenize_test.go`, `normalize.go`, `normalize_test.go`, `relationships_test.go`, and sanitized golden files under `pkg/postgresprofile/`.

- [ ] Write failing tests proving equal typed source values in one FK domain produce equal tokens, different domains do not collide, UUIDs remain UUIDs, and originals never serialize. Read the HMAC key only from an environment variable.
- [ ] Implement deterministic HMAC-SHA-256 tokenization entirely in memory; never store/log the key or unsanitized value observations.
- [ ] Write a failing golden test for reltuples, absolute/relative n-distinct, null fraction, width, MCV/frequency, histogram, supported/unsupported types, and extended n-distinct/MCVs.
- [ ] Normalize negative n-distinct as `abs(n_distinct) * row_count_estimate`; retain PostgreSQL semantics in provenance.
- [ ] Write failing single-FK tests using non-null child rows divided by distinct FK values, with tokenized MCV frequencies representing hot-parent shape.
- [ ] Write failing composite-FK tests requiring matching extended n-distinct; otherwise emit `insufficient_statistics`. Never multiply independent single-column estimates.
- [ ] Sort all output deterministically and reserve PostgreSQL-native names for provenance/observations.
- [ ] Run `go test ./pkg/postgresprofile -run 'TestToken|TestNormalize|Test.*Fanout|TestComposite' -count=1`; expect PASS.

### Task 5: Atomic profile bundle

**Files:** Create `pkg/postgresprofile/bundle.go` and `bundle_test.go`.

- [ ] Write failing tests for required entries, sanitized CSVs, sorted safe paths, payload checksums excluding `manifest.yaml`, cleanup on failure, and atomic publication.
- [ ] Put a unique raw secret in an in-memory observation and assert it appears in neither temporary files nor ZIP bytes.
- [ ] Serialize only sanitized types. Hash uncompressed payload bytes, serialize manifest last, write a temporary ZIP adjacent to the destination, close/fsync, and rename atomically.
- [ ] Reject absolute paths, `..`, duplicates, symlinks, and unexpected entries.
- [ ] Run `go test ./pkg/postgresprofile -run TestBundle -count=1`; expect PASS.

```text
source-profile.zip
├── manifest.yaml
├── schema.sql
├── profile.yaml
└── observations/
    ├── pg_class.csv
    ├── pg_stats.csv
    ├── pg_stats_ext.csv
    ├── foreign_keys.csv
    ├── pg_stat_indexes.csv
    ├── pg_stat_tables.csv
    └── pg_stat_statements.csv       # omitted with warning if extension absent
```

### Task 6: Orchestration and compact CLI wiring

**Files:** Modify `pkg/postgresprofile/profile.go` and `cmd/export.go`; add orchestration/command tests.

- [ ] Write a failing orchestration test requiring: validate, connect, version check, fingerprint-before, pg_dump, catalog collection, tokenize, normalize, fingerprint-after, publish.
- [ ] Prove version mismatch, catalog failure, concurrent DDL, cancellation, or missing core output never publishes a ZIP.
- [ ] Implement orchestration without logging connection data.
- [ ] Write failing CLI tests proving `export`, `postgres`, and `postgres profile` exist and existing export flags/defaults remain unchanged.
- [ ] Add the compact Cobra declarations to `cmd/export.go`. Accept connection through `POSTGRES_PROFILE_URL` or explicit `--url`; docs/integration use the environment without showing its value.
- [ ] Add output, schema include/exclude, pg_dump path, and timeout flags only.
- [ ] Run tests, `go build -o workload-exporter .`, and both command help pages; expect new functionality with unchanged `export` behavior.

### Task 7: Real Docker PostgreSQL 16 environment

**Files:** Create `docker-compose.postgres-test.yml` and local `.env.test.local`; modify `.gitignore` and `docs/TESTING.md`.

- [ ] Ignore `.env.test.local` before creating it; verify `git check-ignore .env.test.local`.
- [ ] Define `postgres:16` with named volume, localhost-only configured port, and health check. User/database/password/port fields must be `${...}` substitutions from `.env.test.local`; Compose contains no literal credentials or URL.
- [ ] Create local `.env.test.local` with Compose variables, `POSTGRES_PROFILE_URL`, `POSTGRES_PROFILE_TEST_URL`, and token key. Never display or commit it.
- [ ] Start with `docker compose --env-file .env.test.local -f docker-compose.postgres-test.yml up -d --wait`; verify health without echoing environment values.
- [ ] Document safe start, stop, reset, and test commands. Do not add a committed example env file containing a URL.

### Task 8: PostgreSQL 16 end-to-end test

**Files:** Create `pkg/postgresprofile/integration_test.go`; modify `README.md`.

- [ ] Add `//go:build integration`; read test URL/token key only with `os.Getenv`, and never print their values.
- [ ] Create a uniquely named disposable schema containing synthetic ordinary tables, scalar types, unsupported JSON/array columns, indexes, single/composite FKs, and multicolumn statistics. `ANALYZE` is allowed only on these disposable fixtures.
- [ ] Run the profiler and validate entries, YAML, checksums, row/column shape, presence of deterministic tokens, absence of raw source values, and single/composite fan-out. Drop only the disposable schema in cleanup.
- [ ] Run `go test -tags=integration -v ./pkg/postgresprofile/ -run TestIntegrationProfile -count=1`; expect PASS against Docker PostgreSQL 16.
- [ ] Update README with environment-only usage, PostgreSQL 16/pg_dump prerequisites, safety boundary, bundle, limitations, and deferred work—without a literal URL.

### Task 9: Verification and uncommitted handoff

- [ ] Run `go fmt ./...`, `go vet ./...`, and `golangci-lint run --timeout=5m`.
- [ ] Run `go test ./...` and `go test -race ./...`.
- [ ] Run the tagged PostgreSQL 16 integration test.
- [ ] Run `go build -ldflags="-X main.Version=v0.0.0-test" -o workload-exporter .`; verify version and both help pages.
- [ ] Run `git diff --check`, inspect status, and search tracked changes for credentials, URLs, debug prints, and forbidden profiler SQL.
- [ ] Confirm `.env.test.local` is ignored and absent from diffs, logs, ZIPs, and reports.
- [ ] Report exact results, bundle contents, PostgreSQL 16 limitation, deferred features, and uncommitted files. Do not claim success if a required check fails.

## Completion criteria

- Existing `workload-exporter export` behavior is unchanged.
- `workload-exporter postgres profile` creates the approved bundle.
- The Docker PostgreSQL 16 end-to-end test passes.
- No connection string or credential exists in source, committed configuration, docs, output, or logs.
- No profiler query scans or modifies source user tables.
- Every FK has a fan-out estimate or explicit insufficient status.
- Raw value statistics are tokenized before filesystem access.
- Concurrent DDL or core failure prevents publication.
- Unit, race, vet, lint, build, and integration checks pass.
