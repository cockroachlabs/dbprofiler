# dbprofile MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `dbprofile`, a standalone open-source Go CLI that connects to a customer's PostgreSQL server from a laptop or jumpbox and produces a shareable, checksummed source-profile bundle for CockroachDB migration planning — without scanning production user tables. The `postgres` subcommand handles PostgreSQL; the binary and package layout leave room for future source types (`mysql`, `oracle`, …) without restructuring.

**Why a new repo:** Decoupled from `workload-exporter`. Distributed as a single static binary via GoReleaser. Customers audit the source, download a signed binary, and run it from their own machine against a prod PG connection string.

**Tech Stack:** Go 1.23, Cobra, pgx v5, YAML v3, standard-library CSV/ZIP/HMAC-SHA-256, Docker Compose, PostgreSQL (target major TBD with customer — see below), external `pg_dump`, GoReleaser + cosign for release.

**Guidance:** Follow the new repo's `.claude/rules/development.md` (to be seeded from workload-exporter's). Do not commit unless the user explicitly authorizes it.

## Open items to confirm before Task 1

- **PostgreSQL major version.** Plan currently assumes PostgreSQL 16 based on prior scoping. Confirm the customer's actual server major before implementing the version check and integration fixtures. If they run 14 or 15, adjust the `pg_dump` major-match logic and integration `postgres:X` image. Older majors (≤12) will need re-validation of `pg_stats_ext` / `pg_stat_statements` column shapes.
- **GitHub org** for `github.com/<org>/dbprofile`.
- **Env-var namespace** confirmed as `DBPROFILE_POSTGRES_URL` (scoped so future `DBPROFILE_MYSQL_URL` etc. compose cleanly).

---

## MVP boundary

Included: direct PostgreSQL collection (target major TBD); `pg_dump` schema extraction; `pg_class.reltuples`; supported `pg_stats`; declared FKs; existing extended n-distinct/MCV statistics; single/composite FK fan-out; deterministic HMAC-SHA-256 tokenization of MCVs / histograms / query text; Tier 1 workload telemetry (`pg_stat_user_indexes`, `pg_stat_user_tables`, `pg_stat_statements`); and a checksummed ZIP containing the normalized contract and sanitized observations.

Deferred: configurable privacy policies, `--schema-file`, `--exclude-code`, validation artifacts, detailed unsupported-object classification, partial-collector recovery, PostgreSQL versions other than the confirmed target, non-Tier-1 workload telemetry (per-block I/O, replication, bgwriter/WAL, function stats), non-PostgreSQL source types.

Safety boundary — enforced by a guard test on query constants:

- No `COUNT(*)` or scans over user tables.
- No `ANALYZE` on customer data (only allowed on disposable integration fixtures).
- No `CREATE STATISTICS`.
- Only catalog views (`pg_catalog.*`, `pg_stat_*`, `pg_class`, `pg_namespace`, `pg_attribute`, `pg_type`, `pg_constraint`, `pg_index`, `pg_stats`, `pg_stats_ext`).
- Read-only `REPEATABLE READ` transaction with statement and lock timeouts.

## Workload telemetry scope (Tier 1)

Rationale: three PG runtime signals materially drive PG→CRDB sizing, index strategy, and compatibility-testing scope. Cache-hit ratios, per-block I/O, replication, and bgwriter/WAL are omitted — CRDB's storage/caching/distribution model makes them noise for planning.

- **`observations/pg_stat_indexes.csv`** — one row per user index, joining `pg_stat_user_indexes` with `pg_class` for size: `schema`, `table`, `index`, `idx_scan`, `idx_tup_read`, `idx_tup_fetch`, `size_bytes`. Surfaces unused indexes (`idx_scan == 0`) that should not be ported.
- **`observations/pg_stat_tables.csv`** — one row per user table from `pg_stat_user_tables`: `schema`, `table`, `seq_scan`, `seq_tup_read`, `idx_scan`, `idx_tup_fetch`, `n_tup_ins`, `n_tup_upd`, `n_tup_del`, `n_tup_hot_upd`, `n_live_tup`, `n_dead_tup`, `last_vacuum`, `last_autovacuum`, `last_analyze`, `last_autoanalyze`. Identifies full-scan hot spots and write mix.
- **`observations/pg_stat_statements.csv`** — top-N fingerprints (N=200 by `total_exec_time`, unioned with top-200 by `calls`, deduped by `queryid`): `queryid`, tokenized normalized query text, `calls`, `rows`, `total_exec_time`, `mean_exec_time`, `shared_blks_hit`, `shared_blks_read`, `shared_blks_dirtied`, `shared_blks_written`, `wal_bytes`. Query text is HMAC-tokenized under the same policy as MCVs. `manifest.yaml` records the `stats_reset` timestamp from `pg_stat_statements_info`.

Graceful degradation:

- `pg_stat_statements` extension not installed or user lacks privilege → emit a `warning` in `manifest.yaml`, omit the CSV, continue.
- Permission failure on `pg_stat_user_*` → warning + omit, not fatal.

## Bundle layout

```text
source-profile.zip
├── manifest.yaml                      # written last; holds SHA-256 of all other payload bytes
├── schema.sql                         # pg_dump --schema-only --no-owner --no-privileges
├── profile.yaml                       # normalized contract (ContractVersion "1.0")
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
├── cmd/
│   └── dbprofile/
│       └── main.go                    # Cobra root; registers `postgres` subcommand
├── pkg/
│   ├── postgres/                      # PostgreSQL-specific: config, collect, schema, normalize, cmd wiring
│   │   ├── cmd.go                     # `dbprofile postgres` Cobra command
│   │   ├── config.go
│   │   ├── collect/                   # catalog + Tier-1 workload SQL as `const`, guard test
│   │   ├── schema/                    # pg_dump shell-out, injected CommandRunner, fingerprint
│   │   ├── normalize/                 # n-distinct, FK fan-out, composite handling
│   │   └── orchestrator.go
│   ├── tokenize/                      # shared: HMAC-SHA-256 deterministic tokenization
│   ├── model/                         # shared: typed contract structs (no map[string]any)
│   └── bundle/                        # shared: atomic ZIP, manifest-last, sanitized CSV
├── .github/workflows/
│   ├── ci.yaml                        # go test / race / vet / lint
│   └── release.yaml                   # goreleaser + cosign on tag
├── .goreleaser.yaml
├── docker-compose.postgres-test.yml
├── .env.test.local                    # gitignored, never committed
├── docs/
│   ├── SCOPE.md                       # ports the source-profile-scope.md contract
│   ├── SAFETY.md                      # safety boundary + audit story
│   └── TESTING.md
├── README.md
├── go.mod                             # module github.com/<org>/dbprofile
├── LICENSE                            # MIT
└── .claude/rules/development.md
```

Shared packages (`tokenize`, `model`, `bundle`) intentionally live outside `pkg/postgres/` so a future `pkg/mysql/` or `pkg/oracle/` can reuse them without churn.

No connection string or credential may appear in Go source, committed fixtures, documentation examples, Compose files, or logs. Runtime code reads environment variables; Compose substitutes values from `.env.test.local`.

## CLI shape

```bash
export DBPROFILE_POSTGRES_URL='postgres://...'   # customer-set locally
export DBPROFILE_TOKEN_KEY='...'                 # HMAC key for tokenization (shared across source types)

dbprofile postgres \
  --output ./source-profile.zip \
  [--url <conn-string>] \                          # alternative to DBPROFILE_POSTGRES_URL
  [--schema-include <name>]... \
  [--schema-exclude <name>]... \
  [--pg-dump-path /usr/bin/pg_dump] \
  [--timeout 5m]
```

Only these flags exist in MVP. `dbprofile --version` prints the build tag. `dbprofile --help` shows registered source subcommands; MVP registers only `postgres`.

---

### Task 1: Repo bootstrap

**Files:** create `go.mod`, `LICENSE` (MIT), `README.md` skeleton, `.gitignore`, `.claude/rules/development.md`, `.github/workflows/ci.yaml`, `.golangci.yml`, `cmd/dbprofile/main.go` (empty Cobra root + `--version`), `Makefile` (optional).

- [ ] Confirm PostgreSQL target major, GitHub org, and env-var namespace (see "Open items").
- [ ] `go mod init github.com/<org>/dbprofile`; add `github.com/spf13/cobra`, `github.com/jackc/pgx/v5`, `gopkg.in/yaml.v3`.
- [ ] Write `LICENSE` with the MIT text and current year / copyright holder.
- [ ] Add `.gitignore` covering `.env.test.local`, `dist/`, `dbprofile` binary, `*.zip` fixtures.
- [ ] Seed `.claude/rules/development.md` from workload-exporter's, dropping CRDB-specific bits and renaming binary references.
- [ ] Add CI workflow running `go vet`, `go test ./...`, `go test -race ./...`, `golangci-lint run --timeout=5m`.
- [ ] Verify `go build -o dbprofile ./cmd/dbprofile && ./dbprofile --version` prints `dev`.

### Task 2: Contract types and configuration

**Files:** `pkg/postgres/config.go`, `pkg/model/`, tests.

- [ ] Write failing tests for env-sourced connection config, `.zip` output validation, PostgreSQL major-version assertion (parameterized on the confirmed target), schema include/exclude conflicts, contract version `1.0`. Use `t.Setenv`; never embed a URL.
- [ ] Define explicit YAML structs for profile, source, tables, columns, relationships, fan-out, column groups, provenance, manifest, artifacts, warnings, and observations. Avoid `map[string]any` in the public contract.
- [ ] Implement `Config`, validation, `New(ctx, config)`, `Run(ctx)`, and idempotent `Close(ctx)` signatures with injectable dependencies.
- [ ] Compare fields with `docs/SCOPE.md`.

```go
const ContractVersion = "1.0"
func New(ctx context.Context, config Config) (*Profiler, error)
func (p *Profiler) Run(ctx context.Context) error
func (p *Profiler) Close(ctx context.Context) error
```

### Task 3: Safe pg_dump schema extraction

**Files:** `pkg/postgres/schema/`, tests.

- [ ] Write failing tests for executable discovery, `pg_dump` major >= server major, target-major enforcement (from the confirmed version), system-schema rejection, schema-arg construction, redacted errors, deterministic fingerprints.
- [ ] Assert command arguments contain `--schema-only --no-owner --no-privileges` and schema filters but no URL, username, password, or env value.
- [ ] Implement injected `CommandRunner`; locate `pg_dump`; pass libpq settings only through child environment; capture DDL in memory; redact child errors.
- [ ] Select all non-system schemas by default; support repeatable include/exclude filters; reject catalog, toast, temporary schemas.
- [ ] Compute SHA-256 fingerprints from sorted catalog schema-object identities before and after collection; mismatch is fatal.

### Task 4: Catalog-only observations

**Files:** `pkg/postgres/collect/catalog.go`, tests.

- [ ] Write failing mock tests requiring a read-only `REPEATABLE READ` transaction, local statement/lock timeouts, fixed catalog queries, commit, and rollback on error.
- [ ] Implement typed collection from `pg_class`, `pg_namespace`, `pg_attribute`, `pg_type`, `pg_constraint`, `pg_index`, `pg_stats`, `pg_stats_ext`.
- [ ] Collect table row/size estimates, supported column statistics, ordered FK columns/actions, existing multicolumn n-distinct/MCV statistics.
- [ ] Detect partitioned/inherited tables and fail with an unsupported-MVP error before normalized output.
- [ ] Add a guard test asserting query constants contain no `COUNT(`, `ANALYZE`, `CREATE STATISTICS`, or non-catalog relation reads.

### Task 5: Tier 1 workload telemetry

**Files:** `pkg/postgres/collect/workload.go`, tests.

- [ ] Write failing tests for: `pg_stat_user_indexes` join with `pg_class` size; `pg_stat_user_tables` full column set; `pg_stat_statements` extension probe (installed vs. missing → warning + omit, never fatal); top-N selection (200 by `total_exec_time` unioned with 200 by `calls`, deduped by `queryid`); `pg_stat_statements_info.stats_reset` captured into manifest; HMAC tokenization of normalized query text with no raw literal reaching disk.
- [ ] Extend the guard test to cover these queries — still only `pg_stat_*` and catalog views, no user relations.
- [ ] Assert permission errors on any of the three sources degrade to a manifest warning and omitted CSV, not a bundle failure.

### Task 6: Tokenization and normalization

**Files:** `pkg/tokenize/`, `pkg/postgres/normalize/`, tests, sanitized golden files.

- [ ] Write failing tests proving equal typed source values in one FK domain produce equal tokens, different domains do not collide, UUIDs remain UUIDs, and originals never serialize. Read the HMAC key only from an environment variable (`DBPROFILE_TOKEN_KEY`).
- [ ] Implement deterministic HMAC-SHA-256 tokenization entirely in memory; never store/log the key or unsanitized value observations.
- [ ] Write failing golden tests for reltuples, absolute/relative n-distinct, null fraction, width, MCV/frequency, histogram, supported/unsupported types, extended n-distinct/MCVs.
- [ ] Normalize negative `n_distinct` as `abs(n_distinct) * row_count_estimate`; retain PostgreSQL semantics in provenance.
- [ ] Write failing single-FK tests using non-null child rows divided by distinct FK values, with tokenized MCV frequencies representing hot-parent shape.
- [ ] Write failing composite-FK tests requiring matching extended n-distinct; otherwise emit `insufficient_statistics`. Never multiply independent single-column estimates.
- [ ] Sort all output deterministically; reserve PostgreSQL-native names for provenance/observations.

### Task 7: Atomic profile bundle

**Files:** `pkg/bundle/`, tests.

- [ ] Write failing tests for required entries, sanitized CSVs, sorted safe paths, payload checksums excluding `manifest.yaml`, cleanup on failure, atomic publication.
- [ ] Put a unique raw secret into an in-memory observation and assert it appears in neither temporary files nor final ZIP bytes.
- [ ] Serialize only sanitized types. Hash uncompressed payload bytes, serialize manifest last, write a temporary ZIP adjacent to the destination, close/fsync, and rename atomically.
- [ ] Reject absolute paths, `..`, duplicates, symlinks, and unexpected entries.

### Task 8: Orchestration and CLI wiring

**Files:** `pkg/postgres/orchestrator.go`, `pkg/postgres/cmd.go`, `cmd/dbprofile/main.go`, tests.

- [ ] Write a failing orchestration test requiring: validate, connect, version check, fingerprint-before, `pg_dump`, catalog collection, workload telemetry, tokenize, normalize, fingerprint-after, publish.
- [ ] Prove version mismatch, catalog failure, concurrent DDL, cancellation, or missing core output never publishes a ZIP.
- [ ] Implement orchestration without logging connection data.
- [ ] Wire Cobra: root `dbprofile` registers `postgres` subcommand from `pkg/postgres/cmd.go`. Accept connection through `DBPROFILE_POSTGRES_URL` or `--url`; docs/integration use the env without showing its value.
- [ ] Add only these flags: `--output`, `--url`, `--schema-include`, `--schema-exclude`, `--pg-dump-path`, `--timeout`.

### Task 9: Docker PostgreSQL test environment

**Files:** `docker-compose.postgres-test.yml`, local `.env.test.local`, `docs/TESTING.md`.

- [ ] Ignore `.env.test.local` before creating it; verify `git check-ignore .env.test.local`.
- [ ] Define `postgres:<TARGET_MAJOR>` (from confirmed version) with named volume, localhost-only configured port, health check, `pg_stat_statements` preloaded. User/database/password/port fields must be `${...}` substitutions from `.env.test.local`; Compose contains no literal credentials or URL.
- [ ] Create local `.env.test.local` with Compose variables, `DBPROFILE_POSTGRES_URL`, `DBPROFILE_POSTGRES_TEST_URL`, and `DBPROFILE_TOKEN_KEY`. Never display or commit it.
- [ ] Start with `docker compose --env-file .env.test.local -f docker-compose.postgres-test.yml up -d --wait`; verify health without echoing env values.
- [ ] Document safe start, stop, reset, and test commands. Do not add a committed example env file containing a URL.

### Task 10: End-to-end integration test

**Files:** `pkg/postgres/integration_test.go`, `README.md`.

- [ ] Add `//go:build integration`; read test URL / token key only with `os.Getenv`, never print their values.
- [ ] Create a uniquely named disposable schema with synthetic ordinary tables, scalar types, unsupported JSON/array columns, indexes, single/composite FKs, and multicolumn statistics. `ANALYZE` is allowed only on these disposable fixtures.
- [ ] Seed enough activity to make `pg_stat_statements` non-empty for assertions.
- [ ] Run the profiler and validate: entries, YAML shape, checksums, row/column shape, deterministic tokens present, no raw source values present, single/composite fan-out present, Tier 1 CSVs populated, `stats_reset` captured. Drop only the disposable schema in cleanup.
- [ ] Update `README.md` with environment-only usage, PostgreSQL target major / `pg_dump` prerequisites, safety boundary, bundle contents, and deferred work — without a literal URL.

### Task 11: Release plumbing (GoReleaser + cosign)

**Files:** `.goreleaser.yaml`, `.github/workflows/release.yaml`.

- [ ] Configure GoReleaser to build for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`.
- [ ] Emit `checksums.txt` (SHA-256).
- [ ] Sign checksums with cosign (keyless, GitHub OIDC).
- [ ] Release workflow triggers on `v*` tags, uploads binaries + checksums + signature to GitHub Releases.
- [ ] README documents the download-and-verify flow.

### Task 12: Verification and uncommitted handoff

- [ ] Run `go fmt ./...`, `go vet ./...`, `golangci-lint run --timeout=5m`.
- [ ] Run `go test ./...` and `go test -race ./...`.
- [ ] Run the tagged PostgreSQL integration test.
- [ ] Run `go build -ldflags="-X main.Version=v0.0.0-test" -o dbprofile ./cmd/dbprofile`; verify `--version` and `postgres --help`.
- [ ] Dry-run GoReleaser locally (`goreleaser release --snapshot --clean --skip=publish`); verify per-platform binaries.
- [ ] Run `git diff --check`, inspect status, search tracked changes for credentials, URLs, debug prints, forbidden profiler SQL.
- [ ] Confirm `.env.test.local` is ignored and absent from diffs, logs, ZIPs, and reports.
- [ ] Report exact results, bundle contents, PostgreSQL target-major limitation, deferred features, and uncommitted files. Do not claim success if a required check fails.

## Completion criteria

- `dbprofile postgres` produces the approved bundle from a PostgreSQL source at the confirmed target major.
- Every FK has a fan-out estimate or explicit `insufficient_statistics`.
- Raw value statistics are tokenized before filesystem access.
- Query text in `pg_stat_statements.csv` is tokenized; `stats_reset` captured in manifest.
- Missing `pg_stat_statements` extension warns and omits the CSV; permission errors on stat views warn and omit; neither is fatal.
- Concurrent DDL or core failure prevents publication.
- No connection string or credential exists in source, committed configuration, docs, output, or logs.
- No profiler query scans or modifies source user tables (guard test passes).
- Unit, race, vet, lint, build, integration, and GoReleaser dry-run checks all pass.
- Signed binary artifacts published on tag via GitHub Releases.
- Repo layout supports adding future source subcommands (`mysql`, `oracle`, …) without restructuring shared packages.
