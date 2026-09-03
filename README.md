# dbprofiler

Data and workload profiling for migrating workloads to CockroachDB, starting with PostgreSQL.

`dbprofiler` connects to a source database, collects a schema and a catalog-derived
data-shape profile, and writes a checksummed ZIP bundle you can share with a migration
team — **without scanning your tables**.

> **Status: pre-release.** The `postgres` subcommand collects and publishes a bundle,
> and the integration suite exercises it end to end against a live PostgreSQL 16. See
> `docs/superpowers/plans/` for the implementation plan.

## Safety boundary

The tool reads catalog and statistics views only. It does not scan user tables.

- No `COUNT(*)`, no table scans. Row counts come from `pg_class.reltuples`.
- No `ANALYZE` against your data. Statistics are read as PostgreSQL already computed them.
- No `CREATE STATISTICS`. Extended statistics are read only where they already exist.
- Credentials never appear on a child process command line, in logs, in errors, or in
  the bundle.

### What a bundle contains

The boundary is about *how* the tool reads, not about what the statistics happen to hold.
PostgreSQL's own statistics embed literal values from your tables — `pg_stats`
most-common values and histogram bounds, extended-statistics most-common value lists —
and `pg_stat_statements` records query text, which is normalized to `$1` placeholders for
DML but kept verbatim for utility statements. `dbprofiler` publishes all of that as
PostgreSQL computed it.

That is deliberate. The bundle's purpose is to drive synthetic data generation and
statistics injection on the target, and both need real value distributions: ordering,
range boundaries, skew, and physical clustering are exactly the properties a digest or a
token would destroy.

**Treat a bundle as carrying a sample of your data, and share it accordingly.** It is not
a full extract — a few hundred values per column at most — but it is not anonymized
either. Read `observations/pg_stats.csv` and `observations/pg_stat_statements.csv` in a
bundle before sending one anywhere you would not send a data sample.

### Mechanical enforcement

The boundary is enforced by the tool, not just documented:

```bash
python3 dbprofiler.py --check-safety
```

That mode reads the tool's own source and exits non-zero on any violation. It enumerates
every SQL statement the tool can issue and checks each one for forbidden operations and
against an explicit relation allowlist — there is no `pg_catalog` wildcard, because that
schema also holds password hashes and large objects. It then parses this file and
verifies there is exactly one child-process call site, that it passes an explicit
environment, that it never uses a shell, and that no connection string with credentials
is present in the source. CI runs it on every commit.

## Requirements

- Python 3.9 or newer. No third-party packages — standard library only.
- `psql` and `pg_dump` version 16 on `PATH`.
- A PostgreSQL 16 server, and a role that can read the catalog and statistics views.

## Install

Download the script and its checksum from the
[latest release](https://github.com/cockroachlabs/dbprofiler/releases/latest), verify,
then run:

```bash
curl -LO https://github.com/cockroachlabs/dbprofiler/releases/latest/download/dbprofiler.py
curl -LO https://github.com/cockroachlabs/dbprofiler/releases/latest/download/dbprofiler.py.sha256
sha256sum -c dbprofiler.py.sha256
```

On macOS, `shasum -a 256 -c dbprofiler.py.sha256` does the same thing.

The checksum proves the file survived the transfer. To prove it came from this
repository's release workflow and not from someone who could write to the release page,
verify the provenance attestation as well:

```bash
gh attestation verify dbprofiler.py --repo cockroachlabs/dbprofiler
```

That checks a signature made by GitHub's own OIDC identity for this repository, recording
which workflow built the artifact and from which commit. The release workflow publishes
the tagged file unmodified — no version stamping, no rewriting — so the bytes you verify
are the bytes in the tag, and `git show <tag>:dbprofiler.py | diff - dbprofiler.py` is
empty.

It is a single file with no dependencies, so you can read all of it before you run it.

## Usage

```bash
export DBPROFILER_POSTGRES_URL='postgres://...'   # parsed once, never logged

python3 dbprofiler.py postgres --output ./source-profile.zip
```

The connection string may also be passed with `--url`. Either way it is parsed into
libpq environment variables for the child processes and never placed on their command
lines.

Progress goes to stderr; stdout is the path of the bundle and nothing else, so
`OUT=$(python3 dbprofiler.py postgres --output ./source-profile.zip)` works. Restrict
the run with `--schema-include NAME` or `--schema-exclude NAME`, both repeatable.

The catalog is fingerprinted before and after collection. Each query is its own
transaction, so a migration running concurrently would otherwise produce a bundle that
mixed two versions of a schema; if the fingerprints disagree the run fails and writes
nothing. Cancelling with Ctrl-C leaves no partial bundle behind.

Two runs against an unchanged source produce byte-identical *payloads* — entries are
written in a fixed order, with a fixed archive timestamp, so the SHA-256 of every entry
in `manifest.json` can be compared between runs. The manifest itself records when the
collection ran, so the archive as a whole differs run to run by that one field.

## Bundle contents

```text
source-profile.zip
├── manifest.json          # written last; SHA-256 of every other payload
├── schema.sql             # pg_dump --schema-only --no-owner --no-privileges
├── profile.json           # normalized contract
└── observations/
    ├── pg_class.csv             # row and page counts, TOAST presence
    ├── pg_stats.csv             # per-column distribution, ordering, correlation
    ├── pg_stats_ext.csv         # multi-column distribution where it exists
    ├── pg_index.csv             # one row per index key position
    ├── pg_sequence.csv          # sequence parameters
    ├── foreign_keys.csv
    ├── pg_stat_indexes.csv
    ├── pg_stat_tables.csv
    └── pg_stat_statements.csv   # omitted with a warning if the extension is absent
```

`observations/` holds one CSV per statistics source, as close to what the source returned
as the format allows. `profile.json` is the normalized contract derived from them —
versioned, and the thing downstream tooling should read.

`manifest.json` records a SHA-256 of every other entry's uncompressed bytes, so a
recipient can verify the bundle without trusting the transport. It is written last,
after the payloads it hashes, and it lists a warning for every section that was omitted
— an unreadable statistics view or a missing extension degrades the bundle rather than
failing the run.

The bundle is published atomically. It is built in a temporary file beside the
destination, flushed to disk, and moved into place with a rename, so an interrupted run
leaves either the previous bundle or nothing — never a truncated archive.

## What this release does not do

Deliberately out of scope for now, so that what is here can be reviewed as a whole:

- **PostgreSQL 16 only.** Other majors are refused rather than approximated; the catalog
  and statistics shapes this reads are version-specific.
- **No other source types.** MySQL and Oracle would each be their own subcommand.
- **Tier 1 workload telemetry only** — table, index, and statement counters. Per-block
  I/O, replication, bgwriter and WAL, and function statistics are not collected.
- **No redaction or masking.** Statistics are published as PostgreSQL computed them.
  There is no mode that suppresses, hashes, or masks the values they contain.
- **No `--schema-file` or `--exclude-code`.** Scope is set with `--schema-include` and
  `--schema-exclude` only.
- **Coarse unsupported-type reporting.** A column is marked supported or not; the bundle
  does not classify *how* an unsupported type should be migrated.
- **No partial-collector recovery.** A statistics source that cannot be read is omitted
  with a warning; there is no retry and no fallback query.

## Development

```bash
python3 -m unittest -v            # unit tests
python3 dbprofiler.py --check-safety
ruff check                        # optional
```

Integration tests run against a local PostgreSQL 16 in Docker and are skipped unless
configured — a plain `python3 -m unittest` opens no sockets. They build a uniquely named
disposable schema, run the shipped script against it as a subprocess, check the bundle,
and drop the schema again:

```bash
python3 -m unittest integration_test -v
```

See `docs/TESTING.md` for the server and the configuration it needs.

## Releasing

```bash
# 1. Bump VERSION in dbprofiler.py, commit, merge to main.
# 2. Tag the merged commit.
git tag -a v1.2.3 -m 'v1.2.3'
git push origin v1.2.3
```

`.github/workflows/release.yaml` takes it from there: it runs the safety audit and the
unit suite on Python 3.9, refuses to continue if the tag disagrees with `VERSION`,
computes and re-verifies the checksum, attests build provenance, and creates the release
with `dbprofiler.py` and `dbprofiler.py.sha256` attached. It never edits the script, so
the asset is byte-identical to the tag.

`test_dbprofiler.py` holds guard tests over that workflow — trigger, step order,
permissions scope, action pinning, and the absence of any step that could rewrite the
script — so the release path is covered by the same suite as the tool.

## License

MIT. See [LICENSE](LICENSE).
