# dbprofiler

Data and workload profiling for migrating workloads to CockroachDB, starting with PostgreSQL.

`dbprofiler` connects to a source database, collects a schema and a catalog-derived
data-shape profile, and writes a checksummed ZIP bundle you can share with a migration
team — **without reading your data**.

> **Status: pre-release.** The `postgres` subcommand is not implemented yet. See
> `docs/superpowers/plans/` for the implementation plan.

## Safety boundary

The tool reads catalog and statistics views only. It does not scan user tables.

- No `COUNT(*)`, no table scans. Row counts come from `pg_class.reltuples`.
- No `ANALYZE` against your data. Statistics are read as PostgreSQL already computed them.
- No `CREATE STATISTICS`. Extended statistics are read only where they already exist.
- Credentials never appear on a child process command line, in logs, in errors, or in
  the bundle.

Catalog statistics can still embed literal values — `pg_stats` most-common values and
histogram bounds, and query text in `pg_stat_statements`. Every such value is replaced
by an HMAC-SHA-256 token before it reaches disk. Equal values tokenize equally within a
domain, which preserves the join and skew shape a migration needs without disclosing the
values themselves.

This is enforced mechanically, not just documented:

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

It is a single file with no dependencies, so you can read all of it before you run it.

## Usage

```bash
export DBPROFILER_POSTGRES_URL='postgres://...'   # parsed once, never logged
export DBPROFILER_TOKEN_KEY='...'                 # HMAC key for tokenization

python3 dbprofiler.py postgres --output ./source-profile.zip
```

The connection string may also be passed with `--url`. Either way it is parsed into
libpq environment variables for the child processes and never placed on their command
lines.

`DBPROFILER_TOKEN_KEY` is read from the environment only — never from an argument, so it
cannot appear in a process listing — and there is no default, because a default would
tokenize every deployment identically. Keep it: re-running with the same key produces
comparable tokens, and a different key makes two bundles impossible to correlate.

## Bundle contents

```text
source-profile.zip
├── manifest.json          # written last; SHA-256 of every other payload
├── schema.sql             # pg_dump --schema-only --no-owner --no-privileges
├── profile.json           # normalized contract
└── observations/
    ├── pg_class.csv
    ├── pg_stats.csv
    ├── pg_stats_ext.csv
    ├── foreign_keys.csv
    ├── pg_stat_indexes.csv
    ├── pg_stat_tables.csv
    └── pg_stat_statements.csv   # omitted with a warning if the extension is absent
```

`manifest.json` records a SHA-256 of every other entry's uncompressed bytes, so a
recipient can verify the bundle without trusting the transport. It is written last,
after the payloads it hashes, and it lists a warning for every section that was omitted
— an unreadable statistics view or a missing extension degrades the bundle rather than
failing the run.

The bundle is published atomically. It is built in a temporary file beside the
destination, flushed to disk, and moved into place with a rename, so an interrupted run
leaves either the previous bundle or nothing — never a truncated archive.

## Development

```bash
python3 -m unittest -v            # unit tests
python3 dbprofiler.py --check-safety
ruff check                        # optional
```

Integration tests run against a local PostgreSQL 16 in Docker and are skipped unless
configured. See `docs/TESTING.md`.

## License

MIT. See [LICENSE](LICENSE).
