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

That mode reads the tool's own source, enumerates every SQL statement it can issue, and
exits non-zero if any of them violates the boundary. CI runs it on every commit.

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
