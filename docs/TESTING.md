# Testing

Three suites, in increasing order of what they need from you.

| Suite | Command | Needs |
| --- | --- | --- |
| Safety audit | `python3 dbprofiler.py --check-safety` | nothing |
| Unit | `python3 -m unittest -v` | nothing |
| Integration | `python3 -m unittest integration_test -v` | a local PostgreSQL 16 |

The first two open no sockets and start no containers. Run both before every commit;
CI runs them on every push.

## The safety audit

```bash
python3 dbprofiler.py --check-safety
```

Reads the tool's own source and exits non-zero on a violation: a SQL constant containing
a forbidden operation, a relation outside the allowlist, more than one child-process call
site, a missing `env=`, a `shell=`, or a credentialed URL literal. It is the check that
has to pass; the others tell you whether the tool works, this one tells you whether it is
still safe.

## Unit tests

```bash
python3 -m unittest -v
```

No network, no database, no container. Collector tests replay recorded `psql --csv`
output from `testdata/golden/`; every value in there is synthetic.

## Integration tests

These run the whole tool against a real PostgreSQL 16 and are **skipped unless
configured**, so a plain `python3 -m unittest` stays offline. They need two environment
variables:

- `DBPROFILER_POSTGRES_TEST_URL` — a connection string for a database you are willing to
  have fixtures created and dropped in.
- `DBPROFILER_TOKEN_KEY` — any non-empty string.

### Configuration lives in `.env.test.local`

Create that file yourself; it is gitignored and must never be committed, echoed, or
pasted into an issue. Confirm before you write anything into it:

```bash
git check-ignore -v .env.test.local   # must print a .gitignore line and exit 0
```

It defines, one `NAME=value` per line:

| Variable | Used by |
| --- | --- |
| `DBPROFILER_TEST_PGUSER` | Compose, as `POSTGRES_USER` |
| `DBPROFILER_TEST_PGPASSWORD` | Compose, as `POSTGRES_PASSWORD` |
| `DBPROFILER_TEST_PGDATABASE` | Compose, as `POSTGRES_DB` |
| `DBPROFILER_TEST_PGPORT` | Compose, the loopback port to publish |
| `DBPROFILER_POSTGRES_URL` | the tool, when you run it by hand |
| `DBPROFILER_POSTGRES_TEST_URL` | the integration suite |
| `DBPROFILER_TOKEN_KEY` | tokenization |

Both URLs point at `127.0.0.1` on `DBPROFILER_TEST_PGPORT` with the user, password, and
database above. There is deliberately no committed example file: an example env file is
where a real connection string eventually gets pasted, and nobody reviewing the diff can
tell that the value in it was supposed to be fake.

Pick throwaway values. The container is disposable and reachable only from this machine.

### Start the server

Every Compose subcommand interpolates the file, so every one of them needs
`--env-file` — not just `up`. An alias keeps that from being something you can forget:

```bash
alias pgtest='docker compose --env-file .env.test.local -f docker-compose.postgres-test.yml'
pgtest up -d --wait
```

`--wait` blocks until the health check passes, so the next command cannot race the first
connection. The Compose file publishes the port on `127.0.0.1` only, starts the server
with `shared_preload_libraries=pg_stat_statements`, and runs
`testdata/postgres-test-init.sql` on first boot to create the extension in the target
database.

Check it without printing anything secret:

```bash
pgtest ps --format '{{.Name}} {{.Status}}'
pgtest exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -Atc "select extname from pg_extension"'
```

The credentials are expanded by the shell inside the container, from the environment the
server already has, so they never appear in your history or in the command line of a
process on your machine. You should see `pg_stat_statements` listed; if you do not, the
volume predates the init script — see the reset below.

Podman works too: `docker compose` delegates to `podman-compose` if that is what is
installed. The Compose file uses no Docker-specific extension. Verified against
PostgreSQL 16.15 under Podman 5.8.

### Run the suite

```bash
set -a; . ./.env.test.local; set +a
python3 -m unittest integration_test -v
```

`set -a` exports each assignment as it is read, and `set +a` turns that back off; nothing
is echoed. Prefer a subshell — `( set -a; . ./.env.test.local; set +a; python3 -m unittest
integration_test -v )` — if you would rather the variables not outlive the run.

If the suite reports skips instead of results, one of the two required variables is
unset. Check which without revealing a value:

```bash
for v in DBPROFILER_POSTGRES_TEST_URL DBPROFILER_TOKEN_KEY; do
  [ -n "${!v-}" ] && echo "$v set" || echo "$v MISSING"
done
```

### Stop, and reset

```bash
# Stop, keep the data.
pgtest down

# Stop and delete the volume. Do this after changing the init script or the
# server command line -- the init script only runs against an empty volume, so
# a stale volume will not have the extension.
pgtest down -v
```

`down -v` destroys the test database. That is the intent: nothing in it is worth keeping,
and a reused volume is how a fixture from an earlier run leaks into a later assertion.

## Before you commit

```bash
python3 dbprofiler.py --check-safety
python3 -m unittest -v
ruff check          # optional, development-only
git diff --staged   # read it for credentials, URLs, and debug prints
```

Nothing about the tool needs `ruff` or `mypy` at runtime; they are development aids and
must never become dependencies.

## A note on writing tests here

For anything that writes a bundle, assert the negative. Plant a unique value in the
input and prove the exact bytes on disk do not contain it — searching the archive as
stored *and* every member decompressed, because a DEFLATE-compressed literal is invisible
to a search of the raw file. `zip_bytes()` in `test_dbprofiler.py` does both.
