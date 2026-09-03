# Development rules

This repository ships a single auditable Python script. The rules below exist to keep
that property true.

## Single-file discipline

- Everything the tool does lives in `dbprofiler.py`. Do not split it into a package.
  The value proposition is that a customer's security reviewer reads one file top to
  bottom before running it against production.
- Tests live outside it: `test_dbprofiler.py` (unit) and `integration_test.py` (Docker).
- Keep the section order in `dbprofiler.py` intact — safety block, `SQL_*` constants,
  contract dataclasses, subprocess helpers, collectors, normalization, bundle
  publication, orchestration, entry point. Reviewers read in that order.

## No dependencies

- Standard library only. No `pip install`, no `requirements.txt`, no vendored code.
- `ruff` and `mypy` are development-only and must never be needed at runtime.
- Support Python 3.9 and newer. Use `from __future__ import annotations` rather than
  syntax that only parses on newer versions.

## Safety boundary

The boundary is about how the tool reads, not about what the statistics contain. Values
from `pg_stats`, `pg_stats_ext`, and `pg_stat_statements` are published as PostgreSQL
computed them, because ordering, skew, and clustering are what downstream data generation
and statistics injection need. Do not add redaction, hashing, or masking: it was removed
deliberately. A bundle carries a sample of the source data, and the README says so.

- Every SQL statement must be a module-level constant named `SQL_*`. This is not style:
  `--check-safety` enumerates them by reflection, and a query built inline is a query the
  audit cannot see.
- Never issue `COUNT(*)`, `ANALYZE`, or `CREATE STATISTICS` against customer data. None of
  the three may appear in `dbprofiler.py` at all; `--check-safety` enforces that.
- `ANALYZE`, `CREATE STATISTICS`, and the DDL and DML around them are permitted in
  `integration_test.py`, and only there, against the uniquely named disposable schema that
  test creates and drops. That is not a loophole in the boundary: the tool reads statistics
  rather than computing them, so something has to compute them before there is anything to
  read. `COUNT(*)` is likewise permitted there, but only to prove a fixture really holds
  what the test planted in it. Assert the profiler's own numbers against sizes the seed
  makes predictable, never against a count queried at assertion time: a count would agree
  with a broken estimator that happened to be wrong in the same direction.
- Query only allowlisted catalog and statistics relations.
- Run `python3 dbprofiler.py --check-safety` before every commit. CI runs it too.
- When you add a collector, add its relations to the `--check-safety` allowlist in the
  same change, and add a guard test.

## Credentials

- No real connection string or credential in source, tests, fixtures, docs, output,
  logs, or error messages.
- Tests that must exercise connection strings use only these synthetic values, so that
  a reviewer grepping for a leak can tell test data from the real thing at a glance:
  host `db.invalid` (`.invalid` is reserved by RFC 2606 and can never resolve), user
  `example-user`, password `example-password`, database `example-db`. Do not invent
  new ones.
- Credentials reach child processes only through `env=`, never through `argv`.
- Every `DBPROFILER_*` variable is stripped from every child environment. The tool's own
  configuration is the tool's; a child gets libpq variables and nothing else.
- Redact subprocess stderr before it is surfaced. Assume every error path is printed.
- `.env.test.local` holds local test configuration, is gitignored, and is never
  displayed, echoed, or committed.

## Testing

- Test-driven: write the failing test first, then the implementation.
- `python3 -m unittest -v` must pass before any commit.
- Integration tests are opt-in and skip unless `DBPROFILER_POSTGRES_TEST_URL` is set.
- Collector tests use recorded, sanitized `psql --csv` fixtures in `testdata/golden/`.
  No real customer identifiers in fixtures.
- For anything that writes a bundle, plant a unique value and assert on the exact output
  bytes. Which way the assertion runs depends on what was planted: statistics are
  published deliberately, so a planted statistic value must be proven *present and
  intact* — that catches a dropped column or a mangled separator, which absence would
  not. A credential has no route into a bundle, so for credentials the assertion stays
  negative.

## Committing

- Do not commit unless the user explicitly authorizes it.
- Before committing, check the diff for credentials, URLs, debug prints, and forbidden
  SQL tokens.

## Public repository

This repository is public. Anything written here — code, comments, docs, commit
messages, issue and PR text — is publicly visible. Do not reference internal systems,
internal repositories, or customer names.
