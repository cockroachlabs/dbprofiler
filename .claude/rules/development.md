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
  the three may appear in any `SQL_*` constant; `--check-safety` enforces that.

### Three kinds of SQL

`SQL_*` constants are statements issued against a **source** database. The forbidden
tokens must never appear in one, and every relation they read must be on the allowlist.

`TARGET_SQL_*` constants are issued against a **reproduction target** the operator built
and named. Refreshing that target's planner statistics is the right thing to do, so
`ANALYZE` is allowed there. `COUNT(` and `CREATE STATISTICS` are not: a loaded
reproduction can be enormous, nothing here needs a row count, and inventing statistics
the source did not have would make the reproduction lie. `--check-safety` audits them on
that rule, and `audit_target_sql()` is where it lives.

### Statements issued versus artifacts written

The ban above governs what this tool *issues*. `SQL_*` constants are statements sent to a
source database, and the forbidden tokens must never appear in one.

`EMIT_*` constants are different in kind: they are the text of files the `generate`
subcommand *writes*, which an operator later runs against a reproduction database they
built themselves. A script that bulk-loads a target and then refreshes its planner
statistics is doing the right thing, and it is not reaching a source. So `EMIT_*` may
contain `ANALYZE`.

It may not contain anything else on the list. `COUNT(*)` stays banned everywhere, emitted
text included — a generated script that scans a table teaches the wrong habit, and an
emptiness check has `SELECT 1 ... LIMIT 1`. `--check-safety` audits `EMIT_*` for
credentials, and the unit suite asserts that no emitted file contains `COUNT(`.

The boundary that makes this safe is structural rather than textual, and it is tested:
`generate` opens no connection and starts no child process. `audit_subprocess_usage()`
permits exactly one subprocess call site in the whole file and the collector owns it, so
a second one anywhere — including in the generate path — fails the audit.
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
