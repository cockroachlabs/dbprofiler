---
name: dbworkload-kit
description: Drive the whole path from a source database to a running reproduction - collect a bundle, generate a kit, fill the stubs it leaves (correlated keys, synthetic identifiers, the workload), load, and verify. Use when asked to profile a database, build a reproduction, generate synthetic data from a profile bundle, or finish a generated kit.
---

# From a source database to a running reproduction

Five steps. `dbprofiler` does steps 0 and 1; the rest is judgement work this skill
carries, because per-column statistics cannot supply it.

    0. collect    dbprofiler postgres   -> a bundle (.zip)
    1. generate   dbprofiler generate   -> a kit (8 files, 2 of them stubs)
    2. keys       fill keys.py          <- joins do not resolve until this is done
    3. values     classify the MCVs     <- vocabulary stays, identifiers get synthesized
    4. workload   fill workload.py      <- transcribed from pg_stat_statements
    5. load       reproduce.sh          -> a loaded, validated database

Read `<kit>/README.md` before starting step 2: it records what was derived for that
specific bundle and lists its TODOs with the tables they apply to.

## Workspace

Keep one directory per profiled database and let everything land in it. The kit defaults
to a sibling of its bundle, so naming the bundle is enough:

    ~/profile-bundles/<database>/
      <database>.zip         the bundle
      <database>-kit/        the kit, created beside it

A bundle and the kit derived from it belong together — same scale, same schema, same key
space — and a kit is meaningless beside a different bundle. Never keep bundles inside a
source repository: one carries a sample of real data, and `dbprofiler`'s own `.gitignore`
excludes them for that reason.

## 0. Collect

```bash
export DBPROFILER_POSTGRES_URL='postgres://...'   # parsed once, never logged
python3 dbprofiler.py postgres --output ~/profile-bundles/<database>/<database>.zip
```

Restrict scope with `--schema-include` / `--schema-exclude`, both repeatable. The tool
reads catalog and statistics views only — no table scans, no `ANALYZE` — so it is safe
against production, and `--check-safety` proves that claim mechanically.

stdout is the bundle path and nothing else, so `OUT=$(python3 dbprofiler.py postgres ...)`
works. If collection fails on a changed catalog fingerprint, a migration was running;
re-run when none is in flight rather than retrying blindly.

**Treat the bundle as carrying a sample of the source data.** It holds most-common values,
histogram bounds and query text as PostgreSQL computed them. Share it accordingly, and
never commit one.

## 1. Generate

```bash
python3 dbprofiler.py generate --bundle <bundle.zip|dir> [--output DIR] \
        --scale N --procs 8 [--schema NAME]
```

`--output` defaults to a `-kit` directory beside the bundle, which is usually what you
want. The kit includes `schema.crdb.sql` — a CockroachDB schema grouped one section per
table, with index recommendations — which `reproduce.sh` applies unless `--schema-file`
names another. Read its recommendations before loading: an unindexed foreign key or a
monotonic primary key will shape how the reproduction behaves under load. It carries no
CHECK constraints or partial-index predicates; those are in the bundle's `schema.sql`. `--bundle` takes a `.zip` or an extracted directory at any path, and a bundle that
has been re-zipped (a single top-level folder prefix) is read as well as a fresh one.

- `--scale` divides every row count. Pick it from how much disk the target has and how
  long a load can take; the kit README prints source and generated counts side by side.
- `--procs` is **part of the data definition**, not a speed setting. dbworkload derives
  one sub-seed per generation process from it, so the same definition generated with a
  different `-x` is different data. Whatever is chosen here must be used for every
  `dbworkload util csv -x`, and any key generator must be keyed on the same number.
- `--schema` is required when the bundle covers more than one.

Read the generated YAML before going further. It is output, not source — fix the bundle,
the scale, or the generator, and regenerate. Hand edits to it are lost.

**Regenerating is safe once work has started.** Re-running `generate` over an existing kit
refreshes the derived files and keeps any `keys.py` or `workload.py` that differs from a
fresh stub, reporting each one it kept. So changing `--scale` after implementing the key
generator costs nothing. `--force` overrides that and replaces the stubs — it discards
whatever was written in them, so only use it to start over deliberately.

## 2. Correlated keys — `keys.py`

**Do this first. Nothing else matters until it is done.** Every column is generated
independently, so a child's foreign key holds a value that almost certainly does not
exist in its parent, and every join in the workload returns nothing.

The foreign keys and the fan-out each must reproduce are in `keys.py`'s docstring.

The pattern that works: dbworkload expands a YAML `seed` into one sub-seed per generation
process, so two columns in two tables sharing a seed and generated with the same `-x` get
the same sub-seed in the same process. Make every value a **pure function of (sub-seed,
row ordinal)**. Nothing is materialised, no column needs to know what another emitted, and
each process's key space stays disjoint — which is what keeps primary keys unique once the
per-process chunks are concatenated.

Work out the key *shape* from the bundle's `histogram_bounds` for the key columns: segment
layout, width, nesting and per-level fan-out all drive index size, comparison cost and
join selectivity. Reproduce the shape; synthesize the identifiers.

Name the module so the class name resolves. dbworkload derives it from the filename, and
the rule changed across versions: older releases capitalize the whole name, newer ones
capitalize each part and also try all-caps. `keys.py` → `Keys` works everywhere. A module
name with an underscore needs every spelling bound to the one class, and the aliases must
come after any `sys.modules` canonicalisation block so they track the surviving class.

## 3. Taxonomy versus identifiers — the YAML

Most-common values are reproduced verbatim. Go through them and split into two groups:

- **A closed vocabulary** — statuses, types, categories, enumerations. Keep verbatim. The
  schema's CHECK constraints and the workload's predicates are written against these
  exact strings, and changing them changes which rows match.
- **Real data** — identifiers, URIs, account numbers, hostnames, emails. Replace with
  synthetic values of the same **shape, width and cardinality**, under an obviously
  reserved namespace. Width and cardinality drive index size and join cost, so preserve
  them; the literal bytes are a sample of someone's data.

A column is usually identifiers if its values are high-cardinality, structurally uniform,
and carry an embedded UUID, digit run, or domain. Keep one mapping for a value that
appears in several tables, so they still agree.

## 4. The workload — `workload.py`

`observations/pg_stat_statements.csv` carries statement text, call count and total
execution time for every shape the source ran. That is the source of truth; do not invent
a workload.

- Transcribe the shapes that matter. Weight by **call count**, not by guess. Keeping the
  weights in the counters' own units rather than percentages keeps rare-but-expensive
  paths expressible.
- Anchor read transactions by dividing a shape's call count by the statements-per-
  transaction the read side averages; anchor writes on whichever statement runs once per
  transaction.
- Record what you did **not** model and why. The source's own foreign-key probes
  (`SELECT 1 ... FOR KEY SHARE`) arrive automatically with the inserts, and monitoring
  agents polling the catalog are platform, not application.
- Reuse the key space from `keys.py` so a read can name a row instead of hunting for one.

Fill `BOOTSTRAP` with reference rows the load's foreign keys point at — re-runnable, so a
second bootstrap conflicts rather than duplicates. Fill `FINALIZE` with what the bulk load
cannot produce: derived tables, sequence values past the loaded maximum, and the
empty-string fixup (loading with `NULL ''` turns a real empty string into NULL).

## 5. Load and verify

Two ways to run it. `dbprofiler reproduce` does the whole path in one command, reading
`DBPROFILER_POSTGRES_URL` and `DBPROFILER_TARGET_URL`; `--bundle` or `--kit` resumes from
a later stage, and `--steps` runs a subset. The kit's own
`reproduce.sh` does the same and adds the workload run, `--recreate-database` and
`--concurrency`; `--start-at` / `--stop-after` make each step re-runnable.

Expect the load to stop while `keys.py` is a stub — on a duplicate key for any unique
column that is not a uuid, or on a foreign key violation. Both are the stub, not the data
path, and both errors say so.

The target comes from `DSN`, else `DBPROFILER_TARGET_URL`, else whatever `--target-url`
recorded when the kit was generated — the mirror of `DBPROFILER_POSTGRES_URL` on the
collection side. A recorded target is stored **without its username or password**, since
a kit gets copied and shared; supply those with `PGUSER` and `PGPASSWORD`.

```bash
export PGUSER=someone
read -rs PGPASSWORD && export PGPASSWORD
./reproduce.sh --stop-after load
```

Non-negotiable checks after any bulk import:

- **Validate every foreign key.** A bulk import may not enforce them while loading and may
  leave them marked valid afterwards, so a missed file is silent corruption rather than an
  error. The `validate` step does this; never skip it.
- **Check row counts** per table against the YAML's `count`.
- **Truncate before retrying.** Importing appends.

## Traps

- **`constant` with a fractional `null_pct` is not reproducible.** SimpleFaker's dispatcher
  discards `seed` for that generator, so it reseeds from OS entropy and the output changes
  every run. Adding `seed:` does not help. Use a one-element `choice`. `generate` never
  emits `constant`; keep it that way when editing by hand.
- **YAML 1.1 needs a decimal point and a signed exponent** before it reads a number as a
  float. `5e-05` loads as the *string* `5e-05` and fails deep inside the generator. Write
  `5.0e-05`.
- **Generators are single-pass.** A streaming loader that fails partway cannot resume —
  truncate that table and start it over.
- **`search_path` belongs in the connection URI**, not in a `SET`. dbworkload calls a
  workload's `setup()` once per thread, so a connection reopened after an error never gets
  the `SET` again and every later statement fails with a misleading "relation does not
  exist". Spell it `-csearch_path=NAME` with no space: dbworkload rebuilds the URI when it
  stamps `application_name`, and a space becomes `+`, which libpq does not decode.
- **Check which dbworkload is on PATH.** Multiple installs differ in how they resolve a
  custom generator's class name. Verify a change under each one you use.

## Boundaries

- `generate` opens no connection and starts no child process. Keep it that way: the safety
  audit permits exactly one subprocess call site in `dbprofiler.py` and the collector owns
  it.
- A bundle carries a sample of a real database. Never commit one, and never paste its
  statistics values into a public repository, an issue, or a commit message.
- Nothing about a particular source database belongs in `dbprofiler.py`, its tests, or
  this file. Every name in a kit is read from the bundle at run time.
