# Golden fixtures

Recorded `psql --csv -t` output, one file per `SQL_*` constant. Every value here is
synthetic. There are no real customer identifiers, hostnames, or data values in this
directory, and there must never be: a reviewer grepping this repository for a leak has
to be able to tell fixture data from the real thing at a glance.

Conventions that match what `psql --csv -t` actually emits:

- No header row — `-t` suppresses it.
- `NULL` renders as an empty field.
- `boolean` renders as `t` or `f`.
- Array-valued columns are cast to `text` in the query, so they arrive as
  `{a,b,c}` and are quoted by CSV when they contain a comma.

Email-like values use the `.invalid` TLD, which RFC 2606 reserves so it can never
resolve.

`statements.csv` records `pg_stat_statements` output. Its query text is deliberately
representative of the worst case: normalized statements with `$1` placeholders, one
statement carrying an unnormalized literal, and one `queryid` appearing twice. Those
three shapes are what the top-N dedup and the tokenization tests are written against.
