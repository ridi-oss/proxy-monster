# Derived-projection masking

A masked column used in a provably-total, side-effect-free string transform is
redacted in full — the output ordinal is blanked with mask kind `NULL` — instead
of denying the whole statement. This is a strict, whitelist-gated widening; the
conservative DENY floor is unchanged for everything else.

## Problem

`SELECT id, name, upper(email), left(phone, 3) FROM customers` would deny the
whole statement because `upper(email)` and `left(phone, 3)` are computed outputs
over masked columns, even though the caller only wants a displayable,
non-reversible form. This is the common display case, and it can be served
safely for a narrow, proven set of transforms.

## Why "redact the output cell and execute the expression" is not safe in general

Blanking the output cell does not stop the query from executing on the raw
value, and execution has side channels the proxy cannot mask:

- Error presence / SQLSTATE. A value-conditional error is a per-bit oracle.
  `SELECT 1/(CASE WHEN ssn LIKE '90%' THEN 0 ELSE 1 END)` (PostgreSQL) errors
  iff a row matches; `CAST('x' AS JSON)` and `EXP(710)` are hard errors on both
  engines. Diagnostic redaction
  ([diagnostic-redaction.md](./diagnostic-redaction.md)) strips the error text,
  but the client still sees that the statement errored and the SQLSTATE/essno.
  Loop over prefixes and reconstruct the value.
- Warning count. MySQL puts a `warning_count` in the OK packet.
  `CAST(CASE WHEN … THEN 'x' ELSE '1' END AS UNSIGNED)` warns iff the branch
  matches, so the count is an oracle. The `SHOW WARNINGS` deny closes the
  warning text, not the OK-packet count.

A conditional is not even required — arithmetic and coercion fault on the value
directly. `1/(ASCII(SUBSTRING(ssn,1,1)) - 115)` faults iff the first character
is `s`; `POW(1e300, ASCII(SUBSTRING(ssn,1,1)) - 100)` overflows past a threshold
(a comparison done arithmetically, so binary-searchable);
`CAST(SUBSTRING(ssn,1,1) AS UNSIGNED)` warns iff the character is not a digit.
These are exploitable against a real masking proxy, single-row-targeted via a
non-sensitive `WHERE id = N`, so the row cap does not help.

So a blacklist cannot be sound: "does this expression fault" is itself a
predicate on the value, and arithmetic overflow/division and type coercion fault
intrinsically. You would have to exclude conditionals, comparisons, all
arithmetic, and all casts/parsers — everything but total string transforms.

## The safe set — a positive whitelist of provably-total operations

A projection is redactable iff its whole expression tree is built only from:

- the masked column, as a pure identity reference (see the nested rule);
- literals; and
- whitelisted total, side-effect-free string functions, with every numeric /
  non-string argument a literal — so a numeric position (`SUBSTRING`
  start/length, `LEFT`/`RIGHT` n) cannot carry the column into a coercion, and
  no fault-capable subexpression hides in a non-string slot.

The whitelist (extend cautiously — each entry must be total on every
engine/version): `UPPER`, `LOWER`, `INITCAP`,
`SUBSTRING`/`SUBSTR`/`MID`/`LEFT`/`RIGHT`, `TRIM`/`LTRIM`/`RTRIM`, `REPLACE`,
`CONCAT`, `REVERSE`, `COALESCE`, `LENGTH`/`CHAR_LENGTH`, `MD5`/`SHA1`, `HEX`.
Anything else in the tree — cast/`::`, arithmetic, comparison, `CASE`/`IF`, the
`||` concat operator, JSON/date/regex/geometry/decode,
aggregate/window/subquery, or any non-whitelisted call — denies.

### Nested rule (subquery / CTE / derived table)

A column leaf is redactable only if it resolves as a pure identity to a base
column. A column that resolves (one or more scopes down) to a non-identity
derivation is denied, because an oracle can hide there:
`SELECT c FROM (SELECT cast(ssn AS json) AS c) t`, or even
`SELECT upper(c) FROM (…)`, would otherwise pass a surface whitelist check while
the cast still executes in the subquery. Failing closed here also denies a safe
transform hidden in a subquery — accepted over-restriction.

Row-shaping uses of the masked column — predicate, join, `ORDER BY`, `GROUP BY`,
`DISTINCT`, set-op — still deny via the reference-context rule (the reference
walk runs before redaction), independent of the whitelist.

## Design

- Analyzer (`analyzer/probe/probe.go`): `OriginInfo.Derived`.
  `redactableTransform(proj)` implements the whitelist + literal-numeric-arg +
  identity-column-leaf walk; the probe marks a projection `Derived=true` only
  when it holds. Otherwise the projection stays a plain derived reference and
  denies. A `SELECT DISTINCT` query and a set-op-branch site also stay plain
  derived references.
- Control-plane grant walk (`Query.kt`): a masked base of a derived origin
  carries `MaskedDisposition.MASKED_DISPOSITION_REDACT_OUTPUT_NULL` and is
  redacted with mask kind `NULL` — a value-independent, type-safe full blank,
  valid for every column type where a fixed text token would be a wire type
  mismatch. A denied base still denies. A direct identity projection masks with
  the column's own kind.
- Proxy: no change — `engine.applyMaskKind` (`goproxy/engine/masking.go`)
  already renders `NULL` to nil.

## Tests

- `analyzer/probe/derived_masking_test.go`: `TestRedactableWhitelistGate`
  (MySQL + PostgreSQL) locks the boundary — total transforms redact;
  cast/arithmetic/`CASE`/comparison/overflow/coercion-arg and subquery-hidden
  transforms deny. `TestDerivedProjectionFacts` locks the per-ordinal facts.
- Control-plane: `GateSqlglotRegressionTest` (`upper(ssn)` redacts to mask kind
  `NULL`; the whitelist redact/deny split; hidden-in-derived-table denies),
  `EnforcementDbTest` (cast/arithmetic deny), `SchemaThreadingDbTest` (whole-row
  JSON deny).

## Known limitations

- Totality assumes built-in resolution. The whitelist matches a bare built-in
  name/kind; sqlglot cannot distinguish a user-defined function named
  `upper`/`left`/`md5` from the built-in, so a same-named UDF would route
  through the total path. Mitigated by `sql.ddl`-gated function creation and the
  operational rule that a masking datasource carries no data-reading UDFs
  ([KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md)); a schema-qualified call
  (`app.upper(ssn)`) is not matched and denies.
- `CONCAT` is total except at `max_allowed_packet` (MySQL): a result exceeding
  the packet limit yields NULL plus a warning, so a ~64 MB padded literal is a
  per-row length (not value) oracle — impractical, but noted; prefer
  length-bounded forms if tightened.
- Over-restriction, safe by design: the `||` concat operator, `CONCAT_WS`, a
  whitelisted transform hidden in a subquery, `COALESCE` with a
  non-string-literal fallback, and a function absent on the target engine
  (`hex`/`quote` on PostgreSQL) currently deny or constant-error. Widen later
  only with proof of totality. `CONCAT_WS` denies because it parses as an
  anonymous call (unlike `CONCAT`, which has its own node kind) and no
  `concat_ws` entry exists in the anonymous-function whitelist.
- Each whitelisted function must be re-checked total per engine/version
  (`REPEAT`/`LPAD` only with a small literal count — excluded for now).
- `GROUP BY` / `DISTINCT` redaction is not reconsidered here.
