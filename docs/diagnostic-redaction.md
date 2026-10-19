# Diagnostic-message value redaction — the DB error/warning side-channel

Masking rewrites result rows. But a database's own warning / error / notice
messages echo the raw, stored value that enforcement is meant to hide, and the
proxy relays those diagnostics to the client verbatim. The diagnostic channel is
therefore an unmasked side-channel around the entire enforcement path — for any
column the principal is not authorized to read in cleartext, including DENY
columns, not just masked ones. It happens on both engines, and no DB setting
closes it (see
[Why the database cannot fix it](#why-the-database-cannot-fix-it)) — the proxy
is the only place.

## The leak channels

MySQL — a conversion warning leaks the value while the query succeeds (result
maskable, warning carries the raw value):

```
SELECT CAST(ssn AS UNSIGNED) FROM t;   -- ssn='010-1234-5678' -> result 10 (maskable)
SHOW WARNINGS; -> Warning 1292  Truncated incorrect INTEGER value: '010-1234-5678'
```

PostgreSQL — `DETAIL: Failing row contains (…)` dumps the entire row, including
columns the statement never referenced and columns the principal is denied:

```
UPDATE t SET salary=9999999 WHERE uq='x';   -- caller names only `salary`
  ERROR 23514 ... DETAIL: Failing row contains (1, x, 010-1234-5678, 9999999, victim@example.com).
```

The value reaches the client through many fields and paths, not just the primary
message:

- MySQL: the ERR packet; `SHOW WARNINGS`; `GET DIAGNOSTICS … MESSAGE_TEXT`
  laundered into a plain `SELECT @v` row.
- PostgreSQL `ErrorResponse`/`NoticeResponse` fields: `M` message, `D` detail,
  `H` hint, `q` internal-query (dynamic
  `EXECUTE 'SELECT ''<stored value>''::int'` echoes the stored value here, not
  client input), `W` where-context, and the structural strings `t`/`c`/`n`/`d`.
  `RAISE … USING CONSTRAINT='<stored value>', TABLE=…, COLUMN=…` can put
  arbitrary stored data into those name fields under a benign SQLSTATE, and
  `RAISE NOTICE '%', (SELECT email FROM t)` echoes any column — but every
  `RAISE` form needs PL/pgSQL (an anonymous `DO`, a `CALL`, or
  `CREATE FUNCTION`), which a restricted principal has no grant to run. So
  `RAISE`-based vectors are not reachable through the principal's own statement,
  and for an ordinary error the structural fields and `H` hold object names or
  fixed text. Ordinary SQL does reach `M` (conversion), `D` (the whole-row
  `DETAIL` dump), `W` (an input function's context:
  `JSON data, line 1: {"value":"<stored value>"`), and `q` (SQL text built at
  run time and run by `query_to_xml` or `ts_stat`); those four are stripped.
- The editor/approval run path stores a failed statement's target-DB error, so
  `goproxy/run/runner.go` carries both forms (raw + redacted strip) and the
  control plane picks one per viewer at view time — an error string cannot be
  re-masked by ordinal the way rows are.

## Why an enumerated denylist is unsafe

A diagnostic leaks iff its message/fields echo the offending operand or row;
messages that name only the column/type/constraint do not (MySQL `3819` CHECK is
value-free and never dumps unreferenced columns; a PostgreSQL constraint `M` is
value-free, the value is only in `D`). Every diagnostic carries a stable numeric
code — MySQL essno, PostgreSQL SQLSTATE (`C`) — which is the reliable handle.

But the set of value-echoing codes is larger than any hand-survey and cannot be
trusted as a denylist. Beyond the two examples above: MySQL
`1366`/`1411`/`1062`/`1292` and `1300` — the invalid-character warning is a
general chunk-extraction oracle, not a niche invalid-byte leak:
`CONVERT(CONCAT(UNHEX('FF'), SUBSTRING(CAST(v AS BINARY), offset, n)) USING utf8mb4); SHOW WARNINGS`
returns `Invalid utf8mb4 character string: 'FF706D'`, revealing `pm`; vary the
offset to walk the entire stored value out in hex. PostgreSQL class-`23`
(`23514/23505/23503/23502` — whole-row / key DETAIL), class-`22`
(`22P02/22007/22003/22008/22023`), and `23P01` (exclusion, echoes both keys).
New error families surface per engine version. The design is therefore
fail-closed — redact everything the proxy cannot prove safe — not
deny-the-known-leaky. The leaky-code list is a monitoring aid
([Monitoring probe](#monitoring-probe)), not the enforcement basis.

## Why the database cannot fix it

- MySQL — no redaction knob. `sql_mode` only flips error↔warning; the value
  appears either way (non-strict is worse — succeeds and still warns).
  `log_error_verbosity` is the server log file only.
- PostgreSQL — no server-side ERROR-value redaction.
  `client_min_messages='error'` drops NOTICE/WARNING (the `RAISE` channel) but
  not ERROR + `DETAIL`. `log_error_verbosity` is server-log only.
  `psql \set VERBOSITY terse` hides `DETAIL` client-side, but the server still
  sends it in the `D` field, so a hostile client just leaves verbosity at
  default.

## Design — strip the value-carriers, keep the structure

When a decision is redacted (per decision, not per connection — see
[The redact predicate](#the-redact-predicate)), the proxy strips only the fields
that can carry a value a restricted principal could not otherwise reach, and
keeps the rest:

- The free-form message (`M`) is kept verbatim when it names only schema objects
  (see [Schema names pass, values never](#schema-names-pass-values-never)).
  Otherwise it is replaced with the code's canonical identity from a static
  table the proxy owns (`goproxy/pgproxy/diagcodes.go`,
  `goproxy/mysql/diagcodes.go`) — PostgreSQL to the SQLSTATE condition name
  (`23514` → `check_violation`), falling back to the 2-char class name (`23` →
  `integrity_constraint_violation`) then a generic string; MySQL to the essno
  symbol (`1146` → `ER_NO_SUCH_TABLE`), generic fallback. It is looked up only
  by the numeric code, never reconstructed from the target DB's echoed text
  (truncating at `: '`, stripping quotes) — that would re-open the leak, since a
  crafted value can contain the delimiters. A free-message catch-all code (MySQL
  `1105` `ER_UNKNOWN_ERROR`, which `extractvalue`/`updatexml` abuse) keeps only
  its honest symbol, never the text.
- PostgreSQL `Detail` (`D`) is dropped: an ordinary error fills it with a value
  the statement never named — the whole-row `Failing row contains (…)` dump.
- PostgreSQL `Where` (`W`) is dropped: an input function reports the text it
  failed on there (`JSON data, line 1: …`).
- PostgreSQL `InternalQuery` (`q`) and internal position (`p`) are dropped, and
  an error that carries `q` also strips `M`: `q` marks an error in SQL text
  built at run time (`query_to_xml('SELECT ' || col, …)`, `ts_stat`), where a
  value can fill any schema-name template.
- Unknown fields are dropped, since their content cannot be classified. Codes
  absent from the table degrade to the class/generic message — a fail-safe UX
  default, not the boundary (the strip is).

Everything else is kept. For an ordinary target-DB error the remaining
PostgreSQL fields hold object names or fixed text, not row values — the
structural `s`/`t`/`c`/`d`/`n` (schema/table/column/type/constraint) and the
hint `H`. The only way to put an arbitrary value in any of them is
`RAISE … USING` or dynamic PL/pgSQL, which needs a `DO`/`CALL`/function and is
denied for a restricted principal. Keeping them gives a developer the real
diagnostic —
`[23514] check_violation on orders.amount, constraint amount_positive` — instead
of a bare code. The accepted residual: a pre-existing trigger or vouched
function that RAISEs a value into one of those fields, fired by an allowed
statement — it needs a privileged author, so it is outside the
restricted-principal threat model.

### Schema names pass, values never

Schema is not data. A message whose interpolated parts are only schema names —
database/schema, table/view/relation, column, index/key, constraint, routine,
trigger, type, collation, charset, engine — or numbers from the definition (a
column count, a maximum key length) reaches the client verbatim:
`Table 'acme.orders' doesn't exist`,
`null value in column "email" of relation "orders" violates not-null constraint`.
A message that can carry a stored value, a statement literal or fragment
(`1064 … near '…'`), a row number, a file path, an account name, or free text is
stripped as above.

The allowlists are explicit tables, keyed by code and matched against the
message template:

- MySQL — `goproxy/mysql/diagschema.go`: essno → the English template from
  `share/messages_to_clients.txt` of MySQL 8.0 and 8.4. A code is listed only
  when its template is schema-only in both series. The message must match the
  template, so a `SIGNAL` text under that essno, a non-English `lc_messages`, or
  a truncated message is stripped.
- PostgreSQL — `goproxy/pgproxy/diagschema.go`: SQLSTATE → anchored `M`
  templates from the PostgreSQL 16 and 17 message catalogs. A SQLSTATE covers
  many messages, so the SQLSTATE alone keeps nothing. A quoted name stops at the
  template's quote, so a name containing `"` is stripped. Only `M` is affected;
  `D` and the other fields follow the table below.

A template is listed only when its name can come solely from statement text or
the catalog. Where a run-time value can become the name, the template is omitted
— even though enforcement denies the vector — so the allowlist never depends on
enforcement holding.

- PostgreSQL has single-statement resolvers that turn a string into an object
  name and report it: `'…'::regclass` / `::regtype` / `::regnamespace` /
  `::regoper` / `::regcollation`, `nextval`/`currval`, the `has_*_privilege`
  family (`has_column_privilege` resolves its column argument too),
  `pg_relation_size` and the other size functions, `pg_get_serial_sequence`, and
  `pg_get_object_address`. The error _is_ the exfiltration channel, so the
  templates they produce are not allowlisted: `relation "%s" does not exist`
  (42P01), `column "%s" of relation "%s" does not exist` (42703),
  `type "%s" does not exist`, `collation "%s" for encoding "%s" does not exist`,
  and `trigger "%s" for table "%s" does not exist` (42704),
  `schema "%s" does not exist` (3F000), and every 42883 form —
  `operator does not exist: …` and the `function`/`procedure name(argtypes)`
  signatures. These strip to the SQLSTATE condition name even for a plain
  mistyped name. Kept: the bare `column "%s" does not exist`, `column t.c`, the
  index/constraint `does not exist` forms, and the `missing FROM` /
  table/view/sequence/matview variants, whose names come only from statement
  text. Statement text built at run time (`query_to_xml`, `ts_stat`) can fill
  those too; PostgreSQL marks such an error with `q`, and any error carrying `q`
  strips `M`.
- MySQL has no such single-statement resolver — identifiers are always literal
  statement text. The only value-to-name path is dynamic SQL: load the value
  into a user variable, then `PREPARE` a statement text built from it. That path
  is denied at its first step, which is the real barrier, not this allowlist:
  `SET @v = (SELECT <masked or ungranted col>)` is a write to an unmaskable
  target and denies, and if it ever did not, `SELECT @v` would return the value
  as an ordinary row that no allowlist governs. The MySQL schema-name templates
  are therefore kept. The barrier is locked by `DynamicSqlNameExfilMySqlDbTest`.

### PostgreSQL error/notice fields — kept vs stripped

<!-- prettier-ignore -->
| Field | Meaning | Redaction |
| --- | --- | --- |
| `S` / `V` | Severity (localized / non-localized) | kept |
| `C` | SQLSTATE code | kept — drives the canonical message |
| `M` | primary message | kept if schema-only and `q` is empty, else replaced with the code's canonical identity |
| `D` | Detail | dropped — the whole-row `Failing row contains (…)` |
| `H` | Hint | kept (advisory; object names or fixed text) |
| `P` | Position | kept (an offset into the client's own statement) |
| `p` / `q` | Internal position / internal query | dropped — SQL text built at run time (`query_to_xml`, `ts_stat`); its presence also strips `M` |
| `W` | Where (context) | dropped — an input function's context echoes its input (`JSON data, line 1: …`) |
| `s` `t` `c` `d` `n` | Schema / Table / Column / DataType / coNstraint names | kept — object names; a value needs denied `RAISE … USING` |
| `F` / `L` / `R` | File / Line / Routine (server source) | kept (no user data) |
| _unknown_ | unrecognized field codes | dropped (unclassifiable) |

`NoticeResponse` is forwarded unchanged (see
[Notices are forwarded, not redacted](#notices-are-forwarded-not-redacted)).
MySQL ERR packets keep essno + SQLSTATE and the schema-only message, or replace
the message with the essno symbol; MySQL has no structured error fields.

The strip runs where the target DB wire is decoded — the native relay
(`goproxy/pgproxy/relay.go`, `goproxy/mysql/relay.go`, and the PostgreSQL
extended-protocol `forwardError`/`forwardNotice` in
`goproxy/pgproxy/diagnostics.go`) and the editor path.

## The read-back statements

`SHOW WARNINGS` and `GET DIAGNOSTICS` are statements, not rewritable response
packets, and the proxy cannot identify them from a connection flag:
`GET DIAGNOSTICS … MESSAGE_TEXT` launders the string into a server user var that
surfaces as an ordinary `SELECT @v` row (no lineage to bind), and a
`SHOW WARNINGS` result set is indistinguishable from normal rows on the wire. So
the control-plane admission gate handles them, never a blind proxy rewrite of
arbitrary result sets.

On the production floor, `SHOW WARNINGS` / `SHOW ERRORS` are deny-by-default and
hard via the utility gate (the `system:data-leak` forbid), and `GET DIAGNOSTICS`
classifies as a statement kind a restricted principal has no grant for, so it is
denied. Both relax only on a `system:development` datasource (no PII).

Why keep the deny, given the error strip and enforcement? `SHOW WARNINGS`
returns the warning buffer as result rows, not an ERR packet — the message strip
does not touch it, and the proxy cannot bind a mask to a `SHOW WARNINGS` row (no
lineage). Enforcement already denies the queries that would put a masked value
in a warning — a transformed read of a masked column (CAST, the `1300` chunk
oracle) is denied — so for a restricted principal the buffer holds nothing
sensitive. But `SHOW WARNINGS` is a general extraction oracle: any single
warning-path enforcement gap it surfaces becomes full value extraction (walk the
value out in hex via `1300`). Unlike the narrow `RAISE`-via-trigger residual,
that is a broad "trust enforcement is complete on every warning path" assumption
the design refuses to make — so the read-back stays denied on the floor, at
negligible cost to a restricted principal who generates few meaningful warnings
anyway.

## Notices are forwarded, not redacted

PostgreSQL `NoticeResponse` is forwarded unchanged — the proxy's default;
nothing special is built for it. A notice carries no value a restricted
principal could not otherwise reach: server-generated notices are advisory
(object names, DDL, transaction state), never a row value, and the only
value-bearing notice is `RAISE NOTICE`, which needs PL/pgSQL and is denied. So
the notice channel is closed by enforcement, not by anything in the proxy — the
same posture as the kept error structural fields, with the same accepted
residual (a pre-existing trigger / vouched function that RAISEs a NOTICE via an
allowed statement).

## The redact predicate

The analyzer (Go) decides what a statement could leak; the control-plane
(Kotlin) only authorizes it. Per engine (`engine.DiagnosticLeakKeys`), the
analyzer emits `StatementFacts.diagnostic_leak_columns`: the referenced columns,
plus — PostgreSQL writes only — the whole target row, because
`INSERT INTO users (id) VALUES (1)` can fail with
`DETAIL: Failing row contains (1, 010-1234-5678, …)`.

`decideQuery` computes the flag per decision: `MASK`/`DENY` always redacts; an
`ALLOW` redacts iff the principal cannot read every leak column **unmasked**
(`readsAllUnmasked`, `Query.kt`). So `select id from users` relays raw while the
INSERT above redacts for anyone masked on `ssn`. `result.read.unmasked` is
checked per column, never against the Datasource entity — the datasource-level
grant that let a `MASK` diagnostic surface raw was #228.

An `ALLOW` with no analyzable leak set (`exception.unanalyzable`, an uncovered
column) fails closed and redacts. Not covered: an FK `ON DELETE CASCADE` dumping
a child table's row (KNOWN_LIMITATIONS.md).

The synchronous `POST /api/datasources/{id}/query` route returns the result
inline, so a target-DB failure surfaces the form the run's own decision dictated
— raw unless it sanitized diagnostics (the proxy echoes the flag back on
`RunDecision`). The async editor/approval paths instead store both forms and
re-gate per viewer at view (above).

The control plane carries the per-decision result as
`Verdict.sanitize_diagnostics` — an imperative command the proxy executes
mechanically, not a statement-meaning flag. The engine applies it to that
statement (`QueryEngine.SanitizeDiagnostics()`), so the stateless relay is
preserved.

## Monitoring probe

An end-to-end probe builds a corpus from each engine's full error-code catalog
plus adversarial constraints/conversions/functions/`RAISE … USING`, runs it
against every supported engine version, and asserts no stored value survives in
any passed-through wire field on a redacted connection (field-level, across
every delivery path — not just "a new code echoes in `M`"). The
canonical-message tables in `diagcodes.go` are the complete catalogs generated
from source (the PostgreSQL `errcodes.txt` appendix and MySQL's
`mysqld_error.h`), so every code renders its real identity rather than the
generic fallback. Because the strip is fail-closed, this probe protects UX /
false-strips and catches regressions; it is not what makes the system safe.

## Ownership

The field strip and the code-to-identity table live in the proxy (mechanical).
The control plane computes the redact flag per decision and denies/commands the
read-back statements. No SQL classification or enforcement decision moves into
the proxy.

## Known limitations

- Existence oracle — code + severity still reveal "a unique value collided" or
  "this did not convert." Small; accepted.
- Self-input — a `22P02` on the client's own literal (`SELECT 'x'::int`) is
  redacted too; the proxy cannot cheaply distinguish self-input from a
  stored-value leak. Minor UX cost, correct trade.
- Driver behavior — dropping `DETAIL` and names is low-risk (drivers branch on
  SQLSTATE `C`, retained); a few ORMs parse `Key (col)=(val)` and lose it.
  Accepted.
- There is no bypass mode. A denylist that passes unknown codes leaks (see
  [Why an enumerated denylist is unsafe](#why-an-enumerated-denylist-is-unsafe)).
