# analyzer — the Layer-1 SQL statement-facts probe

This is proxy-monster's enforcement analyzer: given one SQL statement + a
catalog, it returns a complete authorization contract — a `StatementFacts`
message stating what the statement does and every Cedar grant required to run it
(per-column result grants with mask/deny dispositions, table-coverage, function
facts, utility grants, the coarse `sql.<kind>`, `isWrite`, and the `*`-expanded
`rewrittenSql`). The control plane walks that contract against Cedar policy; it
never parses or classifies SQL itself. This is the security-critical core, so it
lives in this repo and is versioned here.

It calls [sqlglot-go](https://github.com/ridi-oss/sqlglot-go) purely as a SQL
library (parser · `optimizer.Qualify` · `TraverseScope`/scope graph · generator
· schema). The analysis logic (`probe/`) is ours; sqlglot-go is a dependency,
like Calcite would be.

The engine (`:engine`) calls it in-process through a JVM Foreign Function &
Memory binding to a Go c-shared lib. Both directions of the boundary are
length-prefixed protobuf (`proto/src/main/proto/analyzer.proto`): an
`AnalyzeRequest` in, a `StatementFacts` out, so Go/JVM schema drift is a
compile-time mismatch, not a silent runtime one.

## Layout

```
analyzer/
  go.mod                     Go module github.com/ridi-oss/proxy-monster/analyzer;
                             pins github.com/ridi-oss/sqlglot-go v0.22.0
  probe/                     the analyzer (package probe)
    facts.go                 EmitFacts: classify the statement + emit statement_exec + result-read grants
    probe.go, helpers.go     internal column lineage + reference bucketing + SELECT * expansion
    pb/analyzer.pb.go        generated Go bindings for analyzer.proto
    *_test.go                golden (hermetic) + parity (vs Python sqlglot) + admission-parity + unit tests
    testdata/golden.json     frozen regression snapshot (internal probe)
    testdata/oracle/         the Python parity oracle (driver.py + probe.py) — test-only
  cmd/libsqlglot/main.go     C-shared entry: exports AnalyzeStatement / SqlNormalize / FreeCString (cgo confined here)
  jvm/                       Gradle subproject :analyzer:jvm
    build.gradle.kts         builds cmd/libsqlglot (go build -buildmode=c-shared) + bundles the lib
    src/main/kotlin/…/Sqlglot.kt   the FFM binding: Sqlglot.analyzeStatement(requestBytes) / sqlNormalize(sql, dialect)
```

`:engine` depends on `project(":analyzer:jvm")`; that project's
`processResources` runs the native build first, so the lib is on the classpath.
`--enable-native-access=ALL-UNNAMED` is added to every module's
`Test`/`JavaExec` task in the root build.

## The sqlglot-go dependency

sqlglot-go is a version-pinned `go mod` dependency — no subtree, no vendored
source. `analyzer/go.mod` pins `github.com/ridi-oss/sqlglot-go v0.22.0` and
`analyzer/go.sum` locks its checksum, so a fresh clone / CI builds with a plain
`go build`. Bump the pin with:

```bash
go get -C analyzer github.com/ridi-oss/sqlglot-go@<tag-or-commit>   # then commit go.mod + go.sum
```

The committed root `go.work` lists only this repo's own modules, so sqlglot-go
always resolves from that pin — the workspace makes every Go command take
root-relative paths (`go test ./analyzer/probe/...`) without changing which
version of the dependency is used.

## Building

The native lib builds automatically as part of the normal Gradle build.
Directly:

```bash
mise exec -- ./gradlew --no-daemon :analyzer:jvm:buildNativeLib   # host lib only (fast; dev default)
mise exec -- ./gradlew --no-daemon :analyzer:jvm:build            # + compile binding, run its FFM test
mise exec -- ./gradlew --no-daemon :analyzer:jvm:build -Psqlglot.native.all=true  # fat jar: darwin/arm64 + linux amd64/arm64
```

The default builds the host lib only. `-Psqlglot.native.all=true` cross-compiles
the two Linux targets with Zig as the C compiler (`zig cc -target …`, glibc 2.17
for forward-compat) and bundles all three at `native/<os>-<arch>/`; the wrapper
picks the right one at runtime. That build must run on macOS/arm64
(cross-building darwin needs the macOS SDK). Build machine needs the Go
toolchain + a C compiler (cgo) — pinned in the repo `mise.toml` (`mise install`)
— plus, for the all-targets build only, `zig` on PATH, which `mise.toml` does
not pin; install it separately.

## Testing

```bash
go test ./analyzer/probe/...
```

- TestProbeGolden — internal-probe regression against `testdata/golden.json`;
  hermetic (no Python).
- TestProbeParity — regenerates expected output from a pinned Python sqlglot at
  `.reference/…` and diffs. Skips when that checkout (or python3) is absent —
  it's the oracle behind `golden.json`, run when updating the snapshot.
- admission_parity_test.go — runs a corpus of security-sensitive statements
  through `EmitFacts` and asserts the expected outcome: batch/injection,
  privilege SET, dangerous functions, INTO writes, EXPLAIN-of-query,
  SHOW/DESCRIBE, user-type casts.

The real end-to-end verdict coverage is the Kotlin `GateSqlglotRegressionTest`
in `:control-plane`, which drives this probe through the FFM binding on a large
SQL corpus.

## API & contract

The boundary is one protobuf call in, one out (see
`proto/src/main/proto/analyzer.proto` for the authoritative schema). From Kotlin
the engine calls:

```kotlin
val facts: StatementFacts = SqlglotProbe.analyze(
    sql,
    namespace,     // catalog + ordered search_path
    catalog,       // flat List<ColumnSpec> (catalog.schema.table.column + type)
    engineConfig,  // engine identity + version + MySQL lower_case_table_names
)
```

`AnalyzeRequest` carries `sql`, `namespace`, the flat `catalog`, and
`engine_config`. The response `StatementFacts` carries `resolved`, the
`failure_class` / `failed_stage` / `detail` for an unresolved statement, the
`statement_class` (ANALYZED / METADATA / SESSION), the ordered `output_columns`,
`is_write` / `catalog_changing`, the `*`-expanded `rewritten_sql`, and — the
heart of it — `required_grants`: each a Cedar action over a typed resource
(Column / Table / Function / Utility / Datasource) with a masked disposition and
the output ordinals it gates. Thread-safe (the Go side is a pure function; each
call uses its own confined `Arena`). Requires JDK 24+ — the binding's bytecode
target, which also provides FFM.

Fail-closed. Any malformed/unparseable input or internal error returns a valid
`StatementFacts{resolved:false, …}` — never an exception. A non-resolved result
is treated as DENY (fail-open only on `system:development`'s
`exception.unanalyzable` gate). This is the safe direction for a security probe:
a parser gap becomes DENY rather than a leak.

All SQL understanding lives here on the AST — the analyzer never scans SQL text.
`EXPLAIN`/`DESCRIBE` is decided structurally: an EXPLAIN-of-a-query (including
`EXPLAIN ANALYZE`, which executes its inner statement) is analyzed as that inner
statement and inherits its column enforcement, while a DESCRIBE-of-a-table is
metadata passthrough. MySQL executable comments (`/*!NNNNN … */`) are decoded
and analyzed under the connection's server version. A statement whose lineage
the analyzer cannot pin to concrete source columns degrades to a fail-closed
over-deny rather than a leak — `NATURAL JOIN` (shared-column lineage is
ambiguous), `PIVOT`, a data-modifying CTE, and `SELECT *` over a table-function
/ `VALUES` / `LATERAL` source (no fixed column list, so mask ordinals cannot be
bound) all resolve false and route through the `exception.unanalyzable` gate.
