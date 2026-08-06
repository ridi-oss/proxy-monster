package datasource_test

// The three TableDetailDbTest.kt cases that assert TableDetailService — the PRODUCER side of the
// table-detail stream — which is not ported. This file states that, and nothing else.
//
// The deferral is a statement about a MISSING SUBJECT, not about difficulty. Every one of the three
// asserts behaviour that lives in the Kotlin's `TableDetailService.fetch`
// (control-plane/.../TableDetailExec.kt:70-116), and none of that behaviour exists in Go yet:
//
//  1. `resolveSchema(schema, dbName)` for the schema the proxy's reply must come back under — the reason
//     the MySQL fixture answers to BOTH `detail_mysql` and `public` (TableDetailDbTest.kt:112).
//  2. The response-mixup guard: `detail.schema != expectedSchema || detail.table != table` throws
//     ProxyTableDetailException (TableDetailExec.kt:104).
//  3. 🔒 The CLASSIFICATION OVERLAY: `catalog(datasource.id)` filtered to the returned schema/table,
//     associated by column, then `column.copy(classification = classifications[column.name])`
//     (TableDetailExec.kt:108-116). This is the substance of cases 1 and 2 — `classified_secret` comes
//     back carrying tags=[pii] + its maskFnName, and the post-sync `live_only` column carries null.
//  4. The pending/attach/timeout/close lifecycle the fake proxy in the Kotlin suite drives.
//
// What Go HAS is the SEAM: `management.TableDetails` is an interface with one method
// (internal/management/datasource.go:37), and `GetTableDetail` returns the fetched detail VERBATIM —
// there is no overlay, no resolveSchema and no mixup guard anywhere in the Go tree
// (internal/management/datasource.go:177-206). The interface has no production implementation at all:
// internal/app/http.go:246 passes a nil TableDetails on purpose, and doc.go:56 and service.go:28 both
// record it — "TODO(A5): the admin routes and TableDetailExec's producer side" and "What does not exist
// yet is A7's RunExecService / A5's TableDetailExec".
//
// So a Go test here could only assert its own fake's return value. That is worse than an honest gap: it
// would read as coverage of an overlay that no Go code performs, and the day the producer lands with the
// overlay missing, nothing would fail.
//
// What IS already covered, and deliberately not claimed as these cases: routes_db_test.go's
// TestTableDetailServesTheProxysAnswerVerbatim (the top-level key set and the no-rows/data/preview rule),
// TestTableDetailRequiresBothSchemaAndTableInOneError, TestTableDetailOrdersItsChecksTheKotlinsWay and
// TestAnAbsentTableIs404AndAFailedIntrospectionIs502 cover the ROUTE's own guards — which is a proper
// subset of case 4 and none of cases 1-2. Case 4 additionally asserts that a schema/table carrying an SQL
// or backtick payload is an EXACT LOOKUP that 404s (five payloads) and that no nudge is sent for an
// invalid selector, both of which need the producer to observe.
//
// Case 3 of the same file IS ported — the transport half exists — in
// internal/grpcsvc/tabledetailexec_test.go.
//
// The two OVERLAY cases are no longer deferred: the producer landed in internal/tabledetail and they
// are ported there (TestPostgresTableDetailOverlaysClassificationAndStaysStateless,
// TestMysqlTableDetailResolvesPublicToTheDatabaseAndOverlays), which is also where the
// resolveSchema mapping they turn on now lives.
//
// KT-DEFER: TableDetailDbTest.kt#route validates selectors rejects identifier attacks and reports proxy failures — no longer BLOCKED (the producer exists and can be observed), only unwritten: the case needs the five identifier-attack payloads driven through the HTTP route AND the assertion that an invalid selector sends the proxy no nudge, which spans internal/datasource's route tests and internal/tabledetail's fake proxy. The selector/404/502 half is already covered by routes_db_test.go. Deferred as fixture work, not a missing production path.
