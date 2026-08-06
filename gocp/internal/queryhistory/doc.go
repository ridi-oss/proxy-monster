// Package queryhistory is `QueryHistory.kt` (76 LOC): the per-principal editor history — the store,
// its one DTO, and the two routes that read and clear it.
//
// Area doc: plans/proxy-monster-go-port/07-tasks-approvals-results.md §9.
//
// ⚠️ NOTE ON THE AREA LABEL. This surface is sometimes referred to as "A12" because
// `/api/query-history` sits next to the request-context work in the route table, but A12 is
// 12-request-context.md (`RequesterIp.kt`, `httpAuthzContext`, `PM_TRUSTED_PROXIES`) and has nothing
// to do with it. `QueryHistoryStore` + `queryHistoryRoutes` are A7's, specified in
// 07-tasks-approvals-results.md §9 and counted in that area's LOC table (00-INDEX.md:109). Cite §9,
// not 12-request-context.md, when checking anything here.
//
// # What it is, and what it is not
//
// V5__tasks.sql:104's own comment draws the line: "Per-principal editor history: every run from the
// web editor, so a user can recall recent statements. Convenience only — distinct from audit_event,
// which is the security record."
//
// 🔒 That distinction governs everything else in this package. `query_history` is a UX affordance: it
// is deletable by its own owner (there is no admin view and no retention policy), it has a plain
// BIGSERIAL id, and A6's `queryRoutes` writes to it best-effort inside `runCatching`, so a history
// write that fails never blocks a query. `audit_event` is the opposite on every count — hash-chained,
// application-allocated ids, append-only, and its insert composes into the deciding transaction
// precisely so a failure DOES fail the operation. Nothing here may grow into an audit substitute, and
// nothing here may be relied on as evidence.
//
// # Principal-scoped, with no way to widen it
//
// ⚠️ Both routes are scoped from the SESSION only — no `principal` query parameter, no admin view, no
// cross-principal read (07-tasks-approvals-results.md §9). [Store.Recent] and [Store.Clear] both take
// a principal and neither has an unscoped variant, so there is no method on this package a route
// could call to read someone else's history even by mistake.
//
// # The Postgres-specific read
//
// ⚠️ [Store.Recent] uses `DISTINCT ON`, which is PostgreSQL-only. The control-plane store IS
// Postgres-only (Db.kt), so that is fine, but §9 carries the warning a port needs: "a Go port using a
// generic query builder must not rewrite it to `GROUP BY` (which would need an aggregate over
// `created_at` and a self-join to recover `datasource_id`)."
//
// # Zero inherited test coverage
//
// 🔴 00-INDEX.md F17: "`QueryHistoryStore` has no dedicated test file — `DISTINCT ON` dedup, `limit`
// coercion, and blank-SQL skipping are all unasserted. Second untested store after `PolicyStore`
// (F10)." So, exactly as in internal/policy, there is nothing to migrate and every test in this
// package is NEW, written against §9 as the sole specification. The three behaviours F17 names are
// the three the suite leads with.
package queryhistory
