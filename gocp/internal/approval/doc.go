// Package approval is `Approvals.kt` — the human query-approval workflow, execute-under-R, and the
// live view re-decision — plus the two surfaces that are built out of the same parts: A6's
// `editorSessionRoutes` (Query.kt:904-1180) and A1's `taskEventsRoute` (App.kt:89-152).
//
// Area docs: plans/proxy-monster-go-port/07-tasks-approvals-results.md §§5-6 and §8, with
// 06-query-decision.md §6 for the editor routes and 01-bootstrap.md §2 for the SSE stream.
//
// # Why three Kotlin files land in one Go package
//
// The Kotlin splits them by file, and the split is by AREA OWNERSHIP, not by dependency: the editor
// routes call A7's `autoApproveTask` and `decideResultView` and hand their runs to A7's
// `RunExecService`; the SSE route consumes A7's `TaskCompletionHub` and is described by its own area
// doc as "defined in App.kt (A1) but task-centric; counted here" (07 §10). Splitting them into three
// Go packages would put [DecideResultView] and [TaskCompletionHub] behind an exported seam for two
// callers that are the same increment, and would give a reader three files to open for one story. The
// FILE-level separation is kept instead — routes.go, editorroutes.go, taskevents.go — so a diff
// against the Kotlin still reads one-to-one.
//
// # What is here and what is a seam
//
// Ported: the pure policy helpers (§5), [TaskCompletionHub] (§8), and all 18 routes.
//
// Consumed through a narrow interface rather than owned: `RunExecService` (§7, RunExec.kt, 655 LOC) —
// the CP-driven run transport over a proxy-dialed gRPC stream. It IS ported now, as internal/runexec;
// the routes here reach it through [RunExec] and switch on the five `RunExecException` sentinels,
// because the exception→HTTP-status mapping IS route behaviour and is specified by the two area docs'
// route tables. runexec.go aliases the contract, which is declared in internal/query — the package
// that owns the [query.QueryResponse] every run answers with, and the home of the transport's OTHER
// HTTP consumer, `POST /api/datasources/{id}/query`.
//
// # The three gate asymmetries, stated once
//
// They are the whole point of the area, and each is easy to lose by "tidying":
//
//   - [Routes.mayRequest] and [Routes.mayDecide] bypass under `authDebug`; [Routes.mayReadResult]
//     does NOT (🔒 INV-A7-18 / INV-A6-25 — result rows are data confidentiality, enforced in
//     development too).
//   - `/execute`'s `req.decidedBy != executor` guard has no `authDebug` bypass either
//     (🔒 INV-A7-26 — an identity invariant, not an authorization).
//   - The editor read paths layer an OWNER guard and a Cedar gate, and 🔒 INV-A6-26 says neither
//     substitutes for the other.
package approval
