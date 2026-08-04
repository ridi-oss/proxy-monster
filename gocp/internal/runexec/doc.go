// Package runexec is `RunExecService` (RunExec.kt, 655 LOC) — the CP-driven run transport.
//
// Area doc: plans/proxy-monster-go-port/07-tasks-approvals-results.md §7. The CONTRACT it implements
// (the five exception kinds, RunInput/SessionRunInput, the RunExec interface) is declared in
// internal/query, which owns the [query.QueryResponse] every path here answers with; this package
// cannot host it because it imports internal/core, which imports internal/query.
//
// # What it does
//
// One CP-driven query over a proxy-dialed `RunExec` stream. The proxy executes on the target and
// streams back the ENFORCED (decided + masked) result.
//
// 🔒 THE CONTROL PLANE NEVER DIALS INTO A PROXY (INV-A10-35 / A12 INV-A12-12). Every path here writes
// an OpenRunChannel event down a pipe the PROXY already opened
// ([core.ProxyEventsHub.RequestOpenRun]), and the proxy then dials the run stream back in. That is
// what lets a proxy sit behind NAT with no inbound listener, and it is why the dial is a rendezvous —
// register a pending session, nudge, await Ready — rather than a connect.
//
// Two shapes share the machinery:
//
//   - [Service.Run] — ONE-SHOT: mint → open catalog connection → register → nudge → await Ready →
//     send → collect → tear everything down. Backs `POST /api/datasources/{id}/query` and the approval
//     execute-under-R path.
//   - [Service.OpenSession] + [Service.RunOnSession] — PERSISTENT: one held stream, hence one dedicated
//     backend connection, across MANY queries, so SET/USE, temp objects and BEGIN…COMMIT persist
//     exactly like a native wire client. This is the web SQL editor's path.
//
// 🔒 INV-A7-38 — enforcement stays PER-STATEMENT on a persistent session. Each query re-decides
// against the connection's live namespace/catalog on the EDITOR channel under the caller's own roles.
// A held connection is a data-plane fact, not an authz relaxation.
//
// # The five things a port gets wrong
//
//  1. 🔒 INV-A7-35 — THE CANCEL GATE'S SEND HAPPENS WHILE HOLDING THE LOCK. Building the message under
//     the lock and sending outside it reintroduces the bug where a RunCancel lands BEFORE its query
//     and an idle proxy drops it, letting a just-cancelled query run. TestTheQuerySendHappensWhile
//     HoldingTheCancelGate fails if the send moves out.
//  2. 🔒 INV-A7-36 — the `attached == nil && remove() == nil` dance in the cleanup. Without it a
//     cancel that raced the claim leaves the proxy holding a backend connection forever.
//  3. 🔒 INV-A7-33 — RequesterIPRegistry.Put and .Set have deliberately different nil semantics, and
//     [Service.RunOnSession] must Set BEFORE the send.
//  4. 🔒 INV-A7-32 — a session is claimable exactly once; the registry's Attach removes-then-completes.
//  5. `maxRows` is coerced into [0, 5000] with 0 PRESERVED as the wire sentinel meaning "use the
//     proxy's default (500)". Coercing to [1, 5000] silently changes every default-max-rows query.
//
// # Go-shape divergences, all three deliberate
//
//  1. Kotlin's `closeConnectionCatalog` wraps a `runBlocking` "to keep suspend cleanup out of run()'s
//     already-large state machine (JDK verifier sensitivity)". OMITTED — the wrapper exists because of
//     the JDK verifier, not the contract, and has no observable behaviour of its own, so Go calls
//     ConnectionCatalog.Close directly (confirmed 99-reconciliation-report.md, A7 Q7).
//  2. Kotlin's cleanup DB work (`tokenStore.revoke`) is a blocking JDBC call, unaffected by coroutine
//     cancellation. Go's is ctx-bound, so every cleanup path runs on [cleanupContext] — a
//     WithoutCancel copy with its own budget. Running it on the caller's ctx would mean a cancelled or
//     client-disconnected request NEVER REVOKES ITS EPHEMERAL TOKEN, which is a live credential leak
//     rather than a tidiness issue.
//  3. The blocking query send is bounded by [outboundSendBudget]. Kotlin's `SendChannel.send` to a
//     stream whose consumer has died throws ClosedSendChannelException and becomes
//     `ProxyRunException("proxy run stream closed before the query was sent")`; a Go channel with a
//     dead drainer merely FILLS, and an unbounded send under the cancel gate would then wedge
//     [Service.CancelActiveRun] too. The budget produces the same observable error from the same
//     condition.
package runexec
