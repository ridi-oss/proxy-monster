// Package controlplane is the Go port of the Kotlin control-plane (control-plane/src/main/kotlin).
//
// The port is specified by the area docs under plans/proxy-monster-go-port/ — fourteen documents that
// describe the Kotlin's observable behaviour so the port can be written without reading the Kotlin.
// 00-INDEX.md is the entry point; it also carries the binding PORT POLICY:
//
//	Reproduce the Kotlin's observable behaviour EXACTLY, including its defects. Fix nothing.
//	REPRODUCE (default) · REPRODUCE + PIN (security/data paths — a test asserts the BUGGY behaviour)
//	· OMIT (dead code and JVM artifacts only, i.e. non-observable) · DEFER.
//
// Inefficiency, duplication, inconsistency and ugliness are REPRODUCE, never OMIT. A refactor during
// a port is a fix during a port.
//
// # Layout
//
// cmd/controlplane is the binary; everything else lives under internal/. No sibling module in this
// workspace imports its types (auditmon re-derives the audit-record canonicalisation in its own
// auditmon/canon package), so internal/ states that and lets the package boundaries move freely while
// the port is in flight.
//
//	cmd/controlplane     main(): the env contract, the boot sequence, the signal handler (A1)
//	internal/app         App wiring — Config → Db → Core → gRPC → HTTP — plus the HTTP surface (A1)
//	internal/core        ControlPlaneCore, the ONE shared graph; decideConnection; the registries
//	internal/grpcsvc     the ten RPCs, the secret-token gate, the gRPC server (A10)
//	internal/pb          generated gRPC/protobuf stubs for proto/src/main/proto/controlplane.proto
//	internal/types       Decision, AuditEvent, ApiError + the error helpers   (A1 §3)
//	internal/config      the PM_* environment contract and its 11 validations (A1 §1-2)
//	internal/store       the pgx pool and the Flyway-compatible migration runner (A1 §2)
//	internal/migrations  the ten V1..V10 Flyway SQL files, embedded
//	internal/authz       Cedar: schema, entity marshalling, policy store, authorize* (A2)
//	internal/token       the wire-token half of A4: Kind, Hash, issue/resolve/validate
//	internal/audit       the hash-chained audit store + the read routes' visibility model (A8)
//	internal/dbtest      the DB-backed test harness: shared containers + the enforcement fixtures
//
// # Increment status
//
// THE CONTROL PLANE NOW RUNS. `go run ./cmd/controlplane` boots the real process: it reads the env
// contract, migrates its store, builds the shared graph, serves gRPC on PM_GRPC_PORT and HTTP on
// PM_HTTP_PORT, and answers a proxy's full handshake — Register, PushCatalog, ValidateToken, Decide,
// PushSchemaFragment, Decide, ReportCompletion — with verdicts computed by internal/query.DecideQuery
// over a catalog the proxy pushed. internal/app/boot_e2e_db_test.go is that proof, over a socket.
//
// Landed: A1's boot sequence and two HTTP routes (/health, /api/ingest/decision) · A2's Cedar engine
// and CedarPolicyStore read half · A5's connection catalog, datasource store and decideConnection ·
// A6's decideQuery · A8's audit store · A10 in full · the wire-token slice of A4.
//
//	A1:  Main, App wiring and ControlPlaneCore are DONE. The other ~118 HTTP routes, the five session
//	     cookies, StatusPages/CallLogging and the two background timer loops are not — see http.go's
//	     route inventory and 01-bootstrap.md §2.
//	TODO(A3):  identity + SCIM routes         — see 03-identity-scim.md. The stores (UserGroupStore,
//	   RoleResolver) are ported, in internal/identity.
//	A4 (internal/token): the wire half only — Kind, tokenHash, issue/resolve/validate, the TTL clamp.
//	   TODO(A4): device authorization, web sessions, session renewal, the MCP token families and the
//	   /api/tokens routes — see 04-auth-session-tokens.md.
//	A5 (internal/datasource + internal/core/decideconnection.go): the stores, the per-connection
//	   catalog registry and decideConnection. TODO(A5): the admin routes and TableDetailExec's
//	   producer side.
//	A6 (internal/query): decideQuery — the 32-step enforcement pipeline of 06-query-decision.md §3.
//	   Its ROUTES half (queryRoutes, editorSessionRoutes, accessRoutes) is still open. Its production
//	   callers ARE now wired: decideConnection in internal/core, the gRPC Decide in internal/grpcsvc.
//	TODO(A7):  tasks, approvals, results      — see 07-tasks-approvals-results.md. The store is ported
//	   (internal/access) and so are the registries A10 needs (RunChannelRegistry,
//	   RequesterIPRegistry, in internal/core); RunExecService itself is not.
//	A8 (internal/audit): the chain-linked AuditStore + the read routes' store half — 08-audit.md.
//	   Its HTTP half (the two GET routes, requireApi, badId, notFound) is A1's and is still open.
//	TODO(A9):  policy CRUD routes             — see 09-policies.md
//	A10 (internal/grpcsvc): all ten RPCs, the SecretTokenInterceptor (unary AND stream), GrpcServer
//	   with the ephemeral-port readback and the graceful-then-force shutdown, GrpcMappers and
//	   inspectTrustChain. RunExec/TableDetailExec are transport-complete; their PRODUCER services
//	   are A7's and A5's.
//	TODO(A11): MCP, OAuth, management         — see 11-mcp-oauth-management.md
//	TODO(A12): request context + trusted proxies — see 12-request-context.md. ProxyEventsHub's
//	   fan-out half is in internal/core; the request/response half (requestOpenRun) is not.
//	A13 (internal/engine): the analyzer wrapper, system classification, masking, normalisation.
//	TODO(A14): OIDC login + the auth module   — see 14-auth.md
package controlplane
