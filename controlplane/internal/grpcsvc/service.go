// Package grpcsvc is A10 — the proxy↔control-plane gRPC surface
// (plans/proxy-monster-go-port/10-grpc.md).
//
// Ten RPCs over plaintext HTTP/2 on PM_GRPC_PORT, gated by ONE shared transport secret, all handled
// by a single service struct backed by the SAME [core.ControlPlaneCore] the HTTP surface uses
// (INV-A1-1).
//
// # This area owns transport, request validation and marshalling only
//
// Every decision it returns is computed by A5's DecideConnection → A6's DecideQuery; every catalog
// mutation is A5's; every audit write is A8's. The handler bodies are almost entirely ARGUMENT
// DERIVATION AND FAIL-CLOSED GUARDS, and that is where the security content of the area lives.
//
// # The contract is machine-readable, so the port does not get to redesign it
//
// proto/src/main/proto/controlplane.proto is the single source of truth for both sides' bindings and
// goproxy already generates a Go CLIENT from it. This server must serve exactly the ten RPCs
// pb.ControlPlaneServer declares, with the same status codes, because goproxy/cp/client.go already
// maps those codes to fail-closed behaviour.
//
// # Increment status
//
// Complete: ValidateToken, Decide, Register, PushCatalog, PushSchemaFragment, CloseConnection,
// ReportCompletion, Events.
// Transport-complete, PRODUCER-side pending: RunExec and TableDetailExec claim their session, relay
// the proxy's messages onto the registry's inbound channel and drain the registry's outbound channel
// onto the wire — every guard and every status code of 10-grpc.md §3.1. What does not exist yet is
// A7's RunExecService / A5's TableDetailExec, i.e. the code that REGISTERS a pending session and
// writes down the outbound channel. Until they land, a proxy dialing these gets NOT_FOUND, which is
// exactly what the Kotlin does for an unknown session id.
package grpcsvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/core"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/datasource"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/token"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// RunStreamTimeout is `RUN_STREAM_TIMEOUT_MS = 15 * 60 * 1000L` — the DEFAULT lifetime cap on one
// proxy-dialed RunExec stream.
//
// Production OVERRIDES it: Main computes max(15min, DIAL_TIMEOUT + queryExchangeTimeout + 30s),
// because "the stream is opened before the proxy reports ready, so its lifetime has to cover the dial
// as well as the exchange that follows. Leave the dial out and the cap falls short of the work it
// wraps once PM_QUERY_TIMEOUT is large: the stream then dies under a statement that is still
// legitimately running, and the caller sees a stream-closed error rather than the timeout it actually
// is."
//
// 🔒 INV-A10-50 — the cap covers the WHOLE STREAM LIFETIME, not one query: a persistent editor
// session runs N queries on ONE held stream.
const RunStreamTimeout = 15 * time.Minute

// TableDetailStreamTimeout is `TABLE_DETAIL_STREAM_TIMEOUT_MS = 60_000L`.
//
// ⚠️ F22 — hard-coded, NOT injectable, unlike its RunExec sibling. No test drives it. The asymmetry is
// reproduced rather than tidied.
const TableDetailStreamTimeout = 60 * time.Second

// completionStatuses is `COMPLETION_STATUSES = setOf("ok", "error", "canceled")`.
//
// "The completion-event terminal statuses the proxy reports: a clean finish, a backend/relay error
// carrying partial counts, or a canceled statement. Any other value is rejected fail-closed SO A
// MALFORMED REPORT CAN'T WRITE AN UNINTERPRETABLE OUTCOME INTO THE AUDIT TRAIL."
var completionStatuses = []string{"ok", "error", "canceled"}

// completionStatusesJoined is the exact text the INVALID_ARGUMENT description carries, so the JOIN
// ORDER above is message parity, not styling: "status must be one of ok|error|canceled".
var completionStatusesJoined = strings.Join(completionStatuses, "|")

// Service is `class ControlPlaneGrpcService(core, runStreamTimeoutMs = RUN_STREAM_TIMEOUT_MS)`.
//
// ⚠️ It deliberately does NOT embed pb.UnimplementedControlPlaneServer's forward-compatibility
// behaviour by accident: embedding turns a FORGOTTEN handler into a runtime Unimplemented instead of
// a compile error. The embed is required by the generated interface, so the compile-time assertion
// below is what actually proves all ten are implemented — do not delete it.
type Service struct {
	pb.UnimplementedControlPlaneServer

	core             *core.ControlPlaneCore
	runStreamTimeout time.Duration
	log              *slog.Logger
}

// The explicit assertion 10-grpc.md §3.1 asks for: every RPC is implemented on *Service itself, not
// inherited from the Unimplemented embed.
var (
	_ pb.ControlPlaneServer = (*Service)(nil)
	_                       = allHandlersImplemented
)

// NewService wires the service over the SHARED core (INV-A1-1). A zero runStreamTimeout takes the
// [RunStreamTimeout] default.
func NewService(c *core.ControlPlaneCore, runStreamTimeout time.Duration, log *slog.Logger) *Service {
	if runStreamTimeout <= 0 {
		runStreamTimeout = RunStreamTimeout
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{core: c, runStreamTimeout: runStreamTimeout, log: log}
}

// ---- 3. ValidateToken -------------------------------------------------------------------------

// ValidateToken is the once-per-session wire handshake: "May this session open?"
//
// 🔒 INV-A10-21 — an ephemeral (EDITOR / APPROVER_EXEC) token must NEVER pass this handshake. The
// enforcement lives in [token.Store.Validate]'s `kind IN ('SESSION','USER')` predicate, not here, so
// a leaked ephemeral token cannot open a native MySQL/PG session as that principal within its TTL.
//
// INV-A10-8 — the search-path seed is `defaultSchemas + systemSchemas` ONLY. No search_path crosses
// the wire here (the proxy has not opened a client session yet). Note the asymmetry with Decide's
// recovery path, which seeds `request.searchPath + defaultSchemas + systemSchemas`.
func (s *Service) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.WireIdentity, error) {
	// 1. The WRITE path (stamps last_used_at), restricted to SESSION|USER.
	id, err := s.core.TokenStore.Validate(ctx, req.GetToken())
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, status.Error(codes.Unauthenticated, "invalid, expired, or revoked wire token")
	}

	// 2. Deprovisioning is authN, not authZ — see INV-A10-11.
	deactivated, err := s.core.UserGroupStore.IsDeactivated(ctx, id.Principal)
	if err != nil {
		return nil, err
	}
	if deactivated {
		return nil, status.Error(codes.Unauthenticated, "principal is deprovisioned")
	}

	// 3. ⚠️ F26 — this runs THIRD, so a bad token AND a blank name reports UNAUTHENTICATED, not
	// INVALID_ARGUMENT. Reproduced.
	if strings.TrimSpace(req.GetDatasourceName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "datasource_name must not be blank")
	}

	// 4.
	ds, found, err := s.core.DatasourceStore.GetByName(ctx, req.GetDatasourceName())
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "unknown datasource '%s'", req.GetDatasourceName())
	}

	// 5.
	schemas, err := handshakeSchemas(ds)
	if err != nil {
		return nil, err
	}
	adopt, err := datasource.CatalogIsConnectionIndependent(ds.Engine)
	if err != nil {
		return nil, err
	}
	opened := s.core.ConnectionCatalog.Open(
		datasource.Binding{DatasourceName: ds.Name, Principal: id.Principal, TokenKind: id.Kind}, schemas, adopt,
	)

	// 6. ⚠️ F25 — `roles` comes STRAIGHT FROM THE TOKEN ROW, not server-resolved. Reproduced: A10's
	// Decide never trusts these for a SESSION/USER token (INV-A10-13), so the field is advisory here.
	return &pb.WireIdentity{
		Principal:    id.Principal,
		Roles:        id.Roles,
		ConnectionId: opened.ConnectionID.Bytes(),
		OnOpen:       proxyCommands(opened.OnOpen),
	}, nil
}

// handshakeSchemas is `ds.defaultSchemas + ds.engine.systemSchemas`, in a DETERMINISTIC order — see
// datasource.SystemSchemaNames on why ranging the map would not do.
func handshakeSchemas(ds datasource.Datasource) ([]string, error) {
	system, err := datasource.SystemSchemaNames(ds.Engine)
	if err != nil {
		return nil, err
	}
	return append(append([]string{}, ds.DefaultSchemas...), system...), nil
}

// ---- 4. Decide --------------------------------------------------------------------------------

// Decide is the per-statement enforcement decision.
//
// 🔒 It NEVER trusts a proxy-asserted principal, channel, or role set; every one of those is derived
// server-side from the raw token. The fifteen numbered steps below are 10-grpc.md §3.1's ordered rule
// list and the numbering is there so a reviewer can diff them line by line.
func (s *Service) Decide(ctx context.Context, req *pb.DecisionRequest) (*pb.WireDecision, error) {
	// 1. 🔒 INV-A10-9 — the RAW token is re-validated on EVERY query, so a mid-session revocation
	// takes effect on the NEXT query rather than at session end.
	// 🔒 INV-A10-10 — RESOLVE, not validate: read-only, so concurrent queries sharing one daemon token
	// do not serialize on the token row's last_used_at write. Unifying the two statements either
	// serializes the hot path or opens INV-A10-21's hole.
	id, err := s.core.TokenStore.Resolve(ctx, req.GetToken())
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, status.Error(codes.Unauthenticated, "invalid, expired, or revoked wire token")
	}

	// 2. 🔒 INV-A10-11 — an authN failure is UNAUTHENTICATED, NEVER a DENY verdict, "so the proxy can
	// tear the session down". This check is DELIBERATELY DUPLICATED with decideQuery's own
	// deactivation gate, because that one produces a DENY — and a DENY leaves the session open.
	deactivated, err := s.core.UserGroupStore.IsDeactivated(ctx, id.Principal)
	if err != nil {
		return nil, err
	}
	if deactivated {
		return nil, status.Error(codes.Unauthenticated, "principal is deprovisioned")
	}

	// 3.
	ds, found, err := s.core.DatasourceStore.GetByName(ctx, req.GetDatasourceName())
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "unknown datasource '%s'", req.GetDatasourceName())
	}

	// 4. A blank becomes nil, so a proxy that sends "" is not mistaken for having observed an address.
	var clientAddr *string
	if strings.TrimSpace(req.GetClientAddr()) != "" {
		v := req.GetClientAddr()
		clientAddr = &v
	}

	// 5. fromWire returns not-ok on an unrecognized value rather than throwing, so callers fail closed.
	kind, ok := token.KindFromWire(id.Kind)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "token kind is not valid for query decisions")
	}

	// 6-7. 🔒 INV-A10-12 — channel and assume-roles derive from the token KIND, which only the control
	// plane can set; the proxy cannot assert it.
	// 🔒 INV-A10-13 — a native-wire token's ON-TOKEN ROLES ARE IGNORED ENTIRELY. Only the ephemeral
	// kinds may carry a CP-computed assume-role set (execute-under-R), and it reaches DecideQuery as
	// ProvidedRoles, which REPLACES server role resolution (A6 step 6, A7 INV-A7-1).
	assumeRoles := assumeRolesFor(kind, id.Roles)
	// 🔒 INV-A10-14 — a no-R APPROVER_EXEC decides at EDITOR, never at WORKFLOW_EXECUTOR.
	// workflow-executor (where a policy may unmask R at execute) is reachable ONLY by an approver-exec
	// token that actually carries an assume-role set. Mapping APPROVER_EXEC → WORKFLOW_EXECUTOR
	// unconditionally reintroduces an escalation bug that was already fixed once.
	channel := channelFor(kind, assumeRoles != nil)

	// 8.
	tempColumns, err := editorTempOverlay(channel, req.GetTempColumns(), ds.Engine, ds.DBName)
	if err != nil {
		return nil, err
	}

	// 9. 🔒 INV-A10-17 — the requester-IP read is gated STRICTLY ON TOKEN KIND, never on "an entry
	// exists", so a native-wire token can never pick up a registry entry. The registry is keyed by the
	// token's SHA-256 HASH, never the raw token.
	var httpIP *string
	if kind == token.KindEditor || kind == token.KindApproverExec {
		httpIP = s.core.RunRequesterIPs.Get(token.Hash(req.GetToken()))
	}

	// 10. 🔒 INV-A10-18 — connection_id must be EXACTLY 16 bytes; both directions enforce it.
	// ⚠️ F27 — this is rule TEN, after three DB round-trips and two derivations. The position is
	// unpinned by any Kotlin test, and hoisting it would break none; it is reproduced here anyway
	// because a port is not the place to reorder guards.
	if len(req.GetConnectionId()) != 16 {
		return nil, status.Error(codes.InvalidArgument, "connection_id must be exactly 16 bytes")
	}

	// 11.
	binding := datasource.Binding{DatasourceName: ds.Name, Principal: id.Principal, TokenKind: id.Kind}
	connectionID := datasource.ConnectionID(req.GetConnectionId())

	// 12. ⚠️ INV-A10-20 — an unknown connection_id is RECOVERED, not rejected. That is deliberate (it
	// is how a control-plane restart re-learns live proxy connections) and it is a DOCUMENTED DEFECT:
	// a closed or forged id is recovered by Decide because there is no tombstone and no mint evidence.
	// Recovery does re-bind to (ds.name, principal, kind) from the freshly-resolved token, so the
	// blast radius is bounded by the proxy's own trust boundary. See F29 and
	// TestPostCloseDecideReuseIsRecovered, the characterization test that carries the defect's record.
	connection := s.core.ConnectionCatalog.Find(connectionID)
	if connection == nil {
		adopt, err := datasource.CatalogIsConnectionIndependent(ds.Engine)
		if err != nil {
			return nil, err
		}
		system, err := datasource.SystemSchemaNames(ds.Engine)
		if err != nil {
			return nil, err
		}
		seed := append(append(append([]string{}, req.GetSearchPath()...), ds.DefaultSchemas...), system...)
		recovered, ok := s.core.ConnectionCatalog.Recover(connectionID, binding, seed, adopt)
		if !ok {
			return nil, status.Error(codes.Aborted, "connection recovery raced with another request")
		}
		// No verdict, no audit row.
		return beforeDecideDecision(recovered.OnOpen), nil
	}

	// 13. 🔒 INV-A10-19 — a live connection's binding must equal (datasource, principal, kind). A live
	// id presented with a different principal's token is FAILED_PRECONDITION, not a decision.
	if connection.Binding != binding {
		return nil, status.Error(codes.FailedPrecondition, "connection binding mismatch")
	}

	// 14. NOTE THE ARGUMENT: assumeRoles lands on DecideConnection's ProvidedRoles.
	// 🔒 INV-A10-15 — search_path crosses VERBATIM; an empty list is NOT collapsed to the datasource
	// default. "Absent = default" would be fail-OPEN, since a failed namespace probe would authorize
	// against the stored default. An empty namespace resolves fail-closed (unqualified references
	// cannot resolve → DENY).
	outcome, found, err := s.core.DecideConnection(ctx, core.DecideConnectionInput{
		ConnectionID:    connectionID,
		Principal:       id.Principal,
		Datasource:      ds,
		SQL:             req.GetSql(),
		SearchPath:      req.GetSearchPath(),
		ClientAddr:      clientAddr,
		AnsiQuotes:      req.GetMysqlAnsiQuotes(),
		Channel:         channel,
		ProvidedRoles:   assumeRoles,
		TempColumns:     tempColumns,
		HTTPRequesterIP: httpIP,
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, status.Error(codes.NotFound, "connection disappeared during Decide")
	}

	// 15.
	switch o := outcome.(type) {
	case core.OutcomeBeforeDecide:
		return beforeDecideDecision(o.Commands), nil
	case core.OutcomeVerdict:
		return toWireDecision(o.Ctx, o.DecisionID, o.Generation, o.AfterStatement), nil
	default:
		// Unreachable: EnforcementOutcome has exactly two arms. Fail closed rather than return a
		// WireDecision with neither outcome arm set, which the proxy would deny anyway (INV-A10-38).
		return nil, status.Error(codes.Internal, "decideConnection returned no outcome")
	}
}

// assumeRolesFor is rule 6: `if (kind == EDITOR || kind == APPROVER_EXEC)
// id.roles.toSet().takeIf { it.isNotEmpty() } else null`.
//
// The result is a POINTER TO A SLICE because DecideQuery distinguishes nil ("resolve server-side")
// from the empty set ("this principal has no roles"). `takeIf { isNotEmpty() }` means an ephemeral
// token with an EMPTY role snapshot resolves server-side like any other — it does not decide with no
// roles.
func assumeRolesFor(kind token.Kind, roles []string) *[]string {
	if kind != token.KindEditor && kind != token.KindApproverExec {
		return nil
	}
	// `toSet()` — dedupe, preserving first-seen order (Kotlin's LinkedHashSet).
	seen := map[string]struct{}{}
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if _, dup := seen[r]; dup {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil
	}
	return &out
}

// channelFor is rule 7's `when (kind)`.
func channelFor(kind token.Kind, hasAssumeRoles bool) query.Channel {
	switch kind {
	case token.KindSession, token.KindUser:
		return query.ChannelWire
	case token.KindEditor:
		return query.ChannelEditor
	case token.KindApproverExec:
		if hasAssumeRoles {
			return query.ChannelWorkflowExecutor
		}
		return query.ChannelEditor
	default:
		// Unreachable — KindFromWire already rejected anything else. Editor is the more restrictive of
		// the two reachable answers, so the unreachable arm fails closed.
		return query.ChannelEditor
	}
}

// editorTempOverlay turns the proxy's self-reported session-temp columns into catalog rows the
// decision path may read UNMASKED — after applying BOTH trust gates.
//
// 🔒 INV-A10-16 — THE OVERLAY HAS TWO INDEPENDENT TRUST GATES AND BOTH ARE LOAD-BEARING, because
// "an overlay column is read without a Cedar grant AND skips the uncovered-scan gate, so it is
// load-bearing that only genuine session temps reach it."
//
//   - CHANNEL gate — temps are only legitimate on the EDITOR path (a persistent editor session holds
//     the backend connection whose temps these are). A wire / approver-exec decision carrying
//     temp_columns is a buggy or compromised proxy: DROP THEM ALL rather than grant the unmask on a
//     channel that was never analyzed for it.
//   - pg_temp* filter — an overlay entry names a schema read unmasked, so it must be an actual
//     session-temp namespace. Dropping anything else stops a proxy unmasking a real table (say
//     public.users) by mislabeling it a temp. Postgres reserves the `pg_` prefix, so no real schema
//     is ever named pg_temp*.
//
// 🔒 The reason an overlay column may be read unmasked AT ALL (controlplane.proto:196-199): a temp
// carries no classification, and THE WRITE-REFERENCES-MASKED DENY AT CREATE TIME ensures a temp only
// ever holds data its creator was entitled to read. A Go port that relaxes that A6 deny silently
// invalidates this unmasked read.
//
// ⚠️ F31 — this prefix test is CASE-SENSITIVE (`strings.HasPrefix`), while A5's freshness gate over
// the SAME request's search_path is case-INSENSITIVE. A `PG_TEMP_9` entry is therefore excluded from
// the fragments the freshness gate requires while its temp columns are dropped here. Postgres folds
// unquoted identifiers to lower case so a correct proxy never produces this; the divergence resolves
// fail-closed (no fragment and no overlay row ⇒ the name cannot resolve ⇒ DENY). Reproduced, and
// flagged at both call sites so a Go-side unification is a deliberate decision.
//
// INV-A10-7 — the catalog segment must match the analyzer namespace's (Postgres: the database name;
// MySQL: "def") so a temp key aligns with the base-catalog keys. A mismatched segment silently makes
// every temp key un-matchable.
func editorTempOverlay(
	channel query.Channel, temps []*pb.TempColumn, engine datasource.Engine, dbName string,
) ([]datasource.CatalogColumn, error) {
	if channel != query.ChannelEditor || len(temps) == 0 {
		return nil, nil
	}
	catalogName, err := datasource.CatalogName(engine, dbName)
	if err != nil {
		return nil, err
	}
	out := []datasource.CatalogColumn{}
	for _, t := range temps {
		if !strings.HasPrefix(t.GetSchema(), "pg_temp") {
			continue
		}
		out = append(out, datasource.CatalogColumn{
			Catalog: catalogName,
			Schema:  t.GetSchema(),
			Table:   t.GetTable(),
			Column:  t.GetColumn(),
			// dataType AND sqlType both take the proxy's sql_type; nullable is hard-coded true;
			// classification is left nil (a temp is unclassified by construction).
			DataType: t.GetSqlType(),
			SQLType:  t.GetSqlType(),
			Ordinal:  t.GetOrdinal(),
			Nullable: true,
			IsTemp:   true,
		})
	}
	return out, nil
}

// ---- 10. ReportCompletion ---------------------------------------------------------------------

// ReportCompletion records the post-relay completion as a chained audit event and moves a correlated
// NATIVE-WIRE task to its terminal state. It NEVER re-decides enforcement.
//
// 🔒 INV-A10-22 — both request guards run BEFORE any DB work, so a malformed report cannot write an
// uninterpretable outcome into the audit trail.
func (s *Service) ReportCompletion(ctx context.Context, req *pb.CompletionReport) (*emptypb.Empty, error) {
	// 1. decision_id 0 is rejected: a statement with no recorded decision is never reported.
	if req.GetDecisionId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "decision_id must reference a recorded decision")
	}
	// 2.
	if !isCompletionStatus(req.GetStatus()) {
		return nil, status.Error(codes.InvalidArgument, "status must be one of "+completionStatusesJoined)
	}
	// 3.
	decision, err := s.core.AuditStore.Get(ctx, req.GetDecisionId())
	if err != nil {
		return nil, err
	}
	if decision == nil {
		return nil, status.Errorf(codes.NotFound, "unknown decision_id %d", req.GetDecisionId())
	}

	// 4. ⚠️ F24 — EXACTLY FIVE identity fields are mirrored (principal, datasource, statement,
	// decision, channel). roles, clientAddr, effectiveNamespace, maskedColumns, piiTouched,
	// contextTags, failedStage and detail are all left at their defaults, even though INV-A10-45 says
	// "the completion mirrors the referenced decision's identity fields so the row is self-describing".
	// The gap is the finding; reproducing it is the port.
	completion := types.NewAuditEvent(decision.Principal, decision.Datasource, decision.Statement, decision.Decision)
	completion.Channel = decision.Channel
	completion.Kind = "completion"
	decisionID := req.GetDecisionId()
	completion.DecisionID = &decisionID
	rows := req.GetRowsReturned()
	completion.RowsReturned = &rows
	bytesReturned := req.GetBytesReturned()
	completion.BytesReturned = &bytesReturned
	outcome := req.GetStatus()
	completion.Outcome = &outcome
	completion.LatencyMs = req.GetDurationMs()

	// 5. 🔒 INV-A10-23 — the completion event and the task transition commit in ONE transaction, so an
	// audit-insert failure rolls the task transition back and vice versa.
	err = store.InTxDo(ctx, s.core.DB.Pool, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.core.AuditStore.InsertOn(ctx, tx, completion); err != nil {
			return err
		}
		// 🔒 INV-A10-25 — a completion for a decision with NO wire task is AUDIT-ONLY, so editor and
		// workflow execution lifecycles are untouched.
		taskID, err := s.core.AccessStore.WireTaskIDForDecision(ctx, tx, req.GetDecisionId())
		if err != nil {
			return err
		}
		if taskID == nil {
			return nil
		}
		// INV-A10-24 — the transition is an IDEMPOTENT COMPARE-AND-SET: duplicate reports still append
		// completion events, while ClaimExecution silently no-ops after the first terminal report.
		claimed, err := s.core.AccessStore.ClaimExecutionOn(ctx, tx, *taskID)
		if err != nil {
			return err
		}
		if !claimed {
			return nil
		}
		var moved bool
		if req.GetStatus() == "ok" {
			moved, err = s.core.AccessStore.MarkExecutedOn(ctx, tx, *taskID)
		} else {
			moved, err = s.core.AccessStore.MarkFailedOn(ctx, tx, *taskID)
		}
		if err != nil {
			return err
		}
		if !moved {
			// Kotlin's `check(...)` — an IllegalStateException that propagates out of inTx and aborts
			// the transaction. It is deliberately NOT mapped to a friendly status: an unmarkable task is
			// an INVARIANT VIOLATION, not a client error.
			return fmt.Errorf("wire task %d left EXECUTING", *taskID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func isCompletionStatus(v string) bool {
	for _, s := range completionStatuses {
		if s == v {
			return true
		}
	}
	return false
}

// ---- 5. PushSchemaFragment --------------------------------------------------------------------

// PushSchemaFragment applies a proxy-measured schema fragment to the connection it names.
//
// INV-A10-46 — the CONNECTION LOOKUP PRECEDES the datasource checks: a forged connection_id is
// NOT_FOUND regardless of what datasource_name says, and only a LIVE id with a mismatched name
// reaches FAILED_PRECONDITION.
//
// INV-A10-47 — A5 owns the rejection reason AND its status code, so the generation/hash/unchanged
// validation lives entirely in the registry and this handler is a pass-through. That is why
// datasource.Rejected carries a gRPC code: re-deriving the mapping here is exactly the duplication
// A5's design avoids.
func (s *Service) PushSchemaFragment(ctx context.Context, req *pb.SchemaFragmentPush) (*pb.SchemaFragmentAck, error) {
	connection := s.core.ConnectionCatalog.Find(datasource.ConnectionID(req.GetConnectionId()))
	if connection == nil {
		return nil, status.Error(codes.NotFound, "unknown connection_id")
	}
	if req.GetDatasourceName() != connection.Binding.DatasourceName {
		return nil, status.Error(codes.FailedPrecondition, "datasource binding mismatch")
	}
	ds, found, err := s.core.DatasourceStore.GetByName(ctx, req.GetDatasourceName())
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "unknown datasource '%s'", req.GetDatasourceName())
	}
	switch r := s.core.ConnectionCatalog.ApplyPush(req, ds).(type) {
	case datasource.Applied:
		return &pb.SchemaFragmentAck{Generation: uint64(r.Generation)}, nil
	case datasource.Rejected:
		return nil, status.Error(r.Code, r.Description)
	default:
		return nil, status.Error(codes.Internal, "unknown catalog mutation result")
	}
}

// ---- 6. CloseConnection -----------------------------------------------------------------------

// CloseConnection is the proxy-initiated close; the control-plane idle sweep is the backstop.
// No guard beyond the registry's own. Note Applied.Generation is DISCARDED on this path.
func (s *Service) CloseConnection(_ context.Context, req *pb.CloseConnectionRequest) (*pb.CloseConnectionResponse, error) {
	switch r := s.core.ConnectionCatalog.Close(
		datasource.ConnectionID(req.GetConnectionId()), req.GetDatasourceName(),
	).(type) {
	case datasource.Applied:
		return &pb.CloseConnectionResponse{}, nil
	case datasource.Rejected:
		return nil, status.Error(r.Code, r.Description)
	default:
		return nil, status.Error(codes.Internal, "unknown catalog mutation result")
	}
}

// ---- 1. Register ------------------------------------------------------------------------------

// Register is the idempotent upsert by name. The proxy declares its own identity on boot; the control
// plane never dials the target and holds no service credential for it.
func (s *Service) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// 1.
	if strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "datasource name must not be blank")
	}

	// 2. 🔒 INV-A10-26 — THE ENGINE CHECK IS INVERTED ON PURPOSE: pass the proto Engine through as the
	// domain type, rejecting only the invalid sentinels, so a FUTURE proto engine passes through
	// untouched instead of being rejected by an enumeration of the currently-known ones. Writing
	// `switch { case POSTGRES, MYSQL: ok; default: reject }` inverts the intent.
	// ⚠️ Go's generated enums have NO UNRECOGNIZED constant — an unknown wire value arrives as the raw
	// Engine(n) — so the second half of the condition is the descriptor lookup, and getting it wrong
	// silently accepts garbage.
	engine := req.GetEngine()
	if engine == enginepb.Engine_ENGINE_UNSPECIFIED || engine.Descriptor().Values().ByNumber(engine.Number()) == nil {
		return nil, status.Error(codes.InvalidArgument, "engine must be POSTGRES or MYSQL")
	}

	// 3. 🔒 INV-A10-27 — advertise_cert_chain presence is THREE-VALUED: ABSENT keeps what is stored (a
	// transient cert read on the proxy), PRESENT-but-empty means "publish nothing" and CLEARS it.
	// Collapsing the two would either drop a chain on every hiccup or strand clients on roots the
	// proxy no longer serves.
	var certChain *string
	if req.AdvertiseCertChain != nil {
		v := req.GetAdvertiseCertChain()
		certChain = &v
	}

	// 4. 🔒 INV-A10-28 — a questionable chain is REPORTED, NEVER REFUSED. Whether a chain is usable is
	// the CLIENT's verification to make, and rejecting at registration costs far more than it buys:
	// the datasource never gets created, no catalog is pushed, and every decision fails closed — a
	// total outage in place of one client's TLS error. Note a PRESENT-but-BLANK chain skips inspection
	// but is still forwarded, and therefore still clears the stored chain.
	if certChain != nil && strings.TrimSpace(*certChain) != "" {
		if reason, bad := InspectTrustChain(*certChain); bad {
			s.log.Warn(
				"datasource advertised a wire cert chain that may not verify — serving it anyway; "+
					"clients will report their own verification errors",
				"datasource", req.GetName(), "reason", reason,
			)
		}
	}

	// 5.
	var priorDBName *string
	if prior, found, err := s.core.DatasourceStore.GetByName(ctx, req.GetName()); err != nil {
		return nil, err
	} else if found {
		v := prior.DBName
		priorDBName = &v
	}

	// 6. INV-A10-48 — engine is IMMUTABLE at register and a rejection touches nothing. The guard is
	// A5's atomic conflict arm; this handler only maps the exception, as a client PRECONDITION
	// failure rather than a server error.
	ds, err := s.core.DatasourceStore.Register(
		ctx, req.GetName(), engine, req.GetHost(), req.GetPort(), req.GetDbName(), req.GetTags(),
		req.GetAdvertiseAddr(), certChain, req.GetAdvertiseWireTls(),
	)
	if err != nil {
		var conflict *datasource.EngineConflictError
		if errors.As(err, &conflict) {
			return nil, status.Error(codes.FailedPrecondition, conflict.Error())
		}
		return nil, err
	}

	// 7. 🔒 INV-A10-29 — a db_name RETARGET invalidates the held enforcement catalog. "The catalog push
	// that follows registration CANNOT repair this: it only confirms content it agrees with, and a
	// retarget is precisely the case where it disagrees. So the held structure would survive,
	// describing a database that is no longer there, and the next connection would adopt it."
	if priorDBName != nil && *priorDBName != ds.DBName {
		dropped := s.core.ConnectionCatalog.InvalidateDatasource(ds.Name)
		s.log.Info("datasource retargeted: dropped enforcement schemas",
			"datasource", ds.Name, "from", *priorDBName, "to", ds.DBName, "schemas", len(dropped))
	}

	// 8.
	return &pb.RegisterResponse{Name: ds.Name}, nil
}

// ---- 2. PushCatalog ---------------------------------------------------------------------------

// PushCatalog stores the whole catalog the proxy introspected.
//
// 🔒 INV-A10-30 — PushCatalog NEVER IMPLICITLY CREATES A DATASOURCE. The proxy must Register first;
// an unknown name is a fail-closed NOT_FOUND.
func (s *Service) PushCatalog(ctx context.Context, req *pb.CatalogRequest) (*pb.CatalogResponse, error) {
	ds, found, err := s.core.DatasourceStore.GetByName(ctx, req.GetDatasourceName())
	if err != nil {
		return nil, err
	}
	if !found {
		// The em dash is verbatim.
		return nil, status.Errorf(codes.NotFound, "unknown datasource '%s' — Register first", req.GetDatasourceName())
	}

	pushed := make([]datasource.PushedColumn, 0, len(req.GetColumns()))
	fragments := map[string][]datasource.FragmentColumn{}
	for _, c := range req.GetColumns() {
		pushed = append(pushed, datasource.PushedColumn{
			Schema: c.GetSchema(), Table: c.GetTable(), Column: c.GetColumn(),
			DataType: c.GetDataType(), Ordinal: c.GetOrdinal(), Nullable: c.GetNullable(),
		})
		fragments[c.GetSchema()] = append(fragments[c.GetSchema()], datasource.FragmentColumn{
			Schema: c.GetSchema(), Table: c.GetTable(), Column: c.GetColumn(),
			DataType: c.GetDataType(), Ordinal: c.GetOrdinal(), Nullable: c.GetNullable(),
		})
	}

	// `optional` int32: absent ⇒ nil, NOT 0. lower_case_table_names 0 is a real, load-bearing value.
	var lowerCase *int32
	if req.MysqlLowerCaseTableNames != nil {
		v := req.GetMysqlLowerCaseTableNames()
		lowerCase = &v
	}

	stored, err := s.core.DatasourceStore.StorePushedCatalog(
		ctx, ds.ID, req.GetDefaultSchemas(), lowerCase, req.GetEngineVersion(), pushed,
	)
	if err != nil {
		return nil, err
	}

	// INV-A10-31 — the push DOUBLES AS AN AMBIENT RE-MEASUREMENT of the ENFORCEMENT catalog, and the
	// staleness ceiling depends on it: "this push is a fresh whole-catalog read of the backend, so
	// where it agrees with content the enforcement pool already holds it RE-MEASURES that content …
	// and a connection is not made to re-probe a schema the proxy just confirmed."
	if confirmed := s.core.ConnectionCatalog.RecordAmbientMeasurement(ds.Name, fragments); len(confirmed) > 0 {
		s.log.Debug("ambient catalog measurement confirmed schemas", "datasource", ds.Name, "schemas", confirmed)
	}

	// INV-A10-49 — the manifest resolution is LOGGED at push time, per datasource: "Boot logs the
	// available set; this logs the hit." An operator sees at connect time whether this datasource's
	// system schemas are classified, on a fallback major, or uncertified (deny-by-default).
	var version *string
	if strings.TrimSpace(req.GetEngineVersion()) != "" {
		v := req.GetEngineVersion()
		version = &v
	}
	s.log.Info("datasource system-classification manifest",
		"datasource", ds.Name, "manifest", s.core.SystemClassification.DescribeManifestFor(ds.Engine, version))

	return &pb.CatalogResponse{Columns: int32(stored)}, nil
}

// ---- 7. Events --------------------------------------------------------------------------------

// Events is the proxy-initiated liveness + refresh stream. The proxy opens it once at startup and
// holds it for its lifetime: THE OPEN STREAM IS THE LIVENESS SIGNAL (close == the proxy detached).
//
// 🔒 INV-A10-35 — THE CONTROL PLANE NEVER DIALS INTO A PROXY. It only ever writes back down this
// proxy-opened pipe, and this handler is where the pipe is created.
//
// INV-A10-36 — markSeen is stamped on BOTH ATTACH AND DETACH. Stamping only on attach would report
// when the proxy ATTACHED, under-reporting liveness by a whole (possibly days-long) session.
// ⚠️ Consequence for the port: the Go client rotates this stream every 4 MINUTES, so the control
// plane sees detach-immediately-followed-by-attach on a 4-minute cadence. That is NORMAL, not
// flapping — and the control plane must NOT grow its own liveness probe on the assumption the stream
// is authoritative, because the design deliberately puts the recovery on the client. (The rotation
// exists because HTTP/2 keepalive proves the CONNECTION is alive, not that the stream still reaches a
// live control plane.)
func (s *Service) Events(req *pb.EventsRequest, stream pb.ControlPlane_EventsServer) error {
	ctx := stream.Context()
	name := req.GetDatasourceName()
	// No separate blank-name guard: GetByName("") simply finds nothing.
	ds, found, err := s.core.DatasourceStore.GetByName(ctx, name)
	if err != nil {
		return err
	}
	if !found {
		return status.Errorf(codes.NotFound, "unknown datasource '%s' — Register first", name)
	}
	if err := s.core.DatasourceStore.MarkSeen(ctx, ds.ID); err != nil {
		return err
	}

	sub := core.NewEventSubscriber()
	s.core.ProxyEventsHub.Register(name, sub)
	defer func() {
		s.core.ProxyEventsHub.Deregister(name, sub)
		// The detach stamp. context.Background() rather than ctx: ctx is already cancelled on the
		// ordinary close path, and a cancelled context would make the very write this invariant exists
		// for a no-op.
		if err := s.core.DatasourceStore.MarkSeen(context.Background(), ds.ID); err != nil {
			s.log.Warn("markSeen on Events detach failed", "datasource", name, "err", err)
		}
	}()

	// Emits nothing of its own; while open it relays whatever the hub pushes down the channel.
	for {
		select {
		case ev := <-sub.C():
			if err := stream.Send(ev); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// ---- 8. RunExec -------------------------------------------------------------------------------

// RunExec is the proxy-dialed, single-request run stream: the first request must CLAIM a pending run
// session, and every later proxy message is relayed to that request's private inbound channel.
//
// 🔒 INV-A10-32 — the first message must be the Ready arm, and A SESSION IS CLAIMABLE EXACTLY ONCE.
// The registry's attach removes-then-completes atomically, so an unknown id and a duplicate claim are
// INDISTINGUISHABLE BY DESIGN — both are NOT_FOUND. A claimed-twice stream could otherwise share
// another request's token and query.
//
// INV-A10-33 — the request stream is consumed by exactly ONE loop. grpc-go's Recv is naturally
// single-consumer so the Kotlin's single-collect constraint disappears, but the SHAPE (one goroutine
// draining Recv, writes going out through a registry-held channel) survives.
//
// INV-A10-34 — the cleanup runs on EVERY exit path. Closing the inbound channel unblocks whoever is
// reading it; removing the session is a no-op when Attach already removed the entry, which is what
// makes the failed-claim path safe. ⚠️ sessionID is assigned BEFORE Attach is attempted, deliberately:
// if the claim fails, the cleanup still names the session. Reproduce this ordering.
func (s *Service) RunExec(stream pb.ControlPlane_RunExecServer) error {
	ctx, cancel := context.WithTimeout(stream.Context(), s.runStreamTimeout)
	defer cancel()

	var (
		sessionID string
		attached  *core.Attached
	)
	defer func() {
		if attached != nil {
			close(attached.Inbound)
		}
		if sessionID != "" {
			s.core.RunChannels.Remove(sessionID)
		}
	}()

	outbound := make(chan *pb.ControlRunMsg, runOutboundBuffer)
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case msg, ok := <-outbound:
				if !ok {
					sendErr <- nil
					return
				}
				if err := stream.Send(msg); err != nil {
					sendErr <- err
					return
				}
			case <-ctx.Done():
				sendErr <- nil
				return
			}
		}
	}()

	for {
		msg, err := recvWithDeadline(ctx, stream.Recv)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				// Keep the CODE DeadlineExceeded: the Go client checks the code, never the text, and it
				// is what distinguishes an expected stream expiry from a fault.
				return status.Error(codes.DeadlineExceeded, "run stream lifetime exceeded")
			}
			if errors.Is(err, errStreamEOF) {
				break
			}
			return err
		}
		if attached == nil {
			if msg.GetSessionReady() == nil {
				return status.Error(codes.FailedPrecondition, "the first RunExec message must be RunReady")
			}
			sessionID = msg.GetSessionReady().GetSessionId()
			attached = s.core.RunChannels.Attach(sessionID, outbound)
			if attached == nil {
				return status.Errorf(codes.NotFound, "unknown or already-claimed run session '%s'", sessionID)
			}
			continue
		}
		select {
		case attached.Inbound <- msg:
		case <-ctx.Done():
			return status.Error(codes.DeadlineExceeded, "run stream lifetime exceeded")
		}
	}

	if attached == nil {
		return status.Error(codes.FailedPrecondition, "RunExec closed before RunReady")
	}
	return <-sendErr
}

// ---- 9. TableDetailExec -----------------------------------------------------------------------

// TableDetailExec is structurally identical to RunExec with four differences: the timeout is the
// hard-coded 60 s (F22), the registry is the table-detail one, the messages differ, and NO QUERY
// TOKEN IS NEEDED — this is metadata-only introspection.
func (s *Service) TableDetailExec(stream pb.ControlPlane_TableDetailExecServer) error {
	ctx, cancel := context.WithTimeout(stream.Context(), TableDetailStreamTimeout)
	defer cancel()

	var (
		sessionID string
		attached  *core.AttachedTableDetail
	)
	defer func() {
		if attached != nil {
			close(attached.Inbound)
		}
		if sessionID != "" {
			s.core.TableDetailChannels.Remove(sessionID)
		}
	}()

	outbound := make(chan *pb.ControlTableDetailMsg, runOutboundBuffer)
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case msg, ok := <-outbound:
				if !ok {
					sendErr <- nil
					return
				}
				if err := stream.Send(msg); err != nil {
					sendErr <- err
					return
				}
			case <-ctx.Done():
				sendErr <- nil
				return
			}
		}
	}()

	for {
		msg, err := recvWithDeadline(ctx, stream.Recv)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return status.Error(codes.DeadlineExceeded, "table-detail stream lifetime exceeded")
			}
			if errors.Is(err, errStreamEOF) {
				break
			}
			return err
		}
		if attached == nil {
			if msg.GetSessionReady() == nil {
				return status.Error(codes.FailedPrecondition, "the first TableDetailExec message must be TableDetailReady")
			}
			sessionID = msg.GetSessionReady().GetSessionId()
			attached = s.core.TableDetailChannels.Attach(sessionID, outbound)
			if attached == nil {
				return status.Errorf(codes.NotFound, "unknown or already-claimed table-detail session '%s'", sessionID)
			}
			continue
		}
		select {
		case attached.Inbound <- msg:
		case <-ctx.Done():
			return status.Error(codes.DeadlineExceeded, "table-detail stream lifetime exceeded")
		}
	}

	if attached == nil {
		return status.Error(codes.FailedPrecondition, "TableDetailExec closed before TableDetailReady")
	}
	return <-sendErr
}

// runOutboundBuffer is the depth of the per-stream outbound queue the producer writes into. Kotlin's
// channelFlow uses the BUFFERED default.
const runOutboundBuffer = 64

// errStreamEOF marks the client's half-close, which both bidi loops treat as "collect returned".
var errStreamEOF = errors.New("stream half-closed")

// recvWithDeadline runs one Recv against the stream deadline. grpc-go's Recv already observes the
// stream context, but the DERIVED timeout context is ours, so its expiry has to be turned into
// DEADLINE_EXCEEDED explicitly rather than surfacing as whatever a cancelled context produces.
func recvWithDeadline[T any](ctx context.Context, recv func() (*T, error)) (*T, error) {
	type result struct {
		msg *T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		msg, err := recv()
		ch <- result{msg, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			if errors.Is(r.err, io.EOF) {
				return nil, errStreamEOF
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, context.DeadlineExceeded
			}
			return nil, r.err
		}
		return r.msg, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, errStreamEOF
	}
}

// allHandlersImplemented is the compile-time proof that all ten RPCs are declared on *Service rather
// than inherited from the Unimplemented embed. If a handler is deleted, this stops compiling.
var allHandlersImplemented = []any{
	(*Service).Register, (*Service).PushCatalog, (*Service).ValidateToken, (*Service).Decide,
	(*Service).PushSchemaFragment, (*Service).CloseConnection, (*Service).Events,
	(*Service).RunExec, (*Service).TableDetailExec, (*Service).ReportCompletion,
}
