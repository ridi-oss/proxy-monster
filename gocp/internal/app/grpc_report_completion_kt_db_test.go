package app_test

// GrpcReportCompletionHandlerDbTest.kt — 6 cases.
//
// ReportCompletion is the proxy's post-relay report of what a permitted statement ACTUALLY returned, and
// it is the only place the audit trail learns result VOLUME. That is what makes it worth a DB-backed
// suite rather than a handler unit test: the report lands as a `kind="completion"` row inside the same
// hash chain as the decision it references, so a bad insert is not merely a missing metric — it breaks
// the chain an off-box verifier walks.

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ridi-oss/proxy-monster/gocp/internal/audit"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// completionFixture is the Kotlin's @BeforeAll, minus the wire task: every case here is about the
// AUDIT-ONLY path, and the task-transition half is WireTaskDecideDbTest's.
type completionFixture struct {
	t *testing.T
	b *bootedApp
}

func newCompletionFixture(t *testing.T) *completionFixture {
	t.Helper()
	return &completionFixture{t: t, b: bootE2E(t, nil)}
}

// seedDecision inserts the decision a completion will reference, straight through the store — the
// Kotlin does the same, because what is under test is the HANDLER and not how the decision got there.
func (f *completionFixture) seedDecision(principal, datasource, statement, channel string) int64 {
	f.t.Helper()
	rec := types.NewAuditEvent(principal, datasource, statement, types.DecisionAllow)
	if channel != "" {
		rec.Channel = &channel
	}
	rec.Roles = []string{"analyst"}
	id, err := f.b.app.Core.AuditStore.Insert(context.Background(), rec)
	if err != nil {
		f.t.Fatalf("seed decision: %v", err)
	}
	return id
}

func (f *completionFixture) report(req *pb.CompletionReport) error {
	_, err := f.b.client.ReportCompletion(context.Background(), req)
	return err
}

// completionIDFor is the Kotlin's helper: the newest completion row referencing a decision.
func (f *completionFixture) completionIDFor(decisionID int64) int64 {
	f.t.Helper()
	var id int64
	if err := f.b.app.Db.Pool.QueryRow(context.Background(),
		`SELECT id FROM audit_event WHERE kind = 'completion' AND decision_id = $1 ORDER BY id DESC LIMIT 1`,
		decisionID).Scan(&id); err != nil {
		f.t.Fatalf("no completion row for decision %d: %v", decisionID, err)
	}
	return id
}

type chainCols struct {
	chainVersion int32
	prevHash     []byte
	rowHash      []byte
}

func (f *completionFixture) chainColumns(id int64) chainCols {
	f.t.Helper()
	var c chainCols
	if err := f.b.app.Db.Pool.QueryRow(context.Background(),
		`SELECT chain_version, prev_hash, row_hash FROM audit_event WHERE id = $1`, id,
	).Scan(&c.chainVersion, &c.prevHash, &c.rowHash); err != nil {
		f.t.Fatalf("read chain columns for %d: %v", id, err)
	}
	return c
}

func (f *completionFixture) chainHead() (int64, []byte) {
	f.t.Helper()
	var lastID int64
	var headHash []byte
	if err := f.b.app.Db.Pool.QueryRow(context.Background(),
		`SELECT last_id, head_hash FROM audit_chain_head WHERE id = 1`).Scan(&lastID, &headHash); err != nil {
		f.t.Fatalf("read chain head: %v", err)
	}
	return lastID, headHash
}

func (f *completionFixture) accessRequestCount() int64 {
	f.t.Helper()
	var n int64
	if err := f.b.app.Db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM access_request`).Scan(&n); err != nil {
		f.t.Fatalf("count access_request: %v", err)
	}
	return n
}

// TestACompletionReportInsertsAChainedCompletionEventReferencingTheDecision is case 1, the whole
// contract in one case.
//
// 🔒 IT CHAINS. prev_hash IS the decision's row_hash, the stored row_hash RECOMPUTES from the persisted
// columns under the canonical format, and the chain HEAD advanced to the completion. That triple is
// exactly what an off-box verifier re-walks, so a completion inserted outside the chain-head lock — or
// with a hand-built prev_hash — would leave a trail that verifies nowhere.
//
// 🔒 The completion MIRRORS the decision's identity fields rather than trusting the proxy for them. The
// proxy sends only a decision id and four numbers; principal, datasource, statement and decision are
// read back off the referenced row. A completion that carried proxy-supplied identity would let a
// compromised proxy write an audit row attributing a query to someone else.
//
// ⚠️ F24 — the mirror is FIVE fields (principal, datasource, statement, decision, channel) and no more:
// roles, clientAddr, effectiveNamespace, maskedColumns, piiTouched, contextTags, failedStage and detail
// stay at their defaults even though INV-A10-45 says the row should be self-describing. The seeded
// decision above carries roles DELIBERATELY, and the assertion below pins that they do NOT cross — the
// gap is a recorded finding, and reproducing it is the port.
//
// KT: GrpcReportCompletionHandlerDbTest.kt#a completion report inserts a chained completion event referencing the decision
func TestACompletionReportInsertsAChainedCompletionEventReferencingTheDecision(t *testing.T) {
	f := newCompletionFixture(t)
	ctx := context.Background()

	decisionID := f.seedDecision("analyst@example.com", "sales-mysql", "SELECT name FROM users", "wire")
	decisionRowHash := f.chainColumns(decisionID).rowHash

	if err := f.report(&pb.CompletionReport{
		DecisionId: decisionID, RowsReturned: 50_000, BytesReturned: 262_144, Status: "ok", DurationMs: 42,
	}); err != nil {
		t.Fatalf("ReportCompletion: %v", err)
	}

	completionID := f.completionIDFor(decisionID)
	completion, err := f.b.app.Core.AuditStore.Get(ctx, completionID)
	if err != nil || completion == nil {
		t.Fatalf("get completion %d: %v", completionID, err)
	}

	if completion.Kind != "completion" {
		t.Errorf("kind = %q, want completion", completion.Kind)
	}
	if completion.DecisionID == nil || *completion.DecisionID != decisionID {
		t.Errorf("decisionId = %v, want %d", completion.DecisionID, decisionID)
	}
	if completion.RowsReturned == nil || *completion.RowsReturned != 50_000 {
		t.Errorf("rowsReturned = %v, want 50000", completion.RowsReturned)
	}
	if completion.BytesReturned == nil || *completion.BytesReturned != 262_144 {
		t.Errorf("bytesReturned = %v, want 262144", completion.BytesReturned)
	}
	if completion.Outcome == nil || *completion.Outcome != "ok" {
		t.Errorf("outcome = %v, want ok", completion.Outcome)
	}
	if completion.LatencyMs != 42 {
		t.Errorf("latencyMs = %d, want 42", completion.LatencyMs)
	}

	// The mirrored identity — read off the decision, never taken from the proxy.
	if completion.Principal != "analyst@example.com" {
		t.Errorf("principal = %q, want the DECISION's principal", completion.Principal)
	}
	if completion.Datasource != "sales-mysql" {
		t.Errorf("datasource = %q — the mass-export rule keys on this, so it must mirror the decision", completion.Datasource)
	}
	if completion.Statement != "SELECT name FROM users" {
		t.Errorf("statement = %q, want the decision's", completion.Statement)
	}
	if completion.Decision != types.DecisionAllow {
		t.Errorf("decision = %v, want ALLOW mirrored from the decision", completion.Decision)
	}
	// ⚠️ F24, pinned: the seeded decision carries roles and the completion does not.
	if len(completion.Roles) != 0 {
		t.Errorf("roles = %v, want EMPTY — F24 records that only five identity fields are mirrored. If "+
			"roles now cross, the gap was closed and this assertion (plus F24) needs updating", completion.Roles)
	}

	// ---- the chain.
	chain := f.chainColumns(completionID)
	if !bytes.Equal(chain.prevHash, decisionRowHash) {
		t.Error("the completion did not chain onto the decision: prev_hash is not the decision's row_hash")
	}
	if chain.chainVersion != int32(audit.ChainVersion) {
		t.Errorf("chain_version = %d, want %d", chain.chainVersion, audit.ChainVersion)
	}
	if completion.TS == nil {
		t.Fatal("the completion has no ts, so its hash cannot be recomputed")
	}
	ts, err := audit.ParseInstant(*completion.TS)
	if err != nil {
		t.Fatalf("parse completion ts %q: %v", *completion.TS, err)
	}
	want, err := audit.RowHash(completionID, *completion, audit.EpochMicros(audit.TruncateToMicros(ts)), chain.prevHash)
	if err != nil {
		t.Fatalf("recompute the completion row hash: %v", err)
	}
	if !bytes.Equal(want, chain.rowHash) {
		t.Error("the persisted completion does not reproduce its stored row_hash — an off-box verifier " +
			"would report the trail as tampered")
	}

	// ---- and the head advanced to it.
	headLast, headHash := f.chainHead()
	if headLast != completionID {
		t.Errorf("chain head last_id = %d, want the completion %d", headLast, completionID)
	}
	if !bytes.Equal(headHash, chain.rowHash) {
		t.Error("chain head hash is not the completion's row_hash")
	}
}

// TestACompletionForADecisionWithoutAWireTaskStaysAuditOnly is case 2 — 🔒 INV-A10-25.
//
// The handler's transaction ALSO transitions a wire task when the decision has one. A decision that has
// none — every editor and native-wire query — must therefore take the audit-only path and touch
// `access_request` not at all. A handler that inserted or updated a task row here would fabricate
// approval-workflow state for a query that was never part of a workflow.
//
// KT: GrpcReportCompletionHandlerDbTest.kt#a completion for a decision without a wire task stays audit-only
func TestACompletionForADecisionWithoutAWireTaskStaysAuditOnly(t *testing.T) {
	f := newCompletionFixture(t)

	decisionID := f.seedDecision("editor@example.com", "sales-mysql", "SELECT id FROM users", "editor")
	before := f.accessRequestCount()

	if err := f.report(&pb.CompletionReport{
		DecisionId: decisionID, Status: "ok", RowsReturned: 1, BytesReturned: 8, DurationMs: 1,
	}); err != nil {
		t.Fatalf("ReportCompletion: %v", err)
	}

	if after := f.accessRequestCount(); after != before {
		t.Errorf("access_request rows %d → %d; a decision with no wire task must stay AUDIT-ONLY", before, after)
	}
	completion, err := f.b.app.Core.AuditStore.Get(context.Background(), f.completionIDFor(decisionID))
	if err != nil || completion == nil {
		t.Fatalf("get completion: %v", err)
	}
	if completion.Kind != "completion" {
		t.Errorf("kind = %q, want completion — audit-only still means AUDITED", completion.Kind)
	}
}

// TestACompletionCarriesTheTerminalErrorStatusAndPartialCounts is case 3.
//
// 🔒 A FAILED RELAY STILL REPORTS WHAT IT SENT. The rows that reached the client before the failure left
// the building whether or not the statement completed, so an implementation that discarded the counts on
// a non-ok status — or refused the report — would lose exactly the volume a mass-export investigation
// needs, and would do so on the failures that are most worth investigating.
//
// KT: GrpcReportCompletionHandlerDbTest.kt#a completion carries the terminal error status and partial counts
func TestACompletionCarriesTheTerminalErrorStatusAndPartialCounts(t *testing.T) {
	f := newCompletionFixture(t)

	decisionID := f.seedDecision("analyst@example.com", "sales-mysql", "SELECT * FROM big", "")
	if err := f.report(&pb.CompletionReport{
		DecisionId: decisionID, RowsReturned: 7, BytesReturned: 512, Status: "error", DurationMs: 3,
	}); err != nil {
		t.Fatalf("ReportCompletion: %v", err)
	}

	completion, err := f.b.app.Core.AuditStore.Get(context.Background(), f.completionIDFor(decisionID))
	if err != nil || completion == nil {
		t.Fatalf("get completion: %v", err)
	}
	if completion.Outcome == nil || *completion.Outcome != "error" {
		t.Errorf("outcome = %v, want the terminal error status carried verbatim", completion.Outcome)
	}
	if completion.RowsReturned == nil || *completion.RowsReturned != 7 {
		t.Errorf("rowsReturned = %v, want the PARTIAL count 7 — those rows reached the client", completion.RowsReturned)
	}
}

// TestACompletionWithDecisionIdZeroIsRejectedInvalidArgument is case 4.
//
// ⚠️ proto3 makes 0 the ABSENT value for an int64, so "no decision id" and "decision id 0" are the same
// message on the wire. The guard is therefore load-bearing rather than defensive: without it the handler
// would look the id up, find nothing, and answer NOT_FOUND — telling the proxy "that decision is gone"
// when the real problem is that it sent no id at all. Audit ids start at 1, which is what makes 0 a safe
// sentinel.
//
// KT: GrpcReportCompletionHandlerDbTest.kt#a completion with decision_id 0 is rejected INVALID_ARGUMENT
func TestACompletionWithDecisionIdZeroIsRejectedInvalidArgument(t *testing.T) {
	f := newCompletionFixture(t)

	err := f.report(&pb.CompletionReport{DecisionId: 0, Status: "ok"})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("decision_id 0 = %v, want INVALID_ARGUMENT (not NOT_FOUND — the id is absent, not missing)", got)
	}
}

// TestACompletionForAnUnknownDecisionIsRejectedNotFound is case 5: a well-formed id that names no row.
//
// 🔒 The insert would violate `decision_id`'s foreign key anyway; answering NOT_FOUND rather than letting
// the constraint fire is what turns an opaque 500 into something a proxy can act on. It also proves the
// completion cannot exist without its decision — the property AuditTrailSchemaDbTest asserts from the
// schema side.
//
// KT: GrpcReportCompletionHandlerDbTest.kt#a completion for an unknown decision is rejected NOT_FOUND
func TestACompletionForAnUnknownDecisionIsRejectedNotFound(t *testing.T) {
	f := newCompletionFixture(t)

	err := f.report(&pb.CompletionReport{DecisionId: 9_223_372_036_854_775_807, Status: "ok"})
	if got := status.Code(err); got != codes.NotFound {
		t.Errorf("an unknown decision_id = %v, want NOT_FOUND", got)
	}
}

// TestACompletionWithAnUnknownStatusIsRejectedInvalidArgument is case 6.
//
// 🔒 `status` DRIVES THE WIRE-TASK TRANSITION — "ok" marks the task executed and anything else marks it
// failed. An unvalidated status would therefore make any typo silently mean "failed", and an approved
// workflow execution that actually succeeded would be recorded as a failure. Rejecting the report is the
// only answer that does not guess.
//
// ⚠️ The order matters and is asserted by construction: the decision here EXISTS, so a NOT_FOUND would
// mean the status check runs after the lookup. The Go handler validates the status second, before the
// lookup — matching the Kotlin.
//
// KT: GrpcReportCompletionHandlerDbTest.kt#a completion with an unknown status is rejected INVALID_ARGUMENT
func TestACompletionWithAnUnknownStatusIsRejectedInvalidArgument(t *testing.T) {
	f := newCompletionFixture(t)

	decisionID := f.seedDecision("p", "d", "s", "")
	err := f.report(&pb.CompletionReport{DecisionId: decisionID, Status: "weird"})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("an unknown status = %v, want INVALID_ARGUMENT", got)
	}
	// And nothing was written: a rejected report must not leave a completion row behind.
	var n int64
	if err := f.b.app.Db.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_event WHERE kind = 'completion' AND decision_id = $1`, decisionID).Scan(&n); err != nil {
		t.Fatalf("count completions: %v", err)
	}
	if n != 0 {
		t.Errorf("a REJECTED report left %d completion row(s) behind", n)
	}
}
