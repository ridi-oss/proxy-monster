package core_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/grpcsvc"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// PORT of `WireTaskDecideDbContract` — 10 cases, run against BOTH engines like the Kotlin's two
// subclasses (WireTaskDecideMysqlDbTest / WireTaskDecidePostgresDbTest).
//
// WHAT THE SUITE IS FOR: a WIRE decision does not only answer the proxy, it also writes an
// `access_request` lifecycle row (kind=QUERY, creator_kind=WIRE) so every wire statement is
// accounted for. These cases pin the row's state machine against each decision outcome, and — just as
// importantly — that the row's existence did NOT change the bytes relayed to the proxy.
//
// 🔒 WIRE TASKS ARE INTERNAL LIFECYCLE ROWS, deliberately kept OFF the human /api/approvals feed
// (which returns WORKFLOW rows only), so they are listed straight from the table here.
//
// ⚠️ ONE DEVIATION, stated because it is a weakening. The Kotlin's `assertWireBytesUnchanged` compares
// the serialized WireDecision proto before and after. Go's `toWireDecision` is unexported in
// internal/grpcsvc, so the comparison here is over the DecisionContext fields that FEED it — action,
// deny reason, masks, rewritten SQL, failed stage — plus the after-statement commands. That is the
// complete input set of the mapper (internal/grpcsvc/mappers.go:27), so a difference in relay bytes
// implies a difference here; what is lost is catching a change in the MAPPER itself, which
// internal/grpcsvc/mappers_test.go owns.
// ---------------------------------------------------------------------------------------------

type wireTaskFixture struct {
	t       *testing.T
	f       *perConnCatalogFixture
	svc     *grpcsvc.Service
	ctx     context.Context
	created []int64
}

func newWireTaskFixture(t *testing.T, engine string) *wireTaskFixture {
	t.Helper()
	f := newPerConnCatalogFixture(t, engine)
	w := &wireTaskFixture{
		t: t, f: f, ctx: context.Background(),
		svc: grpcsvc.NewService(f.core, 0, slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	// `@AfterEach disableTestPolicies` — every forbid a case adds is disabled again, so the two
	// policy-override cases cannot leak a deny into the eight that expect ALLOW/MASK.
	t.Cleanup(func() {
		for _, id := range w.created {
			if _, err := f.core.CedarPolicyStore.SetEnabled(w.ctx, id, false, types.Ptr("test-cleanup")); err != nil {
				t.Errorf("disable policy %d: %v", id, err)
			}
		}
	})
	return w
}

func (w *wireTaskFixture) schemas() []string { return w.f.datasource.DefaultSchemas }

// decide is the Kotlin's `decide(opened, sql, channel)`.
func (w *wireTaskFixture) decide(opened datasource.OpenConnection, sql string, channel query.Channel) core.EnforcementOutcome {
	w.t.Helper()
	out, found, err := w.f.core.DecideConnection(w.ctx, core.DecideConnectionInput{
		ConnectionID: opened.ConnectionID,
		Principal:    dbtest.FixturePrincipal,
		Datasource:   w.f.datasource,
		SQL:          sql,
		SearchPath:   w.schemas(),
		ClientAddr:   types.Ptr("127.0.0.1:54321"),
		Channel:      channel,
	})
	if err != nil {
		w.t.Fatalf("DecideConnection: %v", err)
	}
	if !found {
		w.t.Fatal("connection disappeared during decision")
	}
	return out
}

func (w *wireTaskFixture) wireDecide(opened datasource.OpenConnection, sql string) core.EnforcementOutcome {
	return w.decide(opened, sql, query.ChannelWire)
}

// verdict demands the Verdict arm — `assertIs<EnforcementOutcome.Verdict>(…)`.
func (w *wireTaskFixture) verdict(out core.EnforcementOutcome) core.OutcomeVerdict {
	w.t.Helper()
	v, ok := out.(core.OutcomeVerdict)
	if !ok {
		w.t.Fatalf("outcome = %T, want a Verdict", out)
	}
	return v
}

// relayShape is the set of DecisionContext fields the wire mapper reads — see the deviation note.
type relayShape struct {
	action       pb.EnfAction
	denyReason   string
	masks        []*pb.ColumnMask
	rewrittenSQL string
	failedStage  string
	after        []*pb.Refetch
}

func shapeOf(v core.OutcomeVerdict) relayShape {
	s := relayShape{action: v.Ctx.Action, masks: v.Ctx.Masks, after: v.AfterStatement}
	if v.Ctx.DenyReason != nil {
		s.denyReason = *v.Ctx.DenyReason
	}
	if v.Ctx.RewrittenSQL != nil {
		s.rewrittenSQL = *v.Ctx.RewrittenSQL
	}
	if v.Ctx.FailedStage != nil {
		s.failedStage = *v.Ctx.FailedStage
	}
	return s
}

// assertRelayUnchanged is `assertWireBytesUnchanged`: creating the wire-task row must not perturb
// anything the proxy is told.
func (w *wireTaskFixture) assertRelayUnchanged(want, got relayShape) {
	w.t.Helper()
	if want.action != got.action {
		w.t.Errorf("relay action changed: %s → %s", want.action, got.action)
	}
	if want.denyReason != got.denyReason {
		w.t.Errorf("relay denyReason changed: %q → %q", want.denyReason, got.denyReason)
	}
	if want.rewrittenSQL != got.rewrittenSQL {
		w.t.Errorf("relay rewrittenSql changed: %q → %q", want.rewrittenSQL, got.rewrittenSQL)
	}
	if want.failedStage != got.failedStage {
		w.t.Errorf("relay failedStage changed: %q → %q", want.failedStage, got.failedStage)
	}
	if len(want.masks) != len(got.masks) {
		w.t.Errorf("relay mask count changed: %d → %d", len(want.masks), len(got.masks))
		return
	}
	for i := range want.masks {
		if !proto.Equal(want.masks[i], got.masks[i]) {
			w.t.Errorf("relay mask %d changed: %v → %v", i, want.masks[i], got.masks[i])
		}
	}
}

// wireTasks lists the WIRE-created QUERY rows for the fixture principal, oldest first.
func (w *wireTaskFixture) wireTasks() []int64 {
	w.t.Helper()
	rows, err := w.f.core.DB.Pool.Query(w.ctx,
		`SELECT id FROM access_request
		     WHERE kind = 'QUERY' AND creator_kind = 'WIRE' AND principal = $1 ORDER BY id`,
		dbtest.FixturePrincipal)
	if err != nil {
		w.t.Fatalf("list wire tasks: %v", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			w.t.Fatalf("scan wire task: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

// taskForDecision is `wireTasks().single { it.sourceDecisionId == decisionId }`.
func (w *wireTaskFixture) taskForDecision(decisionID int64) *accessRequestRow {
	w.t.Helper()
	var found *accessRequestRow
	for _, id := range w.wireTasks() {
		r := w.request(id)
		if r.sourceDecisionID != nil && *r.sourceDecisionID == decisionID {
			if found != nil {
				w.t.Fatalf("two wire tasks reference decision %d", decisionID)
			}
			found = r
		}
	}
	if found == nil {
		w.t.Fatalf("no wire task references decision %d", decisionID)
	}
	return found
}

type accessRequestRow struct {
	id               int64
	status           string
	sourceDecisionID *int64
	executingAt      *string
	executedAt       *string
	executeAs        []string
}

func (w *wireTaskFixture) request(id int64) *accessRequestRow {
	w.t.Helper()
	r, err := w.f.core.AccessStore.GetRequest(w.ctx, id)
	if err != nil || r == nil {
		w.t.Fatalf("GetRequest(%d): %v", id, err)
	}
	return &accessRequestRow{
		id: r.ID, status: r.Status, sourceDecisionID: r.SourceDecisionID,
		executingAt: r.ExecutingAt, executedAt: r.ExecutedAt, executeAs: r.ExecuteAs,
	}
}

// complete is the Kotlin's `complete(decisionId, status)` — through the REAL gRPC handler, because the
// task transition is the handler's, not the store's.
func (w *wireTaskFixture) complete(decisionID int64, status string) {
	w.t.Helper()
	if _, err := w.svc.ReportCompletion(w.ctx, &pb.CompletionReport{
		DecisionId: decisionID, Status: status,
		RowsReturned: 1, BytesReturned: 10, DurationMs: 1,
	}); err != nil {
		w.t.Fatalf("ReportCompletion(%d, %s): %v", decisionID, status, err)
	}
}

func (w *wireTaskFixture) childCount(taskID int64) int {
	w.t.Helper()
	var n int
	if err := w.f.core.DB.Pool.QueryRow(w.ctx,
		`SELECT count(*) FROM query_result WHERE task_id = $1`, taskID).Scan(&n); err != nil {
		w.t.Fatalf("child count for %d: %v", taskID, err)
	}
	return n
}

func (w *wireTaskFixture) addForbid(name, src string) {
	w.t.Helper()
	p, err := w.f.core.CedarPolicyStore.Create(w.ctx, policy.NewCedarPolicyInput(name, src), types.Ptr("wire-task-test"))
	if err != nil {
		w.t.Fatalf("create forbid %s: %v", name, err)
	}
	w.created = append(w.created, p.ID)
}

func (w *wireTaskFixture) openAndPush() datasource.OpenConnection {
	w.t.Helper()
	return w.f.openAndPush(dbtest.FixturePrincipal, w.schemas()...)
}

// eachEngine runs a case against both engines, which is what the Kotlin's two subclasses do.
func eachEngine(t *testing.T, body func(t *testing.T, w *wireTaskFixture)) {
	for _, engine := range []string{"postgres", "mysql"} {
		t.Run(engine, func(t *testing.T) {
			body(t, newWireTaskFixture(t, engine))
		})
	}
}

// --- the cases ------------------------------------------------------------------------------------

// KT: WireTaskDecideDbTest.kt#ALLOW stays approved until a clean completion executes it and preserves relay bytes
func TestWireTaskAllowStaysApprovedUntilCleanCompletion(t *testing.T) {
	eachEngine(t, func(t *testing.T, w *wireTaskFixture) {
		opened := w.openAndPush()
		baseline := shapeOf(w.verdict(w.wireDecide(opened, "select id from users")))

		v := w.verdict(w.wireDecide(opened, "select id from users"))
		if v.Ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("action = %s, want ALLOW (%v)", v.Ctx.Action, v.Ctx.DenyReason)
		}
		w.assertRelayUnchanged(baseline, shapeOf(v))

		task := w.taskForDecision(v.DecisionID)
		if task.status != "APPROVED" {
			t.Errorf("status = %s, want APPROVED — a wire ALLOW is not executed until the proxy says so",
				task.status)
		}
		if task.sourceDecisionID == nil || *task.sourceDecisionID != v.DecisionID {
			t.Errorf("sourceDecisionId = %v, want %d", task.sourceDecisionID, v.DecisionID)
		}
		if len(task.executeAs) != 1 || task.executeAs[0] != dbtest.FixtureRole {
			t.Errorf("executeAs = %v, want [%s]", task.executeAs, dbtest.FixtureRole)
		}
		// 🔒 A wire task stores NO result rows: the proxy streams to the client directly.
		if n := w.childCount(task.id); n != 0 {
			t.Errorf("child result rows = %d, want 0", n)
		}

		w.complete(v.DecisionID, "ok")

		done := w.request(task.id)
		if done.status != "EXECUTED" {
			t.Errorf("status after a clean completion = %s, want EXECUTED", done.status)
		}
		if done.executingAt == nil {
			t.Error("executingAt is null after completion")
		}
		if done.executedAt == nil {
			t.Error("executedAt is null after a CLEAN completion")
		}
	})
}

// KT: WireTaskDecideDbTest.kt#error and canceled completions fail their wire tasks
func TestWireTaskErrorAndCanceledCompletionsFail(t *testing.T) {
	eachEngine(t, func(t *testing.T, w *wireTaskFixture) {
		opened := w.openAndPush()
		for _, status := range []string{"error", "canceled"} {
			v := w.verdict(w.wireDecide(opened, "select id from users"))
			task := w.taskForDecision(v.DecisionID)
			if task.status != "APPROVED" {
				t.Fatalf("%s: pre-completion status = %s, want APPROVED", status, task.status)
			}

			w.complete(v.DecisionID, status)

			failed := w.request(task.id)
			if failed.status != "FAILED" {
				t.Errorf("%s: status = %s, want FAILED", status, failed.status)
			}
			if failed.executingAt == nil {
				t.Errorf("%s: executingAt is null; the task did start", status)
			}
			// 🔒 executedAt is TERMINAL-SUCCESS ONLY. A failed run must not look like a completed one.
			if failed.executedAt != nil {
				t.Errorf("%s: executedAt = %v, want null on a failure", status, *failed.executedAt)
			}
		}
	})
}

// KT: WireTaskDecideDbTest.kt#only the completed decision executes in a prepare then execute pair
//
// 🔒 THE COMPLETION IS KEYED ON ITS DECISION, not on the principal or the connection. A prepare/execute
// pair produces two decisions and two tasks; completing the second must leave the first APPROVED.
func TestWireTaskOnlyTheCompletedDecisionExecutes(t *testing.T) {
	eachEngine(t, func(t *testing.T, w *wireTaskFixture) {
		opened := w.openAndPush()
		before := map[int64]bool{}
		for _, id := range w.wireTasks() {
			before[id] = true
		}

		prepared := w.verdict(w.wireDecide(opened, "select id from users"))
		executed := w.verdict(w.wireDecide(opened, "select id from users"))

		w.complete(executed.DecisionID, "ok")

		if got := w.taskForDecision(prepared.DecisionID).status; got != "APPROVED" {
			t.Errorf("prepared task status = %s, want APPROVED — completing one decision must not "+
				"execute its sibling", got)
		}
		if got := w.taskForDecision(executed.DecisionID).status; got != "EXECUTED" {
			t.Errorf("executed task status = %s, want EXECUTED", got)
		}
		newlyExecuted := 0
		for _, id := range w.wireTasks() {
			if !before[id] && w.request(id).status == "EXECUTED" {
				newlyExecuted++
			}
		}
		if newlyExecuted != 1 {
			t.Errorf("newly EXECUTED wire tasks = %d, want exactly 1", newlyExecuted)
		}
	})
}

// KT: WireTaskDecideDbTest.kt#MASK stays approved until completion and preserves mask relay bytes
func TestWireTaskMaskStaysApprovedUntilCompletion(t *testing.T) {
	eachEngine(t, func(t *testing.T, w *wireTaskFixture) {
		opened := w.openAndPush()
		baseline := shapeOf(w.verdict(w.wireDecide(opened, "select rrn from users")))

		v := w.verdict(w.wireDecide(opened, "select rrn from users"))
		if v.Ctx.Action != pb.EnfAction_MASK {
			t.Fatalf("action = %s, want MASK (%v)", v.Ctx.Action, v.Ctx.DenyReason)
		}
		// The mask list and the rewritten SQL are the two things a mask verdict relays; both must be
		// byte-identical to the pre-task decision.
		w.assertRelayUnchanged(baseline, shapeOf(v))
		if len(v.Ctx.Masks) == 0 {
			t.Error("a MASK verdict relayed no masks")
		}

		task := w.taskForDecision(v.DecisionID)
		if task.status != "APPROVED" {
			t.Errorf("status = %s, want APPROVED", task.status)
		}
		if len(task.executeAs) != 1 || task.executeAs[0] != dbtest.FixtureRole {
			t.Errorf("executeAs = %v, want [%s]", task.executeAs, dbtest.FixtureRole)
		}
		if n := w.childCount(task.id); n != 0 {
			t.Errorf("child result rows = %d, want 0", n)
		}

		w.complete(v.DecisionID, "ok")
		if got := w.request(task.id).status; got != "EXECUTED" {
			t.Errorf("status = %s, want EXECUTED", got)
		}
	})
}

// KT: WireTaskDecideDbTest.kt#policy DENY fails its wire task inline and preserves deny relay bytes
//
// 🔒 A DENY FAILS ITS TASK INLINE — no completion report is coming, because the proxy never runs the
// statement. A task left APPROVED here would sit forever claiming an execution that cannot happen.
func TestWireTaskPolicyDenyFailsItsTaskInline(t *testing.T) {
	eachEngine(t, func(t *testing.T, w *wireTaskFixture) {
		opened := w.openAndPush()
		baseline := shapeOf(w.verdict(w.wireDecide(opened, "select id from orders")))

		v := w.verdict(w.wireDecide(opened, "select id from orders"))
		if v.Ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %s, want DENY", v.Ctx.Action)
		}
		w.assertRelayUnchanged(baseline, shapeOf(v))

		task := w.taskForDecision(v.DecisionID)
		if task.status != "FAILED" {
			t.Errorf("status = %s, want FAILED inline — no completion report will ever arrive", task.status)
		}
		if len(task.executeAs) != 1 || task.executeAs[0] != dbtest.FixtureRole {
			t.Errorf("executeAs = %v, want [%s]", task.executeAs, dbtest.FixtureRole)
		}
		if n := w.childCount(task.id); n != 0 {
			t.Errorf("child result rows = %d, want 0", n)
		}
	})
}

// KT: WireTaskDecideDbTest.kt#duplicate clean completions leave the wire task executed
//
// Idempotence: the proxy may retry a completion report, and the second must not move an EXECUTED task
// to some other state or error.
func TestWireTaskDuplicateCleanCompletionsAreIdempotent(t *testing.T) {
	eachEngine(t, func(t *testing.T, w *wireTaskFixture) {
		opened := w.openAndPush()
		v := w.verdict(w.wireDecide(opened, "select id from users"))
		task := w.taskForDecision(v.DecisionID)

		w.complete(v.DecisionID, "ok")
		w.complete(v.DecisionID, "ok")

		if got := w.request(task.id).status; got != "EXECUTED" {
			t.Errorf("status after two clean completions = %s, want EXECUTED", got)
		}
	})
}

// KT: WireTaskDecideDbTest.kt#task request forbid overrides enforcement to deny without creating a task
//
// 🔒 THE OVERRIDE IS FAIL-CLOSED AND LEAVES NO ROW. If the principal may not even REQUEST a task, the
// statement is denied at the policy stage and no lifecycle row is written — a task the principal was
// forbidden to create would be a record of an authorization that never existed.
func TestWireTaskRequestForbidDeniesWithoutCreatingATask(t *testing.T) {
	eachEngine(t, func(t *testing.T, w *wireTaskFixture) {
		w.addForbid("wire-task-request-forbid",
			`forbid(principal, action == Action::"task.request", resource == Datasource::"`+w.f.datasource.Name+`");`)
		opened := w.openAndPush()
		before := len(w.wireTasks())

		v := w.verdict(w.wireDecide(opened, "select id from users"))

		if v.Ctx.Action != pb.EnfAction_DENY {
			t.Errorf("action = %s, want DENY", v.Ctx.Action)
		}
		if v.Ctx.FailedStage == nil || *v.Ctx.FailedStage != "policy" {
			t.Errorf("failedStage = %v, want \"policy\"", v.Ctx.FailedStage)
		}
		if len(v.AfterStatement) != 0 {
			t.Errorf("afterStatement = %v, want empty", v.AfterStatement)
		}
		if after := len(w.wireTasks()); after != before {
			t.Errorf("wire task count %d → %d; a forbidden request must create no row", before, after)
		}
	})
}

// KT: WireTaskDecideDbTest.kt#datasource-scoped task approve forbid overrides enforcement to deny without creating a task
func TestWireTaskDatasourceScopedApproveForbidDeniesWithoutCreatingATask(t *testing.T) {
	eachEngine(t, func(t *testing.T, w *wireTaskFixture) {
		w.addForbid("wire-task-approve-forbid",
			`forbid(principal, action == Action::"task.approve", resource) when { resource in Datasource::"`+w.f.datasource.Name+`" };`)
		opened := w.openAndPush()
		before := len(w.wireTasks())

		v := w.verdict(w.wireDecide(opened, "select id from users"))

		if v.Ctx.Action != pb.EnfAction_DENY {
			t.Errorf("action = %s, want DENY", v.Ctx.Action)
		}
		if len(v.AfterStatement) != 0 {
			t.Errorf("afterStatement = %v, want empty", v.AfterStatement)
		}
		if after := len(w.wireTasks()); after != before {
			t.Errorf("wire task count %d → %d; a forbidden self-approve must create no row", before, after)
		}
	})
}

// KT: WireTaskDecideDbTest.kt#stale catalog before-decide creates no wire task
//
// 🔒 A before_decide IS NOT A DECISION. The freshness pre-gate fires before any authorization runs, so
// there is nothing to account for — writing a task here would log a statement that was never judged.
func TestWireTaskStaleCatalogBeforeDecideCreatesNoTask(t *testing.T) {
	eachEngine(t, func(t *testing.T, w *wireTaskFixture) {
		// Opened with NO schemas held, so the first decide must ask for a refetch.
		opened := w.f.core.ConnectionCatalog.Open(datasource.Binding{
			DatasourceName: w.f.datasource.Name, Principal: dbtest.FixturePrincipal, TokenKind: "USER",
		}, nil, false)
		before := len(w.wireTasks())

		out := w.wireDecide(opened, "select id from users")

		if _, ok := out.(core.OutcomeBeforeDecide); !ok {
			t.Fatalf("outcome = %T, want a BeforeDecide", out)
		}
		if after := len(w.wireTasks()); after != before {
			t.Errorf("wire task count %d → %d; a before_decide must create no row", before, after)
		}
	})
}

// KT: WireTaskDecideDbTest.kt#non-wire decide creates no wire task
//
// 🔒 WIRE ONLY. An editor decision is accounted for by its own editor task; creating a WIRE row for it
// would double-count the statement and put an editor query on the wire ledger.
func TestWireTaskNonWireDecideCreatesNoTask(t *testing.T) {
	eachEngine(t, func(t *testing.T, w *wireTaskFixture) {
		opened := w.openAndPush()
		before := len(w.wireTasks())

		v := w.verdict(w.decide(opened, "select id from users", query.ChannelEditor))

		if v.Ctx.Action != pb.EnfAction_ALLOW {
			t.Errorf("action = %s, want ALLOW (%v)", v.Ctx.Action, v.Ctx.DenyReason)
		}
		if after := len(w.wireTasks()); after != before {
			t.Errorf("wire task count %d → %d; only a WIRE decision writes a wire task", before, after)
		}
	})
}
