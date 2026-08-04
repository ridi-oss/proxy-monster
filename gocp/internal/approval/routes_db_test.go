package approval

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `/api/approvals/**` — Approvals.kt:302-887, 07-tasks-approvals-results.md §6.
//
// The Cedar layer is the REAL one: the shipped V8 seed policies over a real CedarEngine (see
// support_db_test.go). Every 🔒 assertion below is about which shipped policy answers and in what
// ORDER the handler asks.
// ---------------------------------------------------------------------------------------------

const (
	requester = dbtest.FixturePrincipal // holds `analyst`
	approver  = "approver@example.com"  // made `system:admin` below
	outsider  = "outsider@example.com"  // holds nothing
)

// withApprover makes `approver` a system:admin, which is what the shipped `workflow.pm-admin-approve`
// permit (V8 -3) keys `task.approve` off. Approver eligibility is a Cedar POLICY, never a datasource
// group (INV-A7-19), so this is the whole of "who may approve" in the fixture.
func (f *httpFixture) withApprover() {
	f.t.Helper()
	f.fx.Seed.AssignRole(approver, f.roleID("system:admin"))
}

// seedDenyDecision writes a real DENY audit row owned by principal — the from-denied branch's source.
func (f *httpFixture) seedDenyDecision(principal, sql string) int64 {
	f.t.Helper()
	ev := types.NewAuditEvent(principal, f.fx.DatasourceName, sql, types.DecisionDeny)
	ev.Detail = strptr("policy denies column users.rrn")
	id, err := f.Audit.Insert(context.Background(), ev)
	if err != nil {
		f.t.Fatalf("seed deny decision: %v", err)
	}
	return id
}

// ---------------------------------------------------------------------------------------------
// `ApprovalSurfaceCreatorKindDbTest` — 3 cases. All three pin 🔒 INV-A7-5.
// ---------------------------------------------------------------------------------------------

// Case 1 — the list surfaces only WORKFLOW tasks; WIRE and EDITOR never appear.
// KT: ApprovalSurfaceCreatorKindDbTest.kt#list surfaces only WORKFLOW tasks - WIRE and EDITOR never appear
func TestTheApprovalListSurfacesOnlyWorkflowTasks(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	ctx := context.Background()

	workflow := f.seedWorkflowTask(requester, "SELECT rrn FROM users", dbtest.FixtureRole)
	if _, err := f.Access.CreateEditorTask(ctx, requester, f.fx.DatasourceID, "SELECT 1", []string{dbtest.FixtureRole}, requester); err != nil {
		t.Fatalf("seed editor task: %v", err)
	}
	decisionID := f.seedDenyDecision(requester, "SELECT 2")
	if _, err := f.Access.CreateWireTask(ctx, f.fx.Store.Pool, requester, f.fx.DatasourceID, []string{dbtest.FixtureRole}, decisionID); err != nil {
		t.Fatalf("seed wire task: %v", err)
	}

	rec := f.get("/api/approvals", f.login(requester))
	assertStatus(t, rec, http.StatusOK, "list")

	var got []access.AccessRequest
	decodeJSON(t, rec, &got)
	if len(got) != 1 || got[0].ID != workflow.ID {
		ids := make([]int64, 0, len(got))
		for _, r := range got {
			ids = append(ids, r.ID)
		}
		t.Fatalf("INV-A7-5: the approval feed returned %v, want only the WORKFLOW task %d", ids, workflow.ID)
	}
	if got[0].CreatorKind == nil || *got[0].CreatorKind != "WORKFLOW" {
		t.Errorf("creatorKind: got %v", got[0].CreatorKind)
	}
}

// Cases 2 and 3 — a WIRE task and an EDITOR task are not fetchable, decidable, executable or
// viewable as approvals. Each sweeps FIVE surfaces, because a guard added to four of them is a guard
// that leaks through the fifth.
//
// KT: ApprovalSurfaceCreatorKindDbTest.kt#a WIRE task is not fetchable, decidable, executable, or viewable as an approval — the WIRE subtest
// KT: ApprovalSurfaceCreatorKindDbTest.kt#an EDITOR task is not fetchable, decidable, executable, or viewable as an approval — the EDITOR subtest
func TestNonWorkflowTasksAreInvisibleOnEveryIdAddressedApprovalSurface(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	ctx := context.Background()

	editor, err := f.Access.CreateEditorTask(ctx, requester, f.fx.DatasourceID, "SELECT 1", []string{dbtest.FixtureRole}, requester)
	if err != nil {
		t.Fatalf("seed editor task: %v", err)
	}
	decisionID := f.seedDenyDecision(requester, "SELECT 2")
	wireID, err := f.Access.CreateWireTask(ctx, f.fx.Store.Pool, requester, f.fx.DatasourceID, []string{dbtest.FixtureRole}, decisionID)
	if err != nil {
		t.Fatalf("seed wire task: %v", err)
	}

	// The approver is a system:admin, so Cedar would ALLOW every one of these actions on a genuine
	// WORKFLOW task. That is what makes the 404s attributable to the creator-kind guard rather than to
	// an authorization refusal.
	cookie := f.login(approver)
	for _, task := range []struct {
		kind string
		id   int64
	}{{"EDITOR", editor.ID}, {"WIRE", wireID}} {
		t.Run(task.kind, func(t *testing.T) {
			id := strconv.FormatInt(task.id, 10)
			surfaces := []struct {
				name   string
				method string
				path   string
				body   any
			}{
				{"detail", http.MethodGet, "/api/approvals/" + id, nil},
				{"approve", http.MethodPost, "/api/approvals/" + id + "/approve", nil},
				{"reject", http.MethodPost, "/api/approvals/" + id + "/reject", map[string]string{"reason": "no"}},
				{"cancel", http.MethodPost, "/api/approvals/" + id + "/cancel", nil},
				{"execute", http.MethodPost, "/api/approvals/" + id + "/execute", nil},
				{"result", http.MethodGet, "/api/approvals/" + id + "/result", nil},
			}
			for _, s := range surfaces {
				rec := f.do(s.method, s.path, s.body, cookie)
				assertStatus(t, rec, http.StatusNotFound, task.kind+" "+s.name)
				assertCode(t, rec, "common.not_found")
			}
			if n := f.RunExec.runCount(); n != 0 {
				t.Errorf("%s: %d runs were launched for a non-workflow task", task.kind, n)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// `ApprovalExecuteRouteDbTest` — the ordering and identity invariants.
// ---------------------------------------------------------------------------------------------

// 🔒 Case 8 / INV-A7-26 — EXECUTE BY AN APPROVER OTHER THAN THE APPROVER OF RECORD IS 403
// `not_the_approver` AND RUNS NOTHING.
//
// `other-approver` is ALSO a system:admin, so Cedar's `task.approve` permits them: the refusal can
// only come from the `decidedBy != executor` identity guard. Asserting the run count is the second
// half — a port that answered 403 after launching the goroutine would pass a status-only assertion
// while the query had already left.
// KT: ApprovalExecuteRouteDbTest.kt#execute by an approver other than the approver of record is 403 not_the_approver and runs nothing
func TestExecuteByAnApproverOtherThanTheApproverOfRecordIs403AndRunsNothing(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	const otherApprover = "other-approver@example.com"
	f.fx.Seed.AssignRole(otherApprover, f.roleID("system:admin"))

	task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
	f.approveTask(task.ID, approver)

	rec := f.post(idPath("/api/approvals/", task.ID, "/execute"), nil, f.login(otherApprover))

	assertStatus(t, rec, http.StatusForbidden, "execute by a non-approver-of-record")
	assertCode(t, rec, "approval.not_the_approver")
	if n := f.RunExec.runCount(); n != 0 {
		t.Errorf("INV-A7-26: the run was launched anyway (%d runs)", n)
	}
	if f.pendingCount() != 0 {
		t.Error("INV-A7-26: an async body was queued for a refused execute")
	}
	if got := f.getRequest(task.ID).Status; got != "APPROVED" {
		t.Errorf("status: got %q, want APPROVED — a refused execute must not claim the task", got)
	}
	// The Kotlin's own last assertion, read where the CONSOLE reads it: the pre-created statement
	// child is still NOT STARTED. Asserting only that no run was launched would miss a port that
	// flipped the child to RUNNING before the gate and then bailed out.
	meta, err := f.Results.Meta(context.Background(), task.ID)
	if err != nil || meta == nil {
		t.Fatalf("child meta: %#v err=%v", meta, err)
	}
	if meta.Status != nil {
		t.Errorf("child status: got %q, want null — no child was ever run", *meta.Status)
	}
}

// 🔒 THE 403 IS NOT A STATE ORACLE. A caller who cannot approve gets the SAME 403
// `approval.not_approver` whatever the task's status, so the 409 already_executed / not_approved
// distinctions never leak state to them.
//
// Driving it across three statuses is what makes the claim: a port that checked status first would
// answer three DIFFERENT bodies here.
func TestExecuteAuthorizesBeforeDisclosingStatusSoTheRefusalIsUniform(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	cookie := f.login(outsider)

	pending := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)

	approved := f.seedWorkflowTask(requester, "SELECT id FROM users WHERE id = 1", dbtest.FixtureRole)
	f.approveTask(approved.ID, approver)

	executed := f.seedWorkflowTask(requester, "SELECT id FROM users WHERE id = 2", dbtest.FixtureRole)
	f.approveTask(executed.ID, approver)
	f.storeResult(executed.ID, approver, []string{"id"}, [][]*string{{strptr("2")}})

	bodies := map[string]string{}
	for name, id := range map[string]int64{"PENDING": pending.ID, "APPROVED": approved.ID, "EXECUTED": executed.ID} {
		rec := f.post(idPath("/api/approvals/", id, "/execute"), nil, cookie)
		assertStatus(t, rec, http.StatusForbidden, "execute as an outsider on a "+name+" task")
		assertCode(t, rec, "approval.not_approver")
		bodies[name] = rec.Body.String()
	}
	if bodies["PENDING"] != bodies["APPROVED"] || bodies["APPROVED"] != bodies["EXECUTED"] {
		t.Errorf("the refusal must be byte-identical across statuses, got %#v", bodies)
	}
}

// Case 3 — execute returns 202 EXECUTING while the run is in flight, then completes to EXECUTED with
// a DONE child.
func TestExecuteReturns202AndThenCompletesToExecutedAndDone(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
	f.approveTask(task.ID, approver)
	f.RunExec.response.Columns = []string{"id"}
	f.RunExec.response.Rows = [][]*string{{strptr("1")}, {strptr("2")}}

	rec := f.post(idPath("/api/approvals/", task.ID, "/execute"), nil, f.login(approver))
	assertStatus(t, rec, http.StatusAccepted, "execute")
	var ack ExecuteApprovalResponse
	decodeJSON(t, rec, &ack)
	if ack.Decision != "EXECUTING" {
		t.Errorf("ack: got %q, want EXECUTING", ack.Decision)
	}
	// Before the async body runs, the parent is already EXECUTING with a RUNNING child (INV-A7-7).
	if got := f.getRequest(task.ID).Status; got != "EXECUTING" {
		t.Errorf("status after the claim: got %q, want EXECUTING", got)
	}

	if n := f.runAsync(); n != 1 {
		t.Fatalf("%d async bodies were queued, want 1", n)
	}

	if got := f.getRequest(task.ID).Status; got != "EXECUTED" {
		t.Errorf("status after the run: got %q, want EXECUTED", got)
	}
	meta, err := f.Results.Meta(context.Background(), task.ID)
	if err != nil || meta == nil || meta.Status == nil || *meta.Status != "DONE" {
		t.Fatalf("child meta: %#v err=%v", meta, err)
	}
	if meta.RowCount == nil || *meta.RowCount != 2 {
		t.Errorf("rowCount: got %v, want 2", meta.RowCount)
	}
	// 🔒 INV-A7-1 — the run carried R ALONE, never a union with the executor's own roles.
	if got := f.RunExec.runs[0].AssumeRoles; len(got) != 1 || got[0] != dbtest.FixtureRole {
		t.Errorf("INV-A7-1: assumeRoles = %v, want exactly [%s]", got, dbtest.FixtureRole)
	}
	if !f.RunExec.runs[0].ApproverExec {
		t.Error("the run must be minted as an APPROVER_EXEC token")
	}
	if f.RunExec.runs[0].MaxRows != ExecuteMaxRows {
		t.Errorf("maxRows: got %d, want the hardcoded %d", f.RunExec.runs[0].MaxRows, ExecuteMaxRows)
	}
	// 🔒 INV-A7-20 — the lifecycle row exists and carries no result-derived data.
	rows := f.auditRows(task.ID)
	if len(rows) != 1 || !strings.HasSuffix(rows[0], "result-executed") {
		t.Errorf("lifecycle audit rows: got %v, want one …result-executed", rows)
	}
}

// Case 2 — a SECOND execute after a successful first is 409 `already_executed`, and exactly ONE
// result is stored.
func TestASecondExecuteIs409AndStoresExactlyOneResult(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
	f.approveTask(task.ID, approver)
	cookie := f.login(approver)

	assertStatus(t, f.post(idPath("/api/approvals/", task.ID, "/execute"), nil, cookie), http.StatusAccepted, "first execute")
	f.runAsync()

	second := f.post(idPath("/api/approvals/", task.ID, "/execute"), nil, cookie)
	assertStatus(t, second, http.StatusConflict, "second execute")
	assertCode(t, second, "approval.already_executed")

	if n := f.RunExec.runCount(); n != 1 {
		t.Errorf("%d runs were launched, want exactly 1", n)
	}
	var children int
	if err := f.fx.Store.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM query_result WHERE task_id = $1 AND status = 'DONE'`, task.ID).Scan(&children); err != nil {
		t.Fatalf("count children: %v", err)
	}
	if children != 1 {
		t.Errorf("%d DONE children, want exactly 1", children)
	}
}

// 🔒 Case 1 — A DENY UNDER R AT EXECUTE LEAKS NO RESULT AND STORES NOTHING. The fail-closed floor:
// the child goes FAILED with a stable code, holds no ciphertext, and the result route answers 409
// rather than any bytes.
func TestADenyUnderRAtExecuteLeaksNoResultAndStoresNothing(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	task := f.seedWorkflowTask(requester, "SELECT rrn FROM users", dbtest.FixtureRole)
	f.approveTask(task.ID, approver)
	f.RunExec.response.Decision = denyWire()
	f.RunExec.response.Rows = [][]*string{{strptr("900101-1234567")}} // the proxy would send nothing; belt and braces
	cookie := f.login(approver)

	assertStatus(t, f.post(idPath("/api/approvals/", task.ID, "/execute"), nil, cookie), http.StatusAccepted, "execute")
	f.runAsync()

	if got := f.getRequest(task.ID).Status; got != "FAILED" {
		t.Errorf("status: got %q, want FAILED", got)
	}
	meta, err := f.Results.Meta(context.Background(), task.ID)
	if err != nil || meta == nil {
		t.Fatalf("child meta: %#v err=%v", meta, err)
	}
	if meta.Status == nil || *meta.Status != "FAILED" {
		t.Errorf("child status: got %v, want FAILED", meta.Status)
	}
	if meta.ErrorCode == nil || *meta.ErrorCode != "approval.execute_denied" {
		t.Errorf("errorCode: got %v, want approval.execute_denied", meta.ErrorCode)
	}
	var ciphertext []byte
	if err := f.fx.Store.Pool.QueryRow(context.Background(),
		`SELECT ciphertext FROM query_result WHERE task_id = $1`, task.ID).Scan(&ciphertext); err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if ciphertext != nil {
		t.Errorf("a DENY stored %d ciphertext bytes; it must store none", len(ciphertext))
	}
	rec := f.get(idPath("/api/approvals/", task.ID, "/result"), cookie)
	assertStatus(t, rec, http.StatusConflict, "result after a denied execute")
	assertCode(t, rec, "approval.result_not_ready")
}

// ---------------------------------------------------------------------------------------------
// GET /api/approvals/{id} — 🔒 INV-A7-23.
// ---------------------------------------------------------------------------------------------

// 🔒 INV-A7-23 — RESULT METADATA IS REDACTED WHEN THE CALLER CANNOT ASSUME R.
//
// `rowCount` and `columns` are cardinality/existence oracles. The requester CAN assume (V8 -21) and
// sees them; a system:admin who is neither party CANNOT (the admin permit covers task.approve /
// task.read / cancel / delete, NOT task.assume) and must see the same row with both cleared.
//
// The pair is the test: asserting only the redacted half would pass for a port that never populated
// the metadata at all.
//
// KT: ApprovalResultViewContextDbTest.kt#approver and auditor assume R while admin sees metadata only — the admin half: rowCount/columns cleared, status still visible
func TestDetailRedactsResultShapeFromACallerWhoCannotAssumeR(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	const admin = "admin@example.com"
	f.fx.Seed.AssignRole(admin, f.roleID("system:admin"))

	task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
	f.approveTask(task.ID, approver)
	f.storeResult(task.ID, approver, []string{"id"}, [][]*string{{strptr("1")}, {strptr("2")}})

	t.Run("the requester assumes R and sees the shape", func(t *testing.T) {
		rec := f.get(idPath("/api/approvals/", task.ID, ""), f.login(requester))
		assertStatus(t, rec, http.StatusOK, "detail as requester")
		var got ApprovalDetail
		decodeJSON(t, rec, &got)
		if got.Result == nil {
			t.Fatal("the requester must see the result metadata")
		}
		if got.Result.RowCount == nil || *got.Result.RowCount != 2 {
			t.Errorf("rowCount: got %v, want 2", got.Result.RowCount)
		}
		if len(got.Result.Columns) != 1 {
			t.Errorf("columns: got %v, want [id]", got.Result.Columns)
		}
	})

	t.Run("an admin who cannot assume R sees status but not shape", func(t *testing.T) {
		rec := f.get(idPath("/api/approvals/", task.ID, ""), f.login(admin))
		assertStatus(t, rec, http.StatusOK, "detail as admin")
		var got ApprovalDetail
		decodeJSON(t, rec, &got)
		if got.Result == nil {
			t.Fatal("task.read must still surface the execution STATUS")
		}
		if got.Result.RowCount != nil {
			t.Errorf("INV-A7-23: rowCount leaked (%d) to a caller who cannot assume R", *got.Result.RowCount)
		}
		if len(got.Result.Columns) != 0 {
			t.Errorf("INV-A7-23: columns leaked %v to a caller who cannot assume R", got.Result.Columns)
		}
		if got.Result.Status == nil || *got.Result.Status != "DONE" {
			t.Errorf("status must still be visible; got %v", got.Result.Status)
		}
	})
}

// ---------------------------------------------------------------------------------------------
// GET /{id}/result — 🔒 INV-A7-28 and INV-A7-29, and the deactivation gate.
// ---------------------------------------------------------------------------------------------

// 🔒 INV-A7-28 — THE VIEW IS AUDITED BEFORE THE ROWS ARE RETURNED, and a failed audit insert
// PROPAGATES as a 500 so PII is never returned without a durable record.
//
// The only way to observe the ordering is to make the audit fail: a port that responded first and
// audited after answers 200 WITH THE ROWS here, which is exactly the leak. The cleartext assertion is
// on the body bytes, not on a decoded field, so a partial write would also fail it.
func TestTheViewIsAuditedBeforeRowsAreReturnedAndAFailedInsertPropagates(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
	f.approveTask(task.ID, approver)
	const secret = "900101-1234567"
	f.storeResult(task.ID, approver, []string{"id"}, [][]*string{{strptr(secret)}})

	f.auditFail = errors.New("audit chain is unavailable")
	rec := f.get(idPath("/api/approvals/", task.ID, "/result"), f.login(requester))

	assertStatus(t, rec, http.StatusInternalServerError, "result view with a failing audit")
	assertCode(t, rec, "common.fallback")
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("INV-A7-28: rows were returned without a durable audit record; body = %s", rec.Body.String())
	}
}

// 🔒 INV-A7-29 — the view event is classified by the viewer's RELATIONSHIP, not requester-vs-everyone.
//
// A `system:auditor` is neither party (V8 -22 grants it task.assume) and must be recorded as an
// ASSUMER, never miscredited to the approver. Three viewers, three distinct event names.
//
// KT: ApprovalResultViewContextDbTest.kt#approver and auditor assume R while admin sees metadata only — the approver+auditor half: both reach 200 and are credited by-approver / by-assumer
func TestTheViewEventIsClassifiedByTheViewersRelationshipToTheTask(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	const auditor = "auditor@example.com"
	f.fx.Seed.AssignRole(auditor, f.roleID("system:auditor"))

	task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
	f.approveTask(task.ID, approver)
	const stored = "42"
	f.storeResult(task.ID, approver, []string{"id"}, [][]*string{{strptr(stored)}})

	for _, viewer := range []struct {
		principal string
		want      string
	}{
		{requester, "result-viewed-by-requester"},
		{approver, "result-viewed-by-approver"},
		{auditor, "result-viewed-by-assumer"},
	} {
		rec := f.get(idPath("/api/approvals/", task.ID, "/result"), f.login(viewer.principal))
		assertStatus(t, rec, http.StatusOK, "result view as "+viewer.principal)
		// Each of the three ASSUMES R and gets the rows — the Kotlin asserts the cell value, not just
		// the status, because a 200 carrying an empty result set would prove nothing about assuming R.
		var view QueryResultView
		decodeJSON(t, rec, &view)
		if len(view.Rows) != 1 || len(view.Rows[0]) != 1 || view.Rows[0][0] == nil || *view.Rows[0][0] != stored {
			t.Errorf("%s: rows = %#v, want the stored [[%s]]", viewer.principal, view.Rows, stored)
		}
	}

	rows := f.auditRows(task.ID)
	var events []string
	for _, r := range rows {
		if i := strings.LastIndex(r, " "); i >= 0 {
			events = append(events, r[i+1:])
		}
	}
	for _, want := range []string{"result-viewed-by-requester", "result-viewed-by-approver", "result-viewed-by-assumer"} {
		found := false
		for _, got := range events {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("INV-A7-29: no %q row; audit statements were %v", want, rows)
		}
	}
}

// 🔒 An OUTSIDER cannot assume the task role, and the refusal is a 404 — not a 403 — so the result's
// existence is never confirmed. mayReadResult has NO authDebug bypass (INV-A7-18), which the second
// sub-test pins by running the same request on a debug fixture.
// KT: ApprovalResultViewContextDbTest.kt#an outsider cannot assume the task role — the non-debug subtest; 404 and no stored PII in the body
func TestAnOutsiderCannotReadTheResultAndTheAssumeGateHasNoAuthDebugBypass(t *testing.T) {
	t.Run("non-debug", func(t *testing.T) {
		f := newHTTPFixture(t, fixtureOptions{})
		f.withApprover()
		task := f.seedWorkflowTask(requester, "SELECT rrn FROM users", dbtest.FixtureRole)
		f.approveTask(task.ID, approver)
		// A distinctive sentinel, so the "no stored PII in the body" half is a real assertion on the
		// bytes rather than a claim about a value that could appear by coincidence.
		const storedPII = "900101-1234567"
		f.storeResult(task.ID, approver, []string{"rrn"}, [][]*string{{strptr(storedPII)}})

		rec := f.get(idPath("/api/approvals/", task.ID, "/result"), f.login(outsider))
		assertStatus(t, rec, http.StatusNotFound, "result view as an outsider")
		assertCode(t, rec, "common.not_found")
		// The Kotlin's second assertion: the assume gate returns NO stored PII. assertCode only reads
		// the `code` field, so the raw body is checked too.
		notInBody(t, rec.Body.String(), storedPII, "result view as an outsider")
	})

	// 🔒 INV-A7-18 — under authDebug there is no session at all, so the caller is "debug-user": a
	// principal who is neither party. requireApi waves them through and mayReadResult must still
	// refuse, because result rows are data confidentiality enforced in development too.
	t.Run("authDebug", func(t *testing.T) {
		f := newHTTPFixture(t, fixtureOptions{AuthDebug: true})
		f.withApprover()
		task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
		f.approveTask(task.ID, approver)
		f.storeResult(task.ID, approver, []string{"id"}, [][]*string{{strptr("1")}})

		rec := f.get(idPath("/api/approvals/", task.ID, "/result"))
		assertStatus(t, rec, http.StatusNotFound, "result view under authDebug")
		if strings.Contains(rec.Body.String(), `"rows"`) {
			t.Fatalf("INV-A7-18: authDebug bypassed the assume gate; body = %s", rec.Body.String())
		}
	})
}

// `ApprovalResultDeactivationDbTest` — 2 cases, and the PAIR is the point: case 1 exists so case 2
// cannot pass vacuously.
//
// The Kotlin isolates the gate on a NO-R task, so its positive control lands on the empty-{R}
// fail-closed 403 and the discriminant is 403-vs-404. Here the task carries a real R, so the positive
// control lands on 200-with-rows: the same claim ("an active viewer passes the gate and reaches the
// live re-decision") asserted one step further along. Gate 2's empty-{R} deny is
// TestViewGate2DeniesAnEmptyExecuteAsRatherThanReleasingTheStoredBytes.
//
// KT: ApprovalResultDeactivationDbTest.kt#an active viewer passes the deactivation gate and reaches the live re-decision — positive control
// KT: ApprovalResultDeactivationDbTest.kt#a deactivated viewer is gated out before any result decision — NotFound, no existence oracle
// KT: ApprovalResultViewContextDbTest.kt#a requester assumes R and reads their own result — the case-1 half: the requester clears task.assume and the live exactly-R view returns their rows
func TestTheDeactivationGateHidesTheResultAndTheActiveControlStillReachesIt(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
	f.approveTask(task.ID, approver)
	f.storeResult(task.ID, approver, []string{"id"}, [][]*string{{strptr("1")}})
	cookie := f.login(requester)

	// Case 1 — POSITIVE CONTROL: an active viewer passes the gate and reaches the live re-decision.
	rec := f.get(idPath("/api/approvals/", task.ID, "/result"), cookie)
	assertStatus(t, rec, http.StatusOK, "active viewer")
	var view QueryResultView
	decodeJSON(t, rec, &view)
	if len(view.Rows) != 1 {
		t.Fatalf("the active control must reach the rows; got %#v", view)
	}

	// Case 2 — 🔒 a deactivated viewer is gated out BEFORE any result decision: 404, no existence
	// oracle.
	f.fx.Seed.User(requester)
	f.fx.Seed.SetUserActive(requester, false)

	rec = f.get(idPath("/api/approvals/", task.ID, "/result"), cookie)
	assertStatus(t, rec, http.StatusNotFound, "deactivated viewer")
	assertCode(t, rec, "common.not_found")
}

// ---------------------------------------------------------------------------------------------
// POST /api/approvals — the two branches.
// ---------------------------------------------------------------------------------------------

// 🔒 EXACTLY ONE SOURCE. Both-set and neither-set answer the SAME 400, so the branches can never be
// entered together and a caller cannot smuggle a chosen datasource onto a decision-derived request.
func TestCreateRequiresExactlyOneSource(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	cookie := f.login(requester)
	decisionID := f.seedDenyDecision(requester, "SELECT rrn FROM users")
	roleID := f.roleID(dbtest.FixtureRole)

	t.Run("neither", func(t *testing.T) {
		rec := f.post("/api/approvals", map[string]any{"reason": "r", "roleId": roleID}, cookie)
		assertStatus(t, rec, http.StatusBadRequest, "neither source")
		assertCode(t, rec, "approval.exactly_one_source_required")
	})
	t.Run("both", func(t *testing.T) {
		rec := f.post("/api/approvals", map[string]any{
			"reason": "r", "roleId": roleID, "sourceDecisionId": decisionID, "datasourceId": f.fx.DatasourceID,
		}, cookie)
		assertStatus(t, rec, http.StatusBadRequest, "both sources")
		assertCode(t, rec, "approval.exactly_one_source_required")
	})
	t.Run("a blank reason is rejected before either branch", func(t *testing.T) {
		rec := f.post("/api/approvals", map[string]any{"reason": "  ", "sourceDecisionId": decisionID}, cookie)
		assertStatus(t, rec, http.StatusBadRequest, "blank reason")
		assertCode(t, rec, "common.field_required")
	})
}

// The from-denied branch end to end, plus 🔒 the pending-per-decision conflict, which is enforced by
// the partial-index upsert and not only by the pre-check (INV-A6-21).
func TestCreateFromADeniedDecisionAndThenRefusesASecondPendingRequest(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	cookie := f.login(requester)
	decisionID := f.seedDenyDecision(requester, "SELECT rrn FROM users")
	roleID := f.roleID(dbtest.FixtureRole)
	body := map[string]any{"reason": " needed ", "roleId": roleID, "sourceDecisionId": decisionID}

	rec := f.post("/api/approvals", body, cookie)
	assertStatus(t, rec, http.StatusCreated, "create from a denied decision")
	var created CreateApprovalResponse
	decodeJSON(t, rec, &created)
	if created.WouldAllow {
		t.Error("the from-denied branch always reports wouldAllow = false")
	}
	if created.Request.SQL == nil || *created.Request.SQL != "SELECT rrn FROM users" {
		t.Errorf("sql: got %v, want the source decision's statement", created.Request.SQL)
	}
	if created.Request.Reason == nil || *created.Request.Reason != "needed" {
		t.Errorf("reason: got %v, want the TRIMMED %q", created.Request.Reason, "needed")
	}
	if len(created.Request.ExecuteAs) != 1 || created.Request.ExecuteAs[0] != dbtest.FixtureRole {
		t.Errorf("executeAs: got %v, want [%s]", created.Request.ExecuteAs, dbtest.FixtureRole)
	}

	second := f.post("/api/approvals", body, cookie)
	assertStatus(t, second, http.StatusConflict, "second pending request for the same decision")
	assertCode(t, second, "approval.pending_request_exists")
}

// 🔒 A NOT-OWNED DECISION IS A 404, NOT A 403 — the discriminant is what stops a caller enumerating
// other principals' decision ids. The 404 must also be the SAME body an absent id answers.
func TestCreateFromAnotherPrincipalsDecisionIs404AndIndistinguishableFromAbsent(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	notMine := f.seedDenyDecision("someone-else@example.com", "SELECT rrn FROM users")
	roleID := f.roleID(dbtest.FixtureRole)
	cookie := f.login(requester)

	owned := f.post("/api/approvals", map[string]any{"reason": "r", "roleId": roleID, "sourceDecisionId": notMine}, cookie)
	absent := f.post("/api/approvals", map[string]any{"reason": "r", "roleId": roleID, "sourceDecisionId": 999999}, cookie)

	assertStatus(t, owned, http.StatusNotFound, "another principal's decision")
	assertCode(t, owned, "common.not_found")
	if owned.Body.String() != absent.Body.String() {
		t.Errorf("a not-owned decision must be indistinguishable from an absent one:\n got %s\nwant %s",
			owned.Body.String(), absent.Body.String())
	}
}

// 🔒 INV-A7-21 — `roleId == null` is checked AFTER each branch's field validation, so an incomplete
// form names its missing field FIRST. Both branches.
//
// KT: ApprovalDiscoverPickSubmitRouteDbTest.kt#a compose with all fields but no elevation role is rejected role_required (single execute-under-R path) — the "proactive: a complete form with no role" subtest
func TestTheRoleRequiredGuardRunsAfterFieldValidationInBothBranches(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	cookie := f.login(requester)

	t.Run("proactive: a missing title names the field, not the role", func(t *testing.T) {
		rec := f.post("/api/approvals", map[string]any{
			"reason": "r", "datasourceId": f.fx.DatasourceID, "sql": "SELECT 1",
		}, cookie)
		assertStatus(t, rec, http.StatusBadRequest, "missing title")
		assertCode(t, rec, "common.field_required")
		var body types.ApiError
		decodeJSON(t, rec, &body)
		if body.Params["fields"] != "title" {
			t.Errorf("fields: got %q, want \"title\"", body.Params["fields"])
		}
	})

	t.Run("proactive: a complete form with no role is role_required", func(t *testing.T) {
		rec := f.post("/api/approvals", map[string]any{
			"reason": "r", "datasourceId": f.fx.DatasourceID, "sql": "SELECT id FROM users", "title": "t",
		}, cookie)
		assertStatus(t, rec, http.StatusBadRequest, "no role")
		assertCode(t, rec, "approval.role_required")
	})

	t.Run("from-denied: no role is role_required", func(t *testing.T) {
		decisionID := f.seedDenyDecision(requester, "SELECT rrn FROM users")
		rec := f.post("/api/approvals", map[string]any{"reason": "r", "sourceDecisionId": decisionID}, cookie)
		assertStatus(t, rec, http.StatusBadRequest, "no role")
		assertCode(t, rec, "approval.role_required")
	})
}

// The proactive branch runs the REAL pipeline on the EDITOR channel and reports its verdict as
// `wouldAllow`, storing the evaluated decision on the row. Nothing executes and no decision audit row
// is written at compose time — the second assertion, which a port that reused the wire path would
// fail.
func TestAProactiveComposeRunsTheRealPipelineAndWritesNoAuditRow(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	cookie := f.login(requester)
	roleID := f.roleID(dbtest.FixtureRole)
	before := f.auditCount()

	rec := f.post("/api/approvals", map[string]any{
		"reason": "r", "datasourceId": f.fx.DatasourceID, "sql": "SELECT id FROM users",
		"title": " weekly report ", "roleId": roleID,
	}, cookie)

	assertStatus(t, rec, http.StatusCreated, "proactive compose")
	var created CreateApprovalResponse
	decodeJSON(t, rec, &created)
	if !created.WouldAllow {
		t.Errorf("`SELECT id FROM users` is granted to %s, so the preview must be ALLOW; got %#v",
			dbtest.FixtureRole, created.Request.EvaluatedDecision)
	}
	if created.Request.EvaluatedDecision == nil || *created.Request.EvaluatedDecision != "ALLOW" {
		t.Errorf("evaluatedDecision: got %v, want ALLOW", created.Request.EvaluatedDecision)
	}
	if created.Request.Title == nil || *created.Request.Title != "weekly report" {
		t.Errorf("title: got %v, want the TRIMMED %q", created.Request.Title, "weekly report")
	}
	if after := f.auditCount(); after != before {
		t.Errorf("the compose preview wrote %d audit rows; it must write none", after-before)
	}
}

func (f *httpFixture) auditCount() int64 {
	f.t.Helper()
	var n int64
	if err := f.fx.Store.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_event`).Scan(&n); err != nil {
		f.t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------------------------
// approve / reject / cancel / inbox
// ---------------------------------------------------------------------------------------------

// 🔒 INV-A7-24 — REJECT ASKS THE SAME `task.approve` QUESTION AS APPROVE. The outsider is refused by
// the same code on both, and the admin approver succeeds on both.
func TestRejectAsksTheSameTaskApproveQuestionAsApprove(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	outsiderCookie, approverCookie := f.login(outsider), f.login(approver)

	for _, action := range []struct {
		name string
		body any
	}{{"approve", nil}, {"reject", map[string]string{"reason": "no"}}} {
		t.Run(action.name, func(t *testing.T) {
			task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
			path := idPath("/api/approvals/", task.ID, "/"+action.name)

			refused := f.post(path, action.body, outsiderCookie)
			assertStatus(t, refused, http.StatusForbidden, action.name+" as an outsider")
			assertCode(t, refused, "approval.not_approver")

			allowed := f.post(path, action.body, approverCookie)
			assertStatus(t, allowed, http.StatusOK, action.name+" as the admin approver")
		})
	}
}

// 🔒 The shipped `no-self-approval` FORBID, not app code, is what stops a requester approving their
// own request (INV-A7-19). The requester holds `analyst` and would otherwise be refused for lack of
// a permit, so the assertion is made against a requester who IS a system:admin: the admin permit
// applies and only the forbid can refuse.
func TestARequesterCannotApproveTheirOwnRequestEvenAsAnAdmin(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	const adminRequester = "admin-requester@example.com"
	f.fx.Seed.AssignRole(adminRequester, f.roleID("system:admin"))
	task := f.seedWorkflowTask(adminRequester, "SELECT id FROM users", dbtest.FixtureRole)

	rec := f.post(idPath("/api/approvals/", task.ID, "/approve"), nil, f.login(adminRequester))

	assertStatus(t, rec, http.StatusForbidden, "self-approval")
	assertCode(t, rec, "approval.not_approver")
}

// ⚠️ The blank-reason 400 answers BEFORE the request lookup, so a reject with no reason on a
// NON-EXISTENT id is a 400, not a 404. Asymmetric with approve, and reproduced.
func TestRejectValidatesItsReasonBeforeLookingTheRequestUp(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	rec := f.post("/api/approvals/999999/reject", map[string]string{"reason": "  "}, f.login(requester))
	assertStatus(t, rec, http.StatusBadRequest, "blank reason on an absent id")
	assertCode(t, rec, "common.field_required")
}

// The inbox is a FORWARD FILTER by Cedar, not a group join: the admin approver sees the pending
// request and an outsider sees none of it.
func TestTheInboxForwardFiltersByTaskApprove(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)

	var forApprover, forOutsider []access.AccessRequest
	decodeJSON(t, f.get("/api/approvals/inbox", f.login(approver)), &forApprover)
	decodeJSON(t, f.get("/api/approvals/inbox", f.login(outsider)), &forOutsider)

	if len(forApprover) != 1 || forApprover[0].ID != task.ID {
		t.Errorf("the approver's inbox: got %d rows, want the pending task %d", len(forApprover), task.ID)
	}
	if len(forOutsider) != 0 {
		t.Errorf("an outsider's inbox leaked %d rows", len(forOutsider))
	}
}

// ⚠️ `GET /api/approvals/inbox` and `GET /api/approvals/{id}` are both three segments; ServeMux
// resolves it by specificity. This pins that `inbox` is not swallowed by `{id}` (which would answer
// 400 common.bad_id, since "inbox" is not a Long).
func TestInboxIsNotSwallowedByTheIdPattern(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	rec := f.get("/api/approvals/inbox", f.login(requester))
	assertStatus(t, rec, http.StatusOK, "inbox")
	if strings.Contains(rec.Body.String(), "common.bad_id") {
		t.Fatal("the {id} pattern swallowed /api/approvals/inbox")
	}
}

// cancel: idempotent 200 on a terminal task, 409 on a pre-execution one, and a real cancel on an
// EXECUTING one — which also terminalizes BOTH rows and pushes CANCELLED immediately (INV-A7-25).
//
// KT: ApprovalExecuteRouteDbTest.kt#canceling an in-flight approval terminalizes both rows and emits RunCancel — the EXECUTING subtest
// KT: ApprovalExecuteRouteDbTest.kt#cancel is idempotent after execution and rejects pending tasks — the PENDING 409 half, and the terminal-idempotent 200 half; TestCancelOnAnExecutedTaskIs200WithTheTaskUnchanged pins the EXECUTED shape the Kotlin uses
func TestCancelIsIdempotentTerminalRefusesPreExecutionAndTerminalizesAnExecutingRun(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	cookie := f.login(requester) // the requester may cancel — V8 -25, task.cancel-parties

	t.Run("PENDING is not cancelable", func(t *testing.T) {
		task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
		rec := f.post(idPath("/api/approvals/", task.ID, "/cancel"), nil, cookie)
		assertStatus(t, rec, http.StatusConflict, "cancel a PENDING task")
		assertCode(t, rec, "approval.not_cancelable")
	})

	t.Run("EXECUTING cancels both rows and emits the control message", func(t *testing.T) {
		task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
		f.approveTask(task.ID, approver)
		// Claim it EXECUTING with a RUNNING child, exactly as /execute's atomic claim does.
		if _, err := f.Results.ClaimAndStartRun(context.Background(), task.ID, approver, claimVia(f, task.ID)); err != nil {
			t.Fatalf("claim: %v", err)
		}
		events := f.Hub.Subscribe(requester)
		defer f.Hub.Unsubscribe(requester, events)

		// 🔒 The detail advertises the run as cancelable WHILE it is in flight. The console renders its
		// cancel button off this flag, so a port that never populated it would leave an unstoppable run
		// with no way to stop it — and nothing else in the suite reads CanCancel.
		var detail ApprovalDetail
		decodeJSON(t, f.get(idPath("/api/approvals/", task.ID, ""), cookie), &detail)
		if !detail.CanCancel {
			t.Error("canCancel: got false on an EXECUTING run, want true")
		}

		rec := f.post(idPath("/api/approvals/", task.ID, "/cancel"), nil, cookie)
		assertStatus(t, rec, http.StatusOK, "cancel an EXECUTING task")
		// The 200 carries the updated request, not an empty ack: the console re-renders straight off it.
		var cancelled access.AccessRequest
		decodeJSON(t, rec, &cancelled)
		if cancelled.Status != "CANCELLED" {
			t.Errorf("the cancel response body's status: got %q, want CANCELLED", cancelled.Status)
		}

		if got := f.getRequest(task.ID).Status; got != "CANCELLED" {
			t.Errorf("parent status: got %q, want CANCELLED", got)
		}
		meta, _ := f.Results.Meta(context.Background(), task.ID)
		if meta == nil || meta.Status == nil || *meta.Status != "CANCELLED" {
			t.Errorf("child status: got %#v, want CANCELLED", meta)
		}
		// The stable code the console looks up as an i18n key — "cancelled" with no reason would be
		// indistinguishable from a failure.
		if meta == nil || meta.ErrorCode == nil || *meta.ErrorCode != "approval.canceled" {
			t.Errorf("child errorCode: got %#v, want approval.canceled", meta)
		}
		if len(f.RunExec.cancels) == 0 {
			t.Error("the cancel must reach the transport (RunCancel), not only the database")
		}
		// INV-A7-25 — pushed immediately, not on the run goroutine's unwind.
		select {
		case e := <-events:
			if e.Status != "CANCELLED" || e.TaskID != task.ID {
				t.Errorf("pushed %#v", e)
			}
		default:
			t.Error("INV-A7-25: the CANCELLED push must happen at cancel time")
		}
		// And the lifecycle audit row is written in the SAME transaction as the child flip.
		if rows := f.auditRows(task.ID); len(rows) != 1 || !strings.HasSuffix(rows[0], "result-canceled") {
			t.Errorf("lifecycle audit rows: got %v, want one …result-canceled", rows)
		}

		// Idempotent: a second cancel on the now-terminal task is a 200 with the request.
		again := f.post(idPath("/api/approvals/", task.ID, "/cancel"), nil, cookie)
		assertStatus(t, again, http.StatusOK, "second cancel")
	})
}

// claimVia is the parent-claim callback /execute passes to ClaimAndStartRun.
func claimVia(f *httpFixture, taskID int64) result.ClaimParent {
	return func(ctx context.Context, c store.Queryer) (bool, error) {
		return f.Access.ClaimExecutionOn(ctx, c, taskID)
	}
}

// denyWire is the wire DENY verdict a proxy returns.
func denyWire() query.WireEnfAction { return query.WireEnfAction(pb.EnfAction_DENY) }

// ---------------------------------------------------------------------------------------------
// `ApprovalDiscoverPickSubmitRouteDbTest` case 1 — through the REAL pipeline.
// ---------------------------------------------------------------------------------------------

// 🔒 Discovery offers the role that returns strictly MORE, and does so under the REAL decideQuery.
//
// The pure suite pins INV-A7-12's mechanism with a scripted decide; this pins that the wiring feeds
// the real pipeline the right things: the requester's own roles for the baseline, R alone for each
// candidate, the datasource's live catalog, and one shared context.
//
// `full-reader` gets result.read.unmasked on `users` WITHOUT the `unless pii` clause the fixture's
// `analyst` grant carries, so `SELECT rrn FROM users` masks for the requester and does not for R —
// the exact "returns more" signal the ranking is defined on.
//
// KT: ApprovalDiscoverPickSubmitRouteDbTest.kt#discover offers full-reader (R-alone) not unmask-only (union trap), pick it, submit carries roleId — the "full-reader is offered with rrn newly unmasked" half; the union trap and the pick→submit round trip are TestDiscoverRefusesTheUnionTrapAndCarriesThePickOntoTheSubmittedRequest
func TestDiscoverOffersTheRoleThatReturnsStrictlyMoreThroughTheRealPipeline(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	users := f.fx.UsersTableEUID()
	f.fx.Seed.Role("full-reader")
	f.fx.AddCedarPolicy("full-reader-connect-select", fmt.Sprintf(
		`permit(principal in Role::"full-reader", action in [Action::"datasource.connect", Action::"sql.select"], resource in Datasource::%q);`,
		f.fx.DatasourceName))
	f.fx.AddCedarPolicy("full-reader-users-unmasked", fmt.Sprintf(
		`permit(principal in Role::"full-reader", action == Action::"result.read.unmasked", resource in Table::%q);`, users))

	rec := f.post("/api/approvals/discover-roles", map[string]any{
		"datasourceId": f.fx.DatasourceID, "sql": "SELECT rrn FROM users",
	}, f.login(requester))

	assertStatus(t, rec, http.StatusOK, "discover-roles")
	var got DiscoverRolesResponse
	decodeJSON(t, rec, &got)

	if !got.BaselineAllowed {
		t.Error("the baseline is a MASK, not a DENY, so baselineAllowed must be true")
	}
	var offered *RoleOption
	for i := range got.Options {
		if got.Options[i].RoleName == "full-reader" {
			offered = &got.Options[i]
		}
		if got.Options[i].RoleName == dbtest.FixtureRole {
			t.Errorf("a role the requester already holds was offered: %#v", got.Options[i])
		}
	}
	if offered == nil {
		t.Fatalf("full-reader was not offered; options = %#v", got.Options)
	}
	if len(offered.UnmasksColumns) != 1 || offered.UnmasksColumns[0] != "rrn" {
		t.Errorf("unmasksColumns: got %v, want [rrn]", offered.UnmasksColumns)
	}
}

// Discovery is a DRY RUN: it writes no audit row, however many candidates it previews.
func TestDiscoverWritesNoAuditRow(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	before := f.auditCount()

	assertStatus(t, f.post("/api/approvals/discover-roles", map[string]any{
		"datasourceId": f.fx.DatasourceID, "sql": "SELECT rrn FROM users",
	}, f.login(requester)), http.StatusOK, "discover-roles")

	if after := f.auditCount(); after != before {
		t.Errorf("discovery wrote %d audit rows; it is a dry run and must write none", after-before)
	}
}

// An unknown datasource is a 404 before any role is previewed.
func TestDiscoverOnAnUnknownDatasourceIs404(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	rec := f.post("/api/approvals/discover-roles", map[string]any{
		"datasourceId": 999999, "sql": "SELECT 1",
	}, f.login(requester))
	assertStatus(t, rec, http.StatusNotFound, "discover on an unknown datasource")
	assertCode(t, rec, "common.not_found")
}
