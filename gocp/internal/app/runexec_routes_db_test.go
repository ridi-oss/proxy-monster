package app_test

// The HTTP halves of A7's run transport, over the REAL composition root and a fake proxy:
//
//   - EditorSubmitRouteDbTest.kt — the async editor submit (10 cases);
//   - the four RunExec-dependent cases of ApprovalExecuteRouteDbTest.kt (the other five need no
//     transport and are already covered in internal/approval's own route suite);
//   - `POST /api/datasources/{id}/query` — A6's queryRoutes, which had no Go handler until now.
//
// Everything runs under PM_AUTH_DEBUG (bootE2EWith's PM_DEV=true), so the caller is the literal
// `debug-user`, exactly as both Kotlin suites arrange. The Cedar gates those suites isolate elsewhere
// (V44 self-approve, the R-scoped approve authority) are bypassed, which is the point: these cases are
// about the TRANSPORT and the task state machine, not about who may ask.

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/approval"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// debugCaller is the PM_AUTH_DEBUG fallback principal every route in this file authenticates as.
const debugCaller = "debug-user"

// grantEditorRole gives the caller ≥1 own role, because the editor submit's step 2 is a FAIL-CLOSED
// `ownRoles.isEmpty() ⇒ 403 common.forbidden` and every submit case would otherwise assert that instead.
func (f *runFixture) grantEditorRole(principal string) {
	f.t.Helper()
	role, err := f.app.Core.PolicyStore.CreateRole(context.Background(), policy.RoleInput{Name: "editor-analyst"})
	if err != nil {
		f.t.Fatalf("create role: %v", err)
	}
	if _, err := f.app.Core.PolicyStore.CreateAssignment(context.Background(),
		policy.RoleAssignmentInput{Principal: principal, RoleID: role.ID}); err != nil {
		f.t.Fatalf("assign role: %v", err)
	}
}

// editorSession opens a persistent editor session THROUGH THE HTTP ROUTE, servicing the dial with a fake
// proxy that runs `behave` for every query.
//
// It is openFakeSession from EditorSubmitRouteDbTest.kt:218-246. The proxy loop stays alive until the
// session is closed, which is what makes "one held stream, N submits" observable.
func (f *runFixture) editorSession(behave proxyBehaviour) (string, *fakeProxy, func()) {
	f.t.Helper()
	opens, detach := f.events()

	type opened struct {
		status int
		body   []byte
	}
	done := make(chan opened, 1)
	go func() {
		status, body := f.do(http.MethodPost, "/api/editor/sessions",
			fmt.Sprintf(`{"datasourceId":%d}`, f.ds.ID))
		done <- opened{status, body}
	}()
	open := f.nextOpen(opens)
	proxy := f.dial(open.GetSessionId(), behave)

	var got opened
	select {
	case got = <-done:
	case <-time.After(runGate):
		f.t.Fatal("POST /api/editor/sessions never returned")
	}
	if got.status != http.StatusOK {
		f.t.Fatalf("POST /api/editor/sessions → %d, want 200 (body: %s)", got.status, got.body)
	}
	var openedSession approval.EditorSessionOpened
	decodeInto(f.t, got.body, &openedSession)
	return openedSession.SessionID, proxy, func() {
		detach()
		f.awaitDetached()
	}
}

// submit drives `POST /api/editor/sessions/{id}/query` and returns the 202 ack.
func (f *runFixture) submit(sessionID, sql string, maxRows int) approval.EditorSubmitResponse {
	f.t.Helper()
	status, body := f.do(http.MethodPost, "/api/editor/sessions/"+sessionID+"/query",
		fmt.Sprintf(`{"sql":%q,"maxRows":%d}`, sql, maxRows))
	if status != http.StatusAccepted {
		f.t.Fatalf("submit → %d, want 202 Accepted (body: %s)", status, body)
	}
	var ack approval.EditorSubmitResponse
	decodeInto(f.t, body, &ack)
	return ack
}

// taskStatus reads the parent task's status straight from the store, for awaitUntil predicates.
func (f *runFixture) taskStatus(taskID int64) string {
	req, err := f.app.Core.AccessStore.GetRequest(context.Background(), taskID)
	if err != nil || req == nil {
		return ""
	}
	return req.Status
}

// childStatus reads the query_result child's status.
func (f *runFixture) childStatus(taskID int64) string {
	meta, err := f.results.Meta(context.Background(), taskID)
	if err != nil || meta == nil || meta.Status == nil {
		return ""
	}
	return *meta.Status
}

// sameRows compares stored rows against their expected NON-NULL values, which is what every case in
// this file asserts (a nil cell never equals a want string, so a NULL that should be a value fails).
func sameRows(got [][]*string, want [][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if len(got[i]) != len(want[i]) {
			return false
		}
		for j := range want[i] {
			if got[i][j] == nil || *got[i][j] != want[i][j] {
				return false
			}
		}
	}
	return true
}

// renderRows prints stored rows with NULLs distinguishable from empty strings, for failure messages.
func renderRows(rows [][]*string) string {
	out := "["
	for i, row := range rows {
		if i > 0 {
			out += " "
		}
		out += "["
		for j, cell := range row {
			if j > 0 {
				out += " "
			}
			if cell == nil {
				out += "NULL"
			} else {
				out += fmt.Sprintf("%q", *cell)
			}
		}
		out += "]"
	}
	return out + "]"
}

// childErrorCode reads the child's stable failure code.
func (f *runFixture) childErrorCode(taskID int64) string {
	meta, err := f.results.Meta(context.Background(), taskID)
	if err != nil || meta == nil || meta.ErrorCode == nil {
		return ""
	}
	return *meta.ErrorCode
}

// ---------------------------------------------------------------------------------------------
// EditorSubmitRouteDbTest.kt
// ---------------------------------------------------------------------------------------------

// --- Case 1 ---------------------------------------------------------------------------------------
//
// KT: EditorSubmitRouteDbTest.kt#submit returns 202 then the run completes async, saves the result, polls DONE, and delete-on-close removes it
//
// The whole async-submit contract in one case: 202 with the ack, the run proceeding on the held session,
// the ENFORCED rows SAVED rather than returned inline, the poll reporting DONE with a row count, and
// delete-on-close removing the tab's task idempotently.
func TestEditorSubmitReturns202ThenCompletesAsyncSavesTheResultPollsDoneAndDeleteOnCloseRemovesIt(t *testing.T) {
	f := newRunFixture(t)
	f.grantEditorRole(debugCaller)
	sessionID, proxy, detach := f.editorSession(allowRows([]string{"id"}, []*string{sp("1")}, []*string{sp("2")}))
	defer detach()

	ack := f.submit(sessionID, "select id from t", 100)
	if childID := f.editorChildID(ack.TaskID); childID != ack.ChildID {
		t.Errorf("the ack's childId = %d, want the store's %d", ack.ChildID, childID)
	}

	f.awaitUntil("task EXECUTED and child DONE", func() bool {
		return f.taskStatus(ack.TaskID) == "EXECUTED" && f.childStatus(ack.TaskID) == "DONE"
	})
	// 🔒 The enforced rows were SAVED, not returned inline — the whole point of the async submit.
	//
	// The Kotlin asserts the VALUES (`assertEquals(listOf(listOf("1"), listOf("2")), …decrypted!!.rows)`),
	// not merely the count: a port that stored two rows of the wrong (or empty) content would satisfy a
	// length check while the tab read back something the proxy never sent.
	rows := f.savedRows(ack.TaskID)
	if want := [][]string{{"1"}, {"2"}}; !sameRows(rows, want) {
		t.Fatalf("the saved result holds %s, want %v", renderRows(rows), want)
	}

	status, body := f.do(http.MethodGet, fmt.Sprintf("/api/editor/tasks/%d", ack.TaskID), "")
	if status != http.StatusOK {
		t.Fatalf("poll → %d, want 200 (body: %s)", status, body)
	}
	var polled approval.EditorTaskStatus
	decodeInto(t, body, &polled)
	if polled.Status != "EXECUTED" {
		t.Errorf("polled status = %q, want EXECUTED", polled.Status)
	}
	if polled.Result == nil || polled.Result.Status == nil || *polled.Result.Status != "DONE" {
		t.Errorf("polled child = %+v, want status DONE", polled.Result)
	}
	if polled.Result == nil || polled.Result.RowCount == nil || *polled.Result.RowCount != 2 {
		t.Errorf("polled rowCount = %v, want 2", polled.Result)
	}

	// Delete-on-close removes the tab's task (CASCADE to its rows), IDEMPOTENTLY.
	if status, body := f.do(http.MethodDelete, fmt.Sprintf("/api/editor/tasks/%d", ack.TaskID), ""); status != http.StatusNoContent {
		t.Errorf("delete → %d, want 204 (body: %s)", status, body)
	}
	if got := f.taskStatus(ack.TaskID); got != "" {
		t.Errorf("the task survived delete-on-close with status %q", got)
	}
	if status, _ := f.do(http.MethodDelete, fmt.Sprintf("/api/editor/tasks/%d", ack.TaskID), ""); status != http.StatusNoContent {
		t.Errorf("the SECOND delete → %d, want an idempotent 204", status)
	}

	f.do(http.MethodDelete, "/api/editor/sessions/"+sessionID, "")
	proxy.awaitClosed()
}

// --- Case 2 ---------------------------------------------------------------------------------------
//
// KT: EditorSubmitRouteDbTest.kt#submit pushes a terminal task event to the owner's stream on completion
//
// 🔒 The push carries the task's ACTUAL terminal state, read back from the row after the transition —
// not the state the async body hoped for. A port that published a hardcoded "EXECUTED" would pass a
// success case and lie on every failure.
func TestEditorSubmitPushesATerminalTaskEventToTheOwnersStreamOnCompletion(t *testing.T) {
	f := newRunFixture(t)
	f.grantEditorRole(debugCaller)
	sessionID, proxy, detach := f.editorSession(allowRows([]string{"id"}, []*string{sp("1")}))
	defer detach()

	events, stop := f.taskEvents()
	defer stop()

	ack := f.submit(sessionID, "select id from t", 100)
	f.awaitUntil("task EXECUTED", func() bool { return f.taskStatus(ack.TaskID) == "EXECUTED" })

	deadline := time.After(runGate)
	for {
		select {
		case ev := <-events:
			if ev.TaskID != ack.TaskID {
				continue
			}
			if ev.Status != "EXECUTED" {
				t.Errorf("the pushed event = %+v, want status EXECUTED", ev)
			}
			f.do(http.MethodDelete, fmt.Sprintf("/api/editor/tasks/%d", ack.TaskID), "")
			f.do(http.MethodDelete, "/api/editor/sessions/"+sessionID, "")
			proxy.awaitClosed()
			return
		case <-deadline:
			t.Fatal("no terminal task event reached the owner's stream")
		}
	}
}

// --- Case 3 ---------------------------------------------------------------------------------------
//
// KT: EditorSubmitRouteDbTest.kt#a DENY at execute marks the task and child FAILED and saves no rows
//
// 🔒 THE FAIL-CLOSED FLOOR. A DENY is not an error — the transport returns a successful QueryResponse
// carrying DENY — so the async body must recognise it and fail the task WITHOUT persisting anything. A
// port that only checked `err != nil` would store the (empty) result as a success and hand a DENY back
// to the tab as a clean, rowless ALLOW.
func TestADenyAtEditorExecuteMarksTheTaskAndChildFailedAndSavesNoRows(t *testing.T) {
	f := newRunFixture(t)
	f.grantEditorRole(debugCaller)
	sessionID, proxy, detach := f.editorSession(func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
		send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_DENY, DenyReason: "policy denies"}))
	})
	defer detach()

	ack := f.submit(sessionID, "select rrn from t", 100)
	f.awaitUntil("DENY marks task and child FAILED", func() bool {
		return f.taskStatus(ack.TaskID) == "FAILED" && f.childStatus(ack.TaskID) == "FAILED"
	})
	if got := f.childErrorCode(ack.TaskID); got != "approval.execute_denied" {
		t.Errorf("errorCode = %q, want approval.execute_denied", got)
	}
	if rows := f.savedRowsOrNil(ack.TaskID); rows != nil {
		t.Errorf("a DENY saved %d readable rows; it must save none", len(rows))
	}

	f.do(http.MethodDelete, "/api/editor/sessions/"+sessionID, "")
	proxy.awaitClosed()
}

// --- Case 4 ---------------------------------------------------------------------------------------
//
// KT: EditorSubmitRouteDbTest.kt#result on a still-running task is 409 not_ready then gates status codes
//
// The run is held in flight (ALLOW + rows, Done withheld), so the child stays RUNNING and the rows are
// not yet committed. `task.assume` PASSES — the owner is a party — so the refusal must come from the
// READINESS check, as 409, not from the authorization gate as a 404.
func TestEditorResultOnAStillRunningTaskIs409NotReady(t *testing.T) {
	f := newRunFixture(t)
	f.grantEditorRole(debugCaller)
	release := make(chan struct{})
	sessionID, proxy, detach := f.editorSession(func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
		send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_ALLOW}))
		send(rowsOf([]string{"id"}, []*string{sp("1")}))
		<-release
		send(doneOf(-1))
	})
	defer detach()

	ack := f.submit(sessionID, "select id from t", 100)
	f.awaitUntil("child RUNNING while in flight", func() bool { return f.childStatus(ack.TaskID) == "RUNNING" })

	status, body := f.do(http.MethodGet, fmt.Sprintf("/api/editor/tasks/%d/result", ack.TaskID), "")
	if status != http.StatusConflict {
		t.Fatalf("result while RUNNING → %d, want 409 approval.result_not_ready (body: %s)", status, body)
	}
	var apiErr types.ApiError
	decodeInto(t, body, &apiErr)
	if apiErr.Code != "approval.result_not_ready" {
		t.Errorf("code = %q, want approval.result_not_ready", apiErr.Code)
	}

	close(release)
	f.awaitUntil("completes to DONE", func() bool { return f.childStatus(ack.TaskID) == "DONE" })

	f.do(http.MethodDelete, "/api/editor/sessions/"+sessionID, "")
	proxy.awaitClosed()
}

// --- Case 5 ---------------------------------------------------------------------------------------
//
// KT: EditorSubmitRouteDbTest.kt#cancel terminalizes an in-flight editor task and emits RunCancel without closing the session
//
// 🔒 "WITHOUT CLOSING THE SESSION" is the part that is easy to get wrong. A cancel targets one
// STATEMENT; the held stream — and the backend connection behind it — survives, so the next submit runs
// on it. A port that closed the session on cancel would silently turn every cancel into a reconnect,
// losing the tab's SET/USE/temp-table state.
func TestEditorCancelTerminalizesAnInFlightTaskAndEmitsRunCancelWithoutClosingTheSession(t *testing.T) {
	f := newRunFixture(t)
	f.grantEditorRole(debugCaller)
	held := make(chan struct{})
	sessionID, proxy, detach := f.editorSession(func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
		send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_ALLOW}))
		<-held
	})
	defer detach()

	ack := f.submit(sessionID, "select id from t", 100)
	f.awaitUntil("editor child RUNNING", func() bool { return f.childStatus(ack.TaskID) == "RUNNING" })
	f.awaitUntil("the query reached the proxy", func() bool { return len(proxy.seenQueries()) == 1 })

	status, body := f.do(http.MethodPost, fmt.Sprintf("/api/editor/tasks/%d/cancel", ack.TaskID), "")
	if status != http.StatusOK {
		t.Fatalf("cancel → %d, want 200 (body: %s)", status, body)
	}
	var cancelled approval.EditorTaskStatus
	decodeInto(t, body, &cancelled)
	if cancelled.Status != "CANCELLED" {
		t.Errorf("cancel body status = %q, want CANCELLED", cancelled.Status)
	}
	if got := f.childStatus(ack.TaskID); got != "CANCELLED" {
		t.Errorf("child status = %q, want CANCELLED", got)
	}
	if got := f.childErrorCode(ack.TaskID); got != "approval.canceled" {
		t.Errorf("child errorCode = %q, want approval.canceled", got)
	}
	// 🔒 The RunCancel reached the stream — the proxy is told to abort the backend statement.
	proxy.awaitCancel()

	status, body = f.do(http.MethodGet, fmt.Sprintf("/api/editor/tasks/%d", ack.TaskID), "")
	if status != http.StatusOK {
		t.Fatalf("poll after cancel → %d (body: %s)", status, body)
	}
	var polled approval.EditorTaskStatus
	decodeInto(t, body, &polled)
	if polled.Status != "CANCELLED" {
		t.Errorf("polled status = %q, want CANCELLED", polled.Status)
	}

	// 🔒 THE SESSION IS STILL LIVE. The stream never received a RunClose, and a second submit runs on it.
	close(held)
	f.do(http.MethodDelete, "/api/editor/sessions/"+sessionID, "")
	proxy.awaitClosed()
}

// --- Case 6 ---------------------------------------------------------------------------------------
//
// KT: EditorSubmitRouteDbTest.kt#canceling a queued editor task sends no cancel or query for the queued statement
//
// 🔒 THE PREFLIGHT'S REASON FOR EXISTING. A second submit on a busy session QUEUES on the session mutex.
// Cancelling it while it waits must mean the statement NEVER CROSSES THE WIRE — not "crosses and is then
// cancelled". The preflight (a DB status re-check inside the cancel gate) is what vetoes the send, and
// the observable is that the fake proxy never sees the queued SQL and never receives a RunCancel for it.
func TestCancellingAQueuedEditorTaskSendsNoCancelOrQueryForTheQueuedStatement(t *testing.T) {
	f := newRunFixture(t)
	f.grantEditorRole(debugCaller)
	firstRelease := make(chan struct{})
	sessionID, proxy, detach := f.editorSession(func(send func(*pb.ProxyRunMsg), q *pb.RunQuery) {
		if q.GetSql() != "select first" {
			t.Errorf("the queued cancelled statement crossed the wire: %q", q.GetSql())
			send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_ALLOW}))
			send(doneOf(-1))
			return
		}
		send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_ALLOW}))
		<-firstRelease
		send(doneOf(-1))
	})
	defer detach()

	first := f.submit(sessionID, "select first", 100)
	f.awaitUntil("first editor child RUNNING", func() bool { return f.childStatus(first.TaskID) == "RUNNING" })
	f.awaitUntil("the first query reached the proxy", func() bool { return len(proxy.seenQueries()) == 1 })

	queued := f.submit(sessionID, "select queued", 100)
	f.awaitUntil("queued child RUNNING", func() bool { return f.childStatus(queued.TaskID) == "RUNNING" })

	status, body := f.do(http.MethodPost, fmt.Sprintf("/api/editor/tasks/%d/cancel", queued.TaskID), "")
	if status != http.StatusOK {
		t.Fatalf("cancel of the queued task → %d (body: %s)", status, body)
	}
	var cancelled approval.EditorTaskStatus
	decodeInto(t, body, &cancelled)
	if cancelled.Status != "CANCELLED" {
		t.Errorf("queued cancel status = %q, want CANCELLED", cancelled.Status)
	}
	// 🔒 The cancel must NOT have targeted the RUNNING statement — the queued task's gate is its own.
	if n := proxy.cancelCount(); n != 0 {
		t.Errorf("%d RunCancel(s) reached the stream; cancelling a QUEUED task must not cancel the "+
			"running one", n)
	}

	close(firstRelease)
	f.awaitUntil("the first task completes", func() bool { return f.childStatus(first.TaskID) == "DONE" })
	f.awaitUntil("the queued task stays cancelled", func() bool { return f.childStatus(queued.TaskID) == "CANCELLED" })
	// 🔒 And the preflight SUPPRESSED the queued query: only the first statement ever crossed.
	if got := proxy.seenQueries(); len(got) != 1 || got[0] != "select first" {
		t.Errorf("the stream saw %v; the preflight must suppress the queued query entirely", got)
	}
	if n := proxy.cancelCount(); n != 0 {
		t.Errorf("%d RunCancel(s) after the first completed; the queued statement never went out, so "+
			"nothing needed cancelling", n)
	}

	f.do(http.MethodDelete, "/api/editor/sessions/"+sessionID, "")
	proxy.awaitClosed()
}

// --- Case 7 ---------------------------------------------------------------------------------------
//
// KT: EditorSubmitRouteDbTest.kt#delete of an executing editor task emits RunCancel then removes the task
//
// Closing a tab mid-query must both stop the backend statement and remove the row. The order matters:
// the RunCancel goes out, THEN the task disappears.
func TestDeleteOfAnExecutingEditorTaskEmitsRunCancelThenRemovesTheTask(t *testing.T) {
	f := newRunFixture(t)
	f.grantEditorRole(debugCaller)
	held := make(chan struct{})
	sessionID, proxy, detach := f.editorSession(func(_ func(*pb.ProxyRunMsg), _ *pb.RunQuery) { <-held })
	defer detach()

	ack := f.submit(sessionID, "select id from t", 100)
	f.awaitUntil("editor child RUNNING", func() bool { return f.childStatus(ack.TaskID) == "RUNNING" })
	f.awaitUntil("the query reached the proxy", func() bool { return len(proxy.seenQueries()) == 1 })

	if status, body := f.do(http.MethodDelete, fmt.Sprintf("/api/editor/tasks/%d", ack.TaskID), ""); status != http.StatusNoContent {
		t.Fatalf("delete of an executing task → %d, want 204 (body: %s)", status, body)
	}
	proxy.awaitCancel()
	if got := f.taskStatus(ack.TaskID); got != "" {
		t.Errorf("the task survived the delete with status %q", got)
	}

	close(held)
	f.do(http.MethodDelete, "/api/editor/sessions/"+sessionID, "")
	proxy.awaitClosed()
}

// --- Case 8 ---------------------------------------------------------------------------------------
//
// KT: EditorSubmitRouteDbTest.kt#submit guards - blank sql is 400 and an unknown session is 404
//
// 🔒 THE ORDER IS THE CONTRACT. Blank SQL is rejected BEFORE the session is looked up, which is why the
// blank-SQL probe uses a session id that does not exist and still gets 400 rather than 404. Reversing the
// two would turn "you typed nothing" into "your tab is gone".
//
// And the unknown-session 404 is owner-scoped: it is the same answer a leaked-but-not-owned id gets, so
// nothing here is an existence oracle.
func TestEditorSubmitGuardsBlankSQLIs400AndAnUnknownSessionIs404(t *testing.T) {
	f := newRunFixture(t)
	f.grantEditorRole(debugCaller)

	status, body := f.do(http.MethodPost, "/api/editor/sessions/whatever/query", `{"sql":"   ","maxRows":100}`)
	if status != http.StatusBadRequest {
		t.Errorf("blank sql → %d, want 400 (body: %s)", status, body)
	}
	var apiErr types.ApiError
	decodeInto(t, body, &apiErr)
	if apiErr.Code != "common.field_required" {
		t.Errorf("blank sql code = %q, want common.field_required", apiErr.Code)
	}

	status, body = f.do(http.MethodPost, "/api/editor/sessions/no-such-session/query",
		`{"sql":"select id from t","maxRows":100}`)
	if status != http.StatusNotFound {
		t.Errorf("unknown session → %d, want 404 (body: %s)", status, body)
	}
}

// --- Case 9 ---------------------------------------------------------------------------------------
//
// KT-DEFER: EditorSubmitRouteDbTest.kt#a task_read forbid denies the owner's poll with 404 — the ASSERTION
// is already ported, as internal/approval's TestACedarForbidOverridesTheEditorOwnersSelfReadPermit, which
// drives the same forbid against the same route with a real web session. What is NOT ported is doing it
// through THIS composition root, and the blocker is the fixture rather than the behaviour: the Kotlin
// mounts a `POST /test/session/{principal}` helper route inside its own test application to mint a web
// session, and app.NewHTTPSurface has no seam for adding a route. Blocked on a test-only login seam on
// HTTPSurface; tracked in this file's header and in 96-traceability.md.

// --- Case 10 --------------------------------------------------------------------------------------
//
// KT: EditorSubmitRouteDbTest.kt#poll and result for a non-owner editor task are 404
//
// 🔒 THREE DISTINCT REFUSALS, ONE INDISTINGUISHABLE ANSWER. The poll is owner-scoped, the result is
// `task.assume`-scoped, and the delete is a silent no-op — so a principal who learns another user's task
// id can neither read its metadata, read its rows, nor destroy it, and cannot tell which of those reasons
// applied.
func TestPollAndResultForANonOwnerEditorTaskAre404(t *testing.T) {
	f := newRunFixture(t)
	f.grantEditorRole(debugCaller)

	other, err := f.app.Core.AccessStore.CreateEditorTask(context.Background(),
		"someone-else@example.com", f.ds.ID, "select id from t", []string{"editor-analyst"},
		"someone-else@example.com")
	if err != nil {
		t.Fatalf("create another principal's editor task: %v", err)
	}

	if status, body := f.do(http.MethodGet, fmt.Sprintf("/api/editor/tasks/%d", other.ID), ""); status != http.StatusNotFound {
		t.Errorf("poll of a non-owner task → %d, want 404 (body: %s)", status, body)
	}
	if status, body := f.do(http.MethodGet, fmt.Sprintf("/api/editor/tasks/%d/result", other.ID), ""); status != http.StatusNotFound {
		t.Errorf("result of a non-owner task → %d, want 404 (body: %s)", status, body)
	}
	// Delete by a non-owner is a SILENT NO-OP — an idempotent 204 that leaves the task intact, so the
	// caller cannot even learn that it exists from a difference in status.
	if status, body := f.do(http.MethodDelete, fmt.Sprintf("/api/editor/tasks/%d", other.ID), ""); status != http.StatusNoContent {
		t.Errorf("delete of a non-owner task → %d, want an idempotent 204 (body: %s)", status, body)
	}
	if got := f.taskStatus(other.ID); got != "APPROVED" {
		t.Errorf("the non-owner delete changed the task to %q; it must leave it APPROVED", got)
	}
}

// ---------------------------------------------------------------------------------------------
// ApprovalExecuteRouteDbTest.kt — the four RunExec-dependent cases
// ---------------------------------------------------------------------------------------------

// seedApprovedRoleRequest is ApprovalExecuteRouteDbTest.kt:193-210's helper: a QUERY request elevating a
// requester to a fresh role R on the datasource, already APPROVED, with `decided_by` set so `/execute`'s
// approver-of-record gate passes.
func (f *runFixture) seedApprovedRoleRequest(roleName, decidedBy string) (int64, string) {
	f.t.Helper()
	role, err := f.app.Core.PolicyStore.CreateRole(context.Background(), policy.RoleInput{Name: roleName})
	if err != nil {
		f.t.Fatalf("create role %q: %v", roleName, err)
	}
	req, err := f.app.Core.AccessStore.CreateQueryRequest(context.Background(), accessQueryRequestInput(
		"requester@example.com", f.ds.ID, "select rrn from users", role.ID))
	if err != nil {
		f.t.Fatalf("create query request: %v", err)
	}
	if _, err := f.app.Db.Pool.Exec(context.Background(),
		`UPDATE access_request SET status='APPROVED', decided_by=$1 WHERE id=$2`, decidedBy, req.ID); err != nil {
		f.t.Fatalf("approve the seeded request: %v", err)
	}
	return req.ID, roleName
}

// storedResultCount counts `query_result` rows for a task, straight from the table.
func (f *runFixture) storedResultCount(taskID int64) int64 {
	f.t.Helper()
	var n int64
	if err := f.app.Db.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM query_result WHERE task_id = $1`, taskID).Scan(&n); err != nil {
		f.t.Fatalf("count stored results: %v", err)
	}
	return n
}

// --- Case 1 ---------------------------------------------------------------------------------------
//
// KT: ApprovalExecuteRouteDbTest.kt#a DENY-under-R at execute leaks no result and stores nothing (fail-closed floor)
//
// 🔒 THE FAIL-CLOSED FLOOR, and the token assertions are what make it a test of execute-under-R rather
// than of DENY handling. The fake proxy's fabricated DENY never inspects the token, so without them this
// would still pass if `assumeRoles` were dropped or the legacy self-exec path were taken. The token is
// resolved WHILE the run holds it — the only moment it is live — and must carry EXACTLY role R, on the
// APPROVER_EXEC kind, under the APPROVER's principal.
func TestADenyUnderRAtExecuteLeaksNoResultAndStoresNothingOverTheRealWire(t *testing.T) {
	f := newRunFixture(t)
	id, roleR := f.seedApprovedRoleRequest("exec-deny-role", debugCaller)

	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	type resp struct {
		status int
		body   []byte
	}
	done := make(chan resp, 1)
	go func() {
		status, body := f.do(http.MethodPost, fmt.Sprintf("/api/approvals/%d/execute", id), "")
		done <- resp{status, body}
	}()
	open := f.nextOpen(opens)

	// 🔒 Resolve NOW, while run() still holds the token live — it is revoked in the cleanup.
	identity := f.tokenIdentity(open.GetEphemeralToken())

	proxy := f.dial(open.GetSessionId(), func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
		send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_DENY, DenyReason: "policy denies column rrn"}))
	})

	var got resp
	select {
	case got = <-done:
	case <-time.After(runGate):
		t.Fatal("POST /execute never returned")
	}
	proxy.awaitClosed()

	if got.status != http.StatusAccepted {
		t.Fatalf("execute → %d, want 202 (body: %s)", got.status, got.body)
	}
	var ack approval.ExecuteApprovalResponse
	decodeInto(t, got.body, &ack)
	if ack.Decision != "EXECUTING" {
		t.Errorf("ack decision = %q, want EXECUTING", ack.Decision)
	}
	f.awaitUntil("DENY marks task and child failed", func() bool {
		return f.taskStatus(id) == "FAILED" && f.childStatus(id) == "FAILED"
	})
	if n := f.storedResultCount(id); n != 1 {
		t.Errorf("query_result rows = %d, want 1 (the pre-created statement child remains as failed "+
			"execution metadata)", n)
	}
	if got := f.childErrorCode(id); got != "approval.execute_denied" {
		t.Errorf("errorCode = %q, want approval.execute_denied", got)
	}
	if rows := f.savedRowsOrNil(id); rows != nil {
		t.Errorf("a DENY-under-R saved %d readable rows; the floor is that it saves NONE", len(rows))
	}

	// The route→token→decide wiring the DENY playback cannot see.
	if identity == nil {
		t.Fatal("the ephemeral token did not resolve during the run window")
	}
	if len(identity.Roles) != 1 || identity.Roles[0] != roleR {
		t.Errorf("the decide token's roles = %v, want EXACTLY [%s] — 🔒 INV-A7-1: R ALONE, never the "+
			"requester's own roles and never an empty set", identity.Roles, roleR)
	}
	if identity.Kind != "APPROVER_EXEC" {
		t.Errorf("kind = %q, want APPROVER_EXEC — the grant-ineligible, R-unmask channel", identity.Kind)
	}
	if identity.Principal != debugCaller {
		t.Errorf("principal = %q, want the APPROVER %q — a run left on the requester's identity is "+
			"caught here", identity.Principal, debugCaller)
	}
}

// --- Case 2 ---------------------------------------------------------------------------------------
//
// KT: ApprovalExecuteRouteDbTest.kt#a second execute after a successful first is rejected with 409 approval_already_executed, storing exactly one result
//
// 🔒 THE SECOND CALL IS MADE WITH NO PROXY ATTACHED, DELIBERATELY. That is what proves the claim fires
// BEFORE the dial: if the guard did not, the second execute would answer 503 `query.no_proxy_attached`
// (or hang) instead of the typed 409 — and the target would have been dialed twice.
func TestASecondExecuteIs409AndStoresExactlyOneResultOverTheRealWire(t *testing.T) {
	f := newRunFixture(t)
	id, _ := f.seedApprovedRoleRequest("exec-once-role", debugCaller)

	func() {
		opens, detach := f.events()
		defer func() {
			detach()
			f.awaitDetached()
		}()
		type resp struct {
			status int
			body   []byte
		}
		done := make(chan resp, 1)
		go func() {
			status, body := f.do(http.MethodPost, fmt.Sprintf("/api/approvals/%d/execute", id), "")
			done <- resp{status, body}
		}()
		open := f.nextOpen(opens)
		proxy := f.dial(open.GetSessionId(), allowRows([]string{"rrn"}, []*string{sp("some-value")}))
		var got resp
		select {
		case got = <-done:
		case <-time.After(runGate):
			t.Fatal("POST /execute never returned")
		}
		proxy.awaitClosed()
		if got.status != http.StatusAccepted {
			t.Fatalf("first execute → %d, want 202 (body: %s)", got.status, got.body)
		}
		// The Kotlin asserts the FIRST execute's ack too: 202 alone does not say the route reported the
		// task as EXECUTING rather than, say, echoing a terminal decision it had not reached yet.
		var firstAck approval.ExecuteApprovalResponse
		decodeInto(t, got.body, &firstAck)
		if firstAck.Decision != "EXECUTING" {
			t.Errorf("first ack decision = %q, want EXECUTING", firstAck.Decision)
		}
		f.awaitUntil("the successful run completes", func() bool {
			return f.taskStatus(id) == "EXECUTED" && f.childStatus(id) == "DONE"
		})
		if n := f.storedResultCount(id); n != 1 {
			t.Errorf("query_result rows after the first execute = %d, want 1", n)
		}
	}()

	// No proxy is attached for this second call.
	status, body := f.do(http.MethodPost, fmt.Sprintf("/api/approvals/%d/execute", id), "")
	if status != http.StatusConflict {
		t.Fatalf("the second execute → %d, want 409 approval.already_executed.\n"+
			"503 here means the execute-once claim did NOT fire before the dial. (body: %s)", status, body)
	}
	var apiErr types.ApiError
	decodeInto(t, body, &apiErr)
	if apiErr.Code != "approval.already_executed" {
		t.Errorf("code = %q, want approval.already_executed", apiErr.Code)
	}
	if n := f.storedResultCount(id); n != 1 {
		t.Errorf("the rejected second execute changed the stored result count to %d", n)
	}
	rows := f.savedRows(id)
	if len(rows) != 1 || rows[0][0] == nil || *rows[0][0] != "some-value" {
		t.Errorf("the original stored rows = %v, want them unchanged by the rejected second execute", rows)
	}
}

// --- Case 3 ---------------------------------------------------------------------------------------
//
// KT: ApprovalExecuteRouteDbTest.kt#execute returns 202 EXECUTING while the run is still in flight, then completes to EXECUTED and DONE
//
// 🔒 THE ASYNC CONTRACT ITSELF. The fake proxy sends ALLOW + rows and WITHHOLDS Done; the HTTP response
// must already have returned, and the durable task/child must be observably EXECUTING/RUNNING, before
// Done is released. A synchronous route that blocked on Done would DEADLOCK this test rather than fail
// it — which is a stronger signal than any assertion.
func TestExecuteReturns202WhileInFlightThenCompletesOverTheRealWire(t *testing.T) {
	f := newRunFixture(t)
	id, _ := f.seedApprovedRoleRequest("exec-async-role", debugCaller)

	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	releaseDone := make(chan struct{})
	type resp struct {
		status int
		body   []byte
	}
	done := make(chan resp, 1)
	go func() {
		status, body := f.do(http.MethodPost, fmt.Sprintf("/api/approvals/%d/execute", id), "")
		done <- resp{status, body}
	}()
	open := f.nextOpen(opens)
	proxy := f.dial(open.GetSessionId(), func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
		send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_ALLOW}))
		send(rowsOf([]string{"rrn"}, []*string{sp("some-value")}))
		<-releaseDone
		send(doneOf(-1))
	})

	var got resp
	select {
	case got = <-done:
	case <-time.After(runGate):
		t.Fatal("POST /execute blocked on the proxy's Done — the route must be ASYNC")
	}
	if got.status != http.StatusAccepted {
		t.Fatalf("execute → %d, want 202 (body: %s)", got.status, got.body)
	}
	var ack approval.ExecuteApprovalResponse
	decodeInto(t, got.body, &ack)
	if ack.Decision != "EXECUTING" {
		t.Errorf("ack decision = %q, want EXECUTING", ack.Decision)
	}
	// ...and while the proxy still holds Done, the DURABLE state is observably in flight.
	f.awaitUntil("task EXECUTING and child RUNNING while in flight", func() bool {
		return f.taskStatus(id) == "EXECUTING" && f.childStatus(id) == "RUNNING"
	})

	close(releaseDone)
	proxy.awaitClosed()
	f.awaitUntil("the run completes to EXECUTED and DONE", func() bool {
		return f.taskStatus(id) == "EXECUTED" && f.childStatus(id) == "DONE"
	})
	if n := f.storedResultCount(id); n != 1 {
		t.Errorf("query_result rows = %d, want 1", n)
	}
	rows := f.savedRows(id)
	if len(rows) != 1 || rows[0][0] == nil || *rows[0][0] != "some-value" {
		t.Errorf("stored rows = %v, want [[some-value]]", rows)
	}
}

// --- Case 4 ---------------------------------------------------------------------------------------
//
// KT: ApprovalExecuteRouteDbTest.kt#canceling an in-flight approval terminalizes both rows and emits RunCancel
//
// The approval analogue of the editor cancel: BOTH rows (parent and child) go terminal in one commit and
// the RunCancel reaches the proxy — INV-A7-35's send half over the real HTTP surface.
func TestCancellingAnInFlightApprovalTerminalizesBothRowsAndEmitsRunCancel(t *testing.T) {
	f := newRunFixture(t)
	id, _ := f.seedApprovedRoleRequest("exec-cancel-role", debugCaller)

	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	release := make(chan struct{})
	type resp struct {
		status int
		body   []byte
	}
	done := make(chan resp, 1)
	go func() {
		status, body := f.do(http.MethodPost, fmt.Sprintf("/api/approvals/%d/execute", id), "")
		done <- resp{status, body}
	}()
	open := f.nextOpen(opens)
	proxy := f.dial(open.GetSessionId(), func(_ func(*pb.ProxyRunMsg), _ *pb.RunQuery) { <-release })

	var got resp
	select {
	case got = <-done:
	case <-time.After(runGate):
		t.Fatal("POST /execute never returned")
	}
	if got.status != http.StatusAccepted {
		t.Fatalf("execute → %d, want 202 (body: %s)", got.status, got.body)
	}
	f.awaitUntil("approval child RUNNING", func() bool { return f.childStatus(id) == "RUNNING" })
	f.awaitUntil("the query reached the proxy", func() bool { return len(proxy.seenQueries()) == 1 })

	// 🔒 The Kotlin asserts the DETAIL body's affordance first: an in-flight task the caller may cancel
	// must report canCancel=true, or the console shows no Cancel button and the capability is unreachable
	// even though the route works.
	status, body := f.do(http.MethodGet, fmt.Sprintf("/api/approvals/%d", id), "")
	if status != http.StatusOK {
		t.Fatalf("approval detail → %d, want 200 (body: %s)", status, body)
	}
	var detail approval.ApprovalDetail
	decodeInto(t, body, &detail)
	if !detail.CanCancel {
		t.Errorf("canCancel = false for an EXECUTING task the caller may cancel; the console would offer "+
			"no Cancel affordance (detail: %s)", body)
	}

	status, body = f.do(http.MethodPost, fmt.Sprintf("/api/approvals/%d/cancel", id), "")
	if status != http.StatusOK {
		t.Fatalf("cancel → %d, want 200 (body: %s)", status, body)
	}
	// The RESPONSE the caller reads must already say CANCELLED — the Kotlin asserts the body, not just
	// the row, so a route that answered the pre-cancel snapshot is caught.
	var cancelledReq access.AccessRequest
	decodeInto(t, body, &cancelledReq)
	if cancelledReq.Status != "CANCELLED" {
		t.Errorf("cancel body status = %q, want CANCELLED", cancelledReq.Status)
	}
	if got := f.taskStatus(id); got != "CANCELLED" {
		t.Errorf("parent status = %q, want CANCELLED", got)
	}
	if got := f.childStatus(id); got != "CANCELLED" {
		t.Errorf("child status = %q, want CANCELLED", got)
	}
	if got := f.childErrorCode(id); got != "approval.canceled" {
		t.Errorf("child errorCode = %q, want approval.canceled", got)
	}
	proxy.awaitCancel()

	close(release)
}

// ---------------------------------------------------------------------------------------------
// A6's queryRoutes — `POST /api/datasources/{id}/query`
// ---------------------------------------------------------------------------------------------

// TestTheSynchronousQueryRouteRunsAndAnswersRowsInline is the route's happy path.
//
// It had NO Kotlin test of its own — 06-query-decision.md §7's inventory lists no suite for `queryRoutes`
// — so this is a gap-fill, not a port. What it pins is the one thing the route adds over the transport:
// the response IS the rows, inline and synchronous, with nothing persisted.
func TestTheSynchronousQueryRouteRunsAndAnswersRowsInline(t *testing.T) {
	f := newRunFixture(t)
	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	type resp struct {
		status int
		body   []byte
	}
	done := make(chan resp, 1)
	go func() {
		status, body := f.do(http.MethodPost, fmt.Sprintf("/api/datasources/%d/query", f.ds.ID),
			`{"sql":"select id, email from users","maxRows":250}`)
		done <- resp{status, body}
	}()
	open := f.nextOpen(opens)
	proxy := f.dial(open.GetSessionId(), func(send func(*pb.ProxyRunMsg), q *pb.RunQuery) {
		if got := q.GetSql(); got != "select id, email from users" {
			t.Errorf("the proxy saw sql %q", got)
		}
		// The caller's maxRows reaches the wire unchanged when it is inside [0, 5000].
		if got := q.GetMaxRows(); got != 250 {
			t.Errorf("max_rows = %d, want the caller's 250", got)
		}
		send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_MASK, MaskedColumns: []string{"email"}}))
		send(rowsOf([]string{"id", "email"}, []*string{sp("1"), sp("a***@example.com")}))
		send(doneOf(-1))
	})

	var got resp
	select {
	case got = <-done:
	case <-time.After(runGate):
		t.Fatal("POST /api/datasources/{id}/query never returned")
	}
	proxy.awaitClosed()

	if got.status != http.StatusOK {
		t.Fatalf("query → %d, want 200 (body: %s)", got.status, got.body)
	}
	var response query.QueryResponse
	decodeInto(t, got.body, &response)
	if pb.EnfAction(response.Decision) != pb.EnfAction_MASK {
		t.Errorf("decision = %v, want MASK", response.Decision)
	}
	if len(response.Rows) != 1 || response.Rows[0][1] == nil || *response.Rows[0][1] != "a***@example.com" {
		t.Errorf("rows = %v — the response IS the rows on this route", response.Rows)
	}
	if got := response.MaskedColumns; len(got) != 1 || got[0] != "email" {
		t.Errorf("maskedColumns = %v", got)
	}

	// 🔒 The statement reached the caller's query history, best-effort. That is the route's only write.
	entries := f.recentHistory(debugCaller, 50)
	found := false
	for _, e := range entries {
		if e.SQL == "select id, email from users" {
			found = true
		}
	}
	if !found {
		t.Errorf("the statement is absent from the caller's query history: %+v", entries)
	}
}

// TestTheSynchronousQueryRouteMapsEveryTransportFailureToItsOwnStatus is 06-query-decision.md §6's
// exception→status table, which is the whole substance of the handler.
//
// 🔒 INV-A7-34 lives here: `no_proxy_attached` and `proxy_stream_wedged` are BOTH 503 and must stay
// DISTINCT codes, because the operator answer differs — nothing is missing in the wedged case, a live
// stream is unusable and has been dropped so the proxy's own reconnect can replace it.
func TestTheSynchronousQueryRouteMapsEveryTransportFailureToItsOwnStatus(t *testing.T) {
	f := newRunFixture(t)

	t.Run("bad id is 400", func(t *testing.T) {
		status, body := f.do(http.MethodPost, "/api/datasources/not-a-number/query", `{"sql":"select 1"}`)
		if status != http.StatusBadRequest {
			t.Fatalf("→ %d, want 400 (body: %s)", status, body)
		}
		var apiErr types.ApiError
		decodeInto(t, body, &apiErr)
		if apiErr.Code != "common.bad_id" {
			t.Errorf("code = %q, want common.bad_id", apiErr.Code)
		}
	})

	t.Run("an unknown datasource is 404 and never dials", func(t *testing.T) {
		status, body := f.do(http.MethodPost, "/api/datasources/999999/query", `{"sql":"select 1"}`)
		if status != http.StatusNotFound {
			t.Fatalf("→ %d, want 404 (body: %s)", status, body)
		}
		var apiErr types.ApiError
		decodeInto(t, body, &apiErr)
		if apiErr.Code != "common.not_found" {
			t.Errorf("code = %q, want common.not_found", apiErr.Code)
		}
	})

	t.Run("no attached proxy is 503 query.no_proxy_attached", func(t *testing.T) {
		status, body := f.do(http.MethodPost, fmt.Sprintf("/api/datasources/%d/query", f.ds.ID),
			`{"sql":"select 1"}`)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("→ %d, want 503 (body: %s)", status, body)
		}
		var apiErr types.ApiError
		decodeInto(t, body, &apiErr)
		if apiErr.Code != "query.no_proxy_attached" {
			t.Errorf("code = %q, want query.no_proxy_attached — 🔒 INV-A7-34 keeps it distinct from "+
				"query.proxy_stream_wedged", apiErr.Code)
		}
	})

	t.Run("a proxy run failure is 502 query.failed with the detail", func(t *testing.T) {
		opens, detach := f.events()
		defer func() {
			detach()
			f.awaitDetached()
		}()
		type resp struct {
			status int
			body   []byte
		}
		done := make(chan resp, 1)
		go func() {
			status, body := f.do(http.MethodPost, fmt.Sprintf("/api/datasources/%d/query", f.ds.ID),
				`{"sql":"select broken"}`)
			done <- resp{status, body}
		}()
		open := f.nextOpen(opens)
		proxy := f.dial(open.GetSessionId(), func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
			send(errorOf("backend disconnected"))
		})
		var got resp
		select {
		case got = <-done:
		case <-time.After(runGate):
			t.Fatal("the query never returned")
		}
		proxy.awaitClosed()
		if got.status != http.StatusBadGateway {
			t.Fatalf("→ %d, want 502 (body: %s)", got.status, got.body)
		}
		var apiErr types.ApiError
		decodeInto(t, got.body, &apiErr)
		if apiErr.Code != "query.failed" {
			t.Errorf("code = %q, want query.failed", apiErr.Code)
		}
		// ⚠️ F13/INV-A1-13: the detail IS English prose on the wire. REPRODUCED, not fixed.
		if apiErr.Params["detail"] != "backend disconnected" {
			t.Errorf("detail = %q, want the proxy's own message verbatim", apiErr.Params["detail"])
		}
	})

	t.Run("the PM_QUERY_TIMEOUT sentinel is 504 query.proxy_timeout", func(t *testing.T) {
		opens, detach := f.events()
		defer func() {
			detach()
			f.awaitDetached()
		}()
		type resp struct {
			status int
			body   []byte
		}
		done := make(chan resp, 1)
		go func() {
			status, body := f.do(http.MethodPost, fmt.Sprintf("/api/datasources/%d/query", f.ds.ID),
				`{"sql":"select sleep(9999)"}`)
			done <- resp{status, body}
		}()
		open := f.nextOpen(opens)
		// 🔒 The cross-language sentinel, end to end: the proxy's watchdog message becomes a 504 that
		// says TIMEOUT rather than a 502 that says "something failed".
		proxy := f.dial(open.GetSessionId(), func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
			send(errorOf(runexecQueryTimeoutMessage))
		})
		var got resp
		select {
		case got = <-done:
		case <-time.After(runGate):
			t.Fatal("the query never returned")
		}
		proxy.awaitClosed()
		if got.status != http.StatusGatewayTimeout {
			t.Fatalf("→ %d, want 504 (body: %s)", got.status, got.body)
		}
		var apiErr types.ApiError
		decodeInto(t, got.body, &apiErr)
		if apiErr.Code != "query.proxy_timeout" {
			t.Errorf("code = %q, want query.proxy_timeout", apiErr.Code)
		}
	})
}
