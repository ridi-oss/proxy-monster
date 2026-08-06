package approval

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
)

// ---------------------------------------------------------------------------------------------
// `/api/editor/**` — Query.kt:904-1180, 06-query-decision.md §6.
//
// Ports `EditorSubmitRouteDbTest` and `EditorSelfApproveAuthzDbTest`, plus the two gate-layering
// invariants the area doc singles out (INV-A6-25, INV-A6-26).
// ---------------------------------------------------------------------------------------------

// openEditorSession opens a session for principal through the real route, and returns its id.
func (f *httpFixture) openEditorSession(principal string, cookie *http.Cookie) string {
	f.t.Helper()
	rec := f.post("/api/editor/sessions", map[string]any{"datasourceId": f.fx.DatasourceID}, cookie)
	assertStatus(f.t, rec, http.StatusOK, "open editor session")
	var opened EditorSessionOpened
	decodeJSON(f.t, rec, &opened)
	if opened.SessionID == "" {
		f.t.Fatal("no session id was returned")
	}
	return opened.SessionID
}

// `EditorSubmitRouteDbTest` — the submit sequence end to end.
func TestEditorSubmitCreatesABornApprovedTaskClaimsItAtomicallyAndCompletes(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	cookie := f.login(requester)
	sessionID := f.openEditorSession(requester, cookie)
	f.RunExec.response.Columns = []string{"id"}
	f.RunExec.response.Rows = [][]*string{{strptr("1")}}

	rec := f.post("/api/editor/sessions/"+sessionID+"/query", map[string]any{"sql": "SELECT id FROM users"}, cookie)

	assertStatus(t, rec, http.StatusAccepted, "editor submit")
	var ack EditorSubmitResponse
	decodeJSON(t, rec, &ack)
	if ack.TaskID == 0 || ack.ChildID <= 0 {
		t.Fatalf("ack: got %#v, want a real taskId and childId", ack)
	}

	// 🔒 INV-A6-23 — the claim is atomic across parent and child: BEFORE the async body runs, the
	// parent is EXECUTING and the child is RUNNING, so a cancel arriving now has something to catch.
	task := f.getRequest(ack.TaskID)
	if task.Status != "EXECUTING" {
		t.Errorf("status after the claim: got %q, want EXECUTING", task.Status)
	}
	if task.CreatorKind == nil || *task.CreatorKind != "EDITOR" {
		t.Errorf("creatorKind: got %v, want EDITOR", task.CreatorKind)
	}
	// 🔒 INV-A6-22 — executeAs is the caller's OWN freshly-resolved roles, never an elevation.
	if len(task.ExecuteAs) != 1 || task.ExecuteAs[0] != dbtest.FixtureRole {
		t.Errorf("executeAs: got %v, want the caller's own [%s]", task.ExecuteAs, dbtest.FixtureRole)
	}
	meta, _ := f.Results.Meta(context.Background(), ack.TaskID)
	if meta == nil || meta.Status == nil || *meta.Status != "RUNNING" {
		t.Errorf("child status after the claim: got %#v, want RUNNING", meta)
	}

	if n := f.runAsync(); n != 1 {
		t.Fatalf("%d async bodies queued, want 1", n)
	}

	if got := f.getRequest(ack.TaskID).Status; got != "EXECUTED" {
		t.Errorf("status after the run: got %q, want EXECUTED", got)
	}
	// 🔒 INV-A6-24 — NO task-level audit row on the success path. The run's own Decide round-trip
	// already wrote the real decision; a row here would duplicate it as a FALSE ALLOW.
	if rows := f.auditRows(ack.TaskID); len(rows) != 0 {
		t.Errorf("INV-A6-24: the editor success path wrote %v; it must write no task-level audit row", rows)
	}
	// The run went to the HELD SESSION, not the one-shot path.
	if len(f.RunExec.sessionRuns) != 1 || f.RunExec.sessionRuns[0].SessionID != sessionID {
		t.Errorf("session runs: got %#v, want one on %s", f.RunExec.sessionRuns, sessionID)
	}
	if f.RunExec.runCount() != 0 {
		t.Error("an editor submit must not use the one-shot run path")
	}
}

// The submit sequence's refusals, in the order the route checks them.
func TestEditorSubmitRefusalsInOrder(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	cookie := f.login(requester)
	sessionID := f.openEditorSession(requester, cookie)

	t.Run("a blank sql names the field", func(t *testing.T) {
		rec := f.post("/api/editor/sessions/"+sessionID+"/query", map[string]any{"sql": "   "}, cookie)
		assertStatus(t, rec, http.StatusBadRequest, "blank sql")
		assertCode(t, rec, "common.field_required")
	})

	// 🔒 A LEAKED SESSION ID CANNOT TARGET ANOTHER PRINCIPAL'S CONNECTION. The lookup is owner-scoped,
	// so an outsider holding the id gets the same 404 an unknown id gets.
	t.Run("another principal's session id is an opaque 404", func(t *testing.T) {
		outsiderCookie := f.login(outsider)
		f.fx.Seed.AssignRole(outsider, f.roleID(dbtest.FixtureRole)) // so the empty-roles 403 is not what refuses

		leaked := f.post("/api/editor/sessions/"+sessionID+"/query", map[string]any{"sql": "SELECT 1"}, outsiderCookie)
		unknown := f.post("/api/editor/sessions/does-not-exist/query", map[string]any{"sql": "SELECT 1"}, outsiderCookie)

		assertStatus(t, leaked, http.StatusNotFound, "a leaked session id")
		assertCode(t, leaked, "common.not_found")
		if leaked.Body.String() != unknown.Body.String() {
			t.Errorf("a leaked id must be indistinguishable from an unknown one:\n got %s\nwant %s",
				leaked.Body.String(), unknown.Body.String())
		}
	})

	// A principal with NO roles cannot submit: executeAs would be empty, and INV-A7-2's empty-{R}
	// failure would then land at view time instead of here.
	t.Run("a principal with no roles is forbidden", func(t *testing.T) {
		const roleless = "roleless@example.com"
		rolelessCookie := f.login(roleless)
		rolelessSession := f.openEditorSession(roleless, rolelessCookie)

		rec := f.post("/api/editor/sessions/"+rolelessSession+"/query", map[string]any{"sql": "SELECT 1"}, rolelessCookie)
		assertStatus(t, rec, http.StatusForbidden, "submit with no roles")
		assertCode(t, rec, "common.forbidden")
	})
}

// With no result store (PM_RESULT_KEY unset) the submit is refused fail-closed rather than running
// the query and dropping the rows on the floor.
func TestEditorSubmitIsRefusedWhenResultStorageIsNotConfigured(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{NoResultStore: true})
	cookie := f.login(requester)
	sessionID := f.openEditorSession(requester, cookie)

	rec := f.post("/api/editor/sessions/"+sessionID+"/query", map[string]any{"sql": "SELECT id FROM users"}, cookie)

	assertStatus(t, rec, http.StatusServiceUnavailable, "submit with no result store")
	assertCode(t, rec, "approval.result_storage_not_configured")
	if len(f.RunExec.sessionRuns) != 0 {
		t.Error("nothing may run when the result cannot be stored")
	}
}

// `EditorSelfApproveAuthzDbTest` — 🔒 INV-A7-17: a self-approved task must clear BOTH lifecycle
// checks a human request+approve would, and EITHER Deny fails it closed.
//
// The two sub-cases forbid one gate each, so a port that checked only one of them fails exactly one
// of them — which is the discrimination a single combined case would lose.
func TestEditorSubmitMustClearBothTaskRequestAndTaskApprove(t *testing.T) {
	for _, forbidden := range []struct {
		action string
		policy string
	}{
		{"task.request", `forbid(principal, action == Action::"task.request", resource);`},
		{"task.approve", `forbid(principal, action == Action::"task.approve", resource);`},
	} {
		t.Run("a forbid on "+forbidden.action+" fails the task closed", func(t *testing.T) {
			f := newHTTPFixture(t, fixtureOptions{})
			cookie := f.login(requester)
			sessionID := f.openEditorSession(requester, cookie)
			f.fx.AddCedarPolicy("forbid-"+strings.ReplaceAll(forbidden.action, ".", "-"), forbidden.policy)

			before := f.taskCount()
			rec := f.post("/api/editor/sessions/"+sessionID+"/query", map[string]any{"sql": "SELECT id FROM users"}, cookie)

			assertStatus(t, rec, http.StatusForbidden, "submit under a "+forbidden.action+" forbid")
			assertCode(t, rec, "common.forbidden")
			if after := f.taskCount(); after != before {
				t.Errorf("INV-A7-17: %d task rows were created despite the refusal", after-before)
			}
			if len(f.RunExec.sessionRuns) != 0 {
				t.Error("INV-A7-17: the query ran despite the refusal")
			}
		})
	}
}

func (f *httpFixture) taskCount() int64 {
	f.t.Helper()
	var n int64
	if err := f.fx.Store.Pool.QueryRow(context.Background(), `SELECT count(*) FROM access_request`).Scan(&n); err != nil {
		f.t.Fatalf("count tasks: %v", err)
	}
	return n
}

// ⚠️ authDebug SHORT-CIRCUITS the self-approve gate — `!config.authDebug && !autoApproveTask(...)` —
// so Cedar is never reached rather than being asked and ignored (INV-A2-16's distinction). The forbid
// below would refuse every submit in production; under authDebug the task is still born.
func TestAuthDebugShortCircuitsTheEditorSelfApproveGate(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{AuthDebug: true})
	sessionID := f.openEditorSession(DebugPrincipal, nil)
	f.fx.Seed.AssignRole(DebugPrincipal, f.roleID(dbtest.FixtureRole))
	f.fx.AddCedarPolicy("forbid-everything", `forbid(principal, action, resource);`)

	rec := f.post("/api/editor/sessions/"+sessionID+"/query", map[string]any{"sql": "SELECT id FROM users"}, nil)

	assertStatus(t, rec, http.StatusAccepted, "submit under authDebug with a blanket forbid")
}

// ---------------------------------------------------------------------------------------------
// The read paths' gate layering — 🔒 INV-A6-25 and 🔒 INV-A6-26.
// ---------------------------------------------------------------------------------------------

// seedEditorTaskWithResult creates a DONE editor task owned by principal.
//
// ⚠️ `sql` must be the statement whose LIVE decision yields exactly `columns`, because the view
// re-decides it and gate 5 (INV-A7-14) denies on any output-column drift. A helper that hardcoded the
// SQL would make every view test a drift test by accident.
func (f *httpFixture) seedEditorTaskWithResult(principal, sql string, columns []string, rows [][]*string) int64 {
	f.t.Helper()
	ctx := context.Background()
	task, err := f.Access.CreateEditorTask(ctx, principal, f.fx.DatasourceID, sql,
		[]string{dbtest.FixtureRole}, principal)
	if err != nil {
		f.t.Fatalf("seed editor task: %v", err)
	}
	f.storeResult(task.ID, principal, columns, rows)
	return task.ID
}

// 🔒 INV-A6-26, DIRECTION 1 — THE OWNER GUARD IS NOT A SUBSTITUTE FOR CEDAR.
//
// A `task.read` forbid must still 404 the OWNER's own poll: a Cedar forbid (an untrusted zone, say)
// overrides the self-read permit. Without the Cedar gate the owner guard alone would answer 200.
func TestACedarForbidOverridesTheEditorOwnersSelfReadPermit(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	taskID := f.seedEditorTaskWithResult(requester, "SELECT id FROM users", []string{"id"}, [][]*string{{strptr("1")}})
	cookie := f.login(requester)

	assertStatus(t, f.get(idPath("/api/editor/tasks/", taskID, ""), cookie), http.StatusOK, "poll before the forbid")

	f.fx.AddCedarPolicy("forbid-task-read", `forbid(principal, action == Action::"task.read", resource);`)

	rec := f.get(idPath("/api/editor/tasks/", taskID, ""), cookie)
	assertStatus(t, rec, http.StatusNotFound, "poll under a task.read forbid")
	assertCode(t, rec, "common.not_found")
}

// 🔒 INV-A6-26, DIRECTION 2 — CEDAR IS NOT A SUBSTITUTE FOR THE OWNER GUARD.
//
// V8 -22 grants `system:auditor` `task.assume` on ANY Request, so Cedar alone would let an auditor
// read another user's editor rows. The frozen contract forbids that, and the owner guard is what
// enforces it — the auditor gets the same opaque 404 as a stranger.
func TestATaskAssumeGranteeStillCannotReadAnotherUsersEditorRows(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	const auditor = "auditor@example.com"
	f.fx.Seed.AssignRole(auditor, f.roleID("system:auditor"))
	const secret = "900101-1234567"
	taskID := f.seedEditorTaskWithResult(requester, "SELECT rrn FROM users", []string{"rrn"}, [][]*string{{strptr(secret)}})

	// The owner can read them, so the 404 below is attributable to the OWNER guard and not to a
	// broken fixture.
	own := f.get(idPath("/api/editor/tasks/", taskID, "/result"), f.login(requester))
	assertStatus(t, own, http.StatusOK, "the owner reads their own editor rows")

	rec := f.get(idPath("/api/editor/tasks/", taskID, "/result"), f.login(auditor))
	assertStatus(t, rec, http.StatusNotFound, "an auditor reading another user's editor rows")
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("the frozen contract was broken: %s", rec.Body.String())
	}
}

// 🔒 INV-A6-25 — THE EDITOR RESULT ROUTE HAS NO authDebug BYPASS on its `task.assume` gate, while the
// metadata poll's `task.read` gate DOES bypass.
//
// Both requests run on the SAME authDebug fixture, as the SAME owner, under the SAME blanket forbid.
// The poll 200s (bypassed) and the result 404s (not bypassed) — one fixture, two answers, which is
// what makes the asymmetry the subject rather than a side effect.
func TestUnderAuthDebugTheEditorMetadataGateBypassesButTheRowGateDoesNot(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{AuthDebug: true})
	const secret = "900101-1234567"
	taskID := f.seedEditorTaskWithResult(DebugPrincipal, "SELECT rrn FROM users", []string{"rrn"}, [][]*string{{strptr(secret)}})
	f.fx.AddCedarPolicy("forbid-task-assume", `forbid(principal, action == Action::"task.assume", resource);`)

	poll := f.get(idPath("/api/editor/tasks/", taskID, ""))
	assertStatus(t, poll, http.StatusOK, "the metadata poll under authDebug")

	rows := f.get(idPath("/api/editor/tasks/", taskID, "/result"))
	assertStatus(t, rows, http.StatusNotFound, "the row read under authDebug")
	if strings.Contains(rows.Body.String(), secret) {
		t.Fatalf("INV-A6-25: authDebug bypassed the row gate; body = %s", rows.Body.String())
	}
}

// 🔒 INV-A6-27 — the response's `decision` is derived SERVER-SIDE from whether the view actually
// masked anything. `SELECT rrn FROM users` under `analyst` is a MASK, so the label must be MASK and
// `maskedColumns` must name the column — the console labels its result from exactly this.
func TestTheEditorResultLabelsItselfMaskWhenTheViewMasked(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	ctx := context.Background()
	task, err := f.Access.CreateEditorTask(ctx, requester, f.fx.DatasourceID, "SELECT rrn FROM users",
		[]string{dbtest.FixtureRole}, requester)
	if err != nil {
		t.Fatalf("seed editor task: %v", err)
	}
	// The stored bytes are what an execution under {analyst} would have produced — already masked by
	// the proxy. The VIEW re-masks them, and the label describes the view.
	f.storeResult(task.ID, requester, []string{"rrn"}, [][]*string{{strptr("**********4567")}})

	rec := f.get(idPath("/api/editor/tasks/", task.ID, "/result"), f.login(requester))
	assertStatus(t, rec, http.StatusOK, "editor result")

	var view QueryResultView
	decodeJSON(t, rec, &view)
	if view.Decision != "MASK" {
		t.Errorf("decision: got %q, want MASK (the view masked %v)", view.Decision, view.MaskedColumns)
	}
	if len(view.MaskedColumns) != 1 || view.MaskedColumns[0] != "rrn" {
		t.Errorf("maskedColumns: got %v, want [rrn]", view.MaskedColumns)
	}
}

// Delete-on-close is owner-scoped, EDITOR-only and an IDEMPOTENT 204 — so it is not an existence
// oracle. The three sub-cases are the three ways it must NOT delete.
func TestEditorTaskDeleteIsOwnerScopedAndIdempotent(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	taskID := f.seedEditorTaskWithResult(requester, "SELECT id FROM users", []string{"id"}, [][]*string{{strptr("1")}})
	workflow := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)

	t.Run("a non-owner deletes nothing and still gets 204", func(t *testing.T) {
		rec := f.do(http.MethodDelete, idPath("/api/editor/tasks/", taskID, ""), nil, f.login(outsider))
		assertStatus(t, rec, http.StatusNoContent, "delete as a non-owner")
		if f.getRequest(taskID) == nil {
			t.Fatal("a non-owner deleted another principal's editor task")
		}
	})

	t.Run("a WORKFLOW task is never deleted through the editor route", func(t *testing.T) {
		rec := f.do(http.MethodDelete, idPath("/api/editor/tasks/", workflow.ID, ""), nil, f.login(requester))
		assertStatus(t, rec, http.StatusNoContent, "delete a workflow task")
		if f.getRequest(workflow.ID) == nil {
			t.Fatal("the editor delete removed a WORKFLOW approval")
		}
	})

	t.Run("the owner deletes it, and a second delete is still 204", func(t *testing.T) {
		cookie := f.login(requester)
		assertStatus(t, f.do(http.MethodDelete, idPath("/api/editor/tasks/", taskID, ""), nil, cookie),
			http.StatusNoContent, "delete as the owner")
		if f.getRequest(taskID) != nil {
			t.Fatal("the owner's delete left the task behind")
		}
		assertStatus(t, f.do(http.MethodDelete, idPath("/api/editor/tasks/", taskID, ""), nil, cookie),
			http.StatusNoContent, "second delete")
	})
}

// 🔒 Closing a session is owner-scoped through RunExec, and an idempotent 204 either way — a
// principal who learns another user's sessionId cannot tear down that connection.
func TestClosingAnEditorSessionIsOwnerScopedAndIdempotent(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	cookie := f.login(requester)
	sessionID := f.openEditorSession(requester, cookie)

	byOutsider := f.do(http.MethodDelete, "/api/editor/sessions/"+sessionID, nil, f.login(outsider))
	assertStatus(t, byOutsider, http.StatusNoContent, "close by a non-owner")
	if _, stillOpen := f.RunExec.SessionDatasourceName(sessionID, requester); !stillOpen {
		t.Fatal("a non-owner tore down another principal's held connection")
	}

	byOwner := f.do(http.MethodDelete, "/api/editor/sessions/"+sessionID, nil, cookie)
	assertStatus(t, byOwner, http.StatusNoContent, "close by the owner")
	if _, stillOpen := f.RunExec.SessionDatasourceName(sessionID, requester); stillOpen {
		t.Fatal("the owner's close did not release the session")
	}
	assertStatus(t, f.do(http.MethodDelete, "/api/editor/sessions/"+sessionID, nil, cookie),
		http.StatusNoContent, "second close")
}

// The transport exception → status mapping, 🔒 including INV-A7-34's requirement that
// NoProxyAttached and StreamWedged stay DISTINCT.
func TestOpenSessionMapsEveryTransportFailureToItsOwnStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
		detail string
	}{
		{"no proxy attached", ErrNoProxyAttached, http.StatusServiceUnavailable, "query.no_proxy_attached", ""},
		{"stream wedged", ErrProxyStreamWedged, http.StatusServiceUnavailable, "query.proxy_stream_wedged", ""},
		{"dial timeout", ErrProxyRunTimeout, http.StatusGatewayTimeout, "query.proxy_timeout", ""},
		{"run failure", &ProxyRunError{Message: "backend refused"}, http.StatusBadGateway, "query.failed", "backend refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHTTPFixture(t, fixtureOptions{})
			f.RunExec.openErr = tc.err

			rec := f.post("/api/editor/sessions", map[string]any{"datasourceId": f.fx.DatasourceID}, f.login(requester))

			assertStatus(t, rec, tc.status, tc.name)
			assertCode(t, rec, tc.code)
			if tc.detail != "" && !strings.Contains(rec.Body.String(), tc.detail) {
				t.Errorf("detail %q is absent from %s", tc.detail, rec.Body.String())
			}
		})
	}
}
