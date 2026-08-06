package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// KOTLIN CASES THIS PACKAGE'S OTHER SUITES DO NOT ASSERT.
//
// Every test here closes a hole the traceability checker (internal/tracing) found: a Kotlin @Test in
// EditorSelfApproveAuthzDbTest, ApprovalExecuteRouteDbTest, ApprovalDiscoverPickSubmitRouteDbTest,
// ApprovalResultViewContextDbTest or ElevationContextRouteAuthzDbTest with no Go test asserting the
// same property. Each carries its traceability marker, and each is written against what the KOTLIN
// asserts — including where the Kotlin's mechanism differs, which the marker's note then states.
// ---------------------------------------------------------------------------------------------

const (
	// alice / bob are EditorSelfApproveAuthzDbTest's two principals: neither holds any role, which is
	// what makes "non-admin self-approve" the claim under test rather than the admin grant.
	alice = "alice@example.com"
	bob   = "bob@example.com"
)

// selfApproveDecision is the Kotlin's private `approveSelf(principal, requester, channel)`: a DIRECT
// `task.approve` query for principal approving `requester`'s request, on the given channel. A nil
// channel is an ordinary human approval (no server attestation).
func (f *httpFixture) selfApproveDecision(principal, requester string, channel *string) authz.AuthzDecision {
	f.t.Helper()
	ds := f.fx.DatasourceRow
	name := ds.Name
	approver := principal
	return f.fx.Authz.AuthorizeWithContext(
		principal, authz.ActionTaskApprove,
		authz.ResourceApprovalRequest{Requester: requester, Approver: &approver, DatasourceName: &name},
		authz.AuthzContext{Channel: channel}, &name, ds.Tags,
	)
}

func channelValue(c query.Channel) *string {
	v := c.ContextValue()
	return &v
}

// `EditorSelfApproveAuthzDbTest` — all four cases, against the REAL migrated Cedar policy set.
//
// 🔒 The four together are one claim with four edges: the two SERVER-ATTESTED channels (editor, wire)
// may self-approve, and nothing else about that permit is loose — not the channel (case 2), and not
// the identity pairing (case 3). Dropping any one of them would leave a permit that reads as narrow
// while admitting either an unattested approval or a cross-user one.
func TestEditorAndWireSelfApproveAgainstTheShippedPolicySet(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})

	// KT: EditorSelfApproveAuthzDbTest.kt#autoApproveTask allows non-admin self-approve on server-attested channels
	t.Run("autoApproveTask allows non-admin self-approve on server-attested channels", func(t *testing.T) {
		// The PRODUCTION autoApproveTask (internal/core), over the fixture's real Cedar engine. It reads
		// nothing but Authz, so a struct literal is the whole dependency — and it is the real function,
		// not the fixture's inlined copy in support_db_test.go.
		gate := &core.ControlPlaneCore{Authz: f.fx.Authz}
		for _, channel := range []query.Channel{query.ChannelEditor, query.ChannelWire} {
			if !gate.AutoApproveTask(alice, nil, f.fx.DatasourceRow, authz.AuthzContext{}, channel) {
				t.Errorf("autoApproveTask on %s: got false, want true (a non-admin may self-approve on a "+
					"server-attested channel)", channel)
			}
		}
	})

	// KT: EditorSelfApproveAuthzDbTest.kt#self-approve is explicitly allowed on editor and wire
	t.Run("self-approve is explicitly allowed on editor and wire", func(t *testing.T) {
		for _, channel := range []query.Channel{query.ChannelEditor, query.ChannelWire} {
			if d := f.selfApproveDecision(alice, alice, channelValue(channel)); !d.Allowed {
				t.Errorf("task.approve self on %s: got DENY (%v), want a permit", channel, d.Reason)
			}
		}
	})

	// 🔒 Case 3 — the permit is scoped to the CHANNEL, so an ordinary human approval (no channel) and
	// the workflow-executor channel stay denied by the shipped `no-self-approval` forbid.
	// KT: EditorSelfApproveAuthzDbTest.kt#self-approve stays denied outside editor and wire
	t.Run("self-approve stays denied outside editor and wire", func(t *testing.T) {
		if d := f.selfApproveDecision(alice, alice, nil); d.Allowed {
			t.Error("task.approve self with NO channel was allowed — an unattested self-approval")
		}
		if d := f.selfApproveDecision(alice, alice, channelValue(query.ChannelWorkflowExecutor)); d.Allowed {
			t.Error("task.approve self on workflow-executor was allowed — only editor and wire are attested")
		}
	})

	// 🔒 Case 4 — THE SERVER-ATTESTED CHANNEL IS NOT A BLANKET APPROVE PERMIT. The channel only ever
	// licenses approving one's OWN request; alice on the editor channel must not be able to approve
	// bob's.
	// KT: EditorSelfApproveAuthzDbTest.kt#server-attested channel permits do not open cross-user approval
	t.Run("server-attested channel permits do not open cross-user approval", func(t *testing.T) {
		for _, channel := range []query.Channel{query.ChannelEditor, query.ChannelWire} {
			if d := f.selfApproveDecision(alice, bob, channelValue(channel)); d.Allowed {
				t.Errorf("alice approved BOB's request on %s — the attested channel opened cross-user "+
					"approval", channel)
			}
		}
	})
}

// ---------------------------------------------------------------------------------------------
// `ApprovalExecuteRouteDbTest` — the two cases the execute/cancel suites do not reach.
// ---------------------------------------------------------------------------------------------

// 🔒 V8 -25 (`task.cancel-parties`) — THE REQUESTER MAY CANCEL THEIR OWN IN-FLIGHT RUN, AND AN
// UNRELATED PRINCIPAL MAY NOT — with NO control message sent for the refusal.
//
// The pair is the test. A port that asked `task.approve` here instead of `task.cancel` would still
// let the approver cancel, so only the REQUESTER half distinguishes the right gate; and only the
// unrelated half proves the gate is asked at all. The `cancels` assertion is the third claim the
// Kotlin's title makes ("without sending control"): a refusal that reached the transport would have
// killed a legitimate run before answering 403.
//
// KT: ApprovalExecuteRouteDbTest.kt#V46 allows the requester to cancel and denies an unrelated principal without sending control
func TestTheRequesterMayCancelAndAnUnrelatedPrincipalMayNotWithoutSendingControl(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	const unrelated = "cancel-unrelated@example.com"

	task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
	f.approveTask(task.ID, approver)
	if _, err := f.Results.ClaimAndStartRun(context.Background(), task.ID, approver, claimVia(f, task.ID)); err != nil {
		t.Fatalf("claim: %v", err)
	}

	denied := f.post(idPath("/api/approvals/", task.ID, "/cancel"), nil, f.login(unrelated))
	assertStatus(t, denied, http.StatusForbidden, "cancel by an unrelated principal")
	assertCode(t, denied, "approval.cancel_forbidden")
	if got := f.getRequest(task.ID).Status; got != "EXECUTING" {
		t.Errorf("status after a refused cancel: got %q, want EXECUTING", got)
	}
	if len(f.RunExec.cancels) != 0 {
		t.Errorf("a REFUSED cancel reached the transport (%v) — the run would have been killed anyway",
			f.RunExec.cancels)
	}

	allowed := f.post(idPath("/api/approvals/", task.ID, "/cancel"), nil, f.login(requester))
	assertStatus(t, allowed, http.StatusOK, "cancel by the requester")
	var out access.AccessRequest
	decodeJSON(t, allowed, &out)
	if out.Status != "CANCELLED" {
		t.Errorf("status: got %q, want CANCELLED", out.Status)
	}
}

// Cancel on an EXECUTED task is an IDEMPOTENT 200 carrying the task unchanged — not a 409 and not a
// second terminal transition. This is the exact shape the Kotlin case uses (EXECUTED, then PENDING);
// TestCancelIsIdempotentTerminalRefusesPreExecutionAndTerminalizesAnExecutingRun covers the PENDING
// 409 and the post-CANCELLED idempotent 200.
//
// KT: ApprovalExecuteRouteDbTest.kt#cancel is idempotent after execution and rejects pending tasks — the EXECUTED half
func TestCancelOnAnExecutedTaskIs200WithTheTaskUnchanged(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
	f.approveTask(task.ID, approver)
	f.storeResult(task.ID, approver, []string{"id"}, [][]*string{{strptr("1")}})

	rec := f.post(idPath("/api/approvals/", task.ID, "/cancel"), nil, f.login(requester))

	assertStatus(t, rec, http.StatusOK, "cancel an EXECUTED task")
	var out access.AccessRequest
	decodeJSON(t, rec, &out)
	if out.Status != "EXECUTED" {
		t.Errorf("status: got %q, want EXECUTED — the idempotent answer carries the task unchanged", out.Status)
	}
	if len(f.RunExec.cancels) != 0 {
		t.Errorf("a terminal task's cancel reached the transport: %v", f.RunExec.cancels)
	}
}

// ---------------------------------------------------------------------------------------------
// `ApprovalDiscoverPickSubmitRouteDbTest` — the route-level field mapping and the union trap.
// ---------------------------------------------------------------------------------------------

// 🔒 THE ROUTE NAMES THE ACTUALLY-MISSING FIELD, for EVERY field reachable at the gate.
//
// The Kotlin parameterizes over all three HTTP-reachable branches for one stated reason: a hardcoded
// `fieldRequired("title")` passes a title-only test. `reason` is checked EARLIER and never reaches
// validateProactiveCompose, which is why it is not in the table.
//
// KT: ApprovalDiscoverPickSubmitRouteDbTest.kt#a proactive compose missing a required field returns common field_required naming that field
func TestTheProactiveComposeRouteNamesEveryReachableMissingField(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	cookie := f.login(requester)
	const sql = "SELECT id, rrn FROM users"

	for _, test := range []struct {
		want string
		body map[string]any
	}{
		// datasourceId absent, sql present ⇒ still the proactive branch ⇒ "datasourceId".
		{"datasourceId", map[string]any{"sql": sql, "title": "need it", "reason": "investigating"}},
		// datasourceId present ⇒ proactive branch; sql absent ⇒ "sql".
		{"sql", map[string]any{"datasourceId": f.fx.DatasourceID, "title": "need it", "reason": "investigating"}},
		// both present, title BLANK (whitespace, as the Kotlin has it) ⇒ "title".
		{"title", map[string]any{"datasourceId": f.fx.DatasourceID, "sql": sql, "title": "  ", "reason": "investigating"}},
	} {
		t.Run(test.want, func(t *testing.T) {
			rec := f.post("/api/approvals", test.body, cookie)
			assertStatus(t, rec, http.StatusBadRequest, "blanking "+test.want)
			assertCode(t, rec, "common.field_required")
			var body types.ApiError
			decodeJSON(t, rec, &body)
			if body.Params["fields"] != test.want {
				t.Errorf("fields: got %q, want %q — the response must name the actually-missing field",
					body.Params["fields"], test.want)
			}
		})
	}
}

// 🔒 INV-A7-12 AT THE ROUTE, AND THE PICK ROUND TRIP — the case the pure suite cannot state.
//
// The fixture is built so the UNION and the R-ALONE previews genuinely diverge, exactly as the
// Kotlin's does:
//
//   - the requester already holds `analyst`, which runs the query with `rrn` MASKED — so the baseline
//     is a real masked ALLOW, not a stub;
//   - `full-reader` unmasks `rrn` ON ITS OWN ⇒ offered under either preview model (the positive
//     control, and the role the pick then carries);
//   - `unmask-only` unmasks `rrn` but grants NO datasource.connect / sql.select, so ALONE it DENIES
//     while `{analyst, unmask-only}` would connect via analyst and unmask. A unioned preview offers
//     it; R-alone must not.
//
// Without an own-role fixture `ownRoles ∪ {R} == {R}` and the two implementations are
// indistinguishable — which is why this cannot be asserted on the no-roles path.
//
// The tail is the other half of the Kotlin's title: the picked roleId is carried onto the created
// request AND is readable back from the store, so a pick that was dropped between the two POSTs
// fails here rather than at execute time.
//
// KT: ApprovalDiscoverPickSubmitRouteDbTest.kt#discover offers full-reader (R-alone) not unmask-only (union trap), pick it, submit carries roleId
func TestDiscoverRefusesTheUnionTrapAndCarriesThePickOntoTheSubmittedRequest(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	users := f.fx.UsersTableEUID()
	const sql = "SELECT id, rrn FROM users"

	f.fx.Seed.Role("full-reader")
	f.fx.AddCedarPolicy("union-full-reader-connect-select",
		`permit(principal in Role::"full-reader", action in [Action::"datasource.connect", Action::"sql.select"], resource in Datasource::"`+
			f.fx.DatasourceName+`");`)
	f.fx.AddCedarPolicy("union-full-reader-unmasked",
		`permit(principal in Role::"full-reader", action == Action::"result.read.unmasked", resource in Table::"`+users+`");`)

	// THE TRAP: unmask-only can read every users column but cannot connect or select.
	f.fx.Seed.Role("unmask-only")
	f.fx.AddCedarPolicy("union-unmask-only-unmasked",
		`permit(principal in Role::"unmask-only", action == Action::"result.read.unmasked", resource in Table::"`+users+`");`)

	cookie := f.login(requester)
	rec := f.post("/api/approvals/discover-roles",
		map[string]any{"datasourceId": f.fx.DatasourceID, "sql": sql}, cookie)
	assertStatus(t, rec, http.StatusOK, "discover-roles")

	var discovered DiscoverRolesResponse
	decodeJSON(t, rec, &discovered)
	if !discovered.BaselineAllowed {
		t.Fatal("the requester holds analyst, which runs the query with rrn masked — the baseline is a masked ALLOW")
	}
	var fullReader *RoleOption
	for i := range discovered.Options {
		switch discovered.Options[i].RoleName {
		case "full-reader":
			fullReader = &discovered.Options[i]
		case "unmask-only":
			t.Errorf("INV-A7-12: `unmask-only` DENIES previewed ALONE (no connect/select) and must NOT be "+
				"offered; a UNIONED preview is the only way it appears. Options: %#v", discovered.Options)
		}
	}
	if fullReader == nil {
		t.Fatalf("full-reader unmasks rrn on its own and must be offered; options = %#v", discovered.Options)
	}
	// The Kotlin picks it with `singleOrNull { roleName == "full-reader" }`, so a duplicated option is a
	// failure there too: the console renders one row per option and would offer the same elevation twice.
	fullReaderCount := 0
	for i := range discovered.Options {
		if discovered.Options[i].RoleName == "full-reader" {
			fullReaderCount++
		}
	}
	if fullReaderCount != 1 {
		t.Errorf("full-reader appears %d times in the options, want exactly 1", fullReaderCount)
	}
	if len(fullReader.UnmasksColumns) != 1 || fullReader.UnmasksColumns[0] != "rrn" {
		t.Errorf("unmasksColumns: got %v, want [rrn]", fullReader.UnmasksColumns)
	}

	// PICK IT, THEN SUBMIT: the roleId must survive onto the created request and into the store.
	submitted := f.post("/api/approvals", map[string]any{
		"datasourceId": f.fx.DatasourceID, "sql": sql, "title": "need rrn",
		"reason": "investigating an incident", "roleId": fullReader.RoleID,
	}, cookie)
	assertStatus(t, submitted, http.StatusCreated, "submit the picked role")

	var created CreateApprovalResponse
	decodeJSON(t, submitted, &created)
	if created.Request.RoleID == nil || *created.Request.RoleID != fullReader.RoleID {
		t.Errorf("roleId on the created request: got %v, want the picked %d",
			created.Request.RoleID, fullReader.RoleID)
	}
	if created.Request.RoleName == nil || *created.Request.RoleName != "full-reader" {
		t.Errorf("roleName: got %v, want full-reader", created.Request.RoleName)
	}
	stored := f.getRequest(created.Request.ID)
	if stored == nil {
		t.Fatal("the created request must be readable back from the store")
	}
	if stored.RoleID == nil || *stored.RoleID != fullReader.RoleID {
		t.Errorf("the STORED roleId is %v, want the picked %d", stored.RoleID, fullReader.RoleID)
	}
	if len(stored.ExecuteAs) != 1 || stored.ExecuteAs[0] != "full-reader" {
		t.Errorf("executeAs: got %v, want [full-reader] — execute-under-R runs the picked role alone",
			stored.ExecuteAs)
	}
}

// notInBody fails when the response body contains a sentinel value, reading the RAW bytes rather
// than a decoded field so a partial write is caught too.
func notInBody(t *testing.T, body, sentinel, what string) {
	t.Helper()
	if strings.Contains(body, sentinel) {
		t.Fatalf("%s: the stored value leaked into the response; body = %s", what, body)
	}
}

// ---------------------------------------------------------------------------------------------
// GET /{id}/result — `ApprovalResultViewContextDbTest`'s ROUTE-level claims.
//
// internal/approval's viewdecision_test.go drives the seven gates directly, which is the only way to
// reach gates 5-7 at all; what it cannot state is how the route ANSWERS a denied view. That is what
// the Kotlin cases assert, and it is a separate claim: a port that mapped a view deny to 200-with-no-
// rows, or that echoed the decision's prose (with the values in it), would pass every gate test.
// ---------------------------------------------------------------------------------------------

// trustedTestEdgeIP is the socket peer httptest.NewRequest reports, and the SOLE trusted edge in the
// tests below — so ONLY an X-Forwarded-For appended behind it is honored as requester_ip.
const trustedTestEdgeIP = "192.0.2.1"

// trustTheTestEdge plugs A12's request-context derivation into the PRODUCTION seam
// ([httpapi.Gates.Context]), which the fixture leaves nil (fail-closed empty context).
//
// 🔒 IT REUSES [httpapi.IsTrustedEdge] RATHER THAN REIMPLEMENTING THE PEER TEST, for the reason
// internal/access's identical stand-in gives: "a second hand-rolled copy of this test is how a header
// ends up honored from an untrusted peer", and a fixture is not exempt. The untrusted-peer half of the
// rule is therefore the production function's, so this cannot be laxer than the real thing.
//
//	TODO(A12): delete this and point Gates.Context at the real httpAuthzContext.
func (f *httpFixture) trustTheTestEdge() {
	trusted := map[string]struct{}{trustedTestEdgeIP: {}}
	f.Gates.Context = func(r *http.Request) authz.AuthzContext {
		peer, present := httpapi.RequestPeer(r)
		if !httpapi.IsTrustedEdge(peer, present, trusted) {
			return authz.AuthzContext{}
		}
		xff := httpapi.LastHeader(r, "X-Forwarded-For")
		if xff == nil || *xff == "" {
			return authz.AuthzContext{}
		}
		return authz.AuthzContext{RequesterIP: xff}
	}
}

// with is [httpFixture.do] plus request headers, which the fixture's helpers do not carry.
func (f *httpFixture) with(
	method, target string, body any, headers map[string]string, cookie *http.Cookie,
) *httptest.ResponseRecorder {
	f.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			f.t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, target, reader)
	r.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	return rec
}

// ciphertext reads the child's stored bytes, so a test can prove a view did not REWRITE storage.
func (f *httpFixture) ciphertext(taskID int64) []byte {
	f.t.Helper()
	var out []byte
	if err := f.fx.Store.Pool.QueryRow(context.Background(),
		`SELECT ciphertext FROM query_result WHERE task_id = $1`, taskID).Scan(&out); err != nil {
		f.t.Fatalf("read ciphertext for %d: %v", taskID, err)
	}
	return out
}

// setPolicyEnabled toggles a seeded Cedar policy and bumps the state version, which is what makes the
// already-built engine rebuild its policy set (INV-A2-19).
func (f *httpFixture) setPolicyEnabled(name string, enabled bool) {
	f.t.Helper()
	tag, err := f.fx.Store.Pool.Exec(context.Background(),
		`UPDATE policy SET enabled = $2 WHERE name = $1`, name, enabled)
	if err != nil {
		f.t.Fatalf("set enabled=%v on policy %s: %v", enabled, name, err)
	}
	if tag.RowsAffected() != 1 {
		f.t.Fatalf("set enabled=%v on policy %s: %d rows matched, want 1", enabled, name, tag.RowsAffected())
	}
	f.fx.PolicyStore.Bump()
}

// storedRawRRN seeds a task whose stored child holds CLEARTEXT rrn — an execution that ran where it
// could unmask. The Kotlin's fixture does the same thing for the same reason: a snapshot-as-is view
// path then fails the context/revocation/DENY/drift cases with OBSERVABLE cleartext rather than
// silently passing.
func (f *httpFixture) storedRawRRN(sql string) access.AccessRequest {
	f.t.Helper()
	task := f.seedWorkflowTask(requester, sql, dbtest.FixtureRole)
	f.approveTask(task.ID, approver)
	f.storeResult(task.ID, approver, []string{"id", "rrn"},
		[][]*string{{strptr("1"), strptr(dbtest.FixtureCleartextRRN[0])}})
	return task
}

// maskedRRN is `last4` (kind LAST_N) applied to the fixture's first cleartext rrn.
const maskedRRN = "**********4567"

// 🔒 EVERY UNCERTAINTY IS A 403 `approval.result_view_denied` THAT RELEASES NO STORED VALUE.
//
// Four distinct leak paths, one shape: the stored row carries a SENTINEL the response must never
// contain, and each sub-case makes the live re-decision disagree with the stored bytes in a different
// way. The sentinel assertion is on the RAW body, so a port that put the deny REASON (which quotes
// column names) or a partially rebound row on the wire fails here.
//
// Each sub-case starts by asserting its PREMISE through the real pipeline — that the live decision
// really is a passthrough / a DENY — because otherwise a sub-case could reach the right 403 through
// the wrong gate and still look green.
func TestTheResultViewDeniesEveryUncertaintyWith403AndReleasesNoStoredValue(t *testing.T) {
	// KT: ApprovalResultViewContextDbTest.kt#a stored query result that re-decides as passthrough is denied without sentinel data
	t.Run("a re-decision that comes back PASSTHROUGH is denied", func(t *testing.T) {
		f := newHTTPFixture(t, fixtureOptions{})
		f.withApprover()
		const sentinel = "LEAK-SENTINEL-PASSTHROUGH"
		task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
		f.approveTask(task.ID, approver)
		f.storeResult(task.ID, approver, []string{"search_path"}, [][]*string{{strptr(sentinel)}})
		// The stored child's own statement is what the view re-decides (INV-A7-9).
		f.overwriteChildSQL(task.ID, "SHOW search_path")

		// PREMISE: on WORKFLOW_VIEWER this statement really does re-decide as a passthrough. Without
		// this the sub-case could be reaching gate 3 (a DENY) and still see the same 403.
		premise := f.fx.DecideWith(query.DecideQueryInput{
			Principal: requester, SQL: "SHOW search_path", Channel: query.ChannelWorkflowViewer,
			ProvidedRoles: &[]string{dbtest.FixtureRole},
		})
		if !premise.Passthrough {
			t.Fatalf("premise broken: `SHOW search_path` did not re-decide as a passthrough (action=%v, "+
				"passthrough=%v) — this sub-case is no longer about gate 4", premise.Action, premise.Passthrough)
		}

		rec := f.get(idPath("/api/approvals/", task.ID, "/result"), f.login(requester))
		assertStatus(t, rec, http.StatusForbidden, "a passthrough re-decision")
		assertCode(t, rec, "approval.result_view_denied")
		notInBody(t, rec.Body.String(), sentinel, "a passthrough decision must never release stored values")
	})

	// KT: ApprovalResultViewContextDbTest.kt#a live DENY on an ungranted table returns 403 without stored sentinel data
	t.Run("a live DENY on an ungranted table is denied", func(t *testing.T) {
		f := newHTTPFixture(t, fixtureOptions{})
		f.withApprover()
		const sentinel = "LEAK-SENTINEL-777"
		task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
		f.approveTask(task.ID, approver)
		f.storeResult(task.ID, approver, []string{"id", "amount"}, [][]*string{{strptr("1"), strptr(sentinel)}})
		// `orders` is UNGRANTED in the fixture: no Cedar grant covers it, so a touched column there
		// resolves to DENIED rather than falling through to cleartext.
		f.overwriteChildSQL(task.ID, "SELECT id, amount FROM orders")

		premise := f.fx.DecideWith(query.DecideQueryInput{
			Principal: requester, SQL: "SELECT id, amount FROM orders", Channel: query.ChannelWorkflowViewer,
			ProvidedRoles: &[]string{dbtest.FixtureRole},
		})
		if premise.Action != pb.EnfAction_DENY {
			t.Fatalf("premise broken: the ungranted table re-decided as %v, not DENY", premise.Action)
		}

		rec := f.get(idPath("/api/approvals/", task.ID, "/result"), f.login(requester))
		assertStatus(t, rec, http.StatusForbidden, "a live DENY")
		assertCode(t, rec, "approval.result_view_denied")
		notInBody(t, rec.Body.String(), sentinel, "a denied live decision must not echo stored values")
	})

	// 🔒 INV-A7-14 — output-column drift. The stored payload has FEWER columns than the live decision
	// returns, which is what a `SELECT *` re-expansion between execute and view looks like; binding a
	// mask positionally against it would slide the mask onto the wrong column and leak a value.
	// KT: ApprovalResultViewContextDbTest.kt#output-column drift fails closed before any partially matched row is returned
	t.Run("output-column drift fails closed before any partially matched row is returned", func(t *testing.T) {
		f := newHTTPFixture(t, fixtureOptions{})
		f.withApprover()
		const sentinel = "LEAK-SENTINEL-DRIFT"
		task := f.seedWorkflowTask(requester, "SELECT id, email, rrn FROM users", dbtest.FixtureRole)
		f.approveTask(task.ID, approver)
		// Stored: TWO columns. Live: three, because the child's statement selects three.
		f.storeResult(task.ID, approver, []string{"id", "email"}, [][]*string{{strptr("1"), strptr(sentinel)}})

		rec := f.get(idPath("/api/approvals/", task.ID, "/result"), f.login(requester))
		assertStatus(t, rec, http.StatusForbidden, "output-column drift")
		assertCode(t, rec, "approval.result_view_denied")
		notInBody(t, rec.Body.String(), sentinel, "catalog drift must not return a partially rebound row")
	})

	// Gate 6 — a stored row WIDER than its own columns. Releasing it would hand back a value no
	// ordinal mask could ever have covered.
	// KT: ApprovalResultViewContextDbTest.kt#stored row-width drift fails closed instead of returning an unbound extra value
	t.Run("stored row-width drift fails closed instead of returning an unbound extra value", func(t *testing.T) {
		f := newHTTPFixture(t, fixtureOptions{})
		f.withApprover()
		const sentinel = "LEAK-SENTINEL-EXTRA-CELL"
		task := f.seedWorkflowTask(requester, "SELECT id, rrn FROM users", dbtest.FixtureRole)
		f.approveTask(task.ID, approver)
		f.storeResult(task.ID, approver, []string{"id", "rrn"},
			[][]*string{{strptr("1"), strptr(dbtest.FixtureCleartextRRN[0]), strptr(sentinel)}})

		rec := f.get(idPath("/api/approvals/", task.ID, "/result"), f.login(requester))
		assertStatus(t, rec, http.StatusForbidden, "stored row-width drift")
		assertCode(t, rec, "approval.result_view_denied")
		notInBody(t, rec.Body.String(), sentinel, "an extra stored cell must never bypass ordinal masking")
	})
}

// 🔒 A `system:admin` WHO IS NEITHER PARTY MAY NOT ASSUME R, so /result is a 404 for them even though
// the same principal reads the task's metadata happily.
//
// The admin grant covers task.approve / task.read / cancel / delete and NOT task.assume, and this is
// the half of that claim about ROWS rather than about the redacted shape
// (TestDetailRedactsResultShapeFromACallerWhoCannotAssumeR is the metadata half).
//
// KT: ApprovalResultViewContextDbTest.kt#approver and auditor assume R while admin sees metadata only — the "admin may not assume R" half: 404 on /result
func TestAnAdminWhoCannotAssumeRIsRefusedTheResultRows(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	const admin = "admin@example.com"
	f.fx.Seed.AssignRole(admin, f.roleID("system:admin"))

	task := f.seedWorkflowTask(requester, "SELECT id, rrn FROM users", dbtest.FixtureRole)
	f.approveTask(task.ID, approver)
	f.storeResult(task.ID, approver, []string{"id", "rrn"},
		[][]*string{{strptr("1"), strptr(dbtest.FixtureCleartextRRN[0])}})
	cookie := f.login(admin)

	// The positive control: the admin DOES reach the task, so the 404 below is the assume gate and not
	// an id or task.read refusal.
	assertStatus(t, f.get(idPath("/api/approvals/", task.ID, ""), cookie), http.StatusOK, "detail as admin")

	rec := f.get(idPath("/api/approvals/", task.ID, "/result"), cookie)
	assertStatus(t, rec, http.StatusNotFound, "result rows as an admin who cannot assume R")
	assertCode(t, rec, "common.not_found")
	notInBody(t, rec.Body.String(), dbtest.FixtureCleartextRRN[0], "the assume gate must return no stored PII")
}

// 🔒 THE DEACTIVATION GATE PRECEDES THE LIVE RESULT DECISION FOR THE EXECUTOR TOO — a deprovisioned
// approver-of-record is turned away with a 404 and no stored PII, exactly like any other viewer.
//
// The Kotlin states this separately from the requester case on purpose: the executor is the one
// principal whose own run produced the bytes, so a port that gated "viewers" but exempted whoever
// stored the row would pass the requester case and fail this one.
//
// KT: ApprovalResultViewContextDbTest.kt#a deactivated executor is hidden before any live result decision
func TestADeactivatedExecutorIsHiddenBeforeAnyLiveResultDecision(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	task := f.storedRawRRN("SELECT id, rrn FROM users")
	cookie := f.login(approver)

	// Positive control: while ACTIVE the executor reaches the rows, so the 404 below is the gate.
	assertStatus(t, f.get(idPath("/api/approvals/", task.ID, "/result"), cookie), http.StatusOK,
		"the active executor")

	f.fx.Seed.User(approver)
	f.fx.Seed.SetUserActive(approver, false)

	rec := f.get(idPath("/api/approvals/", task.ID, "/result"), cookie)
	assertStatus(t, rec, http.StatusNotFound, "the deactivated executor")
	assertCode(t, rec, "common.not_found")
	notInBody(t, rec.Body.String(), dbtest.FixtureCleartextRRN[0], "a deactivated viewer must receive no stored PII")
}

// 🔒 REVOKING THE LIVE UNMASK GRANT RE-MASKS THE NEXT VIEW AND CHANGES NO STORED BYTE.
//
// The pair of views is the claim: the first proves the grant really was what unmasked (so the second
// is not passing vacuously), and the ciphertext comparison proves the re-mask happened at VIEW time.
// A port that masked the stored payload on the way out — rewriting the row — would pass the response
// assertions and fail the storage one, having destroyed R's execution-enforced output.
//
// KT: ApprovalResultViewContextDbTest.kt#disabling the live unmask grant re-masks the next view without changing storage
func TestDisablingTheLiveUnmaskGrantReMasksTheNextViewWithoutChangingStorage(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	const grant = "view-analyst-unmask-pii"
	f.fx.AddCedarPolicy(grant,
		`permit(principal in Role::"`+dbtest.FixtureRole+`", action == Action::"result.read.unmasked", `+
			`resource in Table::"`+f.fx.UsersTableEUID()+`") when { resource in Tag::"pii" };`)

	task := f.storedRawRRN("SELECT id, rrn FROM users")
	storedBefore := f.ciphertext(task.ID)
	cookie := f.login(requester)

	raw := f.get(idPath("/api/approvals/", task.ID, "/result"), cookie)
	assertStatus(t, raw, http.StatusOK, "the view under the unmask grant")
	var unmasked QueryResultView
	decodeJSON(t, raw, &unmasked)
	if got := cell(t, unmasked, 0, 1); got != dbtest.FixtureCleartextRRN[0] {
		t.Fatalf("rrn under the unmask grant: got %q, want the cleartext %q", got, dbtest.FixtureCleartextRRN[0])
	}

	f.setPolicyEnabled(grant, false)

	remasked := f.get(idPath("/api/approvals/", task.ID, "/result"), cookie)
	assertStatus(t, remasked, http.StatusOK, "the view after the grant was revoked")
	var masked QueryResultView
	decodeJSON(t, remasked, &masked)
	if got := cell(t, masked, 0, 1); got != maskedRRN {
		t.Errorf("rrn after revocation: got %q, want the masked %q", got, maskedRRN)
	}
	if !bytes.Equal(storedBefore, f.ciphertext(task.ID)) {
		t.Error("policy revocation rewrote the stored ciphertext; it must affect only the live response")
	}
}

// cell reads one non-nil cell out of a view, failing rather than panicking on a short row.
func cell(t *testing.T, view QueryResultView, row, column int) string {
	t.Helper()
	if len(view.Rows) <= row || len(view.Rows[row]) <= column {
		t.Fatalf("view has no cell [%d][%d]: %#v", row, column, view.Rows)
	}
	value := view.Rows[row][column]
	if value == nil {
		t.Fatalf("cell [%d][%d] is NULL: %#v", row, column, view.Rows)
	}
	return *value
}

// 🔒 THE LIVE VIEW DECISION IS MADE FOR THE VIEWER, NOT FOR THE REQUESTER.
//
// The Kotlin states it with a requester-scoped forbid that must not apply to an executing viewer; this
// asserts the mechanism that makes that true — the principal decideQuery is called with. The two are
// the same claim, and this form also catches the case where the forbid happens not to match.
//
// KT: ApprovalResultViewContextDbTest.kt#the live decision uses the viewer principal rather than the requester identity
func TestTheLiveViewDecisionUsesTheViewerPrincipalNotTheRequesterIdentity(t *testing.T) {
	var asked []string
	d := &Decider{
		Datasources: stubDatasources{},
		Decide: func(_ context.Context, in query.DecideQueryInput) (query.DecisionContext, error) {
			asked = append(asked, in.Principal)
			return allowWithColumns("rrn"), nil
		},
	}
	in := viewInput(result.DecryptedResult{Columns: []string{"rrn"}, Rows: [][]*string{{strptr("x")}}})
	in.Viewer = "viewer@example.com"
	in.Req.Principal = "requester@example.com"

	got, err := d.DecideResultView(context.Background(), in)
	if err != nil {
		t.Fatalf("DecideResultView: %v", err)
	}
	if got.IsDenied() {
		t.Fatalf("unexpected deny: %q", *got.DeniedReason)
	}
	if len(asked) != 1 || asked[0] != in.Viewer {
		t.Errorf("the live decision was made for %v, want exactly [%s] — a requester-scoped policy must "+
			"never decide an executing viewer's view", asked, in.Viewer)
	}
}

// 🔒 THE SAME CLAIM BY THE KOTLIN'S OWN MECHANISM — a REQUESTER-SCOPED `forbid` through the real
// Cedar engine and the real route, not a stub decider.
//
// The unit test above pins the principal handed to decideQuery, which is what makes a requester-scoped
// policy inapplicable to a viewer. This states the consequence the Kotlin actually asserts: with a
// forbid naming the requester ENABLED, the executing viewer still reads cleartext.
//
// The second arm is what keeps the first honest. The Kotlin has no equivalent, and without it a forbid
// that silently never matched anybody would make the first arm pass vacuously: viewing as the
// requester — the principal the forbid names — must come back MASKED, which proves the forbid is live
// and that the only reason it did not bite the approver is the principal the decision was made for.
//
// KT: ApprovalResultViewContextDbTest.kt#the live decision uses the viewer principal rather than the requester identity — the route-level half, by the Kotlin's requester-scoped-forbid mechanism
func TestARequesterScopedForbidDoesNotApplyToTheExecutingViewer(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	users := f.fx.UsersTableEUID()

	// Cleartext is reachable at all only under an unmask grant on the task role.
	f.fx.AddCedarPolicy("viewer-principal-unmask-pii",
		`permit(principal in Role::"`+dbtest.FixtureRole+`", action == Action::"result.read.unmasked", `+
			`resource in Table::"`+users+`") when { resource in Tag::"pii" };`)
	// The Kotlin's `approval-view-requester-unmask-forbid`, scoped to the REQUESTER principal.
	f.fx.AddCedarPolicy("viewer-principal-requester-forbid",
		`forbid(principal, action == Action::"result.read.unmasked", resource in Table::"`+users+`") `+
			`when { principal == User::"`+requester+`" && resource in Tag::"pii" };`)

	task := f.storedRawRRN("SELECT id, rrn FROM users")

	// The approver executed the run and is NOT the forbidden principal: the forbid must not reach them.
	asApprover := f.get(idPath("/api/approvals/", task.ID, "/result"), f.login(approver))
	assertStatus(t, asApprover, http.StatusOK, "the executing viewer's view")
	var approverView QueryResultView
	decodeJSON(t, asApprover, &approverView)
	if got := cell(t, approverView, 0, 1); got != dbtest.FixtureCleartextRRN[0] {
		t.Errorf("rrn for the executing viewer: got %q, want the cleartext %q — a requester-scoped forbid "+
			"must not apply to the viewer", got, dbtest.FixtureCleartextRRN[0])
	}

	// The non-vacuity control: the forbidden principal viewing their OWN result is re-masked.
	asRequester := f.get(idPath("/api/approvals/", task.ID, "/result"), f.login(requester))
	assertStatus(t, asRequester, http.StatusOK, "the forbidden principal's own view")
	var requesterView QueryResultView
	decodeJSON(t, asRequester, &requesterView)
	if got := cell(t, requesterView, 0, 1); got != maskedRRN {
		t.Errorf("rrn for the forbidden principal: got %q, want the masked %q — if this is cleartext the "+
			"forbid never matched anybody and the arm above proves nothing", got, maskedRRN)
	}
}

// 🔒 ONE STORED RESULT, TWO ANSWERS: MASKED OFF-CONTEXT AND UNMASKED IN-CONTEXT, FOR BOTH PARTIES,
// WITH THE STORED BYTES UNTOUCHED THROUGHOUT.
//
// This is the whole point of re-deciding rather than snapshotting. The unmask grant is conditioned on
// a requester-IP-derived context tag, so the SAME viewer reading the SAME row gets cleartext from
// inside the segregated range and the masked form from outside it — and the row on disk never changes.
// A snapshot-as-is path returns cleartext to both, which is why the stored payload is cleartext here.
//
// The tag is server-attested: it is derived only when the request arrives through the trusted edge
// ([httpFixture.trustTheTestEdge]), so the off-context view is a request with no X-Forwarded-For at
// all rather than a different principal.
//
// KT: ApprovalResultViewContextDbTest.kt#the same stored result masks off-segregated and unmasks in-context for approver and requester
func TestTheSameStoredResultMasksOffContextAndUnmasksInContextForBothParties(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	f.withApprover()
	f.trustTheTestEdge()

	// Pass 1: requester_ip inside 100.100.0.0/16 earns the `segregated` tag. Principal-agnostic — the
	// tag is a property of WHERE the request came from, never of who sent it.
	f.fx.AddCedarPolicy("view-segregated-tag",
		`permit(principal, action == Action::"context.tag::segregated", resource) `+
			`when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`)
	// Pass 2: the unmask grant CONSUMES that tag. Without it only the shipped masked-pii grant applies.
	f.fx.AddCedarPolicy("view-unmask-when-segregated",
		`permit(principal in Role::"`+dbtest.FixtureRole+`", action == Action::"result.read.unmasked", `+
			`resource in Table::"`+f.fx.UsersTableEUID()+`") `+
			`when { resource in Tag::"pii" && context has tags && context.tags.contains("segregated") };`)

	task := f.storedRawRRN("SELECT id, rrn FROM users")
	storedBefore := f.ciphertext(task.ID)
	inContext := map[string]string{"X-Forwarded-For": "100.100.5.5"}

	for _, viewer := range []struct {
		name      string
		principal string
	}{{"executor/approver", approver}, {"requester", requester}} {
		t.Run(viewer.name, func(t *testing.T) {
			cookie := f.login(viewer.principal)

			off := f.get(idPath("/api/approvals/", task.ID, "/result"), cookie)
			assertStatus(t, off, http.StatusOK, viewer.name+" off-context")
			var offView QueryResultView
			decodeJSON(t, off, &offView)
			if got := cell(t, offView, 0, 1); got != maskedRRN {
				t.Errorf("off-context rrn: got %q, want the masked %q", got, maskedRRN)
			}
			if len(offView.MaskedColumns) != 1 || offView.MaskedColumns[0] != "rrn" {
				t.Errorf("maskedColumns off-context: got %v, want [rrn] — the view must label what it masked",
					offView.MaskedColumns)
			}

			in := f.with(http.MethodGet, idPath("/api/approvals/", task.ID, "/result"), nil, inContext, cookie)
			assertStatus(t, in, http.StatusOK, viewer.name+" in-context")
			var inView QueryResultView
			decodeJSON(t, in, &inView)
			if got := cell(t, inView, 0, 1); got != dbtest.FixtureCleartextRRN[0] {
				t.Errorf("in-context rrn: got %q, want the cleartext %q", got, dbtest.FixtureCleartextRRN[0])
			}
			if len(inView.MaskedColumns) != 0 {
				t.Errorf("maskedColumns in-context: got %v, want [] — this view masked nothing",
					inView.MaskedColumns)
			}
		})
	}

	if !bytes.Equal(storedBefore, f.ciphertext(task.ID)) {
		t.Error("view-time masking rewrote the stored ciphertext; four views must leave it byte-identical")
	}
}

// ---------------------------------------------------------------------------------------------
// `ElevationContextRouteAuthzDbTest` — the FOUR of its eight cases that drive Approvals.kt.
//
// internal/access carries the two accessRoutes cases and internal/datasource the two Datasources.kt
// ones; these are the query-approval half. What the whole suite is for, from its kdoc: "whether the
// PRODUCTION routes actually thread `call.httpAuthzContext(config)` + the request's datasource into
// that helper. Deleting the wiring at […] Approvals.kt (the query-approval `mayDecide` call) leaves the
// helper test green — so this test drives the REAL routes end to end."
//
// The gate is therefore a task.approve permit conditioned ONLY on a requester-IP-derived datasource
// context tag. The approver here holds `reviewer` and NOTHING else — deliberately not the fixture's
// system:admin, whose shipped grant would approve with no context at all and make every case below
// pass vacuously.
// ---------------------------------------------------------------------------------------------

const elevationApprover = "reviewer@example.com"

// elevationFixture is the Kotlin's @BeforeAll: the reviewer role + the two policies + the trusted
// edge, over the real Cedar engine.
func newElevationFixture(t *testing.T) *httpFixture {
	t.Helper()
	f := newHTTPFixture(t, fixtureOptions{})
	f.trustTheTestEdge()
	f.fx.Seed.AssignRole(elevationApprover, f.fx.Seed.Role("reviewer"))
	f.fx.Seed.Role("target-role")
	// Verbatim from ElevationContextRouteAuthzDbTest.kt:79-87.
	f.fx.AddCedarPolicy("elev-trusted-network-tag",
		`permit(principal, action == Action::"context.tag::trusted-network", resource) `+
			`when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`)
	f.fx.AddCedarPolicy("elev-tag-gated-approve",
		`permit(principal in Role::"reviewer", action == Action::"task.approve", resource) `+
			`when { context has tags && context.tags.contains("trusted-network") };`)
	return f
}

// trustedEdgeHeaders is an in-range X-Forwarded-For, honored because httptest's socket peer is the
// sole trusted edge.
var trustedEdgeHeaders = map[string]string{"X-Forwarded-For": "100.100.5.5"}

// 🔒 THE TWO HALVES ARE A MATCHED PAIR AND NEITHER IS INFORMATIVE ALONE. Same route, same request, same
// policy set; the only difference is one header. Without the trusted XFF, requester_ip is absent, pass
// 1 derives no tag, and the tag-gated permit cannot fire ⇒ 403. With it, the tag is derived ⇒ 200.
//
// The OK half fails if the route drops `gates.AuthzContext(r)` (requester_ip never reaches Cedar) OR
// drops the datasource tag-scoping (no Datasource in scope ⇒ nothing is derived). Both are deletions
// that leave every unit-level authz test green, which is the whole reason this case exists.
//
// KT: ElevationContextRouteAuthzDbTest.kt#query-approval approve fires the tag-gated permit only through a trusted edge (Approvals-kt wiring)
func TestQueryApprovalApproveFiresTheTagGatedPermitOnlyThroughATrustedEdge(t *testing.T) {
	f := newElevationFixture(t)
	cookie := f.login(elevationApprover)

	forbidden := f.seedWorkflowTask(requester, "SELECT id FROM users", "target-role")
	denied := f.post(idPath("/api/approvals/", forbidden.ID, "/approve"), nil, cookie)
	assertStatus(t, denied, http.StatusForbidden,
		"no requester_ip ⇒ no trusted-network tag ⇒ elevation approve denied (would still pass if the "+
			"route dropped httpAuthzContext)")
	assertCode(t, denied, "approval.not_approver")
	if got := f.getRequest(forbidden.ID).Status; got != "PENDING" {
		t.Errorf("status after a refused approve: got %q, want PENDING", got)
	}

	approved := f.seedWorkflowTask(requester, "SELECT id FROM users", "target-role")
	ok := f.with(http.MethodPost, idPath("/api/approvals/", approved.ID, "/approve"), nil, trustedEdgeHeaders, cookie)
	assertStatus(t, ok, http.StatusOK,
		"trusted-edge requester_ip ⇒ derived tag ⇒ approve succeeds; FAILS if the route drops "+
			"httpAuthzContext or the datasource tag-scoping")
	var out access.AccessRequest
	decodeJSON(t, ok, &out)
	if out.Status != "APPROVED" {
		t.Errorf("status: got %q, want APPROVED", out.Status)
	}
}

// 🔒 APPROVE MUTATES AUTHORIZATION STATE AND NOTHING ELSE — it never runs the query.
//
// The task already has exactly one statement child, not yet run. After a successful approve that child
// must still be not-run (status NULL) with no verdict, no ciphertext, no row count and no columns, and
// no second child may appear. A port that ran the query at approve time (or pre-populated the child)
// would leave R's output stored under a task nobody has executed — and `executed_at` cannot be the
// signal, since V9 defaults it at child creation.
//
// KT: ElevationContextRouteAuthzDbTest.kt#query-approval approve mutates only authorization state and never runs the query
func TestQueryApprovalApproveMutatesOnlyAuthorizationStateAndNeverRunsTheQuery(t *testing.T) {
	f := newElevationFixture(t)
	cookie := f.login(elevationApprover)
	task := f.seedWorkflowTask(requester, "SELECT id FROM users", "target-role")

	if n := f.childCount(task.ID); n != 1 {
		t.Fatalf("premise broken: %d children at creation, want exactly 1 not-started child", n)
	}
	before, err := f.Results.Meta(context.Background(), task.ID)
	if err != nil || before == nil || before.Status != nil {
		t.Fatalf("premise broken: the child is already run: %#v (err=%v)", before, err)
	}

	ok := f.with(http.MethodPost, idPath("/api/approvals/", task.ID, "/approve"), nil, trustedEdgeHeaders, cookie)
	assertStatus(t, ok, http.StatusOK, "trusted-edge approve")

	req := f.getRequest(task.ID)
	if req.Status != "APPROVED" {
		t.Errorf("status: got %q, want APPROVED", req.Status)
	}
	if req.DecidedBy == nil || *req.DecidedBy != elevationApprover {
		t.Errorf("decidedBy: got %v, want %s", req.DecidedBy, elevationApprover)
	}
	if req.DecidedAt == nil || req.ApprovedAt == nil {
		t.Errorf("approve must stamp decidedAt and approvedAt; got %v / %v", req.DecidedAt, req.ApprovedAt)
	}

	// …and it ran NOTHING.
	if n := f.childCount(task.ID); n != 1 {
		t.Errorf("%d children after approve, want the original 1", n)
	}
	after, err := f.Results.Meta(context.Background(), task.ID)
	if err != nil || after == nil {
		t.Fatalf("child meta: %#v err=%v", after, err)
	}
	if after.Status != nil {
		t.Errorf("child status after approve: got %q, want NULL (not run)", *after.Status)
	}
	if after.RowCount != nil || len(after.Columns) != 0 {
		t.Errorf("approve stored result shape: rowCount=%v columns=%v, want neither", after.RowCount, after.Columns)
	}
	if raw := f.ciphertext(task.ID); raw != nil {
		t.Errorf("approve stored %d ciphertext bytes; a pure approve must store none", len(raw))
	}
	if f.RunExec.runCount() != 0 || f.pendingCount() != 0 {
		t.Errorf("approve launched %d runs and queued %d async bodies; it must run nothing",
			f.RunExec.runCount(), f.pendingCount())
	}
}

func (f *httpFixture) childCount(taskID int64) int64 {
	f.t.Helper()
	var n int64
	if err := f.fx.Store.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM query_result WHERE task_id = $1`, taskID).Scan(&n); err != nil {
		f.t.Fatalf("count children of %d: %v", taskID, err)
	}
	return n
}

// 🔒 DEFENSE IN DEPTH — /execute RE-CHECKS THE SAME R-SCOPED AUTHORITY, so a request approved earlier
// is not a licence to run it from anywhere.
//
// The gate fires BEFORE the execute-once claim and before runExec is reached, so the refusal is a 403
// and the task is left untouched — a 503 (no proxy) here would mean the gate had leaked.
//
// KT: ElevationContextRouteAuthzDbTest.kt#query-approval execute is forbidden without the trusted edge, even for an already-approved request
func TestQueryApprovalExecuteIsForbiddenWithoutTheTrustedEdgeEvenWhenAlreadyApproved(t *testing.T) {
	f := newElevationFixture(t)
	task := f.seedWorkflowTask(requester, "SELECT id FROM users", "target-role")
	f.approveTask(task.ID, elevationApprover) // approved earlier, by the principal now executing

	denied := f.post(idPath("/api/approvals/", task.ID, "/execute"), nil, f.login(elevationApprover))

	assertStatus(t, denied, http.StatusForbidden, "execute with no requester_ip")
	assertCode(t, denied, "approval.not_approver")
	if got := f.getRequest(task.ID).Status; got != "APPROVED" {
		t.Errorf("status: got %q, want APPROVED — a refused execute must not claim the task", got)
	}
	if f.RunExec.runCount() != 0 || f.pendingCount() != 0 {
		t.Error("the refused execute reached runExec")
	}
}

// The positive control for the case above: through the trusted edge the R-scoped authority gate PASSES
// and the route proceeds to the run — which, with no proxy attached, fails as
// `query.no_proxy_attached`. That specific outcome (202 then a FAILED task, NOT a 403) is the minimal
// honest proof the gate passed.
//
// KT: ElevationContextRouteAuthzDbTest.kt#query-approval execute clears the R-scoped authority gate through a trusted edge (then fails on no attached proxy)
func TestQueryApprovalExecuteClearsTheRScopedAuthorityGateThroughATrustedEdge(t *testing.T) {
	f := newElevationFixture(t)
	task := f.seedWorkflowTask(requester, "SELECT id FROM users", "target-role")
	f.approveTask(task.ID, elevationApprover)
	f.RunExec.err = ErrNoProxyAttached // no fake proxy is attached in this fixture

	ok := f.with(http.MethodPost, idPath("/api/approvals/", task.ID, "/execute"), nil,
		trustedEdgeHeaders, f.login(elevationApprover))

	assertStatus(t, ok, http.StatusAccepted,
		"trusted-edge requester_ip ⇒ derived tag ⇒ the execute-under-R authority passes and submits asynchronously")
	var ack ExecuteApprovalResponse
	decodeJSON(t, ok, &ack)
	if ack.Decision != "EXECUTING" {
		t.Errorf("ack: got %q, want EXECUTING", ack.Decision)
	}

	if n := f.runAsync(); n != 1 {
		t.Fatalf("%d async bodies queued, want 1", n)
	}
	if got := f.getRequest(task.ID).Status; got != "FAILED" {
		t.Errorf("status: got %q, want FAILED (the run had no proxy to dial)", got)
	}
	meta, err := f.Results.Meta(context.Background(), task.ID)
	if err != nil || meta == nil || meta.ErrorCode == nil || *meta.ErrorCode != "query.no_proxy_attached" {
		t.Errorf("child errorCode: got %#v, want query.no_proxy_attached", meta)
	}
}
