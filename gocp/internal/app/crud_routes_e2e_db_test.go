package app_test

// The MOUNT proof for the four CRUD route groups this increment adds to App.kt's composition root:
//
//	A2  /api/policies         (8 routes) — 02-authz.md §8
//	A9  /api/roles, /api/role-assignments, /api/mask-fns (11) — 09-policies.md §3
//	A8  /api/audit            (2 routes) — 08-audit.md §3
//	A7  /api/query-history    (2 routes) — 07-tasks-approvals-results.md §9
//
// The per-package suites already prove the behaviour of each group against a router they build
// themselves. What only THIS file can prove is that internal/app mounts them at all, on ONE ServeMux,
// with the dependencies the real wiring hands them — and that is not a formality:
//
//   - A Go 1.22 pattern CONFLICT panics at registration, so a route table that overlaps between areas
//     fails at boot rather than at the first request. Booting the real app is the check.
//   - `audit.Reader.AuthDebug` and `httpapi.Gates.Config.AuthDebug` are TWO fields with no enforced
//     agreement (internal/audit's TestTheGateAndTheReaderMustAgreeAboutAuthDebug measures what a
//     disagreement produces: a 500). Only the wiring can get that wrong, so only a test over the
//     wiring can catch it.
//
// bootE2E's env sets PM_DEV=true, so PM_AUTH_DEBUG defaults to TRUE. That is what lets these probes
// run with no session: under the bypass every gate admits, which isolates "is it mounted" from "is it
// gated". The gating itself is asserted, exhaustively, in each area's own suite.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// crudProbe is one request against the booted app.
func crudProbe(t *testing.T, b *bootedApp, method, path string) (int, []byte) {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", b.app.HTTPPort(), path)
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// 🔒 Every route group this increment adds is REACHABLE through the real composition root.
//
// The assertion is deliberately "not 404 and not 500", not "200": a 404 means the group was never
// mounted, a 500 means it was mounted with a dependency it cannot use — and those are the two ways a
// wiring line goes wrong. The exact status of each route is its own area suite's business.
func TestTheFourCrudRouteGroupsAreMounted(t *testing.T) {
	b := bootE2E(t, nil)

	for _, probe := range []struct {
		method, path string
		want         int
		area         string
	}{
		{http.MethodGet, "/api/policies", http.StatusOK, "A2"},
		{http.MethodGet, "/api/policies/schema", http.StatusOK, "A2"},
		{http.MethodGet, "/api/roles", http.StatusOK, "A9"},
		{http.MethodGet, "/api/role-assignments", http.StatusOK, "A9"},
		{http.MethodGet, "/api/mask-fns", http.StatusOK, "A9"},
		{http.MethodGet, "/api/audit", http.StatusOK, "A8"},
		{http.MethodGet, "/api/query-history", http.StatusOK, "A7 §9"},
	} {
		t.Run(probe.area+" "+probe.method+" "+probe.path, func(t *testing.T) {
			status, body := crudProbe(t, b, probe.method, probe.path)
			if status != probe.want {
				t.Errorf("%s %s → %d, want %d (body: %s)", probe.method, probe.path, status, probe.want, body)
			}
		})
	}
}

// 🔒 THE PIN FOR THE ONE THING ONLY THE WIRING CAN GET WRONG.
//
// `cfg.AuthDebug` reaches `/api/audit` twice: through `httpapi.Gates.Config` (the requireApi gate) and
// through `audit.Reader.AuthDebug` (the visibility model). Nothing in either type enforces that they
// agree, and internal/audit's TestTheGateAndTheReaderMustAgreeAboutAuthDebug measures the failure:
// gate-on + reader-off admits a sessionless request the reader then cannot serve, and the handler
// answers 500 common.fallback.
//
// Under PM_AUTH_DEBUG this request carries NO SESSION AT ALL, so it only succeeds if BOTH copies are
// on. A wiring that hardcoded `AuthDebug: false` on the Reader would 500 here and nowhere else.
func TestAuditRoutesGetOneAuthDebugValue(t *testing.T) {
	b := bootE2E(t, nil)

	status, body := crudProbe(t, b, http.MethodGet, "/api/audit")

	if status == http.StatusInternalServerError {
		t.Fatalf("GET /api/audit answered 500 with no session under PM_AUTH_DEBUG: %s\n"+
			"That is the signature of the gate and the Reader disagreeing about AuthDebug — "+
			"http.go must pass cfg.AuthDebug to BOTH.", body)
	}
	if status != http.StatusOK {
		t.Fatalf("GET /api/audit → %d, want 200 (body: %s)", status, body)
	}
	// 🔒 INV-A1-4 — an empty feed is `[]`, never `null`.
	if string(body) != "[]" {
		var events []types.AuditEvent
		if err := json.Unmarshal(body, &events); err != nil {
			t.Fatalf("the audit feed must be a JSON array (%v): %s", err, body)
		}
	}
}

// The two routes whose CONTRACT is a status the mount probe above deliberately does not assert, and
// which are cheap to get wrong in the composition root: a 204 that grew a body, and a retired route
// that came back.
func TestCrudRouteContractsSurviveTheRealCompositionRoot(t *testing.T) {
	b := bootE2E(t, nil)

	t.Run("DELETE /api/query-history is 204 with no body", func(t *testing.T) {
		status, body := crudProbe(t, b, http.MethodDelete, "/api/query-history")
		if status != http.StatusNoContent {
			t.Errorf("status = %d, want 204 (body: %s)", status, body)
		}
		if len(body) != 0 {
			t.Errorf("204 must carry no body, got %q", body)
		}
	})

	// 08-audit.md §4 case 4, through the real router this time. Nothing fails when a route is absent,
	// so the assertion has to be written on purpose — and the composition root is exactly where a
	// retired path gets re-added by accident.
	t.Run("GET /api/decisions stays removed", func(t *testing.T) {
		status, _ := crudProbe(t, b, http.MethodGet, "/api/decisions")
		if status != http.StatusNotFound {
			t.Errorf("/api/decisions → %d, want 404; the retired decisions route must stay removed", status)
		}
	})

	// A bad id is answered by idParam before any store is touched, on the real stack too.
	t.Run("GET /api/audit/abc is common.bad_id", func(t *testing.T) {
		status, body := crudProbe(t, b, http.MethodGet, "/api/audit/abc")
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %s)", status, body)
		}
		var e types.ApiError
		if err := json.Unmarshal(body, &e); err != nil {
			t.Fatalf("body is not an ApiError (%v): %s", err, body)
		}
		if e.Code != "common.bad_id" {
			t.Errorf("code = %q, want \"common.bad_id\"", e.Code)
		}
	})
}

// The A2 list route through the real store: the seeded SYSTEM policies are visible with their
// provenance, which is also the cheapest end-to-end proof that the shared `c.CedarPolicyStore` — not
// a second one — is what the routes read.
func TestPolicyListOverTheRealCoreExposesTheSeededSystemRows(t *testing.T) {
	b := bootE2E(t, nil)

	status, body := crudProbe(t, b, http.MethodGet, "/api/policies")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", status, body)
	}

	var policies []struct {
		ID        int64   `json:"id"`
		Origin    string  `json:"origin"`
		SystemKey *string `json:"systemKey"`
		Name      string  `json:"name"`
	}
	if err := json.Unmarshal(body, &policies); err != nil {
		t.Fatalf("decode /api/policies (%v): %s", err, body)
	}
	if len(policies) == 0 {
		t.Fatal("V8 seeds SYSTEM policies; the list must not be empty")
	}
	if policies[0].Origin != "SYSTEM" || policies[0].ID >= 0 {
		t.Errorf("first row = %+v; SYSTEM rows carry NEGATIVE ids and ORDER BY id puts them first",
			policies[0])
	}
	if policies[0].SystemKey == nil {
		t.Error("a SYSTEM row must expose its systemKey — the console renders provenance from it")
	}
}

// 🔒 EVERY GROUP THE COMPOSITION ROOT NOW MOUNTS, ANSWERING FOR REAL.
//
// routetable_db_test.go proves each route has a PATTERN; this proves the group behind it has USABLE
// DEPENDENCIES. Those are different failures with different causes: a missing pattern is a forgotten
// `router.Mount` line, while a 500 is a wiring line that compiled and handed a handler something it
// cannot call — a nil store, a nil management service, a seam pointed at the wrong instance. The Go
// type system catches neither, because every one of these seams is an interface and nil satisfies it.
//
// THE ASSERTION IS "NOT 500 AND NOT 404", not a specific status, and the range matters in both
// directions:
//   - 500 `common.fallback` is what a nil dependency produces, via StatusPages recovering the
//     dereference. It is the signal this file exists for.
//   - 404 means unmounted — already covered next door, kept here so a group that loses its mount line
//     fails in both places rather than one.
//
// Read-only GETs only, deliberately: a probe that mutated would need seeded rows and would start
// asserting the area's behaviour, which is the area suite's job and is where a wiring test goes stale.
//
// bootE2E's env sets PM_DEV=true ⇒ PM_AUTH_DEBUG on, so every gate admits and the probe isolates
// "does the wiring work" from "is the gate right". The gating is swept exhaustively per area.
func TestEveryMountedRouteGroupAnswersThroughTheRealCompositionRoot(t *testing.T) {
	b := bootE2E(t, nil)

	for _, probe := range []struct {
		method, path, area string
	}{
		// A3 — userGroupRoutes + scimRoutes. 🔒 SCIM proves `credentials` is non-nil at BOTH wiring
		// sites (INV-A3-6): NewScimRoutes and NewIdentityService must get the same real object.
		{http.MethodGet, "/api/users", "A3 users"},
		{http.MethodGet, "/api/groups", "A3 groups"},
		{http.MethodGet, "/api/scim/v2/ServiceProviderConfig", "A3 SCIM discovery"},

		// A5 — datasourceRoutes. `/live` exercises the REAL ProxyEventsHub through
		// datasource.ProxyEvents, which needed core.ProxyEventsHub to grow `Attached() map[…]` —
		// a nil Events field 500s here and only here.
		{http.MethodGet, "/api/datasources", "A5 list"},
		{http.MethodGet, "/api/datasources/live", "A5 liveness"},

		// A6 — accessRoutes and the editor. Both list routes forward-filter per row through the
		// SHARED Cedar graph (INV-A6-28), so a nil Authz shows up as a 500 rather than a wrong list.
		{http.MethodGet, "/api/access-requests", "A6 access requests"},
		{http.MethodGet, "/api/access-grants", "A6 access grants"},

		// A7 — approvalRoutes. `/inbox` runs the approver-eligibility path, `/api/approvals` the
		// requester one; both need Access + Audit + the Decider's five seams.
		{http.MethodGet, "/api/approvals", "A7 approvals"},
		{http.MethodGet, "/api/approvals/inbox", "A7 inbox"},

		// A4 — tokenRoutes.
		{http.MethodGet, "/api/tokens", "A4 tokens"},

		// A11 §2 + §6 — the three discovery documents. They are pure functions of config, so a 500
		// here means `installMcp` or `mcpOAuthRoutes` was constructed with a malformed resource URI.
		{http.MethodGet, "/.well-known/oauth-protected-resource", "A11 protected resource"},
		{http.MethodGet, "/.well-known/oauth-protected-resource/mcp", "A11 protected resource /mcp"},
		{http.MethodGet, "/.well-known/oauth-authorization-server", "A11 authorization server"},
	} {
		t.Run(probe.area, func(t *testing.T) {
			status, body := crudProbe(t, b, probe.method, probe.path)
			switch status {
			case http.StatusNotFound:
				t.Errorf("%s %s → 404: the group is not mounted (body: %s)", probe.method, probe.path, body)
			case http.StatusInternalServerError:
				t.Errorf("%s %s → 500: the group is mounted with a dependency it cannot use.\n"+
					"That is a nil seam in NewHTTPSurface, not a bug in the area — check what this route's "+
					"handler reaches for. (body: %s)", probe.method, probe.path, body)
			}
		})
	}
}

// 🔴 THE DEGRADED-STATE ANSWERS, ASSERTED RATHER THAN ASSUMED.
//
// This test used to pin TWO stand-ins: app.unportedRunExec and the nil management.TableDetails. The
// first is GONE — internal/runexec's real RunExecService is wired now — and the assertion is unchanged,
// which is exactly what the stub's justification predicted: 503 `query.no_proxy_attached` is what a
// fully-ported control plane answers for a datasource with no attached proxy, so the real transport and
// the stub are indistinguishable on this input. The stub's claim is retired by being confirmed.
//
// What is still a stand-in is A5/A10's TableDetailService. If it lands, the second subtest becomes
// wrong and must be updated deliberately. That is the intent: the pin forces the update to be noticed.
func TestTheUnportedTransportStubsAnswerTheirDegradedStatus(t *testing.T) {
	b := bootE2E(t, nil)

	// The REAL RunExecService, reached for real. A6 resolves the datasource BEFORE it dials, so an
	// unknown id answers `common.not_found` and never touches the transport — which is why this creates
	// a real datasource first, through the real admin route. Only then does `POST /api/editor/sessions`
	// get as far as OpenSession: it mints the EDITOR token, opens a catalog connection, registers the
	// pending session, and asks the events hub to nudge a proxy. bootE2E starts none, so the dispatch
	// answers NOT_ATTACHED and ErrNoProxyAttached becomes the wire answer.
	//
	// 🔒 That path also proves the failure UNWINDS: the token is revoked and the pending session removed
	// on the way out (openSession's recovery dance). A leak there would not change this status code,
	// which is why internal/runexec asserts the unwind directly as well.
	t.Run("POST /api/editor/sessions reaches the run transport and answers 503", func(t *testing.T) {
		status, body := crudProbeBody(t, b, http.MethodPost, "/api/datasources",
			`{"name":"stub-probe","engine":"postgres","host":"127.0.0.1","port":5432,"dbName":"probe"}`)
		if status != http.StatusCreated {
			t.Fatalf("POST /api/datasources → %d, want 201 (body: %s)", status, body)
		}
		var created struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(body, &created); err != nil || created.ID == 0 {
			t.Fatalf("could not read the created datasource id (%v): %s", err, body)
		}

		status, body = crudProbeBody(t, b, http.MethodPost, "/api/editor/sessions",
			fmt.Sprintf(`{"datasourceId":%d}`, created.ID))
		if status != http.StatusServiceUnavailable {
			t.Fatalf("POST /api/editor/sessions → %d, want 503 query.no_proxy_attached.\n"+
				"A 500 here means the run transport is a nil interface rather than the real service; "+
				"a 404 means the datasource was not created and the probe never reached the transport. "+
				"(body: %s)", status, body)
		}
		var apiErr types.ApiError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			t.Fatalf("the body is not an ApiError (%v): %s", err, body)
		}
		if apiErr.Code != "query.no_proxy_attached" {
			t.Errorf("code = %q, want query.no_proxy_attached — 🔒 INV-A7-34 keeps this DISTINCT from "+
				"query.proxy_stream_wedged, and a hub with no subscriber at all is the no-proxy one, "+
				"never the wedged one", apiErr.Code)
		}
	})

	// 🔴 The nil management.TableDetails, REACHED FOR REAL. The route validates `id > 0` and then
	// `schema`/`table` before it calls the service, so both must be supplied or the probe stops at a
	// 400 without ever touching the seam — and the datasource must exist, since mustGet resolves it
	// first. This creates one and asks for a table on it.
	//
	// 502 `datasource.table_introspection_failed` with a `detail` is the honest answer: no transport is
	// configured, so the control plane could not ask the proxy. The real TableDetailService returns the
	// same code (through management.ErrTableDetailExec) when no proxy is attached or the proxy times
	// out — the `detail` string is the only observable difference, and 502-versus-500 is the part that
	// matters to a caller.
	t.Run("GET table-detail reaches the introspection seam and answers 502", func(t *testing.T) {
		status, body := crudProbeBody(t, b, http.MethodPost, "/api/datasources",
			`{"name":"detail-probe","engine":"postgres","host":"127.0.0.1","port":5432,"dbName":"probe"}`)
		if status != http.StatusCreated {
			t.Fatalf("POST /api/datasources → %d, want 201 (body: %s)", status, body)
		}
		var created struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(body, &created); err != nil || created.ID == 0 {
			t.Fatalf("could not read the created datasource id (%v): %s", err, body)
		}

		status, body = crudProbe(t, b, http.MethodGet,
			fmt.Sprintf("/api/datasources/%d/table-detail?schema=public&table=users", created.ID))
		if status != http.StatusBadGateway {
			t.Fatalf("→ %d, want 502 datasource.table_introspection_failed.\n"+
				"500 means the nil management.TableDetails was dereferenced instead of being reported; "+
				"400 means the probe was rejected by parameter validation and never reached the seam. "+
				"(body: %s)", status, body)
		}
		var apiErr types.ApiError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			t.Fatalf("the body is not an ApiError (%v): %s", err, body)
		}
		if apiErr.Code != "datasource.table_introspection_failed" {
			t.Errorf("code = %q, want datasource.table_introspection_failed", apiErr.Code)
		}
	})
}

// crudProbeBody is [crudProbe] with a JSON body, for the two POST probes above.
func crudProbeBody(t *testing.T, b *bootedApp, method, path, body string) (int, []byte) {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", b.app.HTTPPort(), path)
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}
