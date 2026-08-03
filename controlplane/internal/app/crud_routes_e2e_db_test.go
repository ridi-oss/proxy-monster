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
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
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
