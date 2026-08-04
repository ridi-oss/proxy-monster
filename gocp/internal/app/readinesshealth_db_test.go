package app

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// ---------------------------------------------------------------------------------------------
// `ReadinessDiagnosticDbTest.kt` case 2 — `GET /health`, both states.
//
// boot_e2e_db_test.go's TestHealthRouteReportsOkAndDiagnostics covers the CLEAN-INSTALL state, over a
// full boot. What it does not cover is the transition: it asserts `contains(diagnostics, …)` rather
// than the exact list, and it never opens the install, so an implementation whose diagnostic never
// CLEARS would pass it. That transition is the whole point of the diagnostic — it is how an operator
// knows the bootstrap is done — so it is asserted here.
// ---------------------------------------------------------------------------------------------

// 🔒 TestHealthReportsWhetherSystemAdminHasAnActiveAssigneeAndClearsWhenItDoes is the port of
// `health stays ok and reports whether system-admin has an active assignee`.
//
// Two states, one process:
//
//   - UNOPENED — the seed's `system:admin` group_role link exists but has no members, so no principal
//     resolves the role. `diagnostics` is EXACTLY `["system:admin role has no active assignee"]`.
//   - OPENED — one direct `principal_role` assignment, and `diagnostics` is EMPTY.
//
// 🔒 `status` stays "ok" in BOTH. This is the assertion that matters operationally and the one a port
// is most likely to "improve": a readiness probe that failed on a clean install would keep the pod out
// of service, and the very first login — the thing that fixes it — is only reachable through that
// service. Reported, never down.
//
// The exact-list assertion (rather than a `contains`) is the Kotlin's, and it also pins the SECOND
// diagnostic source: healthHandler appends authz.ContextTagLint over the enabled policy set, and on a
// freshly seeded install that lint must be silent. A dangling-tag lint firing on the SHIPPED policies
// would mean every operator sees a warning on a healthy install.
// KT: ReadinessDiagnosticDbTest.kt#health stays ok and reports whether system-admin has an active assignee
func TestHealthReportsWhetherSystemAdminHasAnActiveAssigneeAndClearsWhenItDoes(t *testing.T) {
	s := newAuthServer(t, nil)

	get := func(what string) HealthResponse {
		t.Helper()
		resp, err := s.bare().Get(s.server.URL + "/health")
		if err != nil {
			t.Fatalf("%s: GET /health: %v", what, err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s: read body: %v", what, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200 (body %s)", what, resp.StatusCode, raw)
		}
		var body HealthResponse
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("%s: decode %q: %v", what, raw, err)
		}
		if body.Status != "ok" {
			t.Errorf("%s: status = %q, want ok — an unopened or half-configured install is REPORTED, "+
				"never marked down, or the readiness probe blocks the login that would fix it",
				what, body.Status)
		}
		return body
	}

	unopened := get("a clean install")
	want := SystemAdminRole + " role has no active assignee"
	if len(unopened.Diagnostics) != 1 || unopened.Diagnostics[0] != want {
		t.Fatalf("diagnostics = %v, want exactly [%q]. One extra entry means the context-tag lint is "+
			"firing on the SHIPPED Cedar policies, which every operator would see on a healthy install",
			unopened.Diagnostics, want)
	}

	// Open the install: one direct assignment of system:admin, the same thing a first login through a
	// mapped IdP group produces via the group path.
	roleID := s.scalarInt64(`SELECT id FROM app_role WHERE name = $1`, SystemAdminRole)
	if _, err := s.db.Pool.Exec(s.t.Context(),
		`INSERT INTO principal_role (principal, role_id) VALUES ('admin@example.com', $1)`, roleID); err != nil {
		t.Fatalf("assign system:admin: %v", err)
	}

	opened := get("after the first admin exists")
	if len(opened.Diagnostics) != 0 {
		t.Errorf("diagnostics = %v, want empty — the diagnostic must CLEAR once the role has an active "+
			"assignee, otherwise it is noise an operator learns to ignore", opened.Diagnostics)
	}
}

// scalarInt64 reads one bigint from the running control plane's own database.
func (s *authServer) scalarInt64(sql string, args ...any) int64 {
	s.t.Helper()
	var out int64
	if err := s.db.Pool.QueryRow(s.t.Context(), sql, args...).Scan(&out); err != nil {
		s.t.Fatalf("scalar %q: %v", sql, err)
	}
	return out
}
