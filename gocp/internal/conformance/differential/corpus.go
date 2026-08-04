// Package differential is the two-implementation harness: replay one request corpus against BOTH the
// Kotlin control-plane and the Go control-plane, then diff the answers.
//
// WHY THIS EXISTS, and why the 903/903 traceability number does not make it redundant. Every other test
// in this repo asserts the Go control-plane against a TRANSCRIPTION — someone read the Kotlin, wrote
// down what they believed it asserted, and checked Go against that. A misreading of the Kotlin becomes
// a Go test that encodes the misreading and passes. The two implementations have never been compared to
// each other, so "1:1" is currently a claim about test bookkeeping, not a measurement of behaviour.
//
// This harness is the measurement. It cannot be fooled by a misread spec, because neither side is the
// spec: the Kotlin's own response IS the oracle.
//
// 🔒 WHAT IT MUST NOT DO: normalise away a real difference. The normaliser below is the only place a
// divergence can be hidden, so every rule in it is justified at its definition and scoped as narrowly
// as the field allows. A rule like "ignore all numbers" would make the harness green and worthless.
package differential

import "net/http"

// Case is one request replayed against both control-planes.
type Case struct {
	// Name is the diff report's label.
	Name string
	// Method / Path are sent verbatim to both.
	Method string
	Path   string
	// Body is a JSON request body; empty sends none.
	Body string
	// Authed sends the debug-login session cookie. Cases that assert the UNAUTHENTICATED shape leave it
	// false, which is a distinct and equally important comparison.
	Authed bool
	// WantDivergence marks a case where the two are KNOWN to differ, with the reason. The harness then
	// FAILS IF THEY AGREE — so a documented divergence that gets fixed cannot silently stay documented.
	WantDivergence string
}

// AnonymousGETs are the parameterless GETs, replayed with NO session.
//
// 🔒 THE UNAUTHENTICATED SHAPE IS A CONTRACT, not an error path to skip. web reads `{"reason":"none"}`
// off a 401 to decide whether to route to /login, so a status or body difference here changes what the
// console does for every logged-out visitor.
var AnonymousGETs = []Case{
	{Name: "health", Method: http.MethodGet, Path: "/health"},
	{Name: "auth-config", Method: http.MethodGet, Path: "/auth/config"},
	{Name: "auth-me-anon", Method: http.MethodGet, Path: "/auth/me"},
	{Name: "session-status-anon", Method: http.MethodGet, Path: "/auth/session/status"},

	// The OAuth/OIDC discovery documents are served to unauthenticated clients by definition.
	{Name: "oauth-as-metadata", Method: http.MethodGet, Path: "/.well-known/oauth-authorization-server"},
	{Name: "oauth-prm", Method: http.MethodGet, Path: "/.well-known/oauth-protected-resource"},
	{Name: "oauth-prm-mcp", Method: http.MethodGet, Path: "/.well-known/oauth-protected-resource/mcp"},

	// Every admin surface, unauthenticated: the gate's answer is the subject.
	{Name: "datasources-anon", Method: http.MethodGet, Path: "/api/datasources"},
	{Name: "roles-anon", Method: http.MethodGet, Path: "/api/roles"},
	{Name: "policies-anon", Method: http.MethodGet, Path: "/api/policies"},
	{Name: "mask-fns-anon", Method: http.MethodGet, Path: "/api/mask-fns"},
	{Name: "role-assignments-anon", Method: http.MethodGet, Path: "/api/role-assignments"},
	{Name: "audit-anon", Method: http.MethodGet, Path: "/api/audit"},
	{Name: "approvals-anon", Method: http.MethodGet, Path: "/api/approvals"},
	{Name: "approvals-inbox-anon", Method: http.MethodGet, Path: "/api/approvals/inbox"},
	{Name: "access-requests-anon", Method: http.MethodGet, Path: "/api/access-requests"},
	{Name: "access-grants-anon", Method: http.MethodGet, Path: "/api/access-grants"},
	{Name: "query-history-anon", Method: http.MethodGet, Path: "/api/query-history"},
	{Name: "tokens-anon", Method: http.MethodGet, Path: "/api/tokens"},
	{Name: "me-permissions-anon", Method: http.MethodGet, Path: "/api/me/permissions"},
	{Name: "policies-schema-anon", Method: http.MethodGet, Path: "/api/policies/schema"},
	{Name: "datasources-live-anon", Method: http.MethodGet, Path: "/api/datasources/live"},
}

// AuthedGETs are the same surfaces WITH a debug-login session holding system:admin. Together with the
// anonymous set they bracket each gate: a route that answered identically to both would mean the gate
// is not gating.
var AuthedGETs = []Case{
	{Name: "auth-me", Method: http.MethodGet, Path: "/auth/me", Authed: true},
	{Name: "session-status", Method: http.MethodGet, Path: "/auth/session/status", Authed: true},
	{Name: "me-permissions", Method: http.MethodGet, Path: "/api/me/permissions", Authed: true},
	{Name: "datasources", Method: http.MethodGet, Path: "/api/datasources", Authed: true},
	{Name: "datasources-live", Method: http.MethodGet, Path: "/api/datasources/live", Authed: true},
	{Name: "roles", Method: http.MethodGet, Path: "/api/roles", Authed: true},
	{Name: "role-assignments", Method: http.MethodGet, Path: "/api/role-assignments", Authed: true},
	{Name: "mask-fns", Method: http.MethodGet, Path: "/api/mask-fns", Authed: true},
	{Name: "policies", Method: http.MethodGet, Path: "/api/policies", Authed: true},
	{Name: "policies-schema", Method: http.MethodGet, Path: "/api/policies/schema", Authed: true},
	{Name: "audit", Method: http.MethodGet, Path: "/api/audit", Authed: true},
	{Name: "approvals", Method: http.MethodGet, Path: "/api/approvals", Authed: true},
	{Name: "approvals-inbox", Method: http.MethodGet, Path: "/api/approvals/inbox", Authed: true},
	{Name: "access-requests", Method: http.MethodGet, Path: "/api/access-requests", Authed: true},
	{Name: "access-grants", Method: http.MethodGet, Path: "/api/access-grants", Authed: true},
	{Name: "query-history", Method: http.MethodGet, Path: "/api/query-history", Authed: true},
	{Name: "tokens", Method: http.MethodGet, Path: "/api/tokens", Authed: true},
	{Name: "users", Method: http.MethodGet, Path: "/api/users", Authed: true},
	{Name: "groups", Method: http.MethodGet, Path: "/api/groups", Authed: true},
}

// ErrorShapes are the malformed / not-found requests. These matter more than the happy paths for a
// port, because an error body is a stable dot-namespaced code the console looks up as an i18n key
// (AGENTS.md) — so a divergence here is a console that renders a raw key or nothing at all.
//
// 🔒 `params` IS PART OF THE SHAPE. Kotlin's ApiError carries a defaulted non-null map and
// encodeDefaults=true always emits it, so `{}` must be present rather than omitted (INV-A1-4).
var ErrorShapes = []Case{
	{Name: "bad-id-datasource", Method: http.MethodGet, Path: "/api/datasources/not-a-number", Authed: true},
	{Name: "bad-id-role", Method: http.MethodGet, Path: "/api/roles/not-a-number", Authed: true},
	{Name: "bad-id-audit", Method: http.MethodGet, Path: "/api/audit/not-a-number", Authed: true},
	{Name: "missing-datasource", Method: http.MethodGet, Path: "/api/datasources/999999", Authed: true},
	{Name: "missing-role", Method: http.MethodGet, Path: "/api/roles/999999", Authed: true},
	{Name: "unknown-route", Method: http.MethodGet, Path: "/api/does-not-exist", Authed: true},

	// A blank required field, and a malformed JSON body — two different rejection paths that both have
	// to produce the same code on both sides.
	{
		Name: "create-role-blank-name", Method: http.MethodPost, Path: "/api/roles",
		Body: `{"name":""}`, Authed: true,
	},
	{
		Name: "create-role-malformed-json", Method: http.MethodPost, Path: "/api/roles",
		Body: `{ this is not json`, Authed: true,
	},
	{
		Name: "debug-login-bad-requester-ip", Method: http.MethodPost, Path: "/auth/debug",
		// 🔒 `100.100.1.0/24` is THE literal that separates the two-stage storable-IP check from a naive
		// one: Cedar's ipaddr accepts a CIDR, and only the charset allowlist rejects it. Both sides must
		// answer 400 auth.invalid_requester_ip.
		Body: `{"principal":"x@example.com","requesterIp":"100.100.1.0/24"}`,
	},
}

// MethodMismatch measures what each plane does when a PATH exists but the METHOD does not.
//
// 🔒 THESE EXIST BECAUSE I GOT IT WRONG FROM THREE SAMPLES. The first differential run showed Kotlin
// answering 404 on `GET /api/roles/{id}` where Go answers 405, and I generalised that into "collapse
// every 405 into a bare 404" — which broke three existing tests that pin 405-with-Allow, one of which
// records that "Ktor gives 405 too (it answers 405 for a path that matches with no method handler)".
// Both observations can be true: Ktor's rule evidently depends on HOW the path matches, and three data
// points did not distinguish the shapes.
//
// So these cases MEASURE the rule across the shapes that differ, rather than asserting a guess:
//
//   - a literal path registered under exactly one method
//   - a literal path registered under several methods
//   - a PARAMETERISED path registered under some methods but not the one sent
//   - a parameterised path under a prefix that has its own literal route
//
// Whatever they report IS Ktor's rule, and the fix — if one is warranted — follows from that rather
// than from a convention or from my reading.
var MethodMismatch = []Case{
	// GET-only literal.
	{Name: "mm-post-to-get-only-literal", Method: http.MethodPost, Path: "/api/datasources/live", Authed: true},
	{Name: "mm-delete-to-get-only-literal", Method: http.MethodDelete, Path: "/api/policies/schema", Authed: true},
	// A literal that legitimately takes GET and POST — DELETE is the mismatch.
	{Name: "mm-delete-to-get-post-literal", Method: http.MethodDelete, Path: "/api/roles", Authed: true},
	{Name: "mm-put-to-get-post-literal", Method: http.MethodPut, Path: "/api/mask-fns", Authed: true},
	// PARAMETERISED paths: `{id}` exists for PUT/DELETE but not GET/POST/PATCH.
	{Name: "mm-get-to-param-put-delete", Method: http.MethodGet, Path: "/api/roles/1", Authed: true},
	{Name: "mm-post-to-param-put-delete", Method: http.MethodPost, Path: "/api/roles/1", Authed: true},
	{Name: "mm-patch-to-param-put-delete", Method: http.MethodPatch, Path: "/api/roles/1", Authed: true},
	{Name: "mm-get-to-param-mask-fns", Method: http.MethodGet, Path: "/api/mask-fns/1", Authed: true},
	// A parameterised path whose prefix HAS a GET literal (/api/audit and /api/audit/{id} both exist),
	// so this one should NOT be a mismatch — it is the control that proves the others are real.
	{Name: "mm-control-get-audit-id", Method: http.MethodGet, Path: "/api/audit/1", Authed: true},
	// An unrouted path under a routed prefix, and a method nobody registers anywhere.
	{Name: "mm-get-unrouted-under-prefix", Method: http.MethodGet, Path: "/api/roles/1/nope", Authed: true},
	{Name: "mm-options-to-literal", Method: http.MethodOptions, Path: "/api/roles", Authed: true},
	{Name: "mm-head-to-get-literal", Method: http.MethodHead, Path: "/api/roles", Authed: true},
}

// Writes are the mutating cases. They run LAST and in order, because each one's answer depends on the
// state the previous left behind — which is also why the harness runs them against both planes in
// lockstep rather than replaying one plane fully and then the other.
var Writes = []Case{
	{Name: "create-role", Method: http.MethodPost, Path: "/api/roles", Body: `{"name":"diff-role","description":"d"}`, Authed: true},
	{Name: "create-role-duplicate", Method: http.MethodPost, Path: "/api/roles", Body: `{"name":"diff-role","description":"d"}`, Authed: true},
	{Name: "list-roles-after-create", Method: http.MethodGet, Path: "/api/roles", Authed: true},
	{Name: "create-mask-fn", Method: http.MethodPost, Path: "/api/mask-fns", Body: `{"name":"diff-mask","kind":"partial"}`, Authed: true},
	{Name: "list-mask-fns-after-create", Method: http.MethodGet, Path: "/api/mask-fns", Authed: true},
	{
		Name: "create-cedar-policy", Method: http.MethodPost, Path: "/api/policies", Authed: true,
		Body: `{"name":"diff-policy","cedarSrc":"permit(principal, action == Action::\"datasource.connect\", resource);"}`,
	},
	{
		Name: "create-cedar-policy-malformed", Method: http.MethodPost, Path: "/api/policies", Authed: true,
		Body: `{"name":"diff-bad","cedarSrc":"this is not cedar"}`,
		// Both answer 400 with the same `{"errors":[…]}` shape; only the MESSAGE differs, because it is
		// passed through verbatim from the Cedar parser and cedar-java and cedar-go word their diagnostics
		// differently:
		//   kotlin: failed to parse policy with id `candidate` from string: unexpected token `is`
		//   go:     parse error at <input>:1:6 "is": unexpected effect: this
		// Not reconcilable without reformatting another library's diagnostics, and the console renders the
		// string as opaque detail. Recorded rather than normalised away, so if the texts ever DO converge
		// this case fails and the note gets deleted.
		WantDivergence: "cedar-java and cedar-go word parse diagnostics differently; the shape and status match",
	},
	{Name: "create-role-assignment", Method: http.MethodPost, Path: "/api/role-assignments", Body: `{"principal":"diff@example.com","roleId":1}`, Authed: true},
	{Name: "create-role-assignment-again", Method: http.MethodPost, Path: "/api/role-assignments", Body: `{"principal":"diff@example.com","roleId":1}`, Authed: true},
}

// Round2 widens the surface: the parameterised routes driven with REAL ids, the full PUT/DELETE
// lifecycle, SCIM, and the validation shapes the first round did not reach.
//
// 🔒 THE IDS ARE THE SEEDED ONES, not ids created by this corpus. V8__seed.sql gives both planes the same
// starting rows (role 1 = system:admin), so `1` addresses the same entity on each. A case that needed an
// id the corpus created would compare two different rows and report noise.
var Round2 = []Case{
	// --- parameterised reads that DO exist on both -------------------------------------------------
	{Name: "r2-datasource-by-id-missing", Method: http.MethodGet, Path: "/api/datasources/1", Authed: true},
	{Name: "r2-audit-by-id-missing", Method: http.MethodGet, Path: "/api/audit/1", Authed: true},
	{Name: "r2-audit-by-id-zero", Method: http.MethodGet, Path: "/api/audit/0", Authed: true},
	{Name: "r2-audit-by-id-negative", Method: http.MethodGet, Path: "/api/audit/-1", Authed: true},
	{Name: "r2-audit-by-id-overflow", Method: http.MethodGet, Path: "/api/audit/99999999999999999999", Authed: true},

	// --- the PUT / DELETE lifecycle on a seeded row ------------------------------------------------
	// 🔒 role 1 is `system:admin`, a SYSTEM role: both planes must refuse to mutate it, and with the same
	// code. This is INV-A9-1's guard observed end to end rather than through a store test.
	{Name: "r2-put-system-role", Method: http.MethodPut, Path: "/api/roles/1", Body: `{"name":"renamed"}`, Authed: true},
	{Name: "r2-delete-system-role", Method: http.MethodDelete, Path: "/api/roles/1", Authed: true},
	{Name: "r2-put-missing-role", Method: http.MethodPut, Path: "/api/roles/999999", Body: `{"name":"x"}`, Authed: true},
	{Name: "r2-delete-missing-role", Method: http.MethodDelete, Path: "/api/roles/999999", Authed: true},
	{Name: "r2-put-role-blank-name", Method: http.MethodPut, Path: "/api/roles/1", Body: `{"name":""}`, Authed: true},
	{Name: "r2-put-role-bad-id", Method: http.MethodPut, Path: "/api/roles/nope", Body: `{"name":"x"}`, Authed: true},
	{Name: "r2-delete-mask-fn-missing", Method: http.MethodDelete, Path: "/api/mask-fns/999999", Authed: true},
	{Name: "r2-delete-role-assignment-missing", Method: http.MethodDelete, Path: "/api/role-assignments/999999", Authed: true},

	// --- policies: the system-policy guard and the id shapes ---------------------------------------
	// 🔒 The seed carries SYSTEM policies at NEGATIVE ids (-300 etc., seen in the live run). Both planes
	// must refuse to mutate or delete one.
	{Name: "r2-delete-system-policy", Method: http.MethodDelete, Path: "/api/policies/-300", Authed: true},
	{Name: "r2-put-system-policy", Method: http.MethodPut, Path: "/api/policies/-300", Body: `{"name":"x","cedarSrc":"permit(principal, action, resource);"}`, Authed: true},
	{Name: "r2-get-policy-missing", Method: http.MethodGet, Path: "/api/policies/999999", Authed: true},
	{Name: "r2-delete-policy-missing", Method: http.MethodDelete, Path: "/api/policies/999999", Authed: true},

	// --- validation shapes round 1 did not reach ---------------------------------------------------
	{Name: "r2-create-role-no-body", Method: http.MethodPost, Path: "/api/roles", Authed: true},
	{Name: "r2-create-role-empty-object", Method: http.MethodPost, Path: "/api/roles", Body: `{}`, Authed: true},
	{Name: "r2-create-role-null-name", Method: http.MethodPost, Path: "/api/roles", Body: `{"name":null}`, Authed: true},
	{Name: "r2-create-role-wrong-type", Method: http.MethodPost, Path: "/api/roles", Body: `{"name":123}`, Authed: true},
	{Name: "r2-create-role-array-body", Method: http.MethodPost, Path: "/api/roles", Body: `[]`, Authed: true},
	{Name: "r2-create-mask-fn-blank-kind", Method: http.MethodPost, Path: "/api/mask-fns", Body: `{"name":"k","kind":""}`, Authed: true},
	{Name: "r2-create-assignment-missing-role", Method: http.MethodPost, Path: "/api/role-assignments", Body: `{"principal":"p@example.com","roleId":999999}`, Authed: true},
	{Name: "r2-create-assignment-blank-principal", Method: http.MethodPost, Path: "/api/role-assignments", Body: `{"principal":"","roleId":1}`, Authed: true},

	// --- /api/role-assignments' documented quirk ---------------------------------------------------
	// ⚠️ INV-A9-4: a MALFORMED roleId returns `[]` rather than 400 common.bad_id, unlike every other
	// id-taking route. A port that "fixed" that inconsistency would break whatever in web relies on it,
	// so both planes must show the same quirk.
	{Name: "r2-assignments-bad-roleid", Method: http.MethodGet, Path: "/api/role-assignments?roleId=nope", Authed: true},
	{Name: "r2-assignments-filter-roleid", Method: http.MethodGet, Path: "/api/role-assignments?roleId=1", Authed: true},
	{Name: "r2-assignments-filter-principal", Method: http.MethodGet, Path: "/api/role-assignments?principal=nobody@example.com", Authed: true},

	// --- SCIM: gated by a bearer, so the unauthenticated shape is the subject ----------------------
	{Name: "r2-scim-users-nobearer", Method: http.MethodGet, Path: "/scim/v2/Users"},
	{Name: "r2-scim-groups-nobearer", Method: http.MethodGet, Path: "/scim/v2/Groups"},
	{Name: "r2-scim-user-by-id-nobearer", Method: http.MethodGet, Path: "/scim/v2/Users/1"},
	{Name: "r2-scim-users-badbearer", Method: http.MethodGet, Path: "/scim/v2/Users", Body: ""},

	// --- query params and encoding -----------------------------------------------------------------
	{Name: "r2-audit-limit-nonnumeric", Method: http.MethodGet, Path: "/api/audit?limit=abc", Authed: true},
	{Name: "r2-audit-limit-negative", Method: http.MethodGet, Path: "/api/audit?limit=-5", Authed: true},
	{Name: "r2-audit-limit-huge", Method: http.MethodGet, Path: "/api/audit?limit=999999", Authed: true},
	{Name: "r2-datasources-unknown-param", Method: http.MethodGet, Path: "/api/datasources?bogus=1", Authed: true},

	// --- the session surface -----------------------------------------------------------------------
	{Name: "r2-heartbeat-anon", Method: http.MethodPost, Path: "/auth/session/heartbeat"},
	{Name: "r2-heartbeat-authed", Method: http.MethodPost, Path: "/auth/session/heartbeat", Authed: true},
	{Name: "r2-logout-anon", Method: http.MethodPost, Path: "/auth/logout"},
	{Name: "r2-debug-blank-principal", Method: http.MethodPost, Path: "/auth/debug", Body: `{"principal":""}`},
	{Name: "r2-debug-no-body", Method: http.MethodPost, Path: "/auth/debug"},
}

// Round3 measures the two questions round 2 left open, on the routes they actually reach.
//
// 🔒 THE INGEST ROUTE IS HERE BECAUSE A GUESS ABOUT IT WAS ALREADY WRONG ONCE. Putting the 415
// content-type gate inside the shared httpapi.Receive turned `POST /api/ingest/decision` from an
// authorized 202 into a 400, and nothing in the repo says whether goproxy sends a Content-Type. So the
// rule gets measured on the route rather than inferred from two others.
//
// ⚠️ Both ingest cases send NO secret header, so they exercise the GATE, not the body. That is
// deliberate: the token check runs before the body is read, so an unauthenticated probe measures the
// gate's answer without depending on what a real proxy sends.
var Round3 = []Case{
	{Name: "r3-ingest-anon-nobody", Method: http.MethodPost, Path: "/api/ingest/decision"},
	{Name: "r3-ingest-anon-withbody", Method: http.MethodPost, Path: "/api/ingest/decision",
		Body: `{"principal":"p@example.com","datasource":"ds","statement":"select 1","decision":"ALLOW"}`},

	// The required-field question, across the DTOs that differ in shape: one required string, a
	// required string plus a required list, and a nested object.
	{Name: "r3-mask-fn-missing-name", Method: http.MethodPost, Path: "/api/mask-fns", Body: `{"kind":"partial"}`, Authed: true},
	{Name: "r3-mask-fn-missing-kind", Method: http.MethodPost, Path: "/api/mask-fns", Body: `{"name":"m"}`, Authed: true},
	{Name: "r3-policy-missing-src", Method: http.MethodPost, Path: "/api/policies", Body: `{"name":"p"}`, Authed: true},
	{Name: "r3-policy-missing-name", Method: http.MethodPost, Path: "/api/policies", Body: `{"cedarSrc":"permit(principal, action, resource);"}`, Authed: true},
	{Name: "r3-assignment-missing-principal", Method: http.MethodPost, Path: "/api/role-assignments", Body: `{"roleId":1}`, Authed: true},
	{Name: "r3-assignment-missing-roleid", Method: http.MethodPost, Path: "/api/role-assignments", Body: `{"principal":"p@example.com"}`, Authed: true},
	{Name: "r3-debug-missing-principal", Method: http.MethodPost, Path: "/auth/debug", Body: `{"roles":["system:admin"]}`},

	// And the same DTOs with an explicit null, which kotlinx treats differently from absent for a
	// non-nullable field.
	{Name: "r3-mask-fn-null-kind", Method: http.MethodPost, Path: "/api/mask-fns", Body: `{"name":"m","kind":null}`, Authed: true},
	{Name: "r3-policy-null-src", Method: http.MethodPost, Path: "/api/policies", Body: `{"name":"p","cedarSrc":null}`, Authed: true},
	{Name: "r3-debug-null-principal", Method: http.MethodPost, Path: "/auth/debug", Body: `{"principal":null}`},
}

// All is the full corpus in execution order: read-only first, then errors, then writes.
func All() []Case {
	out := make([]Case, 0, len(AnonymousGETs)+len(AuthedGETs)+len(ErrorShapes)+len(MethodMismatch)+len(Round2)+len(Round3)+len(Writes))
	out = append(out, AnonymousGETs...)
	out = append(out, AuthedGETs...)
	out = append(out, ErrorShapes...)
	out = append(out, MethodMismatch...)
	out = append(out, Round2...)
	out = append(out, Round3...)
	out = append(out, Writes...)
	return out
}
