package policy

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
)

// ---------------------------------------------------------------------------------------------
// `/api/policies` — 02-authz.md §8's eight routes.
//
// ORACLE: 02-authz.md §8's route table (:502-511) for the eight paths and their success statuses,
// and §10's `CedarPolicyRoutesTest.kt` (5 cases, :625-631) for the behaviours the Kotlin asserts.
// Cited per case. No JVM here, so those enumerations are the oracle rather than a recorded run.
//
// The five Kotlin cases map onto the tests below as:
//
//	1 list exposes system provenance without accepting it in input  → TestListExposesSystemProvenance…
//	                                                                  + TestCreateIgnoresAnOriginClaim…
//	2 POST and USER rename reject the reserved `system:` namespace  → TestCreateRejectsTheReserved…
//	3 PUT and DELETE of a system policy return the 409 conflict     → TestUpdateAndDeleteOfASystem…
//	4 enable and disable remain available for system policies       → TestEnableAndDisableRemain…
//	5 REST mutation stays bound to its numeric id after name reuse  → TestPolicyMutationStaysBound…
//
// Everything else is NEW: the gate map, the statuses the table gives but no Kotlin case reads, and
// the two bodies that are deliberately NOT ApiError.
// ---------------------------------------------------------------------------------------------

// The eight routes, as (method, path) pairs, for the gate sweep.
//
// 🔒 A sweep rather than eight hand-written gate cases, because the claim in 02-authz.md:496 is
// universal — "EVERY route gated `requireAdmin(config, authz, ADMIN_POLICIES)`, INCLUDING THE TWO
// READ-ONLY ONES" — and a hand-written list is exactly how the ninth route added next year ships
// ungated. Adding a route to Register without adding it here leaves it unswept, which is the residual
// gap; TestEveryRegisteredPolicyPatternIsSwept closes it by counting.
var cedarPolicyRoutes = []struct {
	method string
	path   string
	body   string
}{
	{http.MethodGet, "/api/policies", ""},
	{http.MethodPost, "/api/policies", `{"name":"gate-probe","cedarSrc":"` + validCedarSrcJSON + `"}`},
	{http.MethodPut, "/api/policies/1", `{"name":"gate-probe","cedarSrc":"` + validCedarSrcJSON + `"}`},
	{http.MethodDelete, "/api/policies/1", ""},
	{http.MethodPost, "/api/policies/validate", `{"cedarSrc":"` + validCedarSrcJSON + `"}`},
	{http.MethodGet, "/api/policies/schema", ""},
	{http.MethodPost, "/api/policies/1/enable", ""},
	{http.MethodPost, "/api/policies/1/disable", ""},
}

// validCedarSrcJSON is validCedarSrc with its double quotes escaped, for embedding in a JSON literal.
const validCedarSrcJSON = `permit(principal in Role::\"tester\", action == Action::\"audit.read\", resource);`

// ---- The gate ------------------------------------------------------------------------------------

// 🔒 Every one of the eight demands `admin.policies` on the System resource, and nothing else.
//
// Recording WHICH action is the point. A route that gated on `admin.identity` instead would answer
// 200 for exactly the same admin session and would be invisible to a test that only checked the
// status — and the split between `admin.policies` and `admin.identity` is real in this very package
// (A9's assignment routes take the other one).
func TestEveryPolicyRouteDemandsAdminPoliciesOnSystem(t *testing.T) {
	f := newRouteFixture(t)
	cookie := f.login("admin@example.com")

	for _, rt := range cedarPolicyRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			f.authz.allowed = true
			f.authz.reset()

			f.do(rt.method, rt.path, rt.body, cookie)

			if got := f.authz.only(t); got != authz.ActionAdminPolicies {
				t.Errorf("action: got %v, want ActionAdminPolicies", got)
			}
			if _, ok := f.authz.resources[0].(authz.ResourceSystem); !ok {
				t.Errorf("resource: got %T, want authz.ResourceSystem", f.authz.resources[0])
			}
		})
	}
}

// A Cedar DENY is 403 `common.forbidden` carrying Cedar's own reason in `params.detail`, and the
// handler must not have run.
func TestEveryPolicyRouteAnswers403WhenCedarDenies(t *testing.T) {
	f := newRouteFixture(t)
	cookie := f.login("nobody@example.com")

	for _, rt := range cedarPolicyRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			f.authz.allowed = false
			f.authz.reset()

			rec := f.do(rt.method, rt.path, rt.body, cookie)

			assertStatus(t, rec, http.StatusForbidden, "denied")
			body := assertAPIError(t, rec, "common.forbidden", "denied")
			if body.Params["detail"] != f.authz.reason {
				t.Errorf("params.detail: got %q, want Cedar's reason %q", body.Params["detail"], f.authz.reason)
			}
		})
	}
}

// No session at all is 401 `common.unauthenticated`, BEFORE Cedar is consulted — requireAuthz step 2
// precedes step 3, and a port that asked Cedar about an empty principal would leak whether a policy
// happens to permit the anonymous one.
func TestEveryPolicyRouteAnswers401WithNoSession(t *testing.T) {
	f := newRouteFixture(t)

	for _, rt := range cedarPolicyRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			f.authz.allowed = true
			f.authz.reset()

			rec := f.do(rt.method, rt.path, rt.body)

			assertStatus(t, rec, http.StatusUnauthorized, "no session")
			assertAPIError(t, rec, "common.unauthenticated", "no session")
			if len(f.authz.actions) != 0 {
				t.Errorf("Cedar was consulted %d times for an unauthenticated request", len(f.authz.actions))
			}
		})
	}
}

// The sweep above is only as complete as its list. This counts the patterns Register actually mounts
// and demands the list cover every one, so adding a route without adding a gate case fails HERE
// rather than silently shipping ungated.
func TestEveryRegisteredPolicyPatternIsSwept(t *testing.T) {
	mux := http.NewServeMux()
	NewCedarPolicyRoutes(nil, nil, nil).Register(mux)

	// ServeMux has no pattern enumeration, so the count is asserted against the file it comes from:
	// eight HandleFunc calls in Register, eight rows in cedarPolicyRoutes.
	const registered = 8
	if len(cedarPolicyRoutes) != registered {
		t.Fatalf("cedarPolicyRoutes has %d rows; CedarPolicyRoutes.Register mounts %d patterns. "+
			"Every mounted route must appear in the gate sweep.", len(cedarPolicyRoutes), registered)
	}
	// And every row must actually resolve to a handler, which is what catches a typo in the list.
	for _, rt := range cedarPolicyRoutes {
		r, err := http.NewRequest(rt.method, rt.path, nil)
		if err != nil {
			t.Fatalf("build %s %s: %v", rt.method, rt.path, err)
		}
		if h, pattern := mux.Handler(r); h == nil || pattern == "" {
			t.Errorf("%s %s matches no registered pattern", rt.method, rt.path)
		}
	}
}

// ---- GET /api/policies ---------------------------------------------------------------------------

// `CedarPolicyRoutesTest` case 1, first half — "list EXPOSES system provenance". The console renders
// a padlock next to migration-owned rows and needs `origin` and `systemKey` to do it.
//
// 🔒 The order is `ORDER BY id`, and SYSTEM rows carry NEGATIVE ids, so every shipped row sorts
// before every user one. That is the order the console renders, and cedarwrite.go:96-99 says so.
func TestListExposesSystemProvenanceAndOrdersSystemRowsFirst(t *testing.T) {
	f := newRouteFixture(t)
	f.seedUserPolicy("zzz-user-policy", validCedarSrc)

	rec := f.admin(http.MethodGet, "/api/policies", "")
	assertStatus(t, rec, http.StatusOK, "list")

	var got []CedarPolicy
	decodeJSON(t, rec, &got)
	if len(got) < 2 {
		t.Fatalf("the seed ships SYSTEM policies; got %d rows", len(got))
	}
	if got[0].Origin != SystemPolicyOrigin {
		t.Errorf("first row origin: got %q, want SYSTEM (negative ids sort first)", got[0].Origin)
	}
	if got[0].SystemKey == nil {
		t.Error("a SYSTEM row must expose its systemKey")
	}
	last := got[len(got)-1]
	if last.Origin != UserPolicyOrigin || last.Name != "zzz-user-policy" {
		t.Errorf("last row: got %+v, want the USER policy", last)
	}
	if last.SystemKey != nil {
		t.Errorf("a USER row has no systemKey; got %q", *last.SystemKey)
	}
	// The whole list is sorted ascending by id.
	for i := 1; i < len(got); i++ {
		if got[i].ID <= got[i-1].ID {
			t.Fatalf("list is not ORDER BY id: %d follows %d", got[i].ID, got[i-1].ID)
		}
	}
}

// ---- POST /api/policies --------------------------------------------------------------------------

// The success status is **201**, not 200 (02-authz.md:505).
func TestCreatePolicyAnswers201(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/policies",
		`{"name":"created","cedarSrc":"`+validCedarSrcJSON+`"}`)

	assertStatus(t, rec, http.StatusCreated, "create")
	var got CedarPolicy
	decodeJSON(t, rec, &got)
	if got.Name != "created" || got.ID <= 0 {
		t.Errorf("body: %+v", got)
	}
	if got.UpdatedBy == nil || *got.UpdatedBy != "admin@example.com" {
		t.Errorf("updatedBy: got %v, want the session principal", got.UpdatedBy)
	}
}

// 🔒 `CedarPolicyRoutesTest` case 1, second half — "WITHOUT ACCEPTING IT IN INPUT". A POST body that
// claims `origin: "SYSTEM"` and a `systemKey` is not merely rejected: those keys are not fields of
// CedarPolicyInput at all, so they are IGNORED and the row is written 'USER'.
//
// The distinction matters for the reason cedardto.go:20-24 gives: reusing one struct for both
// directions would let the claim through to the INSERT, and V3__policy.sql's CHECK constraints would
// then reject it with a 500 instead of ignoring it.
func TestCreateIgnoresAnOriginClaimInTheRequestBody(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/policies",
		`{"name":"claims-system","cedarSrc":"`+validCedarSrcJSON+`","origin":"SYSTEM","systemKey":"forged","id":-999}`)

	assertStatus(t, rec, http.StatusCreated, "create with a forged origin")
	var got CedarPolicy
	decodeJSON(t, rec, &got)
	if got.Origin != UserPolicyOrigin {
		t.Errorf("origin: got %q, want USER — the input DTO has no origin field", got.Origin)
	}
	if got.SystemKey != nil {
		t.Errorf("systemKey: got %q, want nil", *got.SystemKey)
	}
	if got.ID <= 0 {
		t.Errorf("id: got %d, want one from the positive USER sequence", got.ID)
	}
}

// `enabled` defaults to TRUE when the key is absent — kotlinx applies the declared default, and
// CedarPolicyInput.UnmarshalJSON reproduces it. Go's zero value is false, so a naive decode would
// create every policy DISABLED and nothing would notice until a grant stopped applying.
func TestCreateDefaultsEnabledToTrueWhenTheKeyIsAbsent(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/policies", `{"name":"defaulted","cedarSrc":"`+validCedarSrcJSON+`"}`)
	assertStatus(t, rec, http.StatusCreated, "create with no enabled key")

	var got CedarPolicy
	decodeJSON(t, rec, &got)
	if !got.Enabled {
		t.Error("an absent `enabled` must default to TRUE, not to Go's zero value")
	}

	// An EXPLICIT false is still false — the defaulting must not clobber a stated value.
	rec = f.admin(http.MethodPost, "/api/policies",
		`{"name":"explicitly-off","cedarSrc":"`+validCedarSrcJSON+`","enabled":false}`)
	assertStatus(t, rec, http.StatusCreated, "create with enabled:false")
	decodeJSON(t, rec, &got)
	if got.Enabled {
		t.Error("an explicit `enabled: false` must be honoured")
	}
}

// 🔒 `CedarPolicyRoutesTest` case 2, first half — "POST … rejects the reserved `system:` namespace".
//
// ⚠️ The status is 400, not 409, and that is not an oversight: `policy.reserved_name` is not an arm
// of respondManagementError's switch, so it takes the DEFAULT — and the default is 400 precisely
// because a management service raises a code when it has decided the REQUEST is at fault
// (httpapi.RespondManagementError).
func TestCreateRejectsTheReservedSystemNamespace(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/policies",
		`{"name":"system:forged","cedarSrc":"`+validCedarSrcJSON+`"}`)

	assertStatus(t, rec, http.StatusBadRequest, "reserved name")
	body := assertAPIError(t, rec, "policy.reserved_name", "reserved name")
	if body.Params["name"] != "system:forged" {
		t.Errorf("params.name: got %q, want the offending name", body.Params["name"])
	}
}

// ⚠️ D6 DIVERGENCE, PINNED NOT FIXED — cedarroutes.go:231-237.
//
// Go's decoder is LOOSER than kotlinx about a MISSING non-defaulted field: `{"cedarSrc":"…"}` with
// no `name` decodes cleanly to Name:"" and creates a policy named "" (201), where kotlinx throws
// MissingFieldException and the Kotlin answers 500 common.fallback.
//
// This is the pin cedarroutes.go names by exactly this test name. Fixing the divergence needs a
// required-field check encoding/json cannot express, and inventing one would change WHICH status a
// bad body gets on ~120 routes at once — so the day A1 adds required-field decoding, THIS TEST is
// what changes, deliberately.
func TestCreatePolicyWithNoNameFieldIsAcceptedByGo(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/policies", `{"cedarSrc":"`+validCedarSrcJSON+`"}`)

	assertStatus(t, rec, http.StatusCreated, "missing required field")
	var got CedarPolicy
	decodeJSON(t, rec, &got)
	if got.Name != "" {
		t.Errorf("name: got %q, want \"\" — Go decodes the absent key to the zero value", got.Name)
	}
	t.Log("DIVERGENCE (recorded, not fixed): kotlinx would throw MissingFieldException here and the " +
		"Kotlin would answer 500 common.fallback. See TODO(A1) in cedarroutes.go:239.")
}

// A body that is not JSON at all IS caught, and answers 500 common.fallback — not 400.
//
// ⚠️ That is the Kotlin's behaviour, reproduced rather than improved: the route has no catch for a
// deserialization failure, so App.kt:460's `exception<Throwable>` answers the fallback. Turning it
// into a 400 would stop the web being able to tell "the server rejected my body" from "the server
// broke" — a distinction it currently does not have and must not silently gain.
func TestAMalformedJsonBodyAnswersTheFallbackNotABadRequest(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/policies", `{"name": `)

	assertStatus(t, rec, http.StatusInternalServerError, "malformed JSON")
	assertAPIError(t, rec, "common.fallback", "malformed JSON")
}

// ---- PUT / DELETE --------------------------------------------------------------------------------

// 🔒 `CedarPolicyRoutesTest` case 3 — "PUT and DELETE of a system policy return the immutable
// conflict (409)". `policy.system_immutable` IS an arm of respondManagementError's switch, which is
// what makes it 409 where `policy.reserved_name` is 400.
func TestUpdateAndDeleteOfASystemPolicyAnswer409(t *testing.T) {
	f := newRouteFixture(t)
	id := strconv.FormatInt(seededSystemPolicyID, 10)

	rec := f.admin(http.MethodPut, "/api/policies/"+id,
		`{"name":"system:admin","cedarSrc":"`+validCedarSrcJSON+`"}`)
	assertStatus(t, rec, http.StatusConflict, "PUT a SYSTEM policy")
	assertAPIError(t, rec, "policy.system_immutable", "PUT a SYSTEM policy")

	rec = f.admin(http.MethodDelete, "/api/policies/"+id, "")
	assertStatus(t, rec, http.StatusConflict, "DELETE a SYSTEM policy")
	assertAPIError(t, rec, "policy.system_immutable", "DELETE a SYSTEM policy")
}

// An unparseable id is 400 `common.bad_id`, answered by idParam BEFORE the store is touched — the
// same `val id = call.idParam() ?: return@put call.badId()` every id-taking route in the port opens
// with.
func TestAnUnparseablePolicyIdIsBadIdOnEveryIdTakingRoute(t *testing.T) {
	f := newRouteFixture(t)

	for _, probe := range []struct{ method, path, body string }{
		{http.MethodPut, "/api/policies/abc", `{"name":"x","cedarSrc":"` + validCedarSrcJSON + `"}`},
		{http.MethodDelete, "/api/policies/abc", ""},
		{http.MethodPost, "/api/policies/abc/enable", ""},
		{http.MethodPost, "/api/policies/abc/disable", ""},
	} {
		t.Run(probe.method+" "+probe.path, func(t *testing.T) {
			rec := f.admin(probe.method, probe.path, probe.body)
			assertStatus(t, rec, http.StatusBadRequest, "bad id")
			assertAPIError(t, rec, "common.bad_id", "bad id")
		})
	}
}

// DELETE succeeds with **204** and NO body. An empty body is part of the contract: 204 with content
// is malformed HTTP, and a console that read the body would get "" rather than a policy.
func TestDeletePolicyAnswers204WithNoBody(t *testing.T) {
	f := newRouteFixture(t)
	created := f.seedUserPolicy("deleteme", validCedarSrc)

	rec := f.admin(http.MethodDelete, "/api/policies/"+strconv.FormatInt(created.ID, 10), "")

	assertStatus(t, rec, http.StatusNoContent, "delete")
	if rec.Body.Len() != 0 {
		t.Errorf("204 must carry no body, got %q", rec.Body.String())
	}
	if got := f.mustGetPolicy(created.ID); got != nil {
		t.Error("the row survived the delete")
	}
}

// ⚠️ THE MISSING-ROW ANSWER IS INFERRED, and this test is the pin management_crud.go:174-176 names.
//
// 02-authz.md §8's route table gives DELETE only a success column, so neither reading is stated:
// (a) 404 common.not_found, matching A3's identical management layer for DELETE /api/users/{id};
// (b) an unconditional 204, the F76 precedent. (a) is reproduced. A cutover correction must edit
// this test deliberately rather than quietly change a status.
func TestDeletePolicyAnswersNotFoundForMissingId(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodDelete, "/api/policies/987654", "")

	assertStatus(t, rec, http.StatusNotFound, "delete a missing id")
	body := assertAPIError(t, rec, "common.not_found", "delete a missing id")
	if body.Params["resource"] != ResourcePolicy {
		t.Errorf("params.resource: got %q, want %q", body.Params["resource"], ResourcePolicy)
	}
	t.Log("INFERRED, not quoted by the spec set. TODO(A11): confirm against a running Kotlin control " +
		"plane at cutover — management_crud.go:174-176.")
}

// 🔒 `CedarPolicyRoutesTest` case 5 — "REST-shaped policy mutation remains bound to its NUMERIC ID
// after name reuse".
//
// The scenario: create A, delete it, create B under A's old name. A PUT against A's id must 404
// rather than reaching B. Nothing in the path re-resolves by name (management_crud.go:120-122), and
// the day something does, a rename-and-recreate would silently redirect an admin's edit onto a
// different policy.
func TestPolicyMutationStaysBoundToItsNumericIdAfterNameReuse(t *testing.T) {
	f := newRouteFixture(t)

	first := f.seedUserPolicy("recycled-name", validCedarSrc)
	if _, err := f.policies.Delete(f.ctx, first.ID); err != nil {
		t.Fatalf("delete the first policy: %v", err)
	}
	second := f.seedUserPolicy("recycled-name", validCedarSrc)
	if second.ID == first.ID {
		t.Fatal("the BIGSERIAL sequence must not reuse the id; the case is vacuous if it does")
	}

	rec := f.admin(http.MethodPut, "/api/policies/"+strconv.FormatInt(first.ID, 10),
		`{"name":"recycled-name","cedarSrc":"`+validCedarSrcJSON+`"}`)

	assertStatus(t, rec, http.StatusNotFound, "PUT the dead id")
	assertAPIError(t, rec, "common.not_found", "PUT the dead id")

	// And the live row is untouched.
	if got := f.mustGetPolicy(second.ID); got == nil || got.Name != "recycled-name" {
		t.Errorf("the surviving policy was disturbed: %+v", got)
	}
}

// ---- validate / schema ---------------------------------------------------------------------------

// 🔒 BOTH outcomes are 200. An invalid source is `{"valid":false,"errors":[…]}` at 200, never a 400:
// the route asked "would this compile", and "no" is a successful answer. Only validate-on-WRITE turns
// the same list into a 400.
func TestValidateAnswers200ForBothOutcomes(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/policies/validate", `{"cedarSrc":"`+validCedarSrcJSON+`"}`)
	assertStatus(t, rec, http.StatusOK, "valid source")
	if got := rec.Body.String(); got != `{"valid":true,"errors":[]}` {
		t.Errorf("valid body: got %s, want {\"valid\":true,\"errors\":[]}", got)
	}

	rec = f.admin(http.MethodPost, "/api/policies/validate", `{"cedarSrc":"permit(principal, action =="}`)
	assertStatus(t, rec, http.StatusOK, "invalid source")
	var result CedarValidateResult
	decodeJSON(t, rec, &result)
	if result.Valid {
		t.Error("valid: got true for an unparseable source")
	}
	if len(result.Errors) == 0 {
		t.Error("errors: an invalid source must carry the compiler's messages")
	}
}

// 🔒 INV-A1-4 — `errors` is a defaulted non-null list, so it is ALWAYS present as `[]` for the valid
// case. Go's nil slice would marshal as `null`, and the editor renders `errors.length` with no null
// check. Asserted as literal bytes above; asserted here as the ABSENCE of the null shape, which is
// the failure that would survive a semantic compare.
func TestValidateNeverEmitsNullForTheErrorList(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/policies/validate", `{"cedarSrc":"`+validCedarSrcJSON+`"}`)

	if strings.Contains(rec.Body.String(), "null") {
		t.Errorf("the empty error list must be [] and never null: %s", rec.Body.String())
	}
}

// GET /api/policies/schema serves the bundled schema text verbatim — 02-authz.md:447: "the schema is
// the authz model, not secret". Still behind requireAdmin like every other route in the group; the
// disclosure judgment is about what the schema REVEALS, not a decision to open the route.
func TestSchemaServesTheBundledSchemaText(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodGet, "/api/policies/schema", "")

	assertStatus(t, rec, http.StatusOK, "schema")
	var got CedarSchemaResult
	decodeJSON(t, rec, &got)
	if got.Schema != authz.SchemaSource {
		t.Error("the schema must be served verbatim from the embedded source")
	}
}

// The literal `/validate` and `/schema` segments sit alongside the `{id}` wildcard. Go 1.22+ patterns
// resolve that by SPECIFICITY, not registration order — a literal beats a wildcard — so
// `POST /api/policies/validate` reaches validate and never `{id}`.
//
// Worth pinning because the failure is silent: were the wildcard to win, `validate` would parse as an
// id, fail, and answer 400 common.bad_id — which reads like a client error rather than a routing bug.
func TestALiteralSegmentBeatsTheIdWildcard(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/policies/validate", `{"cedarSrc":"`+validCedarSrcJSON+`"}`)
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("`validate` was routed to the {id} handler: %s", rec.Body.String())
	}
	assertStatus(t, rec, http.StatusOK, "validate beats {id}")
}

// ---- enable / disable ------------------------------------------------------------------------------

// 🔒 `CedarPolicyRoutesTest` case 4 — "enable and disable REMAIN AVAILABLE for system policies".
// Neither goes through the immutability guard PUT and DELETE hit: a toggle is the ONE mutation a
// migration-owned row admits, and INV-A2-22's sentinel audit row is the price.
func TestEnableAndDisableRemainAvailableForSystemPolicies(t *testing.T) {
	f := newRouteFixture(t)
	id := strconv.FormatInt(seededSystemPolicyID, 10)

	rec := f.admin(http.MethodPost, "/api/policies/"+id+"/disable", "")
	assertStatus(t, rec, http.StatusOK, "disable a SYSTEM policy")
	var got CedarPolicy
	decodeJSON(t, rec, &got)
	if got.Enabled {
		t.Error("the toggle did not take effect")
	}

	rec = f.admin(http.MethodPost, "/api/policies/"+id+"/enable", "")
	assertStatus(t, rec, http.StatusOK, "enable a SYSTEM policy")
	decodeJSON(t, rec, &got)
	if !got.Enabled {
		t.Error("re-enabling did not take effect")
	}
}

// 🔒 INV-A2-21 AT THE ROUTE — and 🔒 THE SECOND EXEMPTION FROM INV-A1-13.
//
// 02-authz.md:511: "the validation-error body is `{errors: [...]}` — a BARE MAP, not `ApiError`. An
// exception to INV-A1-13; the messages are Cedar's own compiler output. Preserve the shape."
//
// So this asserts the ABSENCE of `code` as hard as the presence of `errors`. The policy editor
// renders one line per message; an ApiError with a joined `detail` would collapse them AND would
// file Cedar prose under an i18n key that does not exist.
func TestEnablingAMalformedPolicyAnswersTheBareErrorsMapNotAnApiError(t *testing.T) {
	f := newRouteFixture(t)
	id := f.rawInsertPolicy("malformed-via-route", invalidCedarSrc, false)

	rec := f.admin(http.MethodPost, "/api/policies/"+strconv.FormatInt(id, 10)+"/enable", "")

	assertStatus(t, rec, http.StatusBadRequest, "enable a malformed policy")

	var raw map[string]json.RawMessage
	decodeJSON(t, rec, &raw)
	if _, hasCode := raw["code"]; hasCode {
		t.Errorf("the validation body must NOT be an ApiError; it has a `code`: %s", rec.Body.String())
	}
	if _, hasParams := raw["params"]; hasParams {
		t.Errorf("the validation body must NOT be an ApiError; it has `params`: %s", rec.Body.String())
	}
	errs, ok := raw["errors"]
	if !ok {
		t.Fatalf("the body must be {\"errors\":[…]}: %s", rec.Body.String())
	}
	var messages []string
	if err := json.Unmarshal(errs, &messages); err != nil {
		t.Fatalf("`errors` must be an array of strings: %v", err)
	}
	if len(messages) == 0 {
		t.Error("the compiler's messages are what the editor renders; the array must not be empty")
	}
	if len(raw) != 1 {
		t.Errorf("the body is a ONE-key map; got keys %v", mapKeys(raw))
	}

	// 🔒 INV-A2-21's other half: the row STAYS disabled.
	if got := f.mustGetPolicy(id); got == nil || got.Enabled {
		t.Error("a rejected enable must leave the row disabled")
	}
}

// Disabling never validates, so the same malformed row disables cleanly with a 200 — the asymmetry
// that keeps a deployment able to turn off the very row breaking it.
func TestDisablingAMalformedPolicyThroughTheRouteSucceeds(t *testing.T) {
	f := newRouteFixture(t)
	id := f.rawInsertPolicy("malformed-enabled-via-route", invalidCedarSrc, true)

	rec := f.admin(http.MethodPost, "/api/policies/"+strconv.FormatInt(id, 10)+"/disable", "")

	assertStatus(t, rec, http.StatusOK, "disable a malformed policy")
	var got CedarPolicy
	decodeJSON(t, rec, &got)
	if got.Enabled {
		t.Error("the row must be disabled")
	}
}

// A toggle of a nonexistent id is the same inferred 404 the delete path answers.
func TestTogglingAMissingPolicyAnswersNotFound(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/policies/987654/enable", "")

	assertStatus(t, rec, http.StatusNotFound, "enable a missing id")
	assertAPIError(t, rec, "common.not_found", "enable a missing id")
}

// ---- fixture helpers -------------------------------------------------------------------------------

func (f *routeFixture) mustGetPolicy(id int64) *CedarPolicy {
	f.t.Helper()
	row, err := f.policies.Get(f.ctx, id)
	if err != nil {
		f.t.Fatalf("get policy %d: %v", id, err)
	}
	return row
}

// rawInsertPolicy writes a policy bypassing the store's guards — the only way to stage a
// stored-malformed row, since a create can never produce one.
func (f *routeFixture) rawInsertPolicy(name, src string, enabled bool) int64 {
	f.t.Helper()
	var id int64
	err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ($1, $2, $3, 'USER') RETURNING id`,
		name, src, enabled).Scan(&id)
	if err != nil {
		f.t.Fatalf("raw insert %s: %v", name, err)
	}
	return id
}

func mapKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
