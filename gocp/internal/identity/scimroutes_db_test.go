package identity_test

import (
	"net/http"
	"sort"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// 🔴 NEW — the fifteen SCIM routes of `Scim.kt:320-594`, which 03-identity-scim.md coverage gap 6
// calls "the largest untested surface in A3 and … the wire contract web/-adjacent IdPs consume".
// ScimAuthTest drives the GATE through a stand-in `/probe`; nothing drives a real route.
// ---------------------------------------------------------------------------------------------

// mutability is the scimType every Group mutation answers on a SYSTEM group — except DELETE, which
// carries NONE (F26).
var mutability = types.Ptr("mutability")

// 🔒 F33 / INV-A3-38 — THE SCIM GATE HAS NO PM_AUTH_DEBUG BYPASS, and this is the ROUTE-level pin.
// AGENTS.md and docs/authz-model.md:363 both say "PM_AUTH_DEBUG short-circuits all four"; the CODE
// says otherwise and the code is right. A port that implements the documentation makes a dev-mode
// control plane accept unauthenticated directory writes over plaintext.
//
// Every case here runs with AuthDebug ON, exactly as ScimAuthTest.kt:106,111's fixture does, and
// still expects 501/403/401.
func TestScimRoutesHaveNoAuthDebugBypass(t *testing.T) {
	f := newRouteFixture(t)
	f.enableAuthDebug()

	// 403 — plaintext, WITH the correct bearer. 🔒 INV-A3-37: the TLS check precedes the bearer check,
	// so the secret is never compared on a wire-visible request.
	req := newRequest(http.MethodGet, "/api/scim/v2/Users", "")
	req.Header.Set("Authorization", "Bearer "+scimBearer)
	assertScimError(t, f.do(req), http.StatusForbidden, nil, "SCIM requires TLS", "plaintext with a good bearer")

	// 403 — an X-Forwarded-Proto from an UNTRUSTED peer does not satisfy the gate. INV-A3-39.
	req = newRequest(http.MethodGet, "/api/scim/v2/Users", "")
	req.Header.Set("Authorization", "Bearer "+scimBearer)
	req.Header.Set("X-Forwarded-Proto", "https")
	assertScimError(t, f.do(req), http.StatusForbidden, nil, "SCIM requires TLS", "forwarded proto, untrusted peer")

	// 401 — TLS, wrong bearer.
	req = f.scimRequest(http.MethodGet, "/api/scim/v2/Users", "")
	req.Header.Set("Authorization", "Bearer wrong")
	assertScimError(t, f.do(req), http.StatusUnauthorized, nil, "invalid bearer token", "wrong bearer")

	// 401 — TLS, no Authorization header at all.
	req = f.scimRequest(http.MethodGet, "/api/scim/v2/Users", "")
	req.Header.Del("Authorization")
	assertScimError(t, f.do(req), http.StatusUnauthorized, nil, "invalid bearer token", "no bearer")

	// 🔒 INV-A3-36 — an UNCONFIGURED token means NO provisioning surface at all, not an open one, and
	// 501 outranks both other checks: this request is over TLS with the correct bearer.
	f.clearScimToken()
	assertScimError(t, f.scim(http.MethodGet, "/api/scim/v2/Users", ""),
		http.StatusNotImplemented, nil, "SCIM provisioning is not configured", "unconfigured token")

	// And it applies to a MUTATION too, not just a read — the fail-closed direction that matters.
	assertScimError(t, f.scim(http.MethodPost, "/api/scim/v2/Users", `{"externalId":"x","userName":"y"}`),
		http.StatusNotImplemented, nil, "SCIM provisioning is not configured", "unconfigured token, POST")
}

// The three static discovery documents, served BYTE FOR BYTE.
//
// ⚠️ F33 — content type is `application/json`, NOT RFC 7644's `application/scim+json`. Reproduced.
func TestScimDiscoveryDocumentsAreServedVerbatim(t *testing.T) {
	f := newRouteFixture(t)

	for _, tc := range []struct{ path, want string }{
		{"/api/scim/v2/ServiceProviderConfig", identity.ServiceProviderConfigJSON},
		{"/api/scim/v2/ResourceTypes", identity.ResourceTypesJSON},
		{"/api/scim/v2/Schemas", identity.SchemasJSON},
	} {
		rec := f.scim(http.MethodGet, tc.path, "")
		assertStatus(t, rec, http.StatusOK, "GET "+tc.path)
		if rec.Body.String() != tc.want {
			t.Errorf("GET %s:\n got %s\nwant %s", tc.path, rec.Body.String(), tc.want)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("GET %s: content-type %q, want application/json (F33 — NOT application/scim+json)",
				tc.path, got)
		}
	}
}

// GET /Users and GET /Groups: the ListResponse envelope, `Resources` capitalised, no pagination.
func TestScimListRoutesReturnTheWholeDirectoryInOneEnvelope(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.scim(http.MethodGet, "/api/scim/v2/Users", "")
	assertStatus(t, rec, http.StatusOK, "GET /Users (empty)")
	if got := rec.Body.String(); got != `{"schemas":["`+identity.ScimListResponseSchema+
		`"],"totalResults":0,"Resources":[]}` {
		t.Errorf("an empty directory: got %s", got)
	}

	if _, err := f.store.UpsertScimUser(f.ctx, "okta-1", "alice@example.com",
		types.Ptr("alice@corp.example"), types.Ptr("Alice"), true, f.creds); err != nil {
		t.Fatalf("provision: %v", err)
	}
	group, err := f.store.UpsertScimGroup(f.ctx, "okta-g1", "engineering")
	if err != nil {
		t.Fatalf("provision group: %v", err)
	}

	rec = f.scim(http.MethodGet, "/api/scim/v2/Users", "")
	var users identity.ScimListResponse
	decodeJSON(t, rec, &users)
	if users.TotalResults != 1 || len(users.Resources) != 1 {
		t.Errorf("totalResults=%d, %d resources", users.TotalResults, len(users.Resources))
	}
	// ⚠️ There is deliberately NO startIndex / itemsPerPage.
	if b := rec.Body.String(); contains(b, "startIndex") || contains(b, "itemsPerPage") {
		t.Errorf("the envelope must carry no pagination: %s", b)
	}

	// GET /Groups additionally issues one listMembers query per group (N+1) — reproduced; what is
	// asserted here is that the members it re-reads are actually in the body.
	f.seed.GroupMember(group.ID, f.seed.User("bob@example.com"))
	rec = f.scim(http.MethodGet, "/api/scim/v2/Groups", "")
	assertStatus(t, rec, http.StatusOK, "GET /Groups")
	// V8__seed.sql ships eight groups (one LOCAL + seven SYSTEM) plus the one provisioned here.
	var groups identity.ScimListResponse
	decodeJSON(t, rec, &groups)
	if groups.TotalResults != 9 {
		t.Errorf("totalResults=%d, want 9 (8 seeded + 1 provisioned)", groups.TotalResults)
	}
	if !contains(rec.Body.String(), `"display":"bob@example.com"`) {
		t.Errorf("each group's members are re-read into the body: %s", rec.Body.String())
	}
}

// POST /Users — 201, the two 400s (note the EMAIL FALLBACK on userName), and the 409.
func TestScimCreateUser(t *testing.T) {
	f := newRouteFixture(t)

	// 400 — externalId is checked FIRST, before userName.
	assertScimError(t, f.scim(http.MethodPost, "/api/scim/v2/Users", `{"userName":"alice@example.com"}`),
		http.StatusBadRequest, types.Ptr("invalidValue"), "externalId is required", "no externalId")
	assertScimError(t, f.scim(http.MethodPost, "/api/scim/v2/Users", `{"externalId":"  ","userName":"a"}`),
		http.StatusBadRequest, types.Ptr("invalidValue"), "externalId is required", "blank externalId")

	// 400 — neither userName nor a primary email.
	assertScimError(t, f.scim(http.MethodPost, "/api/scim/v2/Users", `{"externalId":"okta-1"}`),
		http.StatusBadRequest, types.Ptr("invalidValue"), "userName is required", "no userName and no email")

	// ⚠️ The EMAIL FALLBACK: a blank userName falls back to primaryEmail(). PUT deliberately does NOT
	// have this — it falls back to the EXISTING principal instead.
	rec := f.scim(http.MethodPost, "/api/scim/v2/Users",
		`{"externalId":"okta-1","userName":"","emails":[{"value":"alice@corp.example","primary":true}]}`)
	assertStatus(t, rec, http.StatusCreated, "POST with the email fallback")
	var created identity.ScimUser
	decodeJSON(t, rec, &created)
	if created.UserName != "alice@corp.example" {
		t.Errorf("userName %q, want the primary email", created.UserName)
	}

	// 201 with the full shape — and NO Location header (F33).
	rec = f.scim(http.MethodPost, "/api/scim/v2/Users",
		`{"externalId":"okta-2","userName":"bob@example.com","name":{"formatted":"Bob"},`+
			`"emails":[{"value":"bob@corp.example","primary":true}]}`)
	assertStatus(t, rec, http.StatusCreated, "POST /Users")
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("201 must carry no Location header (F33), got %q", loc)
	}
	decodeJSON(t, rec, &created)
	if created.Name == nil || created.Name.Formatted == nil || *created.Name.Formatted != "Bob" {
		t.Errorf("name %+v", created.Name)
	}
	if !created.Active {
		t.Errorf("a body omitting `active` must provision an ACTIVE user")
	}

	// 409 uniqueness — a POST whose externalId resolves to a row whose principal would then collide
	// with another row's. Quoted: it "collides here rather than silently producing a split-brain
	// external_id".
	assertScimError(t, f.scim(http.MethodPost, "/api/scim/v2/Users",
		`{"externalId":"okta-1","userName":"bob@example.com"}`),
		http.StatusConflict, types.Ptr("uniqueness"), "principal or externalId already in use",
		"POST colliding on principal")
}

// GET/DELETE /Users/{id} — including the 404-not-400 rule, and INV-A3-19.
func TestScimGetAndDeleteUser(t *testing.T) {
	f := newRouteFixture(t)
	user, err := f.store.UpsertScimUser(f.ctx, "okta-1", "alice@example.com", nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	rec := f.scim(http.MethodGet, "/api/scim/v2/Users/"+itoa64(user.ID), "")
	assertStatus(t, rec, http.StatusOK, "GET /Users/{id}")

	// ⚠️ AN UNPARSEABLE {id} IS 404, NEVER 400 — RFC 7644 addresses resources by opaque id, so "not a
	// number" and "no such resource" are the same answer to an IdP. It diverges from the admin routes,
	// which answer 400 common.bad_id for the same input, and the divergence IS the contract.
	for _, target := range []string{"/api/scim/v2/Users/abc", "/api/scim/v2/Users/987654321"} {
		assertScimError(t, f.scim(http.MethodGet, target, ""),
			http.StatusNotFound, nil, "no such user", "GET "+target)
		assertScimError(t, f.scim(http.MethodDelete, target, ""),
			http.StatusNotFound, nil, "no such user", "DELETE "+target)
		assertScimError(t, f.scim(http.MethodPatch, target, `{"Operations":[{"op":"replace","path":"active","value":false}]}`),
			http.StatusNotFound, nil, "no such user", "PATCH "+target)
		assertScimError(t, f.scim(http.MethodPut, target, `{"externalId":"okta-x","userName":"x"}`),
			http.StatusNotFound, nil, "no such user", "PUT "+target)
	}

	// 🔒 DELETE is 204 with no body and DEPROVISIONS — the row survives, inactive, and the principal's
	// credentials go with it.
	creds := f.seedCredentials("alice@example.com", "reader")
	rec = f.scim(http.MethodDelete, "/api/scim/v2/Users/"+itoa64(user.ID), "")
	assertStatus(t, rec, http.StatusNoContent, "DELETE /Users/{id}")
	if rec.Body.Len() != 0 {
		t.Errorf("204 must carry no body, got %s", rec.Body.String())
	}
	after, err := f.store.GetUser(f.ctx, user.ID)
	if err != nil || after == nil {
		t.Fatalf("SCIM DELETE must NOT hard-delete (INV-A3-19): %+v %v", after, err)
	}
	if after.Active {
		t.Errorf("the row must be inactive after DELETE")
	}
	f.assertRevoked(creds, "SCIM DELETE")
}

// PUT /Users/{id} — the four scalar MERGES, and the verbatim `active` replace.
func TestScimReplaceUserMergesScalarsButReplacesActive(t *testing.T) {
	f := newRouteFixture(t)
	user, err := f.store.UpsertScimUser(f.ctx, "okta-1", "alice@example.com",
		types.Ptr("alice@corp.example"), types.Ptr("Alice"), true, f.creds)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	// A body carrying nothing but `active` keeps all four scalars. ⚠️ Note `userName` falls back to
	// the EXISTING principal — there is NO email fallback here, unlike POST.
	rec := f.scim(http.MethodPut, "/api/scim/v2/Users/"+itoa64(user.ID), `{"active":true}`)
	assertStatus(t, rec, http.StatusOK, "PUT with an empty-ish body")
	var merged identity.ScimUser
	decodeJSON(t, rec, &merged)
	if merged.UserName != "alice@example.com" {
		t.Errorf("userName %q, want the existing principal (no email fallback on PUT)", merged.UserName)
	}
	if merged.ExternalID == nil || *merged.ExternalID != "okta-1" {
		t.Errorf("externalId %v, want the existing okta-1", merged.ExternalID)
	}
	if merged.Name == nil || *merged.Name.Formatted != "Alice" {
		t.Errorf("displayName must merge, got %+v", merged.Name)
	}
	if len(merged.Emails) != 1 || *merged.Emails[0].Value != "alice@corp.example" {
		t.Errorf("email must merge, got %+v", merged.Emails)
	}

	// 400 — a body that explicitly blanks externalId on a row that has none either.
	fresh, err := f.store.CreateUser(f.ctx,
		identity.AppUserInput{Principal: "local@example.com", Active: true}, f.creds)
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	assertScimError(t, f.scim(http.MethodPut, "/api/scim/v2/Users/"+itoa64(fresh.ID), `{"userName":"x"}`),
		http.StatusBadRequest, types.Ptr("invalidValue"), "externalId is required", "PUT with no externalId anywhere")

	// 409 uniqueness — stealing another row's externalId.
	other, err := f.store.UpsertScimUser(f.ctx, "okta-2", "bob@example.com", nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision other: %v", err)
	}
	assertScimError(t, f.scim(http.MethodPut, "/api/scim/v2/Users/"+itoa64(user.ID),
		`{"externalId":"okta-2","userName":"alice@example.com"}`),
		http.StatusConflict, types.Ptr("uniqueness"), "externalId already belongs to a different user",
		"PUT stealing an externalId")
	_ = other

	// 🔒 INV-A3-32 at route level — a PUT whose body keys match ANOTHER row must not mutate that row.
	rec = f.scim(http.MethodPut, "/api/scim/v2/Users/"+itoa64(user.ID),
		`{"externalId":"okta-1","userName":"alice@example.com","emails":[{"value":"bob@corp.example","primary":true}]}`)
	assertStatus(t, rec, http.StatusOK, "PUT reusing another row's email")
	untouched := f.mustUser(other.ID)
	if untouched.Principal != "bob@example.com" {
		t.Errorf("the OTHER row was mutated: %+v", untouched)
	}
}

// 🔒 F22 — THE HIGHEST-RANKED LIVE GAP IN THE AREA, PINNED AS THE BUGGY BEHAVIOUR IT IS.
//
// `ScimUser.active` defaults to TRUE and `PUT /Users/{id}` passes `body.active` VERBATIM, so a
// full-resource PUT that omits `active` — which is a routine Okta push — silently REACTIVATES a
// deprovisioned user. And because the value went false→true, the store's deactivate branch never
// fires, so the credential teardown is not re-run either.
//
// This test asserts the DEFECT. It exists so that fixing F22 is a deliberate, reviewable change with
// a failing test attached (03-identity-scim.md Q1: "Whichever way, a test must pin it before the
// port"), not something a port silently repaired by using Go's zero value.
func TestScimPutOmittingActiveSilentlyReactivatesADeprovisionedUser(t *testing.T) {
	f := newRouteFixture(t)
	user, err := f.store.UpsertScimUser(f.ctx, "okta-1", "alice@example.com", nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	// Deprovision it properly, the way an IdP would.
	assertStatus(t, f.scim(http.MethodDelete, "/api/scim/v2/Users/"+itoa64(user.ID), ""),
		http.StatusNoContent, "DELETE")
	if !f.mustUser(user.ID).Active == false && f.mustUser(user.ID).Active {
		t.Fatalf("precondition: the user must be deprovisioned")
	}

	// A routine full-resource PUT that simply does not mention `active`.
	rec := f.scim(http.MethodPut, "/api/scim/v2/Users/"+itoa64(user.ID),
		`{"externalId":"okta-1","userName":"alice@example.com"}`)
	assertStatus(t, rec, http.StatusOK, "PUT omitting active")

	var body identity.ScimUser
	decodeJSON(t, rec, &body)
	if !body.Active {
		t.Fatalf("F22 IS FIXED — the PUT no longer reactivates. That is a deliberate behaviour change " +
			"(03-identity-scim.md Q1) and this pin must be updated together with it, not deleted.")
	}
	if !f.mustUser(user.ID).Active {
		t.Errorf("the row must have been reactivated — that is the defect being pinned")
	}

	// The second half of the defect: no teardown re-runs, because the deactivate branch never fires.
	// A credential minted while the account was deprovisioned survives the reactivation.
	creds := f.seedCredentials("alice@example.com", "reader")
	rec = f.scim(http.MethodPut, "/api/scim/v2/Users/"+itoa64(user.ID),
		`{"externalId":"okta-1","userName":"alice@example.com"}`)
	assertStatus(t, rec, http.StatusOK, "second PUT omitting active")
	var stillLive bool
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT revoked_at IS NULL FROM proxy_token WHERE id = $1`, creds.tokenID).Scan(&stillLive); err != nil {
		t.Fatalf("read token: %v", err)
	}
	if !stillLive {
		t.Errorf("the reactivating PUT revoked a credential — that is NOT the Kotlin's behaviour")
	}
}

// PATCH /Users/{id} — SetActive, the resource-type pairing, and the validator's own errors.
func TestScimPatchUser(t *testing.T) {
	f := newRouteFixture(t)
	user, err := f.store.UpsertScimUser(f.ctx, "okta-1", "alice@example.com", nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	creds := f.seedCredentials("alice@example.com", "reader")

	// 🔒 replace:active=false goes through SetActiveByID — re-read under the lock, revoke in the same
	// committed transaction.
	rec := f.scim(http.MethodPatch, "/api/scim/v2/Users/"+itoa64(user.ID),
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`)
	assertStatus(t, rec, http.StatusOK, "PATCH replace:active=false")
	var patched identity.ScimUser
	decodeJSON(t, rec, &patched)
	if patched.Active {
		t.Errorf("active must be false in the response, got %+v", patched)
	}
	f.assertRevoked(creds, "PATCH replace:active=false")

	// Reactivating revokes nothing — the same asymmetry F22 exploits, here through PATCH.
	rec = f.scim(http.MethodPatch, "/api/scim/v2/Users/"+itoa64(user.ID),
		`{"Operations":[{"op":"replace","path":"active","value":true}]}`)
	assertStatus(t, rec, http.StatusOK, "PATCH replace:active=true")

	// 🔒 INV-A3-44 — `members` on a USER is 400 invalidPath with THIS message. The validator is
	// resource-agnostic; this branch is the Users half of the pairing.
	assertScimError(t, f.scim(http.MethodPatch, "/api/scim/v2/Users/"+itoa64(user.ID),
		`{"Operations":[{"op":"add","path":"members","value":[{"value":"1"}]}]}`),
		http.StatusBadRequest, types.Ptr("invalidPath"), "path 'members' is only valid on Groups",
		"PATCH members on a User")

	// The validator's own scimType and detail reach the wire unchanged.
	assertScimError(t, f.scim(http.MethodPatch, "/api/scim/v2/Users/"+itoa64(user.ID),
		`{"Operations":[{"op":"replace","path":"active","value":"yes"}]}`),
		http.StatusBadRequest, types.Ptr("invalidValue"), "path 'active' requires a boolean value",
		"PATCH with a non-boolean")
	assertScimError(t, f.scim(http.MethodPatch, "/api/scim/v2/Users/"+itoa64(user.ID),
		`{"Operations":[]}`),
		http.StatusBadRequest, types.Ptr("invalidPath"), "exactly one Operations entry is supported",
		"PATCH with no operations")
}

// POST /Groups — the two 400s, the 409s, and the ADD-ONLY, non-transactional member loop.
func TestScimCreateGroup(t *testing.T) {
	f := newRouteFixture(t)
	alice := f.seed.User("alice@example.com")
	bob := f.seed.User("bob@example.com")

	assertScimError(t, f.scim(http.MethodPost, "/api/scim/v2/Groups", `{"displayName":"eng"}`),
		http.StatusBadRequest, types.Ptr("invalidValue"), "externalId is required", "no externalId")
	assertScimError(t, f.scim(http.MethodPost, "/api/scim/v2/Groups", `{"externalId":"okta-g1"}`),
		http.StatusBadRequest, types.Ptr("invalidValue"), "displayName is required", "no displayName")

	// 201, with members added AFTER the upsert and the member list RE-READ into the response.
	//
	// ⚠️ INV-A3-46 — a NON-NUMERIC member id is silently dropped by toLongOrNull(), not rejected.
	rec := f.scim(http.MethodPost, "/api/scim/v2/Groups",
		`{"externalId":"okta-g1","displayName":"engineering","members":[`+
			`{"value":"`+itoa64(alice)+`"},{"value":"not-a-number"},{"value":"`+itoa64(bob)+`"}]}`)
	assertStatus(t, rec, http.StatusCreated, "POST /Groups")
	var created identity.ScimGroup
	decodeJSON(t, rec, &created)
	if len(created.Members) != 2 {
		t.Errorf("%d members, want 2 — the non-numeric entry is SILENTLY DROPPED, not rejected: %+v",
			len(created.Members), created.Members)
	}

	// ⚠️ A POST onto an EXISTING group is ADD-ONLY — it never removes anyone.
	rec = f.scim(http.MethodPost, "/api/scim/v2/Groups",
		`{"externalId":"okta-g1","displayName":"engineering","members":[]}`)
	assertStatus(t, rec, http.StatusCreated, "POST onto an existing group with no members")
	decodeJSON(t, rec, &created)
	if len(created.Members) != 2 {
		t.Errorf("%d members after an empty-members POST, want 2 (POST never removes)", len(created.Members))
	}

	// 🔒 F36 — 409 `mutability` for ALL SEVEN seeded SYSTEM groups, matched by NAME, and the guard
	// lives INSIDE the store (INV-A3-33) so a concurrent re-point cannot defeat it.
	for _, sys := range f.systemGroups() {
		assertScimError(t, f.scim(http.MethodPost, "/api/scim/v2/Groups",
			`{"externalId":"okta-hijack","displayName":"`+sys.Name+`"}`),
			http.StatusConflict, mutability, "system-managed group is immutable", "POST "+sys.Name)
	}
	if after := f.systemGroups(); len(after) != 7 {
		t.Errorf("%d SYSTEM groups after the refused pushes, want 7", len(after))
	}

	// 409 uniqueness — an externalId that resolves to a row whose NAME would then collide.
	if _, err := f.store.UpsertScimGroup(f.ctx, "okta-g2", "platform"); err != nil {
		t.Fatalf("provision second group: %v", err)
	}
	assertScimError(t, f.scim(http.MethodPost, "/api/scim/v2/Groups",
		`{"externalId":"okta-g1","displayName":"platform"}`),
		http.StatusConflict, types.Ptr("uniqueness"), "name or externalId already in use",
		"POST colliding on name")
}

// PUT /Groups/{id} — scalars MERGE, membership is a TRUE REPLACE.
//
// ⚠️ So a PUT that OMITS `members` reconciles to the EMPTY set and removes everyone, while its scalar
// fields merge. Both halves are real; this is the group-side twin of F22's asymmetry and the reason a
// partial PUT from an IdP can silently empty a group.
func TestScimReplaceGroupMergesScalarsButReplacesMembership(t *testing.T) {
	f := newRouteFixture(t)
	alice := f.seed.User("alice@example.com")
	bob := f.seed.User("bob@example.com")

	group, err := f.store.UpsertScimGroup(f.ctx, "okta-g1", "engineering")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := f.store.AddMember(f.ctx, group.ID, alice); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	// Membership replace: alice out, bob in.
	rec := f.scim(http.MethodPut, "/api/scim/v2/Groups/"+itoa64(group.ID),
		`{"externalId":"okta-g1","displayName":"engineering","members":[{"value":"`+itoa64(bob)+`"}]}`)
	assertStatus(t, rec, http.StatusOK, "PUT /Groups/{id}")
	var replaced identity.ScimGroup
	decodeJSON(t, rec, &replaced)
	if len(replaced.Members) != 1 || replaced.Members[0].Value != itoa64(bob) {
		t.Errorf("membership must be reconciled to exactly the submitted set, got %+v", replaced.Members)
	}

	// ⚠️ Scalars merge: a body with no displayName keeps the existing name — while `members` omitted
	// EMPTIES the group.
	rec = f.scim(http.MethodPut, "/api/scim/v2/Groups/"+itoa64(group.ID), `{"externalId":"okta-g1"}`)
	assertStatus(t, rec, http.StatusOK, "PUT omitting displayName and members")
	decodeJSON(t, rec, &replaced)
	if replaced.DisplayName != "engineering" {
		t.Errorf("displayName must MERGE, got %q", replaced.DisplayName)
	}
	if len(replaced.Members) != 0 {
		t.Errorf("omitting `members` must REPLACE it with the empty set — everyone is removed; got %+v",
			replaced.Members)
	}

	// 400 — a row with no externalId and a body that supplies none.
	local := f.seed.Group("local-only")
	assertScimError(t, f.scim(http.MethodPut, "/api/scim/v2/Groups/"+itoa64(local), `{"displayName":"x"}`),
		http.StatusBadRequest, types.Ptr("invalidValue"), "externalId is required", "PUT with no externalId")

	// 404 for an unparseable id and for a missing row.
	for _, target := range []string{"/api/scim/v2/Groups/abc", "/api/scim/v2/Groups/987654321"} {
		assertScimError(t, f.scim(http.MethodPut, target, `{"externalId":"x","displayName":"y"}`),
			http.StatusNotFound, nil, "no such group", "PUT "+target)
		assertScimError(t, f.scim(http.MethodGet, target, ""),
			http.StatusNotFound, nil, "no such group", "GET "+target)
		assertScimError(t, f.scim(http.MethodPatch, target,
			`{"Operations":[{"op":"add","path":"members","value":[]}]}`),
			http.StatusNotFound, nil, "no such group", "PATCH "+target)
	}

	// 🔒 F36 — 409 mutability on ALL SEVEN, from PUT and PATCH alike (the route-level `isSystemGroup`,
	// INV-A3-45's weaker half — it is what actually protects the rows, since the store's
	// replaceScimGroupById has no guard of its own).
	for _, sys := range f.systemGroups() {
		assertScimError(t, f.scim(http.MethodPut, "/api/scim/v2/Groups/"+itoa64(sys.ID),
			`{"externalId":"okta-x","displayName":"hijacked"}`),
			http.StatusConflict, mutability, "system-managed group is immutable", "PUT "+sys.Name)
		assertScimError(t, f.scim(http.MethodPatch, "/api/scim/v2/Groups/"+itoa64(sys.ID),
			`{"Operations":[{"op":"add","path":"members","value":[{"value":"`+itoa64(alice)+`"}]}]}`),
			http.StatusConflict, mutability, "system-managed group is immutable", "PATCH "+sys.Name)
	}
}

// PATCH /Groups/{id} — add|remove members, and the Groups half of INV-A3-44's pairing.
// KT: ScimGroupsDbTest.kt#SCIM group membership PATCH reuses addMember-removeMember (group_member)
func TestScimPatchGroupMembership(t *testing.T) {
	f := newRouteFixture(t)
	alice := f.seed.User("alice@example.com")
	bob := f.seed.User("bob@example.com")
	group, err := f.store.UpsertScimGroup(f.ctx, "okta-g1", "engineering")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	target := "/api/scim/v2/Groups/" + itoa64(group.ID)

	rec := f.scim(http.MethodPatch, target,
		`{"Operations":[{"op":"add","path":"members","value":[`+
			`{"value":"`+itoa64(alice)+`"},{"value":"`+itoa64(bob)+`"},{"value":"junk"}]}]}`)
	assertStatus(t, rec, http.StatusOK, "PATCH add:members")
	var patched identity.ScimGroup
	decodeJSON(t, rec, &patched)
	if len(patched.Members) != 2 {
		t.Errorf("%d members, want 2 — `junk` is silently dropped: %+v", len(patched.Members), patched.Members)
	}
	// The Kotlin asserts the exact SET, not the count: a count-only check passes for an add that
	// resolved the wrong two ids (e.g. bound `junk` to id 0 and dropped a real member).
	if got := memberIDs(patched); !sameStrings(got, []string{itoa64(alice), itoa64(bob)}) {
		t.Errorf("members = %v, want exactly {%s, %s}", got, itoa64(alice), itoa64(bob))
	}
	// …and they landed in `group_member` — the case's parenthetical claim is that SCIM membership has
	// NO table of its own, it reuses addMember/removeMember on the one membership table.
	if got := f.groupMemberIDs(group.ID); !sameStrings(got, []string{itoa64(alice), itoa64(bob)}) {
		t.Errorf("group_member rows = %v, want exactly {%s, %s} — SCIM must reuse group_member",
			got, itoa64(alice), itoa64(bob))
	}

	rec = f.scim(http.MethodPatch, target,
		`{"Operations":[{"op":"remove","path":"members","value":[{"value":"`+itoa64(alice)+`"}]}]}`)
	assertStatus(t, rec, http.StatusOK, "PATCH remove:members")
	decodeJSON(t, rec, &patched)
	if len(patched.Members) != 1 || patched.Members[0].Value != itoa64(bob) {
		t.Errorf("got %+v", patched.Members)
	}
	if got := f.groupMemberIDs(group.ID); !sameStrings(got, []string{itoa64(bob)}) {
		t.Errorf("group_member rows after the remove = %v, want exactly {%s}", got, itoa64(bob))
	}

	// 🔒 INV-A3-44 — `active` on a GROUP is 400 invalidPath with THIS message.
	assertScimError(t, f.scim(http.MethodPatch, target,
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`),
		http.StatusBadRequest, types.Ptr("invalidPath"), "path 'active' is only valid on Users",
		"PATCH active on a Group")
}

// 🔒 F42 / F26 — `DELETE /api/scim/v2/Groups/{id}` HARD-DELETES, CASCADE-dropping every `group_role`
// and `group_member` row: an IdP group delete silently revokes the group's roles from every member,
// with no audit record and no undo — while users are NEVER hard-deleted. The asymmetry IS the
// finding, and it is reproduced.
//
// ⚠️ F26's second half: this route's 409 carries `scimType = null` where every sibling sets
// "mutability". An IdP branching on scimType sees a different shape from this one route.
func TestScimDeleteGroupHardDeletesAndCascades(t *testing.T) {
	f := newRouteFixture(t)
	alice := f.seed.User("alice@example.com")
	role := f.seed.Role("reader")

	group, err := f.store.UpsertScimGroup(f.ctx, "okta-g1", "engineering")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := f.store.AddMember(f.ctx, group.ID, alice); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if _, err := f.store.AddGroupRole(f.ctx, group.ID, role); err != nil {
		t.Fatalf("map role: %v", err)
	}

	assertStatus(t, f.scim(http.MethodDelete, "/api/scim/v2/Groups/"+itoa64(group.ID), ""),
		http.StatusNoContent, "DELETE /Groups/{id}")

	gone, err := f.store.GetGroup(f.ctx, group.ID)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if gone != nil {
		t.Errorf("the group survived — SCIM group DELETE is a HARD delete (F42)")
	}
	// The CASCADE: both maps are gone, silently.
	var members, roles int64
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT (SELECT count(*) FROM group_member WHERE group_id=$1),
		        (SELECT count(*) FROM group_role   WHERE group_id=$1)`, group.ID).Scan(&members, &roles); err != nil {
		t.Fatalf("count cascades: %v", err)
	}
	if members != 0 || roles != 0 {
		t.Errorf("group_member=%d group_role=%d, want both 0 (ON DELETE CASCADE)", members, roles)
	}
	// The member's own row is untouched — users are never hard-deleted.
	if row, err := f.store.GetUser(f.ctx, alice); err != nil || row == nil {
		t.Errorf("the MEMBER must survive the group delete: %+v %v", row, err)
	}

	// ⚠️ F26 — 409 with NO scimType, on all seven seeded SYSTEM groups.
	for _, sys := range f.systemGroups() {
		assertScimError(t, f.scim(http.MethodDelete, "/api/scim/v2/Groups/"+itoa64(sys.ID), ""),
			http.StatusConflict, nil, "system-managed group is immutable", "DELETE "+sys.Name)
	}

	// 404 for an unparseable id and for a missing row — the SYSTEM check runs first, so a nonexistent
	// id falls through to the delete's false branch.
	for _, target := range []string{"/api/scim/v2/Groups/abc", "/api/scim/v2/Groups/987654321"} {
		assertScimError(t, f.scim(http.MethodDelete, target, ""),
			http.StatusNotFound, nil, "no such group", "DELETE "+target)
	}
}

// ⚠️ F41 / F30 — StatusPages' catch-all answers `ApiError("common.fallback")` for ANY uncaught error,
// INCLUDING on `/api/scim/v2/**`, breaking the documented SCIM error-body exemption exactly where an
// IdP is least able to parse it.
//
// REPRODUCED — it is A1's middleware behaviour, not something the SCIM routes can override — and
// pinned here so the breach is a known, located property rather than a surprise in an Okta log.
func TestScimFallbackAnswersAnApiErrorNotAScimError(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.scim(http.MethodPost, "/api/scim/v2/Users", `{not json`)
	assertStatus(t, rec, http.StatusInternalServerError, "POST with a malformed body")
	body := assertAPIError(t, rec, "common.fallback", "POST with a malformed body")
	if body.Code != "common.fallback" {
		t.Fatalf("code %q", body.Code)
	}
	// It is emphatically NOT a ScimError: no `schemas`, no `status` string, no `detail`.
	var scim httpapi.ScimError
	decodeJSON(t, rec, &scim)
	if len(scim.Schemas) != 0 || scim.Status != "" {
		t.Errorf("the body IS SCIM-shaped — F41 says it is not; if this was fixed deliberately, "+
			"update the finding: %s", rec.Body.String())
	}

	// The same breach on a PATCH body. Note the ORDER: the existence check precedes the decode, so
	// this needs a real row — a PATCH to a missing id answers a proper SCIM 404 and never reaches the
	// decoder.
	user, err := f.store.UpsertScimUser(f.ctx, "okta-1", "alice@example.com", nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	assertAPIError(t, f.scim(http.MethodPatch, "/api/scim/v2/Users/"+itoa64(user.ID), `{oops`),
		"common.fallback", "PATCH with a malformed body")
}

// mustUser reads a row back, failing the test if it vanished.
func (f *routeFixture) mustUser(id int64) identity.AppUser {
	f.t.Helper()
	out, err := f.store.GetUser(f.ctx, id)
	if err != nil {
		f.t.Fatalf("getUser(%d): %v", id, err)
	}
	if out == nil {
		f.t.Fatalf("user %d does not exist", id)
	}
	return *out
}

// memberIDs is the `value` of every member on a SCIM group representation.
func memberIDs(g identity.ScimGroup) []string {
	out := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		out = append(out, m.Value)
	}
	return out
}

// groupMemberIDs reads the membership straight out of `group_member` — the one membership table SCIM
// is required to reuse (ScimGroupsDbTest's `(group_member)`), rather than trusting the route's own
// echo of what it just wrote.
func (f *routeFixture) groupMemberIDs(groupID int64) []string {
	f.t.Helper()
	rows, err := f.db.Pool.Query(f.ctx,
		`SELECT user_id FROM group_member WHERE group_id = $1 ORDER BY user_id`, groupID)
	if err != nil {
		f.t.Fatalf("read group_member for %d: %v", groupID, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			f.t.Fatalf("scan group_member: %v", err)
		}
		out = append(out, itoa64(id))
	}
	if err := rows.Err(); err != nil {
		f.t.Fatalf("iterate group_member: %v", err)
	}
	return out
}

// sameStrings compares two collections as SETS, so an assertion on membership does not accidentally
// also pin the order the route happens to return.
func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	a, b := append([]string(nil), got...), append([]string(nil), want...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
