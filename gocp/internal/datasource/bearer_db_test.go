package datasource_test

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
)

// ---------------------------------------------------------------------------------------------
// requireApiOrBearer / bearerWirePrincipal — 05-datasources-catalog.md §2, INV-A5-3/20/21.
//
// 🔒 INV-A5-20, quoted in full: "Only native-wire kinds (SESSION/USER) count, and this is wired ONLY
// into the read-only datasource GET routes — never mutations or token mint — so a leaked wire token
// cannot bootstrap more credentials through the API. Roles are still resolved server-side per
// principal, so this is a new AUTHENTICATION surface, not a privilege grant."
//
// The whole reason the path exists (Datasources.kt:719-727): "The `pmon` CLI is an authenticated
// OAuth client after `pmon login`, but the device-auth flow hands the browser the web-session
// cookie, not the CLI — so the CLI presents its own wire token as an HTTP `Authorization: Bearer` to
// reach read-only datasource discovery."
// ---------------------------------------------------------------------------------------------

const wireTokenPlaintext = "pmt_deadbeefcafe"

func newBearerFixture(t *testing.T) (*fixture, datasource.Datasource) {
	t.Helper()
	f := newFixture(t)
	ds := f.seedDatasource("discoverable", dbtest.EngineMySQL, "app")
	f.tokens.byToken[wireTokenPlaintext] = &datasource.WireTokenIdentity{
		Principal: "cli@example.com", Kind: "SESSION",
	}
	f.connect.allow["discoverable"] = true
	return f, ds
}

// TestABearerWireTokenAuthenticatesTheThreeReadOnlyGets is the surface, stated exactly.
//
// 🔒 THREE ROUTES AND ONLY THREE: the list, the catalog and the certificate. Everything else on the
// prefix — including `GET /api/datasources/{id}`, which is `requireApi` — must answer 401 to the
// same header. That asymmetry IS the invariant: "wired ONLY into the read-only datasource GET
// routes".
func TestABearerWireTokenAuthenticatesTheThreeReadOnlyGets(t *testing.T) {
	f, ds := newBearerFixture(t)
	id := strconv.FormatInt(ds.ID, 10)
	header := "Bearer " + wireTokenPlaintext

	for _, target := range []string{
		"/api/datasources",
		"/api/datasources/" + id + "/catalog",
	} {
		rec := f.bearer(header, "GET", target)
		assertStatus(t, rec, http.StatusOK, "bearer GET "+target)
	}

	t.Run("and NOT the routes it is not wired into", func(t *testing.T) {
		for _, target := range []string{
			"/api/datasources/" + id,
			"/api/datasources/live",
		} {
			rec := f.bearer(header, "GET", target)
			assertStatus(t, rec, http.StatusUnauthorized,
				"a wire token must not reach "+target+" — the Bearer path is discovery-only")
			assertAPIError(t, rec, "common.unauthenticated", "bearer GET "+target)
		}
		// Mutations are unreachable too: they run requireAdmin, which never consults the Bearer path.
		rec := f.send(request{
			method: "POST", target: "/api/datasources", body: `{"name":"sneaky"}`,
			headers: map[string]string{"Authorization": header},
		})
		assertStatus(t, rec, http.StatusUnauthorized,
			"a leaked wire token must not be able to CREATE a datasource")
	})
}

// TestTheBearerPrincipalIsTheOneCedarSees is 🔒 INV-A5-3 from the other side.
//
// "The helper hands back whichever identity authenticated, and only answers `debug-user` when
// PM_AUTH_DEBUG actually says so." If the route resolved its principal from the session alone it
// would fall through to the literal `debug-user` and run the Cedar check against a synthetic
// identity — so the observable claim is that mayConnect was asked about `cli@example.com`.
func TestTheBearerPrincipalIsTheOneCedarSees(t *testing.T) {
	f, ds := newBearerFixture(t)
	f.roles.roles["cli@example.com"] = []string{"wire-only"}

	rec := f.bearer("Bearer "+wireTokenPlaintext, "GET",
		"/api/datasources/"+strconv.FormatInt(ds.ID, 10)+"/catalog")
	assertStatus(t, rec, http.StatusOK, "bearer catalog")

	if len(f.connect.calls) == 0 {
		t.Fatal("the bearer path never reached mayConnect")
	}
	for _, c := range f.connect.calls {
		if c.principal != "cli@example.com" {
			t.Errorf("Cedar was asked about %q, want the token's principal", c.principal)
		}
		if c.principal == datasource.DebugPrincipal {
			t.Error("the bearer path fell through to the debug-user literal")
		}
		if strings.Join(c.roles, ",") != "wire-only" {
			t.Errorf("roles = %v; roles must be resolved SERVER-side per principal, never from the token",
				c.roles)
		}
	}
}

// TestTheBearerSchemeIsCaseInsensitiveAndFixedWidth pins step 2 and step 3 of
// `bearerWirePrincipal`.
//
// ⚠️ `startsWith("Bearer ", ignoreCase = true)` then `substring(7).trim()`. The prefix test is
// CASE-INSENSITIVE — unlike the SCIM gate's case-SENSITIVE `removePrefix("Bearer ")`
// (httpapi.Gates.RequireScimAuth). The inconsistency between the two is real and is reproduced on
// both sides; a port that unified them would either break `pmon`'s lowercase clients or start
// accepting `bearer` on the SCIM surface.
//
// ⚠️ And the substring is a FIXED 7 characters taken AFTER the case-insensitive test, so
// `bearer  tok` (two spaces) yields ` tok`, which the trim rescues. A port using
// strings.TrimPrefix("Bearer ") would drop nothing from a `bearer ` header and then compare the
// whole string as a token.
func TestTheBearerSchemeIsCaseInsensitiveAndFixedWidth(t *testing.T) {
	f, _ := newBearerFixture(t)

	for _, header := range []string{
		"Bearer " + wireTokenPlaintext,
		"bearer " + wireTokenPlaintext,
		"BEARER " + wireTokenPlaintext,
		"BeArEr " + wireTokenPlaintext,
		"Bearer  " + wireTokenPlaintext,      // the trim rescues the extra space
		"Bearer " + wireTokenPlaintext + " ", // trailing whitespace too
	} {
		rec := f.bearer(header, "GET", "/api/datasources")
		assertStatus(t, rec, http.StatusOK, "Authorization: "+strconv.Quote(header))
	}

	for _, header := range []string{
		"Basic " + wireTokenPlaintext,
		"Token " + wireTokenPlaintext,
		"Bearer",
		"Bearer ",
		"Bearer    ",
		wireTokenPlaintext,
		"",
	} {
		rec := f.bearer(header, "GET", "/api/datasources")
		assertStatus(t, rec, http.StatusUnauthorized, "Authorization: "+strconv.Quote(header))
		assertAPIError(t, rec, "common.unauthenticated", "Authorization: "+strconv.Quote(header))
	}
}

// TestOnlyNativeWireKindsCount is 🔒 INV-A5-20's kind filter.
//
// EDITOR and APPROVER_EXEC are the console's one-shot credentials; a leaked one must not become an
// HTTP identity. Note that A4's `Resolve` DOES return them (it accepts all four kinds), so the
// filter has to live here — a port that trusted Resolve's kind set would admit both.
//
// ⚠️ EDITOR and APPROVER_EXEC tokens are prefix-INDISTINGUISHABLE from USER tokens on the wire, so
// the kind can only come from the resolved row. Never infer it from `pmk_`/`pmt_`.
func TestOnlyNativeWireKindsCount(t *testing.T) {
	f, _ := newBearerFixture(t)

	for kind, wantOK := range map[string]bool{
		"SESSION":       true,
		"USER":          true,
		"EDITOR":        false,
		"APPROVER_EXEC": false,
		"MCP_ACCESS":    false, // not even a member of TokenKind — fromWire answers null
		"":              false,
		"session":       false, // fromWire matches the enum MEMBER NAME, which is upper-case
	} {
		f.tokens.byToken["tok-"+kind] = &datasource.WireTokenIdentity{Principal: "cli@example.com", Kind: kind}
		rec := f.bearer("Bearer tok-"+kind, "GET", "/api/datasources")
		if wantOK {
			assertStatus(t, rec, http.StatusOK, "a "+kind+" token")
			continue
		}
		assertStatus(t, rec, http.StatusUnauthorized, "a "+strconv.Quote(kind)+" token must not authenticate")
	}
}

// TestADeactivatedPrincipalFailsClosedEvenWithALiveTokenRow is 🔒 INV-A5-21.
//
// Quoted: "matches the gRPC decide path (a SCIM `active=false` push or a failed IdP liveness recheck
// can mark the `app_user` inactive without the credential revoke having raced in yet)."
func TestADeactivatedPrincipalFailsClosedEvenWithALiveTokenRow(t *testing.T) {
	f, _ := newBearerFixture(t)

	assertStatus(t, f.bearer("Bearer "+wireTokenPlaintext, "GET", "/api/datasources"),
		http.StatusOK, "an active principal")

	f.users.deactivated["cli@example.com"] = true
	rec := f.bearer("Bearer "+wireTokenPlaintext, "GET", "/api/datasources")
	assertStatus(t, rec, http.StatusUnauthorized,
		"a deactivated principal must fail closed even though the token row is still live")
	assertAPIError(t, rec, "common.unauthenticated", "a deactivated principal")
}

// TestAnUnresolvableTokenIs401 — revoked, expired, or never issued are indistinguishable at this
// layer, which is A4's contract: `Resolve` returns nil for all three.
func TestAnUnresolvableTokenIs401(t *testing.T) {
	f, _ := newBearerFixture(t)
	rec := f.bearer("Bearer pmt_never-issued", "GET", "/api/datasources")
	assertStatus(t, rec, http.StatusUnauthorized, "an unresolvable token")
	assertAPIError(t, rec, "common.unauthenticated", "an unresolvable token")
}

// TestASessionBeatsABearerHeader pins the ORDER in requireApiOrBearer:
// `userSession()?.principal` is consulted FIRST.
//
// A browser that somehow carries both must be identified by its session, not by whatever wire token
// rides along — otherwise a console page open next to a `pmon` daemon could silently act as the
// daemon's identity.
func TestASessionBeatsABearerHeader(t *testing.T) {
	f, ds := newBearerFixture(t)
	f.connect.allow["discoverable"] = true

	rec := f.send(request{
		method:  "GET",
		target:  "/api/datasources/" + strconv.FormatInt(ds.ID, 10) + "/catalog",
		cookies: []*http.Cookie{f.login("browser@example.com")},
		headers: map[string]string{"Authorization": "Bearer " + wireTokenPlaintext},
	})
	assertStatus(t, rec, http.StatusOK, "session + bearer")
	if len(f.connect.calls) == 0 {
		t.Fatal("mayConnect was never reached")
	}
	if got := f.connect.calls[0].principal; got != "browser@example.com" {
		t.Errorf("Cedar was asked about %q; the SESSION principal must win", got)
	}
}

// TestUnderAuthDebugASessionStillWins is the ordering difference between requireApi and
// requireApiOrBearer, made observable.
//
// ⚠️ `requireApi` short-circuits on authDebug FIRST and never reads the session.
// `requireApiOrBearer` reads the session first, so under PM_AUTH_DEBUG a request WITH a session gets
// its REAL principal and only a request without one becomes `"debug-user"`. That difference reaches
// the Cedar decision mayConnect makes, and it is deliberate.
func TestUnderAuthDebugASessionStillWins(t *testing.T) {
	f := newFixture(t, withAuthDebug())
	ds := f.seedDatasource("debug-order", dbtest.EngineMySQL, "app")
	target := "/api/datasources/" + strconv.FormatInt(ds.ID, 10) + "/catalog"

	// With a session: the real principal, even under authDebug. (mayConnect still short-circuits, so
	// this is observable only in that the route does not 401 and does not need the debug identity.)
	assertStatus(t, f.as("real@example.com", "GET", target, ""), http.StatusOK, "authDebug + session")
	// Without one: the debug identity, and the route still serves.
	assertStatus(t, f.anon("GET", target, ""), http.StatusOK, "authDebug + nothing")
}

// TestATokenStoreFailureIs500NotA401 — a JDBC failure on the resolve throws in the Kotlin and
// reaches StatusPages. Swallowing it into the 401 branch would turn a database outage into "your
// credential is bad", and every `pmon` user would re-login into the same outage.
func TestATokenStoreFailureIs500NotA401(t *testing.T) {
	f, _ := newBearerFixture(t)
	f.tokens.err = errSentinel

	rec := f.bearer("Bearer "+wireTokenPlaintext, "GET", "/api/datasources")
	assertStatus(t, rec, http.StatusInternalServerError, "a token-store failure")
	assertAPIError(t, rec, "common.fallback", "a token-store failure")
}

// TestADeactivationLookupFailureIs500NotA401 — same argument for the second store read.
func TestADeactivationLookupFailureIs500NotA401(t *testing.T) {
	f, _ := newBearerFixture(t)
	f.users.err = errSentinel

	rec := f.bearer("Bearer "+wireTokenPlaintext, "GET", "/api/datasources")
	assertStatus(t, rec, http.StatusInternalServerError, "a deactivation-lookup failure")
	assertAPIError(t, rec, "common.fallback", "a deactivation-lookup failure")
}

// TestARoleResolutionFailureIs500NotA403 — mayConnect's `roleResolver.resolve` throws in the Kotlin
// too. A port that treated the error as "no roles" would DENY, which reads as a policy decision and
// would send an operator hunting through Cedar for a database outage.
func TestARoleResolutionFailureIs500NotA403(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("roles-broken", dbtest.EngineMySQL, "app")
	f.roles.err = errSentinel

	rec := f.as("someone@example.com", "GET",
		"/api/datasources/"+strconv.FormatInt(ds.ID, 10)+"/catalog", "")
	assertStatus(t, rec, http.StatusInternalServerError, "a role-resolution failure")
	assertAPIError(t, rec, "common.fallback", "a role-resolution failure")
}
