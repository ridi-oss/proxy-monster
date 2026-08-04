package datasource_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/management"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The gate map — 05-datasources-catalog.md §2's route table, asserted route by route.
// ---------------------------------------------------------------------------------------------

// TestEveryRouteStatesItsGate is the route table's first column, mechanised.
//
// 🔒 It is the ONE test that fails when a route silently loses its gate. AGENTS.md: "a route states
// its requirement by which gate helper it calls", and the only way to observe which helper ran is
// what an unauthenticated request gets back. Three answers are possible and all three appear:
//
//   - requireApi / requireApiOrBearer ⇒ 401 common.unauthenticated (no Cedar reached at all)
//   - requireAdmin(ADMIN_DATASOURCES) ⇒ 401 first (RequireAuthz reads the session before Cedar), so
//     the ADMIN half needs the second table below.
//
// The second table is the load-bearing one: a SESSION-carrying request that Cedar DENIES must be 403
// on the seven admin routes and must NOT be 403 on the six open ones.
func TestEveryRouteStatesItsGate(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("gated", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)

	type route struct {
		method, target, body string
		admin                bool
	}
	routes := []route{
		{method: "GET", target: "/api/datasources"},
		{method: "GET", target: "/api/datasources/live"},
		{method: "GET", target: "/api/datasources/" + id},
		{method: "GET", target: "/api/datasources/" + id + "/catalog"},
		{method: "GET", target: "/api/datasources/" + id + "/wire-cert"},
		{method: "POST", target: "/api/datasources", body: `{"name":"x"}`, admin: true},
		{method: "PUT", target: "/api/datasources/" + id, body: `{"name":"x"}`, admin: true},
		{method: "DELETE", target: "/api/datasources/" + id, admin: true},
		{method: "POST", target: "/api/datasources/" + id + "/refresh", admin: true},
		{method: "POST", target: "/api/datasources/" + id + "/test", admin: true},
		{method: "GET", target: "/api/datasources/" + id + "/table-detail?schema=s&table=t", admin: true},
		{method: "PUT", target: "/api/datasources/" + id + "/classification", body: `{"table":"t","column":"c"}`, admin: true},
		{method: "DELETE", target: "/api/datasources/" + id + "/classification", body: `{"table":"t","column":"c"}`, admin: true},
	}
	if len(routes) != 13 {
		t.Fatalf("the A5 route table has 13 rows, this table has %d", len(routes))
	}

	t.Run("unauthenticated is 401 on every route", func(t *testing.T) {
		for _, rt := range routes {
			rec := f.anon(rt.method, rt.target, rt.body)
			what := rt.method + " " + rt.target
			assertStatus(t, rec, http.StatusUnauthorized, what)
			assertAPIError(t, rec, "common.unauthenticated", what)
		}
	})

	t.Run("a denied session is 403 on the seven admin routes and never on the six open ones", func(t *testing.T) {
		for _, rt := range routes {
			f.admin.allowed = false
			f.admin.reset()
			f.connect.reset()
			rec := f.as("nobody@example.com", rt.method, rt.target, rt.body)
			what := rt.method + " " + rt.target
			if rt.admin {
				assertStatus(t, rec, http.StatusForbidden, what)
				assertAPIError(t, rec, "common.forbidden", what)
				if got := f.admin.only(t); got != authz.ActionAdminDatasources {
					t.Errorf("%s: asked Cedar for %q, want %q", what, got, authz.ActionAdminDatasources)
				}
				if _, ok := f.admin.resources[0].(authz.ResourceSystem); !ok {
					t.Errorf("%s: admin gate resource is %T, want authz.ResourceSystem", what, f.admin.resources[0])
				}
				continue
			}
			if rec.Code == http.StatusForbidden {
				var body types.ApiError
				_ = json.Unmarshal(rec.Body.Bytes(), &body)
				if body.Code == "common.forbidden" {
					t.Errorf("%s: an OPEN route answered the admin gate's 403 — INV-A5's "+
						"\"list + detail stay open to every authenticated principal\" is broken", what)
				}
			}
			if len(f.admin.actions) != 0 {
				t.Errorf("%s: an open route reached the ADMIN gate (%v)", what, f.admin.actions)
			}
		}
	})
}

// TestLiveIsNotSwallowedByTheIdWildcard pins the one pattern overlap in the group.
//
// `GET /api/datasources/live` and `GET /api/datasources/{id}` both match `/api/datasources/live`.
// Ktor resolves that by registration order; Go 1.22+ patterns resolve it by SPECIFICITY, and the
// literal wins. Without this test a port that reordered the two Register lines would look fine and a
// port that dropped the literal would answer `common.bad_id` (because "live" is not a Long) — the
// exact symptom, and one nobody would connect back to routing.
func TestLiveIsNotSwallowedByTheIdWildcard(t *testing.T) {
	f := newFixture(t)
	f.events.attached["attached-one"] = struct{}{}

	rec := f.as("someone@example.com", "GET", "/api/datasources/live", "")
	assertStatus(t, rec, http.StatusOK, "GET /api/datasources/live")

	var names []string
	decodeJSON(t, rec, &names)
	if len(names) != 1 || names[0] != "attached-one" {
		t.Errorf("live returned %v, want [attached-one]", names)
	}
}

// ---------------------------------------------------------------------------------------------
// GET /api/datasources — the list
// ---------------------------------------------------------------------------------------------

// TestTheListIsUnfilteredByDefault is the first half of the deliberate openness at
// Datasources.kt:783-787: "JIT-request compose … must show datasources you CANNOT yet connect to,
// precisely so they can be requested".
//
// The connect fake denies everything, so if the default list were filtered this would answer `[]`.
func TestTheListIsUnfilteredByDefault(t *testing.T) {
	f := newFixture(t)
	f.seedDatasource("alpha", dbtest.EnginePostgres, "app")
	f.seedDatasource("beta", dbtest.EngineMySQL, "shop")

	rec := f.as("nobody@example.com", "GET", "/api/datasources", "")
	assertStatus(t, rec, http.StatusOK, "GET /api/datasources")

	var out []datasource.Datasource
	decodeJSON(t, rec, &out)
	if len(out) != 2 {
		t.Fatalf("unfiltered list returned %d datasources, want 2: %s", len(out), rec.Body.String())
	}
	// ORDER BY id — the store's, and it reaches the wire unchanged.
	if out[0].Name != "alpha" || out[1].Name != "beta" {
		t.Errorf("list order is %q,%q — want alpha,beta (ORDER BY id)", out[0].Name, out[1].Name)
	}
	if len(f.connect.calls) != 0 {
		t.Errorf("the default list ran %d connect decisions; it must run NONE", len(f.connect.calls))
	}
}

// TestConnectableTrueFiltersAndRunsTheTwoPassDecisionPerRow is the other half.
//
// 🔒 Three claims at once, and the last two are only observable from the recorded arguments:
//  1. `?connectable=true` narrows to what the caller may connect to.
//  2. The decision is keyed off the datasource NAME (INV-A2-2), never its numeric id.
//  3. It is the TWO-PASS path — pass 1 derives context tags, pass 2 sees them — and the datasource's
//     own tags are handed to both passes.
func TestConnectableTrueFiltersAndRunsTheTwoPassDecisionPerRow(t *testing.T) {
	f := newFixture(t)
	f.seedDatasource("alpha", dbtest.EnginePostgres, "app", "system:production")
	f.seedDatasource("beta", dbtest.EngineMySQL, "shop")
	f.connect.allow["alpha"] = true
	f.connect.derive = []string{"break-glass"}
	f.roles.roles["picker@example.com"] = []string{"analyst"}

	rec := f.as("picker@example.com", "GET", "/api/datasources?connectable=true", "")
	assertStatus(t, rec, http.StatusOK, "GET /api/datasources?connectable=true")

	var out []datasource.Datasource
	decodeJSON(t, rec, &out)
	if len(out) != 1 || out[0].Name != "alpha" {
		t.Fatalf("connectable list = %v, want just alpha: %s", out, rec.Body.String())
	}

	if len(f.connect.calls) != 4 {
		t.Fatalf("expected two passes over two datasources = 4 calls, got %d: %+v",
			len(f.connect.calls), f.connect.calls)
	}
	pass1, pass2 := f.connect.calls[0], f.connect.calls[1]
	if pass1.pass != "tags" || pass2.pass != "authorize" {
		t.Errorf("pass order is %q then %q, want tags then authorize", pass1.pass, pass2.pass)
	}
	if pass1.datasource != "alpha" || pass2.datasource != "alpha" {
		t.Errorf("decision keyed off %q/%q, want the datasource NAME alpha (INV-A2-2)",
			pass1.datasource, pass2.datasource)
	}
	if strings.Join(pass2.contextTags, ",") != "break-glass" {
		t.Errorf("pass 2 saw context tags %v, want pass 1's [break-glass] — the two-pass thread is broken",
			pass2.contextTags)
	}
	if strings.Join(pass2.dsTags, ",") != "system:production" {
		t.Errorf("pass 2 saw datasource tags %v, want [system:production]", pass2.dsTags)
	}
	if strings.Join(pass2.roles, ",") != "analyst" {
		t.Errorf("pass 2 saw roles %v, want [analyst]", pass2.roles)
	}
	// 🔒 INV-A2-10 — ONE role snapshot threaded through both passes of one datasource.
	if strings.Join(pass1.roles, ",") != strings.Join(pass2.roles, ",") {
		t.Errorf("the two passes saw different role snapshots: %v vs %v", pass1.roles, pass2.roles)
	}
	if pass2.action != authz.ActionDatasourceConnect {
		t.Errorf("pass 2 asked for %q, want %q", pass2.action, authz.ActionDatasourceConnect)
	}
}

// TestConnectableIsCaseInsensitiveEqualsTrueAndNothingElse pins the exact predicate:
// `queryParameters["connectable"].equals("true", ignoreCase = true)`.
//
// ⚠️ `?connectable=1`, `?connectable=yes` and `?connectable=` are all FALSE — i.e. they answer the
// UNFILTERED list. A port that used a permissive bool parse would silently narrow the picker's list
// for a client sending `1`, and a port that treated presence as truth would narrow it for
// `?connectable=false`.
func TestConnectableIsCaseInsensitiveEqualsTrueAndNothingElse(t *testing.T) {
	f := newFixture(t)
	f.seedDatasource("alpha", dbtest.EnginePostgres, "app")

	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", 1},
		{"?connectable=true", 0},
		{"?connectable=TRUE", 0},
		{"?connectable=TrUe", 0},
		{"?connectable=1", 1},
		{"?connectable=yes", 1},
		{"?connectable=false", 1},
		{"?connectable=", 1},
	} {
		rec := f.as("nobody@example.com", "GET", "/api/datasources"+tc.query, "")
		assertStatus(t, rec, http.StatusOK, "GET /api/datasources"+tc.query)
		var out []datasource.Datasource
		decodeJSON(t, rec, &out)
		if len(out) != tc.want {
			t.Errorf("GET /api/datasources%s returned %d rows, want %d", tc.query, len(out), tc.want)
		}
	}
}

// TestAnEmptyConnectableListIsAnArrayNotNull is INV-A1-4 at the one place a Go port most easily
// breaks it: a filter that removed every row leaves a nil slice, which encoding/json renders as
// `null` and the console renders `.length` on.
func TestAnEmptyConnectableListIsAnArrayNotNull(t *testing.T) {
	f := newFixture(t)
	f.seedDatasource("alpha", dbtest.EnginePostgres, "app")

	rec := f.as("nobody@example.com", "GET", "/api/datasources?connectable=true", "")
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("an empty connectable list is %q, want `[]` (INV-A1-4)", got)
	}
}

// TestAnEmptyDatasourceListIsAnArrayNotNull is the same claim for the unfiltered path, which goes
// through management.ListDatasources rather than the route's own slice.
func TestAnEmptyDatasourceListIsAnArrayNotNull(t *testing.T) {
	f := newFixture(t)
	rec := f.as("nobody@example.com", "GET", "/api/datasources", "")
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("an empty datasource list is %q, want `[]`", got)
	}
}

// TestAnEmptyLiveListIsAnArrayNotNull is the third. `attached()` on a control plane with no proxy is
// an empty set, and the console polls it.
func TestAnEmptyLiveListIsAnArrayNotNull(t *testing.T) {
	f := newFixture(t)
	rec := f.as("nobody@example.com", "GET", "/api/datasources/live", "")
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("an empty live list is %q, want `[]`", got)
	}
}

// TestLiveReportsEveryAttachedName covers the multi-name case, sorting first because the Kotlin's
// `Set<String>` carries no ordering guarantee and this port emits Go map order deliberately (see
// Routes.live).
func TestLiveReportsEveryAttachedName(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{"one", "two", "three"} {
		f.events.attached[n] = struct{}{}
	}
	rec := f.as("someone@example.com", "GET", "/api/datasources/live", "")
	assertStatus(t, rec, http.StatusOK, "GET /api/datasources/live")

	var names []string
	decodeJSON(t, rec, &names)
	got := strings.Join(sortedStrings(names), ",")
	if got != "one,three,two" {
		t.Errorf("live = %v, want the three attached names", names)
	}
}

// ---------------------------------------------------------------------------------------------
// POST /api/datasources/{id}/refresh
// ---------------------------------------------------------------------------------------------

// TestRefreshReportsTheNotifiedCountHonestlyIncludingZero.
//
// 🔒 A5 §1's RefreshResult: "0 means no proxy attached, reported honestly (A12 INV-A12-14's honesty
// rule surfaced at the REST layer)". A port that turned zero into a 404 or a 503 would take away the
// one fact the admin opened the page for, and would make "no proxy" indistinguishable from "no such
// datasource".
func TestRefreshReportsTheNotifiedCountHonestlyIncludingZero(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("refreshable", dbtest.EngineMySQL, "app")
	id := strconv.FormatInt(ds.ID, 10)

	rec := f.asAdmin("POST", "/api/datasources/"+id+"/refresh", "")
	assertStatus(t, rec, http.StatusOK, "refresh with no proxy attached")
	var zero datasource.RefreshResult
	decodeJSON(t, rec, &zero)
	if zero.Notified != 0 {
		t.Errorf("notified = %d with no proxy attached, want 0", zero.Notified)
	}

	f.events.notified["refreshable"] = 2
	rec = f.asAdmin("POST", "/api/datasources/"+id+"/refresh", "")
	assertStatus(t, rec, http.StatusOK, "refresh with two streams")
	var two datasource.RefreshResult
	decodeJSON(t, rec, &two)
	if two.Notified != 2 {
		t.Errorf("notified = %d, want 2", two.Notified)
	}

	// 🔒 The push is addressed by NAME, not by id — the events hub is keyed by datasource name.
	if len(f.events.refreshed) != 2 || f.events.refreshed[0] != "refreshable" {
		t.Errorf("refresh addressed %v, want the datasource NAME twice", f.events.refreshed)
	}
}

// TestRefreshRejectsABadIdAndAnUnknownId.
func TestRefreshRejectsABadIdAndAnUnknownId(t *testing.T) {
	f := newFixture(t)

	rec := f.asAdmin("POST", "/api/datasources/abc/refresh", "")
	assertStatus(t, rec, http.StatusBadRequest, "refresh with a non-numeric id")
	assertAPIError(t, rec, "common.bad_id", "refresh with a non-numeric id")

	rec = f.asAdmin("POST", "/api/datasources/999999/refresh", "")
	assertStatus(t, rec, http.StatusNotFound, "refresh an unknown id")
	body := assertAPIError(t, rec, "common.not_found", "refresh an unknown id")
	assertParam(t, body, "resource", "datasource", "refresh an unknown id")
	if len(f.events.refreshed) != 0 {
		t.Errorf("a 404 still pushed a refresh: %v", f.events.refreshed)
	}
}

// ---------------------------------------------------------------------------------------------
// POST /api/datasources — create
// ---------------------------------------------------------------------------------------------

// TestCreateIs201AndOnlyNameIsRequired.
//
// The whole point of the input DTO's defaults: a name-only placeholder created BEFORE any proxy
// attaches. There are no credential fields, by design — the control plane never dials a target.
func TestCreateIs201AndOnlyNameIsRequired(t *testing.T) {
	f := newFixture(t)
	rec := f.asAdmin("POST", "/api/datasources", `{"name":"placeholder"}`)
	assertStatus(t, rec, http.StatusCreated, "create a name-only datasource")

	var created datasource.Datasource
	decodeJSON(t, rec, &created)
	if created.Name != "placeholder" {
		t.Errorf("name = %q, want placeholder", created.Name)
	}
	// kotlinx's `engine: String = "postgres"` default, applied by DecodeDatasourceInput.
	if created.Engine != datasource.EnginePostgres {
		t.Errorf("engine = %v, want the postgres default", created.Engine)
	}
	if created.Host != "" || created.Port != 0 || created.DBName != "" {
		t.Errorf("advisory fields = %q/%d/%q, want the empty defaults", created.Host, created.Port, created.DBName)
	}
	// The two non-nullable lists reach the wire as [], and the row that predates any registration is
	// plaintext until a proxy says otherwise (V9's advertise_wire_tls NOT NULL DEFAULT FALSE).
	raw := rec.Body.String()
	for _, want := range []string{`"tags":[]`, `"defaultSchemas":[]`, `"advertiseWireTls":false`} {
		if !strings.Contains(raw, want) {
			t.Errorf("created body is missing %s: %s", want, raw)
		}
	}
	// explicitNulls=false: every absent optional is OMITTED, never null.
	for _, absent := range []string{"catalogSyncedAt", "lastSeenAt", "engineVersion", "advertiseAddr",
		"advertiseCertChain", "mysqlLowerCaseTableNames"} {
		if strings.Contains(raw, absent) {
			t.Errorf("created body carries %q; INV-A1-4 omits absent optionals: %s", absent, raw)
		}
	}
}

// TestCreateRejectsABlankName pins `common.field_required{fields: name}` — the plural param key
// carrying one field name, which is wire-visible because web/ interpolates it.
func TestCreateRejectsABlankName(t *testing.T) {
	f := newFixture(t)
	for _, body := range []string{`{"name":""}`, `{"name":"   "}`, `{}`} {
		rec := f.asAdmin("POST", "/api/datasources", body)
		assertStatus(t, rec, http.StatusBadRequest, "create with body "+body)
		e := assertAPIError(t, rec, "common.field_required", "create with body "+body)
		assertParam(t, e, "fields", "name", "create with body "+body)
	}
}

// TestCreateCanonicalizesTheEngineAndRejectsEverythingElse is 🔒 INV-A5-7.
//
// Quoting Datasources.kt:819-823 for why the canonicalization is not cosmetic: "a non-canonical value
// (e.g. 'Postgres', 'psql') would be stored verbatim and then LOCKED by the engine-immutability
// guard, so the datasource can never be adopted by its proxy … unusable until deletion."
//
// ⚠️ `postgresql` is REJECTED. EnginesTest case 2 asserts it explicitly — "Kotlin and Go both accept
// exactly {mysql, postgres}". A port that added the alias would let an admin create a row no proxy
// can ever register against.
func TestCreateCanonicalizesTheEngineAndRejectsEverythingElse(t *testing.T) {
	f := newFixture(t)

	t.Run("accepted spellings are stored canonically", func(t *testing.T) {
		for i, spelling := range []string{"mysql", "MySQL", "MYSQL"} {
			name := "canon-my-" + strconv.Itoa(i)
			rec := f.asAdmin("POST", "/api/datasources", `{"name":"`+name+`","engine":"`+spelling+`"}`)
			assertStatus(t, rec, http.StatusCreated, "create with engine "+spelling)
			var created datasource.Datasource
			decodeJSON(t, rec, &created)
			if created.Engine != datasource.EngineMySQL {
				t.Errorf("engine %q stored as %v, want mysql", spelling, created.Engine)
			}
			if !strings.Contains(rec.Body.String(), `"engine":"mysql"`) {
				t.Errorf("engine %q reached the wire as something other than \"mysql\": %s",
					spelling, rec.Body.String())
			}
		}
	})

	// ⚠️ `""` is deliberately ABSENT from this list. An explicit `"engine": ""` is indistinguishable
	// from an absent field after json.Unmarshal, so [datasource.DecodeDatasourceInput] applies
	// kotlinx's "postgres" default and the create SUCCEEDS where the Kotlin 400s — the D6 divergence,
	// isolated in TestAnExplicitEmptyEngineTakesThePostgresDefault below rather than hidden in a loop.
	t.Run("every other spelling is 400 datasource.invalid_engine echoing the input", func(t *testing.T) {
		for _, spelling := range []string{"postgresql", "psql", "pg", "maria", "sqlite", " mysql", "mysql "} {
			body := `{"name":"rejected","engine":"` + spelling + `"}`
			rec := f.asAdmin("POST", "/api/datasources", body)
			what := "create with engine " + strconv.Quote(spelling)
			assertStatus(t, rec, http.StatusBadRequest, what)
			e := assertAPIError(t, rec, "datasource.invalid_engine", what)
			// 🔒 The REJECTED spelling is echoed back verbatim, so the console can name the value it
			// sent. `engineFromWireOrNull` lowercases but does NOT trim, so " mysql" is a rejection.
			assertParam(t, e, "engine", spelling, what)
		}
	})
}

// TestAnExplicitEmptyEngineTakesThePostgresDefault is the D6 divergence the case above stops on,
// isolated and pinned rather than left as a surprise.
//
// ⚠️ Kotlin: `"engine": ""` is PRESENT, so the default does NOT apply, `engineFromWireOrNull("")`
// returns null, and the answer is 400 `datasource.invalid_engine{engine: ""}`. Go: json.Unmarshal
// cannot distinguish an absent string field from an explicitly-empty one, so
// [datasource.DecodeDatasourceInput] applies the default and the create SUCCEEDS as postgres.
// Fixing it needs a presence-aware decode encoding/json cannot express — the same D6 divergence
// recorded for every other DTO in the port — so it is pinned here rather than patched.
func TestAnExplicitEmptyEngineTakesThePostgresDefault(t *testing.T) {
	f := newFixture(t)
	rec := f.asAdmin("POST", "/api/datasources", `{"name":"empty-engine","engine":""}`)
	assertStatus(t, rec, http.StatusCreated,
		"D6: an explicit empty engine is indistinguishable from an absent one in Go")
	var created datasource.Datasource
	decodeJSON(t, rec, &created)
	if created.Engine != datasource.EnginePostgres {
		t.Errorf("engine = %v, want the postgres default", created.Engine)
	}
}

// TestADuplicateNameIsAnUnmapped500 is 🔒 §10 Q12 — REPRODUCED, NOT FIXED.
//
// `store.create` does no uniqueness check and the route catches only the engine conflict, so the
// `datasource_name_key` UNIQUE violation propagates to App.kt:452's `install(StatusPages) {
// exception<Throwable> }` and answers 500 `common.fallback` — NOT the 409 `datasource.name_taken`
// the honest code would emit.
//
// 🔴 This test asserts the BUGGY behaviour on purpose (PORT POLICY: REPRODUCE + PIN). §10 Q12 is an
// open decision; whoever takes it has to change this test, which is exactly the friction that keeps
// the change deliberate.
func TestADuplicateNameIsAnUnmapped500(t *testing.T) {
	f := newFixture(t)
	assertStatus(t, f.asAdmin("POST", "/api/datasources", `{"name":"taken"}`), http.StatusCreated, "first create")

	rec := f.asAdmin("POST", "/api/datasources", `{"name":"taken"}`)
	assertStatus(t, rec, http.StatusInternalServerError, "a duplicate name")
	assertAPIError(t, rec, "common.fallback", "a duplicate name")
}

// TestAMalformedBodyIs500NotBadRequest — the Kotlin route catches nothing around `call.receive`, so
// a body that will not parse reaches StatusPages. Turning it into a 400 would be a fix, and the web
// would stop being able to tell "the server rejected my body" from "the server broke".
func TestAMalformedBodyIs500NotBadRequest(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("malformed", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)

	for _, target := range []string{
		"/api/datasources",
		"/api/datasources/" + id + "/classification",
	} {
		method := "POST"
		if strings.HasSuffix(target, "classification") {
			method = "PUT"
		}
		rec := f.asAdmin(method, target, `{"name":`)
		assertStatus(t, rec, http.StatusInternalServerError, method+" "+target+" with a truncated body")
		assertAPIError(t, rec, "common.fallback", method+" "+target+" with a truncated body")
	}
}

// ---------------------------------------------------------------------------------------------
// GET / PUT / DELETE /api/datasources/{id}
// ---------------------------------------------------------------------------------------------

// TestGetOneAndItsTwoFailureModes.
func TestGetOneAndItsTwoFailureModes(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("one", dbtest.EngineMySQL, "app")

	rec := f.as("anyone@example.com", "GET", "/api/datasources/"+strconv.FormatInt(ds.ID, 10), "")
	assertStatus(t, rec, http.StatusOK, "get one")
	var got datasource.Datasource
	decodeJSON(t, rec, &got)
	if got.ID != ds.ID || got.Name != "one" {
		t.Errorf("got %+v, want the seeded row", got)
	}

	rec = f.as("anyone@example.com", "GET", "/api/datasources/nope", "")
	assertStatus(t, rec, http.StatusBadRequest, "get with a non-numeric id")
	assertAPIError(t, rec, "common.bad_id", "get with a non-numeric id")

	rec = f.as("anyone@example.com", "GET", "/api/datasources/999999", "")
	assertStatus(t, rec, http.StatusNotFound, "get an unknown id")
	body := assertAPIError(t, rec, "common.not_found", "get an unknown id")
	assertParam(t, body, "resource", "datasource", "get an unknown id")
}

// TestANegativeIdIs404NotBadRequestEverywhereExceptTableDetail is the id-parse inconsistency,
// isolated.
//
// ⚠️ `idParam()` is `toLongOrNull()`, which ACCEPTS a leading `-`, so `-1` parses, finds no row and
// 404s — on twelve of the thirteen routes. `{id}/table-detail` alone adds `?.takeIf { it > 0 }` and
// answers 400 `common.bad_id`. Two behaviours for one input, reproduced because the console may key
// off either.
func TestANegativeIdIs404NotBadRequestEverywhereExceptTableDetail(t *testing.T) {
	f := newFixture(t)

	rec := f.as("anyone@example.com", "GET", "/api/datasources/-1", "")
	assertStatus(t, rec, http.StatusNotFound, "GET /api/datasources/-1")
	assertAPIError(t, rec, "common.not_found", "GET /api/datasources/-1")

	for _, id := range []string{"-1", "0"} {
		rec = f.asAdmin("GET", "/api/datasources/"+id+"/table-detail?schema=s&table=t", "")
		assertStatus(t, rec, http.StatusBadRequest, "GET /api/datasources/"+id+"/table-detail")
		assertAPIError(t, rec, "common.bad_id", "GET /api/datasources/"+id+"/table-detail")
	}
}

// TestUpdateEditsTheAdvisoryFields.
func TestUpdateEditsTheAdvisoryFields(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("editable", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)

	rec := f.asAdmin("PUT", "/api/datasources/"+id,
		`{"name":"renamed","engine":"postgres","host":"newhost","port":6543,"dbName":"other"}`)
	assertStatus(t, rec, http.StatusOK, "update")

	var updated datasource.Datasource
	decodeJSON(t, rec, &updated)
	if updated.Name != "renamed" || updated.Host != "newhost" || updated.Port != 6543 || updated.DBName != "other" {
		t.Errorf("update produced %+v", updated)
	}
}

// TestTheEngineIsImmutableAndTheGuardIsA409 is 🔒 INV-A5-9.
//
// The reason it is fail-closed rather than a convenience: flipping the engine "would repoint every FK
// keyed off datasource_id (catalog_column, column_classification, query_history, access_request) at a
// schema from a different dialect, and the analyzer/system-classification manifest resolution keyed
// off engine would go stale — ALL FAIL-OPEN."
//
// The 409 body carries NO params: the offending engines live in the exception message (a log), never
// on the wire.
func TestTheEngineIsImmutableAndTheGuardIsA409(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("locked", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)

	rec := f.asAdmin("PUT", "/api/datasources/"+id, `{"name":"locked","engine":"mysql"}`)
	assertStatus(t, rec, http.StatusConflict, "flip the engine")
	body := assertAPIError(t, rec, "datasource.engine_immutable", "flip the engine")
	if len(body.Params) != 0 {
		t.Errorf("the 409 carries params %v; the Kotlin body is a bare ApiError", body.Params)
	}
	// Thrown BEFORE any write: the row is untouched.
	if after := f.mustGet(ds.ID); after.Engine != datasource.EnginePostgres || after.Name != "locked" {
		t.Errorf("the refused update still wrote: %+v", after)
	}
}

// TestANonCanonicalEngineOnUpdateDoesNotSpuriouslyConflict is the OTHER half of the canonicalization,
// and the one a port loses silently.
//
// Datasources.kt:850-852: "otherwise a PUT carrying 'Postgres', 'postgresql', or the DatasourceInput
// default 'postgres' would be compared verbatim against the stored canonical engine and spuriously
// trip the immutability guard below." So `"engine":"Postgres"` on a postgres row must be a 200, not a
// 409 — and `"engine":"postgresql"` must be a 400 (not a 409), because it never reaches the store.
func TestANonCanonicalEngineOnUpdateDoesNotSpuriouslyConflict(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("case-insensitive", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)

	rec := f.asAdmin("PUT", "/api/datasources/"+id, `{"name":"case-insensitive","engine":"Postgres"}`)
	assertStatus(t, rec, http.StatusOK, `PUT with engine "Postgres" on a postgres row`)

	rec = f.asAdmin("PUT", "/api/datasources/"+id, `{"name":"case-insensitive","engine":"postgresql"}`)
	assertStatus(t, rec, http.StatusBadRequest, `PUT with the rejected "postgresql" alias`)
	assertAPIError(t, rec, "datasource.invalid_engine", `PUT with the rejected "postgresql" alias`)
}

// TestUpdateRejectsABadIdAndAnUnknownId. Note the ORDER: the id parse precedes the body read, which
// precedes the engine validation, which precedes the store call — so an unknown id with an invalid
// engine answers `datasource.invalid_engine`, not `common.not_found`.
func TestUpdateRejectsABadIdAndAnUnknownId(t *testing.T) {
	f := newFixture(t)

	rec := f.asAdmin("PUT", "/api/datasources/xyz", `{"name":"n"}`)
	assertStatus(t, rec, http.StatusBadRequest, "update with a non-numeric id")
	assertAPIError(t, rec, "common.bad_id", "update with a non-numeric id")

	rec = f.asAdmin("PUT", "/api/datasources/999999", `{"name":"n"}`)
	assertStatus(t, rec, http.StatusNotFound, "update an unknown id")
	assertAPIError(t, rec, "common.not_found", "update an unknown id")

	rec = f.asAdmin("PUT", "/api/datasources/999999", `{"name":"n","engine":"nope"}`)
	assertStatus(t, rec, http.StatusBadRequest, "an unknown id with a bad engine")
	assertAPIError(t, rec, "datasource.invalid_engine",
		"the engine check precedes the store lookup, so this is 400 and not 404")
}

// TestDeleteIs204ThenNotFound — 204 with NO body, then 404 for the second attempt.
func TestDeleteIs204ThenNotFound(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("doomed", dbtest.EngineMySQL, "app")
	id := strconv.FormatInt(ds.ID, 10)

	rec := f.asAdmin("DELETE", "/api/datasources/"+id, "")
	assertStatus(t, rec, http.StatusNoContent, "delete")
	if rec.Body.Len() != 0 {
		t.Errorf("204 carried a body: %q", rec.Body.String())
	}

	rec = f.asAdmin("DELETE", "/api/datasources/"+id, "")
	assertStatus(t, rec, http.StatusNotFound, "delete twice")
	assertAPIError(t, rec, "common.not_found", "delete twice")
}

// TestUpdateAndDeleteNeverInvalidateTheInMemoryCatalog is 🔴 F21 — THE GAP, REPRODUCED AND PINNED.
//
// 05-datasources-catalog.md §10 Q1: admin PUT (rename or db_name change) and DELETE clear the
// PERSISTED catalog but never call `connectionCatalog.invalidateDatasource`. Because `authoritative`
// is keyed by datasource NAME, freeing a name leaves its authoritative entries and pooled refs live;
// the replacement target's Register then sees `priorDbName == null` and SKIPS invalidation entirely,
// inheriting them — on MySQL (`catalogIsConnectionIndependent = true`) the next connection ADOPTS
// them with no fetch.
//
// The mechanism lives below the routes, so what this test can pin is the ROUTE-LEVEL half of the
// gap: neither handler holds a registry reference at all, so there is no code path from an admin
// mutation to an invalidation. It asserts that by construction — [datasource.RouteDeps] has no
// registry field — and by behaviour: a rename through the route leaves a registry the routes were
// never given untouched, which is trivially true and is the point.
//
// 🔴 DO NOT "FIX" THIS BY WIRING THE REGISTRY IN. §10 Q1 is open; wiring it here would hide a
// possible live defect behind a port and would make the Kotlin and the Go answer differently.
func TestUpdateAndDeleteNeverInvalidateTheInMemoryCatalog(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("f21-original", dbtest.EngineMySQL, "app")
	id := strconv.FormatInt(ds.ID, 10)

	// A registry holding an authoritative entry for the name the admin is about to free.
	registry := datasource.NewConnectionCatalogRegistry()
	opened := registry.Open(datasource.Binding{
		DatasourceName: "f21-original", Principal: "alice", TokenKind: "SESSION",
	}, []string{"app"}, false)
	if len(opened.ConnectionID.Bytes()) == 0 {
		t.Fatal("registry.Open produced no connection id")
	}

	assertStatus(t, f.asAdmin("PUT", "/api/datasources/"+id, `{"name":"f21-renamed","engine":"mysql","dbName":"app"}`),
		http.StatusOK, "rename through the admin route")

	// F21: the rename freed the name and the registry still holds a live connection bound to it.
	if registry.ConnectionCount() != 1 {
		t.Errorf("registry lost its connection on rename — F21 says it does NOT, and the routes have "+
			"no registry reference to make it. count=%d", registry.ConnectionCount())
	}
	if got := f.mustGet(ds.ID).Name; got != "f21-renamed" {
		t.Fatalf("rename did not take: %q", got)
	}

	assertStatus(t, f.asAdmin("DELETE", "/api/datasources/"+id, ""), http.StatusNoContent, "delete")
	if registry.ConnectionCount() != 1 {
		t.Errorf("registry lost its connection on delete — same gap. count=%d", registry.ConnectionCount())
	}
}

// ---------------------------------------------------------------------------------------------
// POST /api/datasources/{id}/test
// ---------------------------------------------------------------------------------------------

// TestTestIsALivenessReportNotADial is the whole design constraint of the area, at its most visible
// surface: "the control-plane never dials a target database. It holds no target credential, so
// host/port/db_name are advisory display fields, and 'test connection' is a liveness report rather
// than a dial."
//
// ⚠️ `TestResult.message` is ENGLISH PROSE on the wire, which AGENTS.md says never happens outside
// SCIM (§10 Q8, the same class as F13). Asserted verbatim precisely BECAUSE it is a reproduced l10n
// gap: pinning the strings is what makes a later fix a deliberate wire change rather than a drift.
func TestTestIsALivenessReportNotADial(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("testable", dbtest.EngineMySQL, "app")
	id := strconv.FormatInt(ds.ID, 10)

	rec := f.asAdmin("POST", "/api/datasources/"+id+"/test", "")
	assertStatus(t, rec, http.StatusOK, "test with no proxy attached")
	var detached datasource.TestResult
	decodeJSON(t, rec, &detached)
	if detached.OK {
		t.Error("ok=true with no proxy attached")
	}
	if detached.Message != "no proxy attached; catalog not synced; never seen" {
		t.Errorf("message = %q, want the never-attached prose", detached.Message)
	}

	f.events.attached["testable"] = struct{}{}
	rec = f.asAdmin("POST", "/api/datasources/"+id+"/test", "")
	assertStatus(t, rec, http.StatusOK, "test with a proxy attached")
	var attached datasource.TestResult
	decodeJSON(t, rec, &attached)
	if !attached.OK {
		t.Error("ok=false with a proxy attached")
	}
	if attached.Message != "proxy attached; catalog not synced; never seen" {
		t.Errorf("message = %q, want the attached prose", attached.Message)
	}
}

// TestTestRejectsABadIdAndAnUnknownId.
func TestTestRejectsABadIdAndAnUnknownId(t *testing.T) {
	f := newFixture(t)

	rec := f.asAdmin("POST", "/api/datasources/nope/test", "")
	assertStatus(t, rec, http.StatusBadRequest, "test with a non-numeric id")
	assertAPIError(t, rec, "common.bad_id", "test with a non-numeric id")

	rec = f.asAdmin("POST", "/api/datasources/999999/test", "")
	assertStatus(t, rec, http.StatusNotFound, "test an unknown id")
	assertAPIError(t, rec, "common.not_found", "test an unknown id")
}

// ---------------------------------------------------------------------------------------------
// GET /api/datasources/{id}/table-detail
// ---------------------------------------------------------------------------------------------

// TestTableDetailRequiresBothSchemaAndTableInOneError.
//
// ⚠️ ONE param holding TWO comma-separated names: `{fields: "schema, table"}`, comma AND space. It
// fires when EITHER is missing or blank and names BOTH regardless of which was absent — so a client
// cannot tell from the body which one it forgot. Wire-visible; web/ interpolates `{fields}`.
func TestTableDetailRequiresBothSchemaAndTableInOneError(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("detailed", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)

	for _, query := range []string{"", "?schema=public", "?table=users", "?schema=&table=users", "?schema=public&table=%20"} {
		rec := f.asAdmin("GET", "/api/datasources/"+id+"/table-detail"+query, "")
		what := "table-detail" + query
		assertStatus(t, rec, http.StatusBadRequest, what)
		e := assertAPIError(t, rec, "common.field_required", what)
		assertParam(t, e, "fields", "schema, table", what)
	}
}

// TestTableDetailOrdersItsChecksTheKotlinsWay.
//
// 🔒 The order is observable and is the Kotlin's: bad id → field_required → datasource 404 → the
// management call. A request naming a NONEXISTENT datasource AND omitting the table answers
// `common.field_required`, not `common.not_found`.
func TestTableDetailOrdersItsChecksTheKotlinsWay(t *testing.T) {
	f := newFixture(t)

	rec := f.asAdmin("GET", "/api/datasources/999999/table-detail", "")
	assertStatus(t, rec, http.StatusBadRequest, "unknown datasource AND no params")
	assertAPIError(t, rec, "common.field_required",
		"the field check precedes the datasource lookup")

	rec = f.asAdmin("GET", "/api/datasources/999999/table-detail?schema=s&table=t", "")
	assertStatus(t, rec, http.StatusNotFound, "unknown datasource with params")
	body := assertAPIError(t, rec, "common.not_found", "unknown datasource with params")
	assertParam(t, body, "resource", "datasource", "unknown datasource with params")
	if len(f.details.calls) != 0 {
		t.Errorf("a 404 still asked the proxy: %v", f.details.calls)
	}
}

// TestTableDetailServesTheProxysAnswerVerbatim, and pins the top-level key set.
//
// 🔒 `TableDetailDbTest` pins the top-level keys to exactly
// {schema, table, columns, indexes, foreignKeys, referencedBy, metadata} and asserts that no
// `rows`/`data`/`preview` key ever appears — this route is METADATA ONLY, and a port that let row
// data ride along would turn an admin metadata surface into an unmasked read.
func TestTableDetailServesTheProxysAnswerVerbatim(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("detailed", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)
	f.details.detail = &engine.TableDetail{
		Schema: "public", Table: "users",
		Columns:  []engine.TableDetailColumn{{Name: "id", DataType: "integer", Ordinal: 1}},
		Metadata: engine.TableMetadata{Engine: "postgres"},
	}

	rec := f.asAdmin("GET", "/api/datasources/"+id+"/table-detail?schema=public&table=users", "")
	assertStatus(t, rec, http.StatusOK, "table-detail")

	var top map[string]json.RawMessage
	decodeJSON(t, rec, &top)
	want := map[string]bool{
		"schema": true, "table": true, "columns": true, "indexes": true,
		"foreignKeys": true, "referencedBy": true, "metadata": true,
	}
	for k := range top {
		if !want[k] {
			t.Errorf("unexpected top-level key %q in the table-detail body: %s", k, rec.Body.String())
		}
		delete(want, k)
	}
	for k := range want {
		t.Errorf("missing top-level key %q: %s", k, rec.Body.String())
	}
	for _, forbidden := range []string{`"rows"`, `"data"`, `"preview"`} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Errorf("the table-detail body carries %s — this route is metadata only", forbidden)
		}
	}
	// The three empty lists are `[]`, never null.
	for _, arr := range []string{`"indexes":[]`, `"foreignKeys":[]`, `"referencedBy":[]`} {
		if !strings.Contains(rec.Body.String(), arr) {
			t.Errorf("missing %s: %s", arr, rec.Body.String())
		}
	}
	// The proxy is asked by datasource NAME, and for exactly the schema/table requested.
	if len(f.details.calls) != 1 || f.details.calls[0] != [3]string{"detailed", "public", "users"} {
		t.Errorf("proxy asked %v, want [detailed public users]", f.details.calls)
	}
}

// TestAnAbsentTableIs404AndAFailedIntrospectionIs502 is the 502 arm of respondManagementError, which
// A5 is the only area that can reach.
//
// 🔒 "The 502 is the honest status for 'we asked the proxy and the proxy failed' — the control-plane
// is a gateway to the target, and a 500 would blame the wrong component." A port that mapped it to
// 500 sends the operator to the control plane's logs for a target-side failure.
func TestAnAbsentTableIs404AndAFailedIntrospectionIs502(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("detailed", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)

	t.Run("a nil detail with no error is not_found{resource: table}", func(t *testing.T) {
		f.details.detail, f.details.err = nil, nil
		rec := f.asAdmin("GET", "/api/datasources/"+id+"/table-detail?schema=public&table=ghost", "")
		assertStatus(t, rec, http.StatusNotFound, "an absent table")
		body := assertAPIError(t, rec, "common.not_found", "an absent table")
		// ⚠️ `table`, not `datasource` — the two 404s on this route are DIFFERENT resources and the
		// console renders different sentences for them.
		assertParam(t, body, "resource", "table", "an absent table")
	})

	t.Run("a proxy-side failure is 502 with the message in {detail}", func(t *testing.T) {
		f.details.detail = nil
		f.details.err = wrapExec("no proxy attached for datasource 'detailed'")
		rec := f.asAdmin("GET", "/api/datasources/"+id+"/table-detail?schema=public&table=users", "")
		assertStatus(t, rec, http.StatusBadGateway, "a proxy-side failure")
		body := assertAPIError(t, rec, "datasource.table_introspection_failed", "a proxy-side failure")
		if !strings.Contains(body.Params["detail"], "no proxy attached") {
			t.Errorf("{detail} = %q, want the proxy's own message", body.Params["detail"])
		}
	})

	t.Run("a NON-exec error is a plain 500, not a 502", func(t *testing.T) {
		f.details.detail, f.details.err = nil, errSentinel
		rec := f.asAdmin("GET", "/api/datasources/"+id+"/table-detail?schema=public&table=users", "")
		assertStatus(t, rec, http.StatusInternalServerError,
			"only ErrTableDetailExec earns the 502; anything else is a control-plane bug")
		assertAPIError(t, rec, "common.fallback", "a non-exec error")
	})
}

// ---------------------------------------------------------------------------------------------
// PUT / DELETE /api/datasources/{id}/classification
// ---------------------------------------------------------------------------------------------

// TestSetClassificationWritesThroughTheManagementLayer.
func TestSetClassificationWritesThroughTheManagementLayer(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("classified", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)
	maskID := f.seed.MaskFn("last4", "LAST4")

	body := `{"schema":"public","table":"users","column":"ssn","tags":["pii"],"maskFnId":` +
		strconv.FormatInt(maskID, 10) + `}`
	rec := f.asAdmin("PUT", "/api/datasources/"+id+"/classification", body)
	assertStatus(t, rec, http.StatusOK, "set a classification")

	var got datasource.Classification
	decodeJSON(t, rec, &got)
	if got.Schema != "public" || got.Table != "users" || got.Column != "ssn" {
		t.Errorf("classification = %+v", got)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "pii" {
		t.Errorf("tags = %v, want [pii]", got.Tags)
	}
	if got.MaskFnName == nil || *got.MaskFnName != "last4" {
		t.Errorf("maskFnName = %v, want last4 (resolved from the mask_fn row)", got.MaskFnName)
	}
	// It really landed.
	columns, err := f.store.ClassificationsFor(f.ctx, ds.ID)
	if err != nil {
		t.Fatalf("read back classifications: %v", err)
	}
	if len(columns) != 1 {
		t.Errorf("stored %d classifications, want 1", len(columns))
	}
}

// TestAReservedTagIsRefusedAndNothingIsStored is 🔒 INV-A11-28 at the route.
//
// 🔒 The `system:` namespace is owned by the shipped classification manifests. This is the WRITE-side
// half of A2's INV-A2-7 (which enforces the same rule at Cedar marshalling); both halves exist
// deliberately, and removing this one would let an admin mint `system:pii` through the API and have
// every shipped system policy start matching a column they chose.
//
// 🔒 The check runs BEFORE the write and reports the FIRST offender, so a list mixing one reserved
// tag with legitimate ones stores NONE of them.
func TestAReservedTagIsRefusedAndNothingIsStored(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("tagged", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)

	body := `{"schema":"public","table":"users","column":"ssn","tags":["ok","system:pii","system:other"]}`
	rec := f.asAdmin("PUT", "/api/datasources/"+id+"/classification", body)
	assertStatus(t, rec, http.StatusBadRequest, "a reserved tag")
	e := assertAPIError(t, rec, "datasource.reserved_tag", "a reserved tag")
	assertParam(t, e, "tag", "system:pii", "the FIRST offender is reported")

	stored, err := f.store.ClassificationsFor(f.ctx, ds.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(stored) != 0 {
		t.Errorf("the refused write stored %d rows; the guard runs BEFORE the write", len(stored))
	}

	// Case-sensitive prefix: `System:` is NOT reserved, matching the store's own strings.HasPrefix.
	rec = f.asAdmin("PUT", "/api/datasources/"+id+"/classification",
		`{"schema":"public","table":"users","column":"ssn","tags":["System:pii"]}`)
	assertStatus(t, rec, http.StatusOK, "`System:pii` is not the reserved prefix")
}

// TestANullSchemaWithNoDefaultIsSchemaRequired is 🔒 INV-A11-29.
//
// A classification landing on the wrong schema is a masking rule that never fires, so a null schema
// with nothing to resolve it to is a 400 rather than a silent write to some fallback.
func TestANullSchemaWithNoDefaultIsSchemaRequired(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("no-default", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)

	// default_schemas is `[]` until a proxy pushes a catalog, so there is nothing to resolve.
	rec := f.asAdmin("PUT", "/api/datasources/"+id+"/classification", `{"table":"users","column":"ssn"}`)
	assertStatus(t, rec, http.StatusBadRequest, "a null schema with no default")
	assertAPIError(t, rec, "datasource.schema_required", "a null schema with no default")

	rec = f.asAdmin("DELETE", "/api/datasources/"+id+"/classification", `{"table":"users","column":"ssn"}`)
	assertStatus(t, rec, http.StatusBadRequest, "the clear path resolves the schema too")
	assertAPIError(t, rec, "datasource.schema_required", "the clear path resolves the schema too")

	// Once a push captures a default schema, the same body succeeds and lands on it.
	f.seed.Namespace(ds.ID, []string{"pg_catalog", "app_schema"}, nil, "PostgreSQL 16.2")
	rec = f.asAdmin("PUT", "/api/datasources/"+id+"/classification", `{"table":"users","column":"ssn"}`)
	assertStatus(t, rec, http.StatusOK, "a null schema WITH a default")
	var got datasource.Classification
	decodeJSON(t, rec, &got)
	// 🔒 The FIRST NON-SYSTEM entry — `pg_catalog` is skipped.
	if got.Schema != "app_schema" {
		t.Errorf("resolved schema = %q, want app_schema (the first non-system default)", got.Schema)
	}
}

// TestClassificationRequiresTableAndColumn — the `required("table"); required("column")` pair, in
// that order, on both the PUT and the DELETE.
func TestClassificationRequiresTableAndColumn(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("required", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)

	for _, tc := range []struct{ body, want string }{
		{`{"schema":"public","table":"","column":"c"}`, "table"},
		{`{"schema":"public","table":"  ","column":"c"}`, "table"},
		{`{"schema":"public","table":"t","column":""}`, "column"},
		{`{"schema":"public","table":"","column":""}`, "table"}, // table is checked FIRST
	} {
		for _, method := range []string{"PUT", "DELETE"} {
			rec := f.asAdmin(method, "/api/datasources/"+id+"/classification", tc.body)
			what := method + " " + tc.body
			assertStatus(t, rec, http.StatusBadRequest, what)
			e := assertAPIError(t, rec, "common.field_required", what)
			assertParam(t, e, "fields", tc.want, what)
		}
	}
}

// TestClassificationOnAnUnknownDatasourceIs404 — the id goes straight to the management layer, so the
// 404 comes from inside the transaction that would have done the write.
func TestClassificationOnAnUnknownDatasourceIs404(t *testing.T) {
	f := newFixture(t)
	for _, method := range []string{"PUT", "DELETE"} {
		rec := f.asAdmin(method, "/api/datasources/999999/classification", `{"schema":"s","table":"t","column":"c"}`)
		assertStatus(t, rec, http.StatusNotFound, method+" classification on an unknown datasource")
		body := assertAPIError(t, rec, "common.not_found", method+" classification on an unknown datasource")
		assertParam(t, body, "resource", "datasource", method+" classification on an unknown datasource")
	}
}

// TestClearingAClassificationThatDoesNotExistIsStill204 is 🔒 §10 Q13 — REPRODUCED AND PINNED.
//
// The route DISCARDS `clearColumnClassification`'s `DeleteResult` (Datasources.kt:961-962), so
// deleting a classification that does not exist is **204, never 404**. The information is available
// at both the store and the management layer and is deliberately dropped here.
//
// 🔴 A port that 404s on zero rows turns an idempotent surface into a failing one. Q13 is open;
// changing the answer must change this test.
func TestClearingAClassificationThatDoesNotExistIsStill204(t *testing.T) {
	f := newFixture(t)
	ds := f.seedDatasource("idempotent", dbtest.EnginePostgres, "app")
	id := strconv.FormatInt(ds.ID, 10)

	body := `{"schema":"public","table":"users","column":"never-classified"}`
	rec := f.asAdmin("DELETE", "/api/datasources/"+id+"/classification", body)
	assertStatus(t, rec, http.StatusNoContent, "clear a classification that never existed")
	if rec.Body.Len() != 0 {
		t.Errorf("the 204 carried a body: %q — the DeleteResult must be discarded", rec.Body.String())
	}

	// And the real delete is also 204, with the row actually gone.
	assertStatus(t, f.asAdmin("PUT", "/api/datasources/"+id+"/classification",
		`{"schema":"public","table":"users","column":"ssn","tags":["pii"]}`), http.StatusOK, "seed one")
	rec = f.asAdmin("DELETE", "/api/datasources/"+id+"/classification",
		`{"schema":"public","table":"users","column":"ssn"}`)
	assertStatus(t, rec, http.StatusNoContent, "clear an existing classification")
	stored, err := f.store.ClassificationsFor(f.ctx, ds.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(stored) != 0 {
		t.Errorf("the delete left %d rows", len(stored))
	}
}

// TestClassificationRejectsABadId — both verbs, before the body is read.
func TestClassificationRejectsABadId(t *testing.T) {
	f := newFixture(t)
	for _, method := range []string{"PUT", "DELETE"} {
		rec := f.asAdmin(method, "/api/datasources/abc/classification", `{"table":"t","column":"c"}`)
		assertStatus(t, rec, http.StatusBadRequest, method+" classification with a bad id")
		assertAPIError(t, rec, "common.bad_id", method+" classification with a bad id")
	}
}

// TestRespondManagementErrorCarriesTheFullMapping pins all FOUR arms of
// `respondManagementError`'s `when` (Datasources.kt:709-717), plus the default.
//
// 🔴 03-identity-scim.md flagged a TRUNCATED copy of this switch as a finding, and the switch is
// declared in Datasources.kt — A5's file — while being called from six route files. A5 is also the
// only area that can REACH the 502 arm, so a truncation shows up here first or nowhere.
//
// ⚠️ This calls [httpapi.RespondManagementError] directly rather than driving a route, because three
// of the five arms are unreachable from any A5 route: the three `*.system_immutable` codes belong to
// A3 (groups), A9 (roles) and A2 (policies). Testing the switch where its OWNER lives is what stops
// the next area from re-deriving a partial copy — and it needs no edit to internal/httpapi.
//
// 🔒 THE DEFAULT ARM IS 400, NOT 500: a management service raises a code precisely when it has
// decided the REQUEST is at fault, and falling back to 500 would relabel every unlisted validation
// failure as a server bug.
func TestRespondManagementErrorCarriesTheFullMapping(t *testing.T) {
	for _, tc := range []struct {
		code string
		want int
	}{
		{"common.not_found", http.StatusNotFound},
		{"datasource.table_introspection_failed", http.StatusBadGateway},
		{"group.system_immutable", http.StatusConflict},
		{"role.system_immutable", http.StatusConflict},
		{"policy.system_immutable", http.StatusConflict},
		// The default arm, sampled across the areas that reach it.
		{"common.field_required", http.StatusBadRequest},
		{"common.already_exists", http.StatusBadRequest},
		{"datasource.reserved_tag", http.StatusBadRequest},
		{"datasource.schema_required", http.StatusBadRequest},
		{"anything.unlisted", http.StatusBadRequest},
	} {
		rec := httptest.NewRecorder()
		if err := httpapi.RespondManagementError(rec, types.ApiError{
			Code: tc.code, Params: map[string]string{"detail": "x"},
		}); err != nil {
			t.Fatalf("%s: %v", tc.code, err)
		}
		if rec.Code != tc.want {
			t.Errorf("%s answered %d, want %d", tc.code, rec.Code, tc.want)
		}
		// The BODY is the ApiError itself — code and params both survive, which is what the console
		// interpolates.
		body := assertAPIError(t, rec, tc.code, tc.code)
		assertParam(t, body, "detail", "x", tc.code)
	}
}

// wrapExec builds the error a TableDetails implementation must produce for the 502 arm: anything
// wrapping [management.ErrTableDetailExec]. A implementation that forgets to wrap turns a proxy-side
// timeout into a control-plane bug report — which is what the third subtest above pins.
func wrapExec(msg string) error { return &execError{msg: msg} }

type execError struct{ msg string }

func (e *execError) Error() string { return e.msg }
func (e *execError) Unwrap() error { return management.ErrTableDetailExec }
