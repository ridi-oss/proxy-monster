package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// Router — `Application.module()`'s routing half, and D6's stdlib-ServeMux choice
// (99-library-decisions.md §7).
//
// What this file pins is the property the whole route table depends on: a group registers PATTERNS
// and gets the plugin stack for free, in App.kt's order, without knowing the stack exists. Every
// other area's routes will be mounted through [Router.Mount], so a stack that silently stopped
// applying would take the StatusPages contract down across ~120 routes at once with nothing failing
// locally.

// panicGroup is a route group whose handler always blows up — the only way to observe StatusPages
// from outside.
func panicGroup(pattern string) RouteGroup {
	return RouteGroupFunc(func(mux *http.ServeMux) {
		mux.HandleFunc(pattern, func(http.ResponseWriter, *http.Request) {
			panic("boom: a handler failed in a way nobody planned for")
		})
	})
}

// 🔒 The plugin stack reaches a MOUNTED route, not only a hand-wrapped one. If Handler() ever
// returned the bare mux, every route in the port would lose the catch-all body and answer net/http's
// bare connection reset instead.
func TestRouterAppliesStatusPagesToMountedRoutes(t *testing.T) {
	rt := NewRouter(RouterOptions{Log: silentLogger()})
	rt.Mount(panicGroup("GET /api/datasources"))

	rec := httptest.NewRecorder()
	rt.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/datasources", nil))

	assertStatus(t, rec, http.StatusInternalServerError, "panicking handler")
	var body types.ApiError
	decodeBody(t, rec, &body)
	if body.Code != "common.fallback" {
		t.Errorf("code = %q, want \"common.fallback\"", body.Code)
	}
}

// The OAuth branch survives the mount too — an MCP client parses `{"error":…}` and has no schema for
// `{"code":…}`.
func TestRouterAppliesTheOAuthBranchToMountedRoutes(t *testing.T) {
	rt := NewRouter(RouterOptions{Log: silentLogger()})
	rt.Mount(panicGroup("POST /oauth/token"))

	rec := httptest.NewRecorder()
	rt.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/oauth/token", nil))

	assertStatus(t, rec, http.StatusInternalServerError, "panicking oauth handler")
	var body types.OAuthError
	decodeBody(t, rec, &body)
	if body.Error != "server_error" {
		t.Errorf("error = %q, want \"server_error\"", body.Error)
	}
}

// The Sessions middleware is part of the stack when one is supplied, so a mounted handler sees the
// per-request resolution holder and INV-A4-11's caching actually applies in production. Without this
// wiring the cache would silently never engage — every gate on a request would re-resolve, and a
// device-binding mismatch would end the row on the first gate and then fail the second.
func TestRouterInstallsTheSessionsHolderWhenOneIsSupplied(t *testing.T) {
	sessions, _, _ := liveSessions(t)
	rt := NewRouter(RouterOptions{Sessions: sessions, Log: silentLogger()})

	var seated bool
	rt.Mount(RouteGroupFunc(func(mux *http.ServeMux) {
		mux.HandleFunc("GET /probe", func(w http.ResponseWriter, r *http.Request) {
			seated = identityOf(r) != nil
			w.WriteHeader(http.StatusOK)
		})
	}))

	rt.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/probe", nil))
	if !seated {
		t.Error("a mounted handler did not see the resolution holder; Sessions.Install is not in the stack")
	}
}

// Nil Sessions is legal — a group with no session surface wants exactly that, and it must not panic.
func TestRouterWithoutSessionsStillServes(t *testing.T) {
	rt := NewRouter(RouterOptions{Log: silentLogger()})
	rt.Mount(RouteGroupFunc(func(mux *http.ServeMux) {
		mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
			if identityOf(r) != nil {
				t.Error("no Sessions was supplied, so no holder should be seated")
			}
			w.WriteHeader(http.StatusOK)
		})
	}))

	rec := httptest.NewRecorder()
	rt.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	assertStatus(t, rec, http.StatusOK, "health with no sessions")
}

// Mount skips nil so a caller can pass an OPTIONAL area — `oidcRoutes` only when config.oidc is set
// — without branching at the call site. That is the shape App.kt's conditional route groups need.
func TestMountSkipsNilGroups(t *testing.T) {
	rt := NewRouter(RouterOptions{Log: silentLogger()})
	reached := false
	rt.Mount(
		nil,
		RouteGroupFunc(func(mux *http.ServeMux) {
			mux.HandleFunc("GET /probe", func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})
		}),
		nil,
	)

	rt.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/probe", nil))
	if !reached {
		t.Error("a group registered after a nil one was skipped")
	}
}

// Method-aware patterns give 405-with-Allow for free — one of the two reasons D6 chose the stdlib
// mux over a third-party router.
func TestRouterAnswers405WithAllowForAWrongMethod(t *testing.T) {
	rt := NewRouter(RouterOptions{Log: silentLogger()})
	rt.Mount(RouteGroupFunc(func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/tokens", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}))

	rec := httptest.NewRecorder()
	rt.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/tokens", nil))

	assertStatus(t, rec, http.StatusMethodNotAllowed, "wrong method")
	// "GET, HEAD", not "GET" — see TestAGETPatternAlsoServesHEAD.
	if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("Allow = %q, want \"GET, HEAD\"", allow)
	}
}

// 🔴 D6 CONFORMANCE DIVERGENCE, FOUND HERE AND NOT PREVIOUSLY RECORDED: Go's ServeMux registers HEAD
// implicitly alongside every GET pattern and RUNS THE GET HANDLER for it. Ktor does not — a `get {}`
// route answers HEAD only when the `AutoHeadResponse` plugin is installed, and App.kt's plugin list
// (01-bootstrap.md:195) does not install it.
//
// Measured, this session, on go1.26.4: `GET /a` registered alone answers GET 200, HEAD 200 (handler
// executed), POST 405. Unverified on the Kotlin side — there is no JVM on this machine, so what Ktor
// answers to a HEAD on a get-only route is reasoned from the absent plugin, not measured.
//
// It is NOT an authorization hole: a HEAD reaches the same handler and therefore the same gate, so
// nothing becomes readable that a GET could not read. What it widens is the accepted METHOD SET, and
// it does so for all ~120 routes at once. Reproducing the Kotlin would mean rejecting HEAD in the
// stack, which is a behaviour change of its own and is not obviously the safer default (a HEAD on a
// read route is harmless and some monitoring tools use it), so this is RECORDED AND PINNED rather
// than silently accepted or silently "fixed".
//
// 🔒 IT IS NOW INVERTED, BECAUSE THE MEASUREMENT LANDED. This case used to assert 200-with-the-handler-run
// and told its own reader what to do when that changed: "if this changed, the divergence note above is
// stale and A1's cutover TODO can be closed". internal/conformance/differential ran both control-planes
// and measured `HEAD /api/roles` → Ktor 405, Go 200, so [ktorRoutingSemantics] now rejects HEAD on a
// GET-only route and this pins the Ktor-matching 405.
//
// The `Allow` header is asserted too, and deliberately WITHOUT HEAD in it: advertising HEAD while
// refusing it is worse than either answer alone, because a client that reads Allow would retry the
// method it was just refused.
func TestAGETPatternAlsoServesHEAD(t *testing.T) {
	rt := NewRouter(RouterOptions{Log: silentLogger()})
	ran := 0
	rt.Mount(RouteGroupFunc(func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/tokens", func(w http.ResponseWriter, _ *http.Request) {
			ran++
			w.WriteHeader(http.StatusOK)
		})
	}))

	rec := httptest.NewRecorder()
	rt.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/api/tokens", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("HEAD /api/tokens = %d, want 405 — Ktor installs no AutoHeadResponse, measured directly "+
			"in internal/conformance/differential (mm-head-to-get-literal: kotlin=405)", rec.Code)
	}
	if ran != 0 {
		t.Errorf("the GET handler ran %d time(s) for a HEAD; it must be refused before the handler, or "+
			"the route's side effects happen on a method Ktor rejects outright", ran)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET" {
		t.Errorf("Allow = %q, want \"GET\" — HEAD must not appear in the set that just refused it", allow)
	}
}

// 🔒 The other reason D6 chose it: a CONFLICTING pattern registration PANICS AT REGISTRATION, which
// turns the 120-route table into a boot-time consistency check. Two areas that both claim
// `GET /api/tokens/{id}` fail the process on the first boot rather than shadowing each other in
// whatever order the mounts happened to run.
func TestConflictingPatternsPanicAtRegistration(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("registering the same pattern twice did not panic; the route table would " +
				"silently shadow instead of failing at boot")
		}
	}()

	rt := NewRouter(RouterOptions{Log: silentLogger()})
	rt.Mount(
		RouteGroupFunc(func(mux *http.ServeMux) { mux.HandleFunc("GET /api/tokens/{id}", noopHandler) }),
		RouteGroupFunc(func(mux *http.ServeMux) { mux.HandleFunc("GET /api/tokens/{id}", noopHandler) }),
	)
}

// ⚠️ D6 conformance divergence #1, pinned as a CONSTRAINT rather than designed away. Ktor's
// `IgnoreTrailingSlash` plugin is NOT installed, so `/a` and `/a/` are distinct paths there. Go's
// ServeMux treats a pattern ENDING in `/` as a subtree match AND redirects the bare path onto it —
// a behaviour with no Kotlin counterpart. This test documents what the port MUST NOT do, so a route
// group that registers a trailing-slash pattern is a visible, deliberate change.
//
// Measured on go1.26.4: the redirect is 307 with `Location: /api/things/`, NOT the 301 the older
// pre-1.22 mux sent.
func TestATrailingSlashPatternRedirectsWhichIsWhyGroupsMustNotRegisterOne(t *testing.T) {
	rt := NewRouter(RouterOptions{Log: silentLogger()})
	rt.Mount(RouteGroupFunc(func(mux *http.ServeMux) { mux.HandleFunc("GET /api/things/", noopHandler) }))

	rec := httptest.NewRecorder()
	rt.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/things", nil))

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("GET /api/things = %d, want 307 — the stdlib subtree redirect. If this changed, the "+
			"no-trailing-slash rule in Router's doc needs revisiting", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/api/things/" {
		t.Errorf("Location = %q, want /api/things/", loc)
	}
}

// 🔒 The other half of divergence #1, and the reassuring half: as long as no group registers a
// trailing-slash pattern, Ktor's `/a` ≠ `/a/` distinctness HOLDS in Go. A request for `/a/` against
// a bare `/a` pattern is a 404, not a match — so the no-trailing-slash rule is sufficient on its
// own and no IgnoreTrailingSlash-equivalent is needed anywhere.
func TestABarePatternDoesNotMatchTheTrailingSlashPath(t *testing.T) {
	rt := NewRouter(RouterOptions{Log: silentLogger()})
	rt.Mount(RouteGroupFunc(func(mux *http.ServeMux) { mux.HandleFunc("GET /api/things", noopHandler) }))

	rec := httptest.NewRecorder()
	rt.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/things/", nil))

	assertStatus(t, rec, http.StatusNotFound, "/a/ against a bare /a pattern")
}

// A path no group claimed is a 404 from the mux, and it still goes through the stack (so it is
// logged like any other call) rather than short-circuiting somewhere invisible.
func TestAnUnmountedPathIs404(t *testing.T) {
	rt := NewRouter(RouterOptions{Log: silentLogger()})
	rec := httptest.NewRecorder()
	rt.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	assertStatus(t, rec, http.StatusNotFound, "unmounted path")
}

// Mux() is the escape hatch for a caller that must register a pattern itself; it must be the SAME
// mux Mount writes to, or half the route table would be invisible.
func TestMuxIsTheSameMuxMountWritesTo(t *testing.T) {
	rt := NewRouter(RouterOptions{Log: silentLogger()})
	rt.Mount(RouteGroupFunc(func(mux *http.ServeMux) {
		if mux != rt.Mux() {
			t.Error("Mount handed the group a different mux than Mux() returns")
		}
	}))
}

func noopHandler(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
