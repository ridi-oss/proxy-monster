package httpapi

import (
	"log/slog"
	"net/http"
	"strings"
)

// RouteGroup is one of App.kt's fifteen `Route.xxxRoutes(...)` functions: a bundle of related routes
// that knows how to register itself.
//
// internal/oidc and internal/device already implement exactly this shape (`func (rt *Routes)
// Register(mux *http.ServeMux)`), so the interface is a naming of existing practice rather than a new
// convention. It is what lets internal/app mount a new area by adding ONE line to a slice instead of
// editing the mux by hand — the "extend without touching app.go" property.
type RouteGroup interface {
	Register(mux *http.ServeMux)
}

// RouteGroupFunc adapts a plain function to [RouteGroup], for a group too small to deserve a struct
// (`/health` and `/api/ingest/decision` are two such).
type RouteGroupFunc func(mux *http.ServeMux)

// Register implements RouteGroup.
func (f RouteGroupFunc) Register(mux *http.ServeMux) { f(mux) }

// Router is `Application.module()`'s routing half: the mux, the plugin stack, and the list of groups
// mounted on it.
//
// D6 (99-library-decisions.md §7) chose stdlib `net/http.ServeMux` for the whole 120-route table:
// every parameter in the Kotlin is a single literal segment (`{id}`, `{taskId}`, `{userId}` — no
// optional params, no tailcards, no regex constraints), which Go 1.22+ patterns cover exactly.
// Method-aware patterns give 405-with-Allow for free, and a CONFLICTING pattern registration PANICS
// AT STARTUP — which turns the route table into a boot-time consistency check.
//
// ⚠️ Three D6 conformance divergences, reproduced here as constraints rather than designed away:
//
//  1. TRAILING SLASH. Ktor's `IgnoreTrailingSlash` plugin is NOT installed, so `/a` and `/a/` are
//     distinct. ServeMux registering a pattern ENDING in `/` creates a subtree match AND a redirect
//     from the bare path — measured on go1.26.4 as 307 with `Location: /a/`, not the 301 the
//     pre-1.22 mux sent. So: never register a trailing-slash pattern. [Router.Mount] cannot enforce
//     that (the group owns its patterns), but every group in the port must honour it. The
//     REASSURING half, also measured: a BARE pattern does not match the trailing-slash path (404),
//     so the no-trailing-slash rule is sufficient on its own. Both pinned in router_test.go.
//
//  2. PATH CLEANING and `%2F`. ServeMux unescapes segment-by-segment and redirects unclean paths;
//     Ktor's behaviour here is Unverified. A conformance suite over `//`, `/./`, `%2F` and trailing
//     slashes is owed before the route table is trusted end to end.
//
//  3. HEAD — RESOLVED. ServeMux registers HEAD implicitly alongside every GET pattern and RUNS THE
//     GET HANDLER for it, which WIDENED the accepted method set on all ~120 routes at once. Ktor
//     answers HEAD on a `get {}` route only with the `AutoHeadResponse` plugin, which App.kt does not
//     install (01-bootstrap.md:195).
//
//     🔒 THE OPEN QUESTION IS NOW ANSWERED BY MEASUREMENT, not inference. This was recorded as
//     "Unverified on the Kotlin side (no JVM here)" with a TODO to confirm during cutover;
//     internal/conformance/differential booted BOTH control-planes and asked them:
//     `HEAD /api/roles` → Ktor 405, ServeMux 200. So the widening was real, and the choice the TODO
//     posed — HEAD-rejecting wrapper vs accepting it — is settled in favour of the wrapper.
//     [ktorRoutingSemantics] is that wrapper; TestAGETPatternAlsoServesHEAD now pins the 405.
type Router struct {
	mux         *http.ServeMux
	middlewares []Middleware
}

// RouterOptions are the plugin stack's inputs.
type RouterOptions struct {
	// Sessions seats the per-request identity holder. Nil skips that middleware, which makes every
	// request resolve its identity uncached — legal, and what a group with no session surface wants.
	Sessions *Sessions
	// Log is CallLogging's and StatusPages' logger. Defaults to slog.Default().
	Log *slog.Logger

	// Innermost are wrappers installed CLOSEST TO THE MUX, after the session holder, in the order
	// given. They are Ktor's application-level `intercept(Plugins)` hooks — the ones that must run
	// for EVERY request under a prefix, including a request the routing table has no handler for.
	//
	// 🔒 THE ONLY REASON THIS FIELD EXISTS is `installMcpOAuthProtocolGuard()` (App.kt:544). Its
	// whole job is `Cache-Control: no-store` + `Pragma: no-cache` on every `/oauth/**` path, and a
	// per-handler wrapper — which internal/oauth also applies, deliberately — cannot cover a 404
	// under `/oauth/`, because the mux never reaches a handler to wrap. A cached 404 is harmless on
	// its own; the guard being a PREFIX RULE rather than a per-route decoration is the property worth
	// keeping, so that a route added later cannot forget it.
	//
	// They sit INSIDE StatusPages on purpose: the guard writes into the header map before the handler
	// runs, so a panic recovered by StatusPages still carries the directives on its 500.
	Innermost []Middleware
}

// NewRouter builds the mux and the plugin stack IN APP.KT'S ORDER (App.kt:452-542):
//
//	ContentNegotiation → CallLogging → StatusPages → Sessions → Authentication
//
// ContentNegotiation is absent because it is not a wrapper in Go ([RespondJSON] is it), and
// Authentication is absent because it is PER-ROUTE in Ktor too ([Sessions.RequireWebSession]). What
// remains is CallLogging outermost, then StatusPages, then the Sessions holder.
//
// The order of the two that DO wrap is load-bearing in both directions:
//   - CallLogging outside StatusPages, so a panicking handler is logged with the 500 StatusPages
//     produced rather than with the status it never wrote.
//   - StatusPages outside Sessions, so a panic while resolving the session cookie still answers the
//     fallback body instead of escaping to net/http's bare connection reset.
func NewRouter(opts RouterOptions) *Router {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	mw := []Middleware{CallLogging(log), StatusPages(log)}
	if opts.Sessions != nil {
		mw = append(mw, opts.Sessions.Install)
	}
	mw = append(mw, opts.Innermost...)
	return &Router{mux: http.NewServeMux(), middlewares: mw}
}

// Mux exposes the bare mux, for a caller that must register a pattern itself.
func (rt *Router) Mux() *http.ServeMux { return rt.mux }

// Mount registers every group. Nil groups are skipped, so a caller can pass an optional area
// (`oidcRoutes` when config.oidc is set) without branching at the call site.
func (rt *Router) Mount(groups ...RouteGroup) {
	for _, g := range groups {
		if g == nil {
			continue
		}
		g.Register(rt.mux)
	}
}

// Handler is the mux wrapped in the plugin stack — the value to hand to http.Server.
func (rt *Router) Handler() http.Handler {
	return Chain(ktorRoutingSemantics(rt.mux), rt.middlewares...)
}

// wildcardMethods are the methods probed to discover which pattern a method-mismatched path belongs to.
// ServeMux reports an empty pattern on a mismatch, so the owning pattern has to be recovered by asking
// again under each method the API actually uses.
var wildcardMethods = []string{
	http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
	http.MethodPatch, http.MethodHead, http.MethodOptions,
}

// ktorRoutingSemantics reconciles net/http.ServeMux's routing answers with Ktor's, for the two shapes
// the differential harness measured them disagreeing on.
//
// 🔒 THE RULE IS MEASURED, NOT ASSUMED. internal/conformance/differential ran both control-planes over
// the same corpus; `MethodMismatch` there is the evidence and stays as the regression test. What it
// found, and the ONLY two things this wrapper changes:
//
//  1. A PARAMETERISED path with the wrong method: Ktor 404, ServeMux 405. `GET /api/roles/{id}` is
//     registered for PUT and DELETE only, and Ktor's routing fails the `{id}` segment outright when no
//     method selector under it matches, so the request never resolves to a route at all. ServeMux
//     matches the path first and rejects the method second, giving 405.
//  2. HEAD on a GET route: Ktor 405, ServeMux 200. ServeMux registers HEAD implicitly with every GET;
//     Ktor installs no AutoHeadResponse. This is the open question divergence 3 records above —
//     "confirm Ktor's answer to a HEAD on a get-only route during cutover" — and the answer is 405.
//
// ⚠️ WHAT IT DELIBERATELY DOES NOT CHANGE. A LITERAL path with the wrong method already agrees at 405 on
// both sides (`DELETE /api/roles`, `PUT /api/mask-fns`, `OPTIONS /api/roles`, `POST
// /api/datasources/live` all matched), and an unrouted path already agrees at 404. An earlier attempt
// collapsed EVERY 405 into a 404 on three data points, which broke those agreeing cases and the three
// tests that pin them. The narrow rule is the correct one; the broad one was a guess.
//
// 🔒 THE BODY IS SUPPRESSED TOO, and that choice is measured rather than argued. ServeMux answers its own
// 404/405 with text/plain English prose (`404 page not found`, `Method Not Allowed`); the harness measured
// Ktor sending an EMPTY body with no Content-Type. AGENTS.md's rule — "errors are never English prose on
// the wire: a route responds ApiError(code, params)" — would argue for a JSON body instead, and that was
// the tempting reading. But Ktor emits nothing, and inventing an ApiError here would be a NEW divergence
// dressed as a fix: no console code path parses a body from an unrouted request, so the only observable
// effect would be disagreeing with the implementation being ported. If the empty body is later judged a
// defect it is one on BOTH sides and belongs in a change that fixes both.
//
// Suppression is scoped to exactly the branches where ServeMux is about to write its own default error —
// nothing else can be writing a body on those paths.
func ktorRoutingSemantics(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)

		// HEAD resolves to the GET pattern, so a non-empty pattern here means ServeMux would serve it.
		// Ktor would not.
		if r.Method == http.MethodHead && pattern != "" && !patternDeclares(mux, http.MethodHead, r) {
			w.Header().Set("Allow", allowFor(mux, r))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}
		// Empty pattern: either nothing matches this path (Ktor 404, ServeMux 404 — agree), or the path
		// matches under another method (Ktor 405 for a literal, 404 for a parameterised one).
		owner, found := owningPattern(mux, r)
		if found && strings.ContainsRune(owner, '{') {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// ServeMux's own 404/405, with its prose body dropped to match Ktor's empty one.
		mux.ServeHTTP(bodylessErrors{w}, r)
	})
}

// bodylessErrors drops the response body for a 4xx status, so ServeMux's default text/plain prose does
// not reach the wire where Ktor sends nothing. The status and every header ServeMux set (notably `Allow`
// on a 405) are preserved — only the body is suppressed.
type bodylessErrors struct{ http.ResponseWriter }

func (b bodylessErrors) WriteHeader(status int) {
	if status >= 400 {
		// Content-Type/Length describe a body that will not be sent.
		b.Header().Del("Content-Type")
		b.Header().Del("X-Content-Type-Options")
		b.Header().Del("Content-Length")
	}
	b.ResponseWriter.WriteHeader(status)
}

func (b bodylessErrors) Write(p []byte) (int, error) {
	// Claim the write so net/http does not see a short write, but emit nothing.
	return len(p), nil
}

// patternDeclares reports whether the pattern serving r under `method` was registered for that method
// explicitly, as opposed to ServeMux inferring it. A GET registration answers HEAD with the SAME
// pattern string, so an explicit `HEAD /x` registration is distinguished by the pattern naming it.
func patternDeclares(mux *http.ServeMux, method string, r *http.Request) bool {
	_, pattern := mux.Handler(r)
	return strings.HasPrefix(pattern, method+" ")
}

// owningPattern finds the pattern a method-mismatched path belongs to, by re-asking under every method.
func owningPattern(mux *http.ServeMux, r *http.Request) (string, bool) {
	for _, m := range wildcardMethods {
		if m == r.Method {
			continue
		}
		probe := r.Clone(r.Context())
		probe.Method = m
		if _, pattern := mux.Handler(probe); pattern != "" {
			return pattern, true
		}
	}
	return "", false
}

// allowFor builds the Allow header for a 405 this wrapper raises, so the response still carries the
// header ServeMux would have.
func allowFor(mux *http.ServeMux, r *http.Request) string {
	var allowed []string
	for _, m := range wildcardMethods {
		if m == http.MethodHead {
			continue
		}
		probe := r.Clone(r.Context())
		probe.Method = m
		if _, pattern := mux.Handler(probe); pattern != "" && strings.HasPrefix(pattern, m+" ") {
			allowed = append(allowed, m)
		}
	}
	return strings.Join(allowed, ", ")
}
