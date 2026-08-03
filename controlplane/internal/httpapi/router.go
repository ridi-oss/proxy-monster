package httpapi

import (
	"log/slog"
	"net/http"
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
//  2. PATH CLEANING and `%2F`. ServeMux unescapes segment-by-segment and redirects unclean paths;
//     Ktor's behaviour here is Unverified. A conformance suite over `//`, `/./`, `%2F` and trailing
//     slashes is owed before the route table is trusted end to end.
//  3. 🔴 HEAD. ServeMux registers HEAD implicitly alongside every GET pattern and RUNS THE GET
//     HANDLER for it (measured on go1.26.4: GET 200, HEAD 200 with the handler executed, POST 405;
//     the 405's `Allow` reads `GET, HEAD`). Ktor answers HEAD on a `get {}` route only with the
//     `AutoHeadResponse` plugin, which App.kt does not install (01-bootstrap.md:195) — so this
//     WIDENS the accepted method set on all ~120 routes at once. It is not an authorization hole: a
//     HEAD reaches the same handler and therefore the same gate. Unverified on the Kotlin side (no
//     JVM here), so it is RECORDED AND PINNED (TestAGETPatternAlsoServesHEAD) rather than silently
//     accepted or silently "fixed".
//
// Still owed on divergence 3:
//
//	TODO(A1): confirm Ktor's answer to a HEAD on a get-only route during cutover, then decide
//	between a HEAD-rejecting wrapper here and accepting the widening.
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
	return Chain(rt.mux, rt.middlewares...)
}
