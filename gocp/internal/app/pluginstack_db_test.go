package app

// ============================================================================================
// THE PLUGIN STACK, as the composition root assembles it — App.kt:446-544.
//
// Each case here asserts a property that is TRUE OF THE STACK AND OF NOTHING ELSE, so no area suite
// can hold it: the per-package suites build their own router (usually with no middleware at all) and
// would pass whatever internal/app did.
// ============================================================================================

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// 🔒 `installMcpOAuthProtocolGuard()` (App.kt:544) IS A PREFIX RULE, NOT A ROUTE DECORATION.
//
// internal/oauth wraps each of its own nine handlers in [oauth.ProtocolGuard] — deliberately, so the
// directives are right even before a composition root exists. What only the APPLICATION-level install
// can do is cover a path under `/oauth/` that the routing table has no handler for: the mux answers
// its own 404 and never reaches a wrapper. That 404 is not itself a credential, but the guard's value
// is that it holds for the whole prefix rather than for whichever routes someone remembered to
// decorate — so a route added tomorrow is covered on the day it is added.
//
// A failure here means [httpapi.RouterOptions.Innermost] stopped carrying the guard.
func TestTheOAuthProtocolGuardCoversAPathWithNoHandler(t *testing.T) {
	s := newAuthServer(t, nil)
	resp := s.do(s.bare(), http.MethodGet, "/oauth/there-is-no-such-endpoint", "")

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 — the probe must be an UNROUTED path for this to mean anything",
			resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store on an unrouted /oauth/ path", got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache on an unrouted /oauth/ path", got)
	}
}

// The other half of the prefix rule: it is `startsWith("/oauth/")`, WITH the trailing slash
// (OAuthRoutes.kt:95-102), so the discovery documents are NOT covered — and that is the point of a
// discovery document, which is meant to be cacheable.
//
// ⚠️ `/.well-known/oauth-authorization-server` is the one path StatusPages ALSO treats as OAuth
// (App.kt:458, an `==` not a prefix). The two rules are deliberately different and this pins that
// they have not been merged: the metadata route is OAuth-shaped for ERRORS and cache-normal for
// HEADERS.
func TestTheOAuthGuardDoesNotTouchTheDiscoveryDocuments(t *testing.T) {
	s := newAuthServer(t, nil)

	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/mcp",
	} {
		resp := s.do(s.bare(), http.MethodGet, path, "")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s = %d, want 200", path, resp.StatusCode)
		}
		if got := resp.Header.Get("Cache-Control"); got != "" {
			t.Errorf("%s carries Cache-Control %q; the guard is `/oauth/`-prefixed and must not reach a "+
				"discovery document", path, got)
		}
	}
}

// 🔒 SSE SURVIVES THE MIDDLEWARE STACK — the Go-specific half of 01-bootstrap.md's SSE note.
//
// Ktor does not `install(SSE)` in `module()` because the MCP SDK's mount installs it unconditionally
// and a duplicate install throws (App.kt:464), so over there `/api/tasks/events` gets its transport as
// a SIDE EFFECT of `installMcp`. In Go there is no SSE plugin and no such coupling:
// approval.TaskEventsRoute writes the `text/event-stream` framing itself. Nothing needs installing —
// but something CAN still break it, and it lives in this package.
//
// httpapi's StatusPages wraps every response in `statusRecorder`, and a wrapper does not forward
// http.Flusher. The route flushes through http.NewResponseController, which follows `Unwrap()` —
// so deleting statusRecorder.Unwrap silently turns the stream into a buffer that is delivered when
// the handler returns, i.e. never. No unit test of the route can see that, because the route's own
// suite does not install the stack.
//
// THE ASSERTION IS THAT THE RESPONSE STAYS OPEN, and picking that took a correction worth recording:
// asserting only "the headers arrived, with the right Content-Type" PASSES WITH THE BUG. When the
// controller cannot find a flusher it returns http.ErrNotSupported, and the route's own guard then
// logs "the response writer cannot flush" and RETURNS — which completes the response, headers and
// all, in milliseconds. A header-only check cannot tell that apart from a healthy stream.
//
// What distinguishes them is what happens NEXT. Healthy: the handler is parked on its 30-second
// recheck tick with no bytes written, so a read on the body BLOCKS. Broken: the handler has already
// returned, so the body is at EOF immediately. So the test reads, and a read that COMPLETES is the
// failure.
func TestTaskEventsStreamsThroughThePluginStack(t *testing.T) {
	s := newAuthServer(t, nil) // PM_DEV=true ⇒ PM_AUTH_DEBUG on ⇒ principal "debug-user", no cookie needed.

	// Comfortably under the route's 30s recheck tick, so a healthy stream writes nothing in the window.
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, s.server.URL+"/api/tasks/events", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/tasks/events: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 — INV-A1-12 requires a 200 handshake even with no principal",
			resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	// Closing the body (deferred above) unblocks this read, so the goroutine cannot outlive the test.
	type readResult struct {
		n   int
		err error
	}
	done := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 1)
		n, err := resp.Body.Read(buf)
		done <- readResult{n, err}
	}()

	select {
	case got := <-done:
		t.Fatalf("the stream ended immediately (read returned n=%d err=%v) instead of staying open.\n"+
			"The handshake headers alone do NOT prove SSE works: when http.NewResponseController cannot "+
			"find a flusher it returns ErrNotSupported, the route logs \"the response writer cannot "+
			"flush\" and returns, and the client still sees 200 text/event-stream. The likely cause is a "+
			"middleware wrapper in this package's stack that no longer forwards Flush — "+
			"httpapi.statusRecorder.Unwrap.", got.n, got.err)
	case <-time.After(2 * time.Second):
		// Parked on the recheck tick with the headers already delivered: the flush went through the
		// whole stack and the connection is a live stream.
	}
}
