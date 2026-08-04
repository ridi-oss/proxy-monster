package approval

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// SSESessionRecheckMs is `SSE_SESSION_RECHECK_MS = 30_000L` (App.kt:73) — the select's timeout arm,
// which carries BOTH the session re-validation and the keepalive.
const SSESessionRecheckMs int64 = 30_000

// SSEUnauthRetryMs is `SSE_UNAUTH_RETRY_MS = 60_000L` (App.kt:77).
//
// 🔒 INV-A1-12 — an unauthenticated stream LENGTHENS the client's reconnect backoff rather than
// erroring, because EventSource cannot be told to stop reconnecting after a 200 handshake. An
// expired-session tab then re-polls far less aggressively, and the app's 401ing polls are what
// redirect it to login. Poll is the truth; a missed event only delays an update.
const SSEUnauthRetryMs int64 = 60_000

// TaskEventsRoute is `internal fun Route.taskEventsRoute(...)` (App.kt:89-152) — ONE per-principal
// SSE stream of task terminal transitions, so a watching editor/approval tab updates immediately
// instead of on its next poll.
//
// ⚠️ Ktor gets SSE from a plugin App.kt does NOT install — the MCP SDK's stateless streamable-HTTP
// mount installs it and Ktor throws on a duplicate install (01-bootstrap.md:198-200). A Go port that
// replaces the MCP mount must supply SSE itself, which is what [TaskEventsRoute.stream] is.
//
// 🔒 INV-A1-10 — THE PUSH IS BOUND TO THE POLL'S AUTHORIZATION. Every event passes the same live
// `task.read` Cedar gate the poll and detail routes enforce, so a forbid that 404s the poll also
// suppresses the push, and the session is RE-VALIDATED every 30s so a revoked / expired /
// newest-wins-displaced session stops receiving pushes rather than streaming on its handshake
// identity.
//
// 🔒 INV-A1-11 — THE KEEPALIVE RIDES THE CONSUMER'S OWN GOROUTINE. Ktor's `heartbeat` helper writes
// from a SEPARATE coroutine, so when the client is gone its write throws where no handler can reach
// it — every ordinary disconnect surfaced as an unhandled exception and a 500. Writing on this loop
// puts the throw inside the recovery. The Go form of that rule: **all writes happen in
// [TaskEventsRoute.stream]'s single loop**, and a write error simply ends it. Do not "improve" this
// by moving the keepalive to its own goroutine and a shared writer — that reintroduces the bug and a
// data race on top of it.
type TaskEventsRoute struct {
	Gates *httpapi.Gates
	Hub   *TaskCompletionHub
	// Access answers the push filter's task lookup.
	Access AccessStore
	// Datasources supplies the task's datasource tags for the Cedar decision.
	Datasources Datasources
	// Authz is the SHARED Cedar graph (INV-A1-1) — the same one the poll routes ask.
	Authz *authz.Authz
	// Sessions resolves web-session liveness on the 30s tick. It is the PRINCIPAL_SESSION_STORE
	// attribute, narrowed to the two methods httpapi already declares.
	Sessions httpapi.WebSessionResolver
	// RecheckMs and UnauthRetryMs default to the two constants above. They are fields so a suite can
	// drive the timeout arm without a 30-second test.
	RecheckMs     int64
	UnauthRetryMs int64
	Log           *slog.Logger
}

var _ httpapi.RouteGroup = (*TaskEventsRoute)(nil)

// Register mounts the stream.
func (rt *TaskEventsRoute) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/tasks/events", rt.stream)
}

func (rt *TaskEventsRoute) log() *slog.Logger {
	if rt.Log != nil {
		return rt.Log
	}
	return slog.Default()
}

func (rt *TaskEventsRoute) recheck() time.Duration {
	ms := rt.RecheckMs
	if ms <= 0 {
		ms = SSESessionRecheckMs
	}
	return time.Duration(ms) * time.Millisecond
}

func (rt *TaskEventsRoute) unauthRetry() int64 {
	if rt.UnauthRetryMs <= 0 {
		return SSEUnauthRetryMs
	}
	return rt.UnauthRetryMs
}

// stream is the `sse("/api/tasks/events")` handler.
//
//  1. Resolve the live web session — or "debug-user" under authDebug, which reads NO session at all.
//     No principal ⇒ write `retry: 60000` and end (INV-A1-12).
//  2. Subscribe to the hub.
//  3. Loop on a two-way select:
//     • an event ⇒ filter through the live `task.read` gate; if permitted write `event: task` with
//     the JSON TaskEvent. Then re-check session liveness.
//     • the 30s tick ⇒ write a keepalive comment, then re-check session liveness.
//     A false liveness answer ends the stream.
//  4. A write failure or a closed client ends it QUIETLY — that is the NORMAL end of an SSE stream,
//     not a server fault. `defer` unsubscribes on every path.
func (rt *TaskEventsRoute) stream(w http.ResponseWriter, r *http.Request) {
	// 🔒 http.NewResponseController, NOT a `w.(http.Flusher)` type assertion. The plugin stack wraps
	// every response in httpapi's statusRecorder (StatusPages needs to know whether the response has
	// started), and a wrapper does not forward Flusher — a type assertion here fails and the whole
	// stream buffers until the connection closes, which presents as "SSE silently does not work".
	// statusRecorder implements Unwrap() for exactly this, and the controller follows it.
	rc := http.NewResponseController(w)
	flush := func() bool {
		err := rc.Flush()
		if err != nil && errors.Is(err, http.ErrNotSupported) {
			// Unreachable behind net/http's HTTP/1.1 and HTTP/2 writers. If it ever fires, say so
			// rather than streaming into a buffer nobody drains.
			rt.log().Error("task events: the response writer cannot flush, so SSE cannot be served")
			return false
		}
		return true
	}

	authDebug := rt.Gates.Config.AuthDebug

	// `val liveSession = if (config.authDebug) null else call.webSession()` — under authDebug the
	// session is never read, so a debug stream needs no cookie.
	var liveSession *session.WebRow
	if !authDebug {
		row, err := rt.Gates.Sessions.WebSession(r)
		if err != nil {
			httpapi.RespondFallback(w, r, rt.log(), err)
			return
		}
		liveSession = row
	}
	principal := ""
	switch {
	case liveSession != nil:
		principal = liveSession.Principal
	case authDebug:
		principal = DebugPrincipal
	}

	// The 200 handshake happens for BOTH branches: an EventSource that got a non-200 would surface a
	// connection error to the page, and INV-A1-12's whole point is to answer 200 and lengthen the
	// backoff instead.
	writeSSEHeaders(w)
	if !flush() {
		return
	}

	if principal == "" {
		// INV-A1-12.
		_, _ = w.Write([]byte("retry: " + strconv.FormatInt(rt.unauthRetry(), 10) + "\n\n"))
		flush()
		return
	}

	var sessionID *int64
	if liveSession != nil {
		id := liveSession.ID
		sessionID = &id
	}
	deviceID := session.DeviceCookieID(r)
	// The Cedar context is resolved ONCE at handshake, exactly as the Kotlin's `val context =
	// call.httpAuthzContext(config)` is — the stream has no later request to derive one from.
	pushContext := rt.Gates.AuthzContext(r)

	events := rt.Hub.Subscribe(principal)
	defer rt.Hub.Unsubscribe(principal, events)

	ctx := r.Context()
	timer := time.NewTimer(rt.recheck())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			// The client went away. Kotlin observes this as an IOException on the next write; either
			// way the stream just ends, quietly.
			return

		case event, open := <-events:
			if !open {
				// `result.getOrNull() ?: return@onReceiveCatching false` — a closed channel ends it.
				return
			}
			// 🔒 INV-A1-10 — the SAME live gate the poll enforces. A denied or absent task is SKIPPED,
			// not an error: the notification must never reveal metadata the poll would 404.
			readable, err := rt.taskReadableForPush(ctx, principal, event.TaskID, pushContext)
			if err != nil {
				// A store failure mid-stream is not a reason to leak the event. Skip it and keep the
				// stream open; the tab's poll is the source of truth (INV-A7-40).
				rt.log().Warn("task event push filter failed", "task", event.TaskID, "err", err)
			} else if readable {
				body, err := types.MarshalWire(event)
				if err != nil {
					rt.log().Error("failed to encode task event", "task", event.TaskID, "err", err)
					continue
				}
				if _, err := w.Write([]byte("event: task\ndata: " + string(body) + "\n\n")); err != nil {
					return
				}
				flush()
			}
			if !rt.sessionStillLive(ctx, authDebug, sessionID, deviceID) {
				return
			}

		case <-timer.C:
			// The keepalive AND the liveness re-check share this arm, as they do in the Kotlin, and
			// the write is on THIS goroutine — INV-A1-11.
			if _, err := w.Write([]byte(": keepalive\n\n")); err != nil {
				return
			}
			flush()
			if !rt.sessionStillLive(ctx, authDebug, sessionID, deviceID) {
				return
			}
		}
		// Kotlin's `select` restarts its onTimeout on every loop iteration, so the tick is 30s since
		// the LAST activity, not a fixed cadence. A time.Ticker would diverge.
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(rt.recheck())
	}
}

// sessionStillLive is `internal fun sessionStillLive(config, sessionId, deviceId, store)`
// (App.kt:155-156): `authDebug ∨ (sessionId != null ∧ store.resolveWeb(sessionId, deviceId) != null)`.
//
// 🔒 This is the half of INV-A1-10 that stops a revoked session streaming on its handshake identity.
// A resolver ERROR is treated as NOT live — fail-closed: an unreachable store must end the stream,
// never keep pushing.
func (rt *TaskEventsRoute) sessionStillLive(ctx context.Context, authDebug bool, sessionID *int64, deviceID *string) bool {
	if authDebug {
		return true
	}
	if sessionID == nil || rt.Sessions == nil {
		return false
	}
	row, err := rt.Sessions.ResolveWeb(ctx, *sessionID, deviceID)
	if err != nil {
		rt.log().Warn("task events session recheck failed", "sessionId", *sessionID, "err", err)
		return false
	}
	return row != nil
}

// taskReadableForPush is `internal fun taskReadableForPush(...)` (App.kt:160-179) — whether principal
// may still `task.read` taskId, asking the SAME question the poll and detail routes ask.
//
// authDebug ⇒ true. A MISSING TASK IS NOT READABLE (false), which is why a task deleted between the
// publish and the delivery produces no push rather than an unfiltered one.
func (rt *TaskEventsRoute) taskReadableForPush(
	ctx context.Context, principal string, taskID int64, pushContext authz.AuthzContext,
) (bool, error) {
	if rt.Gates.Config.AuthDebug {
		return true, nil
	}
	task, err := rt.Access.GetRequest(ctx, taskID)
	if err != nil {
		return false, err
	}
	if task == nil {
		return false, nil
	}
	var tags []string
	if task.DatasourceID != nil {
		ds, found, err := rt.Datasources.Get(ctx, *task.DatasourceID)
		if err != nil {
			return false, err
		}
		if found {
			tags = ds.Tags
		}
	}
	return rt.Authz.AuthorizeWithContext(
		principal, authz.ActionTaskRead, requestResource(*task), pushContext, task.DatasourceName, tags,
	).Allowed, nil
}

// writeSSEHeaders is the handshake Ktor's SSE plugin writes.
//
// `X-Accel-Buffering: no` is a PORT ADDITION with no Kotlin counterpart: nginx buffers a proxied
// response by default, which holds every event until the buffer fills — the stream then appears dead
// for minutes at a time. Ktor deployments hit the same thing and configure it at the proxy; stating
// it on the response makes the port work behind an unconfigured one.
func writeSSEHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
}

// errorString is a const-friendly error, used by this package's tests for a sentinel with no
// package-level variable.
type errorString string

func (e errorString) Error() string { return string(e) }
