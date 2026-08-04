package approval

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
)

// ---------------------------------------------------------------------------------------------
// `TaskEventsRouteDbTest` — 2 cases, DB + SSE route (07-tasks-approvals-results.md §10;
// 01-bootstrap.md §2's `taskEventsRoute`).
//
// The stream is driven over a REAL http server, not an httptest.ResponseRecorder: a recorder gives no
// incremental read, and the two properties under test — "the event is suppressed" and "the stream
// ends when the session dies" — are both about what arrives WHEN. The fixture's recheck interval is
// 40ms (support_db_test.go), so the keepalive that acts as the barrier below lands promptly.
// ---------------------------------------------------------------------------------------------

// sseStream is one open EventSource, read line by line on the test's own goroutine.
type sseStream struct {
	t      *testing.T
	cancel context.CancelFunc
	body   io.ReadCloser
	reader *bufio.Reader
	server *httptest.Server
}

// openStream connects to /api/tasks/events and returns once the handshake has produced its headers.
func (f *httpFixture) openStream(cookie *http.Cookie) *sseStream {
	f.t.Helper()
	server := httptest.NewServer(f.handler)
	f.t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/tasks/events", nil)
	if err != nil {
		cancel()
		f.t.Fatalf("build SSE request: %v", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		cancel()
		f.t.Fatalf("open SSE stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		f.t.Fatalf("SSE handshake: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		f.t.Errorf("Content-Type: got %q, want text/event-stream", ct)
	}
	s := &sseStream{t: f.t, cancel: cancel, body: resp.Body, reader: bufio.NewReader(resp.Body), server: server}
	f.t.Cleanup(s.close)
	return s
}

func (s *sseStream) close() {
	s.cancel()
	_ = s.body.Close()
}

// readLine returns the next non-empty line, "" on EOF, and fails on a timeout.
func (s *sseStream) readLine(within time.Duration) string {
	s.t.Helper()
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		for {
			line, err := s.reader.ReadString('\n')
			trimmed := strings.TrimRight(line, "\r\n")
			if err != nil {
				ch <- result{trimmed, err}
				return
			}
			if trimmed == "" {
				continue // the blank line that ends an SSE frame
			}
			ch <- result{trimmed, nil}
			return
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil && r.line == "" {
			return "" // EOF: the stream ended
		}
		return r.line
	case <-time.After(within):
		s.t.Fatalf("timed out after %s waiting for an SSE line", within)
		return ""
	}
}

// awaitKeepalive reads until the next keepalive comment, returning every line seen before it. It is
// the BARRIER a suppression assertion needs: once a keepalive has arrived, the loop has been round at
// least once past the published event, so "nothing arrived" is a fact and not a race.
func (s *sseStream) awaitKeepalive(within time.Duration) []string {
	s.t.Helper()
	deadline := time.Now().Add(within)
	var seen []string
	for time.Now().Before(deadline) {
		line := s.readLine(time.Until(deadline) + time.Second)
		if line == "" {
			s.t.Fatal("the stream ended before a keepalive arrived")
		}
		if line == ": keepalive" {
			return seen
		}
		seen = append(seen, line)
	}
	s.t.Fatalf("no keepalive within %s", within)
	return seen
}

// awaitEvent reads until the next `event: task` frame, skipping keepalives, and returns its data
// line. It is awaitKeepalive's mirror: the assertion "the event DID arrive" cannot just read the next
// line, because the fixture's 40ms recheck means a keepalive usually gets there first.
func (s *sseStream) awaitEvent(within time.Duration) string {
	s.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		line := s.readLine(time.Until(deadline) + time.Second)
		if line == "" {
			s.t.Fatal("the stream ended before the event arrived")
		}
		if line == "event: task" {
			return s.readLine(time.Until(deadline) + time.Second)
		}
	}
	s.t.Fatalf("no task event within %s", within)
	return ""
}

// deleteCedarPolicy removes a fixture-created policy row and bumps the state version, which is what
// `core.cedarPolicyStore.delete(forbidId)` does in the Kotlin (the production store bumps on write;
// dbtest's stand-in makes the bump explicit — fixture.go:154-162).
func (f *httpFixture) deleteCedarPolicy(name string) {
	f.t.Helper()
	tag, err := f.fx.Store.Pool.Exec(context.Background(), `DELETE FROM policy WHERE name = $1`, name)
	if err != nil {
		f.t.Fatalf("delete cedar policy %s: %v", name, err)
	}
	if tag.RowsAffected() != 1 {
		f.t.Fatalf("delete cedar policy %s: %d rows affected, want 1", name, tag.RowsAffected())
	}
	f.fx.PolicyStore.Bump()
}

// 🔒 Case 1 — INV-A1-10: THE PUSH FILTER MIRRORS THE POLL. Every event passes the same live
// `task.read` gate the poll and detail routes enforce, so a Cedar forbid that 404s the poll also
// suppresses the push, and a task that does not exist is not readable.
//
// The three sub-cases share one shape: publish, then wait for the keepalive barrier, then assert on
// what came before it. Without the barrier "no event arrived" would be indistinguishable from "the
// event had not arrived yet".
//
// KT: TaskEventsRouteDbTest.kt#the push task_read filter mirrors the poll - owner allowed, a forbid suppresses, absent denied — owner/forbid/absent; the Kotlin's authDebug-bypass half is TestUnderAuthDebugTheStreamOpensWithNoCookieAndPushesEverything
func TestThePushFilterMirrorsThePollsTaskReadGate(t *testing.T) {
	t.Run("the owner receives their own task's event", func(t *testing.T) {
		f := newHTTPFixture(t, fixtureOptions{})
		task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
		stream := f.openStream(f.login(requester))

		f.Hub.Publish(requester, TaskEvent{TaskID: task.ID, Status: "EXECUTED"})

		if got := stream.readLine(2 * time.Second); got != "event: task" {
			t.Fatalf("first line: got %q, want \"event: task\"", got)
		}
		data := stream.readLine(2 * time.Second)
		if !strings.HasPrefix(data, "data: ") || !strings.Contains(data, `"status":"EXECUTED"`) {
			t.Errorf("data line: got %q", data)
		}
	})

	t.Run("a task.read forbid suppresses the push", func(t *testing.T) {
		f := newHTTPFixture(t, fixtureOptions{})
		task := f.seedWorkflowTask(requester, "SELECT id FROM users", dbtest.FixtureRole)
		// The SAME forbid 404s the poll — asserted here so the two really are one gate.
		f.fx.AddCedarPolicy("forbid-task-read", `forbid(principal, action == Action::"task.read", resource);`)
		cookie := f.login(requester)
		assertStatus(t, f.get(idPath("/api/approvals/", task.ID, ""), cookie), http.StatusNotFound, "the poll under the forbid")

		stream := f.openStream(cookie)
		f.Hub.Publish(requester, TaskEvent{TaskID: task.ID, Status: "EXECUTED"})

		if before := stream.awaitKeepalive(3 * time.Second); len(before) != 0 {
			t.Errorf("INV-A1-10: a forbidden task's event was pushed: %v", before)
		}

		// The Kotlin's third arm — "with the forbid gone the push is allowed again"
		// (TaskEventsRouteDbTest.kt:76). It is what makes the gate LIVE rather than snapshotted at the
		// handshake: the same open stream must start delivering once the policy row is gone.
		f.deleteCedarPolicy("forbid-task-read")
		assertStatus(t, f.get(idPath("/api/approvals/", task.ID, ""), cookie), http.StatusOK,
			"the poll with the forbid removed")

		f.Hub.Publish(requester, TaskEvent{TaskID: task.ID, Status: "EXECUTED"})
		if data := stream.awaitEvent(3 * time.Second); !strings.Contains(data, `"status":"EXECUTED"`) {
			t.Errorf("after the forbid was removed the push must be allowed again; data line: got %q", data)
		}
	})

	t.Run("an absent task is not readable, so nothing is pushed", func(t *testing.T) {
		f := newHTTPFixture(t, fixtureOptions{})
		stream := f.openStream(f.login(requester))

		f.Hub.Publish(requester, TaskEvent{TaskID: 999999, Status: "EXECUTED"})

		if before := stream.awaitKeepalive(3 * time.Second); len(before) != 0 {
			t.Errorf("a missing task must not be readable; got %v", before)
		}
	})
}

// 🔒 Case 2 — INV-A1-10's other half: SESSION LIVENESS IS RE-VALIDATED, so a revoked / expired /
// newest-wins-displaced session stops receiving pushes rather than streaming on its handshake
// identity.
//
// The stream is proved ALIVE first (a keepalive arrives), then the session is ended, and the stream
// must END. Without the liveness half it would keep ticking forever.
//
// KT: TaskEventsRouteDbTest.kt#session liveness tracks minting and revocation — the minted-is-live / revoked-is-not halves; the Kotlin's "authDebug is always live" and "a null session id is never live" halves are the two tests below
func TestARevokedSessionStopsTheStreamRatherThanStreamingOnItsHandshakeIdentity(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	stream := f.openStream(f.login(requester))

	stream.awaitKeepalive(3 * time.Second) // alive

	f.endSession(requester)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if stream.readLine(3*time.Second) == "" {
			return // EOF — the stream ended, which is the assertion
		}
	}
	t.Fatal("INV-A1-10: the stream kept pushing after its session was revoked")
}

// 🔒 INV-A1-12 — AN UNAUTHENTICATED STREAM LENGTHENS THE RECONNECT BACKOFF INSTEAD OF ERRORING.
// EventSource cannot be told to stop reconnecting after a 200 handshake, so the answer is 200 +
// `retry: 60000` + end. A 401 here would make an expired-session tab hammer the endpoint on its
// default ~3s retry.
//
// KT: TaskEventsRouteDbTest.kt#session liveness tracks minting and revocation — the "a null session id is never live" half
func TestAnUnauthenticatedStreamAnswers200WithALongerRetryAndEnds(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	stream := f.openStream(nil) // no cookie

	if got := stream.readLine(2 * time.Second); got != "retry: 60000" {
		t.Fatalf("first line: got %q, want \"retry: 60000\"", got)
	}
	if got := stream.readLine(2 * time.Second); got != "" {
		t.Errorf("the stream must END after the retry hint; got %q", got)
	}
}

// Under authDebug there is no session to resolve, so the stream opens for "debug-user" with no cookie
// at all and every event is readable (the push filter's authDebug arm).
//
// KT: TaskEventsRouteDbTest.kt#the push task_read filter mirrors the poll - owner allowed, a forbid suppresses, absent denied — the "authDebug bypasses the gate" half, on a task id that does not exist
// KT: TaskEventsRouteDbTest.kt#session liveness tracks minting and revocation — the "authDebug has no session and is always live" half
func TestUnderAuthDebugTheStreamOpensWithNoCookieAndPushesEverything(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{AuthDebug: true})
	stream := f.openStream(nil)

	// A task id that does not exist: under authDebug taskReadableForPush short-circuits to true, so
	// this still arrives — the same short-circuit-before-Cedar shape every other gate has.
	f.Hub.Publish(DebugPrincipal, TaskEvent{TaskID: 4242, Status: "CANCELLED"})

	if got := stream.readLine(2 * time.Second); got != "event: task" {
		t.Fatalf("got %q, want \"event: task\"", got)
	}
	if data := stream.readLine(2 * time.Second); !strings.Contains(data, `"taskId":4242`) {
		t.Errorf("data line: got %q", data)
	}

	// 🔒 The Kotlin's `assertTrue(sessionStillLive(debug, null, null, sessionStore))` half. The event
	// frame alone does NOT prove it: the write happens BEFORE the liveness re-check
	// (taskevents.go:206-213), so an authDebug arm that answered "not live" would still deliver those
	// two lines and only then end. A keepalive AFTER the event is the discriminator — it can only
	// arrive if the post-event liveness check returned true with no session at all.
	stream.awaitKeepalive(3 * time.Second)
}

// The subscription is RELEASED when the client goes away: the handler's defer runs, so the hub does
// not accumulate a channel per dropped tab.
func TestClosingTheClientReleasesTheSubscription(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{})
	stream := f.openStream(f.login(requester))
	stream.awaitKeepalive(3 * time.Second)

	f.Hub.mu.Lock()
	open := len(f.Hub.subscribers[requester])
	f.Hub.mu.Unlock()
	if open != 1 {
		t.Fatalf("%d subscriptions while the stream is open, want 1", open)
	}

	stream.close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.Hub.mu.Lock()
		remaining := len(f.Hub.subscribers[requester])
		f.Hub.mu.Unlock()
		if remaining == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the subscription was never released after the client disconnected")
}
