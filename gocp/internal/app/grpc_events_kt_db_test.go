package app_test

// GrpcEventsHandlerDbTest.kt — 2 cases (docs/datasource-registration.md).
//
// The `events` handler is the ONE pipe the control plane can write down: 🔒 INV-A10-35 / INV-A12-12 say
// the control plane NEVER dials into a proxy, so every push (RefreshCatalog, OpenRunChannel,
// OpenTableDetailChannel) rides a stream the proxy opened. That makes this handler's four behaviours
// load-bearing rather than incidental — an open stream marks the datasource attached, stamps
// last_seen_at, relays an admin-pushed RefreshCatalog, and DEREGISTERS on client cancel — plus
// NOT_FOUND for a name that was never registered.
//
// It lives here rather than in internal/grpcsvc because the handler reads DatasourceStore and the
// Kotlin case asserts the last_seen_at stamp, so it needs a migrated database and a real server; bootE2E
// is that, over the real [app.Boot] wiring.

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// awaitUntil is the Kotlin's `awaitUntil(what) { predicate }`: the hub registration and the
// deregistration both happen on the SERVER's goroutine, so a test that asserted immediately after the
// client call would race the server. The Kotlin waits 5 s in 20 ms steps; so does this.
func awaitUntil(t *testing.T, what string, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out awaiting: %s", what)
}

// TestAnOpenEventsStreamMarksAttachedStampsLastSeenAndRelaysARefreshCatalog is GrpcEventsHandlerDbTest
// case 1, all four of its claims.
//
// 🔒 THE OPEN STREAM IS THE LIVENESS SIGNAL. `attached()` is what the admin console's "which
// datasources have a proxy" view reads and what `datasource.test` reports, so an entry that outlives
// the stream is a liveness view that LIES — and the Kotlin's own framing is that a lying view sends an
// operator hunting a proxy that is not there. The last assertion is the one that catches that: after
// the client cancels, `requestRefresh` must notify ZERO, not one.
//
// ⚠️ THE CANCEL PATH IS WHERE A GO PORT DIVERGES MOST EASILY. Kotlin's handler suspends in
// `awaitClose`; Go's selects on `stream.Context().Done()` and cleans up in a deferred func. A port that
// returned from the loop without the defer — or that used the cancelled request context for the detach
// stamp — leaves the subscriber registered forever. The Go handler passes context.Background() to the
// detach MarkSeen for exactly that reason (service.go), and this is the test that notices.
//
// KT: GrpcEventsHandlerDbTest.kt#an open events stream marks attached, stamps last_seen_at, and relays a RefreshCatalog
func TestAnOpenEventsStreamMarksAttachedStampsLastSeenAndRelaysARefreshCatalog(t *testing.T) {
	b := bootE2E(t, nil)
	const dsName = "evt-ds"
	mustRegister(t, b, dsName)

	hub := b.app.Core.ProxyEventsHub
	store := b.app.Core.DatasourceStore

	// The Kotlin's `.first()`: collect exactly one event, then cancel the stream — which drives the
	// server through awaitClose/ctx.Done() and so through the deregistration.
	streamCtx, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()
	stream, err := b.client.Events(streamCtx, &pb.EventsRequest{DatasourceName: dsName})
	if err != nil {
		t.Fatalf("open the events stream: %v", err)
	}

	awaitUntil(t, "stream registered", func() bool { return hub.AttachedTo(dsName) })

	// Opening the stream stamps last_seen_at. Without it the liveness view has an attachment with no
	// "when", and the admin surface cannot age a proxy out.
	ds, found, err := store.GetByName(context.Background(), dsName)
	if err != nil || !found {
		t.Fatalf("GetByName(%s) = %v, %v", dsName, found, err)
	}
	if ds.LastSeenAt == nil {
		t.Error("opening the events stream did not stamp last_seen_at")
	}

	// One attached stream is notified — the admin's "refresh now" reaching the proxy.
	if n := hub.RequestRefresh(dsName); n != 1 {
		t.Fatalf("RequestRefresh notified %d, want 1 attached stream", n)
	}
	ev, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv the relayed event: %v", err)
	}
	if ev.GetRefreshCatalog() == nil {
		t.Errorf("the proxy received %v, want the admin's RefreshCatalog", ev)
	}

	// Client cancel ⇒ the server must deregister.
	cancelStream()
	awaitUntil(t, "stream deregistered", func() bool { return !hub.AttachedTo(dsName) })

	// 🔒 And a detached datasource notifies NOBODY. This is the assertion that fails if the cleanup is
	// skipped on any exit path: the count would stay 1 against a stream nothing is reading.
	if n := hub.RequestRefresh(dsName); n != 0 {
		t.Errorf("RequestRefresh on a DETACHED datasource notified %d, want 0", n)
	}
}

// TestEventsForAnUnregisteredDatasourceIsNotFound is case 2.
//
// 🔒 REGISTRATION IS THE PRECONDITION FOR ATTACHING, and NOT_FOUND rather than an empty stream is what
// makes a proxy misconfiguration loud. An empty accepted stream would look identical to "attached, no
// events yet" — the proxy would sit there believing it was connected while the control plane had no row
// for it and every Decide answered NOT_FOUND.
//
// ⚠️ In Go the error surfaces on the first Recv, not on the Events call: grpc-go returns the stream
// handle before the server has run the handler. Asserting only on the call's own error would make this
// test pass vacuously.
//
// KT: GrpcEventsHandlerDbTest.kt#events for an unregistered datasource is NOT_FOUND
func TestEventsForAnUnregisteredDatasourceIsNotFound(t *testing.T) {
	b := bootE2E(t, nil)

	stream, err := b.client.Events(context.Background(), &pb.EventsRequest{DatasourceName: "never-registered"})
	if err == nil {
		_, err = stream.Recv()
	}
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("Events for an unregistered datasource = %v (%v), want NOT_FOUND", got, err)
	}
}
