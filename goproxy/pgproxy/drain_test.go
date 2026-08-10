package pgproxy_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// drainTestTimeout is a generous graceful-drain bound for a local test: long enough that a short in-flight
// statement always finishes inside it, short enough that a test never waits on the real 10s production value.
const drainTestTimeout = 3 * time.Second

// assertPGShutdownNotice checks that message is the PostgreSQL FATAL admin_shutdown (57P01) notice.
func assertPGShutdownNotice(t *testing.T, message pgproto3.BackendMessage) {
	t.Helper()
	errResp, ok := message.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("shutdown message = %T, want *pgproto3.ErrorResponse", message)
	}
	if errResp.Severity != "FATAL" {
		t.Fatalf("shutdown severity = %q, want FATAL", errResp.Severity)
	}
	if errResp.Code != "57P01" {
		t.Fatalf("shutdown SQLSTATE = %q, want 57P01 (admin_shutdown)", errResp.Code)
	}
	if !strings.Contains(errResp.Message, "shutting down") {
		t.Fatalf("shutdown message = %q, want a server-shutting-down notice", errResp.Message)
	}
}

// An idle authenticated connection must be unblocked promptly on Drain and handed the shutdown notice —
// this proves the forced read deadline actually propagates through the deadline wrapper.
func TestDrainIdleConnectionReceivesShutdownNoticeThenCloses(t *testing.T) {
	h := startBroker(t)
	client := newRawPGClient(t, h)

	drained := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), drainTestTimeout)
		defer cancel()
		h.server.Drain(ctx)
		close(drained)
	}()

	if err := client.conn.SetReadDeadline(time.Now().Add(drainTestTimeout)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	message, err := client.frontend.Receive()
	if err != nil {
		t.Fatalf("receive shutdown notice: %v", err)
	}
	assertPGShutdownNotice(t, message)

	if _, err := client.frontend.Receive(); err == nil {
		t.Fatal("connection stayed open after the shutdown notice")
	}
	select {
	case <-drained:
	case <-time.After(drainTestTimeout):
		t.Fatal("Drain did not return after the idle connection closed")
	}
}

// A statement already relaying when Drain starts must deliver its full result — through ReadyForQuery —
// before the connection is wound down: forcing the client read deadline must not truncate an in-flight relay.
func TestDrainLetsInFlightStatementComplete(t *testing.T) {
	h := startBroker(t)
	client := newRawPGClient(t, h)

	// pg_sleep holds the handler in the relay (reading the target DB) across the Drain call.
	client.frontend.Send(&pgproto3.Query{String: "SELECT pg_sleep(0.5)"})
	if err := client.frontend.Flush(); err != nil {
		t.Fatalf("send slow query: %v", err)
	}
	// Let the query reach the target DB and begin relaying before draining.
	time.Sleep(100 * time.Millisecond)

	drained := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), drainTestTimeout)
		defer cancel()
		h.server.Drain(ctx)
		close(drained)
	}()

	if err := client.conn.SetReadDeadline(time.Now().Add(drainTestTimeout)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	sawRow, sawRFQ := false, false
	for !sawRFQ {
		message, err := client.frontend.Receive()
		if err != nil {
			t.Fatalf("receive in-flight result: %v", err)
		}
		switch message.(type) {
		case *pgproto3.DataRow:
			sawRow = true
		case *pgproto3.ReadyForQuery:
			sawRFQ = true
		}
	}
	if !sawRow {
		t.Fatal("in-flight statement produced no row; it was truncated by the drain")
	}
	// Only after the statement completed does the now-idle handler forward the shutdown notice.
	message, err := client.frontend.Receive()
	if err != nil {
		t.Fatalf("receive post-statement shutdown notice: %v", err)
	}
	assertPGShutdownNotice(t, message)
	select {
	case <-drained:
	case <-time.After(drainTestTimeout):
		t.Fatal("Drain did not return after the in-flight statement finished")
	}
}

// Once Drain has started the listener is closed, so a fresh connection attempt is refused.
func TestDrainRefusesNewConnections(t *testing.T) {
	h := startBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), drainTestTimeout)
	defer cancel()
	h.server.Drain(ctx)

	conn, err := net.DialTimeout("tcp", h.addr, time.Second)
	if err != nil {
		return // refused at connect — the listener is gone
	}
	defer conn.Close()
	// A served connection would answer the startup handshake; after Drain closed the listener it must not.
	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "pm", "database": "app"},
	})
	if err := frontend.Flush(); err != nil {
		return // write failed on the reset socket
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := frontend.Receive(); err == nil {
		t.Fatal("a new connection was served after Drain closed the listener")
	}
}

// Drain must return within its bound even when a connection cannot be wound down in time, force-closing the
// straggler rather than waiting for it.
func TestDrainForceClosesStragglerPastTimeout(t *testing.T) {
	h := startBroker(t)
	client := newRawPGClient(t, h)

	// A statement far longer than the drain bound keeps its handler in the relay past the timeout.
	client.frontend.Send(&pgproto3.Query{String: "SELECT pg_sleep(3)"})
	if err := client.frontend.Flush(); err != nil {
		t.Fatalf("send slow query: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	readErr := make(chan error, 1)
	go func() {
		if err := client.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			readErr <- err
			return
		}
		for {
			if _, err := client.frontend.Receive(); err != nil {
				readErr <- err
				return
			}
		}
	}()

	const drainBound = 150 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), drainBound)
	defer cancel()
	start := time.Now()
	h.server.Drain(ctx)
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Fatalf("Drain took %v; it waited on the stuck statement instead of force-closing it", elapsed)
	}
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("straggler read returned cleanly; the connection was not force-closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("straggler connection was not force-closed after the drain timeout")
	}
}
