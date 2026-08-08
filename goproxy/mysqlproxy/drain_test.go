package mysqlproxy_test

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// drainTestTimeout is a generous graceful-drain bound for a local test: long enough that a short in-flight
// statement always finishes inside it, short enough that a test never waits on the real 10s production value.
const drainTestTimeout = 3 * time.Second

func allowAll(*pb.DecisionRequest) (*pb.WireDecision, error) {
	return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
}

// assertShutdownNotice checks that payload is the MySQL ER_SERVER_SHUTDOWN (1053 / 08S01) notice, framed at
// sequence 1 — the response sequence a driver expects after sending its next command as sequence 0.
func assertShutdownNotice(t *testing.T, seq byte, payload []byte) {
	t.Helper()
	if seq != 1 {
		t.Fatalf("shutdown packet sequence = %d, want 1 (the response to the client's next command)", seq)
	}
	if len(payload) < 9 || payload[0] != 0xff {
		t.Fatalf("shutdown packet = %x, want an ERR packet", payload)
	}
	if code := binary.LittleEndian.Uint16(payload[1:3]); code != 1053 {
		t.Fatalf("shutdown error code = %d, want 1053 (ER_SERVER_SHUTDOWN)", code)
	}
	if state := string(payload[4:9]); state != "08S01" {
		t.Fatalf("shutdown SQLSTATE = %q, want 08S01", state)
	}
	if msg := mysqlwire.ErrString(payload); !strings.Contains(msg, "shutting down") {
		t.Fatalf("shutdown message = %q, want a server-shutting-down notice", msg)
	}
}

// An idle authenticated connection must be unblocked promptly on Drain and handed the shutdown notice —
// this proves the forced read deadline actually propagates through the deadline wrapper.
func TestDrainIdleConnectionReceivesShutdownNoticeThenCloses(t *testing.T) {
	h := startBroker(t)
	client := openRawClient(t, h.addr, validToken)

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
	seq, payload, err := mysqlwire.ReadPacket(client.conn)
	if err != nil {
		t.Fatalf("read shutdown notice: %v", err)
	}
	assertShutdownNotice(t, seq, payload)

	if _, _, err := mysqlwire.ReadPacket(client.conn); err == nil {
		t.Fatal("connection stayed open after the shutdown notice")
	}
	select {
	case <-drained:
	case <-time.After(drainTestTimeout):
		t.Fatal("Drain did not return after the idle connection closed")
	}
}

// A statement already relaying when Drain starts must deliver its full result before the connection is
// wound down: forcing the client read deadline must not truncate an in-flight relay.
func TestDrainLetsInFlightStatementComplete(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = allowAll
	client := openRawClient(t, h.addr, validToken)

	// SLEEP holds the handler in the relay (reading the backend) across the Drain call.
	if err := mysqlwire.WritePacket(client.conn, 0, mysqlwire.ComQueryPayload("SELECT SLEEP(0.5)")); err != nil {
		t.Fatalf("write slow query: %v", err)
	}
	// Let the query reach the backend and begin relaying before draining.
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
	// The complete SELECT SLEEP(...) result set (one column, one row, terminator) must arrive intact.
	rows := readTextResult(t, client.conn, 1)
	if len(rows) != 1 {
		t.Fatalf("in-flight result rows = %d, want 1 (statement was truncated by the drain)", len(rows))
	}
	// Only after the statement completed does the now-idle handler forward the shutdown notice.
	seq, payload, err := mysqlwire.ReadPacket(client.conn)
	if err != nil {
		t.Fatalf("read post-statement shutdown notice: %v", err)
	}
	assertShutdownNotice(t, seq, payload)
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
	// Some stacks accept the socket then reset it; a greeting read must then fail.
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, _, err := mysqlwire.ReadPacket(conn); err == nil {
		t.Fatal("a new connection was served a greeting after Drain closed the listener")
	}
}

// Drain must return within its bound even when a connection cannot be wound down in time, force-closing the
// straggler rather than waiting for it.
func TestDrainForceClosesStragglerPastTimeout(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = allowAll
	client := openRawClient(t, h.addr, validToken)

	// A statement far longer than the drain bound keeps its handler in the relay past the timeout.
	if err := mysqlwire.WritePacket(client.conn, 0, mysqlwire.ComQueryPayload("SELECT SLEEP(3)")); err != nil {
		t.Fatalf("write slow query: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	readErr := make(chan error, 1)
	go func() {
		if err := client.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			readErr <- err
			return
		}
		for {
			if _, _, err := mysqlwire.ReadPacket(client.conn); err != nil {
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
			t.Fatal("straggler read returned a clean result; the connection was not force-closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("straggler connection was not force-closed after the drain timeout")
	}
}

// readTextResult reads a complete text-protocol result set (column count, column defs, rows, terminator)
// from a DEPRECATE_EOF connection and returns the row payloads.
func readTextResult(t *testing.T, conn net.Conn, expectedColumns int) [][]byte {
	t.Helper()
	_, first, err := mysqlwire.ReadPacket(conn)
	if err != nil {
		t.Fatalf("read result header: %v", err)
	}
	if len(first) > 0 && first[0] == 0xff {
		t.Fatalf("query error: %s", mysqlwire.ErrString(first))
	}
	count, err := mysqlwire.NewReader(first).Lenenc()
	if err != nil || int(count) != expectedColumns {
		t.Fatalf("result column count = %d (%v), want %d", count, err, expectedColumns)
	}
	for i := 0; i < expectedColumns; i++ {
		if _, _, err := mysqlwire.ReadPacket(conn); err != nil {
			t.Fatalf("read column definition: %v", err)
		}
	}
	var rows [][]byte
	for {
		_, payload, err := mysqlwire.ReadPacket(conn)
		if err != nil {
			t.Fatalf("read result row: %v", err)
		}
		if mysqlwire.IsResultTerminator(payload) {
			return rows
		}
		rows = append(rows, append([]byte(nil), payload...))
	}
}
