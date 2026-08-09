package wire

import (
	"net"
	"testing"
	"time"
)

func TestDeadlineConnBoundsIdleReadAndBlockedWrite(t *testing.T) {
	const timeout = 100 * time.Millisecond

	t.Run("read", func(t *testing.T) {
		client, peer := net.Pipe()
		defer client.Close()
		defer peer.Close()
		wrapped := withIODeadlines(client, timeout, timeout)
		_, err := wrapped.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("idle read did not time out")
		}
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			t.Fatalf("idle read error = %v, want timeout", err)
		}
	})

	t.Run("write", func(t *testing.T) {
		client, peer := net.Pipe()
		defer client.Close()
		defer peer.Close()
		wrapped := withIODeadlines(client, timeout, timeout)
		_, err := wrapped.Write([]byte{0x01})
		if err == nil {
			t.Fatal("blocked write did not time out")
		}
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			t.Fatalf("blocked write error = %v, want timeout", err)
		}
	})
}
