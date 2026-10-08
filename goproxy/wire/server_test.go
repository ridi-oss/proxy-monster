package wire

import (
	"net"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

func TestServerConnectionLimit(t *testing.T) {
	s := New(spi.Listen{}, "test", func(net.Conn) {})
	for i := 0; i < maxConcurrentConnections; i++ {
		if !s.acquireConnection() {
			t.Fatalf("connection slot %d rejected before limit", i)
		}
	}
	if s.acquireConnection() {
		t.Fatal("connection above server-wide limit was accepted")
	}
	s.releaseConnection()
	if !s.acquireConnection() {
		t.Fatal("released connection slot was not reusable")
	}
}
