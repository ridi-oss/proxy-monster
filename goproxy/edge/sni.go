package edge

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
)

const maxClientHello = 64 << 10

var errHelloCaptured = errors.New("edge: client hello captured")

type helloTap struct {
	net.Conn
	r io.Reader
}

func (t helloTap) Read(p []byte) (int, error)  { return t.r.Read(p) }
func (t helloTap) Write(p []byte) (int, error) { return len(p), nil }

func peekClientHello(conn net.Conn) (string, []byte, error) {
	var captured bytes.Buffer
	tap := helloTap{Conn: conn, r: io.TeeReader(io.LimitReader(conn, maxClientHello), &captured)}
	var serverName string
	seen := false
	config := &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		serverName = hello.ServerName
		seen = true
		return nil, errHelloCaptured
	}}
	err := tls.Server(tap, config).Handshake()
	if !seen {
		return "", nil, fmt.Errorf("edge: reading TLS ClientHello: %w", err)
	}
	return serverName, captured.Bytes(), nil
}
