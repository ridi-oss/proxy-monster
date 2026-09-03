package daemon

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBrokerPostgresAuthenticatesLocallyAndInjectsToken(t *testing.T) {
	const localPassword = "pmlocal_test"
	const token = "pmk_token"
	startup := postgresStartup("alice", "app")
	query := postgresFrame('Q', append([]byte("select 1"), 0))

	proxyAddr, proxyDone := postgresProxyStub(t, func(c net.Conn) error {
		packet, code, err := readPostgresStartup(c)
		if err != nil {
			return err
		}
		if code != pgSSLRequest {
			return fmt.Errorf("first startup code = %d, want SSLRequest", code)
		}
		if !bytes.Equal(packet, postgresStartupPacket(pgSSLRequest)) {
			return fmt.Errorf("unexpected SSL request: %x", packet)
		}
		if _, err := c.Write([]byte{'N'}); err != nil {
			return err
		}
		gotStartup, code, err := readPostgresStartup(c)
		if err != nil {
			return err
		}
		if code != pgProtocolVersion30 || !bytes.Equal(gotStartup, startup) {
			return fmt.Errorf("startup was not preserved: %x", gotStartup)
		}
		if err := writePostgresFrame(c, 'v', postgresProtocolNegotiationBody(nil)); err != nil {
			return err
		}
		if err := writePostgresFrame(c, 'R', uint32Bytes(3)); err != nil {
			return err
		}
		typ, body, _, err := readPostgresFrame(c, maxPGAuthBody)
		if err != nil {
			return err
		}
		if typ != 'p' || string(body) != token+"\x00" {
			return fmt.Errorf("token frame = %q %q", typ, body)
		}

		var ready bytes.Buffer
		_ = writePostgresFrame(&ready, 'R', uint32Bytes(0))
		parameter := append(append([]byte("application_name"), 0), append([]byte(strings.Repeat("x", maxPGAuthBody)), 0)...)
		_ = writePostgresFrame(&ready, 'S', parameter)
		_ = writePostgresFrame(&ready, 'Z', []byte{'I'})
		if _, err := c.Write(ready.Bytes()); err != nil {
			return err
		}
		gotQuery := make([]byte, len(query))
		if _, err := io.ReadFull(c, gotQuery); err != nil {
			return err
		}
		if !bytes.Equal(gotQuery, query) {
			return fmt.Errorf("query = %x, want %x", gotQuery, query)
		}
		return writePostgresFrame(c, 'C', append([]byte("SELECT 1"), 0))
	})

	client, broker := net.Pipe()
	brokerDone := make(chan error, 1)
	go func() { brokerDone <- brokerPostgres(broker, proxyAddr, "", false, token, localPassword) }()

	if _, err := client.Write(postgresStartupPacket(pgSSLRequest)); err != nil {
		t.Fatal(err)
	}
	var sslResponse [1]byte
	if _, err := io.ReadFull(client, sslResponse[:]); err != nil || sslResponse[0] != 'N' {
		t.Fatalf("local SSL response = %q, err %v", sslResponse[0], err)
	}
	if _, err := client.Write(startup); err != nil {
		t.Fatal(err)
	}
	assertPostgresAuthCode(t, client, 3)
	if err := writePostgresFrame(client, 'p', append([]byte(localPassword), 0)); err != nil {
		t.Fatal(err)
	}
	assertPostgresAuthCode(t, client, 0)
	if typ, body, _, err := readPostgresFrame(client, maxPGStartupResponseBody); err != nil || typ != 'S' || len(body) <= maxPGAuthBody {
		t.Fatalf("large parameter status = %q len %d, err %v", typ, len(body), err)
	}
	if typ, body, _, err := readPostgresFrame(client, maxPGAuthBody); err != nil || typ != 'Z' || !bytes.Equal(body, []byte{'I'}) {
		t.Fatalf("ready frame = %q %x, err %v", typ, body, err)
	}
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	if typ, body, _, err := readPostgresFrame(client, maxPGAuthBody); err != nil || typ != 'C' || string(body) != "SELECT 1\x00" {
		t.Fatalf("command frame = %q %q, err %v", typ, body, err)
	}
	client.Close()
	broker.Close()
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
	if err := <-brokerDone; err != nil {
		t.Fatalf("brokerPostgres: %v", err)
	}
}

func TestBrokerPostgresRejectsWrongLocalPasswordBeforeDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, broker := net.Pipe()
	defer client.Close()
	defer broker.Close()
	done := make(chan error, 1)
	go func() { done <- brokerPostgres(broker, ln.Addr().String(), "", false, "pmk_token", "correct") }()

	if _, err := client.Write(postgresStartup("alice", "app")); err != nil {
		t.Fatal(err)
	}
	assertPostgresAuthCode(t, client, 3)
	if err := writePostgresFrame(client, 'p', append([]byte("wrong"), 0)); err != nil {
		t.Fatal(err)
	}
	typ, body, _, err := readPostgresFrame(client, maxPGAuthBody)
	if err != nil {
		t.Fatal(err)
	}
	if typ != 'E' || !bytes.Contains(body, []byte("28P01")) {
		t.Fatalf("auth rejection = %q %q", typ, body)
	}
	if err := <-done; !errors.Is(err, errPostgresLocalAuth) {
		t.Fatalf("brokerPostgres error = %v, want local auth failure", err)
	}
	if err := ln.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if c, err := ln.Accept(); err == nil {
		c.Close()
		t.Fatal("wrong local password dialed the proxy")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("accept after wrong password: %v", err)
	}
}

func TestBrokerPostgresReturnsLocalAuthenticationWriteError(t *testing.T) {
	const localPassword = "pmlocal_test"
	proxyAddr, proxyDone := postgresProxyStub(t, func(c net.Conn) error {
		if _, code, err := readPostgresStartup(c); err != nil || code != pgSSLRequest {
			return fmt.Errorf("SSL request code = %d, err %v", code, err)
		}
		if _, err := c.Write([]byte{'N'}); err != nil {
			return err
		}
		if _, _, err := readPostgresStartup(c); err != nil {
			return err
		}
		if err := writePostgresFrame(c, 'R', uint32Bytes(3)); err != nil {
			return err
		}
		if _, _, _, err := readPostgresFrame(c, maxPGAuthBody); err != nil {
			return err
		}
		return writePostgresFrame(c, 'R', uint32Bytes(0))
	})

	client, pipeBroker := net.Pipe()
	defer client.Close()
	defer pipeBroker.Close()
	writeErr := errors.New("local write failed")
	broker := &failNthWriteConn{Conn: pipeBroker, failAt: 2, err: writeErr}
	done := make(chan error, 1)
	go func() {
		done <- brokerPostgres(broker, proxyAddr, "", false, "pmk_token", localPassword)
	}()
	if _, err := client.Write(postgresStartup("alice", "app")); err != nil {
		t.Fatal(err)
	}
	assertPostgresAuthCode(t, client, 3)
	if err := writePostgresFrame(client, 'p', []byte(localPassword+"\x00")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, writeErr) {
		t.Fatalf("brokerPostgres error = %v, want local write failure", err)
	}
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
}

func TestPostgresProxyConnectRefusesTLSDowngradeBeforeStartup(t *testing.T) {
	proxyAddr, proxyDone := postgresProxyStub(t, func(c net.Conn) error {
		_, code, err := readPostgresStartup(c)
		if err != nil {
			return err
		}
		if code != pgSSLRequest {
			return fmt.Errorf("startup code = %d, want SSLRequest", code)
		}
		if _, err := c.Write([]byte{'N'}); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		var one [1]byte
		n, err := c.Read(one[:])
		if n != 0 {
			return fmt.Errorf("client sent %d bytes after TLS refusal", n)
		}
		if err == nil {
			return errors.New("client kept the plaintext connection open")
		}
		return nil
	})

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = postgresProxyConnect(raw, "proxy.example", "", true, postgresStartup("alice", "app"), "sekrit-token", io.Discard)
	raw.Close()
	if err == nil || !strings.Contains(err.Error(), "refused the SSL request") {
		t.Fatalf("postgresProxyConnect error = %v, want downgrade refusal", err)
	}
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
}

func TestPostgresProxyConnectRejectsUnsupportedAuthBeforeToken(t *testing.T) {
	const token = "sekrit-token"
	proxyAddr, proxyDone := postgresProxyStub(t, func(c net.Conn) error {
		if _, code, err := readPostgresStartup(c); err != nil || code != pgSSLRequest {
			return fmt.Errorf("SSL request code = %d, err %v", code, err)
		}
		if _, err := c.Write([]byte{'N'}); err != nil {
			return err
		}
		if _, _, err := readPostgresStartup(c); err != nil {
			return err
		}
		if err := writePostgresFrame(c, 'R', append(uint32Bytes(5), 1, 2, 3, 4)); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, len(token)+16)
		n, err := c.Read(buf)
		if n != 0 {
			return fmt.Errorf("client sent %d bytes after unsupported authentication: %x", n, buf[:n])
		}
		if err == nil {
			return errors.New("client kept the unsupported authentication connection open")
		}
		return nil
	})

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = postgresProxyConnect(raw, "proxy.example", "", false, postgresStartup("alice", "app"), token, io.Discard)
	raw.Close()
	if err == nil || !strings.Contains(err.Error(), "unexpected authentication request") {
		t.Fatalf("postgresProxyConnect error = %v, want unsupported authentication rejection", err)
	}
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
}

func TestPostgresProxyConnectWaitsForReadyForQuery(t *testing.T) {
	proxyAddr, proxyDone := postgresProxyStub(t, func(c net.Conn) error {
		if _, code, err := readPostgresStartup(c); err != nil || code != pgSSLRequest {
			return fmt.Errorf("SSL request code = %d, err %v", code, err)
		}
		if _, err := c.Write([]byte{'N'}); err != nil {
			return err
		}
		if _, _, err := readPostgresStartup(c); err != nil {
			return err
		}
		if err := writePostgresFrame(c, 'R', uint32Bytes(3)); err != nil {
			return err
		}
		if _, _, _, err := readPostgresFrame(c, maxPGAuthBody); err != nil {
			return err
		}
		if err := writePostgresFrame(c, 'R', uint32Bytes(0)); err != nil {
			return err
		}
		var one [1]byte
		if _, err := c.Read(one[:]); err == nil {
			return errors.New("client entered relay before ReadyForQuery")
		}
		return nil
	})

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var local bytes.Buffer
	_, responded, err := postgresProxyConnect(
		raw,
		"proxy.example",
		"",
		false,
		postgresStartup("alice", "app"),
		"sekrit-token",
		&local,
	)
	raw.Close()
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("postgresProxyConnect error = %v, want ReadyForQuery timeout", err)
	}
	if !responded {
		t.Fatal("postgresProxyConnect did not report the forwarded AuthenticationOk")
	}
	if want := postgresFrame('R', uint32Bytes(0)); !bytes.Equal(local.Bytes(), want) {
		t.Fatalf("local startup response = %x, want %x", local.Bytes(), want)
	}
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
}

func TestPostgresProxyConnectUsesAdvertisedTLSChain(t *testing.T) {
	serverCfg, leafDER := selfSignedServer(t)
	chain := certificatePEM(leafDER)
	client, server := net.Pipe()
	deadline := time.Now().Add(3 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	serverDone := make(chan error, 1)
	go func() {
		_, code, err := readPostgresStartup(server)
		if err != nil {
			serverDone <- err
			return
		}
		if code != pgSSLRequest {
			serverDone <- fmt.Errorf("startup code = %d, want SSLRequest", code)
			return
		}
		if _, err := server.Write([]byte{'S'}); err != nil {
			serverDone <- err
			return
		}
		tlsServer := tls.Server(server, serverCfg)
		if err := tlsServer.Handshake(); err != nil {
			serverDone <- err
			return
		}
		if _, _, err := readPostgresStartup(tlsServer); err != nil {
			serverDone <- err
			return
		}
		if err := writePostgresFrame(tlsServer, 'R', uint32Bytes(3)); err != nil {
			serverDone <- err
			return
		}
		typ, body, _, err := readPostgresFrame(tlsServer, maxPGAuthBody)
		if err != nil {
			serverDone <- err
			return
		}
		if typ != 'p' || string(body) != "sekrit-token\x00" {
			serverDone <- fmt.Errorf("token frame = %q %q", typ, body)
			return
		}
		if err := writePostgresFrame(tlsServer, 'R', uint32Bytes(0)); err != nil {
			serverDone <- err
			return
		}
		serverDone <- writePostgresFrame(tlsServer, 'Z', []byte{'I'})
	}()

	up, _, err := postgresProxyConnect(client, "proxy.example", chain, true, postgresStartup("alice", "app"), "sekrit-token", io.Discard)
	if err != nil {
		t.Fatalf("postgresProxyConnect: %v", err)
	}
	up.Close()
	server.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestBrokerPostgresForwardsCancelRequest(t *testing.T) {
	cancel := postgresCancelPacket(123, uint32Bytes(456))
	proxyAddr, proxyDone := postgresProxyStub(t, func(c net.Conn) error {
		if _, code, err := readPostgresStartup(c); err != nil || code != pgSSLRequest {
			return fmt.Errorf("SSL request code = %d, err %v", code, err)
		}
		if _, err := c.Write([]byte{'N'}); err != nil {
			return err
		}
		return expectPostgresCancel(c, cancel)
	})
	client, broker := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- brokerPostgres(broker, proxyAddr, "", false, "", "") }()
	if _, err := client.Write(cancel); err != nil {
		t.Fatal(err)
	}
	client.Close()
	broker.Close()
	if err := <-done; err != nil {
		t.Fatalf("brokerPostgres cancel: %v", err)
	}
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
}

func TestBrokerPostgresForwardsCancelRequestOverTLS(t *testing.T) {
	cancel := postgresCancelPacket(123, uint32Bytes(456))
	serverCfg, leafDER := selfSignedServer(t)
	proxyAddr, proxyDone := postgresProxyStub(t, func(c net.Conn) error {
		if _, code, err := readPostgresStartup(c); err != nil || code != pgSSLRequest {
			return fmt.Errorf("SSL request code = %d, err %v", code, err)
		}
		if _, err := c.Write([]byte{'S'}); err != nil {
			return err
		}
		tlsServer := tls.Server(c, serverCfg)
		if err := tlsServer.Handshake(); err != nil {
			return err
		}
		return expectPostgresCancel(tlsServer, cancel)
	})
	client, broker := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- brokerPostgres(broker, proxyAddr, certificatePEM(leafDER), true, "", "")
	}()
	if _, err := client.Write(cancel); err != nil {
		t.Fatal(err)
	}
	client.Close()
	broker.Close()
	if err := <-done; err != nil {
		t.Fatalf("brokerPostgres cancel: %v", err)
	}
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
}

func TestBrokerPostgresRefusesCancelTLSDowngrade(t *testing.T) {
	cancel := postgresCancelPacket(123, uint32Bytes(456))
	proxyAddr, proxyDone := postgresProxyStub(t, func(c net.Conn) error {
		if _, code, err := readPostgresStartup(c); err != nil || code != pgSSLRequest {
			return fmt.Errorf("SSL request code = %d, err %v", code, err)
		}
		if _, err := c.Write([]byte{'N'}); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		var one [1]byte
		n, err := c.Read(one[:])
		if n != 0 {
			return fmt.Errorf("client sent %d cancel bytes after TLS refusal", n)
		}
		if err == nil {
			return errors.New("client kept the plaintext cancel connection open")
		}
		return nil
	})
	client, broker := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- brokerPostgres(broker, proxyAddr, "", true, "", "") }()
	if _, err := client.Write(cancel); err != nil {
		t.Fatal(err)
	}
	client.Close()
	broker.Close()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "refused the SSL request") {
		t.Fatalf("brokerPostgres cancel error = %v, want downgrade refusal", err)
	}
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
}

func TestLocalPostgresHandshakeNegotiatesProtocol32(t *testing.T) {
	startup := postgresStartupParams(
		pgProtocolVersion32,
		"user", "alice",
		"_pq_.traceparent", "ignored",
		"database", "app",
		"_pq_.feature", "ignored",
	)
	client, broker := net.Pipe()
	defer client.Close()
	defer broker.Close()
	type result struct {
		startup []byte
		err     error
	}
	done := make(chan result, 1)
	go func() {
		got, _, err := localPostgresHandshake(broker, "correct")
		done <- result{startup: got, err: err}
	}()
	if _, err := client.Write(startup); err != nil {
		t.Fatal(err)
	}
	typ, body, _, err := readPostgresFrame(client, maxPGAuthBody)
	if err != nil {
		t.Fatal(err)
	}
	if typ != 'v' || !bytes.Equal(
		body,
		postgresProtocolNegotiationBody([]string{"_pq_.traceparent", "_pq_.feature"}),
	) {
		t.Fatalf("protocol negotiation = %q %x", typ, body)
	}
	assertPostgresAuthCode(t, client, 3)
	if err := writePostgresFrame(client, 'p', []byte("correct\x00")); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil {
		t.Fatalf("localPostgresHandshake: %v", got.err)
	}
	want := postgresStartup("alice", "app")
	if !bytes.Equal(got.startup, want) {
		t.Fatalf("startup = %x, want sanitized protocol 3.0 %x", got.startup, want)
	}
}

func TestReadPostgresStartupPacketLengthBoundary(t *testing.T) {
	for _, tc := range []struct {
		length int
		valid  bool
	}{
		{length: 10_004, valid: true},
		{length: 10_005, valid: false},
	} {
		t.Run(fmt.Sprintf("length_%d", tc.length), func(t *testing.T) {
			packet := make([]byte, tc.length)
			binary.BigEndian.PutUint32(packet, uint32(tc.length))
			binary.BigEndian.PutUint32(packet[4:], pgProtocolVersion30)
			_, _, err := readPostgresStartup(bytes.NewReader(packet))
			if tc.valid && err != nil {
				t.Fatalf("readPostgresStartup: %v", err)
			}
			if !tc.valid && (err == nil || !strings.Contains(err.Error(), "invalid postgres startup packet length")) {
				t.Fatalf("readPostgresStartup error = %v, want invalid length", err)
			}
		})
	}
}

func TestLocalPostgresHandshakeRejectsInvalidCancelLength(t *testing.T) {
	for _, length := range []int{minPGCancelPacket - 1, maxPGCancelPacket + 1} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			packet := make([]byte, length)
			binary.BigEndian.PutUint32(packet, uint32(length))
			binary.BigEndian.PutUint32(packet[4:], pgCancelRequest)
			client, broker := net.Pipe()
			defer client.Close()
			defer broker.Close()
			done := make(chan error, 1)
			go func() {
				_, _, err := localPostgresHandshake(broker, "")
				done <- err
			}()
			if _, err := client.Write(packet); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil || !strings.Contains(err.Error(), "invalid postgres cancel request length") {
				t.Fatalf("localPostgresHandshake error = %v, want invalid cancel length", err)
			}
		})
	}
}

type failNthWriteConn struct {
	net.Conn
	writes int
	failAt int
	err    error
}

func (c *failNthWriteConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes == c.failAt {
		return 0, c.err
	}
	return c.Conn.Write(p)
}

func postgresProxyStub(t *testing.T, serve func(net.Conn) error) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		done <- serve(c)
	}()
	return ln.Addr().String(), done
}

func postgresCancelPacket(processID uint32, secretKey []byte) []byte {
	packet := make([]byte, 0, 12+len(secretKey))
	packet = binary.BigEndian.AppendUint32(packet, uint32(12+len(secretKey)))
	packet = binary.BigEndian.AppendUint32(packet, pgCancelRequest)
	packet = binary.BigEndian.AppendUint32(packet, processID)
	return append(packet, secretKey...)
}

func expectPostgresCancel(r io.Reader, want []byte) error {
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("cancel = %x, want %x", got, want)
	}
	return nil
}

func postgresStartup(user, database string) []byte {
	return postgresStartupParams(pgProtocolVersion30, "user", user, "database", database)
}

func postgresStartupParams(version uint32, params ...string) []byte {
	body := uint32Bytes(version)
	for _, value := range params {
		body = append(body, value...)
		body = append(body, 0)
	}
	body = append(body, 0)
	packet := binary.BigEndian.AppendUint32(nil, uint32(4+len(body)))
	return append(packet, body...)
}

func postgresFrame(typ byte, body []byte) []byte {
	var out bytes.Buffer
	_ = writePostgresFrame(&out, typ, body)
	return out.Bytes()
}

func assertPostgresAuthCode(t *testing.T, r io.Reader, want uint32) {
	t.Helper()
	typ, body, _, err := readPostgresFrame(r, maxPGAuthBody)
	if err != nil {
		t.Fatal(err)
	}
	if typ != 'R' || len(body) != 4 || binary.BigEndian.Uint32(body) != want {
		t.Fatalf("authentication frame = %q %x, want code %d", typ, body, want)
	}
}

func certificatePEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
