package daemon

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// brokerMySQL plays MySQL server to the local client, dials the datasource's proxy (bounded by dialTimeout),
// authenticates there with the token as the cleartext password, then pipes the command phase raw. When
// certChainPEM is set the upstream TLS verifies against it as the root pool, with the advertised host checked
// against it; otherwise it falls back to the system trust store. When wireTLS says this proxy serves TLS, a
// greeting offering none is refused rather than sent the token in plaintext.
func brokerMySQL(local net.Conn, proxyAddr, certChainPEM string, wireTLS bool, principal, token, localPassword string) error {
	scramble, err := mysqlwire.Scramble()
	if err != nil {
		return err
	}
	clientCaps, database, seq, err := localServerGreet(local, scramble, localPassword)
	if err != nil {
		// A rejected password never reaches the proxy: answer here and drop the connection, so a
		// caller that cannot authenticate locally cannot spend the session's token upstream.
		if errors.Is(err, errLocalAuth) {
			_ = mysqlwire.WritePacket(local, seq, mysqlwire.ErrPacketState(1045, "28000", "proxy-monster: access denied"))
		}
		return err
	}
	proxy, err := net.DialTimeout("tcp", proxyAddr, dialTimeout)
	if err != nil {
		_ = mysqlwire.WritePacket(local, seq, mysqlwire.ErrPacket(1045, "proxy-monster: cannot reach proxy"))
		return err
	}
	defer proxy.Close()

	// Bound the HANDSHAKE, not just the dial. DialTimeout only covers refusal: a proxy that accepts and then
	// goes silent (black-holed load balancer, stalled TLS peer) would otherwise park this goroutine and its two
	// sockets forever, and neither a logout nor a revocation can end it — closing the local side does not
	// unblock a read on the upstream one. Cleared before the relay, which is long-lived by design.
	if err := proxy.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	up, err := proxyConnect(proxy, hostOf(proxyAddr), certChainPEM, wireTLS, principal, token, clientCaps)
	if err != nil {
		_ = mysqlwire.WritePacket(local, seq, mysqlwire.ErrPacket(1045, "proxy-monster: "+err.Error()))
		return err
	}
	// A client that selected a database at connect time expects to be in it, and the selection arrived on
	// the local handshake response — consumed here, never relayed — so it has to be applied as a command.
	// Applying it after the upstream handshake means the proxy's per-connection catalog opened on the
	// datasource's default schemas; this one is fetched lazily on the client's first statement.
	if database != "" {
		res, initErr := selectDatabase(up, database)
		if initErr != nil {
			// Not the 1045 the failures above use: the proxy has already answered the handshake and
			// authenticated this session, so an access-denied would send the operator after the wrong
			// thing — and a driver that classifies 1045 as bad credentials will not retry what is a
			// transport failure. The message covers both halves of a round trip that did not complete,
			// because only it reaches the client — the error itself goes to the daemon's log.
			_ = mysqlwire.WritePacket(local, seq, mysqlwire.ErrPacket(1105, "proxy-monster: the database selection failed"))
			return initErr
		}
		switch {
		// Relay the proxy's own refusal verbatim. Its "unknown database" carries the error code and the
		// SQLSTATE a client branches on, which a message rewritten here would throw away.
		case len(res) > 0 && res[0] == 0xff:
			_ = mysqlwire.WritePacket(local, seq, res)
			return errors.New(mysqlwire.ErrString(res))
		// Only an OK means the session really is in that database, so anything else fails closed. Letting
		// an unrecognized packet through to the caller's OK would report a session in the schema the client
		// asked for while it sits in the datasource's default one — the silent wrong-schema failure this
		// selection exists to prevent — and were that packet the first of several, the rest would be
		// relayed as the answer to the client's first query.
		case len(res) == 0 || res[0] != 0x00:
			_ = mysqlwire.WritePacket(local, seq, mysqlwire.ErrPacket(1105, "proxy-monster: unexpected response selecting the database"))
			return fmt.Errorf("unexpected COM_INIT_DB response from proxy (%d bytes): % x", len(res), res)
		}
	}
	// The relay has no time bound — a session may idle legitimately — so drop the handshake deadline.
	if err := proxy.SetDeadline(time.Time{}); err != nil {
		return err
	}
	if err := mysqlwire.WritePacket(local, seq, mysqlwire.OKPacket()); err != nil {
		return err
	}
	pipe(up, local)
	return nil
}

// selectDatabase sends COM_INIT_DB for database and returns the proxy's single response packet — an OK
// or an ERR from a proxy that answered this command, whatever arrived otherwise, which the caller
// judges. Switching the current database is not a gated action, so the proxy relays the command to the
// backend mechanically. The response is consumed here because the local client is still waiting on one
// auth result, and the caller's OK stands in for this exchange's own.
func selectDatabase(up io.ReadWriter, database string) ([]byte, error) {
	if err := mysqlwire.WritePacket(up, 0, append([]byte{mysqlwire.ComInitDB}, database...)); err != nil {
		return nil, err
	}
	_, res, err := mysqlwire.ReadPacket(up)
	return res, err
}

// pipe copies bytes both directions until either side closes.
func pipe(up io.ReadWriter, local net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, local); done <- struct{}{} }()
	go func() { _, _ = io.Copy(local, up); done <- struct{}{} }()
	<-done
}

// hostOf returns the host part of a host:port (the TLS server name), or the input unchanged if it has no port.
func hostOf(hostPort string) string {
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}
