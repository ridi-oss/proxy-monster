package daemon

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// pmon-specific MySQL handshake flows. The daemon's local broker acts as a MySQL *server* to the
// local client (greeting → check the local password → OK) and as a MySQL *client* to the proxy (handshake →
// auth-switch → send the token as the cleartext password). After both handshakes the command phase
// is piped raw. The low-level framing/message primitives live in the shared mysqlwire package.

// serverVersion is what pmon's local broker reports to the client in its greeting.
const serverVersion = "8.0.40-proxy-monster-pm"

// errLocalAuth is what a client that answered the greeting with the wrong password gets. It carries
// no detail beyond access-denied — the wrong password is not worth naming — but it is a distinct
// message from the other local failures, so this does tell a caller its password was wrong. That is
// what any password prompt does; the password is 24 random bytes, not a guessable one.
var errLocalAuth = errors.New("access denied")

// localServerGreet plays the MySQL server to the local client up to (not including) the auth result:
// greeting, then read and verify its handshake response against the daemon's local password. The
// caller sends OK only after the upstream proxy handshake also succeeds, so a bad token surfaces as
// an auth error to the local client rather than a late failure.
//
// The local password is not the credential that reaches the datasource — the upstream token is — but
// checking it keeps any process that can open a loopback socket from borrowing this session. Reading
// the password out of the state file is a strictly higher bar than connecting to a port.
//
// nextSeq is the sequence the caller's reply (OK or ERR) must carry. It depends on how many packets
// the plugin negotiation spent, so the caller must use it rather than assume the handshake ended at
// a fixed point.
//
// database is the one the client selected at connect time, empty when it selected none. The caller
// must select it upstream — see brokerMySQL — because nothing after this point ever sees it again: it
// travels in the handshake response, not as a command.
func localServerGreet(c io.ReadWriter, scramble []byte, localPassword string) (clientCaps uint32, database string, nextSeq byte, err error) {
	// true: this greeting advertises CapConnectWithDB because the caller relays the database this
	// returns. The advertisement is what makes a client send the field at all — a real client (e.g. the
	// mysql CLI) sets its own CapConnectWithDB bit whenever it was given a database, but only WRITES
	// the field when the server offered the capability, so a greeting that stays silent about it turns
	// `-D somedb` into a connection on the datasource's default schema with no error anywhere.
	nextSeq = 2
	if err = mysqlwire.WritePacket(c, 0, mysqlwire.ServerGreeting(1, scramble, serverVersion, true)); err != nil {
		return
	}
	_, resp, err := mysqlwire.ReadPacket(c) // handshake response (seq 1)
	if err != nil {
		return
	}
	if len(resp) >= 4 {
		clientCaps = binary.LittleEndian.Uint32(resp[:4])
	}

	// An empty local password means one was never generated, which would otherwise make every
	// password correct. Refuse rather than fall open.
	if localPassword == "" {
		return clientCaps, "", nextSeq, errLocalAuth
	}
	parsed, err := mysqlwire.ParseHandshakeResponse(resp, true)
	if err != nil {
		return clientCaps, "", nextSeq, errLocalAuth
	}
	// The selected database is reported only once the password checks out. A caller that failed the
	// local check is given no upstream connection, so there is nothing left to select it on.
	nextSeq, err = verifyLocalPassword(c, scramble, localPassword, parsed)
	if err != nil {
		return clientCaps, "", nextSeq, err
	}
	return clientCaps, parsed.Database, nextSeq, nil
}

// verifyLocalPassword checks the client's auth response against localPassword, for whichever plugin
// the client used.
//
// The greeting asks for mysql_native_password, and a client that honors it is answered directly. One
// that asks for caching_sha2_password — MySQL 8's default — is served that plugin instead of refused
// with an opaque access-denied it cannot act on. Anything else is switched to mysql_clear_password,
// the same mechanism the proxy itself uses upstream; a client must permit that plugin, which the
// mysql CLI gates behind --enable-cleartext-plugin.
//
// Every path ends in a constant-time comparison against the same password — as a digest under the
// plugin the client chose, or as the password itself once switched to clear. Returns the sequence
// the caller's reply must carry, which differs per path by how many packets the exchange spent.
func verifyLocalPassword(c io.ReadWriter, scramble []byte, localPassword string, parsed mysqlwire.HandshakeResponse) (nextSeq byte, err error) {
	switch parsed.AuthPlugin {
	case "", "mysql_native_password":
		want := mysqlwire.NativePassword(localPassword, scramble)
		if subtle.ConstantTimeCompare(parsed.AuthResponse, want) != 1 {
			return 2, errLocalAuth
		}
		return 2, nil
	case "caching_sha2_password":
		// A client that asked for this plugin against a native greeting sends no digest with its
		// handshake — it waits to be switched, because it will not hash against a scramble issued
		// under another plugin. Answering the empty response directly would reject every such client.
		if len(parsed.AuthResponse) == 0 {
			return cachingSHA2Switch(c, localPassword)
		}
		want := mysqlwire.CachingSHA2Password(localPassword, scramble)
		if subtle.ConstantTimeCompare(parsed.AuthResponse, want) != 1 {
			return 2, errLocalAuth
		}
		// The client still expects the fast-auth verdict this plugin always ends with.
		if err := mysqlwire.WritePacket(c, 2, mysqlwire.AuthMoreDataPacket(mysqlwire.CachingSHA2FastAuthSuccess)); err != nil {
			return 3, err
		}
		return 3, nil
	}

	// The auth-switch reply reuses the greeting's scramble, so nothing about the exchange changes but
	// the encoding: the client sends the password itself over loopback.
	if err := mysqlwire.WritePacket(c, 2, mysqlwire.AuthSwitchClearPassword()); err != nil {
		return 2, err
	}
	_, reply, err := mysqlwire.ReadPacket(c)
	if err != nil {
		return 4, err
	}
	got := mysqlwire.ParseClearPassword(reply)
	if subtle.ConstantTimeCompare([]byte(got), []byte(localPassword)) != 1 {
		return 4, errLocalAuth
	}
	return 4, nil
}

// cachingSHA2Switch runs the server half of caching_sha2_password: switch the client to the plugin
// with a fresh scramble, check the digest it answers with, and report the fast-auth verdict.
//
// A real server answers a correct-but-uncached credential with CachingSHA2FullAuth, which sends the
// client down an RSA key exchange (or, under TLS, a cleartext send). Neither is needed here: this
// server generated the password and holds it, so the digest alone settles the question, and the
// verdict it reports is what the client waits for before proceeding.
func cachingSHA2Switch(c io.ReadWriter, localPassword string) (byte, error) {
	// Each return reports the sequence for what was actually sent, not what a successful exchange
	// would have sent: a client told its reply was packet 3 and then handed an error numbered 5 reports
	// packets out of order instead of the access-denied it was given.
	scramble, err := mysqlwire.Scramble()
	if err != nil {
		return 2, err
	}
	if err := mysqlwire.WritePacket(c, 2, mysqlwire.AuthSwitchCachingSHA2(scramble)); err != nil {
		return 2, err
	}
	_, reply, err := mysqlwire.ReadPacket(c)
	if err != nil {
		return 4, err
	}
	want := mysqlwire.CachingSHA2Password(localPassword, scramble)
	if subtle.ConstantTimeCompare(reply, want) != 1 {
		return 4, errLocalAuth // the switch (2) and its reply (3) only
	}
	if err := mysqlwire.WritePacket(c, 4, mysqlwire.AuthMoreDataPacket(mysqlwire.CachingSHA2FastAuthSuccess)); err != nil {
		return 5, err
	}
	return 5, nil
}

// proxyConnect authenticates to the proxy as [principal], answering its clear-password auth-switch with
// [token]. If the proxy offers CLIENT_SSL it upgrades to TLS *before* sending the handshake (so the token
// never crosses in the clear). When [certChainPEM] is set — the chain the control plane advertised for this
// datasource — TLS verifies against it as the root pool with [serverName] checked; when empty, TLS (if
// offered) verifies against the system trust store.
//
// [wireTLS] is what makes the plaintext refusal safe, and it is deliberately NOT inferred from
// [certChainPEM]: the control plane reports the TLS requirement separately, because a proxy can serve TLS
// while publishing no chain (a publicly-trusted cert, PM_TLS_NO_ADVERTISE) and a transient cert read
// publishes none either. Gating on the chain instead would mean an on-path attacker who answers with a
// no-TLS greeting is indistinguishable from a datasource that never had TLS, and the token would go out in
// the clear.
//
// Returns the connection to pipe the command phase over — the TLS conn when upgraded, else [raw] — or an
// error (with the proxy's message) if auth fails.
func proxyConnect(raw net.Conn, serverName, certChainPEM string, wireTLS bool, principal, token string, clientCaps uint32) (io.ReadWriter, error) {
	gSeq, greeting, err := mysqlwire.ReadPacket(raw) // greeting (seq 0)
	if err != nil {
		return nil, err
	}
	caps := uint32(mysqlwire.CapProtocol41 | mysqlwire.CapSecureConn | mysqlwire.CapPluginAuth | mysqlwire.CapTransactions)
	// Mirror the client's DEPRECATE_EOF so the proxy's result-set framing matches what we pipe back.
	if clientCaps&mysqlwire.CapDeprecateEOF != 0 {
		caps |= mysqlwire.CapDeprecateEOF
	}

	offersSSL := mysqlwire.GreetingOffersSSL(greeting)
	// A datasource the control plane says serves TLS must not be downgraded to plaintext: something offering
	// none is either misconfigured or not the proxy we meant to reach.
	if wireTLS && !offersSSL {
		return nil, fmt.Errorf("the control plane says this datasource's proxy serves TLS but the greeting offered none — refusing to send the token in plaintext")
	}

	var conn io.ReadWriter = raw
	respSeq := gSeq + 1 // handshake response is seq 1 in the plaintext flow
	if offersSSL {
		caps |= mysqlwire.CapSSL
		// SSLRequest (seq 1) → TLS handshake → real handshake (seq 2) over the encrypted conn.
		if err := mysqlwire.WritePacket(raw, gSeq+1, mysqlwire.SSLRequest(caps)); err != nil {
			return nil, err
		}
		tlsCfg, cfgErr := upstreamTLSConfig(serverName, certChainPEM)
		if cfgErr != nil {
			return nil, cfgErr
		}
		tlsConn := tls.Client(raw, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("TLS handshake with proxy failed: %w", err)
		}
		conn = tlsConn
		respSeq = gSeq + 2
	}

	if err := mysqlwire.WritePacket(conn, respSeq, mysqlwire.ClientHandshakeResponse(caps, principal, []byte{})); err != nil {
		return nil, err
	}
	sSeq, sw, err := mysqlwire.ReadPacket(conn) // expect AuthSwitchRequest (0xfe)
	if err != nil {
		return nil, err
	}
	if len(sw) > 0 && sw[0] == 0xff {
		return nil, fmt.Errorf("%s", mysqlwire.ErrString(sw))
	}
	if len(sw) == 0 || sw[0] != 0xfe {
		return nil, fmt.Errorf("unexpected auth handshake from proxy")
	}
	if err := mysqlwire.WritePacket(conn, sSeq+1, []byte(token)); err != nil { // clear-password = token
		return nil, err
	}
	_, res, err := mysqlwire.ReadPacket(conn) // OK or ERR
	if err != nil {
		return nil, err
	}
	if len(res) > 0 && res[0] == 0xff {
		return nil, fmt.Errorf("%s", mysqlwire.ErrString(res))
	}
	if len(res) > 0 && res[0] == 0x00 {
		return conn, nil
	}
	return nil, fmt.Errorf("unexpected auth result from proxy")
}

// upstreamTLSConfig returns the client TLS config for the upstream proxy hop. The control plane advertises
// the certificate CHAIN to trust for this datasource, so verification is ORDINARY TLS: that chain is the
// root pool, and serverName is checked against it. A self-signed wire cert works because it is its own
// anchor — nothing has to enter the system trust store, and no custom verifier is involved.
//
// This replaced a leaf-fingerprint pin, which had to set InsecureSkipVerify to work and so turned OFF the
// hostname check — a stolen leaf replayed on a different host satisfied it. Chain verification gains that
// hostname binding and is the same verification every other TLS client performs; the tradeoff is that
// identity widens from one exact leaf to any valid certificate for this name under the advertised anchors.
// For a self-signed leaf those are the same thing.
//
// An empty chain falls back to system trust, for a proxy fronted by a publicly-trusted cert. That fallback is
// NOT what decides whether TLS is required — see proxyConnect's wireTLS.
//
// Every certificate in the PEM becomes a trust anchor, INCLUDING the leaf (Go trusts a certificate found
// directly in the roots pool). So a contaminated bundle widens trust rather than failing closed, which is why
// the control plane inspects the chain at registration and warns about anything it cannot verify a path
// through.
func upstreamTLSConfig(serverName, certChainPEM string) (*tls.Config, error) {
	if certChainPEM == "" {
		return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(certChainPEM)) {
		return nil, fmt.Errorf("the advertised wire cert chain for this datasource contains no usable certificate")
	}
	return &tls.Config{ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
}
