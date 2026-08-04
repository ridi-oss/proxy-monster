package daemon

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// TestLocalServerGreetAdvertisesConnectWithDB pins the broker greeting's CONNECT_WITH_DB capability. A
// JDBC driver (Connector/J, so DBeaver) writes its DSN database into the handshake response whether or
// not the greeting offered the capability; withholding it leaves that field unclaimed, so the plugin
// name that follows is read AS the database and the client is switched to mysql_clear_password — which
// it refuses over the plaintext loopback. The selected database is not dropped: brokerMySQL forwards it
// upstream with COM_INIT_DB.
func TestLocalServerGreetAdvertisesConnectWithDB(t *testing.T) {
	clientSide, brokerSide := net.Pipe()
	defer clientSide.Close()
	defer brokerSide.Close()

	type greetResult struct {
		caps uint32
		err  error
	}
	done := make(chan greetResult, 1)
	go func() {
		caps, _, _, err := localServerGreet(brokerSide, make([]byte, 20), "pmlocal_test")
		done <- greetResult{caps: caps, err: err}
	}()

	_, greeting, err := mysqlwire.ReadPacket(clientSide)
	if err != nil {
		t.Fatalf("read broker greeting: %v", err)
	}
	parsed, err := mysqlwire.ParseHandshakeV10(greeting)
	if err != nil {
		t.Fatalf("parse broker greeting: %v", err)
	}
	if parsed.Capabilities&mysqlwire.CapConnectWithDB == 0 {
		t.Fatalf("pmon greeting caps = %#x withhold CONNECT_WITH_DB; a JDBC driver's schema field would be misread as the auth plugin", parsed.Capabilities)
	}
	// The advertised plugin decides which digest a client computes, and the password check verifies
	// against it. A greeting that named a different plugin would still authenticate — the switch paths
	// cover that — but this is the one every client takes without extra configuration.
	if parsed.AuthPlugin != "mysql_native_password" {
		t.Fatalf("pmon greeting advertises %q, want mysql_native_password", parsed.AuthPlugin)
	}

	// Unblock localServerGreet with a minimal handshake response. It carries no auth response, so the
	// password check rejects it — this test is about the greeting's capabilities, and the capability
	// assertion above has already run against the real greeting.
	if err := mysqlwire.WritePacket(clientSide, 1, make([]byte, 32)); err != nil {
		t.Fatalf("write client handshake response: %v", err)
	}
	if res := <-done; !errors.Is(res.err, errLocalAuth) {
		t.Fatalf("localServerGreet with no password: err = %v, want errLocalAuth", res.err)
	}
}

// selfSignedServer builds a server TLS config with a fresh self-signed leaf and returns it alongside the
// leaf DER — the exact bytes a client receives as rawCerts[0] and the proxy would advertise as its SHA-256
// Self-signed on purpose: it is its own trust anchor, which is the ordinary proxy case.
func selfSignedServer(t *testing.T) (*tls.Config, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "proxy.example"},
		// A DNS SAN is required now that verification checks the hostname — the pin it replaced did not.
		DNSNames:              []string{"proxy.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
	return cfg, der
}

// tlsHandshake drives a real client↔server TLS handshake over an in-memory pipe and returns the CLIENT's
// result — so verification is exercised through the actual handshake against the real certificate, not by
// calling a callback with pretend bytes.
//
// Both ends are closed before waiting on the server. net.Pipe is unbuffered and synchronous, so a client
// that ABORTS mid-handshake (which is exactly what a verification failure does) leaves the server blocked
// writing a record nobody will read; waiting on it first would hang the test rather than fail it.
func tlsHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) error {
	t.Helper()
	cConn, sConn := net.Pipe()
	// A deadline on the pipe, not just a Close: net.Pipe is synchronous, so a server mid-write when the client
	// aborts stays blocked inside Handshake even after both ends are closed. The deadline makes that write fail
	// instead, which is the only way this returns rather than hanging the suite. A successful handshake takes
	// microseconds, so this only ever elapses on the abort paths the failure cases deliberately exercise.
	deadline := time.Now().Add(2 * time.Second)
	_ = cConn.SetDeadline(deadline)
	_ = sConn.SetDeadline(deadline)
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		_ = tls.Server(sConn, serverCfg).Handshake()
	}()
	err := tls.Client(cConn, clientCfg).Handshake()
	cConn.Close()
	sConn.Close()
	<-srvDone
	return err
}

// TestUpstreamTLSVerifiesAgainstTheAdvertisedChain proves the end-to-end contract through a real handshake:
// a client given the chain the control plane advertised completes the handshake WITH the hostname checked,
// and a chain for a different certificate aborts it before the connection is usable.
//
// The hostname check is the part the leaf-fingerprint pin this replaced could not do: pinning had to set
// InsecureSkipVerify, so a stolen leaf replayed under any name satisfied it. Here a wrong name fails even
// when the certificate itself is the right one.
func TestUpstreamTLSVerifiesAgainstTheAdvertisedChain(t *testing.T) {
	serverCfg, leafDER := selfSignedServer(t)
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

	cfg, err := upstreamTLSConfig("proxy.example", chain)
	if err != nil {
		t.Fatalf("upstreamTLSConfig: %v", err)
	}
	if err := tlsHandshake(t, serverCfg, cfg); err != nil {
		t.Errorf("handshake against the advertised chain failed: %v", err)
	}

	// A chain for some OTHER certificate must not verify this server.
	_, otherDER := selfSignedServer(t)
	otherChain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER}))
	wrongCfg, err := upstreamTLSConfig("proxy.example", otherChain)
	if err != nil {
		t.Fatalf("upstreamTLSConfig: %v", err)
	}
	if err := tlsHandshake(t, serverCfg, wrongCfg); err == nil {
		t.Error("handshake succeeded against a chain for a different certificate — verification is not enforced")
	}

	// The right certificate under the WRONG NAME must also fail. This is what pinning could not catch.
	nameCfg, err := upstreamTLSConfig("someone-else.example", chain)
	if err != nil {
		t.Fatalf("upstreamTLSConfig: %v", err)
	}
	if err := tlsHandshake(t, serverCfg, nameCfg); err == nil {
		t.Error("handshake succeeded with a mismatched server name — the hostname is not being checked")
	}
}

// TestUpstreamTLSRejectsAnUnusableChain: a chain that carries no certificate is a configuration error, and
// must surface as one rather than silently falling back to system trust (which would accept a public CA's
// certificate for this host — not what the control plane advertised).
func TestUpstreamTLSRejectsAnUnusableChain(t *testing.T) {
	if _, err := upstreamTLSConfig("proxy.example", "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"); err == nil {
		t.Error("an unparseable chain must be an error, not a silent fallback to system trust")
	}
}

// TestProxyConnectRefusesPlaintextWhenTLSIsExpected proves the downgrade refusal end-to-end, and proves it is
// driven by the TLS REQUIREMENT rather than by the presence of trust material.
//
// The second case is the one that matters. A proxy serving a publicly-trusted certificate publishes NO chain
// (PM_TLS_NO_ADVERTISE), so a refusal gated on "is a chain advertised" would go dead for exactly that
// deployment: an on-path attacker answers the unauthenticated greeting without CLIENT_SSL and pmon hands over
// a live session token in plaintext. Gating on wireTLS closes it. If someone reintroduces the chain-based
// gate, the noChain subtest fails.
func TestProxyConnectRefusesPlaintextWhenTLSIsExpected(t *testing.T) {
	const chain = "-----BEGIN CERTIFICATE-----\nirrelevant\n-----END CERTIFICATE-----\n"
	cases := []struct {
		name  string
		chain string
	}{
		{name: "a chain is advertised", chain: chain},
		// No trust material at all: only wireTLS says TLS is expected.
		{name: "no chain is published, only the TLS requirement", chain: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			scramble := make([]byte, 20)
			sentAfterGreeting := make(chan int, 1)
			go func() {
				// Play an attacker (or a misconfigured proxy) advertising NO TLS in its greeting.
				_ = mysqlwire.WritePacket(server, 0, mysqlwire.ServerGreeting(1, scramble, "8.0-test", false))
				buf := make([]byte, 512)
				n, _ := server.Read(buf) // a correct client writes NOTHING after the greeting
				sentAfterGreeting <- n
				server.Close()
			}()

			// The refusal happens on the greeting, before any TLS config is built, so the chain's contents are
			// never reached.
			_, err := proxyConnect(client, "proxy.example", tc.chain, true, "you@example.com", "sekrit-token", 0)
			client.Close() // unblock the server's Read → EOF (n==0 iff the client sent nothing)

			if err == nil {
				t.Fatal("proxyConnect accepted a plaintext (no-TLS) proxy — the token would cross in the clear")
			}
			if !strings.Contains(err.Error(), "offered none") {
				t.Errorf("expected a downgrade refusal, got: %v", err)
			}
			if n := <-sentAfterGreeting; n != 0 {
				t.Errorf("client sent %d bytes to a no-TLS proxy; the token must never be transmitted", n)
			}
		})
	}
}

// TestProxyConnectAllowsPlaintextOnlyWhenTLSIsNotExpected is the negative control for the test above: a
// genuinely plaintext datasource (wireTLS false) must still work, or the refusal would just be an outage. It
// gets past the greeting and writes a handshake instead of erroring out on it.
func TestProxyConnectAllowsPlaintextOnlyWhenTLSIsNotExpected(t *testing.T) {
	client, server := net.Pipe()
	scramble := make([]byte, 20)
	wroteHandshake := make(chan bool, 1)
	go func() {
		_ = mysqlwire.WritePacket(server, 0, mysqlwire.ServerGreeting(1, scramble, "8.0-test", false))
		// A client that proceeds sends its handshake response here. Reading anything at all is the signal;
		// the exchange is then abandoned, so proxyConnect returns an error either way.
		buf := make([]byte, 512)
		n, _ := server.Read(buf)
		wroteHandshake <- n > 0
		server.Close()
	}()

	_, _ = proxyConnect(client, "proxy.example", "", false, "you@example.com", "sekrit-token", 0)
	client.Close()

	if !<-wroteHandshake {
		t.Error("a plaintext datasource with TLS off must still connect; the refusal must not fire here")
	}
}

// handshakeResponseWith builds a client handshake response carrying authResp under plugin, in the
// secure-connection encoding a real MySQL client uses. An empty plugin omits the field entirely,
// which is what a client that negotiated no CapPluginAuth sends.
func handshakeResponseWith(authResp []byte, plugin string) []byte {
	caps := uint32(mysqlwire.CapProtocol41 | mysqlwire.CapSecureConn)
	if plugin != "" {
		caps |= mysqlwire.CapPluginAuth
	}
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 16<<20)
	b = append(b, 45)
	b = append(b, make([]byte, 23)...)
	b = append(b, "pm"...)
	b = append(b, 0)
	b = append(b, byte(len(authResp)))
	b = append(b, authResp...)
	if plugin != "" {
		b = append(b, plugin...)
		b = append(b, 0)
	}
	return b
}

// TestLocalServerGreetChecksPassword is the local trust boundary: the daemon holds a live upstream
// token, so any process that can open its loopback port could otherwise borrow the whole session.
func TestLocalServerGreetChecksPassword(t *testing.T) {
	const password = "pmlocal_correct-horse"
	scramble := bytes.Repeat([]byte{7}, 20)

	tests := []struct {
		name    string
		auth    []byte
		plugin  string
		stored  string
		wantErr bool
		// drains is how many packets the broker writes after the greeting. net.Pipe is unbuffered, so
		// a test that does not read them deadlocks the broker mid-write.
		drains int
	}{
		{"native, correct password", mysqlwire.NativePassword(password, scramble), "mysql_native_password", password, false, 0},
		{"native, wrong password", mysqlwire.NativePassword("pmlocal_wrong", scramble), "mysql_native_password", password, true, 0},
		{"no plugin named, correct password", mysqlwire.NativePassword(password, scramble), "", password, false, 0},
		{"no password", nil, "mysql_native_password", password, true, 0},
		{"empty stored password refuses every client", mysqlwire.NativePassword(password, scramble), "mysql_native_password", "", true, 0},
		{"right password, wrong scramble", mysqlwire.NativePassword(password, bytes.Repeat([]byte{9}, 20)), "mysql_native_password", password, true, 0},
		// MySQL 8's default plugin: a client that answers with it is verified, not refused.
		{"caching_sha2, correct password", mysqlwire.CachingSHA2Password(password, scramble), "caching_sha2_password", password, false, 1},
		{"caching_sha2, wrong password", mysqlwire.CachingSHA2Password("pmlocal_wrong", scramble), "caching_sha2_password", password, true, 0},
		// A native digest presented AS caching_sha2 must not verify: the plugin selects the digest.
		{"plugin/digest mismatch", mysqlwire.NativePassword(password, scramble), "caching_sha2_password", password, true, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientSide, brokerSide := net.Pipe()
			defer clientSide.Close()
			defer brokerSide.Close()

			done := make(chan error, 1)
			go func() {
				_, _, _, err := localServerGreet(brokerSide, scramble, test.stored)
				done <- err
			}()

			if _, _, err := mysqlwire.ReadPacket(clientSide); err != nil {
				t.Fatalf("read greeting: %v", err)
			}
			if err := mysqlwire.WritePacket(clientSide, 1, handshakeResponseWith(test.auth, test.plugin)); err != nil {
				t.Fatalf("write handshake response: %v", err)
			}
			// Drain whatever the broker writes back, or its write blocks on this unbuffered pipe.
			for i := 0; i < test.drains; i++ {
				if _, _, err := mysqlwire.ReadPacket(clientSide); err != nil {
					t.Fatalf("drain broker packet %d: %v", i, err)
				}
			}

			err := <-done
			if test.wantErr && !errors.Is(err, errLocalAuth) {
				t.Fatalf("err = %v, want errLocalAuth", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
		})
	}
}

// TestLocalServerGreetSwitchesUnknownPlugin: a client that answers with a plugin the broker cannot
// verify directly is switched to mysql_clear_password rather than refused, so an unusual driver can
// still authenticate. The switch reply is the password itself, over loopback.
func TestLocalServerGreetSwitchesUnknownPlugin(t *testing.T) {
	const password = "pmlocal_correct-horse"
	scramble := bytes.Repeat([]byte{7}, 20)

	for _, test := range []struct {
		name    string
		send    string
		wantErr bool
	}{
		{"correct password after switch", password, false},
		{"wrong password after switch", "pmlocal_nope", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientSide, brokerSide := net.Pipe()
			defer clientSide.Close()
			defer brokerSide.Close()

			type res struct {
				seq byte
				err error
			}
			done := make(chan res, 1)
			go func() {
				_, _, seq, err := localServerGreet(brokerSide, scramble, password)
				done <- res{seq: seq, err: err}
			}()

			if _, _, err := mysqlwire.ReadPacket(clientSide); err != nil {
				t.Fatalf("read greeting: %v", err)
			}
			// sha256_password is a real plugin this broker verifies neither of directly.
			if err := mysqlwire.WritePacket(clientSide, 1, handshakeResponseWith([]byte{1, 2, 3}, "sha256_password")); err != nil {
				t.Fatalf("write handshake response: %v", err)
			}
			seq, sw, err := mysqlwire.ReadPacket(clientSide)
			if err != nil {
				t.Fatalf("read auth switch: %v", err)
			}
			if len(sw) == 0 || sw[0] != 0xfe {
				t.Fatalf("expected an AuthSwitchRequest, got % x", sw)
			}
			if !bytes.Contains(sw, []byte("mysql_clear_password")) {
				t.Fatalf("switch names %q, want mysql_clear_password", sw)
			}
			if err := mysqlwire.WritePacket(clientSide, seq+1, append([]byte(test.send), 0)); err != nil {
				t.Fatalf("write switch reply: %v", err)
			}

			got := <-done
			if test.wantErr && !errors.Is(got.err, errLocalAuth) {
				t.Fatalf("err = %v, want errLocalAuth", got.err)
			}
			if !test.wantErr && got.err != nil {
				t.Fatalf("err = %v, want nil", got.err)
			}
			// The switch consumed packets 2 and 3, so the caller's reply must not reuse 2.
			if got.seq != 4 {
				t.Fatalf("nextSeq = %d after an auth switch, want 4", got.seq)
			}
			_ = seq
		})
	}
}

// TestLocalServerGreetSwitchesToCachingSHA2 covers what a real MySQL 8 client does when told to
// prefer caching_sha2_password against this broker's native greeting: it names the plugin but sends
// NO digest, waiting to be switched, because it will not hash against a scramble issued under
// another plugin. Verifying that empty response directly would reject every such client.
func TestLocalServerGreetSwitchesToCachingSHA2(t *testing.T) {
	const password = "pmlocal_correct-horse"

	for _, test := range []struct {
		name    string
		send    string
		wantErr bool
	}{
		{"correct password after switch", password, false},
		{"wrong password after switch", "pmlocal_nope", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientSide, brokerSide := net.Pipe()
			defer clientSide.Close()
			defer brokerSide.Close()

			done := make(chan error, 1)
			go func() {
				_, _, _, err := localServerGreet(brokerSide, bytes.Repeat([]byte{7}, 20), password)
				done <- err
			}()

			if _, _, err := mysqlwire.ReadPacket(clientSide); err != nil {
				t.Fatalf("read greeting: %v", err)
			}
			// The plugin named, no digest — exactly what the mysql CLI sends here.
			if err := mysqlwire.WritePacket(clientSide, 1, handshakeResponseWith(nil, "caching_sha2_password")); err != nil {
				t.Fatalf("write handshake response: %v", err)
			}

			seq, sw, err := mysqlwire.ReadPacket(clientSide)
			if err != nil {
				t.Fatalf("read auth switch: %v", err)
			}
			if len(sw) == 0 || sw[0] != 0xfe || !bytes.Contains(sw, []byte("caching_sha2_password")) {
				t.Fatalf("expected a caching_sha2_password AuthSwitchRequest, got % x", sw)
			}
			// The scramble follows the NUL-terminated plugin name, itself NUL-terminated.
			rest := sw[bytes.IndexByte(sw, 0)+1:]
			scramble := bytes.TrimSuffix(rest, []byte{0})
			if len(scramble) != 20 {
				t.Fatalf("switch scramble is %d bytes, want 20", len(scramble))
			}

			if err := mysqlwire.WritePacket(clientSide, seq+1, mysqlwire.CachingSHA2Password(test.send, scramble)); err != nil {
				t.Fatalf("write switch reply: %v", err)
			}
			if !test.wantErr {
				// Success ends with the fast-auth verdict; drain it or the broker blocks writing.
				_, more, err := mysqlwire.ReadPacket(clientSide)
				if err != nil {
					t.Fatalf("read AuthMoreData: %v", err)
				}
				if len(more) < 2 || more[0] != mysqlwire.AuthMoreData || more[1] != mysqlwire.CachingSHA2FastAuthSuccess {
					t.Fatalf("expected fast-auth success, got % x", more)
				}
			}

			err = <-done
			if test.wantErr && !errors.Is(err, errLocalAuth) {
				t.Fatalf("err = %v, want errLocalAuth", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
		})
	}
}

// handshakeResponseWithDB builds a handshake response that selects a database, the way Connector/J (so
// DBeaver) does: CONNECT_WITH_DB set, and the schema written BETWEEN the auth response and the plugin
// name. A broker that does not consume that field reads the plugin name as the database.
func handshakeResponseWithDB(authResp []byte, plugin, database string) []byte {
	caps := uint32(mysqlwire.CapProtocol41 | mysqlwire.CapSecureConn | mysqlwire.CapConnectWithDB)
	if plugin != "" {
		caps |= mysqlwire.CapPluginAuth
	}
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 16<<20)
	b = append(b, 45)
	b = append(b, make([]byte, 23)...)
	b = append(b, "pm"...)
	b = append(b, 0)
	b = append(b, byte(len(authResp)))
	b = append(b, authResp...)
	b = append(b, database...)
	b = append(b, 0)
	if plugin != "" {
		b = append(b, plugin...)
		b = append(b, 0)
	}
	return b
}

// TestLocalServerGreetHandshakeDatabase reproduces the DBeaver/Connector-J connection that motivated
// advertising CONNECT_WITH_DB: the handshake response carries a database between the auth response and
// the plugin name. The broker must read the plugin where the client wrote it (caching_sha2_password
// here) and authenticate through it — not mistake the database for an unknown plugin and switch to
// mysql_clear_password — and it must surface the selected database so brokerMySQL forwards it upstream.
func TestLocalServerGreetHandshakeDatabase(t *testing.T) {
	const password = "pmlocal_correct-horse"
	scramble := bytes.Repeat([]byte{7}, 20)

	clientSide, brokerSide := net.Pipe()
	defer clientSide.Close()
	defer brokerSide.Close()

	type res struct {
		db  string
		err error
	}
	done := make(chan res, 1)
	go func() {
		_, db, _, err := localServerGreet(brokerSide, scramble, password)
		done <- res{db, err}
	}()

	if _, _, err := mysqlwire.ReadPacket(clientSide); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	resp := handshakeResponseWithDB(mysqlwire.CachingSHA2Password(password, scramble), "caching_sha2_password", "app")
	if err := mysqlwire.WritePacket(clientSide, 1, resp); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	// A matching caching_sha2 digest ends in a fast-auth verdict — never an auth switch, and above all
	// never the mysql_clear_password switch the misparse produced. Drain it or the broker blocks writing.
	_, more, err := mysqlwire.ReadPacket(clientSide)
	if err != nil {
		t.Fatalf("read AuthMoreData: %v", err)
	}
	if bytes.Contains(more, []byte("mysql_clear_password")) {
		t.Fatalf("broker switched to mysql_clear_password on a handshake carrying a database")
	}
	if len(more) < 2 || more[0] != mysqlwire.AuthMoreData || more[1] != mysqlwire.CachingSHA2FastAuthSuccess {
		t.Fatalf("expected fast-auth success, got % x", more)
	}

	got := <-done
	if got.err != nil {
		t.Fatalf("err = %v, want nil", got.err)
	}
	if got.db != "app" {
		t.Fatalf("selected database = %q, want %q", got.db, "app")
	}
}

// TestLocalServerGreetSequenceIsContiguous pins the packet numbering each path ends on. MySQL
// requires strictly increasing sequence numbers within a handshake, so a wrong nextSeq desynchronizes
// the client — it reads the caller's OK as belonging to a packet it never sent.
func TestLocalServerGreetSequenceIsContiguous(t *testing.T) {
	const password = "pmlocal_correct-horse"
	scramble := bytes.Repeat([]byte{7}, 20)

	// native: greeting 0, response 1 -> caller replies at 2.
	t.Run("native", func(t *testing.T) {
		clientSide, brokerSide := net.Pipe()
		defer clientSide.Close()
		defer brokerSide.Close()
		type res struct {
			seq byte
			err error
		}
		done := make(chan res, 1)
		go func() {
			_, _, seq, err := localServerGreet(brokerSide, scramble, password)
			done <- res{seq, err}
		}()
		if _, _, err := mysqlwire.ReadPacket(clientSide); err != nil {
			t.Fatalf("greeting: %v", err)
		}
		auth := mysqlwire.NativePassword(password, scramble)
		if err := mysqlwire.WritePacket(clientSide, 1, handshakeResponseWith(auth, "mysql_native_password")); err != nil {
			t.Fatalf("response: %v", err)
		}
		got := <-done
		if got.err != nil {
			t.Fatalf("err = %v", got.err)
		}
		if got.seq != 2 {
			t.Fatalf("nextSeq = %d, want 2", got.seq)
		}
	})

	// caching_sha2 switch: greeting 0, response 1, switch 2, reply 3, AuthMoreData 4 -> caller at 5.
	t.Run("caching_sha2 switch", func(t *testing.T) {
		clientSide, brokerSide := net.Pipe()
		defer clientSide.Close()
		defer brokerSide.Close()
		type res struct {
			seq byte
			err error
		}
		done := make(chan res, 1)
		go func() {
			_, _, seq, err := localServerGreet(brokerSide, scramble, password)
			done <- res{seq, err}
		}()
		if _, _, err := mysqlwire.ReadPacket(clientSide); err != nil {
			t.Fatalf("greeting: %v", err)
		}
		if err := mysqlwire.WritePacket(clientSide, 1, handshakeResponseWith(nil, "caching_sha2_password")); err != nil {
			t.Fatalf("response: %v", err)
		}
		swSeq, sw, err := mysqlwire.ReadPacket(clientSide)
		if err != nil {
			t.Fatalf("switch: %v", err)
		}
		if swSeq != 2 {
			t.Fatalf("switch seq = %d, want 2", swSeq)
		}
		rest := sw[bytes.IndexByte(sw, 0)+1:]
		sc := bytes.TrimSuffix(rest, []byte{0})
		if err := mysqlwire.WritePacket(clientSide, 3, mysqlwire.CachingSHA2Password(password, sc)); err != nil {
			t.Fatalf("reply: %v", err)
		}
		moreSeq, _, err := mysqlwire.ReadPacket(clientSide)
		if err != nil {
			t.Fatalf("AuthMoreData: %v", err)
		}
		if moreSeq != 4 {
			t.Fatalf("AuthMoreData seq = %d, want 4", moreSeq)
		}
		got := <-done
		if got.err != nil {
			t.Fatalf("err = %v", got.err)
		}
		if got.seq != 5 {
			t.Fatalf("nextSeq = %d, want 5", got.seq)
		}
	})
}

// TestCachingSHA2SwitchFailureSequence pins the sequence on the REJECTED path. A wrong digest ends
// the exchange at the reply (packet 3), so the caller's error is packet 4 — reporting 5, as if the
// fast-auth verdict had been sent, makes the client read the error as out of order and hide the
// access-denied behind a protocol complaint.
func TestCachingSHA2SwitchFailureSequence(t *testing.T) {
	clientSide, brokerSide := net.Pipe()
	defer clientSide.Close()
	defer brokerSide.Close()

	const password = "pmlocal_correct-horse"
	type res struct {
		seq byte
		err error
	}
	done := make(chan res, 1)
	go func() {
		_, _, seq, err := localServerGreet(brokerSide, bytes.Repeat([]byte{7}, 20), password)
		done <- res{seq, err}
	}()

	if _, _, err := mysqlwire.ReadPacket(clientSide); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if err := mysqlwire.WritePacket(clientSide, 1, handshakeResponseWith(nil, "caching_sha2_password")); err != nil {
		t.Fatalf("response: %v", err)
	}
	swSeq, sw, err := mysqlwire.ReadPacket(clientSide)
	if err != nil {
		t.Fatalf("switch: %v", err)
	}
	if swSeq != 2 {
		t.Fatalf("switch seq = %d, want 2", swSeq)
	}
	// The scramble is NUL-terminated, as a server sends it; a bare 20 bytes would be a protocol error.
	if sw[len(sw)-1] != 0 {
		t.Fatalf("switch payload does not end in NUL: % x", sw[len(sw)-8:])
	}
	rest := sw[bytes.IndexByte(sw, 0)+1:]
	sc := rest[:len(rest)-1]
	if len(sc) != 20 {
		t.Fatalf("switch scramble is %d bytes, want 20", len(sc))
	}

	if err := mysqlwire.WritePacket(clientSide, 3, mysqlwire.CachingSHA2Password("pmlocal_wrong", sc)); err != nil {
		t.Fatalf("reply: %v", err)
	}
	got := <-done
	if !errors.Is(got.err, errLocalAuth) {
		t.Fatalf("err = %v, want errLocalAuth", got.err)
	}
	if got.seq != 4 {
		t.Fatalf("nextSeq = %d after a rejected switch, want 4 (the switch and its reply only)", got.seq)
	}
}

// TestProxyInitDB covers the upstream database-selection hop the broker performs for a client that chose
// its schema in the handshake: an OK confirms it, the proxy's ERR is returned verbatim so the broker can
// relay the real code and SQLSTATE, and any reply that is neither OK nor ERR fails CLOSED rather than
// letting the broker report the connection ready.
func TestProxyInitDB(t *testing.T) {
	tests := []struct {
		name         string
		reply        []byte
		wantErr      bool
		wantUpstream bool // a relayable ERR payload came back
	}{
		{"ok", mysqlwire.OKPacket(), false, false},
		{"proxy err relayed verbatim", mysqlwire.ErrPacketState(1044, "42000", "Access denied"), true, true},
		{"empty reply fails closed", []byte{}, true, false},
		{"unexpected reply fails closed", []byte{0xfe}, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, proxy := net.Pipe()
			defer client.Close()
			defer proxy.Close()

			go func() {
				_, cmd, err := mysqlwire.ReadPacket(proxy) // COM_INIT_DB
				if err != nil || len(cmd) == 0 || cmd[0] != mysqlwire.ComInitDB || string(cmd[1:]) != "app" {
					return
				}
				_ = mysqlwire.WritePacket(proxy, 1, tc.reply)
			}()

			upErr, err := proxyInitDB(client, "app")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if (upErr != nil) != tc.wantUpstream {
				t.Fatalf("upstreamErr = % x, wantUpstream = %v", upErr, tc.wantUpstream)
			}
			// A relayed payload must be the proxy's ERR verbatim, so its code and SQLSTATE reach the client.
			if tc.wantUpstream && !bytes.Equal(upErr, tc.reply) {
				t.Fatalf("relayed payload = % x, want the proxy's ERR verbatim % x", upErr, tc.reply)
			}
		})
	}
}
