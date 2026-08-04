package daemon

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// fakeMySQLProxy plays the proxy half of pmon's upstream handshake — greeting, clear-password auth
// switch, OK — then reports the first command packet the broker sends and answers it with response. A
// real loopback listener rather than a pipe, because brokerMySQL dials an address.
//
// The returned channel is closed without a value when the connection ends before any command arrives,
// so a test can tell "the broker sent nothing" from "the broker sent the wrong thing".
func fakeMySQLProxy(t *testing.T, response []byte) (string, <-chan []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	commands := make(chan []byte, 1)
	go func() {
		defer close(commands)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		greeting := mysqlwire.ServerGreeting(1, bytes.Repeat([]byte{3}, 20), "8.0.40-fake", true)
		if err := mysqlwire.WritePacket(conn, 0, greeting); err != nil {
			return
		}
		if _, _, err := mysqlwire.ReadPacket(conn); err != nil { // the broker's handshake response
			return
		}
		if err := mysqlwire.WritePacket(conn, 2, mysqlwire.AuthSwitchClearPassword()); err != nil {
			return
		}
		if _, _, err := mysqlwire.ReadPacket(conn); err != nil { // the token, as the cleartext password
			return
		}
		if err := mysqlwire.WritePacket(conn, 4, mysqlwire.OKPacket()); err != nil {
			return
		}
		_, command, err := mysqlwire.ReadPacket(conn)
		if err != nil {
			return
		}
		commands <- command
		if err := mysqlwire.WritePacket(conn, 1, response); err != nil {
			return
		}
		// Stay open. On the success path the broker starts relaying after this, and an upstream that
		// closed here would tear the relay down before the local client could read its auth result.
		_, _ = io.Copy(io.Discard, conn)
	}()
	return listener.Addr().String(), commands
}

// localClientGreet plays the local client's half of the broker handshake: read the greeting, answer with
// a native-password response naming database. It stops before the auth result, because which packet that
// is is the assertion in the refusal case.
func localClientGreet(t *testing.T, client net.Conn, password, database string) {
	t.Helper()
	_, greeting, err := mysqlwire.ReadPacket(client)
	if err != nil {
		t.Fatalf("read broker greeting: %v", err)
	}
	parsed, err := mysqlwire.ParseHandshakeV10(greeting)
	if err != nil {
		t.Fatalf("parse broker greeting: %v", err)
	}
	auth := mysqlwire.NativePassword(password, parsed.Scramble)
	response := handshakeResponseWithDatabase(auth, "mysql_native_password", database)
	if err := mysqlwire.WritePacket(client, 1, response); err != nil {
		t.Fatalf("write client handshake response: %v", err)
	}
}

// localClientGreetCachingSHA2 plays the local client's half through the caching_sha2_password switch —
// what a MySQL 8 client does without being asked — naming database in its handshake response. It returns
// the sequence the broker's auth result must carry, which is three packets past the direct path's.
func localClientGreetCachingSHA2(t *testing.T, client net.Conn, password, database string) byte {
	t.Helper()
	if _, _, err := mysqlwire.ReadPacket(client); err != nil {
		t.Fatalf("read broker greeting: %v", err)
	}
	// The plugin named with no digest: such a client waits to be switched rather than hash against a
	// scramble issued under another plugin.
	response := handshakeResponseWithDatabase(nil, "caching_sha2_password", database)
	if err := mysqlwire.WritePacket(client, 1, response); err != nil {
		t.Fatalf("write client handshake response: %v", err)
	}
	swSeq, sw, err := mysqlwire.ReadPacket(client)
	if err != nil {
		t.Fatalf("read auth switch: %v", err)
	}
	if len(sw) == 0 || sw[0] != 0xfe {
		t.Fatalf("expected an AuthSwitchRequest, got % x", sw)
	}
	scramble := bytes.TrimSuffix(sw[bytes.IndexByte(sw, 0)+1:], []byte{0})
	if err := mysqlwire.WritePacket(client, swSeq+1, mysqlwire.CachingSHA2Password(password, scramble)); err != nil {
		t.Fatalf("write switch reply: %v", err)
	}
	moreSeq, more, err := mysqlwire.ReadPacket(client)
	if err != nil {
		t.Fatalf("read AuthMoreData: %v", err)
	}
	if len(more) < 2 || more[0] != mysqlwire.AuthMoreData || more[1] != mysqlwire.CachingSHA2FastAuthSuccess {
		t.Fatalf("expected fast-auth success, got % x", more)
	}
	return moreSeq + 1
}

// startBroker runs brokerMySQL against addr and returns the local client end of it.
func startBroker(t *testing.T, addr, password string) (net.Conn, <-chan error) {
	t.Helper()
	clientSide, brokerSide := net.Pipe()
	t.Cleanup(func() { _ = clientSide.Close() })

	done := make(chan error, 1)
	go func() {
		done <- brokerMySQL(brokerSide, addr, "", false, "you@example.com", "sekrit-token", password)
	}()
	return clientSide, done
}

const brokerTestPassword = "pmlocal_correct-horse"

// TestBrokerMySQLSelectsHandshakeDatabase is what makes a DSN-selected database work at all: it arrives
// on the local handshake response, which is consumed here and never reaches the proxy, so the broker has
// to select it upstream with a COM_INIT_DB of its own. Without that the client silently lands on the
// datasource's default schema and every unqualified table name resolves in the wrong place.
func TestBrokerMySQLSelectsHandshakeDatabase(t *testing.T) {
	addr, commands := fakeMySQLProxy(t, mysqlwire.OKPacket())
	client, _ := startBroker(t, addr, brokerTestPassword)

	localClientGreet(t, client, brokerTestPassword, "analytics")

	command, ok := <-commands
	if !ok {
		t.Fatal("the proxy received no command: the selected database was never relayed")
	}
	if len(command) == 0 || command[0] != mysqlwire.ComInitDB {
		t.Fatalf("first upstream command = % x, want a COM_INIT_DB (0x%02x)", command, mysqlwire.ComInitDB)
	}
	if got := string(command[1:]); got != "analytics" {
		t.Fatalf("COM_INIT_DB names %q, want analytics", got)
	}

	_, result, err := mysqlwire.ReadPacket(client)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	if len(result) == 0 || result[0] != 0x00 {
		t.Fatalf("auth result = % x, want OK", result)
	}
}

// TestBrokerMySQLRelaysRefusedDatabase: a proxy that refuses the selected database must not leave the
// client with an OK for a session sitting in some other schema. The proxy's own ERR is relayed verbatim,
// so the client keeps the error code and SQLSTATE it would have received connecting directly.
func TestBrokerMySQLRelaysRefusedDatabase(t *testing.T) {
	refusal := mysqlwire.ErrPacketState(1049, "42000", "Unknown database 'nope'")
	addr, commands := fakeMySQLProxy(t, refusal)
	client, done := startBroker(t, addr, brokerTestPassword)

	localClientGreet(t, client, brokerTestPassword, "nope")

	if _, ok := <-commands; !ok {
		t.Fatal("the proxy received no command: the selected database was never relayed")
	}
	_, result, err := mysqlwire.ReadPacket(client)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	if len(result) == 0 || result[0] != 0xff {
		t.Fatalf("auth result = % x, want the proxy's ERR", result)
	}
	if got := mysqlwire.ErrString(result); !strings.Contains(got, "Unknown database") {
		t.Fatalf("relayed error = %q, want the proxy's own message", got)
	}
	if err := <-done; err == nil {
		t.Fatal("brokerMySQL returned nil after the proxy refused the selected database")
	}
}

// TestBrokerMySQLSelectsHandshakeDatabaseAfterAnAuthSwitch runs the whole broker over the path the mysql
// CLI actually takes — its default plugin is caching_sha2_password, so the local handshake ends three
// packets later than the native one — with a database selected, which is what `pmon show --cli` hands out.
// The selection has to survive the switch and reach the proxy, and the result has to arrive on the packet
// the client is waiting for, or a working session is reported as a protocol error.
func TestBrokerMySQLSelectsHandshakeDatabaseAfterAnAuthSwitch(t *testing.T) {
	for _, test := range []struct {
		name      string
		response  []byte
		wantFirst byte
	}{
		{"proxy accepts the database", mysqlwire.OKPacket(), 0x00},
		{"proxy refuses the database", mysqlwire.ErrPacketState(1049, "42000", "Unknown database 'nope'"), 0xff},
	} {
		t.Run(test.name, func(t *testing.T) {
			addr, commands := fakeMySQLProxy(t, test.response)
			client, _ := startBroker(t, addr, brokerTestPassword)

			resultSeq := localClientGreetCachingSHA2(t, client, brokerTestPassword, "analytics")

			command, ok := <-commands
			if !ok {
				t.Fatal("the proxy received no command: the selected database was never relayed")
			}
			if len(command) == 0 || command[0] != mysqlwire.ComInitDB || string(command[1:]) != "analytics" {
				t.Fatalf("first upstream command = % x, want a COM_INIT_DB naming analytics", command)
			}

			seq, result, err := mysqlwire.ReadPacket(client)
			if err != nil {
				t.Fatalf("read auth result: %v", err)
			}
			if seq != resultSeq {
				t.Fatalf("auth result is packet %d, want %d — the client reads it as out of order", seq, resultSeq)
			}
			if len(result) == 0 || result[0] != test.wantFirst {
				t.Fatalf("auth result = % x, want a packet starting 0x%02x", result, test.wantFirst)
			}
		})
	}
}

// TestBrokerMySQLFailsClosedOnAnUnexpectedSelectResponse: only an OK means the session is in the selected
// database. Answering anything else with the caller's OK would report a session in `analytics` while it
// sits in the datasource's default schema — the silent wrong-schema failure this selection exists to
// prevent — and a first-of-several packet would then be relayed as the answer to the client's first query.
func TestBrokerMySQLFailsClosedOnAnUnexpectedSelectResponse(t *testing.T) {
	for _, test := range []struct {
		name     string
		response []byte
	}{
		// A result-set column count: the shape of a response with more packets behind it.
		{"result-set header", []byte{0x01}},
		{"empty payload", []byte{}},
		// 0xfe is the byte most likely to be mistaken for success here: the upstream connection mirrors
		// the client's DEPRECATE_EOF, under which a 0xfe header is an OK packet where an EOF used to be.
		// COM_INIT_DB is answered with a real OK, so 0x00 stays the only accepted header.
		{"EOF", []byte{0xfe, 0x00, 0x00, 0x02, 0x00}},
	} {
		t.Run(test.name, func(t *testing.T) {
			addr, commands := fakeMySQLProxy(t, test.response)
			client, done := startBroker(t, addr, brokerTestPassword)

			localClientGreet(t, client, brokerTestPassword, "analytics")

			if _, ok := <-commands; !ok {
				t.Fatal("the proxy received no command: the selected database was never relayed")
			}
			_, result, err := mysqlwire.ReadPacket(client)
			if err != nil {
				t.Fatalf("read auth result: %v", err)
			}
			if len(result) == 0 || result[0] != 0xff {
				t.Fatalf("auth result = % x, want an ERR: the client must not be told it is in analytics", result)
			}
			if err := <-done; err == nil {
				t.Fatal("brokerMySQL returned nil after an unexpected COM_INIT_DB response")
			}
		})
	}
}

// TestBrokerMySQLSelectsNothingWithoutADatabase: a client that selected none must not have one selected
// for it. The first thing the proxy sees is the client's own command, not a COM_INIT_DB for an empty name.
func TestBrokerMySQLSelectsNothingWithoutADatabase(t *testing.T) {
	addr, commands := fakeMySQLProxy(t, mysqlwire.OKPacket())
	client, _ := startBroker(t, addr, brokerTestPassword)

	localClientGreet(t, client, brokerTestPassword, "")

	_, result, err := mysqlwire.ReadPacket(client)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	if len(result) == 0 || result[0] != 0x00 {
		t.Fatalf("auth result = % x, want OK", result)
	}
	// The relay is up, so what the proxy reads next is whatever the client sends.
	query := append([]byte{mysqlwire.ComQuery}, "SELECT 1"...)
	if err := mysqlwire.WritePacket(client, 0, query); err != nil {
		t.Fatalf("write client query: %v", err)
	}
	command, ok := <-commands
	if !ok {
		t.Fatal("the proxy received no command")
	}
	if !bytes.Equal(command, query) {
		t.Fatalf("first upstream command = % x, want the client's own query % x", command, query)
	}
}
