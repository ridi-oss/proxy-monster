package pgproxy_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

const sslRequestCode = 80877103

func TestTLSMaskedSelect(t *testing.T) {
	h := startBrokerTLS(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks:    []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)}},
		}), nil
	}

	// sslmode=require without sslrootcert deliberately skips verification: the committed fixture is CN-only
	// and has no SAN, while this test is proving encrypted transport and unchanged masking behavior.
	config, err := pgx.ParseConfig(fmt.Sprintf("postgres://pm:%s@%s/app?sslmode=require", validToken, h.addr))
	if err != nil {
		t.Fatalf("pgx.ParseConfig: %v", err)
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("connect with TLS: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	tlsConn, ok := conn.PgConn().Conn().(*tls.Conn)
	if !ok {
		t.Fatalf("client connection = %T, want *tls.Conn", conn.PgConn().Conn())
	}
	if state := tlsConn.ConnectionState(); !state.HandshakeComplete {
		t.Fatal("TLS handshake is not complete")
	}

	rows, err := conn.Query(context.Background(), "SELECT id, name, ssn FROM it_pgproxy.people ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()

	var ids []int
	var names []string
	var ssns []*string
	for rows.Next() {
		var id int
		var name string
		var ssn *string
		if err := rows.Scan(&id, &name, &ssn); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		ids = append(ids, id)
		names = append(names, name)
		ssns = append(ssns, ssn)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	masked := "####"
	if !reflect.DeepEqual(ids, []int{1, 2}) || !reflect.DeepEqual(names, []string{"Alice", "Bob"}) || !reflect.DeepEqual(ssns, []*string{&masked, nil}) {
		t.Fatalf("masked rows: ids=%v names=%v ssns=%v", ids, names, ssns)
	}
}

func TestTLSRequiredRejectsPlaintextStartup(t *testing.T) {
	h := startBrokerTLS(t)
	conn := dialPG(t, h.addr)
	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":     "pm",
			"database": "app",
		},
	})
	if err := frontend.Flush(); err != nil {
		t.Fatalf("send plaintext startup: %v", err)
	}

	message, err := frontend.Receive()
	if err != nil {
		t.Fatalf("receive TLS-required error: %v", err)
	}
	if _, ok := message.(*pgproto3.AuthenticationCleartextPassword); ok {
		t.Fatal("received AuthenticationCleartextPassword before TLS-required rejection")
	}
	response, ok := message.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("startup response = %T, want ErrorResponse", message)
	}
	if response.Severity != "FATAL" || response.Code != "28000" || !strings.Contains(response.Message, "TLS required") {
		t.Fatalf("startup error = severity %q code %q message %q", response.Severity, response.Code, response.Message)
	}

	message, err = frontend.Receive()
	if err == nil {
		if _, ok := message.(*pgproto3.AuthenticationCleartextPassword); ok {
			t.Fatal("received AuthenticationCleartextPassword after TLS-required rejection")
		}
		t.Fatalf("response after TLS-required error = %T, want connection close", message)
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("receive after TLS-required error: %v, want EOF", err)
	}
}

func TestTLSEnabledAnswersSSLRequestWithS(t *testing.T) {
	h := startBrokerTLS(t)
	conn := dialPG(t, h.addr)
	startupConn := &pipelinedTLSConn{Conn: conn}

	// The first TLS write sends the SSLRequest and ClientHello in one socket write. The wrapper consumes exactly
	// the raw 'S' before tls.Client sees the ServerHello, proving the startup codec did not swallow pipelined bytes.
	tlsConn := tls.Client(startupConn, &tls.Config{
		InsecureSkipVerify: true, // The committed fixture has no SAN.
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	if !startupConn.accepted {
		t.Fatal("SSLRequest response was not consumed")
	}
	frontend := pgproto3.NewFrontend(tlsConn, tlsConn)
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":     "pm",
			"database": "app",
		},
	})
	if err := frontend.Flush(); err != nil {
		t.Fatalf("send startup over TLS: %v", err)
	}
	message, err := frontend.Receive()
	if err != nil {
		t.Fatalf("receive auth request over TLS: %v", err)
	}
	if _, ok := message.(*pgproto3.AuthenticationCleartextPassword); !ok {
		t.Fatalf("auth request = %T, want AuthenticationCleartextPassword", message)
	}
}

func TestProtocol32NegotiatesBeforeAuthentication(t *testing.T) {
	h := startBroker(t)
	conn := dialPG(t, h.addr)
	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: 196610,
		Parameters: map[string]string{
			"user":             "pm",
			"database":         "app",
			"_pq_.traceparent": "ignored",
			"_pq_.feature":     "ignored",
		},
	})
	if err := frontend.Flush(); err != nil {
		t.Fatalf("send protocol 3.2 startup: %v", err)
	}
	message, err := frontend.Receive()
	if err != nil {
		t.Fatalf("receive protocol negotiation: %v", err)
	}
	negotiation, ok := message.(*pgproto3.NegotiateProtocolVersion)
	if !ok {
		t.Fatalf("first startup response = %T, want NegotiateProtocolVersion", message)
	}
	if negotiation.NewestMinorProtocol != 0 ||
		!reflect.DeepEqual(negotiation.UnrecognizedOptions, []string{"_pq_.feature", "_pq_.traceparent"}) {
		t.Fatalf("protocol negotiation = %+v", negotiation)
	}
	message, err = frontend.Receive()
	if err != nil {
		t.Fatalf("receive authentication request: %v", err)
	}
	if _, ok := message.(*pgproto3.AuthenticationCleartextPassword); !ok {
		t.Fatalf("second startup response = %T, want AuthenticationCleartextPassword", message)
	}
}

func TestSSLRequestGetsNWhenTLSDisabled(t *testing.T) {
	h := startBroker(t)
	conn := dialPG(t, h.addr)
	sendSSLRequest(t, conn)

	var response [1]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		t.Fatalf("read SSLRequest response: %v", err)
	}
	if response[0] != 'N' {
		t.Fatalf("SSLRequest response = %q, want 'N'", response[0])
	}

	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":     "pm",
			"database": "app",
		},
	})
	if err := frontend.Flush(); err != nil {
		t.Fatalf("send plaintext startup: %v", err)
	}
	message, err := frontend.Receive()
	if err != nil {
		t.Fatalf("receive plaintext auth request: %v", err)
	}
	if _, ok := message.(*pgproto3.AuthenticationCleartextPassword); !ok {
		t.Fatalf("auth request = %T, want AuthenticationCleartextPassword", message)
	}
}

type pipelinedTLSConn struct {
	net.Conn
	firstWrite bool
	accepted   bool
}

func (c *pipelinedTLSConn) Write(payload []byte) (int, error) {
	if c.firstWrite {
		return c.Conn.Write(payload)
	}
	c.firstWrite = true
	request := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(request[0:4], 8)
	binary.BigEndian.PutUint32(request[4:8], sslRequestCode)
	copy(request[8:], payload)
	if _, err := c.Conn.Write(request); err != nil {
		return 0, err
	}
	var response [1]byte
	if _, err := io.ReadFull(c.Conn, response[:]); err != nil {
		return 0, err
	}
	if response[0] != 'S' {
		return 0, fmt.Errorf("SSLRequest response = %q, want 'S'", response[0])
	}
	c.accepted = true
	return len(payload), nil
}

func dialPG(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		t.Fatalf("dial PostgreSQL broker: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		_ = conn.Close()
		t.Fatalf("set PostgreSQL client deadline: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func sendSSLRequest(t *testing.T, conn net.Conn) {
	t.Helper()
	var request [8]byte
	binary.BigEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.BigEndian.PutUint32(request[4:8], sslRequestCode)
	if _, err := conn.Write(request[:]); err != nil {
		t.Fatalf("send SSLRequest: %v", err)
	}
}
