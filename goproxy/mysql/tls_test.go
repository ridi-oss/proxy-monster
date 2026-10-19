package mysql_test

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const testTLSConfigName = "proxy-monster-test"

func registerTestTLSConfig(t *testing.T) {
	t.Helper()
	// InsecureSkipVerify is test-only because the committed proxytls fixture is CN-only with no SAN;
	// current Go releases reject CN-only certificates during hostname verification.
	if err := mysqldriver.RegisterTLSConfig(testTLSConfigName, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Test fixture has no SAN; transport encryption is still exercised.
		MinVersion:         tls.VersionTLS12,
	}); err != nil {
		t.Fatalf("mysqldriver.RegisterTLSConfig: %v", err)
	}
	t.Cleanup(func() { mysqldriver.DeregisterTLSConfig(testTLSConfigName) })
}

func openDBWithDSN(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	conn, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestTLSMaskedSelect(t *testing.T) {
	registerTestTLSConfig(t)
	h := startBrokerTLS(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks: []*pb.ColumnMask{
				{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)},
			},
		}), nil
	}
	dsn := fmt.Sprintf("pm:%s@tcp(%s)/?allowCleartextPasswords=true&interpolateParams=false&tls=%s", validToken, h.addr, testTLSConfigName)
	conn := openDBWithDSN(t, dsn)
	rows, err := conn.Query("SELECT id, name, ssn FROM people ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()

	var got []sql.NullString
	var ids []int
	var names []string
	for rows.Next() {
		var id int
		var name string
		var ssn sql.NullString
		if err := rows.Scan(&id, &name, &ssn); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		ids = append(ids, id)
		names = append(names, name)
		got = append(got, ssn)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	if !reflect.DeepEqual(ids, []int{1, 2}) || !reflect.DeepEqual(names, []string{"Alice", "Bob"}) {
		t.Fatalf("unmasked columns changed: ids=%v names=%v", ids, names)
	}
	want := []sql.NullString{{String: "####", Valid: true}, {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("masked ssn = %#v, want %#v", got, want)
	}
}

func TestTLSRequiredRejectsPlaintextHandshake(t *testing.T) {
	h := startBrokerTLS(t)
	dsn := fmt.Sprintf("pm:%s@tcp(%s)/?allowCleartextPasswords=true&interpolateParams=false", validToken, h.addr)
	conn := openDBWithDSN(t, dsn)
	if err := conn.Ping(); err == nil {
		t.Fatal("Ping succeeded without TLS")
	} else if !strings.Contains(err.Error(), "TLS required") {
		t.Fatalf("Ping error = %q, want TLS required", err)
	}
}

func TestTLSGreetingAdvertisesClientSSL(t *testing.T) {
	tests := []struct {
		name string
		new  func(*testing.T) *brokerHarness
		want bool
	}{
		{name: "TLS", new: startBrokerTLS, want: true},
		{name: "plaintext", new: startBroker, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := test.new(t)
			conn, err := net.Dial("tcp", h.addr)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer conn.Close()
			_, greeting, err := mysqlwire.ReadPacket(conn)
			if err != nil {
				t.Fatalf("ReadPacket greeting: %v", err)
			}
			if got := mysqlwire.GreetingOffersSSL(greeting); got != test.want {
				t.Fatalf("GreetingOffersSSL = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPlaintextStillWorksWhenTLSDisabled(t *testing.T) {
	h := startBroker(t)
	conn := h.openDB(t, validToken)
	if err := conn.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	var got int
	if err := conn.QueryRow("SELECT 1").Scan(&got); err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if got != 1 {
		t.Fatalf("SELECT 1 = %d, want 1", got)
	}
}
