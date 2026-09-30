package pgproxy

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/targettls"
)

func tlsOnlyTarget(t *testing.T, config *tls.Config) spi.TargetDb {
	t.Helper()
	db := dbtest.PostgresTLS(t)
	return spi.TargetDb{Host: db.Host, Port: db.Port, Db: db.DB, User: db.User, Password: db.Password, TLS: config}
}

func TestTargetDbTLSVerifyFull(t *testing.T) {
	target := tlsOnlyTarget(t, nil)
	config, err := targettls.Config(targettls.VerifyFull, dbtest.TLSCAFile(), target.Host)
	if err != nil {
		t.Fatal(err)
	}
	target.TLS = config
	conn, _, keyData, _, _, err := dialTargetDbAuth(context.Background(), target)
	if err != nil {
		t.Fatalf("verify-full dial: %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(*tls.Conn); !ok {
		t.Fatalf("target conn = %T, want *tls.Conn", conn)
	}

	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(&pgproto3.Query{String: "SELECT pg_sleep(30)"})
	if err := frontend.Flush(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := sendCancelRequest(target, keyData.ProcessID, keyData.SecretKey); err != nil {
		t.Fatalf("CancelRequest over TLS: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		message, err := frontend.Receive()
		if err != nil {
			t.Fatalf("read after cancel: %v", err)
		}
		if e, ok := message.(*pgproto3.ErrorResponse); ok {
			if e.Code != "57014" {
				t.Fatalf("pg_sleep failed with %s %s, want 57014 query_canceled", e.Code, e.Message)
			}
			return
		}
		if _, ok := message.(*pgproto3.ReadyForQuery); ok {
			t.Fatal("pg_sleep finished without being canceled")
		}
	}
}

func TestTargetDbTLSRejectsHostnameMismatch(t *testing.T) {
	target := tlsOnlyTarget(t, nil)
	config, err := targettls.Config(targettls.VerifyFull, dbtest.TLSCAFile(), "not-the-san.example")
	if err != nil {
		t.Fatal(err)
	}
	target.TLS = config
	_, _, _, _, _, err = dialTargetDbAuth(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "not-the-san.example") {
		t.Fatalf("verify-full with a mismatched host = %v, want a hostname error", err)
	}
}

func TestTargetDbTLSRequire(t *testing.T) {
	target := tlsOnlyTarget(t, nil)
	config, err := targettls.Config(targettls.Require, "", target.Host)
	if err != nil {
		t.Fatal(err)
	}
	target.TLS = config
	conn, _, _, _, _, err := dialTargetDbAuth(context.Background(), target)
	if err != nil {
		t.Fatalf("require dial: %v", err)
	}
	conn.Close()
}

func TestTargetDbTLSPlaintextIsRefused(t *testing.T) {
	_, _, _, _, _, err := dialTargetDbAuth(context.Background(), tlsOnlyTarget(t, nil))
	if err == nil || !strings.Contains(err.Error(), "pg_hba.conf") {
		t.Fatalf("plaintext dial to a hostssl-only target = %v, want a pg_hba rejection", err)
	}
}

func TestTargetDbTLSRejectsUntrustedCertificate(t *testing.T) {
	target := tlsOnlyTarget(t, nil)
	config, err := targettls.Config(targettls.VerifyFull, "rds", target.Host)
	if err != nil {
		t.Fatal(err)
	}
	target.TLS = config
	_, _, _, _, _, err = dialTargetDbAuth(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("verify-full against the RDS bundle = %v, want a certificate error", err)
	}
}

func TestTargetDbTLSRefusedByPlaintextServer(t *testing.T) {
	db := dbtest.Postgres(t)
	target := spi.TargetDb{Host: db.Host, Port: db.Port, Db: db.DB, User: db.User, Password: db.Password, TLS: dbtest.VerifyFullTLS(t, db.Host)}
	_, _, _, _, _, err := dialTargetDbAuth(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "refused TLS") {
		t.Fatalf("TLS dial to a server without ssl = %v, want a refusal", err)
	}
}

// A Cloud SQL per-instance certificate names no DNS host, so verify-ca must pass on the chain alone.
func TestTargetDbTLSVerifyCAIgnoresHostname(t *testing.T) {
	target := tlsOnlyTarget(t, nil)
	config, err := targettls.Config(targettls.VerifyCA, dbtest.TLSCAFile(), "my-project:my-instance")
	if err != nil {
		t.Fatal(err)
	}
	target.TLS = config
	conn, _, _, _, _, err := dialTargetDbAuth(context.Background(), target)
	if err != nil {
		t.Fatalf("verify-ca dial: %v", err)
	}
	conn.Close()

	if target.TLS, err = targettls.Config(targettls.VerifyCA, dbtest.OtherCAFile(), target.Host); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err = dialTargetDbAuth(context.Background(), target); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("verify-ca with an unrelated CA = %v, want a certificate error", err)
	}
}
