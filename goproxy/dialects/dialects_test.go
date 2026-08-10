package dialects_test

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/db"
	"github.com/ridi-oss/proxy-monster/goproxy/dialects"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

func TestRegistryProviderContracts(t *testing.T) {
	registry := dialects.Registry()
	cases := []struct {
		name    string
		dialect engine.Dialect
		wantDb  engine.Db
	}{
		{"mysql", engine.MySQL, db.MySqlDb{}},
		{"postgres", engine.Postgres, db.PgDb{}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			provider, err := registry.For(test.dialect)
			if err != nil {
				t.Fatalf("For(%v): %v", test.dialect, err)
			}
			if provider.Dialect() != test.dialect {
				t.Errorf("Dialect() = %v, want %v", provider.Dialect(), test.dialect)
			}
			if got := provider.NewDb(); got != test.wantDb {
				t.Errorf("NewDb() = %#v, want %#v", got, test.wantDb)
			}
			server := provider.NewWireServer(0, spi.TargetDb{}, nil, provider.NewDb(), nil)
			switch test.dialect {
			case engine.MySQL:
				if reflect.TypeOf(server).String() != "*mysqlproxy.Server" {
					t.Errorf("NewWireServer() type = %T, want *mysqlproxy.Server", server)
				}
			case engine.Postgres:
				if reflect.TypeOf(server).String() != "*pgproxy.Server" {
					t.Errorf("NewWireServer() type = %T, want *pgproxy.Server", server)
				}
			}
		})
	}

	unknown, _ := engine.ParseDialect("oracle")
	if _, err := registry.For(unknown); err == nil {
		t.Fatal("For(oracle) = nil error without a registered provider")
	}
}

func TestRegistryProbeNamespaceDelegates(t *testing.T) {
	cases := []struct {
		name    string
		dialect engine.Dialect
		open    func(testing.TB, string) *sql.DB
		dbName  string
		assert  func(*testing.T, []string, *int32)
	}{
		{
			name: "mysql", dialect: engine.MySQL, open: dbtest.OpenMySQL, dbName: dbtest.MySQL(t).DB,
			assert: func(t *testing.T, schemas []string, mode *int32) {
				if len(schemas) != 1 || schemas[0] != dbtest.MySQL(t).DB || mode == nil {
					t.Fatalf("ProbeNamespace = %v/%v, want current database plus case mode", schemas, mode)
				}
			},
		},
		{
			name: "postgres", dialect: engine.Postgres, open: dbtest.OpenPostgres, dbName: dbtest.Postgres(t).DB,
			assert: func(t *testing.T, schemas []string, mode *int32) {
				if mode != nil || !contains(schemas, "public") || !contains(schemas, "pg_catalog") {
					t.Fatalf("ProbeNamespace = %v/%v, want PostgreSQL search path and nil case mode", schemas, mode)
				}
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			provider, _ := dialects.For(test.dialect)
			sqlDB := test.open(t, test.dbName)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := sqlDB.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			schemas, mode, err := provider.ProbeNamespace(conn, test.dbName)
			if err != nil {
				t.Fatalf("ProbeNamespace: %v", err)
			}
			test.assert(t, schemas, mode)
		})
	}
}

func TestNewWireServerStartsExpectedProtocol(t *testing.T) {
	for _, dialect := range []engine.Dialect{engine.MySQL, engine.Postgres} {
		t.Run(dialect.WireName(), func(t *testing.T) {
			provider, _ := dialects.For(dialect)
			server := provider.NewWireServer(0, spi.TargetDb{}, nil, provider.NewDb(), nil)
			starter, ok := server.(interface {
				Listen() error
				Serve() error
				Addr() net.Addr
			})
			if !ok {
				t.Fatalf("NewWireServer() type %T lacks testable listener contract", server)
			}
			if err := starter.Listen(); err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer server.Shutdown()
			go func() { _ = starter.Serve() }()
			conn, err := net.DialTimeout("tcp", starter.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 8)
			n, err := conn.Read(buf)
			if err != nil {
				var timeout net.Error
				if dialect != engine.Postgres || !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("read protocol greeting: %v", err)
				}
			}
			if dialect == engine.MySQL && n == 0 {
				t.Fatal("MySQL server sent no initial greeting")
			}
			if dialect == engine.Postgres && n != 0 {
				t.Fatalf("PostgreSQL server sent %d unsolicited greeting bytes", n)
			}
		})
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
