package dialects_test

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/dialects"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

func TestRegistryProviderContracts(t *testing.T) {
	registry := dialects.Registry()
	for _, test := range []struct {
		name    string
		dialect engine.Dialect
		server  string
	}{
		{"mysql", engine.MySQL, "*mysqlproxy.Server"},
		{"postgres", engine.Postgres, "*pgproxy.Server"},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider, err := registry.For(test.dialect)
			if err != nil {
				t.Fatalf("For(%v): %v", test.dialect, err)
			}
			if provider.Dialect() != test.dialect {
				t.Errorf("Dialect() = %v, want %v", provider.Dialect(), test.dialect)
			}
			target := spi.TargetDb{Host: "target", Port: 1234, Db: "app", User: "service", Password: "secret"}
			targetDb, err := provider.NewDb(target)
			if err != nil {
				t.Fatalf("NewDb: %v", err)
			}
			defer targetDb.Close()
			if targetDb.TargetDb() != target {
				t.Fatalf("TargetDb() = %+v, want %+v", targetDb.TargetDb(), target)
			}
			server := targetDb.NewWireServer(0, nil, nil)
			if reflect.TypeOf(server).String() != test.server {
				t.Errorf("NewWireServer() type = %T, want %s", server, test.server)
			}
		})
	}

	unknown, _ := engine.ParseDialect("oracle")
	if _, err := registry.For(unknown); err == nil {
		t.Fatal("For(oracle) = nil error without a registered provider")
	}
}

func TestRegistryIntrospectDelegates(t *testing.T) {
	for _, test := range []struct {
		name    string
		dialect engine.Dialect
		target  dbtest.TargetDb
		assert  func(*testing.T, *pb.CatalogRequest)
	}{
		{
			name: "mysql", dialect: engine.MySQL, target: dbtest.MySQL(t),
			assert: func(t *testing.T, catalog *pb.CatalogRequest) {
				if len(catalog.DefaultSchemas) != 1 || catalog.DefaultSchemas[0] != dbtest.MySQL(t).DB || catalog.MysqlLowerCaseTableNames == nil {
					t.Fatalf("Introspect = %v/%v, want current database plus case mode", catalog.DefaultSchemas, catalog.MysqlLowerCaseTableNames)
				}
			},
		},
		{
			name: "postgres", dialect: engine.Postgres, target: dbtest.Postgres(t),
			assert: func(t *testing.T, catalog *pb.CatalogRequest) {
				if catalog.MysqlLowerCaseTableNames != nil || !contains(catalog.DefaultSchemas, "public") || !contains(catalog.DefaultSchemas, "pg_catalog") {
					t.Fatalf("Introspect = %v/%v, want PostgreSQL search path and nil case mode", catalog.DefaultSchemas, catalog.MysqlLowerCaseTableNames)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider, _ := dialects.For(test.dialect)
			targetDb, err := provider.NewDb(spi.TargetDb{Host: test.target.Host, Port: test.target.Port, Db: test.target.DB, User: test.target.User, Password: test.target.Password})
			if err != nil {
				t.Fatal(err)
			}
			defer targetDb.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			catalog, err := targetDb.Introspect(ctx)
			if err != nil {
				t.Fatalf("Introspect: %v", err)
			}
			test.assert(t, catalog)
		})
	}
}

func TestNewWireServerStartsExpectedProtocol(t *testing.T) {
	for _, dialect := range []engine.Dialect{engine.MySQL, engine.Postgres} {
		t.Run(dialect.WireName(), func(t *testing.T) {
			provider, _ := dialects.For(dialect)
			targetDb, err := provider.NewDb(spi.TargetDb{})
			if err != nil {
				t.Fatal(err)
			}
			defer targetDb.Close()
			server := targetDb.NewWireServer(0, nil, nil)
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
