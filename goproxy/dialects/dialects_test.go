package dialects_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/dialects"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqltarget"
)

func configuredTarget(t *testing.T, name string, config sqltarget.Config) spi.Target {
	t.Helper()
	provider, err := dialects.Registry().For(name)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"PM_TARGET_HOST": config.Host, "PM_TARGET_PORT": fmt.Sprint(config.Port), "PM_TARGET_DB": config.Db, "PM_TARGET_USER": config.User, "PM_TARGET_PASSWORD": config.Password}
	target, err := provider.Configure(func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	return target
}

func TestRegistryProviderContracts(t *testing.T) {
	for _, test := range []struct {
		name, server string
		dialect      engine.Dialect
	}{
		{"mysql", "*mysqlproxy.Server", engine.MySQL},
		{"postgres", "*pgproxy.Server", engine.Postgres},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider, err := dialects.Registry().For(test.name)
			if err != nil {
				t.Fatal(err)
			}
			if definition := provider.Definition(); definition.Name != test.name || definition.Engine != test.dialect.Proto() {
				t.Fatalf("Definition = %+v", definition)
			}
			config := sqltarget.Config{Host: "target", Port: 1234, Db: "app", User: "service", Password: "secret"}
			target := configuredTarget(t, test.name, config)
			if info := target.TargetInfo(); info != (spi.TargetInfo{Host: "target", Port: 1234, Database: "app"}) {
				t.Fatalf("TargetInfo = %+v", info)
			}
			server := target.NewNativeServer(spi.NativeServerOptions{})
			if reflect.TypeOf(server).String() != test.server {
				t.Fatalf("NewNativeServer type = %T, want %s", server, test.server)
			}
		})
	}
	if _, err := dialects.Registry().For("oracle"); err == nil {
		t.Fatal("unregistered engine was accepted")
	}
}

func TestRegistryReadCatalog(t *testing.T) {
	for _, test := range []struct {
		name     string
		database func(testing.TB) dbtest.TargetDb
	}{
		{"mysql", dbtest.MySQL}, {"postgres", dbtest.Postgres},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := test.database(t)
			target := configuredTarget(t, test.name, sqltarget.Config{Host: database.Host, Port: database.Port, Db: database.DB, User: database.User, Password: database.Password})
			catalog, err := target.ReadCatalog(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(catalog.GetCatalog().GetColumns()) == 0 {
				t.Fatal("catalog contained no columns")
			}
			if test.name == "mysql" {
				if !reflect.DeepEqual(catalog.DefaultSchemas, []string{database.DB}) || catalog.MysqlLowerCaseTableNames == nil {
					t.Fatalf("MySQL namespace = %v/%v", catalog.DefaultSchemas, catalog.MysqlLowerCaseTableNames)
				}
			} else if catalog.MysqlLowerCaseTableNames != nil || !contains(catalog.DefaultSchemas, "public") || !contains(catalog.DefaultSchemas, "pg_catalog") {
				t.Fatalf("PostgreSQL namespace = %v/%v", catalog.DefaultSchemas, catalog.MysqlLowerCaseTableNames)
			}
		})
	}
}

func TestNewWireServerStartsExpectedProtocol(t *testing.T) {
	for _, dialect := range []engine.Dialect{engine.MySQL, engine.Postgres} {
		t.Run(dialect.WireName(), func(t *testing.T) {
			target := configuredTarget(t, dialect.WireName(), sqltarget.Config{})
			server := target.NewNativeServer(spi.NativeServerOptions{})
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

func TestProviderConfigureOwnsEnvironment(t *testing.T) {
	for _, test := range []struct {
		name string
		port int
	}{{"mysql", 3307}, {"postgres", 5433}} {
		t.Run(test.name, func(t *testing.T) {
			provider, err := dialects.Registry().For(test.name)
			if err != nil {
				t.Fatal(err)
			}
			for _, endpoint := range []string{"", "  proxy.example:6033  "} {
				values := map[string]string{"PM_ADVERTISE_ADDR": endpoint, "PM_TARGET_PASSWORD": "private-password"}
				target, err := provider.Configure(func(name string) (string, bool) { value, ok := values[name]; return value, ok })
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = target.Close() })
				if info := target.TargetInfo(); info != (spi.TargetInfo{Host: "localhost", Port: test.port, Database: "acme"}) {
					t.Fatalf("defaults = %+v", info)
				}
				info := target.ConnectionInfo()
				if info == nil || info.GetEndpoint() != strings.TrimSpace(endpoint) || len(info.GetProperties()) != 0 {
					t.Fatalf("connection info = %v", info)
				}
			}
		})
	}
}

func TestTargetMetadataHonorsCancellationAndClose(t *testing.T) {
	for _, name := range []string{"mysql", "postgres"} {
		t.Run(name, func(t *testing.T) {
			target := configuredTarget(t, name, sqltarget.Config{Host: "127.0.0.1", Port: 1, Db: "app"})
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := target.ReadCatalog(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled ReadCatalog = %v", err)
			}
			if _, err := target.ReadTableDetail(ctx, &enginepb.TableRef{Schema: "public", Table: "orders"}); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled ReadTableDetail = %v", err)
			}
			if err := target.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := target.ReadCatalog(context.Background()); err == nil {
				t.Fatal("ReadCatalog on a closed target succeeded")
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

func TestCatalogRefreshObservesNewConnectionDefaults(t *testing.T) {
	database := dbtest.Postgres(t)
	seed := dbtest.OpenPostgres(t, "")
	role := fmt.Sprintf("spi_defaults_%d", time.Now().UnixNano())
	if _, err := seed.Exec("CREATE ROLE " + role + " LOGIN PASSWORD 'test-secret'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := seed.Exec("DROP ROLE " + role); err != nil {
			t.Error(err)
		}
	})
	if _, err := seed.Exec("ALTER ROLE " + role + " SET search_path TO public"); err != nil {
		t.Fatal(err)
	}
	target := configuredTarget(t, "postgres", sqltarget.Config{Host: database.Host, Port: database.Port, Db: database.DB, User: role, Password: "test-secret"})
	first, err := target.ReadCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.GetCurrentCatalog() != database.DB || !contains(first.DefaultSchemas, "public") {
		t.Fatalf("initial catalog = %v/%v", first.CurrentCatalog, first.DefaultSchemas)
	}
	if _, err := seed.Exec("ALTER ROLE " + role + " SET search_path TO pg_catalog"); err != nil {
		t.Fatal(err)
	}
	second, err := target.ReadCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.GetCurrentCatalog() != database.DB || !reflect.DeepEqual(second.DefaultSchemas, []string{"pg_catalog"}) {
		t.Fatalf("refreshed catalog = %v/%v", second.CurrentCatalog, second.DefaultSchemas)
	}
}
