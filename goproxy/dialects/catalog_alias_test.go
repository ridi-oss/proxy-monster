package dialects_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqltarget"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type aliasControlPlane struct {
	pb.UnimplementedControlPlaneServer
	catalog, schema      string
	mu                   sync.Mutex
	decisions, fragments int
}

func (c *aliasControlPlane) refetch() *pb.Refetch {
	return &pb.Refetch{Catalog: proto.String(c.catalog), Schema: c.schema}
}

func (c *aliasControlPlane) ValidateToken(context.Context, *pb.ValidateTokenRequest) (*pb.WireIdentity, error) {
	return &pb.WireIdentity{Principal: "reader", ConnectionId: []byte("alias-wire-00001"), OnOpen: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: c.refetch()}}}}, nil
}

func (c *aliasControlPlane) Decide(_ context.Context, request *pb.DecisionRequest) (*pb.WireDecision, error) {
	if request.CurrentCatalog == nil || request.GetCurrentCatalog() != c.catalog {
		return nil, status.Errorf(codes.FailedPrecondition, "catalog %q, want measured %q", request.GetCurrentCatalog(), c.catalog)
	}
	for _, column := range request.TempColumns {
		if column.GetCatalog() != c.catalog {
			return nil, status.Error(codes.FailedPrecondition, "temp catalog is not measured")
		}
	}
	c.mu.Lock()
	c.decisions++
	c.mu.Unlock()
	return &pb.WireDecision{Outcome: &pb.WireDecision_Verdict{Verdict: &pb.Verdict{Decision: pb.EnfAction_ALLOW}}}, nil
}

func (c *aliasControlPlane) PushSchemaFragment(_ context.Context, fragment *pb.SchemaFragmentPush) (*pb.SchemaFragmentAck, error) {
	if fragment.Catalog == nil || fragment.GetCatalog() != c.catalog || fragment.GetSchema() != c.schema || len(fragment.Columns) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "fragment does not match measured catalog")
	}
	for _, column := range fragment.Columns {
		if column.GetCatalog() != c.catalog {
			return nil, status.Error(codes.FailedPrecondition, "fragment column catalog is not measured")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fragments++
	return &pb.SchemaFragmentAck{Generation: uint64(c.fragments)}, nil
}

func (*aliasControlPlane) CloseConnection(context.Context, *pb.CloseConnectionRequest) (*pb.CloseConnectionResponse, error) {
	return &pb.CloseConnectionResponse{}, nil
}

func (*aliasControlPlane) ReportCompletion(context.Context, *pb.CompletionReport) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func TestPostgresCatalogThroughDatabaseAlias(t *testing.T) {
	// The catalog read includes the function inventory, which takes tens of seconds on a CI runner.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	database := dbtest.Postgres(t)
	seed := dbtest.OpenPostgres(t, "")
	schema := fmt.Sprintf("alias_catalog_%d", time.Now().UnixNano())
	if _, err := seed.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := seed.Exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			t.Error(err)
		}
	})
	for _, statement := range []string{
		"CREATE TABLE " + schema + ".parent (id INT PRIMARY KEY)",
		"CREATE TABLE " + schema + ".child (id INT REFERENCES " + schema + ".parent(id))",
	} {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	gateway, rewritten := dbtest.PostgresAlias(t, database, "advisory")
	target := configuredTarget(t, "postgres", sqltarget.Config{Host: gateway.Host, Port: gateway.Port, Db: gateway.DB, User: gateway.User, Password: gateway.Password})
	catalog, err := target.ReadCatalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	measured := catalog.GetCurrentCatalog()
	if measured != database.DB || measured == target.TargetInfo().Database {
		t.Fatalf("measured/advisory catalog = %q/%q, want %q/advisory", measured, target.TargetInfo().Database, database.DB)
	}
	for _, column := range catalog.GetCatalog().GetColumns() {
		if column.GetCatalog() != measured {
			t.Fatalf("ambient column = %v", column)
		}
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	control := &aliasControlPlane{catalog: measured, schema: schema}
	grpcServer := grpc.NewServer()
	pb.RegisterControlPlaneServer(grpcServer, control)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	client, err := cp.New(listener.Addr().String(), "test-secret", "alias-datasource")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	t.Run("table detail", func(t *testing.T) {
		detail, err := target.ReadTableDetail(ctx, &enginepb.TableRef{Catalog: measured, Schema: schema, Table: "child"})
		if err != nil {
			t.Fatal(err)
		}
		if detail == nil || detail.Catalog == nil || *detail.Catalog != measured || len(detail.ForeignKeys) != 1 {
			t.Fatalf("detail = %+v", detail)
		}
		relation := detail.ForeignKeys[0]
		if relation.SourceCatalog == nil || *relation.SourceCatalog != measured || relation.TargetCatalog == nil || *relation.TargetCatalog != measured {
			t.Fatalf("relation = %+v", relation)
		}
		if _, err := target.ReadTableDetail(ctx, &enginepb.TableRef{Catalog: "advisory", Schema: schema, Table: "child"}); err == nil {
			t.Fatal("advisory alias was accepted as a measured table catalog")
		}
	})

	t.Run("native session", func(t *testing.T) {
		server := target.NewNativeServer(spi.NativeServerOptions{Client: client})
		listener := server.(interface {
			Listen() error
			Serve() error
			Addr() net.Addr
		})
		if err := listener.Listen(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { defer close(done); _ = listener.Serve() }()
		t.Cleanup(func() { server.Shutdown(); <-done })
		config, err := pgx.ParseConfig("postgres://reader:test-token@" + listener.Addr().String() + "/advisory?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.Close(context.Background()) })
		for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeSimpleProtocol, pgx.QueryExecModeExec} {
			var current string
			if err := connection.QueryRow(ctx, "SELECT current_database()", mode).Scan(&current); err != nil {
				t.Fatal(err)
			}
			if current != measured {
				t.Fatalf("native catalog = %q, want %q", current, measured)
			}
		}
	})

	t.Run("run session", func(t *testing.T) {
		session, err := target.NewRunSession(ctx, spi.RunSessionOptions{Client: client, Token: "test-token", ConnectionID: []byte("alias-run-000001"), ReadTimeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if err := session.OnOpen(ctx, []*pb.Refetch{control.refetch()}); err != nil {
			t.Fatal(err)
		}
		result, err := session.ServeStatement("SELECT current_database()", 20)
		if err != nil {
			t.Fatal(err)
		}
		if result.Denied || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] == nil || *result.Rows[0][0] != measured {
			t.Fatalf("run result = %+v", result)
		}
	})
	control.mu.Lock()
	decisions, fragments := control.decisions, control.fragments
	control.mu.Unlock()
	if decisions == 0 || fragments == 0 || rewritten.Load() == 0 {
		t.Fatalf("alias coverage: decisions=%d fragments=%d startups=%d", decisions, fragments, rewritten.Load())
	}
	t.Logf("measured=%s advisory=%s decisions=%d fragments=%d rewritten_startups=%d", measured, gateway.DB, decisions, fragments, rewritten.Load())
}
