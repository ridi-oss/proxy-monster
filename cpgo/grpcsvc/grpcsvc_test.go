package grpcsvc

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
	"github.com/ridi-oss/proxy-monster/auditmon/verify"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/cpgo/internal/pb"
)

// kotlin stands in for the Kotlin control plane behind the front door.
type kotlin struct {
	pb.UnimplementedControlPlaneServer
}

func (kotlin) ValidateToken(context.Context, *pb.ValidateTokenRequest) (*pb.WireIdentity, error) {
	return &pb.WireIdentity{Principal: "from-kotlin"}, nil
}

func (kotlin) ReportCompletion(context.Context, *pb.CompletionReport) (*emptypb.Empty, error) {
	return nil, status.Error(codes.FailedPrecondition, "reached kotlin")
}

func serve(t *testing.T, s *grpc.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(s.Stop)
	return ln.Addr().String()
}

func setup(t *testing.T, secret string) (dbtest.Store, pb.ControlPlaneClient) {
	t.Helper()
	st := dbtest.Open(t)
	upstream := grpc.NewServer()
	pb.RegisterControlPlaneServer(upstream, kotlin{})
	up, err := front.DialUpstream(serve(t, upstream))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })
	fd := front.NewGRPC(up, grpc.UnaryInterceptor(SecretToken(secret)))
	Register(fd, st.Pool, authz.New(st.Pool))
	conn, err := grpc.NewClient(serve(t, fd), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return st, pb.NewControlPlaneClient(conn)
}

func decision(t *testing.T, st dbtest.Store) int64 {
	t.Helper()
	ctx := context.Background()
	channel := "wire"
	var id int64
	err := pgx.BeginFunc(ctx, st.Pool, func(tx pgx.Tx) (err error) {
		id, err = audit.Insert(ctx, tx, canon.AuditEvent{Kind: "decision", Principal: "analyst@example.com", Roles: []string{"analyst"},
			Datasource: "sales-mysql", Statement: "SELECT name FROM users", Decision: "ALLOW", Channel: &channel})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestReportCompletion(t *testing.T) {
	st, c := setup(t, "")
	ctx := context.Background()
	id := decision(t, st)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO datasource (name, host, port, db_name) VALUES ('sales-mysql', 'h', 1, 'd')`); err != nil {
		t.Fatal(err)
	}
	const wireTask = `INSERT INTO access_request (principal, kind, creator_kind, source_decision_id, status, datasource_id)
		SELECT 'analyst@example.com', 'QUERY', 'WIRE', $1, 'APPROVED', id FROM datasource RETURNING id`
	var task int64
	if err := st.Pool.QueryRow(ctx, wireTask, id).Scan(&task); err != nil {
		t.Fatal(err)
	}
	failed := decision(t, st)
	if _, err := st.Pool.Exec(ctx, wireTask, failed); err != nil {
		t.Fatal(err)
	}

	if _, err := c.ReportCompletion(ctx, &pb.CompletionReport{DecisionId: id, RowsReturned: 50000, BytesReturned: 262144, Status: "ok", DurationMs: 12}); err != nil {
		t.Fatal(err)
	}
	var row string
	if err := st.Pool.QueryRow(ctx, `SELECT principal||'|'||datasource||'|'||statement||'|'||decision||'|'||channel||'|'||rows_returned||'|'||
		bytes_returned||'|'||outcome||'|'||latency_ms||'|'||decision_id||'|'||roles::text FROM audit_event WHERE kind = 'completion'`).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if want := "analyst@example.com|sales-mysql|SELECT name FROM users|ALLOW|wire|50000|262144|ok|12|" + strconv.FormatInt(id, 10) + "|[]"; row != want {
		t.Fatalf("completion row %s, want %s", row, want)
	}
	var taskStatus string
	_ = st.Pool.QueryRow(ctx, `SELECT status FROM access_request WHERE id = $1 AND executing_at IS NOT NULL AND executed_at IS NOT NULL`, task).Scan(&taskStatus)
	if taskStatus != "EXECUTED" {
		t.Fatalf("wire task %q", taskStatus)
	}
	_ = st.Pool.QueryRow(ctx, `SELECT status FROM access_request WHERE source_decision_id = $1`, failed).Scan(&taskStatus)
	if taskStatus != "APPROVED" {
		t.Fatalf("another decision's wire task %q", taskStatus)
	}
	if _, err := c.ReportCompletion(ctx, &pb.CompletionReport{DecisionId: id, Status: "error"}); err != nil {
		t.Fatalf("a repeated report still records its completion: %v", err)
	}
	_ = st.Pool.QueryRow(ctx, `SELECT status FROM access_request WHERE id = $1`, task).Scan(&taskStatus)
	if taskStatus != "EXECUTED" {
		t.Fatalf("a repeated report moved the wire task to %q", taskStatus)
	}
	canceled := decision(t, st)
	if _, err := st.Pool.Exec(ctx, wireTask, canceled); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		decision int64
		status   string
	}{{failed, "error"}, {canceled, "canceled"}} {
		if _, err := c.ReportCompletion(ctx, &pb.CompletionReport{DecisionId: r.decision, Status: r.status}); err != nil {
			t.Fatal(err)
		}
		_ = st.Pool.QueryRow(ctx, `SELECT status FROM access_request WHERE source_decision_id = $1
			AND executing_at IS NOT NULL AND executed_at IS NULL`, r.decision).Scan(&taskStatus)
		if taskStatus != "FAILED" {
			t.Fatalf("a %s report left its wire task %q", r.status, taskStatus)
		}
	}

	for _, tc := range []struct {
		r    *pb.CompletionReport
		code codes.Code
	}{
		{&pb.CompletionReport{Status: "ok"}, codes.InvalidArgument},
		{&pb.CompletionReport{DecisionId: id, Status: "done"}, codes.InvalidArgument},
		{&pb.CompletionReport{DecisionId: 99999, Status: "ok"}, codes.NotFound},
	} {
		if _, err := c.ReportCompletion(ctx, tc.r); status.Code(err) != tc.code {
			t.Errorf("%v: %v, want %v", tc.r, err, tc.code)
		}
	}
	var n int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE kind = 'completion'`).Scan(&n)
	if n != 4 {
		t.Fatalf("%d completion rows", n)
	}
	dsn := strings.Replace(strings.TrimPrefix(st.JDBCURL, "jdbc:"), "postgresql://", "postgresql://"+st.User+":"+st.Password+"@", 1)
	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if finding, err := verify.VerifyFromGenesis(ctx, reader, canon.GenesisHash(), nil); err != nil || finding != nil {
		t.Fatalf("chain: %+v %v", finding, err)
	}

	if r, err := c.ValidateToken(ctx, &pb.ValidateTokenRequest{}); err != nil || r.GetPrincipal() != "from-kotlin" {
		t.Fatalf("a method Go does not serve must reach Kotlin: %v %v", r, err)
	}
}

func TestSecretToken(t *testing.T) {
	st, c := setup(t, "s3cret")
	ctx := context.Background()
	id := decision(t, st)
	report := &pb.CompletionReport{DecisionId: id, Status: "ok"}
	if _, err := c.ReportCompletion(ctx, report); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no token: %v", err)
	}
	if _, err := c.ReportCompletion(metadata.AppendToOutgoingContext(ctx, "x-pm-secret-token", "nope"), report); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong token: %v", err)
	}
	if _, err := c.ReportCompletion(metadata.AppendToOutgoingContext(ctx, "x-pm-secret-token", "s3cret"), report); err != nil {
		t.Fatalf("right token: %v", err)
	}
	var completions, tasks int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE kind = 'completion' AND decision_id = $1 AND outcome = 'ok'),
		(SELECT count(*) FROM access_request) FROM audit_event`, id).Scan(&completions, &tasks)
	if completions != 1 || tasks != 0 {
		t.Fatalf("a decision without a wire task: %d completions, %d tasks", completions, tasks)
	}
}
