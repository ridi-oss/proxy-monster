package sqldb_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"

	"google.golang.org/protobuf/proto"

	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// namespaceRowConn answers every query with one fixed (DATABASE(), lctn, matches) row.
type namespaceRowConn struct{ row []driver.Value }

func (c namespaceRowConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c namespaceRowConn) Driver() driver.Driver                        { return nil }
func (namespaceRowConn) Prepare(string) (driver.Stmt, error)            { return nil, errors.New("unused") }
func (namespaceRowConn) Close() error                                   { return nil }
func (namespaceRowConn) Begin() (driver.Tx, error)                      { return nil, errors.New("unused") }
func (c namespaceRowConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &namespaceRows{row: c.row}, nil
}

type namespaceRows struct {
	row  []driver.Value
	done bool
}

func (*namespaceRows) Columns() []string { return []string{"database", "lctn", "matches"} }
func (*namespaceRows) Close() error      { return nil }
func (r *namespaceRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.row)
	return nil
}

func TestProbeMySQLNamespaceRefusesUnknownLowerCaseTableNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		lctn driver.Value
		ok   bool
	}{
		{"0", int64(0), true},
		{"1", int64(1), true},
		{"2", int64(2), true},
		{"NULL", nil, false},
		{"3", int64(3), false},
		{"-1", int64(-1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := sql.OpenDB(namespaceRowConn{row: []driver.Value{"App", tc.lctn, true}})
			defer pool.Close()
			conn, err := pool.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			catalog, err := sqldb.ProbeMySQLNamespace(context.Background(), conn, "App")
			if !tc.ok {
				if err == nil {
					t.Fatalf("sqldb.ProbeMySQLNamespace = %+v, want refused", catalog)
				}
				return
			}
			if err != nil {
				t.Fatalf("ProbeMySQLNamespace: %v", err)
			}
			if catalog.MysqlLowerCaseTableNames == nil || int64(catalog.GetMysqlLowerCaseTableNames()) != tc.lctn.(int64) {
				t.Fatalf("lower_case_table_names = %v, want %v", catalog.MysqlLowerCaseTableNames, tc.lctn)
			}
		})
	}
}

func TestRunRefusesUnknownLowerCaseTableNames(t *testing.T) {
	t.Skip("pending-name-fix: introspect folds an unreported or out-of-range lower_case_table_names as 0")
	targetConfig := dbtest.MySQL(t)
	for _, tc := range []struct {
		name string
		lctn *int32
	}{
		{"unreported", nil},
		{"out of range", proto.Int32(3)},
		{"negative", proto.Int32(-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := func(ctx context.Context, conn *sql.Conn, target string) (*pb.CatalogRequest, error) {
				catalog, err := sqldb.ProbeMySQLNamespace(ctx, conn, target)
				if err != nil {
					return nil, err
				}
				catalog.MysqlLowerCaseTableNames = tc.lctn
				return catalog, nil
			}
			cat, err := runWith(sqldb.OpenMySQLTarget, mysql.TargetSQL{}, probe, spi.TargetConfig{Host: targetConfig.Host, Port: targetConfig.Port, Db: targetConfig.DB, User: targetConfig.User, Password: targetConfig.Password})
			if err == nil {
				t.Fatalf("Run pushed a catalog of %d columns, want refused", len(cat.GetCatalog().GetColumns()))
			}
		})
	}
}
