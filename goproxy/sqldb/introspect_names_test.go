package sqldb_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

// namespaceRowConn answers the target settings probe with settings and any other query with namespace, one row each.
type namespaceRowConn struct{ settings, namespace []driver.Value }

func (c namespaceRowConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c namespaceRowConn) Driver() driver.Driver                        { return nil }
func (namespaceRowConn) Prepare(string) (driver.Stmt, error)            { return nil, errors.New("unused") }
func (namespaceRowConn) Close() error                                   { return nil }
func (namespaceRowConn) Begin() (driver.Tx, error)                      { return nil, errors.New("unused") }
func (c namespaceRowConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "lower_case_table_names") {
		return &namespaceRows{row: c.settings}, nil
	}
	return &namespaceRows{row: c.namespace}, nil
}

type namespaceRows struct {
	row  []driver.Value
	done bool
}

func (r *namespaceRows) Columns() []string { return make([]string, len(r.row)) }
func (*namespaceRows) Close() error        { return nil }
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
			pool := sql.OpenDB(namespaceRowConn{settings: []driver.Value{"8.0.40", tc.lctn}, namespace: []driver.Value{"App", true}})
			defer pool.Close()
			conn, err := pool.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			session, err := sqldb.NewConnSession(context.Background(), conn, mysql.Queries)
			if !tc.ok {
				if err == nil {
					t.Fatal("NewConnSession succeeded, want refused")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewConnSession: %v", err)
			}
			catalog, err := mysql.ProbeNamespace(context.Background(), conn, "App", session)
			if err != nil {
				t.Fatalf("mysql.ProbeNamespace: %v", err)
			}
			if catalog.MysqlLowerCaseTableNames == nil || int64(catalog.GetMysqlLowerCaseTableNames()) != tc.lctn.(int64) {
				t.Fatalf("lower_case_table_names = %v, want %v", catalog.MysqlLowerCaseTableNames, tc.lctn)
			}
		})
	}
}

// reportingQueries is MySQL whose target reports lower_case_table_names as lctn.
func reportingQueries(lctn string) sqldb.Queries {
	queries := mysql.Queries
	queries.TargetSettingsProbe = "SELECT VERSION(), " + lctn
	return queries
}

func TestRunRefusesUnknownLowerCaseTableNames(t *testing.T) {
	targetConfig := dbtest.MySQL(t)
	for _, tc := range []struct{ name, lctn string }{
		{"unreported", "NULL"},
		{"out of range", "3"},
		{"negative", "-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cat, err := runWith(mysql.OpenPool, reportingQueries(tc.lctn), mysql.ProbeNamespace, spi.TargetConfig{Host: targetConfig.Host, Port: targetConfig.Port, Db: targetConfig.DB, User: targetConfig.User, Password: targetConfig.Password})
			if err == nil {
				t.Fatalf("sqldb.Introspect pushed a catalog of %d columns, want refused", len(cat.GetCatalog().GetColumns()))
			}
		})
	}
}
