// Package targettest holds helpers the MySQL and PostgreSQL target tests share.
package targettest

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
	"google.golang.org/protobuf/proto"
)

func EqualColumns(left, right []*analyzerpb.Column) bool {
	return slices.EqualFunc(left, right, func(a, b *analyzerpb.Column) bool { return proto.Equal(a, b) })
}

// InCatalog returns columns stamped with the catalog the connection under test measures.
func InCatalog(catalog string, columns []*analyzerpb.Column) []*analyzerpb.Column {
	out := make([]*analyzerpb.Column, len(columns))
	for i, column := range columns {
		out[i] = proto.Clone(column).(*analyzerpb.Column)
		out[i].Catalog = catalog
	}
	return out
}

func Ptr(value string) *string { return &value }

func Rows(values ...string) [][]*string {
	row := make([]*string, len(values))
	for i := range values {
		row[i] = Ptr(values[i])
	}
	return [][]*string{row}
}

const HashTestTimeout = 30 * time.Second

var hashFixtureCounter atomic.Uint64

func UniqueFixtureName(prefix string) string {
	return fmt.Sprintf("%s_%d_%d", prefix, os.Getpid(), hashFixtureCounter.Add(1))
}

func QueryStrings(conn *sql.Conn, statement string, expectedColumns int) ([][]*string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), HashTestTimeout)
	defer cancel()
	rows, err := conn.QueryContext(ctx, statement)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columnNames, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if len(columnNames) != expectedColumns {
		return nil, fmt.Errorf("query returned %d columns, want %d", len(columnNames), expectedColumns)
	}
	var result [][]*string
	for rows.Next() {
		values := make([]sql.NullString, expectedColumns)
		destinations := make([]any, expectedColumns)
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, err
		}
		row := make([]*string, expectedColumns)
		for i := range values {
			if values[i].Valid {
				value := values[i].String
				row[i] = &value
			}
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func IntrospectTarget(t *testing.T, open func(spi.TargetConfig) (*sql.DB, error), queries sqldb.Queries, probe sqldb.NamespaceProbe, targetConfig dbtest.TargetDb, database string) *pb.CatalogRequest {
	t.Helper()
	pool, err := open(spi.TargetConfig{Host: targetConfig.Host, Port: targetConfig.Port, Db: database, User: targetConfig.User, Password: targetConfig.Password})
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	defer pool.Close()
	catalog, err := sqldb.Introspect(context.Background(), pool, queries, probe, database)
	if err != nil {
		t.Fatalf("sqldb.Introspect(%q): %v", database, err)
	}
	return catalog
}

func PinConn(t *testing.T, database *sql.DB) *sql.Conn {
	t.Helper()
	conn, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("pin connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// RelationKey is a column's schema, table and column.
type RelationKey [3]string

func RelationKeys(columns []*analyzerpb.Column, schema string) []RelationKey {
	var keys []RelationKey
	for _, c := range columns {
		if c.GetSchema() == schema {
			keys = append(keys, RelationKey{c.GetSchema(), c.GetTable(), c.GetColumn()})
		}
	}
	slices.SortFunc(keys, func(a, b RelationKey) int {
		return cmp.Or(cmp.Compare(a[1], b[1]), cmp.Compare(a[2], b[2]))
	})
	return keys
}

func SchemaColumns(columns []*analyzerpb.Column, schema string) []*analyzerpb.Column {
	var out []*analyzerpb.Column
	for _, c := range columns {
		if c.GetSchema() == schema {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b *analyzerpb.Column) int {
		return cmp.Or(cmp.Compare(a.GetTable(), b.GetTable()), cmp.Compare(a.GetOrdinal(), b.GetOrdinal()), cmp.Compare(a.GetColumn(), b.GetColumn()))
	})
	return out
}

// AssertFragmentMatchesBulk requires a refetch of schema to equal the bulk catalog, and its hash to be stable.
func AssertFragmentMatchesBulk(t *testing.T, queries sqldb.Queries, conn *sql.Conn, catalog string, bulk *pb.CatalogRequest, schema string) {
	t.Helper()
	want := SchemaColumns(bulk.GetCatalog().GetColumns(), schema)
	if len(want) == 0 {
		t.Fatalf("bulk catalog has no columns under schema %q", schema)
	}
	push := RunRefetchIntegration(t, queries, conn, catalog, schema, nil)
	if got := SchemaColumns(push.GetColumns(), schema); !EqualColumns(got, want) || len(push.GetColumns()) != len(want) {
		t.Fatalf("refetch %q columns = %+v\nwant bulk %+v", schema, push.GetColumns(), want)
	}
	again := RunRefetchIntegration(t, queries, conn, catalog, schema, push.GetContentHash())
	if !again.GetUnchanged() || !bytes.Equal(again.GetContentHash(), push.GetContentHash()) {
		t.Fatalf("refetch %q with its own hash = %+v, want unchanged", schema, again)
	}
}

func TrustedRefetchHash(t *testing.T, queries sqldb.Queries, conn *sql.Conn, schema string) []byte {
	t.Helper()
	var setupRows [][]*string
	if setupSQL := queries.HashSetupProbe; setupSQL != "" {
		rows, err := QueryStrings(conn, setupSQL, queries.HashSetupColumns)
		if err != nil {
			t.Fatalf("hash setup probe: %v", err)
		}
		setupRows = rows
	}
	hashSQL, columns, err := queries.SchemaHash(schema, setupRows)
	if err != nil {
		t.Fatalf("SchemaHashSQL(%q): %v", schema, err)
	}
	rows, err := QueryStrings(conn, hashSQL, columns)
	if err != nil {
		t.Fatalf("hash query for %q: %v\n%s", schema, err, hashSQL)
	}
	hash, trusted, err := queries.SchemaHashFromRows(rows)
	if err != nil || !trusted {
		t.Fatalf("hash for %q = %x, trusted=%v, err=%v, rows=%#v", schema, hash, trusted, err, rows)
	}
	return hash
}

func RunRefetchIntegration(t *testing.T, queries sqldb.Queries, conn *sql.Conn, catalog, schema string, ifHashDiffers []byte) *pb.SchemaFragmentPush {
	t.Helper()
	connectionID := []byte("refetch-test-connection")
	const generation = uint64(41)
	var pushes []*pb.SchemaFragmentPush
	commandRunner := sqldb.ProxyCommandRunner{
		Catalog:           catalog,
		Queries:           queries,
		ConnectionID:      connectionID,
		BackendGeneration: generation,
		Probe: func(statement string, expectedColumns int) ([][]*string, error) {
			return QueryStrings(conn, statement, expectedColumns)
		},
		Push: func(push *pb.SchemaFragmentPush) (uint64, error) {
			pushes = append(pushes, push)
			return uint64(len(pushes)), nil
		},
	}
	if err := commandRunner.Refetch(&pb.Refetch{Catalog: catalog, Schema: schema, IfHashDiffers: ifHashDiffers}); err != nil {
		t.Fatalf("ProxyCommandRunner.Refetch(%q): %v", schema, err)
	}
	if len(pushes) != 1 {
		t.Fatalf("push count = %d, want exactly 1", len(pushes))
	}
	push := pushes[0]
	if !bytes.Equal(push.ConnectionId, connectionID) || push.Schema != schema || push.BackendGeneration != generation {
		t.Fatalf("push identity = %+v, want connection/schema/generation preserved", push)
	}
	return push
}

func AssertFullRefetch(t *testing.T, push *pb.SchemaFragmentPush, currentHash []byte, catalog string, wantColumns []*analyzerpb.Column, wantRoutines []string) {
	t.Helper()
	if push.Unchanged {
		t.Fatalf("push = %+v, want full fetch", push)
	}
	if !bytes.Equal(push.ContentHash, currentHash) {
		t.Fatalf("push hash = %x, want new trusted hash %x", push.ContentHash, currentHash)
	}
	if want := InCatalog(catalog, wantColumns); !EqualColumns(push.Columns, want) {
		t.Fatalf("push columns = %+v, want %+v", push.Columns, want)
	}
	if !reflect.DeepEqual(push.Routines, wantRoutines) {
		t.Fatalf("push routines = %v, want %v", push.Routines, wantRoutines)
	}
}

func ExecRefetchSQL(t *testing.T, conn *sql.Conn, statement string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), HashTestTimeout)
	defer cancel()
	if _, err := conn.ExecContext(ctx, statement); err != nil {
		t.Fatalf("exec %q: %v", statement, err)
	}
}
