package core_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
)

// The Go form of support/PerConnectionCatalogFixture.kt (120 LOC) — "test helper that turns the
// fixture's real target-introspected rows into immutable connection fragments".
//
// internal/dbtest/doc.go recorded it as "PerConnectionCatalogFixture.kt TODO(A5) — needs
// ConnectionCatalog, which is not ported yet". ConnectionCatalog IS ported now
// (internal/datasource/connectioncatalog.go) and so is DecideConnection (internal/core), so this is
// that fixture.
//
// 🔴 `package core_test`, not `package core`, for the reason internal/datasource's route fixture states:
// internal/dbtest imports internal/query and internal/datasource, and internal/core imports all three,
// so an INTERNAL core test could not import dbtest. An external test package can.

type perConnCatalogFixture struct {
	t           testing.TB
	enforcement *dbtest.EnforcementFixture
	core        *core.ControlPlaneCore
	datasource  datasource.Datasource
}

func newPerConnCatalogFixture(t *testing.T, engine string) *perConnCatalogFixture {
	t.Helper()
	fx := dbtest.NewEnforcementFixture(t, engine)
	c, err := core.New(fx.Store, core.Options{})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	// The Kotlin re-reads the datasource through the CORE's own store, not the enforcement fixture's,
	// because that is the row decideConnection is handed.
	ds, found, err := c.DatasourceStore.Get(context.Background(), fx.DatasourceID)
	if err != nil || !found {
		t.Fatalf("core store Get(%d) = found %v, err %v", fx.DatasourceID, found, err)
	}
	return &perConnCatalogFixture{t: t, enforcement: fx, core: c, datasource: ds}
}

// open is `core.connectionCatalog.open(Binding(name, principal, "USER"), schemas)`.
func (f *perConnCatalogFixture) open(principal string, schemas ...string) datasource.OpenConnection {
	f.t.Helper()
	return f.core.ConnectionCatalog.Open(
		datasource.Binding{DatasourceName: f.datasource.Name, Principal: principal, TokenKind: "USER"},
		schemas, false,
	)
}

// openAndPush is the Kotlin `openAndPush`: open, then push each schema's fragment built from the
// GLOBAL catalog rows (the path a sibling test's DELETE can empty).
func (f *perConnCatalogFixture) openAndPush(principal string, schemas ...string) datasource.OpenConnection {
	f.t.Helper()
	opened := f.open(principal, schemas...)
	rows, err := f.core.DatasourceStore.Catalog(context.Background(), f.datasource.ID)
	if err != nil {
		f.t.Fatalf("read the global catalog: %v", err)
	}
	for _, schema := range distinct(schemas) {
		var fragment []datasource.FragmentColumn
		for _, row := range rows {
			if row.Schema != schema {
				continue
			}
			fragment = append(fragment, datasource.FragmentColumn{
				Schema: row.Schema, Table: row.Table, Column: row.Column,
				DataType: row.SQLType, Ordinal: row.Ordinal, Nullable: row.Nullable,
			})
		}
		f.push(opened.ConnectionID, schema, fragment, 1, false)
	}
	return opened
}

// pushFromTarget scans one schema through the CALLER-OWNED backend connection.
//
// The Kotlin's comment is the whole point of taking the connection as a parameter: "This intentionally
// observes that connection's transaction-local DDL rather than opening a fresh connection or copying
// metadata rows."
func (f *perConnCatalogFixture) pushFromTarget(
	target *sql.Conn, connectionID datasource.ConnectionID, schema string,
) {
	f.t.Helper()
	const columnSQL = `SELECT table_schema, table_name, column_name, data_type, ordinal_position, is_nullable
		FROM information_schema.columns
		WHERE table_schema = ?
		ORDER BY table_schema, table_name, ordinal_position`
	q := columnSQL
	if f.enforcement.Engine == dbtest.EnginePostgres {
		q = replacePlaceholder(columnSQL)
	}
	rows, err := target.QueryContext(context.Background(), q, schema)
	if err != nil {
		f.t.Fatalf("introspect %s: %v", schema, err)
	}
	defer rows.Close()

	var fragment []datasource.FragmentColumn
	for rows.Next() {
		var sch, table, column, dataType, nullable string
		var ordinal int32
		if err := rows.Scan(&sch, &table, &column, &dataType, &ordinal, &nullable); err != nil {
			f.t.Fatalf("scan an information_schema row: %v", err)
		}
		fragment = append(fragment, datasource.FragmentColumn{
			Schema: sch, Table: table, Column: column,
			DataType: datasource.SQLTypeFor(dataType), Ordinal: ordinal, Nullable: nullable == "YES",
		})
	}
	if err := rows.Err(); err != nil {
		f.t.Fatalf("iterate information_schema: %v", err)
	}
	f.push(connectionID, schema, fragment, 1, false)
}

func (f *perConnCatalogFixture) push(
	connectionID datasource.ConnectionID, schema string,
	fragment []datasource.FragmentColumn, backendGeneration int64, unchanged bool,
) {
	f.t.Helper()
	push := &pb.SchemaFragmentPush{
		ConnectionId:      connectionID.Bytes(),
		DatasourceName:    f.datasource.Name,
		Schema:            schema,
		ContentHash:       fragmentHash(fragment),
		Unchanged:         unchanged,
		BackendGeneration: uint64(backendGeneration),
	}
	if !unchanged {
		for _, row := range fragment {
			push.Columns = append(push.Columns, &pb.Column{
				Schema: row.Schema, Table: row.Table, Column: row.Column,
				DataType: row.DataType, Ordinal: row.Ordinal, Nullable: row.Nullable,
			})
		}
	}
	result := f.core.ConnectionCatalog.ApplyPush(push, f.datasource)
	if _, applied := result.(datasource.Applied); !applied {
		f.t.Fatalf("fixture fragment push rejected: %#v", result)
	}
}

// decide is the Kotlin contract's `decide(...)`: the WIRE channel, no client address, and a fatal on
// found=false ("connection disappeared during decision").
func (f *perConnCatalogFixture) decide(
	opened datasource.OpenConnection, principal, sql string, schemas []string, ansiQuotes bool,
) core.EnforcementOutcome {
	f.t.Helper()
	outcome, found, err := f.core.DecideConnection(context.Background(), core.DecideConnectionInput{
		ConnectionID: opened.ConnectionID,
		Principal:    principal,
		Datasource:   f.datasource,
		SQL:          sql,
		SearchPath:   schemas,
		AnsiQuotes:   ansiQuotes,
		Channel:      query.ChannelWire,
	})
	if err != nil {
		f.t.Fatalf("DecideConnection: %v", err)
	}
	if !found {
		f.t.Fatal("connection disappeared during decision")
	}
	return outcome
}

// fragmentHash is the Kotlin fixture's `hash(rows)`: a SHA-256 over Java DataOutputStream's writeUTF /
// writeInt / writeBoolean encoding of every field, in order.
//
// The ENCODING has to match the Kotlin's, not just be some hash, because the same fragment content must
// produce the same PoolKey on both sides — INV-A5-38's cross-datasource system-fragment dedup keys on
// it. writeUTF is a big-endian uint16 length followed by the modified-UTF-8 bytes, which for the ASCII
// identifiers here is the plain bytes.
func fragmentHash(rows []datasource.FragmentColumn) []byte {
	var buf bytes.Buffer
	writeUTF := func(s string) {
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(s)))
		buf.WriteString(s)
	}
	for _, row := range rows {
		writeUTF(row.Schema)
		writeUTF(row.Table)
		writeUTF(row.Column)
		writeUTF(row.DataType)
		_ = binary.Write(&buf, binary.BigEndian, row.Ordinal)
		if row.Nullable {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
	}
	sum := sha256.Sum256(buf.Bytes())
	return sum[:]
}

func distinct(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// replacePlaceholder turns the one `?` into pgx's `$1`. The Kotlin uses JDBC, whose placeholder is `?`
// for both engines; Go's two drivers do not agree, so the one query above is rewritten rather than
// duplicated.
func replacePlaceholder(q string) string {
	out := make([]byte, 0, len(q)+1)
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			out = append(out, '$', byte('0'+n))
			continue
		}
		out = append(out, q[i])
	}
	return string(out)
}

// refetchSchemas is `commands.map { it.schema }`.
func refetchSchemas(commands []*pb.Refetch) []string {
	out := make([]string, 0, len(commands))
	for _, c := range commands {
		out = append(out, c.GetSchema())
	}
	return out
}
