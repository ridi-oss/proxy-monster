package db

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func TestMySqlDbConstants(t *testing.T) {
	m := MySqlDb{}
	if m.NamespaceProbeSQL() != "SELECT DATABASE()" {
		t.Errorf("NamespaceProbeSQL() = %q, want %q", m.NamespaceProbeSQL(), "SELECT DATABASE()")
	}
	if m.SupportsTempOverlay() {
		t.Error("SupportsTempOverlay() = true, want false for MySQL")
	}
	if m.TempColumnsProbeSQL() != "" {
		t.Errorf("TempColumnsProbeSQL() = %q, want empty", m.TempColumnsProbeSQL())
	}
}

func TestMySqlSchemaHashSQL(t *testing.T) {
	m := MySqlDb{}
	schema := "hostile'\\name"
	sql, columns, err := m.SchemaHashSQL(schema, nil)
	if err != nil {
		t.Fatalf("SchemaHashSQL: %v", err)
	}
	if columns != 5 {
		t.Fatalf("columns = %d, want 5", columns)
	}
	for _, fragment := range []string{
		"SET_VAR(group_concat_max_len=33554432)",
		"UNIX_TIMESTAMP(SYSDATE(6))",
		"CASE WHEN SYSDATE(6) <> NOW(6)",
		"1000000",
		"@@server_uuid",
		"LENGTH(CAST(sn AS BINARY)), ':'",
		"LENGTH(CAST(tn AS BINARY)), ':'",
		"LENGTH(CAST(cn AS BINARY)), ':'",
		"LENGTH(CAST(dt AS BINARY)), ':'",
		"LENGTH(CAST(op AS CHAR CHARACTER SET ascii)), ':'",
		"LENGTH(CAST(nl AS BINARY)), ':'",
		"ORDER BY CAST(tn AS BINARY), op, CAST(cn AS BINARY)",
		"X'" + fmt.Sprintf("%x", []byte(schema)) + "'",
		// The WHERE filter must be mode-aware (CASE WHEN @@lower_case_table_names = 2 THEN LOWER(...)):
		// a canonical (possibly-folded) schema parameter must still match a live mode-2 server whose
		// information_schema preserves the original stored case.
		"CASE WHEN @@lower_case_table_names = 2 THEN LOWER(CAST(TABLE_SCHEMA AS BINARY)) ELSE CAST(TABLE_SCHEMA AS BINARY) END",
	} {
		if !strings.Contains(sql, fragment) {
			t.Errorf("SchemaHashSQL missing %q:\n%s", fragment, sql)
		}
	}
	if strings.Contains(strings.ToUpper(sql), "SET SESSION") {
		t.Fatalf("SchemaHashSQL mutates session state:\n%s", sql)
	}
	if strings.Contains(sql, "CONCAT(HEX(") {
		t.Fatalf("SchemaHashSQL uses forbidden bare HEX concatenation:\n%s", sql)
	}
	assertClientSettableClockAbsent(t, "SchemaHashSQL", sql)
	// The hashed/selected TABLE_SCHEMA value itself (aliased sn) must stay the RAW live content — only
	// the WHERE-filter comparison folds for mode 2. Folding what's hashed would make the hash no longer
	// fingerprint the database's actual bytes.
	if !strings.Contains(sql, "SELECT TABLE_SCHEMA AS sn") {
		t.Errorf("SchemaHashSQL must select the raw TABLE_SCHEMA value (not folded) for hashing:\n%s", sql)
	}
	columnsSQL := m.SchemaColumnsSQL(schema)
	for _, fragment := range []string{
		"CAST(TABLE_SCHEMA AS BINARY)",
		"ORDER BY CAST(TABLE_NAME AS BINARY), ORDINAL_POSITION, CAST(COLUMN_NAME AS BINARY)",
		"X'" + fmt.Sprintf("%x", []byte(schema)) + "'",
		"CASE WHEN @@lower_case_table_names = 2 THEN LOWER(CAST(TABLE_SCHEMA AS BINARY)) ELSE CAST(TABLE_SCHEMA AS BINARY) END",
	} {
		if !strings.Contains(columnsSQL, fragment) {
			t.Errorf("SchemaColumnsSQL missing %q: %s", fragment, columnsSQL)
		}
	}
	// SELECT TABLE_SCHEMA (unqualified, the first result column) must stay unfolded too, matching
	// FragmentColumnsFromRows' expectation of the live stored value.
	if !strings.HasPrefix(columnsSQL, "SELECT TABLE_SCHEMA,") {
		t.Errorf("SchemaColumnsSQL must SELECT the raw TABLE_SCHEMA value (not folded): %s", columnsSQL)
	}
	if strings.Contains(strings.ToUpper(columnsSQL), "NOT IN") {
		t.Fatalf("SchemaColumnsSQL excludes system schemas: %s", columnsSQL)
	}
}

func TestMySqlNormalizeColumns(t *testing.T) {
	in := []*pb.Column{
		{Schema: "AppDB", Table: "UserRows", Column: "CustomerID", DataType: "int", Ordinal: 1, Nullable: true},
	}
	// mode 1 (case-insensitive): schema/table fold too, alongside the always-unconditional column fold.
	out := (MySqlDb{}).NormalizeColumns(1, in)
	if len(out) != 1 {
		t.Fatalf("NormalizeColumns returned %d columns, want 1", len(out))
	}
	got := out[0]
	if got.GetSchema() != "appdb" || got.GetTable() != "userrows" || got.GetColumn() != "customerid" {
		t.Errorf("mode 1: got %s.%s.%s, want appdb.userrows.customerid", got.GetSchema(), got.GetTable(), got.GetColumn())
	}
	if got.GetDataType() != "int" || got.GetOrdinal() != 1 || !got.GetNullable() {
		t.Errorf("NormalizeColumns must preserve non-identity fields, got %+v", got)
	}
	// Input must not be mutated (NormalizeColumns builds new pb.Column values).
	if in[0].GetSchema() != "AppDB" {
		t.Errorf("NormalizeColumns mutated its input: %+v", in[0])
	}

	// mode 0 (case-sensitive): schema/table stay verbatim; the column still folds unconditionally.
	out0 := (MySqlDb{}).NormalizeColumns(0, in)
	if out0[0].GetSchema() != "AppDB" || out0[0].GetTable() != "UserRows" || out0[0].GetColumn() != "customerid" {
		t.Errorf("mode 0: got %s.%s.%s, want AppDB.UserRows.customerid", out0[0].GetSchema(), out0[0].GetTable(), out0[0].GetColumn())
	}

	// A multi-row fragment with a repeated (schema, table) exercises the batched path (one sqlglot
	// parse per distinct table, memoized; column folded per row). Row order and each row's non-identity
	// fields must be preserved.
	multi := []*pb.Column{
		{Schema: "AppDB", Table: "UserRows", Column: "CustomerID", DataType: "int", Ordinal: 1, Nullable: false},
		{Schema: "AppDB", Table: "UserRows", Column: "EmailAddr", DataType: "varchar", Ordinal: 2, Nullable: true},
		{Schema: "AppDB", Table: "OrderRows", Column: "OrderID", DataType: "bigint", Ordinal: 1, Nullable: false},
	}
	outMulti := (MySqlDb{}).NormalizeColumns(1, multi)
	if len(outMulti) != 3 {
		t.Fatalf("NormalizeColumns returned %d columns, want 3", len(outMulti))
	}
	wantSchema := []string{"appdb", "appdb", "appdb"}
	wantTable := []string{"userrows", "userrows", "orderrows"}
	wantColumn := []string{"customerid", "emailaddr", "orderid"}
	for i, c := range outMulti {
		if c.GetSchema() != wantSchema[i] || c.GetTable() != wantTable[i] || c.GetColumn() != wantColumn[i] {
			t.Errorf("mode 1 row %d: got %s.%s.%s, want %s.%s.%s",
				i, c.GetSchema(), c.GetTable(), c.GetColumn(), wantSchema[i], wantTable[i], wantColumn[i])
		}
		if c.GetDataType() != multi[i].GetDataType() || c.GetOrdinal() != multi[i].GetOrdinal() || c.GetNullable() != multi[i].GetNullable() {
			t.Errorf("mode 1 row %d: non-identity fields not preserved: got %+v, want fields from %+v", i, c, multi[i])
		}
	}
}

func TestPgNormalizeColumnsIsIdentity(t *testing.T) {
	in := []*pb.Column{{Schema: "Sales", Table: "OrderItems", Column: "CustomerID"}}
	out := (PgDb{}).NormalizeColumns(0, in)
	if len(out) != 1 || out[0] != in[0] {
		t.Errorf("PgDb.NormalizeColumns must be an identity passthrough, got %+v", out)
	}
}

// TestFragmentColumnsFromRowsModeAwareSchemaCheck proves engine.FragmentColumnsFromRows' schema
// consistency check follows each dialect/mode's own fold rule instead of a blanket case-insensitive
// comparison: mode 2 is the only configuration where a live row's case may legitimately diverge from
// the requested (canonical) schema, so it's the only one where that divergence is accepted.
func TestFragmentColumnsFromRowsModeAwareSchemaCheck(t *testing.T) {
	str := func(s string) *string { return &s }
	row := func(schema string) [][]*string {
		return [][]*string{{str(schema), str("t"), str("c"), str("int"), str("1"), str("NO")}}
	}

	t.Run("MySQL mode 0 rejects a case-differing schema (no legitimate divergence)", func(t *testing.T) {
		if _, err := engine.FragmentColumnsFromRows(MySqlDb{}, 0, "App", row("app")); err == nil {
			t.Fatal("FragmentColumnsFromRows succeeded, want a strict mismatch under mode 0")
		}
	})

	t.Run("MySQL mode 2 accepts the live stored spelling diverging in case from the canonical request", func(t *testing.T) {
		got, err := engine.FragmentColumnsFromRows(MySqlDb{}, 2, "app", row("App"))
		if err != nil {
			t.Fatalf("FragmentColumnsFromRows: %v", err)
		}
		if len(got) != 1 || got[0].GetSchema() != "app" {
			t.Fatalf("columns = %+v, want a single row folded to canonical schema %q", got, "app")
		}
	})

	t.Run("Postgres rejects a case-differing schema (Postgres never folds)", func(t *testing.T) {
		if _, err := engine.FragmentColumnsFromRows(PgDb{}, 0, "Sales", row("sales")); err == nil {
			t.Fatal("FragmentColumnsFromRows succeeded, want a strict mismatch on Postgres")
		}
	})
}

func TestMySqlSchemaHashFromRows(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	cases := []struct {
		name              string
		rows              [][]*string
		wantHash, trusted bool
		clock             int64
		id                string
	}{
		{"valid", rows(hash, "128", "2", "123", "123e4567-e89b-12d3-a456-426614174000"), true, true, 123, "123e4567-e89b-12d3-a456-426614174000"},
		{"truncated keeps hash", rows(hash, "64", "2", "123", "123e4567-e89b-12d3-a456-426614174000"), true, false, 123, "123e4567-e89b-12d3-a456-426614174000"},
		{"malformed clock", rows(hash, "64", "1", "bad", "123e4567-e89b-12d3-a456-426614174000"), true, true, 0, "123e4567-e89b-12d3-a456-426614174000"},
		{"malformed id", rows(hash, "64", "1", "123", "not-a-uuid"), true, true, 123, ""},
		{"nil clock and id", [][]*string{{ptr(hash), ptr("64"), ptr("1"), nil, nil}}, true, true, 0, ""},
		{"nil hash", [][]*string{{nil, ptr("0"), ptr("0"), ptr("123"), ptr("123e4567-e89b-12d3-a456-426614174000")}}, false, false, 123, "123e4567-e89b-12d3-a456-426614174000"},
		{"extra row", append(rows(hash, "64", "1", "123", "123e4567-e89b-12d3-a456-426614174000"), rows(hash, "64", "1", "123", "123e4567-e89b-12d3-a456-426614174000")[0]), false, false, 0, ""},
		{"short hash", rows("abcd", "64", "1", "123", "123e4567-e89b-12d3-a456-426614174000"), false, false, 123, "123e4567-e89b-12d3-a456-426614174000"},
		// A right-length non-hex digest must yield NO hash and NO trust. hex.DecodeString hands back the
		// bytes it managed to read alongside its error, so ignoring that error leaves an empty-but-non-nil
		// slice that reads as a genuine measurement — and two of them compare equal, making unrelated
		// schemas look coherent.
		{"non-hex hash", rows(strings.Repeat("z", 64), "64", "1", "123", "123e4567-e89b-12d3-a456-426614174000"), false, false, 123, "123e4567-e89b-12d3-a456-426614174000"},
		{"partially-hex hash", rows(strings.Repeat("ab", 31)+"zz", "64", "1", "123", "123e4567-e89b-12d3-a456-426614174000"), false, false, 123, "123e4567-e89b-12d3-a456-426614174000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (MySqlDb{}).SchemaHashFromRows(tc.rows)
			if err != nil {
				t.Fatal(err)
			}
			if (got.Hash != nil) != tc.wantHash || got.Trusted != tc.trusted || got.DbClockMicros != tc.clock || got.BackendID != tc.id {
				t.Fatalf("observation = %+v hash=%x", got, got.Hash)
			}
		})
	}
}

func TestMySqlServerHash(t *testing.T) {
	sql, columns, err := (MySqlDb{}).ServerHashSQL(nil)
	if err != nil || columns != 6 {
		t.Fatalf("ServerHashSQL = columns %d, err %v", columns, err)
	}
	for _, fragment := range []string{"CAST(sn AS BINARY) AS sng", "GROUP BY sng", "@@server_uuid", "UNIX_TIMESTAMP(SYSDATE(6))"} {
		if !strings.Contains(sql, fragment) {
			t.Errorf("ServerHashSQL missing %q:\n%s", fragment, sql)
		}
	}
	if strings.Contains(sql, "WHERE") {
		t.Fatalf("ServerHashSQL contains schema filter:\n%s", sql)
	}
	assertClientSettableClockAbsent(t, "ServerHashSQL", sql)
	hash := strings.Repeat("ab", 32)
	got, err := (MySqlDb{}).ServerHashFromRows([][]*string{{ptr("app"), ptr(hash), ptr("64"), ptr("1"), ptr("123"), ptr("id")}, {ptr("bad"), ptr(hash), ptr("1"), ptr("1"), ptr("bad"), nil}})
	if err != nil || len(got) != 2 || !got[0].Trusted || got[1].Trusted || got[1].Hash == nil || got[1].DbClockMicros != 0 {
		t.Fatalf("ServerHashFromRows = %+v, err %v", got, err)
	}
	if _, err := (MySqlDb{}).ServerHashFromRows([][]*string{{nil, ptr(hash), ptr("64"), ptr("1"), ptr("1"), ptr("123e4567-e89b-12d3-a456-426614174000")}}); err == nil {
		t.Fatal("nil schema succeeded")
	}
	if _, err := (MySqlDb{}).ServerHashFromRows(rows("app", hash)); err == nil {
		t.Fatal("wrong width succeeded")
	}
}

// Both engines' information_schema is privilege-filtered, so every dialect must be able to say whether
// its scan saw the whole server — a subset presented as a whole-server scan tells the manager the
// schemas it could not see were dropped.
func TestCatalogVisibilitySQLExistsPerDialect(t *testing.T) {
	for name, statement := range map[string]string{
		"MySQL":    MySqlDb{}.CatalogVisibilitySQL(),
		"Postgres": PgDb{}.CatalogVisibilitySQL(),
	} {
		if statement == "" {
			t.Errorf("%s CatalogVisibilitySQL is empty, so it can never claim a complete namespace", name)
		}
	}
	// Each fragment is a distinct way the account can see less than the whole server while still
	// answering yes to a naive "does it hold global SELECT" lookup. The live proofs are in
	// hash_integration_test.go; these pin that no fragment is dropped from the statement.
	for fragment, why := range map[string]string{
		"USER_PRIVILEGES":                     "global SELECT is what lifts the information_schema row filter",
		"@@partial_revokes = 0":               "a partial revoke hides a schema while global SELECT still reads as held",
		"information_schema.ENABLED_ROLES":    "global SELECT is usually inherited from an active role, not held directly",
		"information_schema.APPLICABLE_ROLES": "a role may hold global SELECT through another role; MySQL does not flatten the chain",
	} {
		if !strings.Contains(MySqlDb{}.CatalogVisibilitySQL(), fragment) {
			t.Errorf("MySQL visibility probe missing %q: %s", fragment, why)
		}
	}
	for _, fragment := range []string{"is_superuser", "pg_read_all_data"} {
		if !strings.Contains(PgDb{}.CatalogVisibilitySQL(), fragment) {
			t.Errorf("Postgres visibility probe missing %q", fragment)
		}
	}
}

func TestPgDbConstants(t *testing.T) {
	p := PgDb{}
	if p.NamespaceProbeSQL() != "SELECT pg_catalog.unnest(pg_catalog.current_schemas(true))" {
		t.Errorf("NamespaceProbeSQL() = %q", p.NamespaceProbeSQL())
	}
	if !p.SupportsTempOverlay() {
		t.Error("SupportsTempOverlay() = false, want true for Postgres")
	}
	sql := p.TempColumnsProbeSQL()
	if !strings.Contains(sql, "pg_temp%") {
		t.Errorf("TempColumnsProbeSQL() = %q, want it to contain the pg_temp%% predicate", sql)
	}
	if !strings.Contains(sql, "pg_catalog.pg_attribute") {
		t.Errorf("TempColumnsProbeSQL() = %q, want it to reference pg_catalog.pg_attribute", sql)
	}
}

func TestPgSchemaHashSQL(t *testing.T) {
	p := PgDb{}
	schema := "hostile'\\schema"
	cryptoSQL, columns, err := p.SchemaHashSQL(schema, [][]*string{{ptr(`crypto"schema`), ptr("1")}})
	if err != nil {
		t.Fatalf("SchemaHashSQL pgcrypto: %v", err)
	}
	if columns != 5 {
		t.Fatalf("columns = %d, want 5", columns)
	}
	for _, fragment := range []string{
		`"crypto""schema".digest`,
		"pg_catalog.encode(",
		"pg_catalog.convert_to(",
		"pg_catalog.string_agg(",
		"pg_catalog.clock_timestamp()",
		"pg_catalog.pg_control_system()",
		"system_identifier",
		"pg_catalog.octet_length(",
		`COLLATE "C"`,
		"pg_catalog.convert_from('\\x" + fmt.Sprintf("%x", []byte(schema)) + "'::pg_catalog.bytea, 'UTF8')",
	} {
		if !strings.Contains(cryptoSQL, fragment) {
			t.Errorf("pgcrypto SchemaHashSQL missing %q:\n%s", fragment, cryptoSQL)
		}
	}
	if strings.Contains(cryptoSQL, "statement_timestamp") {
		t.Fatalf("SchemaHashSQL uses transaction-frozen statement_timestamp:\n%s", cryptoSQL)
	}
	fallbackSQL, _, err := p.SchemaHashSQL(schema, nil)
	if err != nil {
		t.Fatalf("SchemaHashSQL fallback: %v", err)
	}
	if !strings.Contains(fallbackSQL, "pg_catalog.md5(") || strings.Contains(fallbackSQL, ".digest(") {
		t.Fatalf("fallback is not fully qualified pg_catalog.md5:\n%s", fallbackSQL)
	}
	assertIdentityReadOnlyWhenPermitted(t, p)
	columnsSQL := p.SchemaColumnsSQL(schema)
	for _, fragment := range []string{`COLLATE "C"`, "ordinal_position", "pg_catalog.convert_from('\\x" + fmt.Sprintf("%x", []byte(schema))} {
		if !strings.Contains(columnsSQL, fragment) {
			t.Errorf("SchemaColumnsSQL missing %q: %s", fragment, columnsSQL)
		}
	}
}

func TestPgSchemaHashFromRows(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	md5 := strings.Repeat("cd", 16)
	cases := []struct {
		name              string
		rows              [][]*string
		wantHash, trusted bool
		clock             int64
		id                string
	}{
		{"sha256", rows(sha, "2", "0", "123", "123456789"), true, true, 123, "123456789"},
		{"md5 fallback", rows(md5, "2", "0", "123", "123456789"), true, true, 123, "123456789"},
		{"null row keeps hash", rows(sha, "2", "1", "123", "123456789"), true, false, 123, "123456789"},
		{"bad count keeps hash", rows(sha, "bad", "0", "123", "123456789"), true, false, 123, "123456789"},
		{"bad clock", rows(sha, "2", "0", "bad", "123456789"), true, true, 0, "123456789"},
		{"bad identity", rows(sha, "2", "0", "123", "not-a-number"), true, true, 123, ""},
		{"nil identity", [][]*string{{ptr(sha), ptr("2"), ptr("0"), ptr("123"), nil}}, true, true, 123, ""},
		{"extra row", append(rows(sha, "1", "0", "1", "123456789"), rows(sha, "1", "0", "1", "123456789")[0]), false, false, 0, ""},
		{"short", rows("abcd", "1", "0", "1", "not-a-number"), false, false, 1, ""},
		// See the MySQL matrix: a right-length non-hex digest must not survive as an empty trusted hash.
		{"non-hex sha", rows(strings.Repeat("z", 64), "2", "0", "123", "123456789"), false, false, 123, "123456789"},
		{"non-hex md5", rows(strings.Repeat("z", 32), "2", "0", "123", "123456789"), false, false, 123, "123456789"},
		{"partially-hex sha", rows(strings.Repeat("ab", 31)+"zz", "2", "0", "123", "123456789"), false, false, 123, "123456789"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (PgDb{}).SchemaHashFromRows(tc.rows)
			if err != nil {
				t.Fatal(err)
			}
			if (got.Hash != nil) != tc.wantHash || got.Trusted != tc.trusted || got.DbClockMicros != tc.clock || got.BackendID != tc.id {
				t.Fatalf("observation = %+v hash=%x", got, got.Hash)
			}
		})
	}
}

func TestPgServerHash(t *testing.T) {
	sql, columns, err := (PgDb{}).ServerHashSQL([][]*string{{ptr("crypto"), ptr("1")}})
	if err != nil || columns != 6 {
		t.Fatalf("ServerHashSQL = columns %d, err %v", columns, err)
	}
	for _, fragment := range []string{"SELECT sn", "GROUP BY sn", "pg_catalog.clock_timestamp()", "pg_catalog.pg_control_system()", `"crypto".digest`} {
		if !strings.Contains(sql, fragment) {
			t.Errorf("ServerHashSQL missing %q:\n%s", fragment, sql)
		}
	}
	if strings.Contains(sql, "WHERE table_schema") {
		t.Fatalf("ServerHashSQL contains schema filter:\n%s", sql)
	}
	hash := strings.Repeat("ab", 32)
	got, err := (PgDb{}).ServerHashFromRows([][]*string{{ptr("app"), ptr(hash), ptr("2"), ptr("0"), ptr("123"), ptr("123e4567-e89b-12d3-a456-426614174000")}})
	if err != nil || len(got) != 1 || got[0].Schema != "app" || !got[0].Trusted {
		t.Fatalf("ServerHashFromRows = %+v, err %v", got, err)
	}
	if _, err := (PgDb{}).ServerHashFromRows([][]*string{{nil, ptr(hash), ptr("2"), ptr("0"), ptr("123"), ptr("123456789")}}); err == nil {
		t.Fatal("nil schema succeeded")
	}
}

// TestUndecodableHashNeverPushesAsTrusted joins the REAL dialect decoders to the REAL Refetcher, the
// seam where content_hash and hash_trusted are actually produced. Each side is well covered alone, and
// a corrupt digest still slipped through as an empty hash marked trusted: the decoder's own tests
// asserted `Hash != nil`, and the refetch tests used a hand-rolled fake decoder, so nothing observed
// what the pair puts on the wire. hash_trusted means the measure-fetch-measure bracket held over a
// genuine DB-side hash — an undecodable digest must fail that, and must not let two unrelated schemas
// bracket each other by both decoding to empty.
func TestUndecodableHashNeverPushesAsTrusted(t *testing.T) {
	fragment := [][]*string{{ptr("app"), ptr("t"), ptr("c"), ptr("int"), ptr("1"), ptr("NO")}}
	for _, tc := range []struct {
		name    string
		adapter engine.Db
		rows    [][]*string
	}{
		{"MySQL non-hex", MySqlDb{}, rows(strings.Repeat("z", 64), "64", "1", "123", "123e4567-e89b-12d3-a456-426614174000")},
		{"MySQL partially hex", MySqlDb{}, rows(strings.Repeat("ab", 31)+"zz", "64", "1", "123", "123e4567-e89b-12d3-a456-426614174000")},
		{"Postgres non-hex", PgDb{}, rows(strings.Repeat("z", 64), "1", "0", "123", "123456789")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pushed *pb.SchemaFragmentPush
			refetcher := engine.NewRefetcher(
				tc.adapter, []byte("connection"), 7,
				func(statement string, _ int) ([][]*string, error) {
					if strings.Contains(statement, "information_schema.COLUMNS") && strings.Contains(statement, "ORDINAL_POSITION,") ||
						strings.Contains(statement, "information_schema.columns") && strings.Contains(statement, "ordinal_position,") {
						return fragment, nil
					}
					return tc.rows, nil
				},
				func(push *pb.SchemaFragmentPush) (uint64, error) { pushed = push; return 1, nil },
				nil,
			)
			if err := refetcher.Run(&pb.Refetch{Schema: "app"}); err != nil {
				t.Fatalf("Refetcher.Run: %v", err)
			}
			if pushed.GetHashTrusted() {
				t.Fatalf("undecodable digest pushed as trusted: content_hash=%x", pushed.GetContentHash())
			}
			if len(pushed.GetContentHash()) != 0 {
				t.Fatalf("content_hash = %x, want no bytes for an undecodable digest", pushed.GetContentHash())
			}
		})
	}
}

// assertClientSettableClockAbsent pins the version clock against a client-movable source. NOW()/
// CURRENT_TIMESTAMP return the session's `SET timestamp`, which a client owns on the very connection
// hash probes run on; a poisoned future reading would freeze the manager's strictly-newer ordering
// rule on that version. Only SYSDATE() reads the real clock — and only on a server that did not alias
// the two, which the emitted `SYSDATE(6) <> NOW(6)` guard is there to detect at runtime.
func assertClientSettableClockAbsent(t *testing.T, name, sql string) {
	t.Helper()
	if !strings.Contains(sql, "CASE WHEN SYSDATE(6) <> NOW(6)") {
		t.Fatalf("%s does not guard against a --sysdate-is-now server aliasing SYSDATE to NOW:\n%s", name, sql)
	}
	// The sanctioned forms — the guard's own comparison and the reading it protects — are hidden before
	// scanning so their text cannot mask a genuine client-settable read elsewhere in the statement.
	scanned := strings.ToUpper(strings.ReplaceAll(sql, "CASE WHEN SYSDATE(6) <> NOW(6)", "«GUARD»"))
	scanned = strings.ReplaceAll(scanned, "SYSDATE(6)", "«CLOCK»")
	for _, settable := range []string{"NOW(", "CURRENT_TIMESTAMP", "LOCALTIME"} {
		if strings.Contains(scanned, settable) {
			t.Fatalf("%s reads client-settable clock %q (use SYSDATE(6)):\n%s", name, settable, sql)
		}
	}
}

// assertIdentityReadOnlyWhenPermitted pins the ONE construction that survives a cluster which revoked
// pg_control_system() from PUBLIC: the statement must not name the function at all unless the setup
// probe already established EXECUTE. PostgreSQL resolves function privilege at PLAN time, so an inline
// `CASE WHEN has_function_privilege(...) THEN (SELECT ... FROM pg_control_system()) END` does NOT
// short-circuit — it aborts the entire statement, turning an unavailable backend id into the loss of
// every schema hash. This asserts the emitted SQL both ways so a regression to the inline guard fails
// here rather than only against a hardened cluster nobody tests on.
func assertIdentityReadOnlyWhenPermitted(t *testing.T, p PgDb) {
	t.Helper()
	for _, tc := range []struct {
		name      string
		setupRows [][]*string
		permitted bool
	}{
		{"EXECUTE granted", [][]*string{{nil, ptr("1")}}, true},
		{"EXECUTE revoked", [][]*string{{nil, ptr("0")}}, false},
		{"privilege unknown", [][]*string{{nil, nil}}, false},
		{"setup probe failed", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, sql := range emittedHashStatements(t, p, tc.setupRows) {
				names := strings.Contains(sql, "pg_control_system")
				if names != tc.permitted {
					t.Fatalf("%s names pg_control_system = %v, want %v:\n%s", name, names, tc.permitted, sql)
				}
				// has_function_privilege belongs to the setup probe; inline it and the plan-time check
				// fires anyway.
				if strings.Contains(sql, "has_function_privilege") {
					t.Fatalf("%s guards the identity read inline, which PostgreSQL evaluates at plan time:\n%s", name, sql)
				}
				if !tc.permitted && !strings.Contains(sql, `''`) {
					t.Fatalf("%s must emit a literal empty backend id when the identity is unreadable:\n%s", name, sql)
				}
			}
		})
	}
	if !strings.Contains(p.HashSetupProbeSQL(), "has_function_privilege") {
		t.Fatalf("HashSetupProbeSQL must resolve the identity privilege:\n%s", p.HashSetupProbeSQL())
	}
	if p.HashSetupColumns() != 2 {
		t.Fatalf("HashSetupColumns = %d, want 2 (pgcrypto schema, identity privilege)", p.HashSetupColumns())
	}
}

// emittedHashStatements returns both statements built from one setup-probe result, so a rule about the
// hash SQL is asserted against every form of it rather than whichever one a test happened to build.
func emittedHashStatements(t *testing.T, p PgDb, setupRows [][]*string) map[string]string {
	t.Helper()
	schemaSQL, _, err := p.SchemaHashSQL("app", setupRows)
	if err != nil {
		t.Fatalf("SchemaHashSQL: %v", err)
	}
	serverSQL, _, err := p.ServerHashSQL(setupRows)
	if err != nil {
		t.Fatalf("ServerHashSQL: %v", err)
	}
	return map[string]string{"SchemaHashSQL": schemaSQL, "ServerHashSQL": serverSQL}
}

func ptr(value string) *string { return &value }
func rows(values ...string) [][]*string {
	row := make([]*string, len(values))
	for i := range values {
		row[i] = ptr(values[i])
	}
	return [][]*string{row}
}

var _ engine.Db = MySqlDb{}
var _ engine.Db = PgDb{}
