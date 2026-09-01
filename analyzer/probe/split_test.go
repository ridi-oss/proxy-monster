package probe

import (
	"reflect"
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// The engine configs the splitter is exercised with: the same shape the control-plane forwards from
// what the proxy reported at introspection.
func mysqlSplitConfig() *pb.EngineConfig {
	return &pb.EngineConfig{
		Engine:                   pb.Engine_MYSQL,
		EngineVersion:            "8.0.46",
		MysqlLowerCaseTableNames: proto.Int32(1),
	}
}

func postgresSplitConfig() *pb.EngineConfig {
	return &pb.EngineConfig{Engine: pb.Engine_POSTGRES, EngineVersion: "16.0"}
}

func TestSplitStatements(t *testing.T) {
	cases := []struct {
		name   string
		sql    string
		engine *pb.EngineConfig
		want   []string
	}{
		{"single", "SELECT 1", mysqlSplitConfig(), []string{"SELECT 1"}},
		{"pair", "SELECT 1; SELECT 2", mysqlSplitConfig(), []string{"SELECT 1", "SELECT 2"}},
		{"trailing terminator", "SELECT 1;", mysqlSplitConfig(), []string{"SELECT 1"}},
		{"blank segments dropped", "SELECT 1;; SELECT 2;", mysqlSplitConfig(), []string{"SELECT 1", "SELECT 2"}},
		{"newline separated", "SELECT 1;\n\nSELECT 2\n", mysqlSplitConfig(), []string{"SELECT 1", "SELECT 2"}},
		// A `;` the tokenizer sees inside a literal, an identifier, or a comment is not a boundary.
		{"literal", "SELECT 'a;b' FROM users; SELECT 2", mysqlSplitConfig(), []string{"SELECT 'a;b' FROM users", "SELECT 2"}},
		{"quoted identifier", "SELECT `a;b` FROM t; SELECT 2", mysqlSplitConfig(), []string{"SELECT `a;b` FROM t", "SELECT 2"}},
		{"line comment", "SELECT 1 -- a;b\n; SELECT 2", mysqlSplitConfig(), []string{"SELECT 1", "SELECT 2"}},
		{"block comment", "SELECT /* a;b */ 1; SELECT 2", mysqlSplitConfig(), []string{"SELECT /* a;b */ 1", "SELECT 2"}},
		{"dollar quoted body", "CREATE FUNCTION f() RETURNS int AS $$ BEGIN; RETURN 1; END; $$ LANGUAGE plpgsql; SELECT 2", postgresSplitConfig(),
			[]string{"CREATE FUNCTION f() RETURNS int AS $$ BEGIN; RETURN 1; END; $$ LANGUAGE plpgsql", "SELECT 2"}},
		{"postgres literal", "SELECT 'a;b'; SELECT 2", postgresSplitConfig(), []string{"SELECT 'a;b'", "SELECT 2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := SplitStatements(c.sql, c.engine)
			if !ok {
				t.Fatalf("SplitStatements(%q) failed closed, want %q", c.sql, c.want)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("SplitStatements(%q) = %q, want %q", c.sql, got, c.want)
			}
		})
	}
}

// Every statement must be a verbatim slice of the input: the batch is stored, hashed, and authorized
// per statement, so a regenerated (or re-quoted) form would authorize text the caller never wrote.
func TestSplitStatementsSlicesVerbatim(t *testing.T) {
	sql := "SELECT `a;b`,  'x'  FROM t WHERE id = 1;\n  UPDATE t SET c = 'p;q' WHERE id = 2"
	got, ok := SplitStatements(sql, mysqlSplitConfig())
	if !ok {
		t.Fatalf("SplitStatements failed closed")
	}
	for _, statement := range got {
		if !strings.Contains(sql, statement) {
			t.Fatalf("statement %q is not a verbatim slice of the input", statement)
		}
	}
}

func TestSplitStatementsFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		sql    string
		engine *pb.EngineConfig
	}{
		{"unset engine", "SELECT 1", &pb.EngineConfig{}},
		{"nil config", "SELECT 1", nil},
		// createEngine requires both for MySQL; splitting under a partial config would use a dialect the
		// target does not, so it fails closed exactly as analysis does.
		{"mysql without version", "SELECT 1", &pb.EngineConfig{Engine: pb.Engine_MYSQL, MysqlLowerCaseTableNames: proto.Int32(1)}},
		{"mysql without lower_case_table_names", "SELECT 1", &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46"}},
		{"embedded NUL", "SELECT 1\x00; SELECT 2", mysqlSplitConfig()},
		{"invalid utf8", "SELECT '\xff\xfe'", mysqlSplitConfig()},
		{"empty", "", mysqlSplitConfig()},
		{"blank", "   \n  ", mysqlSplitConfig()},
		{"terminators only", ";;;", mysqlSplitConfig()},
		{"unterminated literal", "SELECT 'abc", mysqlSplitConfig()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, ok := SplitStatements(c.sql, c.engine); ok {
				t.Fatalf("SplitStatements(%q, %q) = %q, want fail-closed", c.sql, c.engine, got)
			}
		})
	}
}

// A split statement must analyze on its own: the batch path feeds each slice back through EmitFacts,
// which admits exactly one statement.
func TestSplitStatementsProduceSingleStatements(t *testing.T) {
	got, ok := SplitStatements("SELECT 'a;b' FROM users; UPDATE users SET name = 'x;y' WHERE id = 1", mysqlSplitConfig())
	if !ok {
		t.Fatalf("SplitStatements failed closed")
	}
	for _, statement := range got {
		if inner, ok := SplitStatements(statement, mysqlSplitConfig()); !ok || len(inner) != 1 {
			t.Fatalf("split statement %q does not re-split to exactly one statement: %q (ok=%v)", statement, inner, ok)
		}
	}
}

// A routine body's semicolons separate the body's OWN statements, so the whole definition is ONE
// statement — and a statement after its END is its own, separately authorized.
func TestSplitStatementsKeepsRoutineBodiesWhole(t *testing.T) {
	cases := []struct {
		sql  string
		want []string
	}{
		{"CREATE PROCEDURE p() BEGIN SELECT 1; SELECT 2; END",
			[]string{"CREATE PROCEDURE p() BEGIN SELECT 1; SELECT 2; END"}},
		{"SELECT 1; CREATE PROCEDURE p() BEGIN SELECT 2; END",
			[]string{"SELECT 1", "CREATE PROCEDURE p() BEGIN SELECT 2; END"}},
		// The trailing statement is NOT absorbed into the routine: it is authorized on its own.
		{"CREATE PROCEDURE p() BEGIN SELECT 1; END; SELECT 2",
			[]string{"CREATE PROCEDURE p() BEGIN SELECT 1; END", "SELECT 2"}},
		{"CREATE PROCEDURE p() BEGIN END; SELECT 2",
			[]string{"CREATE PROCEDURE p() BEGIN END", "SELECT 2"}},
	}
	for _, c := range cases {
		got, ok := SplitStatements(c.sql, mysqlSplitConfig())
		if !ok {
			t.Fatalf("SplitStatements(%q) failed closed, want %q", c.sql, c.want)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("SplitStatements(%q) = %q, want %q", c.sql, got, c.want)
		}
	}
}

// Every routine form folds whole, and a statement after its END stays its own — so a trailing
// statement is authorized separately rather than riding the routine's verdict.
func TestSplitStatementsFoldsEveryRoutineForm(t *testing.T) {
	cases := []struct {
		engine *pb.EngineConfig
		sql    string
		want   []string
	}{
		{mysqlSplitConfig(), "CREATE TRIGGER t BEFORE INSERT ON x FOR EACH ROW BEGIN SET @a = 1; END; SELECT 2",
			[]string{"CREATE TRIGGER t BEFORE INSERT ON x FOR EACH ROW BEGIN SET @a = 1; END", "SELECT 2"}},
		{mysqlSplitConfig(), "CREATE FUNCTION f() RETURNS INT BEGIN RETURN 1; END; SELECT 2",
			[]string{"CREATE FUNCTION f() RETURNS INT BEGIN RETURN 1; END", "SELECT 2"}},
		{postgresSplitConfig(), "CREATE FUNCTION f() RETURNS int LANGUAGE SQL BEGIN ATOMIC SELECT 1; END; SELECT 2",
			[]string{"CREATE FUNCTION f() RETURNS int LANGUAGE SQL BEGIN ATOMIC SELECT 1; END", "SELECT 2"}},
		// Bodies with no BEGIN wrapper: the terminator is the block's own, not a semicolon.
		{mysqlSplitConfig(), "CREATE PROCEDURE p() IF 1 THEN SELECT 1; END IF; SELECT 2",
			[]string{"CREATE PROCEDURE p() IF 1 THEN SELECT 1; END IF", "SELECT 2"}},
		{mysqlSplitConfig(), "CREATE PROCEDURE p() WHILE x DO SELECT 1; END WHILE; SELECT 2",
			[]string{"CREATE PROCEDURE p() WHILE x DO SELECT 1; END WHILE", "SELECT 2"}},
		{mysqlSplitConfig(), "CREATE PROCEDURE p() LOOP SELECT 1; END LOOP; SELECT 2",
			[]string{"CREATE PROCEDURE p() LOOP SELECT 1; END LOOP", "SELECT 2"}},
		{mysqlSplitConfig(), "CREATE PROCEDURE p() REPEAT SELECT 1; UNTIL x END REPEAT; SELECT 2",
			[]string{"CREATE PROCEDURE p() REPEAT SELECT 1; UNTIL x END REPEAT", "SELECT 2"}},
		{mysqlSplitConfig(), "CREATE PROCEDURE p() CASE x WHEN 1 THEN SELECT 1; END CASE; SELECT 2",
			[]string{"CREATE PROCEDURE p() CASE x WHEN 1 THEN SELECT 1; END CASE", "SELECT 2"}},
	}
	for _, c := range cases {
		got, ok := SplitStatements(c.sql, c.engine)
		if !ok {
			t.Fatalf("SplitStatements(%q) failed closed, want %q", c.sql, c.want)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("SplitStatements(%q) = %q, want %q", c.sql, got, c.want)
		}
	}
}

// PostgreSQL's `END` is COMMIT, so `BEGIN; …; END` is an ordinary transaction batch — denying it
// would refuse valid SQL. MySQL has no such form: a top-level END there is a routine body's tail.
func TestSplitStatementsPostgresTransactionEnd(t *testing.T) {
	const sql = "BEGIN; UPDATE t SET a = 1; END"
	got, ok := SplitStatements(sql, postgresSplitConfig())
	if !ok {
		t.Fatalf("SplitStatements(%q, POSTGRES) denied a valid transaction batch", sql)
	}
	want := []string{"BEGIN", "UPDATE t SET a = 1", "END"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitStatements(%q) = %q, want %q", sql, got, want)
	}
	// MySQL has no END statement — real MySQL 8.4 rejects a bare `END` with 1064, and the parser
	// agrees, so the batch is denied without a guard of our own.
	for _, mysqlEnd := range []string{"END", "SELECT 1; END", "END; SELECT 1"} {
		if got, ok := SplitStatements(mysqlEnd, mysqlSplitConfig()); ok {
			t.Fatalf("MySQL has no END statement; want denial for %q, got %q", mysqlEnd, got)
		}
	}
}

// A keyword-named identifier inside a routine body must never let the extent swallow what follows:
// merging `DROP TABLE users` into the CREATE would run it under the routine's verdict.
func TestSplitStatementsNeverMergesTrailingStatement(t *testing.T) {
	// A statement after a routine must be authorized on its own — absorbed into the routine's span it
	// would ride the CREATE's verdict, so a DROP would be permitted by a grant to create routines.
	for _, sql := range []string{
		"CREATE PROCEDURE p() BEGIN SELECT begin FROM t; END; DROP TABLE users",
		"CREATE PROCEDURE p() WHILE x DO SELECT 1; END WHILE; DROP TABLE users",
		"CREATE PROCEDURE p() IF 1 THEN SELECT 1; END IF; DROP TABLE users",
		"CREATE PROCEDURE p() LOOP SELECT 1; END LOOP; DROP TABLE users",
		"CREATE PROCEDURE p() REPEAT SELECT 1; UNTIL x END REPEAT; DROP TABLE users",
		"CREATE PROCEDURE p() CASE x WHEN 1 THEN SELECT 1; END CASE; DROP TABLE users",
		"CREATE TRIGGER t BEFORE INSERT ON x FOR EACH ROW BEGIN SET @a = 1; END; DROP TABLE users",
	} {
		got, ok := SplitStatements(sql, mysqlSplitConfig())
		if !ok {
			t.Fatalf("SplitStatements(%q) denied a valid batch", sql)
		}
		if len(got) != 2 || got[1] != "DROP TABLE users" {
			t.Fatalf("SplitStatements(%q) = %q; the DROP must stand alone", sql, got)
		}
	}
}

// The mirror of a merge: a statement INSIDE a routine body must never surface as its own top-level
// statement, or it would be authorized as that statement instead of as part of the definition.
func TestSplitStatementsNeverEscapesBodyStatement(t *testing.T) {
	for _, sql := range []string{
		"CREATE PROCEDURE p() BEGIN DROP TABLE x; SELECT 1; END",
		"CREATE PROCEDURE p() BEGIN SET @a = end; DROP TABLE x; END",
	} {
		got, ok := SplitStatements(sql, mysqlSplitConfig())
		if !ok {
			continue // denying the batch is fine; escaping is not
		}
		for _, statement := range got {
			if statement == "DROP TABLE x" {
				t.Fatalf("SplitStatements(%q) = %q; a body statement escaped to top level", sql, got)
			}
		}
	}
}

// A chunk the parser cannot place denies the WHOLE batch. Without this, sqlglot-go <= v0.28.0
// returned just [SELECT 1] here — silently dropping SELECT 2, which would then never be authorized.
func TestSplitStatementsDeniesOnParseError(t *testing.T) {
	for _, sql := range []string{
		"SELECT 1; ELSE; SELECT 2",
		// A body statement missing its terminator: real MySQL rejects this with 1064.
		"CREATE PROCEDURE p() BEGIN SELECT 1 END",
		// A label that does not match the block it closes.
		"CREATE PROCEDURE p() lbl: LOOP LEAVE lbl; END LOOP wrong; SELECT 2",
	} {
		if got, ok := SplitStatements(sql, mysqlSplitConfig()); ok {
			t.Fatalf("a parse error must deny the batch, got %q for %q", got, sql)
		}
	}
}

// A transaction BEGIN and a CASE … END are ordinary statement content and must still split: they share
// the BEGIN / END tokens with a routine body, so keying on those alone would refuse a legitimate batch.
func TestSplitStatementsAllowsTransactionAndCase(t *testing.T) {
	cases := []struct {
		sql  string
		want []string
	}{
		{"BEGIN; SELECT 1; COMMIT", []string{"BEGIN", "SELECT 1", "COMMIT"}},
		{"START TRANSACTION; UPDATE t SET a = 1; COMMIT", []string{"START TRANSACTION", "UPDATE t SET a = 1", "COMMIT"}},
		{"SELECT CASE WHEN a = 1 THEN 'x' ELSE 'y' END FROM t; SELECT 2",
			[]string{"SELECT CASE WHEN a = 1 THEN 'x' ELSE 'y' END FROM t", "SELECT 2"}},
	}
	for _, c := range cases {
		got, ok := SplitStatements(c.sql, mysqlSplitConfig())
		if !ok {
			t.Fatalf("SplitStatements(%q) failed closed, want %q", c.sql, c.want)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("SplitStatements(%q) = %q, want %q", c.sql, got, c.want)
		}
	}
}

// A comment carries no statement. The tokenizer attaches comments to the following token rather than
// emitting them, so a comment-only segment is non-blank text with no tokens — emitting it would add a
// statement the caller never wrote, and the batch would fail on it.
func TestSplitStatementsDropsCommentOnlySegments(t *testing.T) {
	cases := []struct {
		sql  string
		want []string
	}{
		{"SELECT 1; -- trailing note", []string{"SELECT 1"}},
		{"SELECT 1; /* trailing */", []string{"SELECT 1"}},
		{"SELECT 1;\n-- a\n-- b", []string{"SELECT 1"}},
		{"-- leading\nSELECT 1; SELECT 2", []string{"SELECT 1", "SELECT 2"}},
	}
	for _, c := range cases {
		got, ok := SplitStatements(c.sql, mysqlSplitConfig())
		if !ok {
			t.Fatalf("SplitStatements(%q) failed closed, want %q", c.sql, c.want)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("SplitStatements(%q) = %q, want %q", c.sql, got, c.want)
		}
	}
	// Nothing but comments is not a batch at all.
	for _, sql := range []string{"-- note", "/* note */", "-- a\n-- b"} {
		if got, ok := SplitStatements(sql, mysqlSplitConfig()); ok {
			t.Fatalf("comment-only input must fail closed, got %q for %q", got, sql)
		}
	}
}

// MySQL runs a version-gated comment's body as SQL, so it must be AUTHORIZED, not discarded: under a
// versionless dialect `DELETE … WHERE id=1 /*!80000 OR 1=1 */` spans only the scoped delete while the
// server deletes every row. The target's own dialect keeps the body inside the span it belongs to.
func TestSplitStatementsKeepsMysqlExecutableComment(t *testing.T) {
	for _, c := range []struct {
		sql  string
		want []string
	}{
		{"SELECT 1; /*!40101 DROP TABLE users */", []string{"SELECT 1", "/*!40101 DROP TABLE users */"}},
		{"/*! DROP TABLE users */; SELECT 1", []string{"/*! DROP TABLE users */", "SELECT 1"}},
		{"DELETE FROM users WHERE id=1 /*!80000 OR 1=1 */", []string{"DELETE FROM users WHERE id=1 /*!80000 OR 1=1 */"}},
		{"INSERT INTO t /*!80000 SELECT * FROM users */", []string{"INSERT INTO t /*!80000 SELECT * FROM users */"}},
	} {
		got, ok := SplitStatements(c.sql, mysqlSplitConfig())
		if !ok {
			t.Errorf("SplitStatements(%q) denied", c.sql)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("SplitStatements(%q) = %q, want %q — the body must be authorized, not dropped", c.sql, got, c.want)
		}
	}
	// A body the parser cannot place in a clean span fails closed rather than authorizing a subset.
	for _, sql := range []string{
		"SELECT 1 /*!80000 ; DROP TABLE users */",
		"/*!40101 SELECT 2 */ SELECT 1",
	} {
		if got, ok := SplitStatements(sql, mysqlSplitConfig()); ok {
			t.Errorf("SplitStatements(%q) = %q, want deny", sql, got)
		}
	}
	// PostgreSQL has no executable comments — it is an ordinary comment there.
	if _, ok := SplitStatements("SELECT 1; /*!40101 DROP TABLE users */", postgresSplitConfig()); !ok {
		t.Error("PostgreSQL must not deny a plain comment")
	}
}

// ANSI_QUOTES moves a boundary: `"…"` is a string by default (one statement) and a quoted identifier
// under the mode, where the `\` is literal, the quote closes, and the `;` splits. Splitting under the
// wrong one would fold DROP TABLE users into the SELECT's span and authorize it as that SELECT.
func TestSplitStatementsHonorsAnsiQuotes(t *testing.T) {
	const sql = `SELECT "a\" FROM t; DROP TABLE users; -- "`
	ansi := &pb.EngineConfig{
		Engine:                   pb.Engine_MYSQL,
		EngineVersion:            "8.0.46",
		MysqlLowerCaseTableNames: proto.Int32(1),
		MysqlAnsiQuotes:          proto.Bool(true),
	}
	got, ok := SplitStatements(sql, ansi)
	if !ok {
		t.Fatalf("SplitStatements(%q) denied under ANSI_QUOTES", sql)
	}
	want := []string{`SELECT "a\" FROM t`, "DROP TABLE users"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitStatements(%q) = %q, want %q — the DROP must stand alone", sql, got, want)
	}
	if plain, _ := SplitStatements(sql, mysqlSplitConfig()); len(plain) != 1 {
		t.Fatalf("default mode = %q, want one statement (the `\"…\"` is a literal there)", plain)
	}
}
