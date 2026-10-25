package engines

import "testing"

func TestSqlNormalizeEqualClasses(t *testing.T) {
	cases := []struct {
		name, dialect, left, right, want string
	}{
		{
			name:    "whitespace",
			dialect: "postgres",
			left:    "SELECT\ta\nFROM t",
			right:   "  SELECT a FROM t  ",
			want:    "select a from t",
		},
		{
			name:    "ordinary comments",
			dialect: "mysql",
			left:    "SELECT /* ordinary */ a -- tail\nFROM t",
			right:   "SELECT a FROM t",
			want:    "select a from t",
		},
		{
			name:    "reserved keyword case",
			dialect: "mysql",
			left:    "SELECT a FROM t WHERE a IS NULL",
			right:   "select a from t where a is null",
			want:    "select a from t where a is null",
		},
		{
			name:    "postgres unquoted identifier case",
			dialect: "postgres",
			left:    "SELECT MixedCase FROM Users",
			right:   "select mixedcase from users",
			want:    "select mixedcase from users",
		},
		{
			name:    "athena explain keyword case",
			dialect: "athena",
			left:    "EXPLAIN SELECT a FROM t",
			right:   "explain select a from t",
			want:    "explain select a from t",
		},
		{
			name:    "athena hive ddl keyword case",
			dialect: "athena",
			left:    "CREATE EXTERNAL TABLE T (A INT) LOCATION 's3://b/'; SELECT A FROM T",
			right:   "create external table t (a int) location 's3://b/'; select a from t",
			want:    "create external table t ( a int ) location 's3://b/' ; select a from t",
		},
		{
			name:    "trailing semicolons",
			dialect: "postgres",
			left:    "SELECT 1;;;;",
			right:   "select 1",
			want:    "select 1",
		},
		{
			// The dot guard is MySQL-only: PostgreSQL folds unquoted names to lowercase server-side
			// (case-insensitive unless double-quoted), so an unquoted reserved word after `.` still
			// folds and `db.INTERSECT`/`db.intersect` remain the SAME relation — no over-deny there.
			name:    "postgres folds reserved word after dot",
			dialect: "postgres",
			left:    "SELECT * FROM db.INTERSECT",
			right:   "SELECT * FROM db.intersect",
			want:    "select * from db . intersect",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			left, leftOK := SqlNormalize(tc.left, tc.dialect)
			right, rightOK := SqlNormalize(tc.right, tc.dialect)
			if !leftOK || !rightOK {
				t.Fatalf("normalization denied: left=(%q, %v) right=(%q, %v)", left, leftOK, right, rightOK)
			}
			if left != tc.want || right != tc.want {
				t.Fatalf("normalized values = (%q, %q), want both %q", left, right, tc.want)
			}
		})
	}
}

func TestSqlNormalizeDistinctClasses(t *testing.T) {
	cases := []struct {
		name, dialect, left, right string
	}{
		{"table name", "postgres", "SELECT a FROM first_table", "SELECT a FROM second_table"},
		{"column name", "postgres", "SELECT first_column FROM t", "SELECT second_column FROM t"},
		{"operator", "mysql", "SELECT a != b", "SELECT a <> b"},
		{"string value", "mysql", "SELECT 'Alpha'", "SELECT 'alpha'"},
		{"number spelling", "postgres", "SELECT 1", "SELECT 01"},
		{"quoted identifier", "postgres", `SELECT "Mixed"`, `SELECT "mixed"`},
		{"mysql non-reserved identifier case", "mysql", "SELECT Comment FROM t", "SELECT comment FROM t"},
		{"postgres dollar quote body", "postgres", "SELECT $$AbC$$", "SELECT $$abc$$"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertNormalizesDistinct(t, tc.dialect, tc.left, tc.right)
		})
	}
}

func TestSqlNormalizeFailsClosed(t *testing.T) {
	invalidUTF8 := string([]byte{'S', 'E', 'L', 'E', 'C', 'T', ' ', 0xff})
	cases := []struct {
		name, dialect, sql string
	}{
		{"empty", "mysql", ""},
		{"whitespace only", "postgres", " \n\t"},
		{"comment only", "mysql", "/* ordinary */ -- tail"},
		{"unterminated mysql string", "mysql", "SELECT 'abc"},
		{"unterminated mysql quoted identifier", "mysql", "SELECT `abc"},
		{"unterminated mysql block comment", "mysql", "SELECT 1 /* abc"},
		{"unterminated postgres string", "postgres", "SELECT 'abc"},
		{"unterminated postgres escape string", "postgres", "SELECT E'abc"},
		{"unterminated postgres quoted identifier", "postgres", `SELECT "abc`},
		{"unterminated postgres block comment", "postgres", "SELECT 1 /* abc"},
		{"unterminated postgres dollar quote", "postgres", "SELECT $tag$abc"},
		{"unknown dialect", "sqlite", "SELECT 1"},
		{"dialect is case sensitive", "MYSQL", "SELECT 1"},
		{"invalid utf8", "mysql", invalidUTF8},
		{"embedded nul", "postgres", "SELECT 1\x00; DROP TABLE users"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SqlNormalize(tc.sql, tc.dialect)
			if ok || got != "" {
				t.Fatalf("SqlNormalize(%q, %q) = (%q, %v), want empty/false", tc.sql, tc.dialect, got, ok)
			}
		})
	}
}

func TestSqlNormalizeRejectsMySQLExecutableAndHintComments(t *testing.T) {
	cases := []struct {
		name, sql string
	}{
		{"executable leading", "/*!40101 SET @x = 1 */ SELECT 1"},
		{"hint leading", "/*+ BKA(t) */ SELECT * FROM t"},
		{"executable canonical", "SELECT /*! STRAIGHT_JOIN */ * FROM t"},
		{"hint canonical token", "SELECT /*+ BKA(t) */ * FROM t"},
		{"executable middle", "SELECT 1 /*! + 2 */ + 3"},
		{"hint middle", "SELECT 1 /*+ BKA(t) */ + 2"},
		{"executable trailing", "SELECT 1 /*!40101 + 2 */"},
		{"hint trailing", "SELECT 1 /*+ BKA(t) */"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SqlNormalize(tc.sql, "mysql")
			if ok || got != "" {
				t.Fatalf("SqlNormalize(%q) = (%q, %v), want empty/false", tc.sql, got, ok)
			}
		})
	}
}

func TestSqlNormalizeAllowsCommentMarkersInsideOpaqueTokens(t *testing.T) {
	cases := []struct {
		name, sql, want string
	}{
		{
			name: "strings",
			sql:  "SELECT '/*! executable lookalike */', '/*+ hint lookalike */'",
			want: "select '/*! executable lookalike */' , '/*+ hint lookalike */'",
		},
		{
			name: "quoted identifiers",
			sql:  "SELECT `/*! executable lookalike */`, `/*+ hint lookalike */`",
			want: "select `/*! executable lookalike */` , `/*+ hint lookalike */`",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SqlNormalize(tc.sql, "mysql")
			if !ok {
				t.Fatalf("SqlNormalize(%q) denied", tc.sql)
			}
			if got != tc.want {
				t.Fatalf("SqlNormalize(%q) = %q, want %q", tc.sql, got, tc.want)
			}
		})
	}
}

func TestSqlNormalizeClassifierCollisionRegressions(t *testing.T) {
	cases := []struct {
		name, dialect, left, right string
	}{
		{"mysql backslash versus doubled quote string", "mysql", `SELECT 'a\\\'b'`, `SELECT 'a''b'`},
		{"postgres escape string case", "postgres", "SELECT E'AbC'", "SELECT E'abc'"},
		{"mysql hex string case", "mysql", "SELECT X'AB'", "SELECT X'ab'"},
		{"postgres hex string case", "postgres", "SELECT X'AB'", "SELECT X'ab'"},
		{"integer leading zero", "mysql", "SELECT 1", "SELECT 01"},
		{"scientific notation exponent case", "postgres", "SELECT 1e5", "SELECT 1E5"},
		{"postgres quoted identifier case", "postgres", `SELECT "CaseSensitive"`, `SELECT "casesensitive"`},
		{"mysql quoted identifier case", "mysql", "SELECT `CaseSensitive`", "SELECT `casesensitive`"},
		{"postgres non-ascii identifier case", "postgres", "SELECT CAFÉ", "SELECT café"},
		{"postgres positional parameter spelling", "postgres", "SELECT $1", "SELECT $01"},
		{"mysql parameter spelling", "mysql", "SELECT @First", "SELECT @Second"},
		{"comparison operator spelling", "postgres", "SELECT a != b", "SELECT a <> b"},
		// A reserved word is legal after `.` as an unquoted MySQL identifier, and lower_case_table_names=0
		// makes qualified table names case-sensitive, so `db.INTERSECT` and `db.intersect` are DISTINCT
		// tables. sqlglot-go's reserved set includes INTERSECT, so folding it after a dot would collapse
		// two different tables onto one grant hash — an
		// authorization escalation. The dot guard preserves word case after `.`.
		{"mysql reserved word qualified table name after dot", "mysql", "SELECT * FROM db.INTERSECT", "SELECT * FROM db.intersect"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertNormalizesDistinct(t, tc.dialect, tc.left, tc.right)
		})
	}
}

func TestSqlNormalizePostgresUsesASCIIFolding(t *testing.T) {
	upper, upperOK := SqlNormalize("SELECT CAFÉ", "postgres")
	lower, lowerOK := SqlNormalize("SELECT café", "postgres")
	if !upperOK || !lowerOK {
		t.Fatalf("normalization denied: upper=(%q, %v) lower=(%q, %v)", upper, upperOK, lower, lowerOK)
	}
	if upper != "select cafÉ" || lower != "select café" {
		t.Fatalf("normalized values = (%q, %q), want (%q, %q)", upper, lower, "select cafÉ", "select café")
	}
	if upper == lower {
		t.Fatalf("ASCII-only identifiers collided: %q", upper)
	}
}

func TestSqlNormalizeIsLexerOnly(t *testing.T) {
	got, ok := SqlNormalize("SELECT (1", "postgres")
	if !ok {
		t.Fatal("lexically complete SQL was denied because it is syntactically invalid")
	}
	if got != "select ( 1" {
		t.Fatalf("SqlNormalize returned %q, want %q", got, "select ( 1")
	}
}

func assertNormalizesDistinct(t *testing.T, dialect, leftSQL, rightSQL string) {
	t.Helper()
	left, leftOK := SqlNormalize(leftSQL, dialect)
	right, rightOK := SqlNormalize(rightSQL, dialect)
	if !leftOK || !rightOK {
		t.Fatalf("normalization denied: left=(%q, %v) right=(%q, %v)", left, leftOK, right, rightOK)
	}
	if left == right {
		t.Fatalf("distinct SQL collided at %q: left=%q right=%q", left, leftSQL, rightSQL)
	}
}
