package engine

import (
	"regexp"
	"testing"
)

// Port of probe/SqlNormalizeTest.kt — 226 LOC, 24 cases.
//
// Header, quoted: "The one-time query-grant hash must satisfy: same statement (up to whitespace /
// comments / keyword-case, plus unquoted-identifier case on Postgres) → same hash; any material
// difference (table, column, operator, literal, quoted identifier) → different hash; unlexable → null."
//
// ⚠️ F21 — these 24 cases (43% of the area's 56) pin behaviour NOTHING CONSUMES: normalizeSql and
// sqlGrantHash have no production caller, and the sql_hash actually persisted on query_result is a raw
// SHA-256 of the SQL bytes. They are ported anyway because 13-engine.md's disposition is DEFER, not OMIT —
// only an explicit "the one-time query grant is not being built" retires the file and this suite together.
//
// ⚠️ They are also, almost entirely, assertions about analyzer/probe/sqlnormalize.go rather than about the
// 34-line Kotlin shim: the probe already has its own suite (analyzer/probe/sqlnormalize_test.go), so these
// are duplicated coverage of the probe plus first coverage of THIS layer's dialect mapping and hashing.
// 13-engine.md §6 asks for that duplication to be checked rather than assumed — it is real, and it is kept
// because the Kotlin suite is what the port ledger counts.

var bothDialects = []Dialect{DialectMySQL, DialectPostgres}

const normalizeBase = "SELECT id FROM users WHERE rrn = '900101-1234567'"

// eq/ne mirror the Kotlin helpers, including echoing the inputs in the failure message.
func eqHash(t *testing.T, a, b string, d Dialect) {
	t.Helper()
	ah, ok := SQLGrantHash(a, d)
	if !ok {
		t.Fatalf("[%v] expected non-null hash for a=%s", d, a)
	}
	bh, ok := SQLGrantHash(b, d)
	if !ok {
		t.Fatalf("[%v] expected non-null hash for b=%s", d, b)
	}
	if ah != bh {
		t.Errorf("[%v] expected EQUAL hash:\n  a=%s\n  b=%s", d, a, b)
	}
}

func neHash(t *testing.T, a, b string, d Dialect) {
	t.Helper()
	ah, ok := SQLGrantHash(a, d)
	if !ok {
		t.Fatalf("[%v] expected non-null hash for a=%s", d, a)
	}
	bh, ok := SQLGrantHash(b, d)
	if !ok {
		t.Fatalf("[%v] expected non-null hash for b=%s", d, b)
	}
	if ah == bh {
		t.Errorf("[%v] expected DIFFERENT hash:\n  a=%s\n  b=%s", d, a, b)
	}
}

func assertNoNormalization(t *testing.T, sql string, d Dialect, msg string) {
	t.Helper()
	if got, ok := NormalizeSQL(sql, d); ok {
		t.Errorf("[%v] %s: expected fail-closed, got %q", d, msg, got)
	}
}

// ---- Hash-EQUAL classes ---------------------------------------------------------------

// Case 1.
// KT: SqlNormalizeTest.kt#whitespace, newlines and tabs are irrelevant
func TestWhitespaceNewlinesAndTabsAreIrrelevant(t *testing.T) {
	for _, d := range bothDialects {
		eqHash(t, normalizeBase, "SELECT   id\nFROM\tusers   WHERE rrn =  '900101-1234567'", d)
		eqHash(t, normalizeBase, "  SELECT id FROM users WHERE rrn = '900101-1234567'  ", d)
	}
}

// Case 2.
// KT: SqlNormalizeTest.kt#trailing semicolons are dropped
func TestTrailingSemicolonsAreDropped(t *testing.T) {
	for _, d := range bothDialects {
		eqHash(t, normalizeBase, normalizeBase+";", d)
		eqHash(t, normalizeBase, normalizeBase+";;", d)
		eqHash(t, normalizeBase, normalizeBase+" ; \n", d)
	}
}

// Case 3.
// KT: SqlNormalizeTest.kt#keyword case is folded in both dialects
func TestKeywordCaseIsFoldedInBothDialects(t *testing.T) {
	for _, d := range bothDialects {
		eqHash(t, normalizeBase, "select id from users where rrn = '900101-1234567'", d)
		eqHash(t, normalizeBase, "SeLeCt id FrOm users WhErE rrn = '900101-1234567'", d)
	}
}

// Case 4.
// KT: SqlNormalizeTest.kt#Postgres folds unquoted identifier case
func TestPostgresFoldsUnquotedIdentifierCase(t *testing.T) {
	eqHash(t, normalizeBase, "SELECT ID FROM USERS WHERE RRN = '900101-1234567'", DialectPostgres)
}

// Case 5 — Postgres: `--` is always a comment. MySQL: `--` needs trailing whitespace; `#` also comments.
// KT: SqlNormalizeTest.kt#line comments are stripped
func TestLineCommentsAreStripped(t *testing.T) {
	eqHash(t, normalizeBase, "SELECT id FROM users -- pick a user\nWHERE rrn = '900101-1234567'", DialectPostgres)
	eqHash(t, normalizeBase, "SELECT id FROM users -- c\rWHERE rrn = '900101-1234567'", DialectPostgres)
	eqHash(t, normalizeBase, "SELECT id FROM users -- pick a user\nWHERE rrn = '900101-1234567'", DialectMySQL)
	eqHash(t, normalizeBase, "SELECT id FROM users -- c\rWHERE rrn = '900101-1234567'", DialectMySQL)
	eqHash(t, normalizeBase, "SELECT id FROM users # pick a user\nWHERE rrn = '900101-1234567'", DialectMySQL)
	eqHash(t, normalizeBase, "SELECT id FROM users # c\rWHERE rrn = '900101-1234567'", DialectMySQL)
}

// Case 6.
// KT: SqlNormalizeTest.kt#block comments are stripped, including mid-statement and multiline
func TestBlockCommentsAreStrippedIncludingMidStatementAndMultiline(t *testing.T) {
	for _, d := range bothDialects {
		eqHash(t, normalizeBase, "SELECT id /* c */ FROM users WHERE rrn = '900101-1234567'", d)
		eqHash(t, normalizeBase, "SELECT id FROM users\n/* multi\n line\n comment */\nWHERE rrn = '900101-1234567'", d)
	}
}

// Case 7.
// KT: SqlNormalizeTest.kt#Postgres nested block comments are stripped
func TestPostgresNestedBlockCommentsAreStripped(t *testing.T) {
	eqHash(t, normalizeBase, "SELECT id /* outer /* inner */ still */ FROM users WHERE rrn = '900101-1234567'", DialectPostgres)
}

// ---- Hash-DIFFERENT classes -----------------------------------------------------------

// Case 8.
// KT: SqlNormalizeTest.kt#a different table changes the hash
func TestADifferentTableChangesTheHash(t *testing.T) {
	for _, d := range bothDialects {
		neHash(t, normalizeBase, "SELECT id FROM orders WHERE rrn = '900101-1234567'", d)
	}
}

// Case 9.
// KT: SqlNormalizeTest.kt#a different column changes the hash
func TestADifferentColumnChangesTheHash(t *testing.T) {
	for _, d := range bothDialects {
		neHash(t, normalizeBase, "SELECT email FROM users WHERE rrn = '900101-1234567'", d)
	}
}

// Case 10.
// KT: SqlNormalizeTest.kt#a different operator changes the hash
func TestADifferentOperatorChangesTheHash(t *testing.T) {
	for _, d := range bothDialects {
		neHash(t, normalizeBase, "SELECT id FROM users WHERE rrn <> '900101-1234567'", d)
	}
}

// Case 11.
// KT: SqlNormalizeTest.kt#a different string literal changes the hash
func TestADifferentStringLiteralChangesTheHash(t *testing.T) {
	for _, d := range bothDialects {
		neHash(t, normalizeBase, "SELECT id FROM users WHERE rrn = '880315-2345678'", d)
		neHash(t, "SELECT id FROM users WHERE id = 1", "SELECT id FROM users WHERE id = 2", d)
	}
}

// Case 12.
// KT: SqlNormalizeTest.kt#literal case and inner whitespace are preserved
func TestLiteralCaseAndInnerWhitespaceArePreserved(t *testing.T) {
	for _, d := range bothDialects {
		neHash(t, "SELECT 'abc'", "SELECT 'ABC'", d)
		neHash(t, "SELECT ' x '", "SELECT 'x'", d)
	}
}

// Case 13 — 🔒 a comment-lookalike inside a literal is preserved.
// KT: SqlNormalizeTest.kt#a comment-lookalike inside a literal is preserved
func TestACommentLookalikeInsideALiteralIsPreserved(t *testing.T) {
	for _, d := range bothDialects {
		neHash(t, "SELECT 'a--b'", "SELECT 'a'", d)
	}
}

// Case 14 — the dialect-divergence case: MySQL `1--2` = 1-(-2) (two operators), Postgres `--2` is a
// comment.
// KT: SqlNormalizeTest.kt#MySQL bare double-dash is arithmetic but Postgres is a comment
func TestMySQLBareDoubleDashIsArithmeticButPostgresIsAComment(t *testing.T) {
	neHash(t, "SELECT 1--2", "SELECT 1", DialectMySQL)
	eqHash(t, "SELECT 1--2", "SELECT 1", DialectPostgres)
}

// Case 15 — 🔒 MySQL executable comments and optimizer hints fail closed. "Deliberate temporary posture
// until version-comment and hint content can be preserved safely."
// KT: SqlNormalizeTest.kt#MySQL executable comments and optimizer hints fail closed
func TestMySQLExecutableCommentsAndOptimizerHintsFailClosed(t *testing.T) {
	executableComments := []string{
		"/*!50000 SELECT 1 */",
		"SELECT /*!50000 SQL_NO_CACHE */ id FROM users",
		"SELECT id FROM users /*!50000 WHERE id = 1 */",
	}
	optimizerHints := []string{
		"/*+ MAX_EXECUTION_TIME(1000) */ SELECT 1",
		"SELECT /*+ NO_RANGE_OPTIMIZATION(users PRIMARY) */ id FROM users",
		"SELECT 1 /*+ SET_VAR(sort_buffer_size=16M) */",
	}
	for _, sql := range append(append([]string{}, executableComments...), optimizerHints...) {
		assertNoNormalization(t, sql, DialectMySQL, "expected fail-closed normalization: "+sql)
	}

	// The same markers INSIDE a literal still hash and stay distinct.
	versionMarkerLiteral := "SELECT '/*!50000 SELECT secret */'"
	hintMarkerLiteral := "SELECT '/*+ MAX_EXECUTION_TIME(1000) */'"
	if _, ok := SQLGrantHash(versionMarkerLiteral, DialectMySQL); !ok {
		t.Error("a version marker inside a literal must still hash")
	}
	if _, ok := SQLGrantHash(hintMarkerLiteral, DialectMySQL); !ok {
		t.Error("a hint marker inside a literal must still hash")
	}
	neHash(t, versionMarkerLiteral, "SELECT '/*!50000 SELECT other */'", DialectMySQL)
	neHash(t, hintMarkerLiteral, "SELECT '/*+ MAX_EXECUTION_TIME(2000) */'", DialectMySQL)
}

// Case 16.
// KT: SqlNormalizeTest.kt#Postgres quoted identifier case is significant
func TestPostgresQuotedIdentifierCaseIsSignificant(t *testing.T) {
	neHash(t, `SELECT id FROM "Users"`, `SELECT id FROM "users"`, DialectPostgres)
}

// Case 17.
// KT: SqlNormalizeTest.kt#MySQL preserves non-reserved identifier case (case-sensitive tables)
func TestMySQLPreservesNonReservedIdentifierCase(t *testing.T) {
	neHash(t, "SELECT id FROM Users", "SELECT id FROM users", DialectMySQL)
	neHash(t, "SELECT id FROM `Users`", "SELECT id FROM `users`", DialectMySQL)
}

// Case 18.
// KT: SqlNormalizeTest.kt#Postgres dollar-quoted string body case is significant
func TestPostgresDollarQuotedStringBodyCaseIsSignificant(t *testing.T) {
	neHash(t, "SELECT $$AbC$$", "SELECT $$abc$$", DialectPostgres)
	neHash(t, "SELECT $t$AbC$t$", "SELECT $t$abc$t$", DialectPostgres)
}

// Case 19 — 🔒 INV-A13-11, the widest case: raw lexeme spellings cannot collide.
// KT: SqlNormalizeTest.kt#raw lexeme spellings cannot collide
func TestRawLexemeSpellingsCannotCollide(t *testing.T) {
	// Decoded-equivalent escaped strings retain their distinct source spellings.
	neHash(t, `SELECT 'a\'b'`, "SELECT 'a''b'", DialectMySQL)
	neHash(t, `SELECT E'a\nb'`, `SELECT E'a\012b'`, DialectPostgres)

	// Literal prefixes, numbers, and quoted identifiers remain byte-exact.
	neHash(t, "SELECT E'abc'", "SELECT e'abc'", DialectPostgres)
	neHash(t, "SELECT X'AB'", "SELECT x'AB'", DialectMySQL)
	for _, d := range bothDialects {
		neHash(t, "SELECT 1", "SELECT 01", d)
	}
	neHash(t, "SELECT 0xAB", "SELECT 0xab", DialectMySQL)
	neHash(t, `SELECT "Name" FROM users`, `SELECT "name" FROM users`, DialectPostgres)
	neHash(t, "SELECT `Name` FROM users", "SELECT `name` FROM users", DialectMySQL)

	// Dollar-quote delimiters, non-reserved MySQL words, operators, and non-ASCII identifiers differ.
	neHash(t, "SELECT $$abc$$", "SELECT $tag$abc$tag$", DialectPostgres)
	neHash(t, "SELECT Comment FROM users", "SELECT comment FROM users", DialectMySQL)
	for _, d := range bothDialects {
		neHash(t, "SELECT id FROM users WHERE id != 1", "SELECT id FROM users WHERE id <> 1", d)
	}
	neHash(t, "SELECT Ä FROM users", "SELECT ä FROM users", DialectPostgres)

	// Canonicalization still accepts and equates ordinary lexical-only differences.
	eqHash(t, "SELECT value FROM t WHERE id = 1", " select value /* c */ from t where id=1 ; ", DialectPostgres)
}

// ---- Fail-closed (null) ---------------------------------------------------------------

// Case 20 — 🔒 INV-A13-10.
// KT: SqlNormalizeTest.kt#unterminated constructs normalize to null
func TestUnterminatedConstructsNormalizeToNull(t *testing.T) {
	for _, d := range bothDialects {
		assertNoNormalization(t, "SELECT 'unterminated", d, "unterminated string")
		assertNoNormalization(t, "SELECT id /* unterminated", d, "unterminated block comment")
	}
	assertNoNormalization(t, "SELECT $$unterminated", DialectPostgres, "unterminated dollar-quote")
}

// Case 21 — 🔒 empty and content-free inputs normalize to null.
// KT: SqlNormalizeTest.kt#empty and content-free inputs normalize to null
func TestEmptyAndContentFreeInputsNormalizeToNull(t *testing.T) {
	for _, d := range bothDialects {
		assertNoNormalization(t, "", d, "empty")
		assertNoNormalization(t, "   \n\t ", d, "whitespace-only")
		assertNoNormalization(t, ";", d, "semicolon-only")
		assertNoNormalization(t, ";;", d, "semicolons-only")
	}
	assertNoNormalization(t, "-- just a comment", DialectPostgres, "comment-only")
	assertNoNormalization(t, "# just a comment", DialectMySQL, "MySQL comment-only")
}

// Case 22 — 🔒 embedded NUL and unpaired surrogates fail closed through the PUBLIC API, both functions.
//
// Kotlin builds the unpaired surrogates as bare Chars ('\uD800'), which a Kotlin String can hold. A Go
// string cannot hold an unpaired surrogate as a valid rune, so they are written here as the raw WTF-8
// byte sequences a naive encoder would produce — which is what probe.SqlNormalize's utf8.ValidString
// guard rejects, the same fail-closed direction.
// KT: SqlNormalizeTest.kt#embedded NUL and unpaired surrogates fail closed through the public API
func TestEmbeddedNULAndUnpairedSurrogatesFailClosedThroughThePublicAPI(t *testing.T) {
	invalidInputs := []string{
		"SELECT 1" + string(rune(0)) + "SELECT 2",
		"SELECT '" + "\xed\xa0\x80" + "'", // U+D800 encoded as WTF-8: invalid UTF-8
		"SELECT '" + "\xed\xb0\x80" + "'", // U+DC00 encoded as WTF-8: invalid UTF-8
	}
	for _, d := range bothDialects {
		for _, sql := range invalidInputs {
			assertNoNormalization(t, sql, d, "invalid input must not normalize")
			if _, ok := SQLGrantHash(sql, d); ok {
				t.Errorf("[%v] invalid input must not hash", d)
			}
		}
	}
}

// Case 23.
// KT: SqlNormalizeTest.kt#normalization is lexical and does not require parser coverage
func TestNormalizationIsLexicalAndDoesNotRequireParserCoverage(t *testing.T) {
	for _, d := range bothDialects {
		if _, ok := NormalizeSQL("SELECT (((1", d); !ok {
			t.Errorf("[%v] lexically complete input must normalize", d)
		}
	}
}

// Case 24 — INV-A13-12.
// KT: SqlNormalizeTest.kt#the hash is 64 lowercase hex chars
func TestTheHashIs64LowercaseHexChars(t *testing.T) {
	hexOnly := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, d := range bothDialects {
		h, ok := SQLGrantHash(normalizeBase, d)
		if !ok {
			t.Fatalf("[%v] the base statement must hash", d)
		}
		if !hexOnly.MatchString(h) {
			t.Errorf("[%v] not 64 lowercase hex: %s", d, h)
		}
	}
	// The absence propagates from NormalizeSQL unchanged: never an empty string, never a hash of "".
	emptyHash, ok := SQLGrantHash("", DialectPostgres)
	if ok {
		t.Errorf("unlexable input must not hash, got %q", emptyHash)
	}
	if emptyHash != "" {
		t.Errorf("the failed hash must be the zero value, got %q", emptyHash)
	}
}

// The Dialect enum itself: two values, mapped to the probe's dialect strings. An out-of-range Dialect maps
// to "", which probe.SqlNormalize rejects — fail-closed, the same direction as the Kotlin catch-all.
func TestDialectMapping(t *testing.T) {
	if got := DialectMySQL.probeName(); got != "mysql" {
		t.Errorf("MYSQL → %q, want \"mysql\"", got)
	}
	if got := DialectPostgres.probeName(); got != "postgres" {
		t.Errorf("POSTGRES → %q, want \"postgres\"", got)
	}
	if _, ok := NormalizeSQL(normalizeBase, Dialect(99)); ok {
		t.Error("an out-of-range dialect must fail closed, not silently pick one")
	}
	if got := DialectMySQL.String(); got != "MYSQL" {
		t.Errorf("String() = %q, want the Kotlin enum constant name", got)
	}
}
