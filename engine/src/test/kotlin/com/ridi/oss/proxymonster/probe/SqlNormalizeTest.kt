package com.ridi.oss.proxymonster.probe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The one-time query-grant hash must satisfy: same statement (up to whitespace / comments /
 * keyword-case, plus unquoted-identifier case on Postgres) → same hash; any material difference
 * (table, column, operator, literal, quoted identifier) → different hash; unlexable → null.
 * Style mirrors TokenTtlTest — loop over classes with input-echoing assert messages.
 */
class SqlNormalizeTest {
    private val base = "SELECT id FROM users WHERE ssn = '987-65-4320'"

    private fun eq(a: String, b: String, d: Dialect) {
        val ah = assertNotNull(sqlGrantHash(a, d), "[$d] expected non-null hash for a=$a")
        val bh = assertNotNull(sqlGrantHash(b, d), "[$d] expected non-null hash for b=$b")
        assertEquals(ah, bh, "[$d] expected EQUAL hash:\n  a=$a\n  b=$b")
    }

    private fun ne(a: String, b: String, d: Dialect) {
        val ah = assertNotNull(sqlGrantHash(a, d), "[$d] expected non-null hash for a=$a")
        val bh = assertNotNull(sqlGrantHash(b, d), "[$d] expected non-null hash for b=$b")
        assertNotEquals(ah, bh, "[$d] expected DIFFERENT hash:\n  a=$a\n  b=$b")
    }

    // ---- Hash-EQUAL classes ---------------------------------------------------------------

    @Test fun `whitespace, newlines and tabs are irrelevant`() {
        for (d in Dialect.values()) {
            eq(base, "SELECT   id\nFROM\tusers   WHERE ssn =  '987-65-4320'", d)
            eq(base, "  SELECT id FROM users WHERE ssn = '987-65-4320'  ", d)
        }
    }

    @Test fun `trailing semicolons are dropped`() {
        for (d in Dialect.values()) {
            eq(base, "$base;", d)
            eq(base, "$base;;", d)
            eq(base, "$base ; \n", d)
        }
    }

    @Test fun `keyword case is folded in both dialects`() {
        for (d in Dialect.values()) {
            eq(base, "select id from users where ssn = '987-65-4320'", d)
            eq(base, "SeLeCt id FrOm users WhErE ssn = '987-65-4320'", d)
        }
    }

    @Test fun `Postgres folds unquoted identifier case`() {
        eq(base, "SELECT ID FROM USERS WHERE SSN = '987-65-4320'", Dialect.POSTGRES)
    }

    @Test fun `line comments are stripped`() {
        // Postgres: `--` always a comment. MySQL: `--` needs trailing whitespace; `#` also comments.
        eq(base, "SELECT id FROM users -- pick a user\nWHERE ssn = '987-65-4320'", Dialect.POSTGRES)
        eq(base, "SELECT id FROM users -- c\rWHERE ssn = '987-65-4320'", Dialect.POSTGRES)
        eq(base, "SELECT id FROM users -- pick a user\nWHERE ssn = '987-65-4320'", Dialect.MYSQL)
        eq(base, "SELECT id FROM users -- c\rWHERE ssn = '987-65-4320'", Dialect.MYSQL)
        eq(base, "SELECT id FROM users # pick a user\nWHERE ssn = '987-65-4320'", Dialect.MYSQL)
        eq(base, "SELECT id FROM users # c\rWHERE ssn = '987-65-4320'", Dialect.MYSQL)
    }

    @Test fun `block comments are stripped, including mid-statement and multiline`() {
        for (d in Dialect.values()) {
            eq(base, "SELECT id /* c */ FROM users WHERE ssn = '987-65-4320'", d)
            eq(base, "SELECT id FROM users\n/* multi\n line\n comment */\nWHERE ssn = '987-65-4320'", d)
        }
    }

    @Test fun `Postgres nested block comments are stripped`() {
        eq(base, "SELECT id /* outer /* inner */ still */ FROM users WHERE ssn = '987-65-4320'", Dialect.POSTGRES)
    }

    // ---- Hash-DIFFERENT classes -----------------------------------------------------------

    @Test fun `a different table changes the hash`() {
        for (d in Dialect.values()) ne(base, "SELECT id FROM orders WHERE ssn = '987-65-4320'", d)
    }

    @Test fun `a different column changes the hash`() {
        for (d in Dialect.values()) ne(base, "SELECT email FROM users WHERE ssn = '987-65-4320'", d)
    }

    @Test fun `a different operator changes the hash`() {
        for (d in Dialect.values()) ne(base, "SELECT id FROM users WHERE ssn <> '987-65-4320'", d)
    }

    @Test fun `a different string literal changes the hash`() {
        for (d in Dialect.values()) {
            ne(base, "SELECT id FROM users WHERE ssn = '987-65-4322'", d)
            ne("SELECT id FROM users WHERE id = 1", "SELECT id FROM users WHERE id = 2", d)
        }
    }

    @Test fun `literal case and inner whitespace are preserved`() {
        for (d in Dialect.values()) {
            ne("SELECT 'abc'", "SELECT 'ABC'", d)
            ne("SELECT ' x '", "SELECT 'x'", d)
        }
    }

    @Test fun `a comment-lookalike inside a literal is preserved`() {
        for (d in Dialect.values()) ne("SELECT 'a--b'", "SELECT 'a'", d)
    }

    @Test fun `MySQL bare double-dash is arithmetic but Postgres is a comment`() {
        // Dialect divergence: MySQL `1--2` = 1-(-2) (two operators), Postgres `--2` is a comment.
        ne("SELECT 1--2", "SELECT 1", Dialect.MYSQL)
        eq("SELECT 1--2", "SELECT 1", Dialect.POSTGRES)
    }

    @Test fun `MySQL executable comments and optimizer hints fail closed`() {
        // Deliberate temporary posture until version-comment and hint content can be preserved safely.
        val executableComments = listOf(
            "/*!50000 SELECT 1 */",
            "SELECT /*!50000 SQL_NO_CACHE */ id FROM users",
            "SELECT id FROM users /*!50000 WHERE id = 1 */",
        )
        val optimizerHints = listOf(
            "/*+ MAX_EXECUTION_TIME(1000) */ SELECT 1",
            "SELECT /*+ NO_RANGE_OPTIMIZATION(users PRIMARY) */ id FROM users",
            "SELECT 1 /*+ SET_VAR(sort_buffer_size=16M) */",
        )
        for (sql in executableComments + optimizerHints) {
            assertNull(normalizeSql(sql, Dialect.MYSQL), "expected fail-closed normalization: $sql")
        }

        val versionMarkerLiteral = "SELECT '/*!50000 SELECT secret */'"
        val hintMarkerLiteral = "SELECT '/*+ MAX_EXECUTION_TIME(1000) */'"
        assertNotNull(sqlGrantHash(versionMarkerLiteral, Dialect.MYSQL))
        assertNotNull(sqlGrantHash(hintMarkerLiteral, Dialect.MYSQL))
        ne(versionMarkerLiteral, "SELECT '/*!50000 SELECT other */'", Dialect.MYSQL)
        ne(hintMarkerLiteral, "SELECT '/*+ MAX_EXECUTION_TIME(2000) */'", Dialect.MYSQL)
    }

    @Test fun `Postgres quoted identifier case is significant`() {
        ne("SELECT id FROM \"Users\"", "SELECT id FROM \"users\"", Dialect.POSTGRES)
    }

    @Test fun `MySQL preserves non-reserved identifier case (case-sensitive tables)`() {
        ne("SELECT id FROM Users", "SELECT id FROM users", Dialect.MYSQL)
        ne("SELECT id FROM `Users`", "SELECT id FROM `users`", Dialect.MYSQL)
    }

    @Test fun `Postgres dollar-quoted string body case is significant`() {
        ne("SELECT \$\$AbC\$\$", "SELECT \$\$abc\$\$", Dialect.POSTGRES)
        ne("SELECT \$t\$AbC\$t\$", "SELECT \$t\$abc\$t\$", Dialect.POSTGRES)
    }

    @Test fun `raw lexeme spellings cannot collide`() {
        // Decoded-equivalent escaped strings retain their distinct source spellings.
        ne("""SELECT 'a\'b'""", "SELECT 'a''b'", Dialect.MYSQL)
        ne("""SELECT E'a\nb'""", """SELECT E'a\012b'""", Dialect.POSTGRES)

        // Literal prefixes, numbers, and quoted identifiers remain byte-exact.
        ne("SELECT E'abc'", "SELECT e'abc'", Dialect.POSTGRES)
        ne("SELECT X'AB'", "SELECT x'AB'", Dialect.MYSQL)
        for (d in Dialect.values()) ne("SELECT 1", "SELECT 01", d)
        ne("SELECT 0xAB", "SELECT 0xab", Dialect.MYSQL)
        ne("SELECT \"Name\" FROM users", "SELECT \"name\" FROM users", Dialect.POSTGRES)
        ne("SELECT `Name` FROM users", "SELECT `name` FROM users", Dialect.MYSQL)

        // Dollar-quote delimiters, non-reserved MySQL words, operators, and non-ASCII identifiers differ.
        ne("SELECT \$\$abc\$\$", "SELECT \$tag\$abc\$tag\$", Dialect.POSTGRES)
        ne("SELECT Comment FROM users", "SELECT comment FROM users", Dialect.MYSQL)
        for (d in Dialect.values()) ne("SELECT id FROM users WHERE id != 1", "SELECT id FROM users WHERE id <> 1", d)
        ne("SELECT Ä FROM users", "SELECT ä FROM users", Dialect.POSTGRES)

        // Canonicalization still accepts and equates ordinary lexical-only differences.
        eq("SELECT value FROM t WHERE id = 1", " select value /* c */ from t where id=1 ; ", Dialect.POSTGRES)
    }

    // ---- Fail-closed (null) ---------------------------------------------------------------

    @Test fun `unterminated constructs normalize to null`() {
        for (d in Dialect.values()) {
            assertNull(normalizeSql("SELECT 'unterminated", d), "[$d] unterminated string")
            assertNull(normalizeSql("SELECT id /* unterminated", d), "[$d] unterminated block comment")
        }
        assertNull(normalizeSql("SELECT \$\$unterminated", Dialect.POSTGRES), "unterminated dollar-quote")
    }

    @Test fun `empty and content-free inputs normalize to null`() {
        for (d in Dialect.values()) {
            assertNull(normalizeSql("", d), "[$d] empty")
            assertNull(normalizeSql("   \n\t ", d), "[$d] whitespace-only")
            assertNull(normalizeSql(";", d), "[$d] semicolon-only")
            assertNull(normalizeSql(";;", d), "[$d] semicolons-only")
        }
        assertNull(normalizeSql("-- just a comment", Dialect.POSTGRES), "comment-only")
        assertNull(normalizeSql("# just a comment", Dialect.MYSQL), "MySQL comment-only")
    }

    @Test fun `embedded NUL and unpaired surrogates fail closed through the public API`() {
        val invalidInputs = listOf(
            "SELECT 1" + 0.toChar() + "SELECT 2",
            "SELECT '" + 0xD800.toChar() + "'",
            "SELECT '" + 0xDC00.toChar() + "'",
        )
        for (d in Dialect.values()) {
            for (sql in invalidInputs) {
                assertNull(normalizeSql(sql, d), "[$d] invalid input must not normalize")
                assertNull(sqlGrantHash(sql, d), "[$d] invalid input must not hash")
            }
        }
    }

    @Test fun `normalization is lexical and does not require parser coverage`() {
        for (d in Dialect.values()) {
            assertNotNull(normalizeSql("SELECT (((1", d), "[$d] lexically complete input")
        }
    }

    @Test fun `the hash is 64 lowercase hex chars`() {
        for (d in Dialect.values()) {
            val h = sqlGrantHash(base, d)!!
            assertTrue(h.matches(Regex("[0-9a-f]{64}")), "[$d] not 64 lowercase hex: $h")
        }
    }
}
