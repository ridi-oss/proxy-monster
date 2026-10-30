package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig
import com.ridi.oss.proxymonster.analyzer.pb.targetSettings
import com.ridi.oss.proxymonster.grpc.Engine
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

    private val MYSQL = engineConfig {
        engine = Engine.MYSQL
        target = targetSettings { engineVersion = "8.0.36"; mysqlLowerCaseTableNames = 0 }
    }
    private val POSTGRES = engineConfig { engine = Engine.POSTGRES }
    private val targets = listOf(MYSQL, POSTGRES, engineConfig { engine = Engine.ATHENA })

    private fun eq(a: String, b: String, d: EngineConfig) {
        val ah = assertNotNull(sqlGrantHash(a, d), "[${d.engine}] expected non-null hash for a=$a")
        val bh = assertNotNull(sqlGrantHash(b, d), "[${d.engine}] expected non-null hash for b=$b")
        assertEquals(ah, bh, "[${d.engine}] expected EQUAL hash:\n  a=$a\n  b=$b")
    }

    private fun ne(a: String, b: String, d: EngineConfig) {
        val ah = assertNotNull(sqlGrantHash(a, d), "[${d.engine}] expected non-null hash for a=$a")
        val bh = assertNotNull(sqlGrantHash(b, d), "[${d.engine}] expected non-null hash for b=$b")
        assertNotEquals(ah, bh, "[${d.engine}] expected DIFFERENT hash:\n  a=$a\n  b=$b")
    }

    // ---- Hash-EQUAL classes ---------------------------------------------------------------

    @Test fun `whitespace, newlines and tabs are irrelevant`() {
        for (d in targets) {
            eq(base, "SELECT   id\nFROM\tusers   WHERE ssn =  '987-65-4320'", d)
            eq(base, "  SELECT id FROM users WHERE ssn = '987-65-4320'  ", d)
        }
    }

    @Test fun `trailing semicolons are dropped`() {
        for (d in targets) {
            eq(base, "$base;", d)
            eq(base, "$base;;", d)
            eq(base, "$base ; \n", d)
        }
    }

    @Test fun `keyword case is folded in both dialects`() {
        for (d in targets) {
            eq(base, "select id from users where ssn = '987-65-4320'", d)
            eq(base, "SeLeCt id FrOm users WhErE ssn = '987-65-4320'", d)
        }
    }

    @Test fun `Postgres folds unquoted identifier case`() {
        eq(base, "SELECT ID FROM USERS WHERE SSN = '987-65-4320'", POSTGRES)
    }

    @Test fun `line comments are stripped`() {
        // Postgres: `--` always a comment. MySQL: `--` needs trailing whitespace; `#` also comments.
        eq(base, "SELECT id FROM users -- pick a user\nWHERE ssn = '987-65-4320'", POSTGRES)
        eq(base, "SELECT id FROM users -- c\rWHERE ssn = '987-65-4320'", POSTGRES)
        eq(base, "SELECT id FROM users -- pick a user\nWHERE ssn = '987-65-4320'", MYSQL)
        eq(base, "SELECT id FROM users -- c\rWHERE ssn = '987-65-4320'", MYSQL)
        eq(base, "SELECT id FROM users # pick a user\nWHERE ssn = '987-65-4320'", MYSQL)
        eq(base, "SELECT id FROM users # c\rWHERE ssn = '987-65-4320'", MYSQL)
    }

    @Test fun `block comments are stripped, including mid-statement and multiline`() {
        for (d in targets) {
            eq(base, "SELECT id /* c */ FROM users WHERE ssn = '987-65-4320'", d)
            eq(base, "SELECT id FROM users\n/* multi\n line\n comment */\nWHERE ssn = '987-65-4320'", d)
        }
    }

    @Test fun `Postgres nested block comments are stripped`() {
        eq(base, "SELECT id /* outer /* inner */ still */ FROM users WHERE ssn = '987-65-4320'", POSTGRES)
    }

    // ---- Hash-DIFFERENT classes -----------------------------------------------------------

    @Test fun `a different table changes the hash`() {
        for (d in targets) ne(base, "SELECT id FROM orders WHERE ssn = '987-65-4320'", d)
    }

    @Test fun `a different column changes the hash`() {
        for (d in targets) ne(base, "SELECT email FROM users WHERE ssn = '987-65-4320'", d)
    }

    @Test fun `a different operator changes the hash`() {
        for (d in targets) ne(base, "SELECT id FROM users WHERE ssn <> '987-65-4320'", d)
    }

    @Test fun `a different string literal changes the hash`() {
        for (d in targets) {
            ne(base, "SELECT id FROM users WHERE ssn = '987-65-4322'", d)
            ne("SELECT id FROM users WHERE id = 1", "SELECT id FROM users WHERE id = 2", d)
        }
    }

    @Test fun `literal case and inner whitespace are preserved`() {
        for (d in targets) {
            ne("SELECT 'abc'", "SELECT 'ABC'", d)
            ne("SELECT ' x '", "SELECT 'x'", d)
        }
    }

    @Test fun `a comment-lookalike inside a literal is preserved`() {
        for (d in targets) ne("SELECT 'a--b'", "SELECT 'a'", d)
    }

    @Test fun `MySQL bare double-dash is arithmetic but Postgres is a comment`() {
        // Dialect divergence: MySQL `1--2` = 1-(-2) (two operators), Postgres `--2` is a comment.
        ne("SELECT 1--2", "SELECT 1", MYSQL)
        eq("SELECT 1--2", "SELECT 1", POSTGRES)
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
            assertNull(normalizeSql(sql, MYSQL), "expected fail-closed normalization: $sql")
        }

        val versionMarkerLiteral = "SELECT '/*!50000 SELECT secret */'"
        val hintMarkerLiteral = "SELECT '/*+ MAX_EXECUTION_TIME(1000) */'"
        assertNotNull(sqlGrantHash(versionMarkerLiteral, MYSQL))
        assertNotNull(sqlGrantHash(hintMarkerLiteral, MYSQL))
        ne(versionMarkerLiteral, "SELECT '/*!50000 SELECT other */'", MYSQL)
        ne(hintMarkerLiteral, "SELECT '/*+ MAX_EXECUTION_TIME(2000) */'", MYSQL)
    }

    @Test fun `Postgres quoted identifier case is significant`() {
        ne("SELECT id FROM \"Users\"", "SELECT id FROM \"users\"", POSTGRES)
    }

    @Test fun `MySQL preserves non-reserved identifier case (case-sensitive tables)`() {
        ne("SELECT id FROM Users", "SELECT id FROM users", MYSQL)
        ne("SELECT id FROM `Users`", "SELECT id FROM `users`", MYSQL)
    }

    @Test fun `Postgres dollar-quoted string body case is significant`() {
        ne("SELECT \$\$AbC\$\$", "SELECT \$\$abc\$\$", POSTGRES)
        ne("SELECT \$t\$AbC\$t\$", "SELECT \$t\$abc\$t\$", POSTGRES)
    }

    @Test fun `raw lexeme spellings cannot collide`() {
        // Decoded-equivalent escaped strings retain their distinct source spellings.
        ne("""SELECT 'a\'b'""", "SELECT 'a''b'", MYSQL)
        ne("""SELECT E'a\nb'""", """SELECT E'a\012b'""", POSTGRES)

        // Literal prefixes, numbers, and quoted identifiers remain byte-exact.
        ne("SELECT E'abc'", "SELECT e'abc'", POSTGRES)
        ne("SELECT X'AB'", "SELECT x'AB'", MYSQL)
        for (d in targets) ne("SELECT 1", "SELECT 01", d)
        ne("SELECT 0xAB", "SELECT 0xab", MYSQL)
        ne("SELECT \"Name\" FROM users", "SELECT \"name\" FROM users", POSTGRES)
        ne("SELECT `Name` FROM users", "SELECT `name` FROM users", MYSQL)

        // Dollar-quote delimiters, non-reserved MySQL words, operators, and non-ASCII identifiers differ.
        ne("SELECT \$\$abc\$\$", "SELECT \$tag\$abc\$tag\$", POSTGRES)
        ne("SELECT Comment FROM users", "SELECT comment FROM users", MYSQL)
        for (d in targets) ne("SELECT id FROM users WHERE id != 1", "SELECT id FROM users WHERE id <> 1", d)
        ne("SELECT Ä FROM users", "SELECT ä FROM users", POSTGRES)

        // Canonicalization still accepts and equates ordinary lexical-only differences.
        eq("SELECT value FROM t WHERE id = 1", " select value /* c */ from t where id=1 ; ", POSTGRES)
    }

    // ---- Fail-closed (null) ---------------------------------------------------------------

    @Test fun `unterminated constructs normalize to null`() {
        for (d in targets) {
            assertNull(normalizeSql("SELECT 'unterminated", d), "[${d.engine}] unterminated string")
            assertNull(normalizeSql("SELECT id /* unterminated", d), "[${d.engine}] unterminated block comment")
        }
        assertNull(normalizeSql("SELECT \$\$unterminated", POSTGRES), "unterminated dollar-quote")
    }

    @Test fun `empty and content-free inputs normalize to null`() {
        for (d in targets) {
            assertNull(normalizeSql("", d), "[${d.engine}] empty")
            assertNull(normalizeSql("   \n\t ", d), "[${d.engine}] whitespace-only")
            assertNull(normalizeSql(";", d), "[${d.engine}] semicolon-only")
            assertNull(normalizeSql(";;", d), "[${d.engine}] semicolons-only")
        }
        assertNull(normalizeSql("-- just a comment", POSTGRES), "comment-only")
        assertNull(normalizeSql("# just a comment", MYSQL), "MySQL comment-only")
    }

    @Test fun `embedded NUL and unpaired surrogates fail closed through the public API`() {
        val invalidInputs = listOf(
            "SELECT 1" + 0.toChar() + "SELECT 2",
            "SELECT '" + 0xD800.toChar() + "'",
            "SELECT '" + 0xDC00.toChar() + "'",
        )
        for (d in targets) {
            for (sql in invalidInputs) {
                assertNull(normalizeSql(sql, d), "[${d.engine}] invalid input must not normalize")
                assertNull(sqlGrantHash(sql, d), "[${d.engine}] invalid input must not hash")
            }
        }
    }

    @Test fun `normalization is lexical and does not require parser coverage`() {
        for (d in targets) {
            assertNotNull(normalizeSql("SELECT (((1", d), "[${d.engine}] lexically complete input")
        }
    }

    @Test fun `the hash is 64 lowercase hex chars`() {
        for (d in targets) {
            val h = sqlGrantHash(base, d)!!
            assertTrue(h.matches(Regex("[0-9a-f]{64}")), "[${d.engine}] not 64 lowercase hex: $h")
        }
    }
}
