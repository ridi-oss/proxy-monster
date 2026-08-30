package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig as PbEngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig
import com.ridi.oss.proxymonster.grpc.Engine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The batch split must cut only at real statement boundaries and hand back verbatim slices: the
 * control-plane stores, hashes, and authorizes each statement it returns, so a boundary the engine
 * would not draw (a `;` inside a literal) or a regenerated statement would authorize text nobody
 * wrote. Anything unsplittable is null — the caller denies.
 */
class SplitStatementsTest {
    private val mysql = engineConfig {
        engine = Engine.MYSQL
        engineVersion = "8.0.46"
        mysqlLowerCaseTableNames = 1
    }
    private val postgres = engineConfig {
        engine = Engine.POSTGRES
        engineVersion = "16.0"
    }

    @Test fun `splits at statement boundaries`() {
        for (d in listOf(mysql, postgres)) {
            assertEquals(listOf("SELECT 1"), splitStatements("SELECT 1", d), "[$d] single statement")
            assertEquals(listOf("SELECT 1"), splitStatements("SELECT 1;", d), "[$d] trailing terminator")
            assertEquals(listOf("SELECT 1", "SELECT 2"), splitStatements("SELECT 1; SELECT 2", d), "[$d] pair")
            assertEquals(
                listOf("SELECT 1", "SELECT 2"),
                splitStatements("SELECT 1;;\n\n SELECT 2;\n", d),
                "[$d] blank segments are dropped",
            )
        }
    }

    @Test fun `a semicolon inside a literal or comment is not a boundary`() {
        for (d in listOf(mysql, postgres)) {
            assertEquals(
                listOf("SELECT 'a;b' FROM users", "SELECT 2"),
                splitStatements("SELECT 'a;b' FROM users; SELECT 2", d),
                "[$d] literal",
            )
            assertEquals(
                listOf("SELECT /* a;b */ 1", "SELECT 2"),
                splitStatements("SELECT /* a;b */ 1; SELECT 2", d),
                "[$d] block comment",
            )
        }
        assertEquals(
            listOf("SELECT `a;b` FROM t", "SELECT 2"),
            splitStatements("SELECT `a;b` FROM t; SELECT 2", mysql),
            "quoted identifier",
        )
        assertEquals(
            listOf("CREATE FUNCTION f() RETURNS int AS \$\$ BEGIN; RETURN 1; END; \$\$ LANGUAGE plpgsql", "SELECT 2"),
            splitStatements(
                "CREATE FUNCTION f() RETURNS int AS \$\$ BEGIN; RETURN 1; END; \$\$ LANGUAGE plpgsql; SELECT 2",
                postgres,
            ),
            "dollar-quoted body",
        )
    }

    @Test fun `every statement is a verbatim slice of the batch`() {
        val batch = "SELECT `a;b`,  'x'  FROM t WHERE id = 1;\n  UPDATE t SET c = 'p;q' WHERE id = 2"
        val statements = assertNotNull(splitStatements(batch, mysql), "expected a split for: $batch")
        for (statement in statements) {
            assertTrue(batch.contains(statement), "not a verbatim slice of the batch: $statement")
        }
    }

    @Test fun `each split statement analyzes as a single statement`() {
        val statements = assertNotNull(
            splitStatements("SELECT 'a;b' FROM users; UPDATE users SET name = 'x' WHERE id = 1", mysql),
        )
        for (statement in statements) {
            assertEquals(listOf(statement), splitStatements(statement, mysql), "re-split changed: $statement")
        }
    }

    // An incomplete config must never fall back to a default tokenizer: base reads `a;b` as TWO
    // statements where MySQL sees one quoted identifier, so it would draw a boundary the target does not.
    @Test fun `an unusable engine config fails closed`() {
        assertNull(splitStatements("SELECT 1", PbEngineConfig.getDefaultInstance()))
        assertNull(splitStatements("SELECT `a;b` FROM t; SELECT 2", PbEngineConfig.getDefaultInstance()))
        // MySQL analysis requires both; splitting under a partial config would use the wrong dialect.
        assertNull(splitStatements("SELECT 1", engineConfig { engine = Engine.MYSQL; engineVersion = "8.0.46" }))
        assertNull(
            splitStatements("SELECT 1", engineConfig { engine = Engine.MYSQL; mysqlLowerCaseTableNames = 1 }),
        )
    }

    // The dialect decides where a statement ends: under ANSI_QUOTES `"…"` is a quoted identifier, so the
    // `\` is literal, the quote closes, and the `;` splits — folding the DROP in would authorize it as
    // part of the SELECT.
    @Test fun `ansi quotes moves the boundary`() {
        val sql = """SELECT "a\" FROM t; DROP TABLE users; -- """"
        val ansi = engineConfig {
            engine = Engine.MYSQL
            engineVersion = "8.0.46"
            mysqlLowerCaseTableNames = 1
            mysqlAnsiQuotes = true
        }
        assertEquals(listOf("""SELECT "a\" FROM t""", "DROP TABLE users"), splitStatements(sql, ansi))
        assertEquals(1, assertNotNull(splitStatements(sql, mysql)).size)
    }

    @Test fun `unsplittable input fails closed`() {
        for (d in listOf(mysql, postgres)) {
            assertNull(splitStatements("", d), "[$d] empty")
            assertNull(splitStatements("   \n ", d), "[$d] blank")
            assertNull(splitStatements(";;;", d), "[$d] terminators only")
            assertNull(splitStatements("SELECT 'abc", d), "[$d] unterminated literal")
            assertNull(splitStatements("SELECT 1\u0000; SELECT 2", d), "[$d] embedded NUL")
        }
    }

    @Test
    fun `an unpaired surrogate denies rather than becoming a question mark`() {
        // Protobuf encodes an unpaired surrogate as `?`, so Go sees valid UTF-8 and cannot detect the
        // substitution: "SELECT '\uD800'" would come back as "SELECT '?'" — not a slice of the input.
        assertNull(splitStatements("SELECT '\uD800'; DROP TABLE users", mysql))
        assertNull(splitStatements("SELECT '\uDC00'", postgres))
        assertNotNull(splitStatements("SELECT '\uD83D\uDE00'; SELECT 2", mysql))
    }

    // MySQL runs a version-gated comment's body as SQL, so it must be authorized rather than dropped:
    // under a versionless dialect the body falls outside every span and never reaches a decision.
    @Test
    fun `a MySQL executable comment stays in its statement`() {
        assertEquals(
            listOf("SELECT 1", "/*!40101 DROP TABLE users */"),
            splitStatements("SELECT 1; /*!40101 DROP TABLE users */", mysql),
        )
        assertEquals(
            listOf("DELETE FROM users WHERE id=1 /*!80000 OR 1=1 */"),
            splitStatements("DELETE FROM users WHERE id=1 /*!80000 OR 1=1 */", mysql),
        )
        assertNotNull(splitStatements("SELECT 1; /* plain */", mysql))
    }
}
