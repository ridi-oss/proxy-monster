package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** High-value lineage and classification regressions through the production StatementFacts grant loop. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GateSqlglotRegressionTest {
    private lateinit var postgres: EnforcementFixture
    private lateinit var mysql: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        postgres = EnforcementFixture.postgres()
        mysql = EnforcementFixture.mysql()
    }

    private fun denied(fixture: EnforcementFixture, sql: String, principal: String = "analyst@example.com") {
        val result = fixture.run(sql, principal)
        assertEquals(EnfAction.DENY, result.decision, "must deny: $sql; ${result.denyReason}")
        assertTrue(result.rows.isEmpty())
    }

    @Test
    fun `reference and membership oracles deny on both engines`() {
        for (fixture in listOf(postgres, mysql)) {
            denied(fixture, "select id from users where rrn = 'secret'")
            denied(fixture, "select id from users where email in (select rrn from users)")
            denied(fixture, "select region from users intersect select rrn from users")
        }
    }

    @Test
    fun `unknown table and UNION TABLE forms fail closed`() {
        for (fixture in listOf(postgres, mysql)) {
            denied(fixture, "select * from no_such_table")
            denied(fixture, "select 0,'x','x','x' union table users")
        }
    }

    @Test
    fun `derived transforms redact while row-shaping use denies`() {
        for (fixture in listOf(postgres, mysql)) {
            val redacted = fixture.run("select id, upper(rrn) from users")
            assertEquals(EnfAction.MASK, redacted.decision, redacted.denyReason)
            assertTrue(redacted.rows.all { it[1] == null })
            denied(fixture, "select id from users order by rrn")
        }
    }

    @Test
    fun `query-to-xml and session-state exfiltration stay closed`() {
        denied(postgres, "select query_to_xml('SELECT rrn FROM users', true, false, '')")
        denied(mysql, "set @x=(select rrn from users)")
    }

    @Test
    fun `cast or typed literal to a user type denies through the production walk`() {
        // A user DOMAIN/type coercion runs its check function on the shared backend session (code exec +
        // error-oracle leak). The Go analyzer marks it INADMISSIBLE; prove the control-plane walk denies.
        for (sql in listOf(
            "SELECT CAST('x' AS public.pm_leak_domain)",
            "SELECT 'x'::public.pm_leak_domain",
            "SELECT 1::public.pm_leak_domain FROM users",
        )) {
            denied(postgres, sql)
        }
    }

    @Test
    fun `schema-qualified user function denies through the production walk`() {
        // public.version() is user code, not the safe metadata version() — a user function shadowing a
        // safe name is an exfil vector, so the qualified Function grant must hard-deny.
        denied(postgres, "SELECT public.version()")
        denied(postgres, "SELECT pm_leak.upper('x')")
    }

    @Test
    fun `non-literal sql_mode assignment denies on MySQL`() {
        // A session variable / CONCAT RHS can flip the lexer (ANSI_QUOTES) while the analyzer keeps parsing
        // the default dialect — INADMISSIBLE, must deny end-to-end.
        denied(mysql, "SET sql_mode = @m")
        denied(mysql, "SET sql_mode = CONCAT('AN','SI_QUOTES')")
        denied(mysql, "SET SESSION sql_mode = @m")
    }

    @Test
    fun `MySQL ANSI_QUOTES masks a double-quoted pii column, default mode leaves it a string literal`() {
        // Under sql_mode=ANSI_QUOTES the backend reads `"rrn"` as
        // the pii column rrn, not a string. Told liveAnsiQuotes=true, the analyzer parses it the same way, so
        // the CP must MASK it instead of skipping it as a literal — this is the whole reason the proxy can now
        // forward an ANSI_QUOTES session instead of failing it closed. Without the flag (default mode) `"rrn"`
        // is the constant string 'rrn' (no pii column touched) → ALLOW. Proving BOTH directions proves the
        // flag is what flips the decision, closing the cleartext-via-quoting bypass. This exercises the CP
        // liveAnsiQuotes threading (decideQuery → EngineConfig.mysqlAnsiQuotes) through the real analyzer.
        val ds = mysql.datasource
        val catalog = mysql.datasourceStore.catalog(ds.id)
        fun decide(ansiQuotes: Boolean) = decideQuery(
            "analyst@example.com", ds, """SELECT "rrn" FROM users""", Channel.WIRE, catalog,
            mysql.policyStore, mysql.accessStore, mysql.userGroupStore, mysql.roleResolver, mysql.authz,
            liveAnsiQuotes = ansiQuotes,
        )

        val masked = decide(true)
        assertEquals(EnfAction.MASK, masked.action, "ANSI_QUOTES: `\"rrn\"` must mask the pii column; ${masked.denyReason}")
        assertTrue(masked.masks.any { it.column == "rrn" }, "the rrn mask must be selected under ANSI_QUOTES")

        val allowed = decide(false)
        assertEquals(EnfAction.ALLOW, allowed.action, "default mode: `\"rrn\"` is a string literal, not the pii column; ${allowed.denyReason}")
        assertTrue(allowed.masks.isEmpty(), "default mode must select no mask for a quoted string literal")
    }

    @Test
    fun `explain of query and reset master deny through the production walk`() {
        // EXPLAIN TABLE analyzes SELECT * over the ungranted orders table; DESC ANALYZE plans the inner
        // query (an EXPLAIN alias that executes) and inherits its verdict; RESET MASTER is administrative.
        denied(mysql, "EXPLAIN TABLE orders")
        denied(postgres, "DESC ANALYZE SELECT rrn FROM users")
        denied(mysql, "RESET MASTER")
        denied(postgres, """SELECT U&"set_confi\0067"('search_path','restricted',false)""")
    }

    @Test
    fun `results-charset NULL is pinned to utf8mb4 through the real analyzer`() {
        // Real analyzer -> decideQuery seam for issue #81: Connector/J's session-init is recognized and
        // emitted as rewrittenSql on the session passthrough. A non-NULL charset is left for the wire
        // invariant to fail closed, not pinned.
        val pinned = mysql.decide("SET character_set_results = NULL")
        assertEquals(EnfAction.ALLOW, pinned.action, pinned.denyReason)
        assertEquals("SET character_set_results = utf8mb4", pinned.rewrittenSql)
        assertEquals(null, mysql.decide("SET character_set_results = latin1").rewrittenSql)
    }
}
