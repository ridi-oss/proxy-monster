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
            denied(fixture, "select id from users where ssn = 'secret'")
            denied(fixture, "select id from users where email in (select ssn from users)")
            denied(fixture, "select region from users intersect select ssn from users")
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
            val redacted = fixture.run("select id, upper(ssn) from users")
            assertEquals(EnfAction.MASK, redacted.decision, redacted.denyReason)
            assertTrue(redacted.rows.all { it[1] == null })
            denied(fixture, "select id from users order by ssn")
        }
    }

    @Test
    fun `query-to-xml and session-state exfiltration stay closed`() {
        denied(postgres, "select query_to_xml('SELECT ssn FROM users', true, false, '')")
        denied(mysql, "set @x=(select ssn from users)")
    }

    @Test
    fun `cast or typed literal to a user type denies through the production walk`() {
        // A user DOMAIN/type coercion runs its check function on the shared target-DB session (code exec +
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
        // Under sql_mode=ANSI_QUOTES the target DB reads `"ssn"` as
        // the pii column ssn, not a string. Told liveAnsiQuotes=true, the analyzer parses it the same way, so
        // the CP must MASK it instead of skipping it as a literal — this is the whole reason the proxy can now
        // forward an ANSI_QUOTES session instead of failing it closed. Without the flag (default mode) `"ssn"`
        // is the constant string 'ssn' (no pii column touched) → ALLOW. Proving BOTH directions proves the
        // flag is what flips the decision, closing the cleartext-via-quoting bypass. This exercises the CP
        // liveAnsiQuotes threading (decideQuery → EngineConfig.mysqlAnsiQuotes) through the real analyzer.
        val ds = mysql.datasource
        val catalog = mysql.datasourceStore.catalog(ds.id)
        fun decide(ansiQuotes: Boolean) = decideQuery(
            "analyst@example.com", ds, """SELECT "ssn" FROM users""", Channel.WIRE, catalog,
            mysql.policyStore, mysql.accessStore, mysql.userGroupStore, mysql.roleResolver, mysql.authz,
            liveAnsiQuotes = ansiQuotes,
        )

        val masked = decide(true)
        assertEquals(EnfAction.MASK, masked.action, "ANSI_QUOTES: `\"ssn\"` must mask the pii column; ${masked.denyReason}")
        assertTrue(masked.masks.any { it.column == "ssn" }, "the ssn mask must be selected under ANSI_QUOTES")

        val allowed = decide(false)
        assertEquals(EnfAction.ALLOW, allowed.action, "default mode: `\"ssn\"` is a string literal, not the pii column; ${allowed.denyReason}")
        assertTrue(allowed.masks.isEmpty(), "default mode must select no mask for a quoted string literal")
    }

    @Test
    fun `explain of an ungranted table and reset master deny through the production walk`() {
        // EXPLAIN TABLE analyzes SELECT * over the ungranted orders table, so its columns resolve DENIED;
        // RESET MASTER is administrative. (A plan-only EXPLAIN of a GRANTED read is exercised separately.)
        denied(mysql, "EXPLAIN TABLE orders")
        // EXPLAIN TABLE gates as a read (stmt.kind.explain), not metadata: the explainer role holds
        // cat.read and NO cat.metadata, so this ALLOW pins the category move.
        val planned = mysql.decide("EXPLAIN TABLE users", principal = "explainer@example.com")
        assertEquals(EnfAction.ALLOW, planned.action, "a read grant clears EXPLAIN TABLE: ${'$'}{planned.denyReason}")
        assertTrue(planned.masks.isEmpty(), "a released plan binds no masks")
        denied(mysql, "RESET MASTER")
        denied(postgres, """SELECT U&"set_confi\0067"('search_path','restricted',false)""")
    }

    @Test
    fun `EXPLAIN of a read runs unmasked whether or not ANALYZE, masked predicate and executing writes still deny`() {
        for (fixture in listOf(postgres, mysql)) {
            // An EXPLAIN of a read returns the query PLAN, not rows — the projection masks have no cell to
            // bind to, so an authorized (masked) read runs unmasked. ANALYZE of a read returns a plan too, so
            // it behaves the same (its exact cardinality is closed by the predicate rule below).
            for (sql in listOf("EXPLAIN SELECT id, ssn FROM users", "EXPLAIN ANALYZE SELECT id, ssn FROM users")) {
                val d = fixture.decide(sql)
                assertEquals(EnfAction.ALLOW, d.action, "$sql must run: ${d.denyReason}")
                assertTrue(d.masks.isEmpty(), "$sql binds no result-stream masks")
            }
            assertTrue(
                fixture.decide("EXPLAIN SELECT id, ssn FROM users").piiTouched.isNotEmpty(),
                "an allowed EXPLAIN still records the touched PII column for audit",
            )
            // A masked column in a PREDICATE / JOIN leaks its selectivity, so it needs result.read.unmasked
            // (which the analyst lacks) — denied, EXPLAIN or not.
            assertEquals(EnfAction.DENY, fixture.decide("EXPLAIN SELECT id FROM users WHERE ssn = 'secret'").action, "masked predicate under EXPLAIN → deny")
            assertEquals(EnfAction.DENY, fixture.decide("EXPLAIN SELECT u.id FROM users u JOIN users v ON u.ssn = v.ssn").action, "masked JOIN key under EXPLAIN → deny")
        }
        // MySQL accepts a parenthesized target (a Subquery wrapper); still a plan-only read EXPLAIN.
        assertEquals(EnfAction.ALLOW, mysql.decide("EXPLAIN (SELECT id, ssn FROM users)").action, "parenthesized EXPLAIN must run")
        assertEquals(EnfAction.ALLOW, mysql.decide("EXPLAIN ANALYZE (SELECT id, ssn FROM users)").action, "parenthesized EXPLAIN ANALYZE of a read must run")
        // PostgreSQL's wrapped ANALYZE of a read, across the JVM↔Go FFM boundary.
        assertEquals(EnfAction.ALLOW, postgres.decide("EXPLAIN (ANALYZE, FORMAT JSON) SELECT id, ssn FROM users").action, "wrapped EXPLAIN ANALYZE of a read must run")
        // An executing EXPLAIN ANALYZE of a WRITE carries the write's own kind, so a read-only analyst (no
        // write grant) is denied at the kind gate — it is the DELETE, not a plan lookup.
        assertEquals(EnfAction.DENY, postgres.decide("EXPLAIN ANALYZE DELETE FROM users WHERE id = 1").action, "EXPLAIN ANALYZE of a write authorizes as the write → deny for a reader")
    }

    @Test
    fun `context stmt_kind lets a policy unmask a masked predicate only under a plan-only EXPLAIN`() {
        for (fixture in listOf(postgres, mysql)) {
            // The explainer role holds result.read.unmasked ONLY when context.stmt_kind == "explain".
            val explained = fixture.decide("EXPLAIN SELECT id FROM users WHERE ssn = 'secret'", principal = "explainer@example.com")
            assertEquals(EnfAction.ALLOW, explained.action, "the stmt_kind policy unmasks the ssn predicate under EXPLAIN: ${explained.denyReason}")
            // The same predicate in a row-returning SELECT keeps ssn masked (the policy does not fire) → deny.
            val selected = fixture.decide("SELECT id FROM users WHERE ssn = 'secret'", principal = "explainer@example.com")
            assertEquals(EnfAction.DENY, selected.action, "the stmt_kind policy must NOT unmask a row-returning SELECT")
        }
    }

    @Test
    fun `EXPLAIN ANALYZE of a materializing write is denied by the payload even for a writer holding the explain-unmask`() {
        // explainer holds write.insert + ddl AND result.read.unmasked when stmt_kind == "explain" — the exact
        // adversary for the materialize-PII bypass. An EXPLAIN ANALYZE that copies masked ssn into another
        // table carries the WRITE kind, not "explain", so the unmask does NOT fire and the write-payload
        // DENY_STATEMENT denies. (If the read-vs-write classification regressed, ssn would resolve unmasked
        // and the CTAS/INSERT…SELECT would execute — this test flips to ALLOW and fails.) The reason must be
        // the payload DENY_STATEMENT ("cannot be masked"), not the generic ordinal-bounds structural deny —
        // every EXPLAIN grant binds no ordinal, so a masked write must reach the payload path to deny.
        fun assertPayloadDeny(fixture: EnforcementFixture, sql: String) {
            val d = fixture.decide(sql, principal = "explainer@example.com")
            assertEquals(EnfAction.DENY, d.action, "$sql must deny by the write payload")
            assertTrue(
                d.denyReason?.contains("cannot be masked") == true,
                "$sql must deny via the write-payload DENY_STATEMENT, not a structural check: ${d.denyReason}",
            )
        }
        for (fixture in listOf(postgres, mysql)) {
            assertPayloadDeny(fixture, "EXPLAIN ANALYZE INSERT INTO users (ssn) SELECT ssn FROM users")
        }
        assertPayloadDeny(postgres, "EXPLAIN ANALYZE CREATE TABLE leak AS SELECT ssn FROM users")
    }

    @Test
    fun `EXPLAIN of a write whose source columns the writer can read runs — no structural ordinal deny`() {
        // A CTAS EXPLAIN is a write with projection origins; every EXPLAIN grant must bind an empty ordinal so
        // it does not collide with the empty output_columns. explainer reads id/region unmasked (non-pii) and
        // holds ddl, so an EXPLAIN [ANALYZE] of a CTAS over only those columns must run. (Before the ordinals
        // were stripped for write EXPLAINs, the ordinal-bounds contract check hard-denied every CTAS EXPLAIN.)
        for (sql in listOf(
            "EXPLAIN CREATE TABLE leak AS SELECT id, region FROM users",
            "EXPLAIN ANALYZE CREATE TABLE leak AS SELECT id, region FROM users",
        )) {
            val d = postgres.decide(sql, principal = "explainer@example.com")
            assertEquals(EnfAction.ALLOW, d.action, "$sql must run: ${d.denyReason}")
        }
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
