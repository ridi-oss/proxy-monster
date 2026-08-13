package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Dangerous-function enforcement on real PostgreSQL/MySQL + real Cedar (docs/facts-emission.md).
 * Enforcement runs entirely through the
 * control-plane function gate, backed by the per-version manifest AND the version-independent
 * [com.ridi.oss.proxymonster.classification.BaselineDangerousFunctions] floor.
 *
 * The datasource here grants `analyst@example.com` a read on `users` (the EnforcementFixture pattern), so a
 * FROM'd function-of-literals over `users` scans the table UNCOVERED but the table gate PASSES — meaning a
 * DENY is attributable to the FUNCTION gate, not a missing table grant (proven by the `now()`/`count(*)`
 * baseline over the same table ALLOWing). Every former `dangerousFuncs` name is asserted DENY:
 *   - on a GOVERNED datasource (engine_version set)     → the manifest classifies it; and
 *   - on a NO-manifest datasource (engine_version null) → the baseline floor classifies it.
 * That per-state parity is the security property the hardcode provided, now provided by policy.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class BaselineDangerousFunctionEnforcementDbTest {
    private lateinit var pg: EnforcementFixture
    private lateinit var my: EnforcementFixture
    private val principal = "analyst@example.com"
    private val classifier = SystemClassificationService()

    private val pg17 = "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc"
    private val mysql80 = "8.0.44"

    // Former probe.go dangerousFuncs, PostgreSQL members (load_file is MySQL, asserted separately). Each
    // used WITH a FROM (mirrors the real gated shape; the no-FROM form is denied earlier by Admission.kt's
    // unchanged allowlist). Args are shape-only — the statement is never executed; it DENYs at decide time.
    private val pgDangerousCalls = listOf(
        "dblink('c', 'SELECT 1')",
        "dblink_exec('c', 'SELECT 1')",
        "dblink_open('c')",
        "dblink_fetch('c')",
        "dblink_send_query('c', 'SELECT 1')",
        "pg_read_file('/etc/passwd')",
        "pg_read_binary_file('/etc/passwd')",
        "pg_ls_dir('/')",
        "pg_stat_file('/etc/passwd')",
        "lo_import('/etc/passwd')",
        "lo_export(16384, '/tmp/x')",
        "query_to_xml('SELECT 1', true, false, '')",
        "query_to_xml_and_xmlschema('SELECT 1', true, false, '')",
        "xpath_table('a', 'b', 'c', 'd', 'e')",
    )

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        pg = EnforcementFixture.postgres()
        my = EnforcementFixture.mysql()
    }

    private fun configure(fx: EnforcementFixture, version: String?, tags: List<String>) {
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET engine_version = ?, tags = ?::jsonb WHERE id = ?").use { ps ->
                ps.setString(1, version)
                ps.setString(2, tags.joinToString(prefix = "[", postfix = "]") { "\"$it\"" })
                ps.setLong(3, fx.datasource.id)
                ps.executeUpdate()
            }
        }
    }

    private fun decide(fx: EnforcementFixture, sql: String, who: String = principal) = decideQuery(
        principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
        systemClassification = classifier,
    )

    @Test
    fun `a null classifier service STILL denies a dangerous builtin via the static baseline`() {
        // Retiring the analyzer dangerousFuncs walk left a latent fail-open: the function gate was guarded by
        // `systemClassification != null`, so a decideQuery caller that wired NO classifier service skipped the
        // gate entirely and relayed a dangerous builtin. The fix classifies via the STATIC
        // BaselineDangerousFunctions when no service is present. (Every production path passes a service today;
        // this proves the floor holds even if one didn't.)
        configure(pg, pg17, listOf("system:production"))
        fun decideNoService(sql: String) = decideQuery(
            principal = principal, ds = pg.datasourceStore.get(pg.datasource.id)!!, sql = sql, channel = Channel.WIRE,
            catalog = pg.datasourceStore.catalog(pg.datasource.id), policyStore = pg.policyStore, accessStore = pg.accessStore,
            userGroupStore = pg.userGroupStore, roleResolver = pg.roleResolver, authz = pg.authz,
            systemClassification = null, // no service wired
        ).action
        assertEquals(EnfAction.ALLOW, decideNoService("select now() from users"), "a safe function must still ALLOW with no service (no over-deny)")
        assertEquals(EnfAction.DENY, decideNoService("select pg_read_file('/etc/passwd') from users"), "a dangerous builtin DENIES via the static baseline even with no classifier service")
        assertEquals(EnfAction.DENY, decideNoService("select dblink_exec('x') from users"), "a critical baseline function DENIES with no service")
    }

    @Test
    fun `every former dangerousFuncs name denies WITH a FROM on a governed PG datasource`() {
        configure(pg, pg17, listOf("system:production"))
        // The table gate is not the reason: a safe function over the SAME readable table ALLOWs.
        assertEquals(EnfAction.ALLOW, decide(pg, "select now() from users").action, "safe function baseline must ALLOW")
        for (call in pgDangerousCalls) {
            val ctx = decide(pg, "select $call from users")
            assertEquals(EnfAction.DENY, ctx.action, "governed PG: '$call' must DENY (manifest function forbid)")
            assertTrue(ctx.detail?.contains("dangerous system function") == true, "DENY names the function gate: ${ctx.detail}")
        }
    }

    @Test
    fun `every former dangerousFuncs name STILL denies on a no-manifest PG datasource (the baseline)`() {
        configure(pg, null, listOf("system:production")) // no engine_version → no governing manifest → baseline floor only
        // The user table stays readable without a manifest, so a safe function over it ALLOWs — the DENYs
        // below are the baseline function forbid, not a table-scan deny.
        assertEquals(EnfAction.ALLOW, decide(pg, "select now() from users").action, "no-manifest safe function must still ALLOW")
        for (call in pgDangerousCalls) {
            val ctx = decide(pg, "select $call from users")
            assertEquals(EnfAction.DENY, ctx.action, "no-manifest PG: '$call' must STILL DENY (baseline floor)")
            assertTrue(ctx.detail?.contains("dangerous system function") == true, "DENY names the function gate: ${ctx.detail}")
        }
    }

    // Dangerous PG functions the shipped manifest classifies (exact + `functionFamilies` prefixes) but the
    // hand-curated 15-name baseline floor MISSED — the cleartext-PII leak class. Each is a
    // whole-table/page/large-object/target DB reader that reads data INVISIBLE to lineage (its data source is a
    // string/regclass/oid arg, not a scanned column), so on a no-manifest datasource a flat 15-name baseline
    // would return null → ALLOW → the target DB would stream e.g. the entire `users` table as XML incl. cleartext ssn.
    private val pgManifestOnlyDangerousCalls = listOf(
        "table_to_xml('public.users'::regclass, true, false, '')", // table_to_xml* family (the canonical dump)
        "query_to_xmlschema('SELECT ssn FROM users', true, false, '')", // query_to_xml* family (NOT the baseline's two exact names)
        "get_raw_page('users', 0)",          // pageinspect, exact
        "pg_terminate_backend(1)",           // critical, exact
        "lo_get(16384)",                     // large-object read, exact
    )

    @Test
    fun `manifest-only dangerous functions deny on a no-manifest datasource via the union floor`() {
        // A no-manifest datasource does not fall back to the thin 15-name baseline for functions —
        // it unions classifyBareFunction across every SHIPPED manifest of the engine (pg 16 ∪ 17), so the
        // manifest's whole dangerous set (incl. the `table_to_xml*`/pageinspect/`lo_*` families) classifies
        // there too. Parity: each call DENIES on a no-manifest datasource AND on a certified one.
        for (version in listOf(null, "PostgreSQL 15.6 on x86_64-pc-linux-gnu", pg17)) {
            configure(pg, version, listOf("system:production"))
            val label = version ?: "no-manifest"
            assertEquals(EnfAction.ALLOW, decide(pg, "select now() from users").action, "[$label] safe fn still ALLOWs (no over-deny)")
            for (call in pgManifestOnlyDangerousCalls) {
                val ctx = decide(pg, "select $call from users")
                assertEquals(EnfAction.DENY, ctx.action, "[$label]: '$call' must DENY (union floor / manifest function forbid)")
                assertTrue(ctx.detail?.contains("dangerous system function") == true, "[$label] DENY names the function gate: ${ctx.detail}")
            }
        }
    }

    @Test
    fun `safe functions and a user UDF are unaffected by the function gate`() {
        configure(pg, pg17, listOf("system:production"))
        // now()/count(*) over the readable table, lower() over a non-pii column, and an unclassified user
        // UDF all pass — the gate is specific to the dangerous set, not "any function".
        assertEquals(EnfAction.ALLOW, decide(pg, "select now() from users").action, "now() unaffected")
        assertEquals(EnfAction.ALLOW, decide(pg, "select count(*) from users").action, "count(*) unaffected")
        assertEquals(EnfAction.ALLOW, decide(pg, "select lower(email) from users").action, "lower(email) unaffected")
        assertEquals(EnfAction.ALLOW, decide(pg, "select my_udf(id) from users").action, "a user UDF is not classified/denied")
    }

    @Test
    fun `a dangerous function is denied on a preset-development datasource, not relayed via sql-unanalyzable`() {
        // The improvement: before this change dangerousFuncs made a FROM'd dangerous call resolved=false, so
        // on a dev datasource that permits exception.unanalyzable it RELAYED VERBATIM (executing the function). Now
        // the call resolves + emits a function fact + is forbidden by the function gate. A `system:critical`
        // function (lo_export) is forbidden UNCONDITIONALLY (V25 -130), even under system:development.
        configure(pg, pg17, listOf("system:development"))
        // Control: the exception.unanalyzable relay path IS live on this dev datasource — an actually-unanalyzable
        // statement (NATURAL JOIN) is relayed verbatim (ALLOW, passthrough). This is the path the dangerous
        // call would take without the function gate.
        val relay = decide(pg, "select count(*) from orders natural join users")
        assertEquals(EnfAction.ALLOW, relay.action, "dev datasource relays an unanalyzable statement via exception.unanalyzable")
        assertTrue(relay.passthrough, "the unanalyzable relay is a verbatim passthrough")
        // Improvement (RESOLVED forms only): a projected/scalar dangerous call RESOLVES + emits a function
        // fact → DENIED by the function gate, NOT relayed, even on dev (lo_export is critical → V25 -130).
        val ctx = decide(pg, "select lo_export(16384, '/tmp/x') from users")
        assertEquals(EnfAction.DENY, ctx.action, "a resolved critical function is denied on dev, not relayed verbatim")
        assertTrue(ctx.detail?.contains("dangerous system function") == true, "the DENY is the function gate, not the relay: ${ctx.detail}")

        // RESOLVED=FALSE forms: the set-returning shape
        // `SELECT * FROM dblink(...)` analyzes resolved=false (unexpandable *), but the analyzer emits the
        // function fact even on a post-parse failure, so the unanalyzable gate runs the SAME function policy
        // the resolved path does — BEFORE the exception.unanalyzable relay.
        // - dblink is system:data-leak → the system:development relaxation applies (consistent with a RESOLVED
        //   dblink on dev), so it proceeds to the verbatim relay.
        val dataLeak = decide(pg, "select * from dblink('h','SELECT 1') as t(c text)")
        assertEquals(EnfAction.ALLOW, dataLeak.action, "a resolved=false data-leak function follows the dev relaxation, consistent with the resolved form")
        assertTrue(dataLeak.passthrough, "the data-leak dev relaxation proceeds to the exception.unanalyzable verbatim relay")
        // - but a system:critical function (dblink_exec) hiding in a resolved=false statement DENIES even on a
        //   system:development datasource — the function gate runs ahead of the exception.unanalyzable relay, so a
        //   critical builtin is NEVER relayed verbatim (V25 -130 is unconditional). This is the residue CLOSED.
        val critical = decide(pg, "select dblink_exec('c','s') from users natural join users")
        assertEquals(EnfAction.DENY, critical.action, "a resolved=false critical function is denied even on a system:development datasource (not relayed via exception.unanalyzable)")
        assertTrue(critical.detail?.contains("dangerous system function") == true, "the DENY is the function gate, not the relay: ${critical.detail}")
        // Both resolved=false forms DENY on the production floor (no exception.unanalyzable permit).
        configure(pg, pg17, listOf("system:production"))
        assertEquals(EnfAction.DENY, decide(pg, "select * from dblink('h','SELECT 1') as t(c text)").action, "resolved=false data-leak denies on the floor")
        assertEquals(EnfAction.DENY, decide(pg, "select dblink_exec('c','s') from users natural join users").action, "resolved=false critical denies on the floor")
        // BOUNDARY (explicit, not a gap this closes): the backfill only fires on a POST-PARSE failure — a
        // statement that sqlglot cannot PARSE (p.root == nil) emits no function facts, so a critical builtin in
        // a parse-failing statement the target DB still accepts takes the exception.unanalyzable verbatim relay on a
        // system:development datasource (it DENIES on the floor). That is the accepted `exception.unanalyzable ⊇ exec`
        // posture an operator opts into with system:development — pre-existing, unclosable via function facts,
        // and the multi-statement route into it is already shut (admission rejects >1-statement batches).
    }

    @Test
    fun `MySQL load_file denies WITH a FROM on both a governed and a no-manifest datasource`() {
        // Governed: the manifest classifies load_file (__builtin__) system:data-leak.
        configure(my, mysql80, listOf("system:production"))
        assertEquals(EnfAction.ALLOW, decide(my, "select count(*) from users").action, "safe function baseline must ALLOW")
        assertEquals(EnfAction.DENY, decide(my, "select load_file('/etc/passwd') from users").action, "governed MySQL: load_file must DENY")
        // No governing manifest: an uncertified but parseable MySQL version keeps analysis live while
        // selecting no shipped classifier, so this still isolates the version-independent baseline floor.
        configure(my, "5.7.44", listOf("system:production"))
        assertEquals(EnfAction.ALLOW, decide(my, "select count(*) from users").action, "no-manifest safe function must still ALLOW")
        assertEquals(EnfAction.DENY, decide(my, "select load_file('/etc/passwd') from users").action, "no-manifest MySQL: load_file must STILL DENY (baseline)")
    }
}
