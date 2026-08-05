package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.classification.SystemClassificationStore
import com.ridi.oss.proxymonster.classification.SystemTag
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * FAIL-CLOSED completeness guard for the utility/command gate (the emission-completeness leak class).
 *
 * `Admission.utilityFacts` hand-recognizes the statements that perform a manifest command id; the shipped
 * `system:` policy then gates them. Three consecutive access-model audits each found a DIFFERENT dangerous
 * command that `utilityFacts` failed to emit — so it relayed verbatim as a passthrough (SET PERSIST;
 * SHOW CREATE USER, which leaks the service account's password hash; SHOW GRANTS; SHOW REPLICA STATUS). The
 * hand-maintained subset kept leaking. This test closes the CLASS: it enumerates EVERY `system:critical` /
 * `system:data-leak` / `system:activity` command id in EVERY shipped manifest and requires each to be either
 *   (a) DENIED through the real `decideQuery` by a representative statement (analyst principal: has
 *       datasource.connect + sql.select + a users read, but NO sql.ddl / admin — so a dangerous command
 *       denies via the utility gate, the sql.<kind> gate, the OTHER-bucket, or a structural admission deny),
 *       or
 *   (b) on the explicit [INTENTIONAL_PASSTHROUGH] allowlist with a documented reason.
 *
 * A NEW manifest command id (a future engine version, a new dangerous statement) with no sample and no
 * passthrough entry FAILS this test — forcing a deliberate decision instead of a silent relay. That is the
 * structural fix the per-id emission patches only chip at.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ManifestCommandCoverageDbTest {
    private lateinit var pg: EnforcementFixture
    private lateinit var my: EnforcementFixture
    private val classifier = SystemClassificationService()

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        pg = EnforcementFixture.postgres()
        my = EnforcementFixture.mysql()
    }

    private enum class Eng { PG, MY }

    private fun fxOf(eng: Eng) = if (eng == Eng.PG) pg else my

    private fun setEngineVersion(eng: Eng, version: String?) {
        val fx = fxOf(eng)
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET engine_version = ? WHERE id = ?").use { ps ->
                ps.setString(1, version); ps.setLong(2, fx.datasource.id); ps.executeUpdate()
            }
        }
    }

    private fun decide(eng: Eng, sql: String, who: String = "analyst@example.com"): EnfAction =
        decideFull(eng, sql, who).action

    private fun decideFull(eng: Eng, sql: String, who: String = "analyst@example.com"): DecisionContext {
        val fx = fxOf(eng)
        return decideQuery(
            principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            systemClassification = classifier,
        )
    }

    // One representative statement per dangerous command id + the engine to decide it on. The completeness
    // assertion below proves this map ∪ INTENTIONAL_PASSTHROUGH covers every manifest dangerous command, so a
    // missing entry is a test failure, not a silent relay. Statements need only ADMIT + decide (they are
    // never executed — a dangerous command denies before it reaches the backend).
    private val samples: Map<String, Pair<Eng, String>> = mapOf(
        // MySQL — account / privilege administration.
        "SET_PASSWORD" to (Eng.MY to "SET PASSWORD = 'x'"),
        "CREATE_USER" to (Eng.MY to "CREATE USER u IDENTIFIED BY 'p'"),
        "ALTER_USER" to (Eng.MY to "ALTER USER u IDENTIFIED BY 'p'"),
        "DROP_USER" to (Eng.MY to "DROP USER u"),
        "GRANT" to (Eng.MY to "GRANT ALL ON *.* TO u"),
        "REVOKE" to (Eng.MY to "REVOKE ALL ON *.* FROM u"),
        "RENAME_USER" to (Eng.MY to "RENAME USER a TO b"),
        "SET_DEFAULT_ROLE" to (Eng.MY to "SET DEFAULT ROLE r TO u"),
        // MySQL — server-state mutation.
        "SET_GLOBAL" to (Eng.MY to "SET GLOBAL max_connections = 1"),
        "SET_PERSIST" to (Eng.MY to "SET PERSIST max_connections = 5000"),
        "SET_PERSIST_ONLY" to (Eng.MY to "SET PERSIST_ONLY max_connections = 5000"),
        "RESET_PERSIST" to (Eng.MY to "RESET PERSIST"),
        "ALTER_INSTANCE" to (Eng.MY to "ALTER INSTANCE ROTATE INNODB MASTER KEY"),
        "CLONE_INSTANCE" to (Eng.MY to "CLONE INSTANCE FROM 'u'@'h':3306 IDENTIFIED BY 'p'"),
        "RESTART" to (Eng.MY to "RESTART"),
        "SHUTDOWN" to (Eng.MY to "SHUTDOWN"),
        // MySQL — replication / binlog.
        "CHANGE_REPLICATION_SOURCE" to (Eng.MY to "CHANGE REPLICATION SOURCE TO SOURCE_HOST = 'h'"),
        "RESET_REPLICA" to (Eng.MY to "RESET REPLICA"),
        "PURGE_BINARY_LOGS" to (Eng.MY to "PURGE BINARY LOGS TO 'mysql-bin.000001'"),
        // MySQL — code loading.
        "INSTALL_PLUGIN" to (Eng.MY to "INSTALL PLUGIN x SONAME 'y.so'"),
        "UNINSTALL_PLUGIN" to (Eng.MY to "UNINSTALL PLUGIN x"),
        "INSTALL_COMPONENT" to (Eng.MY to "INSTALL COMPONENT 'file://x'"),
        "UNINSTALL_COMPONENT" to (Eng.MY to "UNINSTALL COMPONENT 'file://x'"),
        "CREATE_FUNCTION_SONAME" to (Eng.MY to "CREATE FUNCTION x RETURNS INTEGER SONAME 'y.so'"),
        "DROP_FUNCTION_SONAME" to (Eng.MY to "DROP FUNCTION x"),
        // MySQL — file IO (server-side read/write, an exfil surface).
        "INTO_OUTFILE" to (Eng.MY to "SELECT rrn FROM users INTO OUTFILE '/tmp/x'"),
        "INTO_DUMPFILE" to (Eng.MY to "SELECT rrn FROM users INTO DUMPFILE '/tmp/x'"),
        "LOAD_DATA" to (Eng.MY to "LOAD DATA INFILE '/tmp/x' INTO TABLE t"),
        "LOAD_XML" to (Eng.MY to "LOAD XML INFILE '/tmp/x' INTO TABLE t"),
        // MySQL — data-bearing SHOW (the emission-leak class this guard protects).
        "SHOW_CREATE_USER" to (Eng.MY to "SHOW CREATE USER CURRENT_USER()"),
        "SHOW_GRANTS" to (Eng.MY to "SHOW GRANTS"),
        "SHOW_BINLOG_EVENTS" to (Eng.MY to "SHOW BINLOG EVENTS"),
        "SHOW_RELAYLOG_EVENTS" to (Eng.MY to "SHOW RELAYLOG EVENTS"),
        "SHOW_ENGINE_STATUS" to (Eng.MY to "SHOW ENGINE INNODB STATUS"),
        "SHOW_WARNINGS" to (Eng.MY to "SHOW WARNINGS"),
        "SHOW_ERRORS" to (Eng.MY to "SHOW ERRORS"),
        "SHOW_PROCESSLIST" to (Eng.MY to "SHOW PROCESSLIST"),
        "SHOW_REPLICA_STATUS" to (Eng.MY to "SHOW REPLICA STATUS"),
        // PostgreSQL.
        "PG_ALTER_SYSTEM" to (Eng.PG to "ALTER SYSTEM SET work_mem = '1MB'"),
        "PG_ALTER_ROLE_PASSWORD" to (Eng.PG to "ALTER ROLE r PASSWORD 'x'"),
        "PG_CREATE_USER_MAPPING" to (Eng.PG to "CREATE USER MAPPING FOR u SERVER s OPTIONS (user 'x')"),
        "PG_ALTER_SERVER" to (Eng.PG to "ALTER SERVER s OPTIONS (SET host 'h')"),
        "PG_COPY_PROGRAM" to (Eng.PG to "COPY users TO PROGRAM 'cat > /tmp/x'"),
        // Session-identity / lexer-mode SETs — the "engine-safety" danger set. The analyzer resolves these
        // carrying a system-classified Utility grant (not a hard admission deny), so the system:critical
        // floor forbids them through the same gate as SET_GLOBAL/SET_PASSWORD.
        "SET_ROLE" to (Eng.PG to "SET ROLE analyst"),
        "SET_SESSION_AUTHORIZATION" to (Eng.PG to "SET SESSION AUTHORIZATION bob"),
        "SET_STANDARD_CONFORMING_STRINGS" to (Eng.PG to "SET standard_conforming_strings = off"),
        "SET_SQL_MODE" to (Eng.MY to "SET sql_mode = 'ANSI_QUOTES'"),
        // Code-executing / data-reading danger set: a user-type/DOMAIN cast runs the type's coercion
        // function; a subquery / unsafe-function RHS in a SET / SHOW reads data outside a plain query. Each
        // resolves carrying a system:critical Utility grant (the whole-statement gate; column-level masking
        // of the read is backlogged).
        "USER_TYPE_CAST" to (Eng.PG to "SELECT 'x'::public.evil_domain"),
        "SET_SUBQUERY" to (Eng.MY to "SET @x = (SELECT rrn FROM users)"),
        "SHOW_SUBQUERY" to (Eng.MY to "SHOW TABLES WHERE Tables_in_db IN (SELECT rrn FROM users)"),
    )

    // Manifest command ids DELIBERATELY kept passthrough: their statements are needed by ordinary clients
    // (psql/mysql issue them at connect), and they expose server config/counters rather than data/credentials.
    // The manifest tag is over-broad relative to the intended enforcement here — documented, not a leak.
    private val INTENTIONAL_PASSTHROUGH: Map<String, String> = mapOf(
        "SHOW_VARIABLES" to "server config; clients issue SHOW [SESSION] VARIABLES at connect — gating breaks them",
        "SHOW_STATUS" to "server counters (Uptime/Threads_connected); clients poll it — low sensitivity",
        "PG_SHOW_GUC" to "psql issues SHOW <guc> (e.g. SHOW search_path) routinely — gating breaks the client",
    )

    @Test
    fun `every manifest dangerous command is gated (or documented passthrough) — fail-closed emission guard`() {
        val store = SystemClassificationStore.load()
        val gated = setOf(SystemTag.CRITICAL, SystemTag.DATA_LEAK, SystemTag.ACTIVITY)
        // Completeness: every dangerous command id across every shipped manifest MUST have a coverage sample
        // or an explicit passthrough entry. A new manifest command with neither fails HERE.
        val uncovered = mutableListOf<String>()
        for (engine in listOf("postgres", "mysql")) {
            for (c in store.classifiersForEngine(engine)) {
                for (cmd in c.manifest.commands) {
                    val tag = SystemTag.fromId(cmd.tag) ?: continue
                    if (tag !in gated) continue
                    if (cmd.id !in samples && cmd.id !in INTENTIONAL_PASSTHROUGH) uncovered += "$engine:${cmd.id} (${cmd.tag})"
                }
            }
        }
        assertTrue(
            uncovered.isEmpty(),
            "manifest dangerous command(s) with NO decideQuery coverage sample and NO documented passthrough — " +
                "add a sample (must DENY) or an INTENTIONAL_PASSTHROUGH entry, else it relays un-gated: $uncovered",
        )

        // Enforcement, exercised on BOTH datasource states so the DENY is proven via the real gate on each:
        //   - CERTIFIED (a shipped engine_version) → a utility-emitted command denies via its manifest
        //     `system:` tag forbid (critical unconditional; data-leak/activity floor-denied), and the
        //     non-utility ones via the sql.<kind>/OTHER/admission gates; and
        //   - NO-MANIFEST (null engine_version) → a utility-emitted command denies via the unclassified
        //     hard-deny (Query.kt), the non-utility ones unchanged.
        // Running both means a typo'd/wrong emitted command id is caught (it would pass ONLY the no-manifest
        // branch, not the certified tag-forbid), and it proves no dangerous command relays on either state.
        val certified = mapOf(Eng.PG to "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc", Eng.MY to "8.0.44")
        for ((state, versionFor) in listOf("certified" to certified, "no-manifest" to emptyMap<Eng, String>())) {
            setEngineVersion(Eng.PG, versionFor[Eng.PG]); setEngineVersion(Eng.MY, versionFor[Eng.MY])
            for ((id, spec) in samples) {
                val (eng, sql) = spec
                assertEquals(EnfAction.DENY, decide(eng, sql), "[$state] $id must DENY on the production floor: [$eng] $sql")
            }
        }
        // The activity/critical distinction is real: on a CERTIFIED datasource with the system:development
        // relaxation, SHOW REPLICA STATUS (system:activity) is relaxed to ALLOW, but SHOW CREATE USER /
        // SHOW GRANTS (system:critical) are NEVER relaxed — proving the emitted commands carry the right tag,
        // not just "some deny". (No-manifest can't distinguish these — both hard-deny unclassified.)
        setEngineVersion(Eng.MY, "8.0.44")
        setDevPreset(Eng.MY, true)
        assertEquals(EnfAction.ALLOW, decide(Eng.MY, "SHOW REPLICA STATUS"), "SHOW REPLICA STATUS (activity) relaxes on a dev datasource")
        assertEquals(EnfAction.DENY, decide(Eng.MY, "SHOW CREATE USER CURRENT_USER()"), "SHOW CREATE USER (critical) is NEVER relaxed, even on dev")
        assertEquals(EnfAction.DENY, decide(Eng.MY, "SHOW GRANTS"), "SHOW GRANTS (critical) is NEVER relaxed, even on dev")
        setDevPreset(Eng.MY, false)
    }

    private fun setDevPreset(eng: Eng, on: Boolean) {
        val fx = fxOf(eng)
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET tags = ?::jsonb WHERE id = ?").use { ps ->
                ps.setString(1, if (on) """["system:development"]""" else """["system:production"]"""); ps.setLong(2, fx.datasource.id); ps.executeUpdate()
            }
        }
    }

    @Test
    fun `SELECT INTO OUTFILE cannot exfil a masked column even with the file and ddl grants`() {
        // INTO OUTFILE classifies its kind as select_into_outfile (stmt.cat.admin.file) and its datasource verb
        // as ddl. The real exfil concern is a principal who clears BOTH: filewriter@example.com has admin.file +
        // ddl + the same users grants analyst has, so `SELECT rrn INTO OUTFILE` passes the kind gate and the verb
        // loop, resolves rrn to MASKED at column authorization, and must then be denied by the write-payload rule
        // — the OUTFILE analog of the CTAS write-payload check. (A ddl-only principal kind-denies at admin.file
        // before ever reaching this rule, which is why the test needs the file+ddl grant to exercise it.)
        val r = decideFull(Eng.MY, "SELECT rrn FROM users INTO OUTFILE '/tmp/x'", who = "filewriter@example.com")
        assertEquals(EnfAction.DENY, r.action, "INTO OUTFILE of a masked column must DENY (write-payload rule), not exfil cleartext")
        assertTrue(
            r.denyReason.orEmpty().contains("write references protected") && r.denyReason.orEmpty().contains("rrn"),
            "must deny at the write-payload rule, not the kind gate: ${r.denyReason}",
        )
    }
}
