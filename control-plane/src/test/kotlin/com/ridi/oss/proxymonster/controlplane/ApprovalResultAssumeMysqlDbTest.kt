package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.StatementKind
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.grpc.columnMask
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** MySQL-leading proof that saved workflow results hold R's execution-enforced output and task.assume exposes R's live view. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApprovalResultAssumeMysqlDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var datasource: Datasource
    private var roleId = 0L
    private var prodViewerRoleId = 0L

    private val requester = "requester@example.com"
    private val approver = "approver@example.com"
    private val roleName = "system:production-pii-accessor"
    private val prodViewerRoleName = "system:production-viewer"
    private val rawSsn = "987-65-4320"
    private val maskedSsn = "*******4320"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
        roleId = fx.policyStore.listRoles().first { it.name == roleName }.id
        prodViewerRoleId = fx.policyStore.listRoles().first { it.name == prodViewerRoleName }.id
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET tags = ?::jsonb WHERE id = ?").use { ps ->
                ps.setString(1, "[\"system:production\"]")
                ps.setLong(2, fx.datasource.id)
                ps.executeUpdate()
            }
        }
        // -260 (production-metadata) enabled so SHOW CREATE TABLE / DESCRIBE re-decide as an authorized
        // metadata passthrough: statement-classification gates metadata on stmt.cat.metadata (closing the
        // old connect-only gap), so a viewer's re-decision of a stored SHOW now needs it too.
        listOf(-250L, -251L, -256L, -257L, -258L, -260L, -262L).forEach {
            checkNotNull(fx.cedarPolicyStore.setEnabled(it, true, "test-enable-production"))
        }
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "trusted-network-test",
                cedarSrc = """permit(principal, action == Action::"context.tag::trusted-network", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };""",
            ),
            updatedBy = "test-fixture",
        )
        datasource = checkNotNull(fx.datasourceStore.get(fx.datasource.id))
        assertTrue(fx.roleResolver.resolve(requester).isEmpty(), "the requester has no ambient PII role")
    }

    private fun decide(channel: Channel, ip: String): DecisionContext = decideQuery(
        principal = requester,
        ds = datasource,
        sql = "SELECT ssn FROM users",
        channel = channel,
        catalog = fx.datasourceStore.catalog(datasource.id),
        policyStore = fx.policyStore,
        accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore,
        roleResolver = fx.roleResolver,
        authz = fx.authz,
        providedRoles = setOf(roleName),
        context = AuthzContext(requesterIp = ip),
    )

    private fun viewerCtx(
        childSql: String?,
        ip: String,
        req: AccessRequest = request(),
        channel: Channel = Channel.WORKFLOW_VIEWER,
    ) = viewerDecision(
        requester, req, childSql, AuthzContext(requesterIp = ip),
        fx.datasourceStore, fx.policyStore, fx.accessStore, fx.userGroupStore, fx.roleResolver, fx.authz,
        null, channel,
    )!!

    private fun request(
        sql: String = "SELECT ssn FROM users",
        roleName: String = this.roleName,
        roleId: Long = this.roleId,
    ) = AccessRequest(
        id = 1,
        principal = requester,
        roleId = roleId,
        roleName = roleName,
        datasourceId = datasource.id,
        datasourceName = datasource.name,
        requestedDurationSec = 3600,
        status = "EXECUTED",
        decidedBy = approver,
        executedBy = approver,
        createdAt = "2026-07-23T00:00:00Z",
        kind = "QUERY",
        sql = sql,
        executeAs = listOf(roleName),
        creatorKind = "WORKFLOW",
    )

    @Test
    fun `requester assumes R and sees the shipped production view for their live network`() {
        assertEquals(
            AuthzDecision.Allow,
            fx.authz.authorize(
                requester,
                AuthzAction.TASK_ASSUME,
                AuthzResource.ApprovalRequest(
                    requester = requester,
                    approver = approver,
                    executedBy = approver,
                    datasourceName = datasource.name,
                    roleName = roleName,
                ),
            ),
        )
        // Freeze the execution-time requirement digest the way the real run does (R executing on the trusted
        // network), so the view's re-decision matches and the masks bind (an empty digest would fail closed as
        // a pre-fingerprint legacy result).
        val decrypted = DecryptedResult(
            listOf("ssn"),
            listOf(listOf(rawSsn)),
            resultFingerprint = fingerprintOf(decide(Channel.WORKFLOW_EXECUTOR, "100.100.1.10").resultFingerprint),
        )

        val trusted = decideResultView(viewerCtx(request().sql, "100.100.1.10"), decrypted)
        assertEquals(rawSsn, assertIs<ResultViewDecision.Allowed>(trusted).rows.single().single())

        val outside = decideResultView(viewerCtx(request().sql, "100.99.1.10"), decrypted)
        assertEquals(maskedSsn, assertIs<ResultViewDecision.Allowed>(outside).rows.single().single())
    }

    @Test
    fun `workflow executor stores R's execution-enforced masks and the viewer re-decides per context`() {
        // Off the trusted network R (a production PII accessor) cannot unmask ssn, so the stored result is
        // R's execution-enforced masked form — storage is never widened to what some other context reveals.
        val storedOffNetwork = decide(Channel.WORKFLOW_EXECUTOR, "100.99.1.10")
        assertEquals(EnfAction.MASK, storedOffNetwork.action, "off-network execution masks ssn")
        assertEquals(
            listOf("ssn"), storedOffNetwork.masks.map { it.column },
            "storage holds R's execution-context mask plan, never widened",
        )

        // Executing ON the trusted network unmasks ssn, so R stores it cleartext.
        assertEquals(
            EnfAction.ALLOW, decide(Channel.WORKFLOW_EXECUTOR, "100.100.1.10").action,
            "on the trusted network R stores ssn cleartext",
        )

        // The viewer re-decides under exactly {R} in the viewer's own context: masked off-network, unmasked on it.
        val viewedOffNetwork = decide(Channel.WORKFLOW_VIEWER, "100.99.1.10")
        assertEquals(EnfAction.MASK, viewedOffNetwork.action)
        assertEquals("ssn", viewedOffNetwork.masks.single().column)
        assertEquals(EnfAction.ALLOW, decide(Channel.WORKFLOW_VIEWER, "100.100.1.10").action)
    }

    @Test
    fun `an authorized passthrough result is released as-is`() {
        // SHOW CREATE TABLE (and every SHOW / DESCRIBE) re-decides as an ALLOW passthrough — it carries no
        // column-masking model, so the view has nothing to narrow. Once the live re-decision under {R}
        // authorizes it, "authorized to run" is "authorized to see": the stored bytes are released verbatim
        // rather than fail-closing on "re-decided as passthrough".
        val ddl = "CREATE TABLE `users` (\n  `ssn` varchar(20) DEFAULT NULL\n)"
        val stored = DecryptedResult(listOf("Table", "Create Table"), listOf(listOf("users", ddl)), resultFingerprint = fingerprintOf(emptyList()))
        val redecide = decideQuery(
            principal = requester, ds = datasource, sql = "SHOW CREATE TABLE users", channel = Channel.EDITOR,
            catalog = fx.datasourceStore.catalog(datasource.id), policyStore = fx.policyStore,
            accessStore = fx.accessStore, userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver,
            authz = fx.authz, providedRoles = setOf(roleName), context = AuthzContext(requesterIp = "100.99.1.10"),
        )
        assertEquals(EnfAction.ALLOW, redecide.action)
        assertTrue(redecide.passthrough, "SHOW CREATE TABLE re-decides as a passthrough")

        val view = decideResultView(viewerCtx("SHOW CREATE TABLE users", "100.99.1.10", channel = Channel.EDITOR), stored)
        val allowed = assertIs<ResultViewDecision.Allowed>(view)
        assertEquals(listOf("Table", "Create Table"), allowed.columns)
        assertEquals(listOf(listOf("users", ddl)), allowed.rows)
        assertTrue(allowed.maskedColumns.isEmpty(), "a passthrough view masks nothing")
    }

    @Test
    fun `a passthrough that re-decides DENY via Cedar is refused, not released`() {
        // A passthrough is released only when the live re-decision authorizes it. Under a development-only
        // role with no datasource.connect on this system:production datasource, SHOW CREATE TABLE re-decides
        // DENY at the Cedar connect gate, so the view refuses it — the DENY branch, not a blanket passthrough
        // deny. (Contrast the released-as-is case above, which runs under the connect-holding {R}.)
        val stored = DecryptedResult(listOf("Table", "Create Table"), listOf(listOf("users", "CREATE TABLE `users` ()")), resultFingerprint = fingerprintOf(emptyList()))
        val view = decideResultView(
            viewerCtx(
                "SHOW CREATE TABLE users", "100.99.1.10", channel = Channel.EDITOR,
                req = request().copy(roleName = "system:development-viewer", executeAs = listOf("system:development-viewer")),
            ),
            stored,
        )
        assertIs<ResultViewDecision.Denied>(view)
    }

    @Test
    fun `a passthrough result with a mismatched row width is refused`() {
        // The passthrough release path's structural check: stored bytes whose row width does not match the
        // column count are refused rather than released (two columns, a one-cell row).
        val stored = DecryptedResult(listOf("Table", "Create Table"), listOf(listOf("users")), resultFingerprint = fingerprintOf(emptyList()))
        val view = decideResultView(viewerCtx("SHOW CREATE TABLE users", "100.99.1.10", channel = Channel.EDITOR), stored)
        assertIs<ResultViewDecision.Denied>(view)
    }

    // A plan-only EXPLAIN result view: freeze the fingerprint the way the real run does, then re-decide
    // under [roleName] from [ip]. The stored bytes are the target DB's real plan output.
    private fun viewExplain(
        sql: String,
        stored: DecryptedResult,
        roleName: String = this.roleName,
        roleId: Long = this.roleId,
        ip: String = "100.100.1.10",
    ): ResultViewDecision = decideResultView(
        viewerCtx(sql, ip, req = request(sql, roleName, roleId), channel = Channel.EDITOR),
        stored,
    )

    private fun storedExplain(sql: String, executeIp: String = "100.100.1.10"): DecryptedResult {
        val plan = fx.execOnTarget(sql)
        val executed = decideQuery(
            principal = requester, ds = datasource, sql = sql, channel = Channel.WORKFLOW_EXECUTOR,
            catalog = fx.datasourceStore.catalog(datasource.id), policyStore = fx.policyStore,
            accessStore = fx.accessStore, userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver,
            authz = fx.authz, providedRoles = setOf(roleName), context = AuthzContext(requesterIp = executeIp),
        )
        return DecryptedResult(plan.columns, plan.rows, resultFingerprint = fingerprintOf(executed.resultFingerprint))
    }

    // The release must come from the plan-only EXPLAIN branch, not passthrough or the projection path.
    private fun assertPlanOnlyExplain(ctx: DecisionContext) {
        assertEquals(EnfAction.ALLOW, ctx.action)
        assertTrue(!ctx.passthrough, "a columnar EXPLAIN must not re-decide as a passthrough")
        assertEquals(StatementKind.STATEMENT_KIND_EXPLAIN, ctx.statementKind)
        assertTrue(ctx.masks.isEmpty() && ctx.outputColumns.isEmpty())
    }

    @Test
    fun `an allowed plan-only explain releases its target-generated plan columns`() {
        val stored = storedExplain("EXPLAIN SELECT id FROM users")
        assertPlanOnlyExplain(viewerCtx("EXPLAIN SELECT id FROM users", "100.100.1.10", req = request("EXPLAIN SELECT id FROM users"), channel = Channel.EDITOR))
        val allowed = assertIs<ResultViewDecision.Allowed>(viewExplain("EXPLAIN SELECT id FROM users", stored))
        assertEquals(stored.columns, allowed.columns)
        assertEquals(stored.rows, allowed.rows)
        assertTrue(allowed.maskedColumns.isEmpty(), "a released plan masks nothing")
    }

    @Test
    fun `an explain with a protected predicate is refused for a role without the unmasked grant`() {
        // A predicate column emits a DENY_STATEMENT reference grant (its selectivity IS the plan), so the
        // re-decision needs ssn UNMASKED. The pii-accessor holds it via -262 and the plan releases; the
        // production-viewer clears datasource.connect and sql.select but not unmasked-PII, so its
        // re-decision DENIES past the connect gate — at the masking boundary — and the plan is refused.
        val sql = "EXPLAIN SELECT id FROM users WHERE ssn = '$rawSsn'"
        val stored = storedExplain(sql)
        assertIs<ResultViewDecision.Allowed>(viewExplain(sql, stored))
        val viewerRedecision = viewerCtx(
            sql, "100.100.1.10",
            req = request(sql, prodViewerRoleName, prodViewerRoleId), channel = Channel.EDITOR,
        )
        assertEquals(EnfAction.DENY, viewerRedecision.action)
        assertTrue(
            viewerRedecision.denyReason.orEmpty().contains("cannot be masked"),
            "the deny is the protected-predicate DENY_STATEMENT, not the connect gate: ${'$'}{viewerRedecision.denyReason}",
        )
        assertIs<ResultViewDecision.Denied>(
            viewExplain(sql, stored, roleName = prodViewerRoleName, roleId = prodViewerRoleId),
        )
    }

    @Test
    fun `a masked-projection explain releases for a role that may only read masked`() {
        // A PROJECTED column is read to build the plan but never appears in it, so a masked read grant is
        // enough: the production-viewer's EXPLAIN of ssn re-decides ALLOW with empty masks and releases.
        val sql = "EXPLAIN SELECT ssn FROM users"
        val stored = storedExplain(sql)
        val redecision = viewerCtx(
            sql, "100.100.1.10",
            req = request(sql, prodViewerRoleName, prodViewerRoleId), channel = Channel.EDITOR,
        )
        assertPlanOnlyExplain(redecision)
        assertIs<ResultViewDecision.Allowed>(
            viewExplain(sql, stored, roleName = prodViewerRoleName, roleId = prodViewerRoleId),
        )
    }

    @Test
    fun `an explain with a drifted fingerprint is refused before the release path`() {
        val stored = storedExplain("EXPLAIN SELECT id FROM users")
        val drifted = DecryptedResult(stored.columns, stored.rows, resultFingerprint = null)
        assertIs<ResultViewDecision.Denied>(viewExplain("EXPLAIN SELECT id FROM users", drifted))
    }

    @Test
    fun `a malformed-width explain plan is refused`() {
        val stored = storedExplain("EXPLAIN SELECT id FROM users")
        check(stored.columns.size > 1)
        val malformed = DecryptedResult(
            stored.columns.dropLast(1), stored.rows, resultFingerprint = stored.resultFingerprint,
        )
        assertIs<ResultViewDecision.Denied>(viewExplain("EXPLAIN SELECT id FROM users", malformed))
    }

    @Test
    fun `an explain analyze of a read releases like a plan-only explain and a protected predicate still denies`() {
        val stored = storedExplain("EXPLAIN ANALYZE SELECT id FROM users")
        val allowed = assertIs<ResultViewDecision.Allowed>(viewExplain("EXPLAIN ANALYZE SELECT id FROM users", stored))
        assertEquals(stored.rows, allowed.rows)

        val predicate = "EXPLAIN ANALYZE SELECT id FROM users WHERE ssn = '$rawSsn'"
        val denied = storedExplain(predicate)
        val redenied = viewerCtx(predicate, "100.100.1.10", req = request(predicate, prodViewerRoleName, prodViewerRoleId), channel = Channel.EDITOR)
        assertEquals(EnfAction.DENY, redenied.action)
        assertTrue(redenied.denyReason.orEmpty().contains("cannot be masked"))
        assertIs<ResultViewDecision.Denied>(
            viewExplain(predicate, denied, roleName = prodViewerRoleName, roleId = prodViewerRoleId),
        )
    }

    @Test
    fun `a formatted explain releases its single-column plan`() {
        val sql = "EXPLAIN FORMAT=JSON SELECT id FROM users"
        val stored = storedExplain(sql)
        assertPlanOnlyExplain(viewerCtx(sql, "100.100.1.10", req = request(sql), channel = Channel.EDITOR))
        val allowed = assertIs<ResultViewDecision.Allowed>(viewExplain(sql, stored))
        assertEquals(stored.columns, allowed.columns)
        assertEquals(stored.rows, allowed.rows)

        // The JSON plan embeds the predicate as attached_condition, so the protected-predicate deny must
        // survive option handling too.
        val predicate = "EXPLAIN FORMAT=JSON SELECT id FROM users WHERE ssn = '$rawSsn'"
        val redenied = viewerCtx(predicate, "100.100.1.10", req = request(predicate, prodViewerRoleName, prodViewerRoleId), channel = Channel.EDITOR)
        assertEquals(EnfAction.DENY, redenied.action)
        assertTrue(redenied.denyReason.orEmpty().contains("cannot be masked"))
    }

    @Test
    fun `an explain table result releases like a plan-only explain`() {
        // MySQL's `EXPLAIN TABLE t` plans the `SELECT * FROM t` shorthand, so it classifies as the
        // plan-only EXPLAIN kind and its stored plan releases under the same clean-ALLOW gate.
        val sql = "EXPLAIN TABLE users"
        val stored = storedExplain(sql)
        assertPlanOnlyExplain(viewerCtx(sql, "100.100.1.10", req = request(sql), channel = Channel.EDITOR))
        val allowed = assertIs<ResultViewDecision.Allowed>(viewExplain(sql, stored))
        assertEquals(stored.columns, allowed.columns)
        assertEquals(stored.rows, allowed.rows)
    }

    @Test
    fun `a non-explain allow with empty outputs never takes the plan release`() {
        // The statementKind conjunct is load-bearing: an ALLOW with empty masks and outputColumns whose
        // kind is not EXPLAIN (a synthetic non-EXPLAIN context) must fall through to the projection-width
        // check and refuse the stored plan bytes.
        val stored = storedExplain("EXPLAIN SELECT id FROM users")
        val explainCtx = viewerCtx(
            "EXPLAIN SELECT id FROM users", "100.100.1.10",
            req = request("EXPLAIN SELECT id FROM users"), channel = Channel.EDITOR,
        )
        val nonExplain = explainCtx.copy(statementKind = StatementKind.STATEMENT_KIND_STMT_UNKNOWN)
        assertIs<ResultViewDecision.Denied>(decideResultView(nonExplain, stored))
        val maskedExplain = explainCtx.copy(
            masks = listOf(columnMask { column = "ssn"; maskFn = "mask"; kind = "PARTIAL"; ordinal = 0 }),
        )
        assertIs<ResultViewDecision.Denied>(decideResultView(maskedExplain, stored))
    }
}
