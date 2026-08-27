package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Account management (CREATE/ALTER/DROP USER|ROLE) is authorized by its `stmt.cat.admin.account` grant and
 * relayed as a no-column passthrough — so a result-bearing form (`CREATE USER … IDENTIFIED BY RANDOM
 * PASSWORD` returns the generated password) stays viewable rather than dropped for a column mismatch.
 *
 * These go through the real decideQuery/decideResultView against a live MySQL, so they fail if the analyzer
 * classifies account DDL as STMT_UNKNOWN again (it would deny under a mere admin grant), or if it marks it
 * catalog-changing again (its result would leave the passthrough and the stored view would refuse it).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AccountManagementEnforcementDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var datasource: Datasource
    private var roleId = 0L

    private val admin = "useradmin@example.com"
    private val connector = "connector@example.com"
    private val createUserRandom = "CREATE USER 'books-frontend'@'10.23.0.0/255.255.0.0' IDENTIFIED BY RANDOM PASSWORD"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET tags = '[\"system:production\"]'::jsonb WHERE id = ?").use { ps ->
                ps.setLong(1, fx.datasource.id)
                ps.executeUpdate()
            }
        }
        datasource = checkNotNull(fx.datasourceStore.get(fx.datasource.id))
        // The account-admin: stmt.cat.admin.account + datasource.connect on production-tagged datasources.
        roleId = fx.policyStore.createRole(RoleInput("account-admin")).id
        fx.policyStore.createAssignment(RoleAssignmentInput(admin, roleId))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "account-admin-account",
                cedarSrc = """permit(principal in Role::"account-admin", action in [Action::"stmt.cat.admin.account"], resource) when { resource in Tag::"system:production" };""",
            ),
            updatedBy = "test-fixture",
        )
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "account-admin-connect",
                cedarSrc = """permit(principal in Role::"account-admin", action == Action::"datasource.connect", resource) when { resource in Tag::"system:production" };""",
            ),
            updatedBy = "test-fixture",
        )
        // A principal that may CONNECT but holds no stmt.cat.admin.account, so a deny isolates the missing
        // account grant rather than passing at the earlier datasource.connect gate.
        val connectRole = fx.policyStore.createRole(RoleInput("account-connect-only"))
        fx.policyStore.createAssignment(RoleAssignmentInput(connector, connectRole.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "account-connect-only-connect",
                cedarSrc = """permit(principal in Role::"account-connect-only", action == Action::"datasource.connect", resource) when { resource in Tag::"system:production" };""",
            ),
            updatedBy = "test-fixture",
        )
    }

    private fun decide(sql: String, who: String) = decideQuery(
        principal = who,
        ds = datasource,
        sql = sql,
        channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(datasource.id),
        policyStore = fx.policyStore,
        accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore,
        roleResolver = fx.roleResolver,
        authz = fx.authz,
    )

    private fun request() = AccessRequest(
        id = 1,
        principal = admin,
        roleId = roleId,
        roleName = "account-admin",
        datasourceId = datasource.id,
        datasourceName = datasource.name,
        requestedDurationSec = 3600,
        status = "EXECUTED",
        decidedBy = admin,
        executedBy = admin,
        createdAt = "2026-08-14T00:00:00Z",
        kind = "QUERY",
        sql = createUserRandom,
        executeAs = listOf("account-admin"),
        creatorKind = "WORKFLOW",
    )

    @Test
    fun `an admin-account holder runs CREATE USER RANDOM PASSWORD as a passthrough and views its generated password`() {
        val ctx = decide(createUserRandom, admin)
        assertEquals(
            EnfAction.ALLOW,
            ctx.action,
            "CREATE USER denied for the stmt.cat.admin.account holder: ${ctx.denyReason} (stage=${ctx.failedStage})",
        )
        assertTrue(ctx.passthrough, "account DDL must relay as a no-column passthrough, not fall through the DDL/re-measure path")
        assertFalse(ctx.catalogChanging, "CREATE USER changes accounts, not the column catalog the proxy re-measures")

        // MySQL returns the generated password in a result set; the stored workflow result must be viewable,
        // not dropped because the analyzer emitted no output columns for it.
        val stored = DecryptedResult(
            columns = listOf("user", "host", "generated password", "auth_factor"),
            rows = listOf(listOf("books-frontend", "10.23.0.0/255.255.0.0", "}q7=x!P2b0Kd", "1")),
            // A genuine passthrough stores a present-but-empty fingerprint (no result-read grants); null would
            // read as a legacy result and fail closed at view.
            resultFingerprint = fingerprintOf(emptyList()),
        )
        val viewCtx = viewerDecision(
            admin, request(), createUserRandom, AuthzContext(requesterIp = "10.23.1.1"),
            fx.datasourceStore, fx.policyStore, fx.accessStore, fx.userGroupStore, fx.roleResolver, fx.authz,
            null, Channel.WIRE,
        )!!
        val view = decideResultView(viewCtx, stored)
        val allowed = assertIs<ResultViewDecision.Allowed>(view)
        assertEquals(stored.columns, allowed.columns, "the generated-password result is released with its columns intact")
        assertEquals(stored.rows, allowed.rows, "the generated password itself is released, not withheld")
        assertTrue(allowed.maskedColumns.isEmpty(), "a passthrough view masks nothing")
    }

    @Test
    fun `a connect-only role is denied CREATE USER at the account-kind gate`() {
        val ctx = decide("CREATE USER 'x'@'%'", connector)
        assertEquals(EnfAction.DENY, ctx.action, "CREATE USER must stay denied without stmt.cat.admin.account")
    }

    @Test
    fun `an admin-account holder reads SHOW GRANTS on production but never SHOW CREATE USER`() {
        // The production surface this reopened: SHOW GRANTS is in stmt.cat.admin.account, so the holder that
        // may CREATE USER may now audit privileges — previously impossible, because its system:critical
        // Utility hit the unconditional -130 forbid no grant can override. SHOW CREATE USER keeps that
        // Utility (it returns the stored password hash), so it stays denied for the SAME principal on the
        // SAME datasource: the split is credential-vs-privilege-list, not admin-vs-non-admin.
        setEngineVersion("8.0.44")
        for (sql in listOf(
            "SHOW GRANTS",
            "SHOW GRANTS FOR 'books-frontend'@'10.23.0.0/255.255.0.0'",
            "SHOW GRANTS FOR CURRENT_USER()",
        )) {
            val ctx = decideClassified(sql, admin)
            assertEquals(EnfAction.ALLOW, ctx.action, "$sql must be readable by an admin.account holder: ${ctx.denyReason} (stage=${ctx.failedStage})")
        }
        assertEquals(
            EnfAction.DENY,
            decideClassified("SHOW CREATE USER CURRENT_USER()", admin).action,
            "SHOW CREATE USER leaks the password hash — denied even for the admin.account holder",
        )
        assertEquals(
            EnfAction.DENY,
            decideClassified("SHOW GRANTS", connector).action,
            "SHOW GRANTS still needs stmt.cat.admin.account — a connect-only role is denied at the kind gate",
        )
    }

    private fun setEngineVersion(version: String) {
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET engine_version = ? WHERE id = ?").use { ps ->
                ps.setString(1, version); ps.setLong(2, datasource.id); ps.executeUpdate()
            }
        }
        datasource = checkNotNull(fx.datasourceStore.get(datasource.id))
    }

    // decide() with the shipped manifests loaded, so a system-classified Utility (SHOW CREATE USER) resolves
    // its tag and the -130 forbid applies. The default helper passes null, which cannot tell the two apart.
    private fun decideClassified(sql: String, who: String) = decideQuery(
        principal = who,
        ds = datasource,
        sql = sql,
        channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(datasource.id),
        policyStore = fx.policyStore,
        accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore,
        roleResolver = fx.roleResolver,
        authz = fx.authz,
        systemClassification = SystemClassificationService(),
    )
}
