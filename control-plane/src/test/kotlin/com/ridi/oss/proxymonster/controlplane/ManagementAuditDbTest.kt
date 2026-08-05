package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.AuditSource
import com.ridi.oss.proxymonster.controlplane.management.DatasourceManagementService
import com.ridi.oss.proxymonster.controlplane.management.IdentityManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.management.PolicyManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.auditChainHead
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.sql.SQLException
import javax.sql.DataSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ManagementAuditDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var datasources: DatasourceManagementService
    private lateinit var policies: PolicyManagementService
    private lateinit var identities: IdentityManagementService

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_management_audit"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        val recorder = ManagementAuditRecorder(core.auditStore)
        datasources = DatasourceManagementService(core.datasourceStore, core.proxyEventsHub, TableDetailService(core), recorder)
        policies = PolicyManagementService(core.cedarPolicyStore, core.policyStore, recorder)
        identities = IdentityManagementService(
            dataSource, core.userGroupStore, core.policyStore, core.tokenStore, core.accessStore,
            PrincipalSessionStore(dataSource, null), recorder,
        )
    }

    @Test
    fun `each service records one atomic admin event with its pinned descriptor`() {
        val principal = "management-audit-${System.nanoTime()}@example.com"
        val actor = AuditActor(principal, clientAddr = "192.0.2.1", channel = AuditSource.CONSOLE)
        policies.createRole("audit-role-${System.nanoTime()}", null, actor).also { role ->
            assertEvent(principal, AuthzAction.ADMIN_POLICIES, "Role::\"${role.name}\"", "create role '${role.name}'")
        }
        identities.createUser(AppUserInput(principal, active = true), actor)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, "User::\"$principal\"", "create user '$principal'")
        val datasource = datasources.createDatasource(DatasourceInput("audit-ds-${System.nanoTime()}", "postgres"), actor)
        assertEvent(principal, AuthzAction.ADMIN_DATASOURCES, "Datasource::\"${datasource.name}\"", "create datasource '${datasource.name}'")
        verifyAuditChain(dataSource)
    }

    @Test
    fun `batch classification writes one row naming resolved columns in canonical order`() {
        val principal = "management-batch-${System.nanoTime()}@example.com"
        val actor = AuditActor(principal, channel = AuditSource.CONSOLE)
        val ds = datasources.createDatasource(DatasourceInput("audit-batch-${System.nanoTime()}", "postgres"), actor)
        defaultSchemaPublic(ds.id)
        dataSource.inTx { c ->
            datasources.setColumnClassifications(
                ds.name,
                listOf(
                    ClassificationInput(null, "users", "rrn", listOf("pii")),
                    ClassificationInput("public", "users", "email", listOf("contact")),
                    ClassificationInput(null, "users", "phone", listOf("contact")),
                ),
                actor,
                c,
            )
        }
        assertEvent(
            principal, AuthzAction.ADMIN_DATASOURCES, "Datasource::\"${ds.name}\"",
            "tag 3 columns of '${ds.name}' [public.users.email, public.users.phone, public.users.rrn]",
        )
        // One row for the whole batch, not one per column: the batch is a single atomic change.
        assertEquals(1, count("SELECT count(*) FROM audit_event WHERE principal=? AND statement LIKE 'tag %columns%'", principal))
        verifyAuditChain(dataSource)
    }

    @Test
    fun `a rejected audit insert rolls back the mutation it describes`() {
        val principal = "management-rollback-${System.nanoTime()}@example.com"
        val actor = AuditActor(principal, channel = AuditSource.CONSOLE)
        val roleName = "audit-rollback-role"
        val headBefore = auditChainHead(dataSource)
        execute(
            """CREATE OR REPLACE FUNCTION pm_test_reject_admin_audit() RETURNS trigger AS ${'$'}body${'$'}
               BEGIN RAISE EXCEPTION 'forced admin audit failure'; END
               ${'$'}body${'$'} LANGUAGE plpgsql""",
        )
        execute(
            """CREATE TRIGGER pm_test_reject_admin_audit BEFORE INSERT ON audit_event
               FOR EACH ROW WHEN (NEW.kind = 'admin' AND NEW.resource = 'Role::"$roleName"')
               EXECUTE FUNCTION pm_test_reject_admin_audit()""",
        )
        try {
            assertFailsWith<SQLException> { policies.createRole(roleName, null, actor) }
            assertEquals(0, count("SELECT count(*) FROM app_role WHERE name=?", roleName))
            assertEquals(0, count("SELECT count(*) FROM audit_event WHERE principal=?", principal))
            val headAfter = auditChainHead(dataSource)
            assertEquals(headBefore.first, headAfter.first)
            assertContentEquals(headBefore.second, headAfter.second)
        } finally {
            execute("DROP TRIGGER IF EXISTS pm_test_reject_admin_audit ON audit_event")
            execute("DROP FUNCTION IF EXISTS pm_test_reject_admin_audit()")
        }
        verifyAuditChain(dataSource)
    }

    @Test
    fun `a rejected mutation and a no-op removal record nothing`() {
        val principal = "management-noop-${System.nanoTime()}@example.com"
        val actor = AuditActor(principal, channel = AuditSource.CONSOLE)
        val taken = "audit-duplicate-${System.nanoTime()}"
        policies.createRole(taken, null, actor)

        assertFailsWith<ManagementException> { policies.createRole(taken, null, actor) }
        assertEquals(1, count("SELECT count(*) FROM audit_event WHERE principal=? AND resource=?", principal, """Role::"$taken""""))

        // A group the principal was never in: nothing was removed, so there is no change to record.
        val group = identities.createGroup(AppGroupInput("audit-noop-${System.nanoTime()}"), actor)
        val outsider = identities.createUser(AppUserInput("audit-outsider-${System.nanoTime()}@example.com", active = true), actor)
        assertEquals(false, identities.removeGroupMember(group.id, outsider.id, actor).deleted)
        assertEquals(
            0,
            count(
                "SELECT count(*) FROM audit_event WHERE resource=? AND statement LIKE 'remove %'",
                """Group::"${group.name}"""",
            ),
        )

        assertFailsWith<ManagementException> { policies.deleteRole("audit-absent-${System.nanoTime()}", actor) }
        verifyAuditChain(dataSource)
    }

    @Test
    fun `identity and policy edits record their resolved before and after names`() {
        val principal = "management-edits-${System.nanoTime()}@example.com"
        val actor = AuditActor(principal, channel = AuditSource.CONSOLE)
        val role = policies.createRole("audit-rename-${System.nanoTime()}", null, actor)
        val renamed = policies.updateRole(role.id, RoleInput("${role.name}-v2", null), actor)
        assertEvent(principal, AuthzAction.ADMIN_POLICIES, """Role::"${renamed.name}"""", "update role '${role.name}' -> '${renamed.name}'")

        val member = identities.createUser(AppUserInput("audit-member-${System.nanoTime()}@example.com", active = true), actor)
        policies.assignRole(member.principal, renamed.id, actor)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, """Role::"${renamed.name}"""", "assign role '${renamed.name}' to '${member.principal}'")
        assertEquals(true, policies.unassignRole(member.principal, renamed.name, actor).deleted)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, """Role::"${renamed.name}"""", "unassign role '${renamed.name}' from '${member.principal}'")

        val group = identities.createGroup(AppGroupInput("audit-group-${System.nanoTime()}"), actor)
        identities.addGroupMember(group.id, member.id, actor)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, """Group::"${group.name}"""", "add '${member.principal}' to group '${group.name}'")
        identities.setGroupRoles(group.name, setOf(renamed.name), actor)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, """Group::"${group.name}"""", "set group '${group.name}' roles [${renamed.name}]")
        assertEquals(true, identities.removeGroupMember(group.id, member.id, actor).deleted)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, """Group::"${group.name}"""", "remove '${member.principal}' from group '${group.name}'")

        assertEquals(true, identities.deprovisionUser(member.id, actor).deleted)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, """User::"${member.principal}"""", "deprovision user '${member.principal}'")
        assertEquals(true, policies.deleteRole(renamed.id, actor).deleted)
        assertEvent(principal, AuthzAction.ADMIN_POLICIES, """Role::"${renamed.name}"""", "delete role '${renamed.name}'")
        verifyAuditChain(dataSource)
    }

    @Test
    fun `mask function CRUD and a SYSTEM policy toggle each record once`() {
        val principal = "management-maskfn-${System.nanoTime()}@example.com"
        val actor = AuditActor(principal, channel = AuditSource.CONSOLE)
        val fn = policies.createMaskFn(MaskFnInput("audit-mask-${System.nanoTime()}", "redact"), actor)
        assertEvent(principal, AuthzAction.ADMIN_POLICIES, """MaskFn::"${fn.name}"""", "create mask function '${fn.name}'")
        val renamed = policies.updateMaskFn(fn.id, MaskFnInput("${fn.name}-v2", "redact"), actor)
        assertEvent(
            principal, AuthzAction.ADMIN_POLICIES, """MaskFn::"${renamed.name}"""",
            "update mask function '${fn.name}' -> '${renamed.name}'",
        )
        assertEquals(true, policies.deleteMaskFn(renamed.id, actor).deleted)
        assertEvent(principal, AuthzAction.ADMIN_POLICIES, """MaskFn::"${renamed.name}"""", "delete mask function '${renamed.name}'")

        // Toggling a SYSTEM policy is permitted where update and delete are not, so the toggle is the
        // only config change that reaches a SYSTEM row and it must still be audited.
        val system = policies.setPolicyEnabled(-1L, enabled = false, principal = principal, actor = actor)
        assertEvent(principal, AuthzAction.ADMIN_POLICIES, """Policy::"-1"""", "disable policy '${system.name}'")
        policies.setPolicyEnabled(-1L, enabled = true, principal = principal, actor = actor)
        assertEvent(principal, AuthzAction.ADMIN_POLICIES, """Policy::"-1"""", "enable policy '${system.name}'")
        verifyAuditChain(dataSource)
    }

    @Test
    fun `datasource CRUD and single-column tagging record the resolved column path`() {
        val principal = "management-ds-${System.nanoTime()}@example.com"
        val actor = AuditActor(principal, channel = AuditSource.CONSOLE)
        val created = datasources.createDatasource(DatasourceInput("audit-crud-${System.nanoTime()}", "postgres"), actor)
        defaultSchemaPublic(created.id)
        val renamed = assertNotNull(
            datasources.updateDatasource(created.id, DatasourceInput("${created.name}-v2", "postgres"), actor),
        )
        assertEvent(
            principal, AuthzAction.ADMIN_DATASOURCES, """Datasource::"${renamed.name}"""",
            "update datasource '${created.name}' -> '${renamed.name}'",
        )

        // Schema omitted on the wire: both the descriptor and the summary must carry the RESOLVED schema,
        // since that is the column the mask decision reads.
        datasources.setColumnClassification(renamed.id, null, "users", "rrn", listOf("pii"), null, actor)
        assertEvent(
            principal, AuthzAction.ADMIN_DATASOURCES, """Datasource::"${renamed.name}" col public.users.rrn""",
            "tag ${renamed.name}.public.users.rrn [pii]",
        )
        assertEquals(true, datasources.clearColumnClassification(renamed.id, null, "users", "rrn", actor).deleted)
        assertEvent(
            principal, AuthzAction.ADMIN_DATASOURCES, """Datasource::"${renamed.name}" col public.users.rrn""",
            "clear tags on ${renamed.name}.public.users.rrn",
        )

        assertEquals(true, datasources.deleteDatasource(renamed.id, actor).deleted)
        assertEvent(principal, AuthzAction.ADMIN_DATASOURCES, """Datasource::"${renamed.name}"""", "delete datasource '${renamed.name}'")
        assertEquals(false, datasources.deleteDatasource(renamed.id, actor).deleted)
        assertEquals(1, count("SELECT count(*) FROM audit_event WHERE principal=? AND statement LIKE 'delete datasource %'", principal))
        verifyAuditChain(dataSource)
    }

    @Test
    fun `ordinary policy CRUD records create, rename, and delete`() {
        val principal = "management-policy-${System.nanoTime()}@example.com"
        val actor = AuditActor(principal, channel = AuditSource.CONSOLE)
        val src = "permit(principal in Role::\"system:admin\", action == Action::\"admin.policies\", resource);"
        val created = policies.createPolicy("audit-policy-${System.nanoTime()}", src, enabled = true, principal = principal, actor = actor)
        assertEvent(principal, AuthzAction.ADMIN_POLICIES, """Policy::"${created.id}"""", "create policy '${created.name}'")
        val renamed = policies.updatePolicy(created.id, CedarPolicyInput("${created.name}-v2", src, enabled = true), principal, actor)
        assertEvent(
            principal, AuthzAction.ADMIN_POLICIES, """Policy::"${renamed.id}"""",
            "update policy '${created.name}' -> '${renamed.name}'",
        )
        assertEquals(true, policies.deletePolicy(created.id, actor).deleted)
        assertEvent(principal, AuthzAction.ADMIN_POLICIES, """Policy::"${created.id}"""", "delete policy '${renamed.name}'")
        verifyAuditChain(dataSource)
    }

    @Test
    fun `group role grant and revoke each record once`() {
        val principal = "management-grouprole-${System.nanoTime()}@example.com"
        val actor = AuditActor(principal, channel = AuditSource.CONSOLE)
        val role = policies.createRole("audit-grouprole-${System.nanoTime()}", null, actor)
        val group = identities.createGroup(AppGroupInput("audit-rolegroup-${System.nanoTime()}"), actor)
        identities.addGroupRole(group.id, role.id, actor)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, """Group::"${group.name}"""", "add role '${role.name}' to group '${group.name}'")
        assertEquals(true, identities.removeGroupRole(group.id, role.id, actor).deleted)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, """Group::"${group.name}"""", "remove role '${role.name}' from group '${group.name}'")
        verifyAuditChain(dataSource)
    }

    @Test
    fun `repeating an add or assignment records nothing the second time`() {
        val principal = "management-idempotent-${System.nanoTime()}@example.com"
        val actor = AuditActor(principal, channel = AuditSource.CONSOLE)
        val role = policies.createRole("audit-idem-role-${System.nanoTime()}", null, actor)
        val group = identities.createGroup(AppGroupInput("audit-idem-group-${System.nanoTime()}"), actor)
        val user = identities.createUser(AppUserInput("audit-idem-user-${System.nanoTime()}@example.com", active = true), actor)

        // The store upserts, so a repeated add/assign changes nothing — and a change that did not happen
        // must not produce an audit row. assertEvent demands exactly one row for the exact statement, so a
        // second write here fails it.
        identities.addGroupMember(group.id, user.id, actor)
        identities.addGroupMember(group.id, user.id, actor)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, """Group::"${group.name}"""", "add '${user.principal}' to group '${group.name}'")

        identities.addGroupRole(group.id, role.id, actor)
        identities.addGroupRole(group.id, role.id, actor)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, """Group::"${group.name}"""", "add role '${role.name}' to group '${group.name}'")

        policies.assignRole(user.principal, role.id, actor)
        policies.assignRole(user.principal, role.id, actor)
        assertEvent(principal, AuthzAction.ADMIN_IDENTITY, """Role::"${role.name}"""", "assign role '${role.name}' to '${user.principal}'")
        verifyAuditChain(dataSource)
    }

    private fun defaultSchemaPublic(datasourceId: Long) = dataSource.connection.use { c ->
        c.prepareStatement("UPDATE datasource SET default_schemas='[\"public\"]'::jsonb WHERE id=?").use { ps ->
            ps.setLong(1, datasourceId)
            ps.executeUpdate()
        }
    }

    private fun count(sql: String, vararg values: String): Int = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps ->
            values.forEachIndexed { index, value -> ps.setString(index + 1, value) }
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private fun execute(sql: String) =
        dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    private fun assertEvent(principal: String, action: AuthzAction, resource: String, statement: String) {
        val rows = dataSource.connection.use { c ->
            c.prepareStatement(
                """SELECT action, resource, statement, outcome, kind, channel, decision, datasource
                   FROM audit_event WHERE principal=? AND resource=? AND statement=? ORDER BY id""",
            ).use { ps ->
                ps.setString(1, principal); ps.setString(2, resource); ps.setString(3, statement)
                ps.executeQuery().use { rs ->
                    buildList { while (rs.next()) add((1..8).map(rs::getString)) }
                }
            }
        }
        assertEquals(1, rows.size)
        assertEquals(listOf(action.cedarId, resource, statement, "ALLOW", "admin", "console", "ALLOW", "control-plane"), rows.single())
    }
}
