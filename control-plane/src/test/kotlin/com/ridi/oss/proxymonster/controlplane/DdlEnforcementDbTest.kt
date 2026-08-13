package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

/**
 * DDL is authorized by its `stmt.cat.ddl` datasource grant, on a production-tagged datasource.
 *
 * The shipped `system:production-ddl` preset was unreachable: the analyzer reported every DDL form
 * UNRESOLVED, so even after its `stmt.cat.ddl` grant passed the datasource-grant loop, the `!resolved`
 * branch below it routed the statement to the `exception.unanalyzable` gate. That grant ships scoped to
 * `system:development` only, which denied production DDL for every role — including the architect the
 * DDL policy names. Resolving DDL is what lets its `stmt.cat.ddl` grant alone authorize it.
 *
 * DDL resolves as ANALYZED carrying that lone `stmt.cat.ddl` grant — the same shape a grant-only write like
 * INSERT takes — so decideQuery authorizes it off the datasource grant with no DDL-specific branch.
 *
 * These cases go through the real decideQuery against a live database, so they fail if the analyzer marks
 * DDL unresolved again and it falls back through the `exception.unanalyzable` gate.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DdlEnforcementDbTest {
    private lateinit var fx: EnforcementFixture

    private val architect = "architect@example.com"
    private val connector = "connector@example.com"
    private val noRole = "nobody@example.com"

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
        // The shipped production shape: one role, granted stmt.cat.ddl on production-tagged datasources only.
        val role = fx.policyStore.createRole(RoleInput("ddl-architect"))
        fx.policyStore.createAssignment(RoleAssignmentInput(architect, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "architect-production-ddl",
                cedarSrc = """permit(principal in Role::"ddl-architect", action in [Action::"stmt.cat.ddl"], resource) when { resource in Tag::"system:production" };""",
            ),
            updatedBy = "test-fixture",
        )
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "architect-production-connect",
                cedarSrc = """permit(principal in Role::"ddl-architect", action == Action::"datasource.connect", resource) when { resource in Tag::"system:production" };""",
            ),
            updatedBy = "test-fixture",
        )
        // A principal that may CONNECT but holds no stmt.cat.ddl, so a DDL deny for it isolates the missing
        // stmt.cat.ddl grant rather than passing at the earlier datasource.connect gate.
        val connectRole = fx.policyStore.createRole(RoleInput("connect-only"))
        fx.policyStore.createAssignment(RoleAssignmentInput(connector, connectRole.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "connect-only-production-connect",
                cedarSrc = """permit(principal in Role::"connect-only", action == Action::"datasource.connect", resource) when { resource in Tag::"system:production" };""",
            ),
            updatedBy = "test-fixture",
        )
    }

    private fun decide(sql: String, who: String) = decideQuery(
        principal = who,
        ds = fx.datasourceStore.get(fx.datasource.id)!!,
        sql = sql,
        channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id),
        policyStore = fx.policyStore,
        accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore,
        roleResolver = fx.roleResolver,
        authz = fx.authz,
    )

    private val ddlForms = listOf(
        "ALTER TABLE users DROP INDEX idx_ssn",
        "ALTER TABLE users ADD c INT",
        "ALTER TABLE users RENAME TO users2",
        "CREATE INDEX idx_email ON users (email)",
        "DROP INDEX idx_email ON users",
        "DROP TABLE users",
        "TRUNCATE TABLE users",
        "CREATE TABLE t (id int)",
    )

    @Test
    fun `the sql-ddl grant alone authorizes every DDL form on a production datasource`() {
        for (sql in ddlForms) {
            val ctx = decide(sql, architect)
            assertEquals(
                EnfAction.ALLOW,
                ctx.action,
                "$sql denied for the stmt.cat.ddl holder: ${ctx.denyReason} (stage=${ctx.failedStage})",
            )
            // The relay must not be the unmasked exception.unanalyzable passthrough — that grant is a whole-
            // statement unmasked relay and is NOT what authorizes DDL.
            assertEquals(
                false,
                ctx.detail?.contains("unanalyz") ?: false,
                "$sql was relayed through the unanalyzable hatch: ${ctx.detail}",
            )
        }
    }

    @Test
    fun `a principal that can connect but lacks the sql-ddl grant is denied every DDL form`() {
        // `connector` clears datasource.connect (checked before stmt.cat.ddl), so each DENY isolates the
        // missing stmt.cat.ddl grant rather than passing at the connect gate.
        for (sql in ddlForms) {
            val ctx = decide(sql, connector)
            assertEquals(EnfAction.DENY, ctx.action, "$sql must stay denied without stmt.cat.ddl")
        }
    }

    /**
     * A `stmt.cat.ddl` grant authorizes schema DDL, not everything DDL-adjacent. RENAME TABLE and RENAME USER
     * are Commands sqlglot does not model — unanalyzable, so they deny at the `exception.unanalyzable` gate the
     * architect does not hold. DROP USER is account management (`stmt.cat.admin.account`, not schema DDL), so
     * its kind gate demands admin, which the architect also lacks. None is reachable by the ddl grant alone —
     * over-denying is the correct side to fail on.
     */
    @Test
    fun `a statement outside schema DDL stays denied even with the ddl grant`() {
        for (sql in listOf(
            "RENAME TABLE users TO users2",
            "DROP USER 'x'@'%'",
            "RENAME USER 'a'@'%' TO 'b'@'%'",
        )) {
            val ctx = decide(sql, architect)
            assertEquals(EnfAction.DENY, ctx.action, "$sql must stay denied: unmodeled by the parser")
        }
    }

    /**
     * The exfiltration path authz-model.md requires to fail closed: copying a masked column into a new,
     * unclassified table. The DDL grant authorizes the schema change, but every column the write READS is
     * a non-maskable reference, so a masked source column denies the statement.
     *
     * Both spellings are asserted because parentheses put a Subquery around the query body — the bug this
     * covers classified `AS (SELECT …)` as body-less, emitted no column grants, and allowed the copy.
     */
    @Test
    fun `a ddl holder cannot copy a masked column into a new table, parenthesized or not`() {
        for (sql in listOf(
            "CREATE TABLE stolen AS SELECT ssn FROM users",
            "CREATE TABLE stolen AS (SELECT ssn FROM users)",
            "CREATE TABLE stolen AS ((SELECT ssn FROM users))",
            "CREATE VIEW stolen AS (SELECT ssn FROM users)",
        )) {
            val ctx = decide(sql, architect)
            assertEquals(
                EnfAction.DENY,
                ctx.action,
                "$sql must DENY — it copies a masked column into an unclassified table (detail=${ctx.detail})",
            )
        }
    }

    /**
     * A CTAS is a read as well as a write, so stmt.cat.ddl alone never authorizes one: the columns it reads
     * need their own grant. That is what separates plain DDL (schema only) from data-bearing DDL, and it
     * is why the copy above denies on the mask rather than on the DDL grant.
     */
    @Test
    fun `a ddl holder cannot copy even an unclassified column without a read grant`() {
        val ctx = decide("CREATE TABLE fine AS SELECT id FROM users", architect)
        assertEquals(
            EnfAction.DENY,
            ctx.action,
            "a CTAS reads its source columns; stmt.cat.ddl alone is not a read grant",
        )
    }

    /**
     * The reason the architect vanished from the approval picker: discovery previews each candidate role
     * ALONE and drops any whose decision is DENY, with no per-candidate reason surfaced. A DDL statement
     * that cannot be decided under a single role therefore offers no role at all.
     */
    @Test
    fun `role discovery offers the ddl role for a DDL statement`() {
        val response = discoverRoles(ownRoles = emptySet(), allRoles = fx.policyStore.listRoles()) { roles, channel ->
            decideQuery(
                principal = noRole,
                ds = fx.datasourceStore.get(fx.datasource.id)!!,
                sql = "ALTER TABLE users DROP INDEX idx_ssn",
                channel = channel,
                catalog = fx.datasourceStore.catalog(fx.datasource.id),
                policyStore = fx.policyStore,
                accessStore = fx.accessStore,
                userGroupStore = fx.userGroupStore,
                roleResolver = fx.roleResolver,
                authz = fx.authz,
                providedRoles = roles,
            )
        }
        assertEquals(
            listOf("ddl-architect"),
            response.options.map { it.roleName }.filter { it == "ddl-architect" },
            "the stmt.cat.ddl role must be offered; discovery drops DENY candidates silently",
        )
    }
}
