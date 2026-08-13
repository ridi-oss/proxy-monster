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
 * A Cedar evaluation error must fail closed. Cedar SKIPS a policy whose condition errors and reports the
 * error rather than applying it, so a skipped FORBID alongside a valid permit would silently fail open —
 * the worst outcome for this proxy. `Authz.toAuthzDecision` denies whenever the response carries any
 * evaluation error, before it consults isAllowed; this pins that end-to-end through a real decision.
 * Real MySQL + real Cedar with the shipped schema.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EvalErrorFailClosedDbTest {
    private lateinit var fx: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
    }

    private val ds get() = fx.datasource.name
    private val usersEuid
        get() = "$ds/${fx.datasource.engine.catalogName(fx.datasource.dbName)}/${fx.datasource.engine.defaultSchema(fx.datasource.dbName)}/users"

    private fun decide(sql: String, principal: String) = decideQuery(
        principal = principal, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
    )

    private fun grant(role: String, user: String, vararg cedarSrcs: String) {
        val r = fx.policyStore.createRole(RoleInput(role))
        fx.policyStore.createAssignment(RoleAssignmentInput(user, r.id))
        cedarSrcs.forEachIndexed { i, src ->
            fx.cedarPolicyStore.create(CedarPolicyInput(name = "$role-$i", cedarSrc = src), updatedBy = "test")
        }
    }

    @Test
    fun `an erroring forbid is not skipped into an allow`() {
        // The forbid's condition overflows i64, so Cedar skips it and reports the error. A valid permit would
        // otherwise allow the SELECT; the decision must still DENY because the evaluation carried an error.
        val user = "eval-error-forbid@example.com"
        grant(
            "eval-error-forbid", user,
            """permit(principal in Role::"eval-error-forbid", action in [Action::"datasource.connect", Action::"stmt.cat.read"], resource in Datasource::"$ds");""",
            """permit(principal in Role::"eval-error-forbid", action == Action::"result.read.unmasked", resource in Table::"$usersEuid") unless { resource in Tag::"pii" };""",
            """forbid(principal in Role::"eval-error-forbid", action in [Action::"stmt.cat.read"], resource in Datasource::"$ds") when { 9223372036854775807 + 1 == 0 };""",
        )
        assertEquals(EnfAction.DENY, decide("SELECT id FROM users", user).action, "an erroring forbid must fail closed, not be skipped into an allow")
    }
}
