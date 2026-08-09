package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The unmaskable gate's control-plane half against real MySQL metadata + real Cedar. The query is maskable on the
 * text path but not on MySQL's binary result path, so the proxy needs a separate MASK-only capability bit:
 * the production floor leaves it false, while an explicit `sql.unmaskable` permit makes it true without
 * changing the underlying MASK verdict.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UnmaskableGateDbTest {
    private lateinit var fx: EnforcementFixture
    private val principal = "analyst@example.com"
    private val preparedSql = "SELECT ssn FROM users WHERE id = ?"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
    }

    private fun setTags(tagsJson: String) {
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET tags = ?::jsonb WHERE id = ?").use { ps ->
                ps.setString(1, tagsJson)
                ps.setLong(2, fx.datasource.id)
                ps.executeUpdate()
            }
        }
    }

    private fun decide() = decideQuery(
        principal = principal,
        ds = fx.datasourceStore.get(fx.datasource.id)!!,
        sql = preparedSql,
        channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id),
        policyStore = fx.policyStore,
        accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore,
        roleResolver = fx.roleResolver,
        authz = fx.authz,
    )

    @Test
    fun `unmaskable permission is fail-closed and populated only on the final MASK path`() {
        setTags("""["system:production"]""")
        val floor = decide()
        assertEquals(EnfAction.MASK, floor.action)
        assertFalse(floor.unmaskablePermitted, "no sql.unmaskable permit must refuse binary relay")

        // The development preset also grants result.read.unmasked, so the final decision is ALLOW. The wire
        // bit deliberately remains false because the proxy never consults it for ALLOW decisions.
        setTags("""["system:development"]""")
        val development = decide()
        assertEquals(EnfAction.ALLOW, development.action)
        assertFalse(development.unmaskablePermitted, "the capability bit is MASK-only")

        // Isolate the security-critical combination: keep the PII read MASKED, but permit the datasource-level
        // unmaskable relay. This is the exact branch the binary proxy consumes.
        setTags("""["system:production"]""")
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-mysql-binary-unmaskable",
                cedarSrc = """permit(principal, action == Action::"sql.unmaskable", resource == Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        val permitted = decide()
        assertEquals(EnfAction.MASK, permitted.action)
        assertTrue(permitted.unmaskablePermitted, "MASK + sql.unmaskable permit must surface the relay capability")
    }
}
