package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Real-Postgres proof for docs/policy-store.md: readiness uses the same direct ∪ active
 * group-member ∪ active-JIT union as [RoleResolver.resolve], so a clean-but-unopened install is
 * reported without marking the process down and every actually resolvable admin path clears it.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ReadinessDiagnosticDbTest {
    @BeforeAll
    fun requireDatabase() {
        requireDockerOrSkip()
    }

    @Test
    fun `hasActiveAssignee mirrors resolve across direct group and JIT role paths`() {
        val ds = migratedDatabase("pm_readiness_resolver")
        val resolver = RoleResolver(ds, UserGroupStore(ds), AccessStore(ds))
        val roleId = scalarLong(ds, "SELECT id FROM app_role WHERE name='system:admin'")
        val groupId = scalarLong(ds, "SELECT id FROM app_group WHERE name='system:admin'")

        assertFalse(resolver.hasActiveAssignee("system:admin"), "the seed's member-less group_role link is not an assignee")

        execute(ds, "INSERT INTO principal_role (principal, role_id) VALUES ('direct@example.com', $roleId)")
        assertResolvedAndDiagnosed(resolver, "direct@example.com", expected = true)
        execute(ds, "INSERT INTO app_user (principal, active) VALUES ('direct@example.com', false)")
        assertResolvedAndDiagnosed(resolver, "direct@example.com", expected = false)
        execute(ds, "UPDATE app_user SET active=true WHERE principal='direct@example.com'")
        assertResolvedAndDiagnosed(resolver, "direct@example.com", expected = true)
        execute(ds, "DELETE FROM principal_role WHERE principal='direct@example.com'")
        execute(ds, "DELETE FROM app_user WHERE principal='direct@example.com'")
        assertFalse(resolver.hasActiveAssignee("system:admin"))

        execute(ds, "INSERT INTO app_user (principal, active) VALUES ('group@example.com', true)")
        val groupUserId = scalarLong(ds, "SELECT id FROM app_user WHERE principal='group@example.com'")
        execute(ds, "INSERT INTO group_member (group_id, user_id) VALUES ($groupId, $groupUserId)")
        assertResolvedAndDiagnosed(resolver, "group@example.com", expected = true)
        execute(ds, "UPDATE app_user SET active=false WHERE principal='group@example.com'")
        assertResolvedAndDiagnosed(resolver, "group@example.com", expected = false)
        execute(ds, "DELETE FROM app_user WHERE principal='group@example.com'")
        assertFalse(resolver.hasActiveAssignee("system:admin"))

        execute(
            ds,
            """INSERT INTO access_grant (principal, role_id, granted_by, expires_at)
               VALUES ('jit@example.com', $roleId, 'approver@example.com', now() + interval '1 hour')""",
        )
        assertResolvedAndDiagnosed(resolver, "jit@example.com", expected = true)
        execute(ds, "UPDATE access_grant SET expires_at=now() - interval '1 second' WHERE principal='jit@example.com'")
        assertResolvedAndDiagnosed(resolver, "jit@example.com", expected = false)
        execute(ds, "UPDATE access_grant SET expires_at=NULL, revoked_at=NULL WHERE principal='jit@example.com'")
        assertResolvedAndDiagnosed(resolver, "jit@example.com", expected = true)
        execute(ds, "INSERT INTO app_user (principal, active) VALUES ('jit@example.com', false)")
        assertResolvedAndDiagnosed(resolver, "jit@example.com", expected = false)
        execute(ds, "UPDATE app_user SET active=true WHERE principal='jit@example.com'")
        execute(ds, "UPDATE access_grant SET revoked_at=now() WHERE principal='jit@example.com'")
        assertResolvedAndDiagnosed(resolver, "jit@example.com", expected = false)
    }

    @Test
    fun `health stays ok and reports whether system-admin has an active assignee`() {
        val ds = migratedDatabase("pm_readiness_health")
        val roleId = scalarLong(ds, "SELECT id FROM app_role WHERE name='system:admin'")

        testApplication {
            application { module(config(), ControlPlaneCore(ds)) }

            val unopened = client.get("/health")
            assertEquals(HttpStatusCode.OK, unopened.status)
            val unopenedBody = Json.parseToJsonElement(unopened.bodyAsText()).jsonObject
            assertEquals("ok", unopenedBody.getValue("status").jsonPrimitive.content)
            assertEquals(
                listOf("system:admin role has no active assignee"),
                unopenedBody.getValue("diagnostics").jsonArray.map { it.jsonPrimitive.content },
            )

            execute(ds, "INSERT INTO principal_role (principal, role_id) VALUES ('admin@example.com', $roleId)")
            val opened = client.get("/health")
            assertEquals(HttpStatusCode.OK, opened.status)
            val openedBody = Json.parseToJsonElement(opened.bodyAsText()).jsonObject
            assertEquals("ok", openedBody.getValue("status").jsonPrimitive.content)
            assertTrue(openedBody.getValue("diagnostics").jsonArray.isEmpty())
        }
    }

    private fun assertResolvedAndDiagnosed(resolver: RoleResolver, principal: String, expected: Boolean) {
        assertEquals(expected, "system:admin" in resolver.resolve(principal), "resolve disagreed for $principal")
        assertEquals(expected, resolver.hasActiveAssignee("system:admin"), "readiness disagreed for $principal")
    }

    private fun migratedDatabase(prefix: String): DataSource {
        val ds = SharedPostgres.hikari(SharedPostgres.migratedDatabase(prefix))
        return ds
    }

    private fun execute(ds: DataSource, sql: String) {
        ds.connection.use { c -> c.createStatement().use { it.executeUpdate(sql) } }
    }

    private fun scalarLong(ds: DataSource, sql: String): Long = ds.connection.use { c ->
        c.createStatement().use { st -> st.executeQuery(sql).use { rs -> rs.next(); rs.getLong(1) } }
    }

    private fun config() = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = true,
        secretToken = null,
        sessionSecret = "readiness-test-secret",
        oidc = null,
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 3600,
        idpRecheckIntervalSeconds = 600,
        devMarker = true,
    )
}
