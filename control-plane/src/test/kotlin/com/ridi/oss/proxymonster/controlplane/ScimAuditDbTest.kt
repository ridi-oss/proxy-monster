package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.auditChainHead
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.delete
import io.ktor.client.request.header
import io.ktor.client.request.patch
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.slf4j.LoggerFactory
import javax.sql.DataSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Every SCIM mutation ([scimRoutes]) records ONE `kind="admin"` audit event, atomic with the store
 * change, on the SCIM channel under the fixed synthetic `scim` principal (SCIM authenticates with one
 * standing bearer token — there is no per-client identity). Driven through the real routes over a Ktor
 * test host, the same seam App.kt wires, so the handler's inTx + recorder plumbing is proven end to end
 * (mirrors ManagementAuditDbTest for the console path).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ScimAuditDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var tokenStore: TokenStore
    private lateinit var accessStore: AccessStore
    private lateinit var daemonSessionStore: PrincipalSessionStore
    private lateinit var recorder: ManagementAuditRecorder
    private val log = LoggerFactory.getLogger("scim-audit-test")
    private val scimToken = "s3cret-scim-token"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_scim_audit"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        userGroupStore = UserGroupStore(dataSource)
        tokenStore = TokenStore(dataSource)
        accessStore = AccessStore(dataSource)
        daemonSessionStore = PrincipalSessionStore(dataSource, null)
        recorder = ManagementAuditRecorder(AuditStore(dataSource))
    }

    @Test
    fun `user provision, replace, deactivate, activate, and deprovision each record one admin event`() = testApplication {
        scimApp()
        val ext = "okta-audit-user-${System.nanoTime()}"
        val principal = "scim-audit-user-${System.nanoTime()}@example.com"

        assertEquals(
            HttpStatusCode.Created,
            client.post("/api/scim/v2/Users") {
                scimHeaders(); setBody("""{"externalId":"$ext","userName":"$principal","active":true}""")
            }.status,
        )
        assertScimEvent(userResource(principal), "scim provision user '$principal'")

        val id = userGroupStore.findUserByExternalId(ext)!!.id

        assertEquals(HttpStatusCode.OK, client.patch("/api/scim/v2/Users/$id") { scimHeaders(); setBody(setActiveBody(false)) }.status)
        assertScimEvent(userResource(principal), "scim deactivate user '$principal'")

        assertEquals(HttpStatusCode.OK, client.patch("/api/scim/v2/Users/$id") { scimHeaders(); setBody(setActiveBody(true)) }.status)
        assertScimEvent(userResource(principal), "scim activate user '$principal'")

        assertEquals(
            HttpStatusCode.OK,
            client.put("/api/scim/v2/Users/$id") {
                scimHeaders(); setBody("""{"externalId":"$ext","userName":"$principal","active":true}""")
            }.status,
        )
        assertScimEvent(userResource(principal), "scim replace user '$principal'")

        assertEquals(HttpStatusCode.NoContent, client.delete("/api/scim/v2/Users/$id") { scimHeaders() }.status)
        assertScimEvent(userResource(principal), "scim deprovision user '$principal'")

        verifyAuditChain(dataSource)
    }

    @Test
    fun `group provision, membership add and remove, and delete record one event each while a no-op records none`() = testApplication {
        scimApp()
        val gExt = "okta-audit-group-${System.nanoTime()}"
        val gName = "scim-audit-group-${System.nanoTime()}"
        // The member's own provisioning is not under test — create it directly through the store.
        val member = userGroupStore.upsertScimUser(
            externalId = "okta-audit-member-${System.nanoTime()}",
            principal = "scim-audit-member-${System.nanoTime()}@example.com",
            email = null, displayName = null, active = true,
        )

        assertEquals(
            HttpStatusCode.Created,
            client.post("/api/scim/v2/Groups") {
                scimHeaders(); setBody("""{"externalId":"$gExt","displayName":"$gName","members":[]}""")
            }.status,
        )
        assertScimEvent(groupResource(gName), "scim provision group '$gName'")

        val gid = userGroupStore.findGroupByExternalId(gExt)!!.id

        assertEquals(HttpStatusCode.OK, client.patch("/api/scim/v2/Groups/$gid") { scimHeaders(); setBody(membersBody("add", member.id)) }.status)
        assertScimEvent(groupResource(gName), "scim add '${member.principal}' to group '$gName'")

        assertEquals(HttpStatusCode.OK, client.patch("/api/scim/v2/Groups/$gid") { scimHeaders(); setBody(membersBody("remove", member.id)) }.status)
        assertScimEvent(groupResource(gName), "scim remove '${member.principal}' from group '$gName'")

        // Removing a member who is no longer present changes nothing, so it must record nothing — the
        // remove row count stays at the single event the first removal wrote.
        assertEquals(HttpStatusCode.OK, client.patch("/api/scim/v2/Groups/$gid") { scimHeaders(); setBody(membersBody("remove", member.id)) }.status)
        assertEquals(
            1,
            count(
                "SELECT count(*) FROM audit_event WHERE resource=? AND statement=?",
                groupResource(gName), "scim remove '${member.principal}' from group '$gName'",
            ),
        )

        assertEquals(HttpStatusCode.NoContent, client.delete("/api/scim/v2/Groups/$gid") { scimHeaders() }.status)
        assertScimEvent(groupResource(gName), "scim delete group '$gName'")

        verifyAuditChain(dataSource)
    }

    @Test
    fun `a rejected audit insert rolls back the SCIM mutation`() = testApplication {
        scimApp()
        val ext = "okta-audit-rollback-${System.nanoTime()}"
        val principal = "scim-audit-rollback-${System.nanoTime()}@example.com"
        val headBefore = auditChainHead(dataSource)
        execute(
            """CREATE OR REPLACE FUNCTION pm_test_reject_scim_audit() RETURNS trigger AS ${'$'}body${'$'}
               BEGIN RAISE EXCEPTION 'forced scim audit failure'; END
               ${'$'}body${'$'} LANGUAGE plpgsql""",
        )
        execute(
            """CREATE TRIGGER pm_test_reject_scim_audit BEFORE INSERT ON audit_event
               FOR EACH ROW WHEN (NEW.kind = 'admin' AND NEW.resource = 'User::"$principal"')
               EXECUTE FUNCTION pm_test_reject_scim_audit()""",
        )
        try {
            client.post("/api/scim/v2/Users") {
                scimHeaders(); setBody("""{"externalId":"$ext","userName":"$principal","active":true}""")
            }
            assertEquals(0, count("SELECT count(*) FROM app_user WHERE external_id=?", ext))
            assertEquals(0, count("SELECT count(*) FROM audit_event WHERE resource=?", userResource(principal)))
            val headAfter = auditChainHead(dataSource)
            assertEquals(headBefore.first, headAfter.first)
            assertContentEquals(headBefore.second, headAfter.second)
        } finally {
            execute("DROP TRIGGER IF EXISTS pm_test_reject_scim_audit ON audit_event")
            execute("DROP FUNCTION IF EXISTS pm_test_reject_scim_audit()")
        }
        verifyAuditChain(dataSource)
    }

    private fun ApplicationTestBuilder.scimApp() = application {
        install(ContentNegotiation) { json() }
        routing {
            scimRoutes(
                testScimConfig(scimToken = scimToken, trustedProxies = setOf("localhost")),
                userGroupStore, tokenStore, accessStore, daemonSessionStore, recorder, log,
            )
        }
    }

    // The gate is bearer + TLS; a trusted-edge X-Forwarded-Proto stands in for direct HTTPS on the test host.
    private fun HttpRequestBuilder.scimHeaders() {
        header("X-Forwarded-Proto", "https")
        header(HttpHeaders.Authorization, "Bearer $scimToken")
        contentType(ContentType.Application.Json)
    }

    private fun setActiveBody(active: Boolean) =
        """{"Operations":[{"op":"replace","path":"active","value":$active}]}"""

    private fun membersBody(op: String, userId: Long) =
        """{"Operations":[{"op":"$op","path":"members","value":[{"value":"$userId"}]}]}"""

    private fun userResource(principal: String) = """User::"$principal""""
    private fun groupResource(name: String) = """Group::"$name""""

    private fun assertScimEvent(resource: String, statement: String) {
        val rows = dataSource.connection.use { c ->
            c.prepareStatement(
                """SELECT action, resource, statement, outcome, kind, channel, decision, datasource, principal
                   FROM audit_event WHERE resource=? AND statement=? ORDER BY id""",
            ).use { ps ->
                ps.setString(1, resource); ps.setString(2, statement)
                ps.executeQuery().use { rs -> buildList { while (rs.next()) add((1..9).map(rs::getString)) } }
            }
        }
        assertEquals(1, rows.size, "expected exactly one audit row for $resource / $statement")
        assertEquals(
            listOf("admin.identity", resource, statement, "ALLOW", "admin", "scim", "ALLOW", "control-plane", "scim"),
            rows.single(),
        )
    }

    private fun count(sql: String, vararg values: String): Int = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps ->
            values.forEachIndexed { index, value -> ps.setString(index + 1, value) }
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private fun execute(sql: String) =
        dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }
}
