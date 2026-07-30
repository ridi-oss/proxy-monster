package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.AuthorizationCodeInput
import com.ridi.oss.proxymonster.auth.ConsumeAuthorizationCodeInput
import com.ridi.oss.proxymonster.auth.OAuthAuthorizationStore
import com.ridi.oss.proxymonster.auth.pkceS256
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.management.DatasourceManagementService
import com.ridi.oss.proxymonster.controlplane.management.IdentityManagementService
import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import com.ridi.oss.proxymonster.controlplane.management.PolicyManagementService
import com.ridi.oss.proxymonster.controlplane.mcp.installMcp
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.testing.testApplication
import io.modelcontextprotocol.kotlin.sdk.client.StreamableHttpError
import io.modelcontextprotocol.kotlin.sdk.client.mcpStreamableHttp
import io.modelcontextprotocol.kotlin.sdk.types.McpException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpServerDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var oauth: OAuthAuthorizationStore

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_mcp_server"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        oauth = OAuthAuthorizationStore(dataSource)
    }

    @AfterAll
    fun close() {
        (dataSource as? AutoCloseable)?.close()
    }

    @Test
    fun `resource metadata and bearer failures are standards shaped`() = testApplication {
        application { installTestMcp() }
        val client = createClient {
            expectSuccess = false
            install(ClientContentNegotiation) { json(TEST_JSON) }
        }

        val metadata = client.get("/.well-known/oauth-protected-resource/mcp")
        assertEquals(HttpStatusCode.OK, metadata.status)
        val metadataBody = metadata.body<JsonObject>()
        assertEquals(RESOURCE, metadataBody.getValue("resource").jsonPrimitive.content)
        assertEquals("http://localhost", metadataBody.getValue("authorization_servers").jsonArray.single().jsonPrimitive.content)

        val noToken = client.post("/mcp") {
            acceptMcp()
            setBody(toolCall(1, "list_roles"))
        }
        assertEquals(HttpStatusCode.Unauthorized, noToken.status)
        assertContains(assertNotNull(noToken.headers[HttpHeaders.WWWAuthenticate]), "resource_metadata=\"$METADATA_URI\"")

        val foreignOrigin = client.post("/mcp") {
            acceptMcp()
            header(HttpHeaders.Origin, "https://evil.example")
            setBody(toolCall(2, "list_roles"))
        }
        assertEquals(HttpStatusCode.Forbidden, foreignOrigin.status)
        assertEquals("mcp.invalid_origin", TEST_JSON.parseToJsonElement(foreignOrigin.bodyAsText()).jsonObject["code"]?.jsonPrimitive?.content)

        val foreignHost = client.post("/mcp") {
            acceptMcp()
            header(HttpHeaders.Host, "evil.example")
            setBody(toolCall(3, "list_roles"))
        }
        assertEquals(HttpStatusCode.Forbidden, foreignHost.status)
        assertEquals("mcp.invalid_host", TEST_JSON.parseToJsonElement(foreignHost.bodyAsText()).jsonObject["code"]?.jsonPrimitive?.content)
    }

    @Test
    fun `an https resource admits a cleartext-forwarded request whose Host carries no port`() = testApplication {
        // The production shape behind a TLS-terminating edge: the resource is https (default port 443),
        // the edge forwards cleartext to the container, and the client's Host omits the port because it
        // is the scheme default. The gate must clear the host and move on to the bearer check — reaching
        // `common.invalid_token` (not `mcp.invalid_host`) is what proves the authority matched.
        application { installTestMcp("https://console.example.com/mcp") }
        val client = createClient {
            expectSuccess = false
            install(ClientContentNegotiation) { json(TEST_JSON) }
        }
        val response = client.post("/mcp") {
            acceptMcp()
            header(HttpHeaders.Host, "console.example.com")
            setBody(toolCall(1, "list_roles"))
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(
            "common.invalid_token",
            TEST_JSON.parseToJsonElement(response.bodyAsText()).jsonObject["code"]?.jsonPrimitive?.content,
        )

        // A port on the Host is ignored, not compared. `:443` alone would also pass an implementation
        // that compared EFFECTIVE default ports, so the case that actually pins the property is a
        // non-default port against an https resource: it must still reach the bearer check.
        for (authority in listOf("console.example.com:443", "console.example.com:8443")) {
            val withPort = client.post("/mcp") {
                acceptMcp()
                header(HttpHeaders.Host, authority)
                setBody(toolCall(2, "list_roles"))
            }
            assertEquals(HttpStatusCode.Unauthorized, withPort.status, authority)
        }

        // The host is still enforced: a foreign name on the same listener is refused.
        val foreign = client.post("/mcp") {
            acceptMcp()
            header(HttpHeaders.Host, "evil.example")
            setBody(toolCall(3, "list_roles"))
        }
        assertEquals(HttpStatusCode.Forbidden, foreign.status)
        assertEquals("mcp.invalid_host", TEST_JSON.parseToJsonElement(foreign.bodyAsText()).jsonObject["code"]?.jsonPrimitive?.content)
    }

    @Test
    fun `an IPv6 literal resource host matches a forwarded authority`() = testApplication {
        // Java exposes an IPv6 URI host bracketed (`[::1]`) while a forwarded authority resolves to the
        // bare address, so comparing them raw rejects every request to a valid IPv6 resource.
        //
        // Only the FORWARDED path is asserted. Ktor's own `host()` shreds a direct `Host: [::1]` at the
        // literal's first colon and yields `[`, so an IPv6 resource reached without a trusted edge is
        // unreachable for a reason that lives upstream of this gate (KNOWN_LIMITATIONS.md).
        // testApplication's peer address is the literal string "localhost", which only isTrustedEdge's
        // exact-match arm accepts (it never resolves a hostname — see TrustedEdgeCidrTest).
        application { installTestMcp("http://[::1]/mcp", trustedProxies = setOf("localhost")) }
        val client = createClient {
            expectSuccess = false
            install(ClientContentNegotiation) { json(TEST_JSON) }
        }
        val response = client.post("/mcp") {
            acceptMcp()
            header("X-Forwarded-Host", "[::1]")
            setBody(toolCall(1, "list_roles"))
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(
            "common.invalid_token",
            TEST_JSON.parseToJsonElement(response.bodyAsText()).jsonObject["code"]?.jsonPrimitive?.content,
        )

        val foreign = client.post("/mcp") {
            acceptMcp()
            header("X-Forwarded-Host", "[::2]")
            setBody(toolCall(2, "list_roles"))
        }
        assertEquals(HttpStatusCode.Forbidden, foreign.status)
        assertEquals("mcp.invalid_host", TEST_JSON.parseToJsonElement(foreign.bodyAsText()).jsonObject["code"]?.jsonPrimitive?.content)
    }

    @Test
    fun `tool catalog is complete localized and scope cannot grant a write`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-catalog@example.com"
        grantRole(principal, "system:admin")
        val readToken = token(principal, setOf("mcp:read"))
        val client = createClient { expectSuccess = false }

        val sdk = client.mcpStreamableHttp("/mcp") {
            header(HttpHeaders.Authorization, "Bearer $readToken")
            header(HttpHeaders.AcceptLanguage, "ko")
        }
        val tools = sdk.listTools().tools
        assertEquals(McpCapabilityRegistry.approvedToolNames, tools.map { it.name }.toSet())
        assertTrue(tools.all { !it.description.isNullOrBlank() })
        assertContains(assertNotNull(tools.single { it.name == "create_role" }.description), "역할")

        val denied = client.post("/mcp") {
            acceptMcp(readToken)
            setBody(toolCall(10, "create_role", buildJsonObject { put("name", "scope-must-not-authorize") }).toString())
        }
        assertEquals(HttpStatusCode.Forbidden, denied.status)
        val challenge = assertNotNull(denied.headers[HttpHeaders.WWWAuthenticate])
        assertContains(challenge, "error=\"insufficient_scope\"")
        assertContains(challenge, "scope=\"mcp:policies:write\"")
        val error = rpcStructuredContent(denied.bodyAsText())
        assertEquals("mcp.insufficient_scope", error.getValue("code").jsonPrimitive.content)
        assertTrue(error.getValue("message_en").jsonPrimitive.content.isNotBlank())
        assertTrue(error.getValue("message_ko").jsonPrimitive.content.isNotBlank())
    }

    @Test
    fun `mutations are atomic idempotent audited and roles are resolved live`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-mutation@example.com"
        grantRole(principal, "system:admin")
        val token = token(principal, setOf("mcp:read", "mcp:datasources:write", "mcp:policies:write"))
        val client = createClient { expectSuccess = false }
        val sdk = client.mcpStreamableHttp("/mcp") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        val roleName = "mcp-idempotent-role"
        val arguments = mapOf(
            "name" to roleName,
            "description" to "created once",
            "idempotencyKey" to "create-role-once",
        )

        val first = sdk.callTool("create_role", arguments)
        val replay = sdk.callTool("create_role", arguments)
        assertEquals(first.structuredContent, replay.structuredContent)
        assertEquals(1L, scalar("SELECT count(*) FROM app_role WHERE name=?", roleName))
        assertEquals(
            listOf("ALLOW", "IDEMPOTENT_REPLAY"),
            strings(
                """SELECT outcome FROM audit_event
                   WHERE principal=? AND statement='[MCP create_role]' ORDER BY id""",
                principal,
            ),
        )
        assertEquals(
            listOf("mcp"),
            strings(
                """SELECT DISTINCT channel FROM audit_event
                   WHERE principal=? AND statement='[MCP create_role]'""",
                principal,
            ),
        )

        val conflict = sdk.callTool("create_role", arguments + ("description" to "different input"))
        assertEquals(true, conflict.isError)
        assertEquals("mcp.idempotency_conflict", conflict.structuredContent?.get("code")?.jsonPrimitive?.content)

        val malformed = sdk.callTool("create_role", mapOf("name" to "must-not-exist", "unexpected" to true))
        assertEquals(true, malformed.isError)
        assertEquals("mcp.invalid_request", malformed.structuredContent?.get("code")?.jsonPrimitive?.content)
        assertEquals(0L, scalar("SELECT count(*) FROM app_role WHERE name=?", "must-not-exist"))
        assertEquals(
            listOf("mcp.invalid_request"),
            strings(
                """SELECT outcome FROM audit_event
                   WHERE principal=? AND statement='[MCP create_role]' AND outcome='mcp.invalid_request'""",
                principal,
            ),
        )

        val malformedDatasource = sdk.callTool(
            "set_column_classification",
            mapOf("datasource" to mapOf("invalid" to true), "table" to "users", "column" to "rrn", "tags" to listOf("pii")),
        )
        assertEquals(true, malformedDatasource.isError)
        assertEquals("mcp.invalid_request", malformedDatasource.structuredContent?.get("code")?.jsonPrimitive?.content)
        assertEquals(
            listOf("mcp.invalid_request"),
            strings(
                """SELECT outcome FROM audit_event
                   WHERE principal=? AND statement='[MCP set_column_classification]'""",
                principal,
            ),
        )

        unassignRole(principal, "system:admin")
        assertFailsWith<McpException> {
            sdk.callTool(
                "create_role",
                mapOf("name" to "must-not-exist-after-role-loss", "idempotencyKey" to "after-role-loss"),
            )
        }.also { assertEquals(HttpStatusCode.Forbidden.value, (it.cause as? StreamableHttpError)?.code) }
        assertEquals(0L, scalar("SELECT count(*) FROM app_role WHERE name=?", "must-not-exist-after-role-loss"))
    }

    @Test
    fun `Cedar authority remains narrower than a broad consent scope`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-policy-only@example.com"
        val role = core.policyStore.createRole(RoleInput("mcp-policy-only", "Policies but not identity"))
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                "mcp-policy-only",
                """permit(principal in Role::"mcp-policy-only", action == Action::"admin.policies", resource);""",
            ),
            principal,
        )
        grantRole(principal, role.name)
        val accessToken = token(
            principal,
            setOf("mcp:read", "mcp:policies:write", "mcp:identity:write"),
        )
        val client = createClient { expectSuccess = false }
        val sdk = client.mcpStreamableHttp("/mcp") {
            header(HttpHeaders.Authorization, "Bearer $accessToken")
        }

        val created = sdk.callTool("create_role", mapOf("name" to "mcp-created-by-policy-admin"))
        assertTrue(created.isError != true)

        assertFailsWith<McpException> {
            sdk.callTool(
                "assign_role",
                mapOf("principal" to principal, "roleName" to "mcp-created-by-policy-admin"),
            )
        }.also { assertEquals(HttpStatusCode.Forbidden.value, (it.cause as? StreamableHttpError)?.code) }
        assertEquals(
            listOf("common.forbidden"),
            strings(
                """SELECT outcome FROM audit_event
                   WHERE principal=? AND statement='[MCP assign_role]' ORDER BY id""",
                principal,
            ),
        )

        assertFailsWith<McpException> { sdk.callTool("list_users", emptyMap()) }
            .also { assertEquals(HttpStatusCode.Forbidden.value, (it.cause as? StreamableHttpError)?.code) }
        assertEquals(
            listOf("common.forbidden"),
            strings(
                """SELECT outcome FROM audit_event
                   WHERE principal=? AND statement='[MCP list_users]' ORDER BY id""",
                principal,
            ),
        )
    }

    @Test
    fun `representative tool families dispatch successfully with structured liveness and audit`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-tool-families@example.com"
        grantRole(principal, "system:admin")
        seedDatasource("mcp-family-datasource")
        val accessToken = token(
            principal,
            setOf("mcp:read", "mcp:datasources:write", "mcp:policies:write", "mcp:identity:write"),
        )
        val sdk = client.mcpStreamableHttp("/mcp") { header(HttpHeaders.Authorization, "Bearer $accessToken") }

        assertToolSuccess(sdk.callTool("create_user", mapOf("principal" to "mcp-managed-user@example.com")))
        assertToolSuccess(sdk.callTool("create_group", mapOf("name" to "mcp-managed-group")))
        assertToolSuccess(
            sdk.callTool(
                "add_group_member",
                mapOf("groupName" to "mcp-managed-group", "principal" to "mcp-managed-user@example.com"),
            ),
        )
        assertToolSuccess(sdk.callTool("create_role", mapOf("name" to "mcp-managed-role")))
        assertToolSuccess(
            sdk.callTool(
                "assign_role",
                mapOf("principal" to "mcp-managed-user@example.com", "roleName" to "mcp-managed-role"),
            ),
        )
        assertToolSuccess(sdk.callTool("create_mask_fn", mapOf("name" to "mcp-managed-mask", "kind" to "FIXED")))
        assertToolSuccess(
            sdk.callTool(
                "create_policy",
                mapOf(
                    "name" to "mcp-managed-policy",
                    "cedarSrc" to "permit(principal in Role::\"mcp-managed-role\", action == Action::\"admin.identity\", resource);",
                ),
            ),
        )
        assertToolSuccess(
            sdk.callTool(
                "set_column_classification",
                mapOf(
                    "datasource" to "mcp-family-datasource",
                    "schema" to "public",
                    "table" to "users",
                    "column" to "rrn",
                    "tags" to listOf("pii"),
                    "maskFnName" to "mcp-managed-mask",
                ),
            ),
        )

        val liveness = assertNotNull(
            sdk.callTool("get_datasource_liveness", mapOf("datasource" to "mcp-family-datasource")).structuredContent,
        ).getValue("result").jsonObject
        assertEquals("mcp-family-datasource", liveness.getValue("datasource").jsonPrimitive.content)
        assertTrue("attached" in liveness)
        assertTrue("detail" !in liveness)
        assertTrue("message" !in liveness)

        val tags = assertNotNull(
            sdk.callTool("list_column_tags", mapOf("datasource" to "mcp-family-datasource")).structuredContent,
        ).getValue("result").jsonArray
        assertEquals("rrn", tags.single().jsonObject.getValue("column").jsonPrimitive.content)
        assertEquals(8L, scalar("SELECT count(*) FROM audit_event WHERE principal=?", principal))
    }

    @Test
    fun `a failed audit insert rolls back its management mutation`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-audit-rollback@example.com"
        grantRole(principal, "system:admin")
        val accessToken = token(principal, setOf("mcp:read", "mcp:identity:write"))
        val sdk = client.mcpStreamableHttp("/mcp") { header(HttpHeaders.Authorization, "Bearer $accessToken") }
        execute(
            """CREATE OR REPLACE FUNCTION pm_test_fail_mcp_audit() RETURNS trigger AS ${'$'}body${'$'}
               BEGIN RAISE EXCEPTION 'forced MCP audit failure'; END
               ${'$'}body${'$'} LANGUAGE plpgsql""",
        )
        execute(
            """CREATE TRIGGER pm_test_fail_mcp_audit BEFORE INSERT ON audit_event
               FOR EACH ROW WHEN (NEW.statement = '[MCP create_group]')
               EXECUTE FUNCTION pm_test_fail_mcp_audit()""",
        )
        try {
            val failed = sdk.callTool("create_group", mapOf("name" to "must-roll-back-with-audit"))
            assertEquals(true, failed.isError)
            assertEquals(0L, scalar("SELECT count(*) FROM app_group WHERE name=?", "must-roll-back-with-audit"))
        } finally {
            execute("DROP TRIGGER pm_test_fail_mcp_audit ON audit_event")
            execute("DROP FUNCTION pm_test_fail_mcp_audit()")
        }
    }

    private fun io.ktor.server.application.Application.installTestMcp(
        mcpResource: String = RESOURCE,
        trustedProxies: Set<String> = emptySet(),
    ) {
        install(ContentNegotiation) { json(TEST_JSON) }
        val datasourceService = DatasourceManagementService(core.datasourceStore, core.proxyEventsHub, TableDetailService(core))
        val policyService = PolicyManagementService(core.cedarPolicyStore, core.policyStore)
        val identityService = IdentityManagementService(
            dataSource, core.userGroupStore, core.policyStore, core.tokenStore, core.accessStore,
            PrincipalSessionStore(dataSource, null),
        )
        installMcp(config(mcpResource, trustedProxies), core, datasourceService, policyService, identityService)
    }

    private fun io.ktor.client.request.HttpRequestBuilder.acceptMcp(token: String? = null) {
        header(HttpHeaders.Accept, "application/json, text/event-stream")
        contentType(ContentType.Application.Json)
        header("MCP-Protocol-Version", "2025-06-18")
        token?.let { header(HttpHeaders.Authorization, "Bearer $it") }
    }

    private fun toolCall(id: Int, name: String, arguments: JsonObject = JsonObject(emptyMap())) = buildJsonObject {
        put("jsonrpc", "2.0")
        put("id", id)
        put("method", "tools/call")
        put("params", buildJsonObject {
            put("name", name)
            put("arguments", arguments)
        })
    }

    private fun rpcStructuredContent(body: String): JsonObject =
        TEST_JSON.parseToJsonElement(body).jsonObject.getValue("result").jsonObject
            .getValue("structuredContent").jsonObject

    private fun token(principal: String, scopes: Set<String>): String {
        val consent = oauth.rememberConsent(principal, CLIENT_ID, RESOURCE, scopes)
        val code = oauth.createAuthorizationCode(
            AuthorizationCodeInput(CLIENT_ID, principal, REDIRECT_URI, RESOURCE, scopes, CHALLENGE, consentId = consent.id),
        )
        return assertNotNull(
            oauth.consumeAuthorizationCode(
                ConsumeAuthorizationCodeInput(code, CLIENT_ID, REDIRECT_URI, RESOURCE, VERIFIER, 600, 3_600),
            ),
        ).accessToken
    }

    private fun grantRole(principal: String, roleName: String) {
        dataSource.connection.use { connection ->
            connection.prepareStatement(
                """INSERT INTO principal_role(principal, role_id)
                   SELECT ?, id FROM app_role WHERE name=? ON CONFLICT DO NOTHING""",
            ).use { statement ->
                statement.setString(1, principal)
                statement.setString(2, roleName)
                assertEquals(1, statement.executeUpdate())
            }
        }
    }

    private fun unassignRole(principal: String, roleName: String) {
        dataSource.connection.use { connection ->
            connection.prepareStatement(
                """DELETE FROM principal_role
                   WHERE principal=? AND role_id=(SELECT id FROM app_role WHERE name=?)""",
            ).use { statement ->
                statement.setString(1, principal)
                statement.setString(2, roleName)
                assertEquals(1, statement.executeUpdate())
            }
        }
    }

    private fun scalar(sql: String, value: String): Long = dataSource.connection.use { connection ->
        connection.prepareStatement(sql).use { statement ->
            statement.setString(1, value)
            statement.executeQuery().use { result -> result.next(); result.getLong(1) }
        }
    }

    private fun strings(sql: String, value: String): List<String> = dataSource.connection.use { connection ->
        connection.prepareStatement(sql).use { statement ->
            statement.setString(1, value)
            statement.executeQuery().use { result ->
                buildList { while (result.next()) add(result.getString(1)) }
            }
        }
    }

    private fun execute(sql: String) {
        dataSource.connection.use { connection -> connection.createStatement().use { it.execute(sql) } }
    }

    private fun seedDatasource(name: String) {
        dataSource.connection.use { connection ->
            val id = connection.prepareStatement(
                """INSERT INTO datasource(name, engine, host, port, db_name, default_schemas)
                   VALUES (?, 'postgres', '127.0.0.1', 5432, 'mcp', '["public"]'::jsonb) RETURNING id""",
            ).use { statement ->
                statement.setString(1, name)
                statement.executeQuery().use { result -> result.next(); result.getLong(1) }
            }
            connection.prepareStatement(
                """INSERT INTO catalog_column
                   (datasource_id, schema_name, table_name, column_name, data_type, sql_type, ordinal, nullable)
                   VALUES (?, 'public', 'users', 'rrn', 'text', 'VARCHAR', 1, true)""",
            ).use { statement -> statement.setLong(1, id); statement.executeUpdate() }
        }
    }

    private fun assertToolSuccess(result: io.modelcontextprotocol.kotlin.sdk.types.CallToolResult) {
        assertTrue(result.isError != true, result.structuredContent.toString())
        assertNotNull(result.structuredContent)
    }

    private fun config(mcpResource: String = RESOURCE, trustedProxies: Set<String> = emptySet()) = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = false,
        secretToken = null,
        sessionSecret = "mcp-server-test-secret",
        oidc = null,
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 3_600,
        idpRecheckIntervalSeconds = 600,
        devMarker = false,
        mcpResource = mcpResource,
        trustedProxies = trustedProxies,
    )

    private companion object {
        val TEST_JSON = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        const val RESOURCE = "http://localhost/mcp"
        const val METADATA_URI = "http://localhost/.well-known/oauth-protected-resource/mcp"
        const val CLIENT_ID = "https://client.example/mcp.json"
        const val REDIRECT_URI = "http://127.0.0.1:43110/callback"
        val VERIFIER = "m".repeat(43)
        val CHALLENGE = pkceS256(VERIFIER)
    }
}
