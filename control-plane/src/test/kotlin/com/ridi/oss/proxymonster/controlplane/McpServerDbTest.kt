package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.AuthorizationCodeInput
import com.ridi.oss.proxymonster.auth.ConsumeAuthorizationCodeInput
import com.ridi.oss.proxymonster.auth.OAuthAuthorizationStore
import com.ridi.oss.proxymonster.auth.pkceS256
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.controlplane.management.DatasourceManagementService
import com.ridi.oss.proxymonster.controlplane.management.IdentityManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import com.ridi.oss.proxymonster.controlplane.management.PolicyManagementService
import com.ridi.oss.proxymonster.controlplane.mcp.installMcp
import com.ridi.oss.proxymonster.controlplane.support.pushedColumn
import com.ridi.oss.proxymonster.analyzer.pb.catalogSnapshot
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
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
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
import kotlin.test.assertFalse
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
    fun `initialize instructions name the instance and list only datasources the caller may connect to`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        core.datasourceStore.register(
            "mcp-instr-orders", Engine.MYSQL, "db", 3306, "orders", emptyList(), "", null, false,
            description = "Orders and payments",
        )
        val role = core.policyStore.createRole(RoleInput("mcp-instr-connect"))
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                "mcp-instr-connect",
                """permit(principal in Role::"mcp-instr-connect", action == Action::"datasource.connect", resource == Datasource::"mcp-instr-orders");""",
            ),
            "admin@example.com",
        )
        val connector = "mcp-instr-connector@example.com"
        val stranger = "mcp-instr-stranger@example.com"
        grantRole(connector, role.name)
        suspend fun instructions(principal: String, language: String = "en"): String {
            val sdk = client.mcpStreamableHttp("/mcp") {
                header(HttpHeaders.Authorization, "Bearer ${token(principal, setOf("mcp:read"))}")
                header(HttpHeaders.AcceptLanguage, language)
            }
            assertEquals("proxy-monster (hr-pmon)", sdk.serverVersion?.title)
            return assertNotNull(sdk.serverInstructions)
        }

        val granted = instructions(connector)
        assertContains(granted, "\"hr-pmon\": HR and payroll data")
        assertContains(granted, "pmon-*")
        assertContains(granted, "call get_pmon_guide")
        assertContains(granted, "- mcp-instr-orders (mysql): Orders and payments")

        val denied = instructions(stranger)
        assertContains(denied, "\"hr-pmon\"")
        assertFalse("mcp-instr-orders" in denied, denied)

        assertEquals(instructions(connector), instructions(connector, "ko"), "instructions are English for every locale")
    }

    @Test
    fun `get_pmon_guide gives this instance's pmon setup and only the caller's connectable datasources`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        core.datasourceStore.register("mcp-guide-orders", Engine.MYSQL, "db", 3306, "orders", emptyList(), "", null, false)
        core.datasourceStore.register("mcp-guide-payroll", Engine.MYSQL, "db", 3306, "payroll", emptyList(), "", null, false)
        val role = core.policyStore.createRole(RoleInput("mcp-guide-connect"))
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                "mcp-guide-connect",
                """permit(principal in Role::"mcp-guide-connect", action == Action::"datasource.connect", resource == Datasource::"mcp-guide-orders");""",
            ),
            "admin@example.com",
        )
        val connector = "mcp-guide-connector@example.com"
        grantRole(connector, role.name)
        suspend fun guide(principal: String): String {
            val response = client.post("/mcp") {
                acceptMcp(token(principal, setOf("mcp:read")))
                setBody(toolCall(1, "get_pmon_guide").toString())
            }
            val result = TEST_JSON.parseToJsonElement(response.bodyAsText()).jsonObject.getValue("result").jsonObject
            val text = result.getValue("content").jsonArray.single().jsonObject.getValue("text").jsonPrimitive.content
            assertEquals(text, result.getValue("structuredContent").jsonObject.getValue("result").jsonPrimitive.content)
            return text
        }

        val granted = guide(connector)
        assertContains(granted, "brew trust --formula ridi-oss/tap/pmon")
        assertContains(granted, "brew install ridi-oss/tap/pmon")
        assertContains(granted, "pmon server set hr-pmon --url http://localhost")
        assertContains(granted, "pmon login hr-pmon\n")
        assertContains(granted, "claude mcp add --scope user pmon-hr-pmon -- pmon mcp hr-pmon")
        assertContains(granted, "codex mcp add pmon-hr-pmon -- pmon mcp hr-pmon")
        assertContains(granted, "\"args\": [\"mcp\", \"hr-pmon\"]")
        assertContains(granted, "pmon show hr-pmon mcp-guide-orders --cli")
        assertFalse("mcp-guide-payroll" in granted, granted)
        assertContains(granted, "pmon status")
        assertContains(granted, "pmon logout hr-pmon")
        assertContains(granted, "--scopes mcp:query,mcp:read,mcp:approvals:write")

        val stranger = guide("mcp-guide-stranger@example.com")
        assertFalse("pmon show" in stranger, stranger)
        assertContains(stranger, "pmon login hr-pmon")
    }

    @Test
    fun `tool catalog is complete and scope cannot grant a write`() = testApplication {
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
        assertEquals("Create an access-control role.", tools.single { it.name == "create_role" }.description)

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
            listOf("IDEMPOTENT_REPLAY"),
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
        // The config change itself is audited once, by the service, carrying the roles `authorize`
        // resolved — the HTTP actor has no resolved set to carry, so this is what pins the difference.
        assertEquals(
            listOf("admin.policies|ALLOW|mcp|system:admin"),
            strings(
                """SELECT action || '|' || outcome || '|' || channel || '|' ||
                          (SELECT string_agg(r, ',' ORDER BY r) FROM jsonb_array_elements_text(roles) r)
                   FROM audit_event WHERE kind='admin' AND resource=? ORDER BY id""",
                """Role::"$roleName"""",
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
            mapOf("datasource" to mapOf("invalid" to true), "catalog" to "mcp", "table" to "users", "column" to "ssn", "tags" to listOf("pii")),
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
                    "catalog" to "mcp",
                    "schema" to "public",
                    "table" to "users",
                    "column" to "ssn",
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
        assertEquals("ssn", tags.single().jsonObject.getValue("column").jsonPrimitive.content)
        assertEquals(8L, scalar("SELECT count(*) FROM audit_event WHERE principal=? AND kind='admin'", principal))
        assertEquals(0L, scalar("SELECT count(*) FROM audit_event WHERE principal=? AND statement LIKE '[MCP %'", principal))
    }

    @Test
    fun `a batch classification applies atomically and never half-applies`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-batch-tags@example.com"
        grantRole(principal, "system:admin")
        seedDatasource("mcp-batch-datasource", listOf("ssn", "email", "phone"))
        val accessToken = token(principal, setOf("mcp:read", "mcp:datasources:write", "mcp:policies:write"))
        val sdk = client.mcpStreamableHttp("/mcp") { header(HttpHeaders.Authorization, "Bearer $accessToken") }
        assertToolSuccess(sdk.callTool("create_mask_fn", mapOf("name" to "mcp-batch-mask", "kind" to "FIXED")))

        val applied = assertToolSuccess(
            sdk.callTool(
                "set_column_classifications",
                mapOf(
                    "datasource" to "mcp-batch-datasource",
                    "columns" to listOf(
                        mapOf("catalog" to "mcp", "table" to "users", "column" to "ssn", "tags" to listOf("pii"), "maskFnName" to "mcp-batch-mask"),
                        mapOf("catalog" to "mcp", "schema" to "public", "table" to "users", "column" to "email", "tags" to listOf("pii", "contact")),
                        mapOf("catalog" to "mcp", "table" to "users", "column" to "phone", "tags" to listOf("contact")),
                    ),
                ),
            ),
        ).getValue("result").jsonObject
        assertEquals(
            listOf("email", "phone", "ssn"),
            applied.getValue("columns").jsonArray.map { it.jsonObject.getValue("column").jsonPrimitive.content }.sorted(),
        )
        // The schema each entry omitted resolved from the datasource default, not from a literal null.
        assertTrue(applied.getValue("columns").jsonArray.all { it.jsonObject.getValue("schema").jsonPrimitive.content == "public" })
        assertEquals(3L, classifiedColumns("mcp-batch-datasource"))

        // A reserved tag anywhere in the batch rejects the WHOLE batch. The valid leading entry is the
        // one that would survive a per-entry loop, so its absence is what proves atomicity.
        val reserved = sdk.callTool(
            "set_column_classifications",
            mapOf(
                "datasource" to "mcp-batch-datasource",
                "columns" to listOf(
                    mapOf("catalog" to "mcp", "table" to "orders", "column" to "buyer", "tags" to listOf("pii")),
                    mapOf("catalog" to "mcp", "table" to "orders", "column" to "card", "tags" to listOf("system:reserved")),
                ),
            ),
        )
        assertEquals(true, reserved.isError)
        assertEquals("datasource.reserved_tag", reserved.structuredContent?.get("code")?.jsonPrimitive?.content)
        assertEquals(3L, classifiedColumns("mcp-batch-datasource"))

        // An unknown mask function is resolved before any write, for the same reason.
        val unknownMask = sdk.callTool(
            "set_column_classifications",
            mapOf(
                "datasource" to "mcp-batch-datasource",
                "columns" to listOf(
                    mapOf("catalog" to "mcp", "table" to "orders", "column" to "buyer", "tags" to listOf("pii")),
                    mapOf("catalog" to "mcp", "table" to "orders", "column" to "card", "tags" to listOf("pii"), "maskFnName" to "no-such-mask"),
                ),
            ),
        )
        assertEquals(true, unknownMask.isError)
        assertEquals("common.not_found", unknownMask.structuredContent?.get("code")?.jsonPrimitive?.content)
        assertEquals(3L, classifiedColumns("mcp-batch-datasource"))

        // Two entries for one column are refused rather than letting the later silently win — the
        // caller could not otherwise tell which tag set decides masking.
        val duplicate = sdk.callTool(
            "set_column_classifications",
            mapOf(
                "datasource" to "mcp-batch-datasource",
                "columns" to listOf(
                    mapOf("catalog" to "mcp", "table" to "users", "column" to "ssn", "tags" to listOf("pii")),
                    mapOf("catalog" to "mcp", "schema" to "public", "table" to "users", "column" to "ssn", "tags" to emptyList<String>()),
                ),
            ),
        )
        assertEquals(true, duplicate.isError)
        assertEquals("datasource.duplicate_column", duplicate.structuredContent?.get("code")?.jsonPrimitive?.content)

        // An unknown key inside an entry is rejected, matching the top-level argument check — a batch
        // entry must not be applied as though a field the server ignored had been understood.
        val unknownKey = sdk.callTool(
            "set_column_classifications",
            mapOf(
                "datasource" to "mcp-batch-datasource",
                "columns" to listOf(mapOf("catalog" to "mcp", "table" to "users", "column" to "ssn", "tags" to listOf("pii"), "maskFnId" to 1)),
            ),
        )
        assertEquals(true, unknownKey.isError)
        assertEquals("mcp.invalid_request", unknownKey.structuredContent?.get("code")?.jsonPrimitive?.content)

        val details = strings(
            """SELECT detail FROM audit_event
               WHERE principal=? AND statement='[MCP set_column_classifications]' ORDER BY id""",
            principal,
        )
        assertEquals(4, details.size)
        // Failure rows retain the submitted detail because no resolved write exists.
        assertContains(details.first(), "orders.buyer")
        assertContains(details.first(), "orders.card")
        val adminStatement = strings(
            """SELECT statement FROM audit_event WHERE principal=? AND kind='admin'
               AND resource='Datasource::"mcp-batch-datasource"' AND statement LIKE 'tag 3 columns%'""",
            principal,
        ).single()
        assertContains(adminStatement, "public.users.email")
        assertContains(adminStatement, "public.users.phone")
        assertContains(adminStatement, "public.users.ssn")
        assertEquals(
            listOf("datasource.reserved_tag", "common.not_found", "datasource.duplicate_column", "mcp.invalid_request"),
            strings(
                """SELECT outcome FROM audit_event
                   WHERE principal=? AND statement='[MCP set_column_classifications]' ORDER BY id""",
                principal,
            ),
        )
        assertEquals(
            listOf("mcp-batch-datasource"),
            strings(
                """SELECT DISTINCT datasource FROM audit_event
                   WHERE principal=? AND statement='[MCP set_column_classifications]'""",
                principal,
            ),
        )
    }

    @Test
    fun `a batch classification rolls back a write that already succeeded`() = testApplication {
        // The validation-failure cases above all reject before the first upsert, so they would still
        // pass an implementation that committed each column on its own connection. Failing the SECOND
        // write is what actually pins the transaction boundary: the first must not survive.
        application { installTestMcp() }
        val principal = "mcp-batch-rollback@example.com"
        grantRole(principal, "system:admin")
        seedDatasource("mcp-batch-rollback-datasource", listOf("ssn", "email"))
        val accessToken = token(principal, setOf("mcp:read", "mcp:datasources:write"))
        val sdk = client.mcpStreamableHttp("/mcp") { header(HttpHeaders.Authorization, "Bearer $accessToken") }
        execute(
            """CREATE OR REPLACE FUNCTION pm_test_fail_second_classification() RETURNS trigger AS ${'$'}body${'$'}
               BEGIN RAISE EXCEPTION 'forced classification failure'; END
               ${'$'}body${'$'} LANGUAGE plpgsql""",
        )
        execute(
            """CREATE TRIGGER pm_test_fail_second_classification BEFORE INSERT ON column_classification
               FOR EACH ROW WHEN (NEW.column_name = 'ssn')
               EXECUTE FUNCTION pm_test_fail_second_classification()""",
        )
        try {
            // Written in canonical order, so 'email' commits before 'ssn' trips the trigger.
            val failed = sdk.callTool(
                "set_column_classifications",
                mapOf(
                    "datasource" to "mcp-batch-rollback-datasource",
                    "columns" to listOf(
                        mapOf("catalog" to "mcp", "table" to "users", "column" to "email", "tags" to listOf("pii")),
                        mapOf("catalog" to "mcp", "table" to "users", "column" to "ssn", "tags" to listOf("pii")),
                    ),
                    "idempotencyKey" to "batch-rolled-back",
                ),
            )
            assertEquals(true, failed.isError)
            assertEquals(0L, classifiedColumns("mcp-batch-rollback-datasource"))
            // The idempotency row must roll back too, or a retry would replay a result never applied.
            assertEquals(0L, scalar("SELECT count(*) FROM mcp_mutation_idempotency WHERE idempotency_key=?", "batch-rolled-back"))
        } finally {
            execute("DROP TRIGGER pm_test_fail_second_classification ON column_classification")
            execute("DROP FUNCTION pm_test_fail_second_classification()")
        }
    }

    @Test
    fun `a batch classification never writes an unresolvable schema`() = testApplication {
        // A blank schema is absent, not a name: taken literally it writes a row keyed on "" that no
        // enforcement lookup can match, so the caller sees success while the real column stays
        // untagged and reads cleartext.
        application { installTestMcp() }
        val principal = "mcp-batch-blank-schema@example.com"
        grantRole(principal, "system:admin")
        seedDatasource("mcp-batch-blank-datasource", listOf("ssn"))
        val sdk = client.mcpStreamableHttp("/mcp") {
            header(HttpHeaders.Authorization, "Bearer ${token(principal, setOf("mcp:read", "mcp:datasources:write"))}")
        }
        val applied = assertToolSuccess(
            sdk.callTool(
                "set_column_classifications",
                mapOf(
                    "datasource" to "mcp-batch-blank-datasource",
                    "columns" to listOf(mapOf("catalog" to "mcp", "schema" to "", "table" to "users", "column" to "ssn", "tags" to listOf("pii"))),
                ),
            ),
        ).getValue("result").jsonObject
        assertEquals(
            "public",
            applied.getValue("columns").jsonArray.single().jsonObject.getValue("schema").jsonPrimitive.content,
        )
        assertEquals(
            0L,
            scalar("SELECT count(*) FROM column_classification WHERE schema_name=? AND column_name='ssn'", ""),
        )
        // A blank schema and the resolved default are the SAME column, so submitting both is a duplicate.
        val duplicate = sdk.callTool(
            "set_column_classifications",
            mapOf(
                "datasource" to "mcp-batch-blank-datasource",
                "columns" to listOf(
                    mapOf("catalog" to "mcp", "schema" to "", "table" to "users", "column" to "ssn", "tags" to listOf("pii")),
                    mapOf("catalog" to "mcp", "table" to "users", "column" to "ssn", "tags" to emptyList<String>()),
                ),
            ),
        )
        assertEquals(true, duplicate.isError)
        assertEquals("datasource.duplicate_column", duplicate.structuredContent?.get("code")?.jsonPrimitive?.content)
    }

    @Test
    fun `a batch classification refuses an oversized batch before doing its work`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-batch-cap@example.com"
        grantRole(principal, "system:admin")
        seedDatasource("mcp-batch-cap-datasource", listOf("ssn"))
        val sdk = client.mcpStreamableHttp("/mcp") {
            header(HttpHeaders.Authorization, "Bearer ${token(principal, setOf("mcp:read", "mcp:datasources:write"))}")
        }
        val overCap = sdk.callTool(
            "set_column_classifications",
            mapOf(
                "datasource" to "mcp-batch-cap-datasource",
                "columns" to (1..DatasourceManagementService.MAX_CLASSIFICATION_BATCH + 1).map {
                    mapOf("catalog" to "mcp", "table" to "users", "column" to "c$it", "tags" to listOf("pii"))
                },
            ),
        )
        assertEquals(true, overCap.isError)
        assertEquals("datasource.batch_too_large", overCap.structuredContent?.get("code")?.jsonPrimitive?.content)
        assertEquals(0L, classifiedColumns("mcp-batch-cap-datasource"))
        // The refusal is audited, and its detail does not inline the entries it never applied.
        val detail = strings(
            """SELECT detail FROM audit_event
               WHERE principal=? AND statement='[MCP set_column_classifications]' ORDER BY id""",
            principal,
        ).single()
        assertContains(detail, "columns=${DatasourceManagementService.MAX_CLASSIFICATION_BATCH + 1}")
        assertTrue("users.c1" !in detail, detail)

        val empty = sdk.callTool(
            "set_column_classifications",
            mapOf("datasource" to "mcp-batch-cap-datasource", "columns" to emptyList<Map<String, String>>()),
        )
        assertEquals(true, empty.isError)
        assertEquals("common.field_required", empty.structuredContent?.get("code")?.jsonPrimitive?.content)
    }

    @Test
    fun `a batch classification is denied without the datasource Cedar action`() = testApplication {
        // Every other batch test runs as system:admin, which permits everything — so none of them would
        // notice the tool being registered under the wrong Cedar action. A policy-only admin must be
        // denied, and the singular and batch tools must agree.
        application { installTestMcp() }
        val principal = "mcp-batch-policy-only@example.com"
        val role = core.policyStore.createRole(RoleInput("mcp-batch-policy-only", "Policies but not datasources"))
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                "mcp-batch-policy-only",
                """permit(principal in Role::"mcp-batch-policy-only", action == Action::"admin.policies", resource);""",
            ),
            principal,
        )
        grantRole(principal, role.name)
        seedDatasource("mcp-batch-cedar-datasource", listOf("ssn"))
        val sdk = client.mcpStreamableHttp("/mcp") {
            header(
                HttpHeaders.Authorization,
                "Bearer ${token(principal, setOf("mcp:read", "mcp:datasources:write", "mcp:policies:write"))}",
            )
        }
        for (tool in listOf("set_column_classification", "set_column_classifications")) {
            val arguments = if (tool == "set_column_classification") {
                mapOf(
                    "datasource" to "mcp-batch-cedar-datasource",
                    "catalog" to "mcp", "table" to "users", "column" to "ssn", "tags" to listOf("pii"),
                )
            } else {
                mapOf(
                    "datasource" to "mcp-batch-cedar-datasource",
                    "columns" to listOf(mapOf("catalog" to "mcp", "table" to "users", "column" to "ssn", "tags" to listOf("pii"))),
                )
            }
            assertFailsWith<McpException>(tool) { sdk.callTool(tool, arguments) }
                .also { assertEquals(HttpStatusCode.Forbidden.value, (it.cause as? StreamableHttpError)?.code, tool) }
        }
        assertEquals(0L, classifiedColumns("mcp-batch-cedar-datasource"))
        assertEquals(
            listOf("common.forbidden", "common.forbidden"),
            strings(
                """SELECT outcome FROM audit_event WHERE principal=?
                   AND statement LIKE '[MCP set_column_classification%' ORDER BY id""",
                principal,
            ),
        )
    }

    @Test
    fun `a batch classification obeys the scope ceiling and replays idempotently`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-batch-scope@example.com"
        grantRole(principal, "system:admin")
        seedDatasource("mcp-batch-scope-datasource", listOf("ssn"))

        val readOnly = createClient { expectSuccess = false }.post("/mcp") {
            acceptMcp(token(principal, setOf("mcp:read")))
            setBody(
                toolCall(
                    1,
                    "set_column_classifications",
                    buildJsonObject {
                        put("datasource", "mcp-batch-scope-datasource")
                        put("columns", buildJsonArray {
                            add(
                                buildJsonObject {
                                    put("catalog", "mcp")
                                    put("table", "users")
                                    put("column", "ssn")
                                    put("tags", buildJsonArray { add(JsonPrimitive("pii")) })
                                },
                            )
                        })
                    },
                ).toString(),
            )
        }
        assertEquals(HttpStatusCode.Forbidden, readOnly.status)
        assertEquals("mcp.insufficient_scope", rpcStructuredContent(readOnly.bodyAsText()).getValue("code").jsonPrimitive.content)
        assertEquals(0L, classifiedColumns("mcp-batch-scope-datasource"))

        val sdk = client.mcpStreamableHttp("/mcp") {
            header(HttpHeaders.Authorization, "Bearer ${token(principal, setOf("mcp:read", "mcp:datasources:write"))}")
        }
        val arguments = mapOf(
            "datasource" to "mcp-batch-scope-datasource",
            "columns" to listOf(mapOf("catalog" to "mcp", "table" to "users", "column" to "ssn", "tags" to listOf("pii"))),
            "idempotencyKey" to "batch-once",
        )
        val first = sdk.callTool("set_column_classifications", arguments)
        val replay = sdk.callTool("set_column_classifications", arguments)
        assertEquals(first.structuredContent, replay.structuredContent)
        assertEquals(1L, classifiedColumns("mcp-batch-scope-datasource"))

        // The request hash must cover the NESTED entries, not just the top-level datasource and length.
        // If it did not, reusing the key with different tags would replay the old response while
        // silently never applying the tags the caller asked for.
        val changedTags = sdk.callTool(
            "set_column_classifications",
            arguments + ("columns" to listOf(mapOf("catalog" to "mcp", "table" to "users", "column" to "ssn", "tags" to listOf("contact")))),
        )
        assertEquals(true, changedTags.isError)
        assertEquals("mcp.idempotency_conflict", changedTags.structuredContent?.get("code")?.jsonPrimitive?.content)
        assertEquals(
            listOf("pii"),
            strings(
                """SELECT jsonb_array_elements_text(c.tags) FROM column_classification c
                   JOIN datasource d ON d.id = c.datasource_id WHERE d.name=?""",
                "mcp-batch-scope-datasource",
            ),
        )
        // The scope refusal above is audited too — a denied batch leaves a trail, it does not vanish.
        assertEquals(
            listOf("mcp.insufficient_scope", "IDEMPOTENT_REPLAY", "IDEMPOTENCY_CONFLICT"),
            strings(
                """SELECT outcome FROM audit_event
                   WHERE principal=? AND statement='[MCP set_column_classifications]' ORDER BY id""",
                principal,
            ),
        )
        // One admin row across all four calls: only the first applied anything, and the replay and the
        // conflict must not each look like another config change.
        assertEquals(
            1L,
            scalar(
                "SELECT count(*) FROM audit_event WHERE principal=? AND kind='admin' AND resource=?",
                principal, """Datasource::"mcp-batch-scope-datasource"""",
            ),
        )
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
               FOR EACH ROW WHEN (NEW.kind = 'admin' AND NEW.resource = 'Group::"must-roll-back-with-audit"')
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

    @Test
    fun `policy tools return the policy and record each change`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-admin-policies@example.com"
        grantRole(principal, "system:admin")
        val sdk = adminSdk(principal)
        val source = """permit(principal in Role::"mcp-admin-policy-role", action == Action::"admin.identity", resource);"""
        val updatedSource = """permit(principal in Role::"mcp-admin-policy-role", action == Action::"admin.policies", resource);"""

        assertToolSuccess(sdk.callTool("create_policy", mapOf("name" to "mcp-admin-policy", "cedarSrc" to source, "enabled" to false)))
        val policy = callResult(sdk, "get_policy", mapOf("name" to "mcp-admin-policy")).jsonObject
        assertEquals("mcp-admin-policy", policy.getValue("name").jsonPrimitive.content)
        assertEquals(source, policy.getValue("cedarSrc").jsonPrimitive.content)
        val policyResource = """Policy::"${policy.getValue("id").jsonPrimitive.content}""""

        val listed = callResult(sdk, "list_policies", emptyMap()).jsonArray
        assertTrue(listed.any { it.jsonObject.getValue("name").jsonPrimitive.content == "mcp-admin-policy" })

        val valid = callResult(sdk, "validate_policy", mapOf("cedarSrc" to source)).jsonObject
        assertEquals(true, valid.getValue("valid").jsonPrimitive.content.toBoolean())
        assertTrue(valid.getValue("errors").jsonArray.isEmpty())
        val invalid = callResult(
            sdk, "validate_policy",
            mapOf("cedarSrc" to """permit(principal, action == Action::"no.such.action", resource);"""),
        ).jsonObject
        assertEquals(false, invalid.getValue("valid").jsonPrimitive.content.toBoolean())
        assertTrue(invalid.getValue("errors").jsonArray.isNotEmpty())

        val schema = callResult(sdk, "get_policy_schema", emptyMap()).jsonObject
        assertContains(schema.getValue("schema").jsonPrimitive.content, "admin.policies")

        val updated = callResult(
            sdk, "update_policy",
            mapOf("name" to "mcp-admin-policy", "newName" to "mcp-admin-policy-renamed", "cedarSrc" to updatedSource),
        ).jsonObject
        assertEquals("mcp-admin-policy-renamed", updated.getValue("name").jsonPrimitive.content)
        assertEquals(
            listOf(updatedSource),
            strings("SELECT cedar_src FROM policy WHERE name=? AND deleted_at IS NULL", "mcp-admin-policy-renamed"),
        )
        assertMcpAudit(principal, policyResource, "update policy 'mcp-admin-policy' -> 'mcp-admin-policy-renamed'")

        val enabled = callResult(sdk, "enable_policy", mapOf("name" to "mcp-admin-policy-renamed")).jsonObject
        assertEquals(true, enabled.getValue("enabled").jsonPrimitive.content.toBoolean())
        assertEquals(listOf("t"), strings("SELECT enabled FROM policy WHERE name=? AND deleted_at IS NULL", "mcp-admin-policy-renamed"))
        assertMcpAudit(principal, policyResource, "enable policy 'mcp-admin-policy-renamed'")

        val disabled = callResult(sdk, "disable_policy", mapOf("name" to "mcp-admin-policy-renamed")).jsonObject
        assertEquals(false, disabled.getValue("enabled").jsonPrimitive.content.toBoolean())
        assertEquals(listOf("f"), strings("SELECT enabled FROM policy WHERE name=? AND deleted_at IS NULL", "mcp-admin-policy-renamed"))
        assertMcpAudit(principal, policyResource, "disable policy 'mcp-admin-policy-renamed'")

        assertDeleted(callResult(sdk, "delete_policy", mapOf("name" to "mcp-admin-policy-renamed")))
        assertEquals(1L, scalar("SELECT count(*) FROM policy WHERE name=? AND deleted_at IS NOT NULL", "mcp-admin-policy-renamed"))
        assertMcpAudit(principal, policyResource, "delete policy 'mcp-admin-policy-renamed'")
    }

    @Test
    fun `role and assignment tools return the rows and record each change`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-admin-roles@example.com"
        grantRole(principal, "system:admin")
        val sdk = adminSdk(principal)
        val member = "mcp-admin-role-member@example.com"
        assertToolSuccess(sdk.callTool("create_user", mapOf("principal" to member)))
        assertToolSuccess(sdk.callTool("create_role", mapOf("name" to "mcp-admin-role", "description" to "before")))
        assertToolSuccess(sdk.callTool("assign_role", mapOf("principal" to member, "roleName" to "mcp-admin-role")))

        val assignments = callResult(sdk, "list_role_assignments", mapOf("principal" to member)).jsonArray
        assertEquals(listOf("mcp-admin-role"), assignments.map { it.jsonObject.getValue("roleName").jsonPrimitive.content })
        val byRole = callResult(sdk, "list_role_assignments", mapOf("roleName" to "mcp-admin-role")).jsonArray
        assertEquals(listOf(member), byRole.map { it.jsonObject.getValue("principal").jsonPrimitive.content })

        assertDeleted(callResult(sdk, "unassign_role", mapOf("principal" to member, "roleName" to "mcp-admin-role")))
        assertEquals(
            0L,
            scalar(
                "SELECT count(*) FROM principal_role WHERE principal=? AND role_id=(SELECT id FROM app_role WHERE name=? AND deleted_at IS NULL)",
                member, "mcp-admin-role",
            ),
        )
        assertMcpAudit(principal, """Role::"mcp-admin-role"""", "unassign role 'mcp-admin-role' from '$member'")

        val updated = callResult(
            sdk, "update_role",
            mapOf("name" to "mcp-admin-role", "newName" to "mcp-admin-role-renamed", "description" to "after"),
        ).jsonObject
        assertEquals("mcp-admin-role-renamed", updated.getValue("name").jsonPrimitive.content)
        assertEquals("after", updated.getValue("description").jsonPrimitive.content)
        assertEquals(listOf("after"), strings("SELECT description FROM app_role WHERE name=? AND deleted_at IS NULL", "mcp-admin-role-renamed"))
        assertMcpAudit(principal, """Role::"mcp-admin-role-renamed"""", "update role 'mcp-admin-role' -> 'mcp-admin-role-renamed'")

        assertDeleted(callResult(sdk, "delete_role", mapOf("name" to "mcp-admin-role-renamed")))
        assertEquals(1L, scalar("SELECT count(*) FROM app_role WHERE name=? AND deleted_at IS NOT NULL", "mcp-admin-role-renamed"))
        assertMcpAudit(principal, """Role::"mcp-admin-role-renamed"""", "delete role 'mcp-admin-role-renamed'")
    }

    @Test
    fun `user tools return the user and record each change`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-admin-users@example.com"
        grantRole(principal, "system:admin")
        val sdk = adminSdk(principal)
        val user = "mcp-admin-managed-user@example.com"
        assertToolSuccess(sdk.callTool("create_user", mapOf("principal" to user)))

        val updated = callResult(
            sdk, "update_user",
            mapOf("principal" to user, "displayName" to "Managed User", "email" to "managed@example.com"),
        ).jsonObject
        assertEquals("Managed User", updated.getValue("displayName").jsonPrimitive.content)
        assertEquals("managed@example.com", updated.getValue("email").jsonPrimitive.content)
        assertEquals(listOf("Managed User|managed@example.com"), strings("SELECT display_name || '|' || email FROM app_user WHERE principal=?", user))
        assertMcpAudit(principal, """User::"$user"""", "update user '$user'")

        assertDeleted(callResult(sdk, "deprovision_user", mapOf("principal" to user)))
        assertEquals(listOf("f"), strings("SELECT active FROM app_user WHERE principal=?", user))
        assertMcpAudit(principal, """User::"$user"""", "deprovision user '$user'")
    }

    @Test
    fun `group tools return the group and record each change`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-admin-groups@example.com"
        grantRole(principal, "system:admin")
        val sdk = adminSdk(principal)
        val member = "mcp-admin-group-member@example.com"
        assertToolSuccess(sdk.callTool("create_user", mapOf("principal" to member)))
        assertToolSuccess(sdk.callTool("create_role", mapOf("name" to "mcp-admin-group-role-a")))
        assertToolSuccess(sdk.callTool("create_role", mapOf("name" to "mcp-admin-group-role-b")))
        assertToolSuccess(sdk.callTool("create_group", mapOf("name" to "mcp-admin-group", "description" to "before")))
        assertToolSuccess(sdk.callTool("add_group_member", mapOf("groupName" to "mcp-admin-group", "principal" to member)))

        val first = callResult(sdk, "set_group_roles", mapOf("groupName" to "mcp-admin-group", "roleNames" to listOf("mcp-admin-group-role-a"))).jsonObject
        assertEquals(listOf("mcp-admin-group-role-a"), first.getValue("roleNames").jsonArray.map { it.jsonPrimitive.content })
        val replaced = callResult(sdk, "set_group_roles", mapOf("groupName" to "mcp-admin-group", "roleNames" to listOf("mcp-admin-group-role-b"))).jsonObject
        assertEquals(listOf("mcp-admin-group-role-b"), replaced.getValue("roleNames").jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("mcp-admin-group-role-b"), groupRoles("mcp-admin-group"))
        assertMcpAudit(principal, """Group::"mcp-admin-group"""", "set group 'mcp-admin-group' roles [mcp-admin-group-role-b]")

        val listed = callResult(sdk, "list_groups", emptyMap()).jsonArray
            .map { it.jsonObject }.single { it.getValue("name").jsonPrimitive.content == "mcp-admin-group" }
        assertEquals(1, listed.getValue("memberCount").jsonPrimitive.content.toInt())
        assertEquals(listOf("mcp-admin-group-role-b"), listed.getValue("roles").jsonArray.map { it.jsonObject.getValue("name").jsonPrimitive.content })

        assertDeleted(callResult(sdk, "remove_group_member", mapOf("groupName" to "mcp-admin-group", "principal" to member)))
        assertEquals(
            0L,
            scalar(
                """SELECT count(*) FROM group_member m JOIN app_group g ON g.id = m.group_id
                   WHERE g.name=? AND g.deleted_at IS NULL""",
                "mcp-admin-group",
            ),
        )
        assertMcpAudit(principal, """Group::"mcp-admin-group"""", "remove '$member' from group 'mcp-admin-group'")

        val updated = callResult(
            sdk, "update_group",
            mapOf("name" to "mcp-admin-group", "newName" to "mcp-admin-group-renamed", "description" to "after"),
        ).jsonObject
        assertEquals("mcp-admin-group-renamed", updated.getValue("name").jsonPrimitive.content)
        assertEquals(listOf("after"), strings("SELECT description FROM app_group WHERE name=? AND deleted_at IS NULL", "mcp-admin-group-renamed"))
        assertMcpAudit(principal, """Group::"mcp-admin-group-renamed"""", "update group 'mcp-admin-group' -> 'mcp-admin-group-renamed'")

        assertDeleted(callResult(sdk, "delete_group", mapOf("name" to "mcp-admin-group-renamed")))
        assertEquals(1L, scalar("SELECT count(*) FROM app_group WHERE name=? AND deleted_at IS NOT NULL", "mcp-admin-group-renamed"))
        assertMcpAudit(principal, """Group::"mcp-admin-group-renamed"""", "delete group 'mcp-admin-group-renamed'")
    }

    @Test
    fun `mask function tools return the function and record each change`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-admin-masks@example.com"
        grantRole(principal, "system:admin")
        val sdk = adminSdk(principal)
        assertToolSuccess(sdk.callTool("create_mask_fn", mapOf("name" to "mcp-admin-mask", "kind" to "FIXED")))

        val listed = callResult(sdk, "list_mask_fns", emptyMap()).jsonArray
            .map { it.jsonObject }.single { it.getValue("name").jsonPrimitive.content == "mcp-admin-mask" }
        assertEquals("FIXED", listed.getValue("kind").jsonPrimitive.content)

        val updated = callResult(
            sdk, "update_mask_fn",
            mapOf("name" to "mcp-admin-mask", "newName" to "mcp-admin-mask-renamed", "kind" to "LAST_N"),
        ).jsonObject
        assertEquals("mcp-admin-mask-renamed", updated.getValue("name").jsonPrimitive.content)
        assertEquals("LAST_N", updated.getValue("kind").jsonPrimitive.content)
        assertEquals(listOf("LAST_N"), strings("SELECT kind FROM mask_fn WHERE name=? AND deleted_at IS NULL", "mcp-admin-mask-renamed"))
        assertMcpAudit(principal, """MaskFn::"mcp-admin-mask-renamed"""", "update mask function 'mcp-admin-mask' -> 'mcp-admin-mask-renamed'")

        assertDeleted(callResult(sdk, "delete_mask_fn", mapOf("name" to "mcp-admin-mask-renamed")))
        assertEquals(1L, scalar("SELECT count(*) FROM mask_fn WHERE name=? AND deleted_at IS NOT NULL", "mcp-admin-mask-renamed"))
        assertMcpAudit(principal, """MaskFn::"mcp-admin-mask-renamed"""", "delete mask function 'mcp-admin-mask-renamed'")
    }

    @Test
    fun `datasource read tools return the seeded datasource catalog and live table detail`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-admin-datasource-reads@example.com"
        grantRole(principal, "system:admin")
        seedDatasource("mcp-admin-read-datasource", listOf("ssn", "email"))
        val sdk = adminSdk(principal)

        val listed = callResult(sdk, "list_datasources", emptyMap()).jsonArray
            .map { it.jsonObject }.single { it.getValue("name").jsonPrimitive.content == "mcp-admin-read-datasource" }
        assertEquals("mcp", listed.getValue("dbName").jsonPrimitive.content)

        val catalog = callResult(sdk, "browse_catalog", mapOf("datasource" to "mcp-admin-read-datasource")).jsonArray.map { it.jsonObject }
        assertEquals(listOf("email", "ssn"), catalog.map { it.getValue("column").jsonPrimitive.content }.sorted())
        assertTrue(catalog.all { it.getValue("table").jsonPrimitive.content == "users" && it.getValue("schema").jsonPrimitive.content == "public" })

        answerTableDetail("mcp-admin-read-datasource", tableDetail("mcp", "public", "users", listOf("ssn", "email"))).use {
            val detail = callResult(
                sdk, "get_table_detail",
                mapOf("datasource" to "mcp-admin-read-datasource", "catalog" to "mcp", "schema" to "public", "table" to "users"),
            ).jsonObject
            assertEquals("users", detail.getValue("table").jsonPrimitive.content)
            assertEquals(listOf("ssn", "email"), detail.getValue("columns").jsonArray.map { it.jsonObject.getValue("name").jsonPrimitive.content })
        }
    }

    @Test
    fun `clear_column_classification removes the row and records the change`() = testApplication {
        application { installTestMcp() }
        val principal = "mcp-admin-classification@example.com"
        grantRole(principal, "system:admin")
        seedDatasource("mcp-admin-clear-datasource", listOf("ssn"))
        val sdk = adminSdk(principal)
        assertToolSuccess(
            sdk.callTool(
                "set_column_classification",
                mapOf("datasource" to "mcp-admin-clear-datasource", "catalog" to "mcp", "table" to "users", "column" to "ssn", "tags" to listOf("pii")),
            ),
        )
        assertEquals(1L, classifiedColumns("mcp-admin-clear-datasource"))

        assertDeleted(
            callResult(
                sdk, "clear_column_classification",
                mapOf("datasource" to "mcp-admin-clear-datasource", "catalog" to "mcp", "table" to "users", "column" to "ssn"),
            ),
        )
        assertEquals(0L, classifiedColumns("mcp-admin-clear-datasource"))
        assertMcpAudit(
            principal,
            """Datasource::"mcp-admin-clear-datasource" col public.users.ssn""",
            "clear tags on mcp-admin-clear-datasource.public.users.ssn",
        )
    }

    private suspend fun io.ktor.server.testing.ApplicationTestBuilder.adminSdk(principal: String): io.modelcontextprotocol.kotlin.sdk.client.Client {
        val accessToken = token(principal, setOf("mcp:read", "mcp:datasources:write", "mcp:policies:write", "mcp:identity:write"))
        return client.mcpStreamableHttp("/mcp") { header(HttpHeaders.Authorization, "Bearer $accessToken") }
    }

    private suspend fun callResult(
        sdk: io.modelcontextprotocol.kotlin.sdk.client.Client,
        tool: String,
        arguments: Map<String, Any?>,
    ): kotlinx.serialization.json.JsonElement = assertToolSuccess(sdk.callTool(tool, arguments)).getValue("result")

    private fun assertDeleted(result: kotlinx.serialization.json.JsonElement) =
        assertEquals(true, result.jsonObject.getValue("deleted").jsonPrimitive.content.toBoolean())

    private fun assertMcpAudit(principal: String, resource: String, statement: String) = assertEquals(
        listOf("mcp"),
        strings(
            "SELECT channel FROM audit_event WHERE kind='admin' AND principal=? AND resource=? AND statement=?",
            principal, resource, statement,
        ),
        "$resource: $statement",
    )

    private fun groupRoles(group: String): List<String> = strings(
        """SELECT r.name FROM group_role gr
           JOIN app_group g ON g.id = gr.group_id AND g.deleted_at IS NULL
           JOIN app_role r ON r.id = gr.role_id WHERE g.name=? ORDER BY r.name""",
        group,
    )

    private fun tableDetail(catalog: String, schema: String, table: String, columns: List<String>) =
        com.ridi.oss.proxymonster.probe.TableDetail(
            catalog = catalog,
            schema = schema,
            table = table,
            columns = columns.mapIndexed { index, name ->
                com.ridi.oss.proxymonster.probe.TableDetailColumn(
                    name, "text", index + 1, true, null, null, null, null, false, false, null, null, null, null,
                )
            },
            indexes = emptyList(),
            foreignKeys = emptyList(),
            referencedBy = emptyList(),
            metadata = com.ridi.oss.proxymonster.probe.TableMetadata("PostgreSQL", 0, null, null, null, null),
        )

    /** Stands in for an attached proxy that answers every OpenTableDetailChannel for [datasource] with [detail]. */
    private fun answerTableDetail(datasource: String, detail: com.ridi.oss.proxymonster.probe.TableDetail): AutoCloseable {
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.Default)
        val events = kotlinx.coroutines.channels.Channel<com.ridi.oss.proxymonster.grpc.ControlEvent>(kotlinx.coroutines.channels.Channel.UNLIMITED)
        core.proxyEventsHub.register(datasource, events)
        scope.launch {
            for (event in events) {
                if (!event.hasOpenTableDetailChannel()) continue
                val outbound = kotlinx.coroutines.channels.Channel<com.ridi.oss.proxymonster.grpc.ControlTableDetailMsg>(
                    kotlinx.coroutines.channels.Channel.BUFFERED,
                )
                val attached = core.tableDetailChannels.attach(event.openTableDetailChannel.sessionId, outbound) ?: continue
                attached.inbound.send(
                    com.ridi.oss.proxymonster.grpc.proxyTableDetailMsg {
                        result = com.ridi.oss.proxymonster.grpc.tableDetailResult { json = TEST_JSON.encodeToString(detail) }
                    },
                )
                outbound.receive()
                attached.inbound.close()
                outbound.close()
            }
        }
        return AutoCloseable {
            core.proxyEventsHub.deregister(datasource, events)
            events.close()
            scope.cancel()
        }
    }

    private fun io.ktor.server.application.Application.installTestMcp(
        mcpResource: String = RESOURCE,
        trustedProxies: Set<String> = emptySet(),
    ) {
        install(ContentNegotiation) { json(TEST_JSON) }
        val recorder = ManagementAuditRecorder(core.auditStore)
        val datasourceService = DatasourceManagementService(core.datasourceStore, core.proxyEventsHub, TableDetailService(core), recorder)
        val policyService = PolicyManagementService(core.cedarPolicyStore, core.policyStore, recorder)
        val identityService = IdentityManagementService(
            dataSource, core.userGroupStore, core.policyStore, core.tokenStore, core.accessStore,
            PrincipalSessionStore(dataSource, null), recorder,
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

    private fun scalar(sql: String, vararg values: String): Long = dataSource.connection.use { connection ->
        connection.prepareStatement(sql).use { statement ->
            values.forEachIndexed { index, value -> statement.setString(index + 1, value) }
            statement.executeQuery().use { result -> result.next(); result.getLong(1) }
        }
    }

    private fun strings(sql: String, vararg values: String): List<String> = dataSource.connection.use { connection ->
        connection.prepareStatement(sql).use { statement ->
            values.forEachIndexed { index, value -> statement.setString(index + 1, value) }
            statement.executeQuery().use { result ->
                buildList { while (result.next()) add(result.getString(1)) }
            }
        }
    }

    private fun execute(sql: String) {
        dataSource.connection.use { connection -> connection.createStatement().use { it.execute(sql) } }
    }

    private fun seedDatasource(name: String, columns: List<String> = listOf("ssn")) {
        dataSource.connection.use { connection ->
            val id = connection.prepareStatement(
                """INSERT INTO datasource(name, engine, host, port, db_name, default_schemas)
                   VALUES (?, 'postgres', '127.0.0.1', 5432, 'mcp', '["public"]'::jsonb) RETURNING id""",
            ).use { statement ->
                statement.setString(1, name)
                statement.executeQuery().use { result -> result.next(); result.getLong(1) }
            }
            core.datasourceStore.storePushedCatalog(
                id = id,
                currentCatalog = "mcp",
                defaultSchemas = listOf("public"),
                mysqlLowerCaseTableNames = null,
                engineVersion = "PostgreSQL 16.4",
                catalog = catalogSnapshot {
                    this.columns += columns.mapIndexed { index, column ->
                        pushedColumn("public", "users", column, "text", index + 1, true, catalog = "mcp")
                    }
                },
            )
        }
    }

    private fun classifiedColumns(datasource: String): Long = scalar(
        """SELECT count(*) FROM column_classification c
           JOIN datasource d ON d.id = c.datasource_id WHERE d.name = ?""",
        datasource,
    )

    private fun assertToolSuccess(result: io.modelcontextprotocol.kotlin.sdk.types.CallToolResult): JsonObject {
        assertTrue(result.isError != true, result.structuredContent.toString())
        return assertNotNull(result.structuredContent)
    }

    private fun config(mcpResource: String = RESOURCE, trustedProxies: Set<String> = emptySet()) = Config(
        instanceName = "hr-pmon",
        instanceDescription = "HR and payroll data",
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
