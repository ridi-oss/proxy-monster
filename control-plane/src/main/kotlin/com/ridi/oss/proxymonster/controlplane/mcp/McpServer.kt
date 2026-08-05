package com.ridi.oss.proxymonster.controlplane.mcp

import com.ridi.oss.proxymonster.auth.McpAccessIdentity
import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.controlplane.ApiError
import com.ridi.oss.proxymonster.controlplane.AuditStore
import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.ClassificationInput
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.Decision
import com.ridi.oss.proxymonster.controlplane.AuditEvent
import com.ridi.oss.proxymonster.controlplane.AppGroupInput
import com.ridi.oss.proxymonster.controlplane.AppUserInput
import com.ridi.oss.proxymonster.controlplane.MaskFnInput
import com.ridi.oss.proxymonster.controlplane.httpRequesterIp
import com.ridi.oss.proxymonster.controlplane.resolveForwardedAuthority
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.AuditSource
import com.ridi.oss.proxymonster.controlplane.management.CapabilityClassification
import com.ridi.oss.proxymonster.controlplane.management.CedarValidationManagementException
import com.ridi.oss.proxymonster.controlplane.management.ColumnClassificationBatch
import com.ridi.oss.proxymonster.controlplane.management.DatasourceManagementService
import com.ridi.oss.proxymonster.controlplane.management.IdentityManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.management.McpCapability
import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import com.ridi.oss.proxymonster.controlplane.management.PolicyManagementService
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.request.host
import io.ktor.server.request.path
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.util.AttributeKey
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcpStatelessStreamableHttp
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolAnnotations
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.net.URI
import java.sql.Connection
import java.sql.Types
import java.util.Locale
import java.util.ResourceBundle
import javax.sql.DataSource

private val MCP_CONTEXT = AttributeKey<McpRequestContext>("mcp-request-context")
private val mcpJson = Json { encodeDefaults = true; explicitNulls = false }
private val POLICY_MUTATION_TOOLS = setOf(
    "create_policy", "update_policy", "enable_policy", "disable_policy", "delete_policy",
)
private val CLASSIFICATION_TOOLS = setOf(
    "set_column_classification", "set_column_classifications", "clear_column_classification",
)
private val CLASSIFICATION_ENTRY_KEYS = setOf("schema", "table", "column", "tags", "maskFnName")

data class McpRequestContext(
    val principal: String,
    val clientId: String,
    val scopes: Set<String>,
    val requesterIp: String?,
)

fun Application.installMcp(
    config: Config,
    core: ControlPlaneCore,
    datasourceService: DatasourceManagementService,
    policyService: PolicyManagementService,
    identityService: IdentityManagementService,
) {
    McpCapabilityRegistry.verify()
    val metadataUri = protectedResourceMetadataUri(config.mcpResource)
    val resourceUri = URI(config.mcpResource)
    val resourceOrigin = URI(resourceUri.scheme, null, resourceUri.host, resourceUri.port, null, null, null)
    // Java exposes an IPv6 URI host bracketed (`[::1]`) while a request authority resolves to the bare
    // address, so both sides are unbracketed before they are compared.
    val resourceHost = resourceUri.host.removeSurrounding("[", "]")

    intercept(ApplicationCallPipeline.Plugins) {
        if (call.request.path() != "/mcp") return@intercept
        // The client-addressed host, not the socket's. Ktor normalizes HTTP/1.1 Host and HTTP/2
        // :authority through host(), so reading the literal Host header would reject every HTTP/2
        // request; behind a reverse proxy that authority is the PROXY's unless the edge preserves the
        // client Host, so a trusted edge's X-Forwarded-Host supersedes it (resolveForwardedAuthority —
        // honored only from a peer in PM_TRUSTED_PROXIES, so a direct caller still cannot assert its
        // way past this check).
        val host = resolveForwardedAuthority(
            directHost = call.request.host(),
            peerAddress = call.request.local.remoteAddress,
            forwardedHost = call.request.headers["X-Forwarded-Host"],
            trustedProxies = config.trustedProxies,
        )
        if (!host.removeSurrounding("[", "]").equals(resourceHost, ignoreCase = true)) {
            call.respond(HttpStatusCode.Forbidden, ApiError("mcp.invalid_host"))
            finish()
            return@intercept
        }
        call.request.headers[HttpHeaders.Origin]?.let { rawOrigin ->
            val origin = runCatching { URI(rawOrigin) }.getOrNull()
            if (origin == null || !origin.sameOrigin(resourceOrigin)) {
                call.respond(HttpStatusCode.Forbidden, ApiError("mcp.invalid_origin"))
                finish()
                return@intercept
            }
        }
        val token = call.request.headers[HttpHeaders.Authorization]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.substringAfter(' ')
            ?.takeIf(String::isNotBlank)
        val identity = token?.let { core.mcpTokenStore.resolveAccess(it, config.mcpResource) }
        if (identity == null || core.userGroupStore.isDeactivated(identity.principal)) {
            call.response.header(HttpHeaders.WWWAuthenticate, "Bearer resource_metadata=\"$metadataUri\", scope=\"mcp:read\"")
            call.respond(HttpStatusCode.Unauthorized, ApiError("common.invalid_token", mapOf("kind" to "MCP bearer")))
            finish()
            return@intercept
        }
        call.attributes.put(MCP_CONTEXT, identity.toContext(call.httpRequesterIp(config)))
    }

    routing {
        get("/.well-known/oauth-protected-resource") { call.respond(resourceMetadata(config)) }
        get("/.well-known/oauth-protected-resource/mcp") { call.respond(resourceMetadata(config)) }
    }

    val authorizer = McpAuthorizer(config, core)
    val mutationExecutor = McpMutationExecutor(core.dataSource, core.auditStore, core.cedarPolicyStore, authorizer)
    mcpStatelessStreamableHttp(
        path = "/mcp",
        // The SDK's built-in guard reads the HTTP/1.1 Host header literally and rejects HTTP/2
        // :authority as missing. The interceptor above enforces the configured host through Ktor's
        // protocol-neutral host() view and validates Origin before authentication.
        enableDnsRebindingProtection = false,
    ) {
        val requestContext = call.attributes[MCP_CONTEXT]
        createMcpServer(
            call,
            metadataUri,
            requestContext,
            authorizer,
            mutationExecutor,
            datasourceService,
            policyService,
            identityService,
            core,
        )
    }
}

@Serializable
private data class ProtectedResourceMetadata(
    val resource: String,
    val authorization_servers: List<String>,
    val scopes_supported: List<String>,
    val bearer_methods_supported: List<String>,
)

private fun resourceMetadata(config: Config) = ProtectedResourceMetadata(
    resource = config.mcpResource,
    authorization_servers = listOf(config.mcpIssuer),
    scopes_supported = McpCapabilityRegistry.supportedScopes.toList(),
    bearer_methods_supported = listOf("header"),
)

private fun protectedResourceMetadataUri(resource: String): String {
    val uri = URI(resource)
    return URI(uri.scheme, uri.userInfo, uri.host, uri.port, "/.well-known/oauth-protected-resource/mcp", null, null).toASCIIString()
}

private fun McpAccessIdentity.toContext(requesterIp: String?) = McpRequestContext(principal, clientId, scopes, requesterIp)

private class McpAuthorizationException(val error: ApiError, val roles: Set<String>) : RuntimeException(error.code)

private class McpAuthorizer(private val config: Config, private val core: ControlPlaneCore) {
    fun authorize(context: McpRequestContext, capability: McpCapability): Set<String> {
        if (capability.requiredScope !in context.scopes) {
            throw McpAuthorizationException(
                ApiError("mcp.insufficient_scope", mapOf("scope" to capability.requiredScope)),
                emptySet(),
            )
        }
        val roles = core.roleResolver.resolve(context.principal)
        if (!config.authDebug) {
            val decision = core.authz.authorizeAs(
                context.principal,
                roles,
                capability.action,
                capability.resource,
                AuthzContext(channel = Channel.MCP.contextValue, requesterIp = context.requesterIp),
            )
            if (decision is AuthzDecision.Deny) {
                throw McpAuthorizationException(ApiError("common.forbidden", mapOf("detail" to decision.reason)), roles)
            }
        }
        return roles
    }
}

private class IdempotencyConflictException : RuntimeException()

private class McpMutationExecutor(
    private val dataSource: DataSource,
    private val auditStore: AuditStore,
    private val cedarPolicyStore: com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore,
    private val authorizer: McpAuthorizer,
) {
    fun execute(
        context: McpRequestContext,
        capability: McpCapability,
        arguments: JsonObject,
        datasource: String = "control-plane",
        detail: String,
        mutation: (Connection, AuditActor) -> JsonObject,
    ): JsonObject {
        val roles = try {
            authorizer.authorize(context, capability)
        } catch (e: McpAuthorizationException) {
            auditFailure(context, capability, e.roles, datasource, detail, Decision.DENY, e.error.code)
            throw ManagementException(e.error)
        }
        // Built from the roles `authorize` just resolved, so the audit row names the authority the call
        // actually ran under. Sorted because the row is hashed into the audit chain.
        val actor = AuditActor(context.principal, roles.sorted(), context.requesterIp, AuditSource.MCP)
        try {
            validateArguments(capability, arguments)
        } catch (e: McpInputException) {
            auditFailure(context, capability, roles, datasource, detail, Decision.ERROR, "mcp.invalid_request")
            throw e
        }
        val key = arguments["idempotencyKey"]?.jsonPrimitive?.contentOrNull?.takeIf(String::isNotBlank)
        val canonicalInput = canonicalJson(JsonObject(arguments.filterKeys { it != "idempotencyKey" }))
        val requestHash = sha256Hex(canonicalInput)
        try {
            val result = dataSource.connection.use { connection ->
                connection.autoCommit = false
                try {
                    if (key != null) {
                        val lockKey = listOf(context.principal, context.clientId, capability.toolName, key).joinToString("\\u0000")
                        connection.prepareStatement("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))").use { statement ->
                            statement.setString(1, lockKey)
                            statement.executeQuery().use { it.next() }
                        }
                        val prior = connection.prepareStatement(
                            """SELECT request_hash, response_json FROM mcp_mutation_idempotency
                               WHERE principal=? AND client_id=? AND tool_name=? AND idempotency_key=? FOR UPDATE""",
                        ).use { statement ->
                            statement.setString(1, context.principal)
                            statement.setString(2, context.clientId)
                            statement.setString(3, capability.toolName)
                            statement.setString(4, key)
                            statement.executeQuery().use { resultSet ->
                                if (resultSet.next()) resultSet.getString(1) to mcpJson.parseToJsonElement(resultSet.getString(2)).jsonObject else null
                            }
                        }
                        if (prior != null) {
                            if (prior.first != requestHash) throw IdempotencyConflictException()
                            auditStore.insert(
                                connection,
                                mcpAuditRecord(
                                    context, capability, roles, datasource, detail,
                                    Decision.ALLOW, "IDEMPOTENT_REPLAY",
                                ),
                            )
                            connection.commit()
                            return@use prior.second to true
                        }
                    }
                    val structured = mutation(connection, actor)
                    if (key != null) {
                        connection.prepareStatement(
                            """INSERT INTO mcp_mutation_idempotency
                               (principal, client_id, tool_name, idempotency_key, request_hash, response_json)
                               VALUES (?, ?, ?, ?, ?, ?::jsonb)""",
                        ).use { statement ->
                            statement.setString(1, context.principal)
                            statement.setString(2, context.clientId)
                            statement.setString(3, capability.toolName)
                            statement.setString(4, key)
                            statement.setString(5, requestHash)
                            statement.setString(6, structured.toString())
                            statement.executeUpdate()
                        }
                    }
                    connection.commit()
                    structured to false
                } catch (e: Exception) {
                    connection.rollback()
                    throw e
                } finally {
                    connection.autoCommit = true
                }
            }
            if (!result.second && capability.toolName in POLICY_MUTATION_TOOLS) cedarPolicyStore.markCommittedMutation()
            return result.first
        } catch (_: IdempotencyConflictException) {
            auditFailure(context, capability, roles, datasource, detail, Decision.ERROR, "IDEMPOTENCY_CONFLICT")
            throw ManagementException(ApiError("mcp.idempotency_conflict"))
        } catch (e: ManagementException) {
            auditFailure(context, capability, roles, datasource, detail, Decision.ERROR, e.error.code)
            throw e
        } catch (e: CedarValidationManagementException) {
            auditFailure(context, capability, roles, datasource, detail, Decision.ERROR, "CEDAR_VALIDATION")
            throw e
        } catch (e: McpInputException) {
            auditFailure(context, capability, roles, datasource, detail, Decision.ERROR, "mcp.invalid_request")
            throw e
        } catch (e: Exception) {
            auditFailure(context, capability, roles, datasource, detail, Decision.ERROR, "INTERNAL_ERROR")
            throw e
        }
    }

    private fun auditFailure(
        context: McpRequestContext,
        capability: McpCapability,
        roles: Set<String>,
        datasource: String,
        detail: String,
        decision: Decision,
        outcome: String,
    ) {
        runCatching { auditStore.insert(mcpAuditRecord(context, capability, roles, datasource, detail, decision, outcome)) }
    }

}

private fun mcpAuditRecord(
    context: McpRequestContext,
    capability: McpCapability,
    roles: Set<String>,
    datasource: String,
    detail: String,
    decision: Decision,
    outcome: String,
) = AuditEvent(
    principal = context.principal,
    roles = roles.sorted(),
    datasource = datasource,
    clientAddr = context.requesterIp,
    statement = "[MCP ${capability.toolName}]",
    decision = decision,
    detail = detail,
    channel = Channel.MCP.contextValue,
    authzAction = capability.action.cedarId,
    authzResource = "System::\"system\"",
    outcome = outcome,
    kind = ManagementAuditRecorder.KIND_ADMIN,
)

private fun createMcpServer(
    call: ApplicationCall,
    metadataUri: String,
    context: McpRequestContext,
    authorizer: McpAuthorizer,
    mutations: McpMutationExecutor,
    datasourceService: DatasourceManagementService,
    policyService: PolicyManagementService,
    identityService: IdentityManagementService,
    core: ControlPlaneCore,
): Server {
    val locale = requestLocale(call)
    val server = Server(
        Implementation("proxy-monster-access-control", "1.0.0"),
        ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false))),
    )
    for (capability in McpCapabilityRegistry.entries) {
        server.addTool(
            name = capability.toolName,
            description = toolDescription(capability.toolName, locale),
            inputSchema = schemaFor(capability.toolName),
            toolAnnotations = ToolAnnotations(
                readOnlyHint = capability.annotations.readOnlyHint,
                destructiveHint = capability.annotations.destructiveHint,
                idempotentHint = capability.classification == CapabilityClassification.READ,
                openWorldHint = capability.toolName == "get_table_detail",
            ),
        ) { request ->
            val args = request.arguments ?: JsonObject(emptyMap())
            try {
                val structured = if (capability.classification == CapabilityClassification.READ) {
                    authorizeRead(context, capability, args, authorizer, core.auditStore)
                    validateArguments(capability, args)
                    executeRead(capability.toolName, args, datasourceService, policyService, identityService)
                } else {
                    executeWrite(capability, args, context, mutations, datasourceService, policyService, identityService, core)
                }
                CallToolResult(content = listOf(TextContent(structured.toString())), structuredContent = structured)
            } catch (e: CedarValidationManagementException) {
                val raw = buildJsonObject { put("errors", JsonArray(e.errors.map(::JsonPrimitive))) }
                CallToolResult(content = listOf(TextContent(raw.toString())), isError = true, structuredContent = raw)
            } catch (e: McpAuthorizationException) {
                localizedError(call, e.error, metadataUri)
            } catch (e: ManagementException) {
                localizedError(call, e.error, metadataUri)
            } catch (_: McpInputException) {
                localizedError(call, ApiError("mcp.invalid_request"))
            } catch (_: Exception) {
                localizedError(call, ApiError("mcp.internal_error"))
            }
        }
    }
    return server
}

private fun authorizeRead(
    context: McpRequestContext,
    capability: McpCapability,
    arguments: JsonObject,
    authorizer: McpAuthorizer,
    auditStore: AuditStore,
) {
    try {
        authorizer.authorize(context, capability)
    } catch (e: McpAuthorizationException) {
        runCatching {
            auditStore.insert(
                mcpAuditRecord(
                    context, capability, e.roles, safeDatasource(capability, arguments),
                    mutationDetail(capability.toolName, arguments), Decision.DENY, e.error.code,
                ),
            )
        }
        throw e
    }
}

private suspend fun executeRead(
    tool: String,
    args: JsonObject,
    datasources: DatasourceManagementService,
    policies: PolicyManagementService,
    identities: IdentityManagementService,
): JsonObject = when (tool) {
    "list_datasources" -> structured(datasources.listDatasources())
    "get_datasource_liveness" -> structured(datasources.getDatasourceLiveness(args.requiredString("datasource")))
    "browse_catalog" -> structured(datasources.browseCatalog(args.requiredString("datasource")))
    "get_table_detail" -> structured(
        datasources.getTableDetail(args.requiredString("datasource"), args.requiredString("schema"), args.requiredString("table")),
    )
    "list_column_tags" -> structured(datasources.listColumnTags(args.requiredString("datasource")))
    "list_policies" -> structured(policies.listPolicies())
    "get_policy" -> structured(policies.getPolicy(args.requiredString("name")))
    "validate_policy" -> structured(policies.validatePolicy(args.requiredString("cedarSrc")))
    "get_policy_schema" -> structured(policies.policySchema())
    "list_roles" -> structured(policies.listRoles())
    "list_role_assignments" -> structured(policies.listAssignments(args.string("principal"), args.string("roleName")))
    "list_users" -> structured(identities.listUsers())
    "list_groups" -> structured(identities.listGroups())
    "list_mask_fns" -> structured(policies.listMaskFns())
    else -> throw ManagementException(ApiError("mcp.invalid_request"))
}

private fun executeWrite(
    capability: McpCapability,
    args: JsonObject,
    context: McpRequestContext,
    mutations: McpMutationExecutor,
    datasources: DatasourceManagementService,
    policies: PolicyManagementService,
    identities: IdentityManagementService,
    core: ControlPlaneCore,
): JsonObject {
    val datasourceName = safeDatasource(capability, args)
    val detail = mutationDetail(capability.toolName, args)
    return mutations.execute(context, capability, args, datasource = datasourceName, detail = detail) { connection, actor ->
        when (capability.toolName) {
            "set_column_classification" -> {
                val maskFnId = args.string("maskFnName")?.let { name ->
                    core.policyStore.getMaskFnByName(name, connection)?.id
                        ?: throw ManagementException(ApiError("common.not_found", mapOf("resource" to "mask function")))
                }
                structured(
                    datasources.setColumnClassification(
                        args.requiredString("datasource"), args.string("schema"), args.requiredString("table"),
                        args.requiredString("column"), args.stringSet("tags").toList(), maskFnId, actor, connection,
                    ),
                )
            }
            "set_column_classifications" -> {
                val entries = args.objectArray(
                    "columns",
                    CLASSIFICATION_ENTRY_KEYS,
                    DatasourceManagementService.MAX_CLASSIFICATION_BATCH,
                )
                // One name→id lookup per DISTINCT mask function, not per column: a batch tagging a whole
                // table typically names the same one throughout.
                val maskFnIds = entries.mapNotNull { it.string("maskFnName") }.toSet().associateWith { name ->
                    core.policyStore.getMaskFnByName(name, connection)?.id
                        ?: throw ManagementException(ApiError("common.not_found", mapOf("resource" to "mask function")))
                }
                structured(
                    ColumnClassificationBatch(
                        args.requiredString("datasource"),
                        datasources.setColumnClassifications(
                            args.requiredString("datasource"),
                            entries.map { entry ->
                                ClassificationInput(
                                    entry.string("schema"),
                                    entry.requiredString("table"),
                                    entry.requiredString("column"),
                                    entry.stringSet("tags").toList(),
                                    entry.string("maskFnName")?.let(maskFnIds::getValue),
                                )
                            },
                            actor, connection,
                        ),
                    ),
                )
            }
            "clear_column_classification" -> structured(
                datasources.clearColumnClassification(
                    args.requiredString("datasource"), args.string("schema"), args.requiredString("table"),
                    args.requiredString("column"), actor, connection,
                ),
            )
            "create_policy" -> structured(
                policies.createPolicy(args.requiredString("name"), args.requiredString("cedarSrc"), args.boolean("enabled") ?: true, context.principal, actor, connection),
            )
            "update_policy" -> structured(
                policies.getPolicy(args.requiredString("name"), connection).let { current ->
                    policies.updatePolicy(
                        current.name, args.string("newName"), args.requiredString("cedarSrc"),
                        if (args.has("enabled")) args.boolean("enabled") ?: current.enabled else current.enabled,
                        context.principal, actor, connection,
                    )
                },
            )
            "enable_policy" -> structured(policies.setPolicyEnabled(args.requiredString("name"), true, context.principal, actor, connection))
            "disable_policy" -> structured(policies.setPolicyEnabled(args.requiredString("name"), false, context.principal, actor, connection))
            "delete_policy" -> structured(policies.deletePolicy(args.requiredString("name"), actor, connection))
            "create_role" -> structured(policies.createRole(args.requiredString("name"), args.string("description"), actor, connection))
            "update_role" -> structured(
                policies.getRole(args.requiredString("name"), connection).let { current ->
                    policies.updateRole(
                        current.name,
                        args.string("newName"),
                        if (args.has("description")) args.string("description") else current.description,
                        actor, connection,
                    )
                },
            )
            "delete_role" -> structured(policies.deleteRole(args.requiredString("name"), actor, connection))
            "assign_role" -> structured(policies.assignRole(args.requiredString("principal"), args.requiredString("roleName"), actor, connection))
            "unassign_role" -> structured(policies.unassignRole(args.requiredString("principal"), args.requiredString("roleName"), actor, connection))
            "create_user" -> structured(
                identities.createUser(
                    AppUserInput(
                        args.requiredString("principal"), args.string("displayName"), args.string("email"), args.boolean("active") ?: true,
                    ),
                    actor, connection,
                ),
            )
            "update_user" -> structured(
                identities.getUser(args.requiredString("principal"), connection).let { current ->
                    identities.updateUser(
                        current.principal,
                        args.string("newPrincipal"),
                        if (args.has("displayName")) args.string("displayName") else current.displayName,
                        if (args.has("email")) args.string("email") else current.email,
                        if (args.has("active")) args.boolean("active") ?: current.active else current.active,
                        actor, connection,
                    )
                },
            )
            "deprovision_user" -> structured(identities.deprovisionUser(args.requiredString("principal"), actor, connection))
            "create_group" -> structured(
                identities.createGroup(AppGroupInput(args.requiredString("name"), args.string("description")), actor, connection),
            )
            "update_group" -> structured(
                identities.getGroup(args.requiredString("name"), connection).let { current ->
                    identities.updateGroup(
                        current.name,
                        args.string("newName"),
                        if (args.has("description")) args.string("description") else current.description,
                        actor, connection,
                    )
                },
            )
            "delete_group" -> structured(identities.deleteGroup(args.requiredString("name"), actor, connection))
            "add_group_member" -> structured(
                identities.addGroupMember(args.requiredString("groupName"), args.requiredString("principal"), actor, connection),
            )
            "remove_group_member" -> structured(
                identities.removeGroupMember(args.requiredString("groupName"), args.requiredString("principal"), actor, connection),
            )
            "set_group_roles" -> structured(
                identities.setGroupRoles(args.requiredString("groupName"), args.stringSet("roleNames"), actor, connection),
            )
            "create_mask_fn" -> structured(
                policies.createMaskFn(MaskFnInput(args.requiredString("name"), args.requiredString("kind")), actor, connection),
            )
            "update_mask_fn" -> structured(
                policies.getMaskFn(args.requiredString("name"), connection).let { current ->
                    policies.updateMaskFn(
                        current.name,
                        MaskFnInput(
                            args.string("newName") ?: current.name,
                            args.requiredString("kind"),
                        ),
                        actor, connection,
                    )
                },
            )
            "delete_mask_fn" -> structured(policies.deleteMaskFn(args.requiredString("name"), actor, connection))
            else -> throw ManagementException(ApiError("mcp.invalid_request"))
        }
    }
}

private fun schemaFor(tool: String): ToolSchema {
    val properties = buildJsonObject {
        fun string(name: String) = putJsonObject(name) { put("type", "string") }
        fun boolean(name: String) = putJsonObject(name) { put("type", "boolean") }
        fun strings(name: String) = putJsonObject(name) {
            put("type", "array")
            put("items", buildJsonObject { put("type", "string") })
        }
        when (tool) {
            "get_datasource_liveness", "browse_catalog", "list_column_tags" -> string("datasource")
            "get_table_detail" -> { string("datasource"); string("schema"); string("table") }
            "get_policy", "enable_policy", "disable_policy", "delete_policy", "delete_role", "delete_group", "delete_mask_fn" -> string("name")
            "validate_policy" -> string("cedarSrc")
            "list_role_assignments" -> { string("principal"); string("roleName") }
            "set_column_classification" -> {
                string("datasource"); string("schema"); string("table"); string("column"); strings("tags"); string("maskFnName"); string("idempotencyKey")
            }
            "set_column_classifications" -> {
                string("datasource")
                putJsonObject("columns") {
                    put("type", "array")
                    put("minItems", 1)
                    put("maxItems", DatasourceManagementService.MAX_CLASSIFICATION_BATCH)
                    put("items", buildJsonObject {
                        put("type", "object")
                        put("additionalProperties", false)
                        put("required", buildJsonArray { add(JsonPrimitive("table")); add(JsonPrimitive("column")); add(JsonPrimitive("tags")) })
                        putJsonObject("properties") {
                            putJsonObject("schema") { put("type", "string") }
                            putJsonObject("table") { put("type", "string") }
                            putJsonObject("column") { put("type", "string") }
                            putJsonObject("tags") {
                                put("type", "array")
                                put("items", buildJsonObject { put("type", "string") })
                            }
                            putJsonObject("maskFnName") { put("type", "string") }
                        }
                    })
                }
            }
            "clear_column_classification" -> { string("datasource"); string("schema"); string("table"); string("column"); string("idempotencyKey") }
            "create_policy" -> { string("name"); string("cedarSrc"); boolean("enabled"); string("idempotencyKey") }
            "update_policy" -> { string("name"); string("newName"); string("cedarSrc"); boolean("enabled"); string("idempotencyKey") }
            "create_role" -> { string("name"); string("description"); string("idempotencyKey") }
            "update_role" -> { string("name"); string("newName"); string("description"); string("idempotencyKey") }
            "assign_role", "unassign_role" -> { string("principal"); string("roleName"); string("idempotencyKey") }
            "create_user" -> { string("principal"); string("displayName"); string("email"); boolean("active"); string("idempotencyKey") }
            "update_user" -> { string("principal"); string("newPrincipal"); string("displayName"); string("email"); boolean("active"); string("idempotencyKey") }
            "deprovision_user" -> { string("principal"); string("idempotencyKey") }
            "create_group" -> { string("name"); string("description"); string("idempotencyKey") }
            "update_group" -> { string("name"); string("newName"); string("description"); string("idempotencyKey") }
            "add_group_member", "remove_group_member" -> { string("groupName"); string("principal"); string("idempotencyKey") }
            "set_group_roles" -> { string("groupName"); strings("roleNames"); string("idempotencyKey") }
            "create_mask_fn" -> { string("name"); string("kind"); string("idempotencyKey") }
            "update_mask_fn" -> { string("name"); string("newName"); string("kind"); string("idempotencyKey") }
        }
        if (McpCapabilityRegistry.byName[tool]?.classification == CapabilityClassification.WRITE) {
            string("idempotencyKey")
        }
    }
    val required = when (tool) {
        "get_datasource_liveness", "browse_catalog", "list_column_tags" -> listOf("datasource")
        "get_table_detail" -> listOf("datasource", "schema", "table")
        "get_policy", "enable_policy", "disable_policy", "delete_policy", "delete_role", "delete_group", "delete_mask_fn" -> listOf("name")
        "validate_policy" -> listOf("cedarSrc")
        "set_column_classification" -> listOf("datasource", "table", "column", "tags")
        "set_column_classifications" -> listOf("datasource", "columns")
        "clear_column_classification" -> listOf("datasource", "table", "column")
        "create_policy" -> listOf("name", "cedarSrc")
        "update_policy" -> listOf("name", "cedarSrc")
        "create_role", "create_group" -> listOf("name")
        "update_role", "update_group" -> listOf("name")
        "assign_role", "unassign_role" -> listOf("principal", "roleName")
        "create_user", "update_user", "deprovision_user" -> listOf("principal")
        "add_group_member", "remove_group_member" -> listOf("groupName", "principal")
        "set_group_roles" -> listOf("groupName", "roleNames")
        "create_mask_fn", "update_mask_fn" -> listOf("name", "kind")
        else -> emptyList()
    }
    return ToolSchema(properties = properties, required = required)
}

private inline fun <reified T> structured(value: T): JsonObject = buildJsonObject {
    put("result", mcpJson.encodeToJsonElement(serializer<T>(), value))
}

private fun localizedError(call: ApplicationCall, error: ApiError, metadataUri: String? = null): CallToolResult {
    if (error.code == "mcp.insufficient_scope" || error.code == "common.forbidden") {
        call.response.status(HttpStatusCode.Forbidden)
    }
    if (error.code == "mcp.insufficient_scope") {
        val scope = error.params.getValue("scope")
        val metadata = requireNotNull(metadataUri)
        call.response.header(
            HttpHeaders.WWWAuthenticate,
            "Bearer error=\"insufficient_scope\", scope=\"$scope\", resource_metadata=\"$metadata\"",
        )
    }
    val en = messageFor(error, Locale.ENGLISH)
    val ko = messageFor(error, Locale.KOREAN)
    val body = buildJsonObject {
        put("code", error.code)
        put("params", buildJsonObject { error.params.forEach { (key, value) -> put(key, value) } })
        put("message_en", en)
        put("message_ko", ko)
    }
    return CallToolResult(content = listOf(TextContent(body.toString())), isError = true, structuredContent = body)
}

private class McpInputException : RuntimeException()

private fun validateArguments(capability: McpCapability, arguments: JsonObject) {
    val allowed = schemaFor(capability.toolName).properties?.keys.orEmpty()
    if ((arguments.keys - allowed).isNotEmpty()) throw McpInputException()
    arguments["idempotencyKey"]?.let { value ->
        val key = (value as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
            ?: throw McpInputException()
        if (key.isBlank() || key.length > 128) throw McpInputException()
    }
}

private fun messageFor(error: ApiError, locale: Locale): String {
    val bundle = ResourceBundle.getBundle("mcp_errors", locale)
    var message = bundle.getString(error.code)
    error.params.forEach { (key, value) -> message = message.replace("{$key}", value) }
    return message
}

private fun mutationDetail(tool: String, args: JsonObject): String {
    val targetKeys = listOf("datasource", "name", "principal", "groupName", "roleName", "table", "column")
    return buildString {
        append(tool)
        targetKeys.mapNotNull { key ->
            (args[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.let { "$key=$it" }
        }
            .joinToString(",", prefix = " ").takeIf { it.isNotBlank() }?.let(::append)
        // A batch's targets are nested, so the loop above records only its datasource. Naming each
        // column keeps one audit row per batch as answerable as the single-column tool's row is —
        // an auditor reading the trail must see WHICH columns were tagged, not just how many.
        if (tool == "set_column_classifications") {
            val entries = (args["columns"] as? JsonArray).orEmpty()
            append(" columns=${entries.size}")
            // Capped, because this string is built from unvalidated arguments BEFORE authorization —
            // an unauthenticated-for-write caller must not be able to size the audit row. An
            // over-cap batch is refused outright, so naming the entries it never applied is noise.
            if (entries.size <= DatasourceManagementService.MAX_CLASSIFICATION_BATCH) {
                entries.mapNotNull { entry ->
                    (entry as? JsonObject)?.let { column ->
                        val table = (column["table"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
                        val name = (column["column"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
                        val schema = (column["schema"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
                        if (table == null || name == null) null else listOfNotNull(schema, table, name).joinToString(".")
                    }
                }
                    .takeIf { it.isNotEmpty() }
                    ?.let { append(it.joinToString(",", prefix = " [", postfix = "]")) }
            }
        }
    }
}

private fun safeDatasource(capability: McpCapability, args: JsonObject): String =
    if (capability.toolName in CLASSIFICATION_TOOLS) {
        (args["datasource"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
            ?.takeIf(String::isNotBlank) ?: "control-plane"
    } else {
        "control-plane"
    }

private fun JsonObject.requiredString(name: String): String = string(name)?.takeIf(String::isNotBlank)
    ?: throw ManagementException(ApiError("common.field_required", mapOf("fields" to name)))
private fun JsonObject.string(name: String): String? {
    val value = get(name) ?: return null
    if (value is JsonNull) return null
    return (value as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: throw McpInputException()
}
private fun JsonObject.boolean(name: String): Boolean? {
    val value = get(name) ?: return null
    if (value is JsonNull) return null
    return (value as? JsonPrimitive)?.booleanOrNull ?: throw McpInputException()
}
/**
 * Read a bounded array of objects, rejecting any key the entry schema does not declare.
 * [validateArguments] only sees top-level keys, so without this a batch entry could carry an unknown
 * field and be applied as though it were understood — the same silent-acceptance the top-level check
 * exists to prevent. The size is checked before the caller reads any entry, so an oversized batch
 * costs no per-entry work (notably the mask-function lookups) on its way to being refused.
 */
private fun JsonObject.objectArray(name: String, allowed: Set<String>, max: Int): List<JsonObject> {
    val array = get(name) as? JsonArray
        ?: throw ManagementException(ApiError("common.field_required", mapOf("fields" to name)))
    if (array.size > max) {
        throw ManagementException(ApiError("datasource.batch_too_large", mapOf("max" to max.toString())))
    }
    return array.map { element ->
        val entry = element as? JsonObject ?: throw McpInputException()
        if ((entry.keys - allowed).isNotEmpty()) throw McpInputException()
        entry
    }
}

private fun JsonObject.stringSet(name: String): Set<String> {
    val array = get(name) as? JsonArray
        ?: throw ManagementException(ApiError("common.field_required", mapOf("fields" to name)))
    return array.map { value ->
        (value as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: throw McpInputException()
    }.toSet()
}
private fun JsonObject.has(name: String): Boolean = containsKey(name)

private fun requestLocale(call: ApplicationCall): Locale =
    if (call.request.headers[HttpHeaders.AcceptLanguage]?.lowercase(Locale.ROOT)?.startsWith("ko") == true) {
        Locale.KOREAN
    } else {
        Locale.ENGLISH
    }

private fun toolDescription(toolName: String, locale: Locale): String =
    ResourceBundle.getBundle("mcp_tools", locale).getString(toolName)

private fun URI.sameOrigin(other: URI): Boolean =
    scheme.equals(other.scheme, ignoreCase = true) && host.equals(other.host, ignoreCase = true) &&
        effectivePort() == other.effectivePort() && userInfo == null && path.isNullOrEmpty() && query == null && fragment == null

private fun URI.effectivePort(): Int = if (port >= 0) port else if (scheme.equals("https", true)) 443 else 80

private fun canonicalJson(element: JsonElement): String = when (element) {
    is JsonObject -> element.entries.sortedBy { it.key }.joinToString(",", "{", "}") { (key, value) ->
        mcpJson.encodeToString(JsonPrimitive(key)) + ":" + canonicalJson(value)
    }
    is JsonArray -> element.joinToString(",", "[", "]", transform = ::canonicalJson)
    else -> element.toString()
}
