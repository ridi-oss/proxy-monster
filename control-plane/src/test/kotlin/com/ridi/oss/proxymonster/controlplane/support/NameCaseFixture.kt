package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceInput
import com.ridi.oss.proxymonster.controlplane.DecisionContext
import com.ridi.oss.proxymonster.controlplane.MaskFn
import com.ridi.oss.proxymonster.controlplane.MaskFnInput
import com.ridi.oss.proxymonster.controlplane.QueryResponse
import com.ridi.oss.proxymonster.controlplane.RoleAssignmentInput
import com.ridi.oss.proxymonster.controlplane.RoleInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.decideQuery
import com.ridi.oss.proxymonster.controlplane.effectiveCatalog
import com.ridi.oss.proxymonster.grpc.EnfAction
import io.ktor.client.HttpClient
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.flywaydb.core.Flyway
import java.sql.DriverManager
import java.sql.Statement
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertTrue

const val NAME_READER = "name-reader@example.com"
const val NAME_ADMIN = "name-admin@example.com"
const val NAME_SENTINEL = "cleartext.sentinel@example.com"

/** One control plane over a fresh metadata store, with an admin and a per-datasource reader role. */
class NameCaseStack private constructor(val metadata: DataSource, val core: ControlPlaneCore) {
    val maskFn: MaskFn = core.policyStore.createMaskFn(MaskFnInput("name-case-last4", "LAST_N"))
    val tokens = McpTokens(metadata)
    private val counter = AtomicInteger()

    init {
        val admin = checkNotNull(core.policyStore.getRoleByName("system:admin"))
        core.policyStore.createAssignment(RoleAssignmentInput(NAME_ADMIN, admin.id))
        val reader = core.policyStore.createRole(RoleInput("name-reader"))
        core.policyStore.createAssignment(RoleAssignmentInput(NAME_READER, reader.id))
    }

    fun adminToken(): String = tokens.token(NAME_ADMIN, ALL_MCP_SCOPES)

    fun mysql(server: SharedMySqlServer, setup: (Statement) -> Unit): NameCaseTarget {
        val database = server.freshDatabase("pm_names")
        val url = server.jdbcUrlFor(database)
        DriverManager.getConnection(url, server.username(), server.password()).use { c -> c.createStatement().use(setup) }
        return register("mysql", server.host(), server.port(), database, url, server.username(), server.password())
    }

    fun postgres(setup: (Statement) -> Unit): NameCaseTarget {
        val database = SharedPostgres.freshDatabase("pm_names_pg")
        val url = SharedPostgres.jdbcUrlFor(database)
        DriverManager.getConnection(url, SharedPostgres.username(), SharedPostgres.password()).use { c -> c.createStatement().use(setup) }
        return register("postgres", SharedPostgres.host(), SharedPostgres.port(), database, url, SharedPostgres.username(), SharedPostgres.password())
    }

    private fun register(engine: String, host: String, port: Int, database: String, url: String, user: String, password: String): NameCaseTarget {
        val created = core.datasourceStore.create(DatasourceInput("names-$engine-${counter.incrementAndGet()}", engine, host, port, database))
        core.datasourceStore.pushTestCatalog(created, url, user, password, canonical = true)
        val ds = checkNotNull(core.datasourceStore.get(created.id))
        policy(
            "${ds.name}-connect",
            """permit(principal in Role::"name-reader", action in [Action::"datasource.connect", Action::"stmt.cat.read", Action::"stmt.cat.write.insert"], resource in Datasource::"${ds.name}");""",
        )
        policy(
            "${ds.name}-unmasked",
            """permit(principal in Role::"name-reader", action == Action::"result.read.unmasked", resource in Datasource::"${ds.name}") unless { resource in Tag::"pii" };""",
        )
        policy(
            "${ds.name}-masked",
            """permit(principal in Role::"name-reader", action == Action::"result.read.masked", resource in Datasource::"${ds.name}") when { resource in Tag::"pii" };""",
        )
        return NameCaseTarget(this, ds, url, user, password)
    }

    fun policy(name: String, source: String) {
        core.cedarPolicyStore.create(CedarPolicyInput(name, source), updatedBy = "name-case-test")
    }

    companion object {
        fun create(): NameCaseStack {
            val metadata = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_names_meta"))
            Flyway.configure().dataSource(metadata).load().migrate()
            return NameCaseStack(metadata, ControlPlaneCore(metadata))
        }
    }
}

class NameCaseTarget(
    val stack: NameCaseStack,
    val datasource: Datasource,
    val jdbcUrl: String,
    val user: String,
    val password: String,
) {
    val core: ControlPlaneCore get() = stack.core
    val catalog: String get() = datasource.effectiveCatalog
    val schema: String get() = datasource.defaultSchemas.first { !it.startsWith("pg_") && it != "information_schema" }

    fun run(sql: String, principal: String = NAME_READER): QueryResponse = runEnforcedForTest(
        principal = principal,
        ds = datasource,
        sql = sql,
        maxRows = 100,
        clientAddr = "127.0.0.1",
        datasourceStore = core.datasourceStore,
        policyStore = core.policyStore,
        auditStore = core.auditStore,
        accessStore = core.accessStore,
        userGroupStore = core.userGroupStore,
        roleResolver = core.roleResolver,
        authz = core.authz,
        execute = { s, maxRows -> execOnTarget(jdbcUrl, user, password, s, maxRows) },
    )

    fun decide(
        sql: String,
        principal: String = NAME_READER,
        channel: Channel = Channel.EDITOR,
        providedRoles: Set<String>? = null,
    ): DecisionContext = decideQuery(
        principal, datasource, sql, channel, core.datasourceStore.catalog(datasource.id),
        core.policyStore, core.accessStore, core.userGroupStore, core.roleResolver, core.authz,
        providedRoles = providedRoles,
    )

    fun assertMasked(sql: String, sentinel: String = NAME_SENTINEL) {
        val response = run(sql)
        assertEquals(EnfAction.MASK, response.decision, "$sql: ${response.denyReason}")
        assertTrue(response.rows.flatten().none { it?.contains(sentinel) == true }, "$sql returned cleartext: ${response.rows}")
    }

    fun assertDenied(sql: String) {
        val response = run(sql)
        assertEquals(EnfAction.DENY, response.decision, "$sql: ${response.denyReason}")
        assertTrue(response.rows.isEmpty(), "$sql returned rows: ${response.rows}")
    }

    fun assertCleartext(sql: String, sentinel: String = NAME_SENTINEL) {
        val response = run(sql)
        assertEquals(EnfAction.ALLOW, response.decision, "$sql: ${response.denyReason}")
        assertTrue(response.rows.flatten().any { it == sentinel }, "$sql did not return its unclassified value: ${response.rows}")
    }

    fun classificationArgs(schema: String?, table: String, column: String, catalog: String = this.catalog): JsonObject = buildJsonObject {
        put("catalog", catalog)
        schema?.let { put("schema", it) }
        put("table", table)
        put("column", column)
        put("tags", buildJsonArray { add(JsonPrimitive("pii")) })
        put("maskFnName", stack.maskFn.name)
    }

    suspend fun mcpClassify(client: HttpClient, token: String, schema: String?, table: String, column: String): JsonObject =
        client.mcpCall(
            token,
            "set_column_classification",
            JsonObject(classificationArgs(schema, table, column) + ("datasource" to JsonPrimitive(datasource.name))),
        )

    suspend fun httpClassify(client: HttpClient, schema: String?, table: String, column: String): HttpResponse =
        client.put("/api/datasources/${datasource.id}/classification") {
            contentType(ContentType.Application.Json)
            setBody(
                buildJsonObject {
                    put("catalog", catalog)
                    schema?.let { put("schema", it) }
                    put("table", table)
                    put("column", column)
                    put("tags", buildJsonArray { add(JsonPrimitive("pii")) })
                    put("maskFnId", stack.maskFn.id)
                }.toString(),
            )
        }

    suspend fun listedTags(client: HttpClient, token: String): List<JsonObject> =
        client.mcpCall(token, "list_column_tags", buildJsonObject { put("datasource", datasource.name) })
            .okResult().jsonArray.map { it.jsonObject }
}
