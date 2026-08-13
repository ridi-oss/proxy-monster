package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import com.ridi.oss.proxymonster.grpc.ControlEvent
import com.ridi.oss.proxymonster.grpc.ProxyTableDetailMsg
import com.ridi.oss.proxymonster.grpc.controlTableDetailMsg
import com.ridi.oss.proxymonster.grpc.proxyTableDetailMsg
import com.ridi.oss.proxymonster.grpc.tableDetailClose
import com.ridi.oss.proxymonster.grpc.tableDetailError
import com.ridi.oss.proxymonster.grpc.tableDetailReady
import com.ridi.oss.proxymonster.grpc.tableDetailResult
import com.ridi.oss.proxymonster.probe.TableDetail
import com.ridi.oss.proxymonster.probe.TableDetailColumn
import com.ridi.oss.proxymonster.probe.TableIndex
import com.ridi.oss.proxymonster.probe.TableIndexColumn
import com.ridi.oss.proxymonster.probe.TableMetadata
import com.ridi.oss.proxymonster.probe.TableRelation
import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.consumeAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.CopyOnWriteArrayList
import javax.sql.DataSource
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TableDetailDbTest {
    private lateinit var metadata: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var datasourceStore: DatasourceStore
    private lateinit var policyStore: PolicyStore
    private lateinit var authz: Authz
    private lateinit var postgres: Fixture
    private lateinit var mysql: Fixture
    private val fakeProxies = ArrayList<FakeTableDetailProxy>()

    private val caller = "dev@example.com"

    private val config = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = false,
        secretToken = null,
        sessionSecret = "table-detail-test-secret",
        oidc = null,
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 3600,
        idpRecheckIntervalSeconds = 600,
        devMarker = true,
    )

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        metadata = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_table_detail_channel"))
        Flyway.configure().dataSource(metadata).load().migrate()
        core = ControlPlaneCore(metadata)
        datasourceStore = core.datasourceStore
        policyStore = core.policyStore
        val cedarStore = CedarPolicyStore(metadata)
        // This suite exercises detail ASSEMBLY, not the connect gate (DatasourceMetadataConnectGateDbTest
        // owns that), so the engine carries an outright connect permit and every case signs in as an
        // ordinary principal. The permit goes to the ENGINE, which is what authorize() reads.
        authz = Authz(
            CedarEngine(listOf(1L to """permit(principal, action == Action::"datasource.connect", resource);""")),
            cedarStore,
            RoleSource { emptySet() },
        )
        postgres = createFixture("detail-postgres", "postgres", "detail_schema", "detail_pg")
        mysql = createFixture("detail-mysql", "mysql", "detail_mysql", "detail_my")
        fakeProxies += FakeTableDetailProxy(core, postgres.datasource.name) { schema, table ->
            if (schema == postgres.requestSchema && table == postgres.middle) ProxyReply.Detail(postgres.detail) else ProxyReply.NotFound
        }
        fakeProxies += FakeTableDetailProxy(core, mysql.datasource.name) { schema, table ->
            if ((schema == mysql.requestSchema || schema == "public") && table == mysql.middle) {
                ProxyReply.Detail(mysql.detail)
            } else {
                ProxyReply.NotFound
            }
        }
    }

    @AfterAll
    fun close() {
        fakeProxies.forEach(FakeTableDetailProxy::close)
        (metadata as? AutoCloseable)?.close()
    }

    @Test
    fun `postgres route assembles proxy detail overlays classification and stays stateless`() = testApplication {
        assertRouteContract(postgres)
    }

    @Test
    fun `mysql route assembles proxy detail overlays classification and stays stateless`() = testApplication {
        assertRouteContract(mysql)
    }

    @Test
    fun `grpc table-detail stream claims once and relays both directions`() = runBlocking {
        val pending = PendingTableDetail("grpc-table-detail", CompletableDeferred())
        core.tableDetailChannels.register(pending)
        val requests = Channel<ProxyTableDetailMsg>(Channel.BUFFERED)
        val controls = Channel<com.ridi.oss.proxymonster.grpc.ControlTableDetailMsg>(Channel.BUFFERED)
        val collectJob = launch {
            ControlPlaneGrpcService(core).tableDetailExec(requests.consumeAsFlow()).collect { controls.send(it) }
        }

        requests.send(
            proxyTableDetailMsg {
                sessionReady = tableDetailReady { sessionId = pending.sessionId }
            },
        )
        val attached = withTimeout(5_000) { pending.ready.await() }
        val result = proxyTableDetailMsg { this.result = tableDetailResult { json = "null" } }
        requests.send(result)
        assertEquals(result, withTimeout(5_000) { attached.inbound.receive() })

        attached.outbound.send(controlTableDetailMsg { close = tableDetailClose {} })
        assertTrue(withTimeout(5_000) { controls.receive() }.hasClose())
        requests.close()
        collectJob.join()
    }

    @Test
    fun `route validates selectors rejects identifier attacks and reports proxy failures`() = testApplication {
        val client = wireTableDetailApp()
        val base = "/api/datasources/${mysql.datasource.id}/table-detail"
        val proxy = fakeProxies.single { it.datasourceName == mysql.datasource.name }
        val requestsBeforeValidation = proxy.requests.size

        assertEquals(HttpStatusCode.BadRequest, client.get(base) { parameter("table", mysql.middle) }.status)
        assertEquals(HttpStatusCode.BadRequest, client.get(base) { parameter("schema", "public") }.status)
        assertEquals(
            HttpStatusCode.BadRequest,
            client.get(base) { parameter("schema", ""); parameter("table", mysql.middle) }.status,
        )
        assertEquals(
            HttpStatusCode.BadRequest,
            client.get(base) { parameter("schema", "public"); parameter("table", "") }.status,
        )
        assertEquals(requestsBeforeValidation, proxy.requests.size, "invalid selectors must be rejected before a nudge")
        assertEquals(HttpStatusCode.BadRequest, client.get("/api/datasources/999999/table-detail").status)

        assertEquals(
            HttpStatusCode.NotFound,
            client.get("/api/datasources/999999/table-detail") {
                parameter("schema", "public")
                parameter("table", mysql.middle)
            }.status,
        )
        assertEquals(
            HttpStatusCode.NotFound,
            client.get(base) { parameter("schema", "public"); parameter("table", "${mysql.prefix}_absent") }.status,
        )

        val attacks = listOf(
            "public' OR '1'='1' --" to mysql.middle,
            "public`; SHOW TABLES; --" to mysql.middle,
            "public" to "${mysql.middle}' OR 1=0; SHOW TABLES; --",
            "public" to "${mysql.middle}`; SHOW TABLES; --",
            "public" to "${mysql.middle}`; DROP TABLE `${mysql.parent}`; --",
        )
        for ((schema, table) in attacks) {
            val attack = client.get(base) { parameter("schema", schema); parameter("table", table) }
            assertEquals(HttpStatusCode.NotFound, attack.status, "identifier payload must be treated as an exact lookup")
        }

        val failing = datasourceStore.create(
            DatasourceInput(
                name = "failing-proxy-target",
                engine = "postgres",
                host = "advisory.invalid",
                port = 5432,
                dbName = "unreachable",
            ),
        )
        fakeProxies += FakeTableDetailProxy(core, failing.name) { _, _ -> ProxyReply.Error("target-DB connection failed") }
        val failedResponse = client.get("/api/datasources/${failing.id}/table-detail") {
            parameter("schema", "public")
            parameter("table", "anything")
        }
        assertEquals(HttpStatusCode.BadGateway, failedResponse.status)
        assertContains(failedResponse.bodyAsText(), "target-DB connection failed")

        val detached = datasourceStore.create(
            DatasourceInput(
                name = "detached-proxy",
                engine = "postgres",
                host = "advisory.invalid",
                port = 5432,
                dbName = "detached",
            ),
        )
        val detachedResponse = client.get("/api/datasources/${detached.id}/table-detail") {
            parameter("schema", "public")
            parameter("table", "anything")
        }
        assertEquals(HttpStatusCode.BadGateway, detachedResponse.status)
    }

    private suspend fun ApplicationTestBuilder.assertRouteContract(fixture: Fixture) {
        val beforeCatalog = datasourceStore.catalog(fixture.datasource.id)
        val beforeSyncedAt = datasourceStore.get(fixture.datasource.id)?.catalogSyncedAt
        assertFalse(beforeCatalog.any { it.schema == fixture.requestSchema && it.table == fixture.middle && it.column == "live_only" })

        val response = wireTableDetailApp().tableDetail(fixture)
        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        val detail = Json.decodeFromString<TableDetail>(body)
        assertEquals(
            setOf("schema", "table", "columns", "indexes", "foreignKeys", "referencedBy", "metadata"),
            Json.parseToJsonElement(body).jsonObject.keys,
        )
        assertEquals(fixture.requestSchema, detail.schema)
        assertEquals(fixture.middle, detail.table)
        assertTrue(detail.columns.isNotEmpty())
        assertTrue(detail.indexes.isNotEmpty())
        assertTrue(detail.foreignKeys.isNotEmpty())
        assertTrue(detail.referencedBy.isNotEmpty())

        val secret = detail.columns.single { it.name == "classified_secret" }
        val live = detail.columns.single { it.name == "live_only" }
        val classification = assertNotNull(secret.classification, "persisted classification must overlay live proxy metadata")
        assertEquals(listOf("pii"), classification.tags)
        assertEquals(fixture.maskName, classification.maskFnName)
        assertEquals(null, live.classification)
        assertTrue(secret.partOfIndex)
        assertTrue(detail.indexes.single { it.name == fixture.index }.unique)
        assertEquals(fixture.outboundFk, detail.foreignKeys.single().name)
        assertEquals(fixture.inboundFk, detail.referencedBy.single().name)
        assertEquals(fixture.detail.metadata, detail.metadata)
        assertFalse(body.contains(fixture.sentinel), "table-detail must never serialize raw row values")
        assertFalse(Json.parseToJsonElement(body).jsonObject.keys.any { it in setOf("rows", "data", "preview") })

        assertEquals(beforeCatalog, datasourceStore.catalog(fixture.datasource.id))
        assertEquals(beforeSyncedAt, datasourceStore.get(fixture.datasource.id)?.catalogSyncedAt)
        metadata.connection.use { connection ->
            connection.prepareStatement(
                """SELECT count(*) FROM catalog_column
                   WHERE datasource_id=? AND schema_name=? AND table_name=? AND column_name='live_only'""",
            ).use { statement ->
                statement.setLong(1, fixture.datasource.id)
                statement.setString(2, fixture.requestSchema)
                statement.setString(3, fixture.middle)
                statement.executeQuery().use { rows ->
                    rows.next()
                    assertEquals(0L, rows.getLong(1), "live detail must not persist post-sync columns")
                }
            }
        }
    }

    private fun createFixture(name: String, engine: String, schema: String, prefix: String): Fixture {
        val parent = "${prefix}_parent"
        val middle = "${prefix}_middle"
        val child = "${prefix}_child"
        val index = "${prefix}_secret_uq"
        val outboundFk = "${prefix}_middle_parent_fk"
        val inboundFk = "${prefix}_child_middle_fk"
        val maskName = "${prefix}_mask"
        val datasource = datasourceStore.create(
            DatasourceInput(
                name = name,
                engine = engine,
                host = "proxy-owned.invalid",
                port = if (engine == "mysql") 3306 else 5432,
                dbName = schema,
            ),
        )
        datasourceStore.storePushedCatalog(
            id = datasource.id,
            defaultSchemas = listOf(schema),
            mysqlLowerCaseTableNames = if (engine == "mysql") 0 else null,
            engineVersion = if (engine == "mysql") "8.4.0" else "PostgreSQL 17.6",
            columns = listOf(
                DatasourceStore.PushedColumn(schema, middle, "id", "bigint", 1, false),
                DatasourceStore.PushedColumn(schema, middle, "classified_secret", "varchar", 2, false),
                DatasourceStore.PushedColumn(schema, middle, "amount", if (engine == "mysql") "decimal" else "numeric", 3, false),
                DatasourceStore.PushedColumn(schema, middle, "optional_note", "varchar", 4, true),
            ),
        )
        val mask = policyStore.createMaskFn(MaskFnInput(maskName, "LAST_N"))
        datasourceStore.upsertClassification(
            datasource.id,
            ClassificationInput(
                schema = schema,
                table = middle,
                column = "classified_secret",
                tags = listOf("pii"),
                maskFnId = mask.id,
            ),
        )
        val detail = TableDetail(
            schema = schema,
            table = middle,
            columns = listOf(
                TableDetailColumn("id", "bigint", 1, false, null, null, 64, 0, true, true, null, null, null, null),
                TableDetailColumn(
                    "classified_secret", "varchar", 2, false, "'pending'", 64, null, null, true, false,
                    "classified secret column", if (engine == "mysql") "utf8mb4" else null,
                    if (engine == "mysql") "utf8mb4_bin" else null, null,
                ),
                TableDetailColumn("amount", if (engine == "mysql") "decimal" else "numeric", 3, false, "1.250", null, 12, 3, true, false, null, null, null, null),
                TableDetailColumn("optional_note", "varchar", 4, true, null, 40, null, null, false, false, null, null, null, null),
                TableDetailColumn("live_only", "varchar", 5, false, "'live-default'", 18, null, null, false, false, "post-sync column", null, null, null),
            ),
            indexes = listOf(
                TableIndex(index, listOf(TableIndexColumn("classified_secret", 1, "DESC"), TableIndexColumn("amount", 2, "ASC")), true, if (engine == "mysql") "BTREE" else "btree"),
            ),
            foreignKeys = listOf(
                TableRelation(outboundFk, schema, middle, listOf("parent_id"), schema, parent, listOf("id"), "NO ACTION", "NO ACTION"),
            ),
            referencedBy = listOf(
                TableRelation(inboundFk, schema, child, listOf("middle_id"), schema, middle, listOf("id"), "NO ACTION", "NO ACTION"),
            ),
            metadata = TableMetadata(
                if (engine == "mysql") "InnoDB" else "PostgreSQL",
                1,
                if (engine == "mysql") "Dynamic" else null,
                16_384,
                if (engine == "mysql") "utf8mb4_0900_ai_ci" else null,
                "$engine middle table",
            ),
        )
        return Fixture(
            datasource, prefix, schema, parent, middle, child, index, outboundFk, inboundFk,
            "SENTINEL_SECRET_DO_NOT_SERIALIZE", maskName, detail,
        )
    }

    /** The routes plus a client already signed in as [caller] — the detail route needs an authenticated one. */
    private suspend fun ApplicationTestBuilder.wireTableDetailApp(): HttpClient {
        application { installTableDetailTestApp() }
        val client = createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$caller").status)
        return client
    }

    private fun Application.installTableDetailTestApp() {
        val sessionStore = PrincipalSessionStore(metadata, null)
        attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(Sessions) { webSessionCookie(sessionStore, config.sessionSecret) }
        routing {
            testLoginRoute(sessionStore, config)
            datasourceRoutes(config, authz, core.roleResolver, datasourceStore, core.proxyEventsHub, TableDetailService(core), core.tokenStore, core.userGroupStore)
        }
    }

    private suspend fun HttpClient.tableDetail(fixture: Fixture): HttpResponse =
        get("/api/datasources/${fixture.datasource.id}/table-detail") {
            parameter("schema", fixture.requestSchema)
            parameter("table", fixture.middle)
        }

    private data class Fixture(
        val datasource: Datasource,
        val prefix: String,
        val requestSchema: String,
        val parent: String,
        val middle: String,
        val child: String,
        val index: String,
        val outboundFk: String,
        val inboundFk: String,
        val sentinel: String,
        val maskName: String,
        val detail: TableDetail,
    )

    private sealed interface ProxyReply {
        data class Detail(val value: TableDetail) : ProxyReply
        data object NotFound : ProxyReply
        data class Error(val message: String) : ProxyReply
    }

    private class FakeTableDetailProxy(
        private val core: ControlPlaneCore,
        val datasourceName: String,
        private val responder: (schema: String, table: String) -> ProxyReply,
    ) : AutoCloseable {
        val requests = CopyOnWriteArrayList<Pair<String, String>>()
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        private val events = Channel<ControlEvent>(Channel.UNLIMITED)

        init {
            core.proxyEventsHub.register(datasourceName, events)
            scope.launch {
                for (event in events) {
                    if (!event.hasOpenTableDetailChannel()) continue
                    val open = event.openTableDetailChannel
                    requests += open.schema to open.table
                    val outbound = Channel<com.ridi.oss.proxymonster.grpc.ControlTableDetailMsg>(Channel.BUFFERED)
                    val attached = core.tableDetailChannels.attach(open.sessionId, outbound) ?: continue
                    attached.inbound.send(responseMessage(responder(open.schema, open.table)))
                    // The service always closes a claimed stream, including result/error/not-found paths.
                    outbound.receive()
                    attached.inbound.close()
                    outbound.close()
                }
            }
        }

        private fun responseMessage(reply: ProxyReply): ProxyTableDetailMsg = proxyTableDetailMsg {
            when (reply) {
                is ProxyReply.Detail -> result = tableDetailResult { json = Json.encodeToString(reply.value) }
                ProxyReply.NotFound -> result = tableDetailResult { json = "null" }
                is ProxyReply.Error -> error = tableDetailError { message = reply.message }
            }
        }

        override fun close() {
            core.proxyEventsHub.deregister(datasourceName, events)
            events.close()
            scope.cancel()
        }
    }
}
