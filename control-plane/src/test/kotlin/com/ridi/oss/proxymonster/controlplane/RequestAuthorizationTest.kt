package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.google.protobuf.UnknownFieldSet
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.RequestAuthorization
import com.ridi.oss.proxymonster.grpc.namespaceRef
import com.ridi.oss.proxymonster.grpc.readCatalog
import com.ridi.oss.proxymonster.grpc.readTableMetadata
import com.ridi.oss.proxymonster.grpc.tableRef
import java.lang.reflect.Proxy
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RequestAuthorizationTest {
    private val datasource = Datasource(1, "reports", Engine.MYSQL, "", 0, "app", tags = listOf("production"))
    private val allow = authz("""permit(principal, action == Action::"datasource.connect", resource);""")

    @Test
    fun `MySQL and PostgreSQL metadata use the same datasource connect gate as HTTP`() {
        for (ds in listOf(datasource, datasource.copy(engine = Engine.POSTGRES))) {
            val requests = listOf(catalogRequest(ds), tableRequest(ds))
            for (request in requests) {
                assertTrue(authorize(request, allow, ds))
                assertFalse(authorize(request, authz(), ds))
            }
        }
    }

    @Test
    fun `metadata gate preserves datasource name tags role and requester IP restrictions`() {
        val gate = authz(
            """permit(principal in Role::"reader", action == Action::"datasource.connect", resource in Tag::"production")
                when { resource has name && resource.name == "reports" && context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };""",
        )
        val request = catalogRequest(datasource)
        val trusted = AuthzContext(requesterIp = "10.2.3.4")
        assertTrue(authorize(request, gate, context = trusted))
        assertFalse(authorize(request, gate, roles = emptySet(), context = trusted))
        assertFalse(authorize(request, gate, ds = datasource.copy(tags = emptyList()), context = trusted))
        assertFalse(authorize(request, gate, context = AuthzContext(requesterIp = "198.51.100.7")))
        assertFalse(authorize(request, gate))
    }

    @Test
    fun `HTTP metadata retains absent channel while wire requests carry their channel`() {
        val gate = authz(
            """permit(principal, action == Action::"datasource.connect", resource)
                when { context has channel && context.channel == "wire" };""",
        )
        assertFalse(authorizeMetadata(gate, "alice", setOf("reader"), datasource, AuthzContext()))
        assertTrue(authorize(catalogRequest(datasource), gate, context = AuthzContext(channel = "wire")))
        assertFalse(authorize(catalogRequest(datasource), gate, context = AuthzContext(channel = "editor")))
    }

    @Test
    fun `metadata derives context tags and ignores supplied tags and statement kind`() {
        val gate = authz(
            """permit(principal, action == Action::"context.tag::trusted-network", resource)
                when { context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };""",
            """permit(principal, action == Action::"datasource.connect", resource)
                when { context has tags && context.tags.contains("trusted-network") && !(context has stmt_kind) };""",
        )
        assertTrue(authorize(catalogRequest(datasource), gate, context = AuthzContext(requesterIp = "10.2.3.4", stmtKind = "select")))
        assertFalse(authorize(catalogRequest(datasource), gate, context = AuthzContext(tags = setOf("trusted-network"))))
    }

    @Test
    fun `unknown and missing operations deny even with a broad connect permit`() {
        assertFalse(authorize(RequestAuthorization.newBuilder().setDatasourceName(datasource.name).build(), allow))
        val unknown = RequestAuthorization.newBuilder().setDatasourceName(datasource.name).setUnknownFields(
            UnknownFieldSet.newBuilder().addField(99, UnknownFieldSet.Field.newBuilder().addLengthDelimited(ByteString.EMPTY).build()).build(),
        ).build()
        assertFalse(authorize(RequestAuthorization.parseFrom(unknown.toByteArray()), allow))
    }

    @Test
    fun `catalog and table selectors must be present nonblank and bound to the datasource`() {
        val catalogRequest = catalogRequest(datasource)
        val tableRequest = tableRequest(datasource)
        val invalid = listOf(
            catalogRequest.toBuilder().clearReadCatalog().build(),
            catalogRequest.toBuilder().setReadCatalog(readCatalog {}).build(),
            catalogRequest.toBuilder().setReadCatalog(readCatalog { namespace = namespaceRef { catalog = "def" } }).build(),
            catalogRequest.toBuilder().setReadCatalog(readCatalog { namespace = namespaceRef { schema = "app" } }).build(),
            catalogRequest.toBuilder().setReadCatalog(readCatalog { namespace = namespaceRef { catalog = "def"; schema = " " } }).build(),
            catalogRequest.toBuilder().setReadCatalog(readCatalog { namespace = namespaceRef { catalog = "other"; schema = "app" } }).build(),
            tableRequest.toBuilder().clearReadTableMetadata().build(),
            tableRequest.toBuilder().setReadTableMetadata(readTableMetadata {}).build(),
            tableRequest.toBuilder().setReadTableMetadata(readTableMetadata { table = tableRef { catalog = "def"; schema = "app" } }).build(),
            tableRequest.toBuilder().setReadTableMetadata(readTableMetadata { table = tableRef { catalog = "def"; table = "users" } }).build(),
            tableRequest.toBuilder().setReadTableMetadata(readTableMetadata { table = tableRef { schema = "app"; table = "users" } }).build(),
            tableRequest.toBuilder().setReadTableMetadata(readTableMetadata { table = tableRef { catalog = "def"; schema = "app"; table = " " } }).build(),
            tableRequest.toBuilder().setReadTableMetadata(readTableMetadata { table = tableRef { catalog = "other"; schema = "app"; table = "users" } }).build(),
            catalogRequest.toBuilder().setDatasourceName("other").build(),
            tableRequest.toBuilder().clearDatasourceName().build(),
        )
        invalid.forEach { assertFalse(authorize(it, allow), it.toString()) }
    }

    @Test
    fun `PostgreSQL selectors cannot cross databases`() {
        val ds = datasource.copy(engine = Engine.POSTGRES)
        val catalogOperation = catalogRequest(ds).toBuilder().setReadCatalog(
            readCatalog { namespace = namespaceRef { catalog = "other"; schema = "public" } },
        ).build()
        val tableOperation = tableRequest(ds).toBuilder().setReadTableMetadata(
            readTableMetadata { table = tableRef { catalog = "other"; schema = "public"; table = "users" } },
        ).build()
        assertFalse(authorize(catalogOperation, allow, ds))
        assertFalse(authorize(tableOperation, allow, ds))
    }

    private fun authorize(
        request: RequestAuthorization,
        authz: Authz,
        ds: Datasource = datasource,
        roles: Set<String> = setOf("reader"),
        context: AuthzContext = AuthzContext(),
    ) = ds.engine.definition.requestAuthorizer.authorize(request, ds, "alice", roles, context, authz)

    private fun catalogRequest(ds: Datasource): RequestAuthorization = RequestAuthorization.newBuilder()
        .setDatasourceName(ds.name)
        .setReadCatalog(readCatalog { namespace = namespaceRef { catalog = ds.effectiveCatalog; schema = "app" } })
        .build()

    private fun tableRequest(ds: Datasource): RequestAuthorization = RequestAuthorization.newBuilder()
        .setDatasourceName(ds.name)
        .setReadTableMetadata(readTableMetadata { table = tableRef { catalog = ds.effectiveCatalog; schema = "app"; table = "users" } })
        .build()

    private fun authz(vararg policies: String): Authz = Authz(
        CedarEngine(policies.mapIndexed { index, source -> index.toLong() + 1 to source }),
        CedarPolicyStore(
            Proxy.newProxyInstance(DataSource::class.java.classLoader, arrayOf(DataSource::class.java)) { _, _, _ ->
                error("metadata authorization must not access the store")
            } as DataSource,
        ),
        RoleSource { emptySet() },
    )
}
