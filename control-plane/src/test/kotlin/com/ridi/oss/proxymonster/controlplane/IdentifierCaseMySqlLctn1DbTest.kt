package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.MCP_TEST_JSON
import com.ridi.oss.proxymonster.controlplane.support.NAME_ADMIN
import com.ridi.oss.proxymonster.controlplane.support.NAME_READER
import com.ridi.oss.proxymonster.controlplane.support.NAME_SENTINEL
import com.ridi.oss.proxymonster.controlplane.support.NameCaseStack
import com.ridi.oss.proxymonster.controlplane.support.NameCaseTarget
import com.ridi.oss.proxymonster.controlplane.support.SharedMySqlLowerCaseTableNames1
import com.ridi.oss.proxymonster.controlplane.support.decideAndAudit
import com.ridi.oss.proxymonster.controlplane.support.errorCode
import com.ridi.oss.proxymonster.controlplane.support.installControlPlane
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.ok
import com.ridi.oss.proxymonster.controlplane.support.okResult
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ControlEvent
import com.ridi.oss.proxymonster.grpc.ControlTableDetailMsg
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.proxyTableDetailMsg
import com.ridi.oss.proxymonster.grpc.tableDetailResult
import com.ridi.oss.proxymonster.probe.TableDetail
import com.ridi.oss.proxymonster.probe.TableDetailColumn
import com.ridi.oss.proxymonster.probe.TableMetadata
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel as KChannel
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.sql.DriverManager
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** MySQL with lower_case_table_names=1: table names fold to lowercase, column names always do. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IdentifierCaseMySqlLctn1DbTest {
    private lateinit var stack: NameCaseStack

    private val reads = listOf(
        "SELECT email FROM Users",
        "SELECT EMAIL FROM USERS",
        "SELECT `Email` FROM `Users`",
    )

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        stack = NameCaseStack.create()
    }

    private fun target(): NameCaseTarget = stack.mysql(SharedMySqlLowerCaseTableNames1) { st ->
        st.execute("CREATE TABLE `Users` (id BIGINT PRIMARY KEY, `Email` VARCHAR(64), `SSN` VARCHAR(32))")
        st.execute("INSERT INTO `Users` VALUES (1, '$NAME_SENTINEL', '900-00-0001')")
    }.also { t ->
        val lctn = DriverManager.getConnection(t.jdbcUrl, t.user, t.password).use { c ->
            c.createStatement().use { it.executeQuery("SELECT @@lower_case_table_names").use { rs -> rs.next(); rs.getInt(1) } }
        }
        assertEquals(1, lctn, "this suite must run against lower_case_table_names=1")
        assertEquals(1, t.datasource.mysqlLowerCaseTableNames)
    }

    private fun classifyOverHttp(table: String, column: String) = testApplication {
        val client = installControlPlane(mcpTestConfig(), stack.core)
        val t = target()
        client.login(NAME_ADMIN)
        assertEquals(HttpStatusCode.OK, t.httpClassify(client, t.schema, table, column).status)
        reads.forEach(t::assertMasked)
        assertListed(t, t.listedTags(client, stack.adminToken()))
    }

    private fun classifyOverMcp(table: String, column: String) = testApplication {
        val client = installControlPlane(mcpTestConfig(), stack.core)
        val t = target()
        val token = stack.adminToken()
        t.mcpClassify(client, token, t.schema, table, column).ok()
        reads.forEach(t::assertMasked)
        assertListed(t, t.listedTags(client, token))
    }

    private fun assertListed(t: NameCaseTarget, tags: List<JsonObject>) {
        assertTrue(
            tags.any {
                it.str("schema") == t.schema && it.str("table") == "users" && it.str("column") == "email" &&
                    it.getValue("tags").jsonArray.any { tag -> tag.jsonPrimitive.content == "pii" }
            },
            "list_column_tags does not show the tagged column: $tags",
        )
    }

    @Test
    @Disabled("pending-name-fix: classification input Users.Email is stored as typed and never attaches to users.email")
    fun `HTTP classification Users_Email masks every legal spelling`() = classifyOverHttp("Users", "Email")

    @Test
    fun `HTTP classification users_email masks every legal spelling`() = classifyOverHttp("users", "email")

    @Test
    @Disabled("pending-name-fix: classification input USERS.EMAIL is stored as typed and never attaches to users.email")
    fun `HTTP classification USERS_EMAIL masks every legal spelling`() = classifyOverHttp("USERS", "EMAIL")

    @Test
    @Disabled("pending-name-fix: classification input Users.Email is stored as typed and never attaches to users.email")
    fun `MCP classification Users_Email masks every legal spelling`() = classifyOverMcp("Users", "Email")

    @Test
    fun `MCP classification users_email masks every legal spelling`() = classifyOverMcp("users", "email")

    @Test
    @Disabled("pending-name-fix: classification input USERS.EMAIL is stored as typed and never attaches to users.email")
    fun `MCP classification USERS_EMAIL masks every legal spelling`() = classifyOverMcp("USERS", "EMAIL")

    @Test
    @Disabled("pending-name-fix: batch dedup compares typed spellings, so Users.SSN and users.ssn both pass")
    fun `a batch naming one column in two spellings is refused as a duplicate`() = testApplication {
        val client = installControlPlane(mcpTestConfig(), stack.core)
        val t = target()
        val result = client.mcpCall(
            stack.adminToken(),
            "set_column_classifications",
            buildJsonObject {
                put("datasource", t.datasource.name)
                put(
                    "columns",
                    buildJsonArray {
                        add(t.classificationArgs(t.schema, "Users", "SSN"))
                        add(t.classificationArgs(t.schema, "users", "ssn"))
                    },
                )
            },
        )
        assertEquals("datasource.duplicate_column", result.errorCode())
    }

    @Test
    fun `a Cedar forbid on the canonical Column denies every legal spelling`() {
        val t = target()
        stack.policy(
            "${t.datasource.name}-forbid-email",
            """forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource == Column::"${t.datasource.name}/${t.catalog}/${t.schema}/users/email");""",
        )
        reads.forEach(t::assertDenied)
        assertEquals(EnfAction.ALLOW, t.run("SELECT ID FROM USERS").decision)
    }

    @Test
    fun `a Cedar forbid on the canonical Table denies every legal spelling`() {
        val t = target()
        assertEquals(EnfAction.ALLOW, t.run("SELECT id FROM USERS").decision)
        stack.policy(
            "${t.datasource.name}-forbid-users",
            """forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource in Table::"${t.datasource.name}/${t.catalog}/${t.schema}/users");""",
        )
        (reads + "SELECT id FROM USERS" + "SELECT `ID` FROM `Users`").forEach(t::assertDenied)
    }

    @Test
    @Disabled("pending-name-fix: table detail compares the requested Users to the proxy's users and refuses")
    fun `table detail by a differently cased name returns the canonical table with its tags`() = testApplication {
        val client = installControlPlane(mcpTestConfig(), stack.core)
        val t = target()
        stack.core.datasourceStore.upsertClassification(
            t.datasource.id, ClassificationInput(t.schema, "users", "email", listOf("pii"), stack.maskFn.id, t.catalog),
        )
        answerTableDetail(t, tableDetail(t.catalog, t.schema, "users", listOf("id", "email", "ssn"))).use {
            val detail = client.mcpCall(
                stack.adminToken(),
                "get_table_detail",
                buildJsonObject {
                    put("datasource", t.datasource.name)
                    put("catalog", t.catalog)
                    put("schema", t.schema)
                    put("table", "Users")
                },
            ).okResult().jsonObject
            assertEquals("users", detail.str("table"))
            val email = detail.getValue("columns").jsonArray.map { it.jsonObject }.single { it.str("name") == "email" }
            assertTrue(
                email.getValue("classification").jsonObject.getValue("tags").jsonArray.any { it.jsonPrimitive.content == "pii" },
                "email lost its tags: $email",
            )
        }
    }

    @Test
    fun `the audit records the tagged column in canonical spelling`() {
        val t = target()
        stack.core.datasourceStore.upsertClassification(
            t.datasource.id, ClassificationInput(t.schema, "users", "email", listOf("pii"), stack.maskFn.id, t.catalog),
        )
        assertAuditCanonical(t)
    }

    @Test
    @Disabled("pending-name-fix: classification input Users.Email never attaches, so nothing is recorded as tagged")
    fun `the audit records a column tagged as Users_Email in canonical spelling`() {
        val t = target()
        stack.core.datasourceStore.upsertClassification(
            t.datasource.id, ClassificationInput(t.schema, "Users", "Email", listOf("pii"), stack.maskFn.id, t.catalog),
        )
        assertAuditCanonical(t)
    }

    private fun assertAuditCanonical(t: NameCaseTarget) {
        val sql = "SELECT EMAIL FROM USERS /* audit-${t.datasource.name} */"
        val (ctx, _) = decideAndAudit(stack.core, NAME_READER, t.datasource, sql, null, clientAddr = null)
        assertEquals(EnfAction.MASK, ctx.action, "reason=${ctx.denyReason}")
        val event = stack.core.auditStore.recent(200).single { it.statement == sql }
        assertEquals(listOf("${t.catalog}.${t.schema}.users.email"), event.piiTouched)
    }

    @Test
    fun `a case variant never releases a masked column's diagnostics`() {
        val t = target()
        stack.core.datasourceStore.upsertClassification(
            t.datasource.id, ClassificationInput(t.schema, "users", "email", listOf("pii"), stack.maskFn.id, t.catalog),
        )
        for (sql in listOf(
            "SELECT id FROM users WHERE CAST(email AS SIGNED) = 1",
            "SELECT ID FROM USERS WHERE CAST(EMAIL AS SIGNED) = 1",
            "SELECT `Id` FROM `Users` WHERE CAST(`Email` AS SIGNED) = 1",
        )) {
            val ctx = t.decide(sql)
            assertTrue(ctx.action != EnfAction.ALLOW || ctx.sanitizeDiagnostics, "$sql would relay raw diagnostics: ${ctx.action}")
        }
    }

    @Test
    fun `a stored editor task in another spelling re-decides masked`() {
        val t = target()
        stack.core.datasourceStore.upsertClassification(
            t.datasource.id, ClassificationInput(t.schema, "users", "email", listOf("pii"), stack.maskFn.id, t.catalog),
        )
        assertStoredTaskMasked(t)
    }

    @Test
    @Disabled("pending-name-fix: classification input Users.Email never attaches, so the stored task re-decides unmasked")
    fun `a stored editor task re-decides masked when tagged as Users_Email`() {
        val t = target()
        stack.core.datasourceStore.upsertClassification(
            t.datasource.id, ClassificationInput(t.schema, "Users", "Email", listOf("pii"), stack.maskFn.id, t.catalog),
        )
        assertStoredTaskMasked(t)
    }

    private fun assertStoredTaskMasked(t: NameCaseTarget) {
        val task = stack.core.accessStore.createEditorTask(
            NAME_READER, t.datasource.id, listOf("SELECT `EMAIL` FROM `USERS`"), listOf("name-reader"), approver = NAME_ADMIN,
        )
        val ctx = t.decide(checkNotNull(task.sql), channel = Channel.WORKFLOW_EXECUTOR, providedRoles = task.executeAs.toSet())
        assertEquals(EnfAction.MASK, ctx.action, "reason=${ctx.denyReason}")
    }

    private fun JsonObject.str(name: String): String? = (this[name] as? JsonPrimitive)?.content

    private fun tableDetail(catalog: String, schema: String, table: String, columns: List<String>) = TableDetail(
        catalog = catalog,
        schema = schema,
        table = table,
        columns = columns.mapIndexed { index, name ->
            TableDetailColumn(name, "varchar", index + 1, true, null, null, null, null, false, false, null, null, null, null)
        },
        indexes = emptyList(),
        foreignKeys = emptyList(),
        referencedBy = emptyList(),
        metadata = TableMetadata("MySQL", 0, null, null, null, null),
    )

    private fun answerTableDetail(t: NameCaseTarget, detail: TableDetail): AutoCloseable {
        val core = stack.core
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val events = KChannel<ControlEvent>(KChannel.UNLIMITED)
        core.proxyEventsHub.register(t.datasource.name, events)
        scope.launch {
            for (event in events) {
                if (!event.hasOpenTableDetailChannel()) continue
                val outbound = KChannel<ControlTableDetailMsg>(KChannel.BUFFERED)
                val attached = core.tableDetailChannels.attach(event.openTableDetailChannel.sessionId, outbound) ?: continue
                attached.inbound.send(proxyTableDetailMsg { result = tableDetailResult { json = MCP_TEST_JSON.encodeToString(detail) } })
                outbound.receive()
                attached.inbound.close()
                outbound.close()
            }
        }
        return AutoCloseable {
            core.proxyEventsHub.deregister(t.datasource.name, events)
            events.close()
            scope.cancel()
        }
    }
}
