package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.NAME_ADMIN
import com.ridi.oss.proxymonster.controlplane.support.NAME_SENTINEL
import com.ridi.oss.proxymonster.controlplane.support.NameCaseStack
import com.ridi.oss.proxymonster.controlplane.support.NameCaseTarget
import com.ridi.oss.proxymonster.controlplane.support.SharedMySql
import com.ridi.oss.proxymonster.controlplane.support.installControlPlane
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.okResult
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

private const val LOWER_SENTINEL = "lowercase.table@example.com"

/** MySQL with lower_case_table_names=0: `Users` and `users` are two tables; column names still fold. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IdentifierCaseMySqlLctn0DbTest {
    private lateinit var stack: NameCaseStack

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        stack = NameCaseStack.create()
    }

    private fun target(): NameCaseTarget = stack.mysql(SharedMySql) { st ->
        st.execute("CREATE TABLE `Users` (id BIGINT PRIMARY KEY, `Email` VARCHAR(64))")
        st.execute("INSERT INTO `Users` VALUES (1, '$NAME_SENTINEL')")
        st.execute("CREATE TABLE `users` (id BIGINT PRIMARY KEY, `email` VARCHAR(64))")
        st.execute("INSERT INTO `users` VALUES (1, '$LOWER_SENTINEL')")
    }.also { assertEquals(0, it.datasource.mysqlLowerCaseTableNames, "this suite must run against lower_case_table_names=0") }

    private fun classifyUsersOnly(column: String) = testApplication {
        val client = installControlPlane(mcpTestConfig(), stack.core)
        val t = target()
        client.login(NAME_ADMIN)
        assertEquals(HttpStatusCode.OK, t.httpClassify(client, t.schema, "Users", column).status)
        t.assertMasked("SELECT email FROM Users")
        t.assertMasked("SELECT `EMAIL` FROM `Users`")
        t.assertCleartext("SELECT email FROM users", LOWER_SENTINEL)
        t.assertCleartext("SELECT EMAIL FROM `users`", LOWER_SENTINEL)
    }

    @Test
    @Disabled("pending-name-fix: classification column Email is stored as typed and never attaches to Users.email")
    fun `classifying Users_Email masks only the Users table`() = classifyUsersOnly("Email")

    @Test
    fun `classifying Users_email masks only the Users table`() = classifyUsersOnly("email")

    @Test
    fun `classifying a table that does not exist is refused or visibly not attached`() = testApplication {
        val client = installControlPlane(mcpTestConfig(), stack.core)
        val t = target()
        val token = stack.adminToken()
        val result = t.mcpClassify(client, token, t.schema, "USERS", "email")
        if (result["isError"]?.jsonPrimitive?.content != "true") {
            val listed = t.listedTags(client, token)
            assertTrue(listed.none { it.str("table").equals("users", ignoreCase = true) }, "a classification of USERS shows as attached: $listed")
        }
        t.assertCleartext("SELECT email FROM Users")
        t.assertCleartext("SELECT email FROM users", LOWER_SENTINEL)
    }

    @Test
    @Disabled("pending-name-fix: the control plane treats SYS and MySQL as system schemas regardless of lower_case_table_names")
    fun `SYS and MySQL are ordinary databases under lower_case_table_names 0`() = testApplication {
        for (db in listOf("SYS", "MySQL")) {
            SharedMySql.executeAdmin("CREATE DATABASE IF NOT EXISTS `$db`")
            SharedMySql.executeAdmin("CREATE TABLE IF NOT EXISTS `$db`.`notes` (id BIGINT PRIMARY KEY)")
            SharedMySql.executeAdmin("GRANT SELECT ON `$db`.* TO '${SharedMySql.username()}'@'%'")
        }
        val client = installControlPlane(mcpTestConfig(), stack.core)
        val t = target()
        val columns = client.mcpCall(stack.adminToken(), "browse_catalog", buildJsonObject { put("datasource", t.datasource.name) })
            .okResult().jsonArray.map { it.jsonObject }
        for (db in listOf("SYS", "MySQL")) {
            val rows = columns.filter { it.str("schema") == db }
            assertTrue(rows.isNotEmpty(), "the catalog push missed the user database $db")
            assertTrue(rows.none { it["system"]?.jsonPrimitive?.boolean == true }, "$db is flagged as a system schema: $rows")
        }
    }

    private fun JsonObject.str(name: String): String? = (this[name] as? JsonPrimitive)?.content
}
