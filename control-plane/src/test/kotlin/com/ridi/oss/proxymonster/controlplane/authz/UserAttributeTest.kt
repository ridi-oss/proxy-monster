package com.ridi.oss.proxymonster.controlplane.authz

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.AfterEach
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class UserAttributeTest {
    private val managerPolicy = """permit(principal, action == Action::"task.approve", resource is Request)
        when { resource.requester has manager && resource.requester.manager == principal };"""

    @AfterEach
    fun reset() = CedarSchema.declareUserAttributes(emptyList())

    @Test
    fun `parses name-type pairs`() {
        assertEquals(
            listOf(
                UserAttribute("manager", UserAttribute.Type.USER),
                UserAttribute("department", UserAttribute.Type.STRING),
                UserAttribute("teams", UserAttribute.Type.STRING_SET),
                UserAttribute("level", UserAttribute.Type.LONG),
                UserAttribute("contractor", UserAttribute.Type.BOOL),
            ),
            UserAttribute.parseList("manager:User, department:String,teams:Set<String>,level:Long,contractor:Bool"),
        )
        assertEquals(emptyList(), UserAttribute.parseList(null))
        assertEquals(emptyList(), UserAttribute.parseList(""))
    }

    @Test
    fun `rejects a malformed or duplicate declaration`() {
        listOf("manager", "manager:Email", "1x:String", "a-b:String", "manager:User,manager:String").forEach {
            assertFailsWith<IllegalArgumentException>(it) { UserAttribute.parseList(it) }
        }
    }

    @Test
    fun `keeps only claims of the declared type`() {
        val declared = UserAttribute.parseList("manager:User,department:String,teams:Set<String>,level:Long,contractor:Bool")
        val claims = mapOf(
            "manager" to "lead@example.com",
            "department" to listOf("not", "a", "string"),
            "teams" to listOf("backend", "infra"),
            "level" to 3L,
            "contractor" to "true",
            "undeclared" to "dropped",
        )
        assertEquals(
            JsonObject(
                mapOf(
                    "manager" to JsonPrimitive("lead@example.com"),
                    "teams" to JsonArray(listOf(JsonPrimitive("backend"), JsonPrimitive("infra"))),
                    "level" to JsonPrimitive(3L),
                ),
            ),
            declared.fromClaims(claims),
        )
    }

    @Test
    fun `a policy reads an attribute only once it is declared`() {
        val unguarded = """permit(principal, action == Action::"task.approve", resource) when { principal.department == "data" };"""
        assertTrue(CedarSchema.validate(unguarded).isNotEmpty())
        CedarSchema.declareUserAttributes(UserAttribute.parseList("manager:User"))
        assertEquals(emptyList(), CedarSchema.validate(managerPolicy))
        assertTrue(CedarSchema.text.contains("manager?: User"))
    }

    @Test
    fun `a declared attribute is type-checked`() {
        CedarSchema.declareUserAttributes(UserAttribute.parseList("manager:String"))
        assertTrue(CedarSchema.validate(managerPolicy).isNotEmpty())
    }

    @Test
    fun `lints a has-check on an undeclared attribute`() {
        val sources = listOf(1L to managerPolicy, 2L to """forbid(principal, action, resource) when { principal has "contractor" };""")
        assertEquals(
            listOf(
                "policy 1: `has manager` names an attribute no schema type declares, so it is always false",
                "policy 2: `has contractor` names an attribute no schema type declares, so it is always false",
            ),
            CedarSchema.undeclaredAttributeLint(sources),
        )
        CedarSchema.declareUserAttributes(UserAttribute.parseList("manager:User,contractor:Bool"))
        assertEquals(emptyList(), CedarSchema.undeclaredAttributeLint(sources))
    }

    @Test
    fun `an attribute name Cedar rejects fails at declaration`() {
        assertFailsWith<IllegalArgumentException> { CedarSchema.declareUserAttributes(UserAttribute.parseList("in:String")) }
        assertEquals(emptyList(), CedarSchema.userAttributes)
    }
}
