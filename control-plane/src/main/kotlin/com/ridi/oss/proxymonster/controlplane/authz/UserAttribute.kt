package com.ridi.oss.proxymonster.controlplane.authz

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * An id_token claim copied onto the Cedar `User` entity as an optional attribute of the same name
 * (`PM_OIDC_USER_ATTRIBUTES=manager:User,department:String`). A `User` attribute holds a principal name, so
 * `resource.requester.manager == principal` compares entities.
 */
data class UserAttribute(val name: String, val type: Type) {
    enum class Type(val cedar: String) {
        STRING("String"), LONG("Long"), BOOL("Bool"), STRING_SET("Set<String>"), USER("User"),
    }

    /** [claim] as stored JSON, or null when it is absent or not of [type]. */
    fun fromClaim(claim: Any?): JsonElement? = when (type) {
        Type.STRING, Type.USER -> (claim as? String)?.takeIf { it.isNotBlank() }?.let(::JsonPrimitive)
        Type.LONG -> (claim as? Number)?.takeIf { it is Long || it is Int }?.let { JsonPrimitive(it.toLong()) }
        Type.BOOL -> (claim as? Boolean)?.let(::JsonPrimitive)
        Type.STRING_SET -> (claim as? List<*>)?.takeIf { list -> list.all { it is String } }
            ?.let { list -> JsonArray(list.map { JsonPrimitive(it as String) }) }
    }

    companion object {
        private val NAME = Regex("[A-Za-z_][A-Za-z0-9_]*")

        /** `name:Type,…`; a malformed entry fails boot rather than silently dropping an attribute a policy reads. */
        fun parseList(env: String?): List<UserAttribute> {
            val attributes = env.orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }.map { entry ->
                val name = entry.substringBefore(':').trim()
                val typeName = entry.substringAfter(':', "").trim()
                val type = Type.entries.firstOrNull { it.cedar == typeName }
                require(NAME.matches(name) && type != null) {
                    "PM_OIDC_USER_ATTRIBUTES entry must be <name>:<${Type.entries.joinToString("|") { it.cedar }}>, got '$entry'"
                }
                UserAttribute(name, type)
            }
            val duplicates = attributes.groupBy { it.name }.filterValues { it.size > 1 }.keys
            require(duplicates.isEmpty()) { "PM_OIDC_USER_ATTRIBUTES declares ${duplicates.joinToString()} twice" }
            return attributes
        }
    }
}

/** The declared attributes [claims] carries, as the JSON object stored on `app_user.attributes`. */
fun List<UserAttribute>.fromClaims(claims: Map<String, Any?>): JsonObject =
    JsonObject(mapNotNull { a -> a.fromClaim(claims[a.name])?.let { a.name to it } }.toMap())
