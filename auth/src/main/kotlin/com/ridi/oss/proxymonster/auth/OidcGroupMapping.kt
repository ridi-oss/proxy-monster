package com.ridi.oss.proxymonster.auth

data class OidcGroupMapping(val map: Map<String, String>, val prefix: String?) {
    fun resolve(idpGroups: List<String>): Set<String> = idpGroups.mapNotNullTo(LinkedHashSet()) { group ->
        map[group] ?: run {
            val raw = if (prefix != null && group.startsWith(prefix)) group.removePrefix(prefix) else group
            raw.ifBlank { null }?.takeUnless(::isReservedGroupName)
        }
    }

    companion object {
        const val RESERVED_GROUP_PREFIX = "system:"

        fun isReservedGroupName(name: String): Boolean = name.startsWith(RESERVED_GROUP_PREFIX, ignoreCase = true)

        fun parse(mapEnv: String?, prefixEnv: String?): OidcGroupMapping = OidcGroupMapping(
            map = mapEnv.orEmpty().split(',').mapNotNull { entry ->
                if ('=' !in entry) return@mapNotNull null
                val idp = entry.substringBefore('=').trim()
                val local = entry.substringAfter('=').trim()
                if (idp.isBlank() || local.isBlank()) null else idp to local
            }.toMap(),
            prefix = prefixEnv?.takeIf { it.isNotEmpty() },
        )
    }
}
