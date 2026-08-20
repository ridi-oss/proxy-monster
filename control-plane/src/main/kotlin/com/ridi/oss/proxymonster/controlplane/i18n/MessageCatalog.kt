package com.ridi.oss.proxymonster.controlplane.i18n

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * The control plane's server-side message catalog (docs/l10n.md).
 *
 * Everywhere the console can translate for us, the server returns a stable error CODE. A message the server
 * itself renders — a Slack DM today, an email next — has no browser to do that, so it is localized here. One
 * catalog per domain, loaded from `resources/messages/<locale>/<domain>.json` and keyed by dot path.
 * Interpolation is plain `{name}` substitution; no ICU, because nothing here needs plurals or gender.
 */
class MessageCatalog(
    private val domain: String,
    private val defaultLocale: String = FALLBACK,
    private val catalogs: Map<String, JsonObject> = load(domain),
) {
    /** [key] in [locale], falling back to the default locale, then English, then the key itself. */
    fun text(key: String, locale: String, params: Map<String, String> = emptyMap()): String {
        val raw = lookup(locale, key) ?: lookup(defaultLocale, key) ?: lookup(FALLBACK, key) ?: return key
        // Single pass over the TEMPLATE: each {placeholder} is resolved from params, and a substituted value is
        // never re-scanned. A sequential replace would let one field's value smuggle another field's
        // placeholder — a requester's free-text reason containing "{statementNote}" would expand to that field
        // (second-order injection into a message rendered beside the real Approve button). An unknown
        // placeholder is left as written.
        return PLACEHOLDER.replace(raw) { m -> params[m.groupValues[1]] ?: m.value }
    }

    private fun lookup(locale: String, key: String): String? {
        var node = catalogs[locale] ?: return null
        val parts = key.split('.')
        for ((i, part) in parts.withIndex()) {
            val child = node[part] ?: return null
            if (i == parts.lastIndex) return (child as? JsonPrimitive)?.let { runCatching { it.content }.getOrNull() }
            node = runCatching { child.jsonObject }.getOrNull() ?: return null
        }
        return null
    }

    companion object {
        const val FALLBACK = "en"

        /** One `{placeholder}` token. `[^{}]+` never spans a brace, so a substituted value is not a new token. */
        private val PLACEHOLDER = Regex("""\{([^{}]+)\}""")

        /** The locales every domain must provide a file for — the l10n invariant is enforced by [load]. */
        val LOCALES = listOf("en", "ko")

        private fun load(domain: String): Map<String, JsonObject> = LOCALES.associateWith { locale ->
            val path = "/messages/$locale/$domain.json"
            val text = MessageCatalog::class.java.getResourceAsStream(path)?.bufferedReader()?.use { it.readText() }
                ?: error("i18n: $path is missing from the classpath")
            Json.parseToJsonElement(text).jsonObject
        }
    }
}
