package com.ridi.oss.proxymonster.controlplane.i18n

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The server-side message catalog, against fixture domains under `test/resources/messages/<locale>/`. No DB.
 */
class MessageCatalogTest {
    private val catalog = MessageCatalog(domain = "test-catalog")

    @Test
    fun `looks up a key and interpolates named params`() {
        assertEquals("Hello Sam", catalog.text("greeting", "en", mapOf("name" to "Sam")))
        assertEquals("안녕 Sam", catalog.text("greeting", "ko", mapOf("name" to "Sam")))
    }

    @Test
    fun `resolves a nested dot path`() {
        assertEquals("deep-ko", catalog.text("nested.deep", "ko"))
    }

    @Test
    fun `falls back to the default locale for a key a locale is missing`() {
        assertEquals("english only", catalog.text("only_en", "ko"), "ko lacks the key, so it falls to en")
    }

    @Test
    fun `an unknown locale falls back to the default`() {
        assertEquals("Hello X", catalog.text("greeting", "fr", mapOf("name" to "X")))
    }

    @Test
    fun `an unknown key returns the key itself rather than throwing`() {
        assertEquals("no.such.key", catalog.text("no.such.key", "en"))
    }

    @Test
    fun `a missing domain file fails fast`() {
        val error = runCatching { MessageCatalog(domain = "does-not-exist") }.exceptionOrNull()
        assertEquals(true, error is IllegalStateException, "the l10n invariant is fail-fast, not silent")
    }
}
