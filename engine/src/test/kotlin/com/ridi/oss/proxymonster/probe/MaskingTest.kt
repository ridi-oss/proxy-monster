package com.ridi.oss.proxymonster.probe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** Deterministic masking shared by the control plane and the wire proxy — must not drift. */
class MaskingTest {
    @Test fun `last_n reveals only the final four`() {
        assertEquals("*******4320", Masking.apply("987-65-4320", "LAST_N"))
    }

    @Test fun `last_n on short values masks entirely`() {
        assertEquals("***", Masking.apply("abc", "LAST_N"))
        assertEquals("****", Masking.apply("1234", "LAST_N"))
    }

    @Test fun `format_preserving keeps separators, masks alphanumerics`() {
        assertEquals("***-****-****", Masking.apply("010-1234-5678", "FORMAT_PRESERVING"))
    }

    @Test fun `fixed and null kinds`() {
        assertEquals("####", Masking.apply("anything", "FIXED"))
        assertNull(Masking.apply("anything", "NULL"))
    }

    @Test fun `null input stays null and unknown kind is fully masked`() {
        assertNull(Masking.apply(null, "LAST_N"))
        assertEquals("****", Masking.apply("secret", "WHATEVER"))
    }
}
