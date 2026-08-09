package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.grpc.columnMask
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BindMasksTest {
    @Test fun `ordinal binds`() {
        val binding = bindMasks(listOf(columnMask { column = "ssn"; kind = "FIXED"; ordinal = 1 }), 2)
        assertEquals(mapOf(1 to "FIXED"), binding.byIndex)
        assertTrue(binding.allBound)
    }

    @Test fun `name is ignored`() {
        val binding = bindMasks(listOf(columnMask { column = "EXPR\$0"; kind = "LAST_N"; ordinal = 0 }), 1)
        assertEquals(mapOf(0 to "LAST_N"), binding.byIndex)
        assertTrue(binding.allBound)
    }

    @Test fun `out of range ordinal is unbound`() {
        val binding = bindMasks(listOf(columnMask { column = "ssn"; kind = "FIXED"; ordinal = 5 }), 2)
        assertEquals(emptyMap(), binding.byIndex)
        assertFalse(binding.allBound)
        assertEquals(listOf(columnMask { column = "ssn"; kind = "FIXED"; ordinal = 5 }), binding.unbound)
    }

    @Test fun `absent ordinal is unbound - never binds to result column 0`() {
        // No ordinal set: proto explicit-presence hasOrdinal() is false. It must NOT fall through to
        // column 0 (that would mask the wrong column and leak the intended one); it is reported unbound.
        val mask = columnMask { column = "ssn"; kind = "FIXED" }
        val binding = bindMasks(listOf(mask), 2)
        assertEquals(emptyMap(), binding.byIndex)
        assertFalse(binding.allBound)
        assertEquals(listOf(mask), binding.unbound)
    }

    @Test fun `multiple ordinals bind`() {
        val binding = bindMasks(
            listOf(
                columnMask { column = "ssn"; kind = "FIXED"; ordinal = 0 },
                columnMask { column = "email"; kind = "LAST_N"; ordinal = 2 },
            ),
            3,
        )
        assertEquals(mapOf(0 to "FIXED", 2 to "LAST_N"), binding.byIndex)
        assertTrue(binding.allBound)
    }
}
