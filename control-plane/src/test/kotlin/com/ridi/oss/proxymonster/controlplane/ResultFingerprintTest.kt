package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.objectRef
import com.ridi.oss.proxymonster.analyzer.pb.MaskedDisposition
import com.ridi.oss.proxymonster.analyzer.pb.RequireResultReadGrant
import com.ridi.oss.proxymonster.analyzer.pb.requireResultReadGrant
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** [fingerprintOf] bundles the grants into a ResultFingerprint; [ResultFingerprintSerializer] round-trips it. */
class ResultFingerprintTest {
    private fun column(column: String, disposition: MaskedDisposition, ordinals: List<Int>) =
        requireResultReadGrant {
            this.column = objectRef {
                catalog = "def"; schema = "app"; table = "users"; this.column = column
            }
            maskedDisposition = disposition
            outputOrdinals.addAll(ordinals)
        }

    private val ssnAt1 = listOf(column("ssn", MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(1)))

    @Test
    fun `equal requirements compare equal, a reordered ordinal does not`() {
        val ssnAt0 = listOf(column("ssn", MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0)))
        assertEquals(fingerprintOf(ssnAt1), fingerprintOf(ssnAt1))
        assertNotEquals(fingerprintOf(ssnAt1), fingerprintOf(ssnAt0))
    }

    @Test
    fun `a non-projection requirement (a scanned table) changes the fingerprint`() {
        val withTable: List<RequireResultReadGrant> = ssnAt1 +
            requireResultReadGrant { table = objectRef { catalog = "def"; schema = "app"; table = "orders" } }
        assertNotEquals(fingerprintOf(ssnAt1), fingerprintOf(withTable))
    }

    @Test
    fun `no requirements yield an empty fingerprint`() {
        assertTrue(fingerprintOf(emptyList()).grantsList.isEmpty())
    }

    @Test
    fun `the serializer round-trips the message`() {
        val fp = fingerprintOf(ssnAt1)
        assertEquals(fp, Json.decodeFromString(ResultFingerprintSerializer, Json.encodeToString(ResultFingerprintSerializer, fp)))
    }
}
