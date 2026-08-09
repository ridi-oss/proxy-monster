package com.ridi.oss.proxymonster.controlplane

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ResultCryptoTest {
    private val key = ByteArray(32) { it.toByte() }
    private val crypto = ResultCrypto(key)

    @Test fun `round-trips plaintext`() {
        val plain = "ssn=987-65-4320".toByteArray()
        val blob = crypto.encrypt(plain)
        assertContentEquals(plain, crypto.decrypt(blob))
    }

    @Test fun `ciphertext is not the plaintext and uses a random iv`() {
        val plain = "987-65-4320".toByteArray()
        val a = crypto.encrypt(plain)
        val b = crypto.encrypt(plain)
        assertFalse(a.contentEquals(b), "same plaintext must not produce identical blobs (random IV)")
        assertFalse(a.drop(12).toByteArray().contentEquals(plain), "ciphertext must not equal plaintext")
    }

    @Test fun `tampered ciphertext fails to decrypt`() {
        val blob = crypto.encrypt("secret".toByteArray())
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 0x01).toByte()
        assertFailsWith<Exception> { crypto.decrypt(blob) }
    }

    @Test fun `wrong key fails to decrypt`() {
        val blob = crypto.encrypt("secret".toByteArray())
        val other = ResultCrypto(ByteArray(32) { (it + 1).toByte() })
        assertFailsWith<Exception> { other.decrypt(blob) }
    }

    @Test fun `key must be 32 bytes`() {
        assertFailsWith<IllegalArgumentException> { ResultCrypto(ByteArray(16)) }
    }

    @Test fun `too-short blob is rejected`() {
        assertFailsWith<IllegalArgumentException> { crypto.decrypt(ByteArray(8)) }
    }

    @Test fun `empty plaintext round-trips`() {
        assertTrue(crypto.decrypt(crypto.encrypt(ByteArray(0))).isEmpty())
    }
}

// Result confidentiality is exercised end-to-end through the task.assume route gate and the live
// exactly-R view decision in ApprovalResultViewContextDbTest rather than as a crypto-layer unit test.
