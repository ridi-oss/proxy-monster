package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.probe.Dialect
import com.ridi.oss.proxymonster.probe.sqlGrantHash
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ChangeKeyTest {
    private fun key(sql: String, fileKey: String = "0042") = changeKey(fileKey, contentHash(sql, Dialect.MYSQL))

    @Test
    fun the_same_name_and_sql_get_the_same_key() {
        assertEquals(key("UPDATE t SET a = 1"), key("UPDATE t SET a = 1"))
    }

    @Test
    fun a_different_file_key_gets_a_different_key() {
        val sql = "UPDATE t SET a = 1"
        assertNotEquals(key(sql, "0042"), key(sql, "0043"))
    }

    @Test
    fun the_change_key_hashes_the_file_key_and_the_content_hash() {
        val hash = contentHash("UPDATE t SET a = 1", Dialect.MYSQL)
        assertTrue(hash.startsWith("n:"))
        assertTrue(contentHash("SELECT /*!50000 * */ FROM users", Dialect.MYSQL).startsWith("r:"))
        assertEquals(sha256Hex("0042\n$hash"), changeKey("0042", hash))
    }

    @Test
    fun reformatted_sql_keeps_its_key() {
        val sql = "UPDATE t SET a = 1 WHERE id = 7"
        assertEquals(key(sql), key("update  t\n  set a = 1 -- fix\n where id = 7"))
    }

    @Test
    fun literal_changes_get_different_keys() {
        assertNotEquals(key("SELECT * FROM users WHERE id = 1"), key("SELECT * FROM users WHERE id = 2"))
    }

    @Test
    fun executable_comments_and_hints_are_not_normalized() {
        assertNull(sqlGrantHash("SELECT /*+ MAX_EXECUTION_TIME(5000) */ * FROM users", Dialect.MYSQL))
        assertNull(sqlGrantHash("SELECT /*!50000 * */ FROM users", Dialect.MYSQL))
    }

    @Test
    fun raw_keyed_sql_changes_its_key_on_any_edit() {
        val sql = "SELECT /*!50000 * */ FROM users"
        val k = key(sql)
        assertTrue(k.matches(Regex("[0-9a-f]{64}")))
        assertEquals(k, key(sql))
        assertNotEquals(k, key("SELECT  /*!50000 * */ FROM users"))
        assertNotEquals(k, key("SELECT /*!50000 * */ FROM users -- note"))
        assertNotEquals(k, key("SELECT * FROM users"))
    }
}
