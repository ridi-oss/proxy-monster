package com.ridi.oss.proxymonster.controlplane.notify

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * What the recipient can actually read, and therefore whether they may approve from the message
 * (docs/notifications.md, "Never approve what you cannot see").
 *
 * The rule is deliberately about the RENDERED text, not the configured mode: a short statement under
 * TRUNCATED was never truncated, and a long one under FULL is still elided by a transport's own ceiling.
 * Writing the gate against the mode gets both edges backwards, which is what these cases pin.
 */
class NotificationsTest {

    private val short = "SELECT id FROM users"
    private val long = "SELECT " + "x".repeat(500) + " FROM users"

    @Test
    fun `a statement shorter than the limit is complete under truncated`() {
        val r = renderStatement(short, StatementDisclosure.TRUNCATED, maxChars = 200)
        assertEquals(short, r.text)
        assertTrue(r.complete, "nothing was cut, so the approver has read the whole statement")
    }

    @Test
    fun `a statement longer than the limit is cut and incomplete`() {
        val r = renderStatement(long, StatementDisclosure.TRUNCATED, maxChars = 200)
        assertFalse(r.complete)
        assertTrue(r.text!!.length <= 200, "the ellipsis must fit INSIDE the ceiling, not overrun it")
        assertTrue(r.text!!.endsWith("…"))
    }

    @Test
    fun `full carries the whole statement when the transport can hold it`() {
        val r = renderStatement(long, StatementDisclosure.FULL, maxChars = 200, hardLimit = 2800)
        assertEquals(long, r.text)
        assertTrue(r.complete, "the configured truncation limit does not apply under FULL")
    }

    /** The edge the mode-based rule got wrong: FULL still loses the button when the transport elides. */
    @Test
    fun `full is incomplete when the transport ceiling cuts it`() {
        val huge = "SELECT " + "y".repeat(4000) + " FROM users"
        val r = renderStatement(huge, StatementDisclosure.FULL, maxChars = 200, hardLimit = 2800)
        assertFalse(r.complete, "elided is elided, whoever did it")
        assertTrue(r.text!!.length <= 2800)
    }

    @Test
    fun `omit carries no statement and is never complete`() {
        val r = renderStatement(short, StatementDisclosure.OMIT, maxChars = 200)
        assertEquals(null, r.text)
        assertFalse(r.complete)
    }

    @Test
    fun `a task with no statement is never complete`() {
        val r = renderStatement(null, StatementDisclosure.FULL, maxChars = 200)
        assertEquals(null, r.text)
        assertFalse(r.complete)
    }

    @Test
    fun `parse rejects an unrecognized disclosure mode`() {
        assertEquals(StatementDisclosure.TRUNCATED, StatementDisclosure.parse("truncated"))
        assertEquals(StatementDisclosure.FULL, StatementDisclosure.parse("FULL"))
        assertEquals(null, StatementDisclosure.parse("sometimes"))
    }
}
