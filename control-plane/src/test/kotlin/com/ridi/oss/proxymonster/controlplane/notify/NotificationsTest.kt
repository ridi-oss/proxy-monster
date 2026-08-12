package com.ridi.oss.proxymonster.controlplane.notify

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * What the recipient can actually read, and therefore whether they may approve from the message
 * (docs/notifications.md, "Never approve what you cannot see").
 *
 * The rule is deliberately about the RENDERED text, not the configured mode: a shown statement that fits is
 * complete, and one the transport's own ceiling elides is not, whichever mode chose to show it. Writing the
 * gate against the mode gets both edges backwards, which is what these cases pin.
 */
class NotificationsTest {

    private val short = "SELECT id FROM users"
    private val long = "SELECT " + "x".repeat(500) + " FROM users"

    @Test
    fun `a shown statement under the ceiling is complete`() {
        val r = renderStatement(short, show = true)
        assertEquals(short, r.text)
        assertTrue(r.complete, "nothing was cut, so the approver has read the whole statement")
    }

    @Test
    fun `a shown statement within the transport ceiling is complete`() {
        val r = renderStatement(long, show = true, hardLimit = 2800)
        assertEquals(long, r.text)
        assertTrue(r.complete)
    }

    @Test
    fun `the transport ceiling cuts an overlong statement and drops completeness`() {
        val huge = "SELECT " + "y".repeat(4000) + " FROM users"
        val r = renderStatement(huge, show = true, hardLimit = 2800)
        assertFalse(r.complete, "elided is elided")
        assertTrue(r.text!!.length <= 2800, "the ellipsis must fit INSIDE the ceiling, not overrun it")
        assertTrue(r.text!!.endsWith("…"))
    }

    @Test
    fun `a hidden statement carries no text and is never complete`() {
        val r = renderStatement(short, show = false)
        assertEquals(null, r.text)
        assertFalse(r.complete)
    }

    @Test
    fun `a task with no statement is never complete`() {
        val r = renderStatement(null, show = true, hardLimit = 2800)
        assertEquals(null, r.text)
        assertFalse(r.complete)
    }

    @Test
    fun `parse accepts the three modes and rejects anything else`() {
        assertEquals(StatementDisclosure.OMIT, StatementDisclosure.parse("omit"))
        assertEquals(StatementDisclosure.AUTO, StatementDisclosure.parse("auto"))
        assertEquals(StatementDisclosure.FULL, StatementDisclosure.parse("FULL"))
        // `truncated` is removed; the enum does not know it (Config coerces it to auto with a warning).
        assertEquals(null, StatementDisclosure.parse("truncated"))
        assertEquals(null, StatementDisclosure.parse("sometimes"))
    }

    @Test
    fun `omit never shows the statement`() {
        for (pending in listOf(true, false)) {
            for (cleared in listOf(true, false)) {
                assertFalse(discloseStatement(StatementDisclosure.OMIT, pending, cleared))
            }
        }
    }

    @Test
    fun `auto follows the hint, pending or handled`() {
        assertTrue(discloseStatement(StatementDisclosure.AUTO, pending = true, cleared = true))
        assertTrue(discloseStatement(StatementDisclosure.AUTO, pending = false, cleared = true))
        assertFalse(discloseStatement(StatementDisclosure.AUTO, pending = true, cleared = false))
        assertFalse(discloseStatement(StatementDisclosure.AUTO, pending = false, cleared = false))
    }

    @Test
    fun `full shows a pending statement even when the hint flags it`() {
        assertTrue(
            discloseStatement(StatementDisclosure.FULL, pending = true, cleared = false),
            "a pending approver must be able to read the statement to decide and approve-and-run",
        )
        assertTrue(discloseStatement(StatementDisclosure.FULL, pending = true, cleared = true))
    }

    @Test
    fun `full falls back to the hint once the task is handled`() {
        assertFalse(
            discloseStatement(StatementDisclosure.FULL, pending = false, cleared = false),
            "a flagged statement is hidden after the decision, so a protected value does not linger",
        )
        assertTrue(discloseStatement(StatementDisclosure.FULL, pending = false, cleared = true))
    }
}
