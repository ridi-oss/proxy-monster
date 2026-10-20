package com.ridi.oss.proxymonster.controlplane.notify

import kotlin.test.Test
import kotlin.test.assertEquals

class SlackMarkupTest {
    @Test
    fun `escape leaves no markup Slack would read`() {
        assertEquals("&lt;!channel&gt; &amp;lt; &lt;https://x.test|y&gt;", SlackMarkup.escape("<!channel> &lt; <https://x.test|y>"))
    }

    @Test
    fun `mentioned ids are the user mentions, once each`() {
        assertEquals(listOf("U1", "W2"), SlackMarkup.mentionedIds("<@U1> <@W2|bo> <@U1> <#C3> <!here>"))
    }

    @Test
    fun `a message reads as plain text`() {
        assertEquals(
            "@ann @Cy @U4 #ops @here @team see docs (https://x.test/?a=1&b=2) https://y.test a < b & c",
            SlackMarkup.plainText(
                "<@U1> <@U3|Cy> <@U4> <#C9|ops> <!here> <!subteam^S1|@team> " +
                    "see <https://x.test/?a=1&amp;b=2|docs> <https://y.test> a &lt; b &amp; c",
                mapOf("U1" to "ann", "U4" to null),
            ),
        )
    }

    @Test
    fun `escaped text reads back as the original`() {
        val s = "a <b> & <@U1> &amp;"
        assertEquals(s, SlackMarkup.plainText(SlackMarkup.escape(s)))
    }
}
