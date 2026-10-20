package com.ridi.oss.proxymonster.controlplane.notify

import kotlin.test.Test
import kotlin.test.assertEquals

class SlackMarkupTest {
    @Test
    fun `escape leaves no markup Slack would read`() {
        assertEquals("&lt;!channel&gt; &amp;lt; &lt;https://x.test|y&gt;", SlackMarkup.escape("<!channel> &lt; <https://x.test|y>"))
    }
}
