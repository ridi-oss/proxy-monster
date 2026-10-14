package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.SlackChannelRoute
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SlackChannelRoutingTest {
    private val tags = mapOf(1L to listOf("service:manta", "system:production"), 2L to listOf("system:production"), 3L to listOf("other"))
    private val routes = listOf(SlackChannelRoute("service:manta", "C_MANTA"), SlackChannelRoute("system:production", "C_PROD"))

    private fun req(ds: Long) = AccessRequest(id = 9, principal = "p", datasourceId = ds, requestedDurationSec = 0, status = "PENDING", createdAt = "", revision = 1)

    private fun transports(channelOnly: Boolean): Pair<SlackTransport, SlackTransport> {
        val router = SlackChannelRouter(routes, channelOnly) { tags[it].orEmpty() }
        val http = slackHttpClient()
        return SlackTransport(http, "xoxb", "https://c", NotificationRenderer(), channels = router) to
            SlackTransport(http, "xoxb", "https://c", NotificationRenderer(), channels = router, toChannel = true)
    }

    @Test
    fun `the first matching tag picks the channel, and an unmatched datasource has none`() {
        val (_, channel) = transports(channelOnly = false)
        assertEquals("C_MANTA", channel.taskAddress(req(1)))
        assertEquals("C_PROD", channel.taskAddress(req(2)))
        assertNull(channel.taskAddress(req(3)))
    }

    @Test
    fun `channel mode skips DMs only for a request that has a channel`() {
        val (dmBoth, _) = transports(channelOnly = false)
        assertTrue(dmBoth.serves(req(1)), "both mode keeps DMs")
        val (dm, _) = transports(channelOnly = true)
        assertFalse(dm.serves(req(1)))
        assertTrue(dm.serves(req(3)), "no channel falls back to DMs")
    }
}
