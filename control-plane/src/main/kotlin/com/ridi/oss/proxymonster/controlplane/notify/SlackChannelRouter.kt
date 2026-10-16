package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.SlackChannelRoute

/**
 * The Slack channel a request is posted to: the first route whose tag its datasource carries. A request on no
 * datasource (a role on every datasource) goes to the first route.
 */
class SlackChannelRouter(
    private val routes: List<SlackChannelRoute>,
    val channelOnly: Boolean,
    private val tagsOf: (Long) -> List<String>,
) {
    fun channelFor(req: AccessRequest): String? {
        if (routes.isEmpty()) return null
        val tags = req.datasourceId?.let(tagsOf) ?: return routes.first().channel
        return routes.firstOrNull { it.tag in tags }?.channel
    }
}
