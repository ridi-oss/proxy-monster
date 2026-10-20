package com.ridi.oss.proxymonster.controlplane.notify

/** Slack mrkdwn both ways: escaping a value posted to Slack, and reading a message a person wrote there. */
object SlackMarkup {
    /** Escapes the characters Slack reads as structure, so a value cannot open a `<…|link>`, a `<!channel>`, or an entity. */
    fun escape(s: String): String = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
}
