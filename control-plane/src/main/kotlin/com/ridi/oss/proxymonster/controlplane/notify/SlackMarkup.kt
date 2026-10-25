package com.ridi.oss.proxymonster.controlplane.notify

/** Slack mrkdwn both ways: escaping a value posted to Slack, and reading a message a person wrote there. */
object SlackMarkup {
    private val MENTION = Regex("<@([UW][A-Z0-9_]+)(?:\\|[^>]*)?>")
    private val MARKUP = Regex("<([^<>|]+)(?:\\|([^<>]*))?>")

    /** Escapes the characters Slack reads as structure, so a value cannot open a `<…|link>`, a `<!channel>`, or an entity. */
    fun escape(s: String): String = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    /** The Slack user IDs a message @-mentions, without repeats. */
    fun mentionedIds(text: String): List<String> = MENTION.findAll(text).map { it.groupValues[1] }.distinct().toList()

    /** A message as plain text: `<@U1>` as `@username` from [usernames], a link as `label (url)`, entities decoded. */
    fun plainText(text: String, usernames: Map<String, String?> = emptyMap()): String =
        MARKUP.replace(text) { m ->
            val target = m.groupValues[1]
            val label = m.groupValues[2].takeIf { it.isNotEmpty() }
            when (target.first()) {
                '@' -> "@" + (usernames[target.drop(1)] ?: label ?: target.drop(1))
                '#' -> "#" + (label ?: target.drop(1))
                '!' -> label ?: "@" + target.drop(1).substringBefore('^')
                else -> label?.let { "$it ($target)" } ?: target
            }
        }.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}
