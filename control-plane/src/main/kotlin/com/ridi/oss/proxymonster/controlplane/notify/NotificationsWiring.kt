package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessStore
import com.ridi.oss.proxymonster.controlplane.ApprovalService
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.QueryResultStore
import com.ridi.oss.proxymonster.controlplane.RoleResolver
import com.ridi.oss.proxymonster.controlplane.UserGroupStore
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.source.SourceAdapter
import io.ktor.server.application.Application
import kotlinx.coroutines.launch
import java.time.Duration
import javax.sql.DataSource

private const val DRAIN_INTERVAL_MS = 5_000L

/**
 * Wires the notification layer and returns the service the task routes emit through, or null when no
 * transport is configured (both Slack tokens absent) — then the whole layer is inert and the workflow is
 * unchanged, the same posture an unset PM_SCIM_TOKEN gives SCIM. Owns the outbound drain loop and, when
 * Slack is configured, the inbound Socket Mode connection; both are cancelled with the application.
 */
fun Application.installNotifications(
    config: Config,
    dataSource: DataSource,
    authz: Authz,
    roleResolver: RoleResolver,
    accessStore: AccessStore,
    queryResultStore: QueryResultStore?,
    approvals: () -> ApprovalService,
    sourceAdapter: SourceAdapter? = null,
): NotificationService? {
    val slackHttp = if (config.slackBotToken != null && config.slackAppToken != null) slackHttpClient() else null
    val transports = buildList {
        if (slackHttp != null && config.slackBotToken != null) {
            add(SlackTransport(slackHttp, config.slackBotToken, config.webBaseUrl, NotificationRenderer()))
        }
        if (sourceAdapter != null) add(PullRequestCommentTransport(sourceAdapter))
    }
    if (transports.isEmpty()) return null

    val notifications = NotificationService(
        store = NotificationStore(dataSource),
        recipients = RecipientResolver(authz, roleResolver) { roleResolver.listActivePrincipals() },
        transports = transports,
        accessStore = accessStore,
        queryResultStore = queryResultStore,
        webBaseUrl = config.webBaseUrl,
        disclosure = StatementDisclosure.parse(config.notifyStatement) ?: StatementDisclosure.AUTO,
        defaultLocale = config.notifyLocale,
    )
    // A plain poll rather than LISTEN/NOTIFY: the table is the queue, so a notification would only be a
    // wake-up hint. wake() covers interactive latency; this is the backstop.
    launch { notifications.runDrainLoop(Duration.ofMillis(DRAIN_INTERVAL_MS)) }

    // Slack Socket Mode: an OUTBOUND WebSocket carrying clicks back, so no inbound ingress performs a
    // privileged action. Each click goes through the same ApprovalService the console routes use.
    if (slackHttp != null && config.slackBotToken != null && config.slackAppToken != null) {
        val handler = SlackDecisionHandler(accessStore, approvals, notifications, config.notifyLocale)
        val identity = UserGroupStore(dataSource)
        launch {
            SlackSocketMode(
                slackHttp,
                config.slackBotToken,
                config.slackAppToken,
                principalForEmail = identity::activePrincipalByEmail,
                onInteraction = { handler.handle(it) },
            ).run()
        }
    }
    return notifications
}
