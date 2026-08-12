package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessStore
import com.ridi.oss.proxymonster.controlplane.AuditStore
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.DatasourceStore
import com.ridi.oss.proxymonster.controlplane.PolicyStore
import com.ridi.oss.proxymonster.controlplane.QueryResultStore
import com.ridi.oss.proxymonster.controlplane.RoleResolver
import com.ridi.oss.proxymonster.controlplane.RunExecService
import com.ridi.oss.proxymonster.controlplane.TaskCompletionHub
import com.ridi.oss.proxymonster.controlplane.UserGroupStore
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.runApprovedTask
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
    datasourceStore: DatasourceStore,
    policyStore: PolicyStore,
    queryResultStore: QueryResultStore?,
    auditStore: AuditStore,
    runExecService: RunExecService,
    taskCompletionHub: TaskCompletionHub,
): NotificationService? {
    val slackHttp = if (config.slackBotToken != null && config.slackAppToken != null) slackHttpClient() else null
    val transports = buildList {
        if (slackHttp != null && config.slackBotToken != null) {
            add(SlackTransport(slackHttp, config.slackBotToken, config.webBaseUrl, NotificationRenderer()))
        }
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
    // privileged action. Approving from Slack also RUNS the query, through the same claim + run the console
    // route uses — the claim is the execute-once CAS, so a console /execute racing this loses cleanly.
    if (slackHttp != null && config.slackBotToken != null && config.slackAppToken != null) {
        val handler = SlackDecisionHandler(
            accessStore = accessStore,
            datasourceStore = datasourceStore,
            authz = authz,
            auditRecorder = ManagementAuditRecorder(auditStore),
            notifications = notifications,
            defaultLocale = config.notifyLocale,
            onApproved = { approved ->
                val ds = approved.datasourceId?.let(datasourceStore::get)
                val sql = approved.sql
                // Filter to LIVE roles, same as the console /execute pre-flight (Approvals.kt), so a role
                // soft-deleted between approval and click refuses BEFORE the claim — matching the console's
                // clean refusal instead of claiming, running, and driving the task to a terminal FAILED.
                val executeAs = policyStore.liveRoleNames(approved.executeAs).toSet()
                // The button offered a run; if by click time it cannot start (result storage unconfigured, the
                // datasource soft-deleted, or every execute-as role gone), throw so the clicker is told
                // "approved, but the run could not be started" rather than silently seeing a "running" message.
                require(queryResultStore != null && ds != null && sql != null && executeAs.isNotEmpty()) {
                    "cannot run task ${approved.id}: results=${queryResultStore != null} ds=${ds != null} " +
                        "sql=${sql != null} roles=${executeAs.size}"
                }
                // The execute-once CAS. A LOST claim means another executor already started it — not a failure.
                val claimed = queryResultStore.claimAndStartRun(approved.id, approved.decidedBy ?: approved.principal) { c ->
                    accessStore.claimExecution(approved.id, c)
                } != null
                if (claimed) {
                    launch {
                        runApprovedTask(
                            id = approved.id,
                            executor = approved.decidedBy ?: approved.principal,
                            ds = ds, sql = sql, executeAs = executeAs,
                            requesterIp = null, // a Slack click carries no attested address
                            requesterPrincipal = approved.principal, req = approved,
                            config = config, accessStore = accessStore, store = queryResultStore,
                            auditStore = auditStore, runExecService = runExecService,
                            taskCompletionHub = taskCompletionHub, notifications = notifications,
                            log = environment.log,
                        )
                    }
                }
            },
        )
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
