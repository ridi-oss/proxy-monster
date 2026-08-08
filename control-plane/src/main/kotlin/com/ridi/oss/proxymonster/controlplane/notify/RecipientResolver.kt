package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.RoleResolver
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.SatisfiableVerdict
import org.slf4j.LoggerFactory

/**
 * Who should hear about a task (docs/notifications.md, "Who can approve"). Cedar answers "may bob approve
 * this", never "who may", so this asks [Authz.satisfiableAs] per active candidate and notifies anyone whose
 * verdict is not IMPOSSIBLE. Over-notifying costs a 403 the recipient was always going to get; missing a real
 * approver leaves the request waiting with nobody told. Pinned against the shipped policies in
 * RecipientResolverDbTest.
 */
class RecipientResolver(
    private val authz: Authz,
    private val roleResolver: RoleResolver,
    private val candidateSource: () -> List<String>,
) {
    private val log = LoggerFactory.getLogger(RecipientResolver::class.java)

    /**
     * Everyone who could plausibly approve [req], plus [alwaysInclude] — the parties told how their own
     * request ended, whether or not they hold approval authority. A routing failure still keeps those.
     */
    fun recipientsFor(req: AccessRequest, alwaysInclude: Collection<String> = emptyList()): Set<String> {
        val eligible = runCatching { approverCandidates(req) }
            .onFailure { log.warn("notification routing failed for task={}", req.id, it) }
            .getOrDefault(emptySet())
        return (eligible + alwaysInclude.filter { it.isNotBlank() }).toSet()
    }

    private fun approverCandidates(req: AccessRequest): Set<String> {
        val resource = AuthzResource.ApprovalRequest(
            requester = req.principal,
            approver = req.decidedBy,
            executedBy = req.executedBy,
            datasourceName = req.datasourceName,
            roleName = req.roleName,
        )
        return candidateSource()
            .filter { candidate ->
                authz.satisfiableAs(
                    candidate,
                    roleResolver.resolve(candidate),
                    AuthzAction.TASK_APPROVE,
                    resource,
                    knownChannel = Channel.WORKFLOW_VIEWER.contextValue,
                    unknownContextKeys = setOf("requester_ip"),
                ) != SatisfiableVerdict.IMPOSSIBLE
            }
            .toSet()
    }
}
