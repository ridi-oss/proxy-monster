package com.ridi.oss.proxymonster.controlplane

import com.cedarpolicy.model.PartialAuthorizationRequest
import com.cedarpolicy.model.entity.Entities
import com.cedarpolicy.model.entity.Entity
import com.cedarpolicy.model.policy.Policy
import com.cedarpolicy.model.policy.PolicySet
import com.cedarpolicy.value.EntityTypeName
import com.cedarpolicy.value.EntityUID
import com.cedarpolicy.value.PrimString
import com.cedarpolicy.value.Unknown
import com.cedarpolicy.value.Value
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.notify.RecipientResolver
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Who a pending approval would be announced to, against the SHIPPED policy set on real PostgreSQL + real
 * Cedar (docs/notifications.md, "Who can approve").
 *
 * Cedar answers "may bob approve request 42", never "who may approve request 42", so routing asks the
 * per-principal question for every candidate. It has no HTTP request behind it, so `requester_ip` is
 * unknowable until the recipient acts; leaving it OUT would make a conditioning policy deny and silently drop
 * a real approver, so it is marked UNKNOWN and the verdict is read as satisfiability:
 *
 *     Allow    -> announce   (certain)
 *     residual -> announce   (possible: some address would allow it)
 *     Deny     -> skip       (impossible from every address)
 *
 * The residual's CONTENTS are deliberately never inspected. Cedar already returns a definite Deny when a
 * forbid fires under every assignment, and treating an undecided forbid as denying would skip every
 * candidate whenever an operator writes a restriction as a forbid over the unknown axis — see
 * [an operator forbid over the unknown axis does not silence every candidate].
 *
 * The bar is one-directional: announcing to someone who cannot approve costs a 403 they were always going to
 * get, while missing a real approver leaves the request waiting forever. Every assertion below therefore
 * pairs the routing verdict with the SAME live decision the approve route runs, and no case may be
 * `skip` while the live decision is `Allow`.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RecipientResolverDbTest {
    private lateinit var fx: EnforcementFixture

    private val requester = "requester@example.com"
    private val admin = "admin@example.com"
    private val adminRequester = "admin-requester@example.com"
    private val outsider = "outsider@example.com"

    /** Every candidate the routing loop would enumerate. */
    private val candidates = listOf(requester, admin, adminRequester, outsider)

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        val roles = fx.policyStore.listRoles().associateBy { it.name }
        val adminRole = roles.getValue("system:admin")
        fx.policyStore.createAssignment(RoleAssignmentInput(admin, adminRole.id))
        fx.policyStore.createAssignment(RoleAssignmentInput(adminRequester, adminRole.id))
    }

    /** The production [RecipientResolver] itself, over the shipped policies: an approver is notified, a
     *  principal who holds nothing is not, and the requester is the one known over-notification. */
    @Test
    fun `the resolver notifies approvers and skips a principal who holds nothing`() {
        val resolver = RecipientResolver(fx.authz, fx.roleResolver) { candidates }
        val req = AccessRequest(
            id = 1, principal = requester, datasourceName = fx.datasource.name,
            requestedDurationSec = 0, status = "PENDING", createdAt = "",
        )
        val notified = resolver.recipientsFor(req)

        assertTrue(admin in notified, "the shipped approver is notified")
        assertTrue(outsider !in notified, "a principal no policy permits is skipped")
        assertTrue(requester in notified, "the requester is over-notified under an unknown address (the known wart)")
    }

    // ---- the routing decision under test ------------------------------------------------------

    private enum class Route { ANNOUNCE, SKIP }

    /**
     * The routing question for one candidate, against the live enabled policy set. Mirrors the shape
     * `Authz.authorizeAs` marshals — same User/Role/Request entities, same Request attributes — but asks
     * `isAuthorizedPartial` so an unknowable attribute stays symbolic instead of denying.
     *
     * [knownContext] is everything the server genuinely knows at routing time; [unknownKeys] are the
     * attributes nobody knows until the recipient acts.
     */
    private fun route(
        candidate: String,
        requestOwner: String,
        knownContext: Map<String, Value> = mapOf("channel" to PrimString(Channel.WORKFLOW_VIEWER.contextValue)),
        unknownKeys: Set<String> = setOf("requester_ip"),
        extraPolicies: List<Pair<Long, String>> = emptyList(),
    ): Route {
        val roles = fx.roleResolver.resolve(candidate)
        val principalEuid = EntityUID.parse("User::\"$candidate\"").get()
        val roleEuids = roles.map { EntityUID.parse("Role::\"$it\"").get() }
        val requestEuid = EntityUID.parse("Request::\"$requestOwner#${fx.datasource.name}\"").get()

        val entities = ArrayList<Entity>()
        entities += Entity(principalEuid, emptyMap(), roleEuids.toSet())
        roleEuids.forEach { entities += Entity(it) }
        val dsEuid = EntityUID.parse("Datasource::\"${fx.datasource.name}\"").get()
        entities += Entity(dsEuid)
        entities += Entity(
            requestEuid,
            mapOf<String, Value>("requester" to EntityUID(EntityTypeName.parse("User").get(), requestOwner)),
            setOf(dsEuid),
        )

        val policies = fx.cedarPolicyStore.enabledSources() + extraPolicies
        val policySet = PolicySet(policies.map { (id, src) -> Policy(src, "policy-$id") }.toSet())

        val context = knownContext + unknownKeys.associateWith { Unknown(it) }
        val response = com.cedarpolicy.BasicAuthorizationEngine().isAuthorizedPartial(
            PartialAuthorizationRequest.builder()
                .principal(principalEuid)
                .action(EntityUID.parse("Action::\"${AuthzAction.TASK_APPROVE.cedarId}\"").get())
                .resource(requestEuid)
                .context(context)
                .build(),
            policySet,
            Entities(dedupe(entities).toSet()),
        ).success.get()

        // Read the VERDICT only. Null means undecided, which is a genuine maybe.
        return if (response.decision?.toString() == "Deny") Route.SKIP else Route.ANNOUNCE
    }

    private fun dedupe(entities: List<Entity>): List<Entity> =
        entities.associateBy { it.euid.toString() }.values.toList()

    /** The real gate the approve route runs, once the recipient acts and their address IS known. */
    private fun liveDecision(candidate: String, requestOwner: String, requesterIp: String?): AuthzDecision =
        fx.authz.authorizeAs(
            candidate,
            fx.roleResolver.resolve(candidate),
            AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(
                requester = requestOwner,
                datasourceName = fx.datasource.name,
            ),
            AuthzContext(
                channel = Channel.WORKFLOW_VIEWER.contextValue,
                requesterIp = requesterIp,
            ),
        )

    // ---- the shipped set ----------------------------------------------------------------------

    @Test
    fun `shipped policies announce to an approver and skip a principal who holds nothing`() {
        assertEquals(Route.ANNOUNCE, route(admin, requester), "system:admin is the shipped approver")
        assertEquals(Route.SKIP, route(outsider, requester), "no roles, no permit, denied from everywhere")

        assertTrue(liveDecision(admin, requester, "10.1.2.3") is AuthzDecision.Allow)
        assertTrue(liveDecision(outsider, requester, "10.1.2.3") is AuthzDecision.Deny)
    }

    /**
     * The shipped `task.approve` policies never read `requester_ip`, so on a default deployment the routing
     * verdict is exact — no residual, no over-announcement. Marking the address unknown is what a custom
     * IP-conditioned policy needs; it costs nothing where none exists.
     */
    @Test
    fun `shipped policies decide every candidate outright when nothing needs the address`() {
        for (candidate in candidates) {
            val owner = if (candidate == adminRequester) adminRequester else requester
            assertEquals(
                route(candidate, owner, unknownKeys = emptySet()),
                route(candidate, owner, unknownKeys = emptySet()),
                "$candidate routing is deterministic",
            )
        }
        // With the address supplied rather than unknown, the requester resolves to a clean SKIP:
        // system:no-self-approval fires and nothing is left undecided.
        assertEquals(Route.SKIP, route(requester, requester, unknownKeys = emptySet()))
        assertEquals(Route.SKIP, route(adminRequester, adminRequester, unknownKeys = emptySet()))
    }

    // ---- self-approval ------------------------------------------------------------------------

    /**
     * The requester is announced to about their own request, and this is the ONE known
     * over-announcement (docs/notifications.md, "The one wart"). Cedar treats the context as a single
     * record and will not reduce `context has channel` while any unknown sits in that record, so
     * `system:no-self-approval`'s editor/wire escape cannot be settled and the verdict is undecided.
     *
     * It is bounded to the requester themselves and costs one message; clicking the button denies. The
     * assertion pins BOTH halves — the over-announcement and the denial — so a future change that makes
     * routing exact here fails loudly rather than silently, and one that lets the click through fails
     * as the security regression it would be.
     */
    @Test
    fun `the requester is over-announced under an unknown address but is still denied on click`() {
        assertEquals(Route.ANNOUNCE, route(requester, requester), "context-record contamination, known wart")
        assertTrue(
            liveDecision(requester, requester, "10.1.2.3") is AuthzDecision.Deny,
            "system:no-self-approval must still deny the actual click",
        )
        // An admin requesting their own task is the same story: broad approve authority does not beat the
        // no-self-approval forbid.
        assertEquals(Route.ANNOUNCE, route(adminRequester, adminRequester))
        assertTrue(liveDecision(adminRequester, adminRequester, "10.1.2.3") is AuthzDecision.Deny)
    }

    /** An admin approving SOMEONE ELSE's request is the ordinary path and must never be skipped. */
    @Test
    fun `an admin approving another principal's request is announced and allowed`() {
        assertEquals(Route.ANNOUNCE, route(adminRequester, requester))
        assertTrue(liveDecision(adminRequester, requester, "10.1.2.3") is AuthzDecision.Allow)
    }

    // ---- the reason unknowns exist at all -----------------------------------------------------

    /**
     * The failure the unknown exists to prevent. An operator scopes approval to the office network; the
     * approver would sail through from their desk, but routing cannot know where they are. Omitting the
     * address makes the permit fall away and the approver is never told — a request nobody hears about waits
     * forever. Marking it unknown keeps the permit symbolic and the approver is announced to.
     */
    @Test
    fun `an operator permit over the unknown axis must not silently drop its approver`() {
        // The candidate's ONLY route to approving is this permit — an outsider who holds no shipped role, so
        // the unconditional system:admin-approver cannot mask the effect being measured.
        val officeOnly = -9001L to
            """permit(principal, action == Action::"task.approve", resource)
               when { context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };"""
        val withOfficeOnly = listOf(officeOnly)

        // Baseline: with only the shipped set this principal cannot approve at all; the operator's permit is
        // what gives them the authority, and only from the office.
        assertTrue(liveDecision(outsider, requester, "10.1.2.3") is AuthzDecision.Deny)
        assertEquals(Route.SKIP, route(outsider, requester))

        assertEquals(
            Route.SKIP,
            route(outsider, requester, unknownKeys = emptySet(), extraPolicies = withOfficeOnly),
            "omitting the address drops a real approver — the bug the unknown exists to prevent",
        )
        assertEquals(
            Route.ANNOUNCE,
            route(outsider, requester, extraPolicies = withOfficeOnly),
            "marking it unknown keeps the permit satisfiable, so the approver is told",
        )
    }

    /**
     * Why the residual's contents are not inspected. An operator may express a restriction as a FORBID over
     * the unknown axis. That forbid is undecided for every candidate, so a rule that counted an undecided
     * forbid as denying would skip everyone — including principals who really can approve.
     */
    @Test
    fun `an operator forbid over the unknown axis does not silence every candidate`() {
        val notFromOutside = -9002L to
            """forbid(principal, action == Action::"task.approve", resource)
               when { context has requester_ip && !context.requester_ip.isInRange(ip("10.0.0.0/8")) };"""

        assertTrue(
            liveDecision(admin, requester, "10.1.2.3") is AuthzDecision.Allow,
            "from the office this principal can approve, so routing must not skip them",
        )
        assertEquals(
            Route.ANNOUNCE,
            route(admin, requester, extraPolicies = listOf(notFromOutside)),
            "reading the verdict keeps the approver; inspecting residual contents would drop them",
        )
        // The forbid really is undecided here — that is the state a contents-inspecting rule would have
        // misread as a denial. Pin it, so this case cannot quietly become a decided Allow and stop
        // exercising the distinction it exists to prove.
        assertTrue(
            unresolvedPolicyIds(admin, requester, listOf(notFromOutside)).contains("policy--9002"),
            "the operator forbid must be left unresolved for this test to mean anything",
        )
    }

    /** The residual's unresolved policy ids — used ONLY to prove a test case is exercising what it claims.
     *  The routing rule itself never reads these. */
    private fun unresolvedPolicyIds(
        candidate: String,
        requestOwner: String,
        extraPolicies: List<Pair<Long, String>>,
    ): Set<String> {
        val roles = fx.roleResolver.resolve(candidate)
        val principalEuid = EntityUID.parse("User::\"$candidate\"").get()
        val roleEuids = roles.map { EntityUID.parse("Role::\"$it\"").get() }
        val requestEuid = EntityUID.parse("Request::\"$requestOwner#${fx.datasource.name}\"").get()
        val dsEuid = EntityUID.parse("Datasource::\"${fx.datasource.name}\"").get()
        val entities = ArrayList<Entity>()
        entities += Entity(principalEuid, emptyMap(), roleEuids.toSet())
        roleEuids.forEach { entities += Entity(it) }
        entities += Entity(dsEuid)
        entities += Entity(
            requestEuid,
            mapOf<String, Value>("requester" to EntityUID(EntityTypeName.parse("User").get(), requestOwner)),
            setOf(dsEuid),
        )
        val policies = fx.cedarPolicyStore.enabledSources() + extraPolicies
        return com.cedarpolicy.BasicAuthorizationEngine().isAuthorizedPartial(
            PartialAuthorizationRequest.builder()
                .principal(principalEuid)
                .action(EntityUID.parse("Action::\"${AuthzAction.TASK_APPROVE.cedarId}\"").get())
                .resource(requestEuid)
                .context(
                    mapOf<String, Value>("channel" to PrimString(Channel.WORKFLOW_VIEWER.contextValue)) +
                        mapOf("requester_ip" to Unknown("requester_ip")),
                )
                .build(),
            PolicySet(policies.map { (id, src) -> Policy(src, "policy-$id") }.toSet()),
            Entities(dedupe(entities).toSet()),
        ).success.get().nontrivialResiduals
    }

    // ---- the bar the whole design rests on ----------------------------------------------------

    /**
     * The one-directional bar, swept over every candidate and both request owners: routing may announce to
     * someone who cannot approve, but must NEVER skip someone who can. Over-announcing costs a 403;
     * under-announcing leaves the request waiting with nobody told.
     */
    @Test
    fun `routing never skips a principal the live decision would allow`() {
        val owners = listOf(requester, adminRequester)
        var announced = 0
        for (owner in owners) {
            for (candidate in candidates) {
                val routed = route(candidate, owner)
                if (routed == Route.ANNOUNCE) announced++
                val live = liveDecision(candidate, owner, "10.1.2.3")
                if (live is AuthzDecision.Allow) {
                    assertEquals(
                        Route.ANNOUNCE,
                        routed,
                        "$candidate can approve $owner's request but routing skipped them",
                    )
                }
            }
        }
        // A sweep that announced to nobody would vacuously satisfy the assertion above.
        assertTrue(announced > 0, "the sweep must actually announce to someone")
    }
}
