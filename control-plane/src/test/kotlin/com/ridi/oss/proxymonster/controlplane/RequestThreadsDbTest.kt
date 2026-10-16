package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Comments, CCs, the timeline and close work on role requests as on query requests. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RequestThreadsDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var threads: RequestThreads
    private lateinit var access: AccessService
    private lateinit var recorder: ManagementAuditRecorder

    private val requester = "req@example.com"
    private val admin = "admin@example.com"
    private val cc = "cc@example.com"
    private val outsider = "out@example.com"

    private fun actor(p: String) = AuditActor(p, channel = "console")

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_request_threads"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        core.policyStore.createAssignment(RoleAssignmentInput(admin, core.policyStore.getRoleByName("system:admin")!!.id))
        core.userGroupStore.createUser(AppUserInput(principal = cc), core.tokenStore, core.accessStore, PrincipalSessionStore(dataSource, null))
        recorder = ManagementAuditRecorder(core.auditStore)
        threads = RequestThreads(core.accessStore, core.datasourceStore, core.roleResolver, core.userGroupStore, core.authz, recorder, null)
        access = AccessService(core.accessStore, core.datasourceStore, core.auditStore, core.roleResolver, core.authz, recorder)
    }

    private fun roleRequest(): Long {
        val role = core.policyStore.createRole(RoleInput("threads-${System.nanoTime()}"))
        return core.accessStore.createRequest(requester, AccessRequestInput(roleId = role.id, reason = "need it"), actor(requester), recorder).id
    }

    private fun kinds(id: Long) = threads.thread(requester, null, id).timeline.map { it.kind }

    @Test
    fun `a role request gets comments, CCs and a timeline, and its approval is recorded`() {
        val id = roleRequest()
        assertFailsWith<TaskServiceException> { threads.thread(cc, null, id) }
        threads.setCc(requester, null, actor(requester), id, cc, add = true)
        assertTrue(threads.thread(cc, null, id).canComment)
        threads.comment(cc, null, actor(cc), id, null, lgtm = true)
        threads.comment(admin, null, actor(admin), id, "granting for a day")
        assertFailsWith<TaskServiceException> { threads.comment(outsider, null, actor(outsider), id, "hi") }
        access.approve(admin, null, actor(admin), id, null)
        assertEquals(listOf("requested", "cc_added", "lgtm", "comment", "approved"), kinds(id))
        assertEquals(setOf(id), threads.involved(cc).map { it.id }.filter { it == id }.toSet())
        assertTrue(threads.involved(admin).any { it.id == id }, "the approver lists the role request they decided")
        assertFalse(threads.thread(requester, null, id).canClose, "an approved role request is a grant, not closable")
    }

    @Test
    fun `the requester closes a pending role request, an outsider cannot`() {
        val id = roleRequest()
        assertTrue(threads.thread(requester, null, id).canClose)
        assertFailsWith<TaskServiceException> { threads.close(outsider, null, actor(outsider), id) }
        assertEquals("CANCELLED", threads.close(requester, null, actor(requester), id).status)
        assertEquals("closed", kinds(id).last())
        assertEquals("CANCELLED", access.approve(admin, null, actor(admin), id, null).status, "a closed request is not approved")
    }

    @Test
    fun `an approved role request records the approver, and a system actor is not listed as a participant`() {
        val id = roleRequest()
        assertEquals("APPROVED", access.approve(admin, null, actor(admin), id, null).status)
        assertEquals(listOf("requested", "approved"), kinds(id))
        assertEquals(listOf(admin), dataSource.connection.use { RequestParticipants.list(it, id) })

        val other = roleRequest()
        dataSource.connection.use { c ->
            RequestEvents.record(c, other, RequestEventKind.REJECTED, "system:auto-approver:agent", "system", "too often")
        }
        assertEquals(emptyList(), dataSource.connection.use { RequestParticipants.list(it, other) })
    }
}
