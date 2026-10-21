package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.UserParents
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Editor and wire self-approve against the real migrated Cedar policy set. Both server-attested channels may
 * approve a principal's own task after task.request clears; workflow, no-channel human approval, and
 * cross-user approval stay denied.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EditorSelfApproveAuthzDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var ds: Datasource

    private val alice = "alice@example.com"
    private val bob = "bob@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_editor_selfapprove"))
        core = ControlPlaneCore(dataSource)
        ds = core.datasourceStore.create(
            DatasourceInput(name = "editor-ds", engine = "postgres", host = "h", port = 5432, dbName = "d"),
        )
    }

    /** Direct task.approve query for a self-request, on the given channel (null = an ordinary human approval). */
    private fun approveSelf(principal: String, requester: String, channel: String?): AuthzDecision =
        core.authz.authorizeWithContext(
            principal, AuthzAction.TASK_APPROVE,
            AuthzResource.ApprovalRequest(requester = requester, approver = principal, datasourceName = ds.name),
            AuthzContext(channel = channel), ds.name, ds.tags,
        )

    @Test
    fun `autoApproveTask allows non-admin self-approve on server-attested channels`() {
        assertTrue(autoApproveTask(alice, UserParents(emptySet()), ds, AuthzContext(), core.authz, Channel.EDITOR))
        assertTrue(autoApproveTask(alice, UserParents(emptySet()), ds, AuthzContext(), core.authz, Channel.WIRE))
    }

    @Test
    fun `self-approve stays denied outside editor and wire`() {
        assertTrue(approveSelf(alice, alice, channel = null) is AuthzDecision.Deny)
        assertTrue(approveSelf(alice, alice, channel = "workflow-executor") is AuthzDecision.Deny)
    }

    @Test
    fun `server-attested channel permits do not open cross-user approval`() {
        assertTrue(approveSelf(alice, bob, channel = "editor") is AuthzDecision.Deny)
        assertTrue(approveSelf(alice, bob, channel = "wire") is AuthzDecision.Deny)
    }

    @Test
    fun `self-approve is explicitly allowed on editor and wire`() {
        assertFalse(approveSelf(alice, alice, channel = "editor") is AuthzDecision.Deny)
        assertFalse(approveSelf(alice, alice, channel = "wire") is AuthzDecision.Deny)
    }
}
