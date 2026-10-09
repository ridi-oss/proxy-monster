package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.FakeOidcIdp
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The first-admin bootstrap through an OIDC login on cp-go (support/CpGoStack.kt): the IdP admin group maps to
 * the seeded `system:admin` group, and the next login without it syncs the membership away.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class BootstrapAdminCpGoTest {
    private lateinit var ds: DataSource
    private lateinit var database: String
    private lateinit var core: ControlPlaneCore
    private lateinit var store: UserGroupStore
    private lateinit var roleResolver: RoleResolver
    private lateinit var idp: FakeOidcIdp
    private val stacks = mutableMapOf<Boolean, CpGoStack>()

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        database = SharedPostgres.freshDatabase("pm_bootstrap_admin_cpgo")
        ds = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(ds).load().migrate()
        core = ControlPlaneCore(ds)
        store = UserGroupStore(ds)
        roleResolver = RoleResolver(ds, store, AccessStore(ds))
        idp = FakeOidcIdp()
    }

    @AfterAll
    fun teardown() {
        stacks.values.forEach { it.close() }
        if (::idp.isInitialized) idp.close()
    }

    /** cp-go with the admin map (`proxy-monster-admin=system:admin`, prefix `proxy-monster-`), or with no mapping. */
    private fun stack(mapped: Boolean): CpGoStack = stacks.getOrPut(mapped) {
        val env = if (mapped) idp.env("proxy-monster-admin=system:admin", "proxy-monster-") else idp.env()
        CpGoStack(config(), core, database, extraEnv = env)
    }

    private fun login(principal: String, email: String?, groups: List<String>, mapped: Boolean = true): AppUser = runBlocking {
        idp.login(stack(mapped).client(), principal, email, groups)
        assertNotNull(store.getUserByPrincipal(principal))
    }

    @Test
    fun `an IdP admin-group member resolves system-admin and loses it when the group is dropped (sync)`() {
        val principal = "boot-admin@example.com"
        val admin = login(principal, principal, listOf("proxy-monster-admin"))
        assertTrue(admin.groups.any { it.name == "system:admin" }, "the IdP admin group maps to system:admin")
        assertTrue("system:admin" in roleResolver.resolve(principal), "membership in system:admin confers system:admin")

        val after = login(principal, principal, emptyList())
        assertFalse(after.groups.any { it.name == "system:admin" }, "sync removes the no-longer-claimed admin group")
        assertFalse("system:admin" in roleResolver.resolve(principal), "dropping the IdP admin group revokes system:admin")
    }

    @Test
    fun `an unmapped IdP group is created by name with the prefix stripped`() {
        val user = login("analyst@example.com", null, listOf("proxy-monster-analysts"))
        val analysts = user.groups.first { it.name == "analysts" }
        assertFalse(store.isSystemGroup(analysts.id), "a JIT-created group is not a SYSTEM group")
    }

    @Test
    fun `a raw reserved-name claim without a mapping does not confer admin (escalation closed)`() {
        val intruder = login("intruder@example.com", null, listOf("system:admin"), mapped = false)
        assertFalse(intruder.groups.any { it.name == "system:admin" }, "a raw system:admin claim must not self-assign admin")
        assertFalse("system:admin" in roleResolver.resolve("intruder@example.com"), "no admin without an explicit mapping")

        login("mapped-admin@example.com", null, listOf("proxy-monster-admin"))
        assertTrue("system:admin" in roleResolver.resolve("mapped-admin@example.com"), "an explicit map entry still confers admin")
    }

    private fun config() = Config(
        httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
        sessionSecret = "bootstrap-admin-test-secret", oidc = null, resultKey = null, scimToken = null,
        sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
    )
}
