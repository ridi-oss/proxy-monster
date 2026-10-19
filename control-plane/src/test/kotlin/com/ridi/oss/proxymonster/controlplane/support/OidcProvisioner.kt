package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.auth.OidcGroupMapping
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import io.ktor.client.request.get
import io.ktor.http.HttpHeaders
import io.ktor.http.parseQueryString
import kotlinx.coroutines.runBlocking

/** JIT provisioning as a real OIDC login leaves it: a login through cp-go, one stack per group mapping. */
class OidcProvisioner(private val core: ControlPlaneCore, private val database: String) : AutoCloseable {
    private val idp = FakeOidcIdp()
    private val stacks = HashMap<OidcGroupMapping, CpGoStack>()
    private val config = Config(
        httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
        sessionSecret = "oidc-provisioner-secret-32-bytes!!", oidc = null, resultKey = null, scimToken = null,
        sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
    )

    /** Logs in as [subject] with the [email] and [groups] claims; the principal is the email, else the subject. */
    fun login(subject: String, email: String?, groups: List<String>, mapping: OidcGroupMapping) = runBlocking {
        val stack = stacks.getOrPut(mapping) { CpGoStack(config, core, database, extraEnv = idp.env(mapping.map, mapping.prefix)) }
        val client = stack.client()
        val query = parseQueryString(checkNotNull(client.get("/auth/oidc/login").headers[HttpHeaders.Location]).substringAfter('?'))
        idp.next(FakeOidcIdp.Identity(subject, email, groups), checkNotNull(query["nonce"]))
        client.get("/auth/oidc/callback?code=provision&state=${checkNotNull(query["state"])}")
        Unit
    }

    override fun close() {
        stacks.values.forEach { it.close() }
        idp.close()
    }
}
