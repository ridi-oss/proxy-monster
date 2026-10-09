package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.AppUser
import com.ridi.oss.proxymonster.controlplane.UserGroupStore

/** An `app_user` row as an OIDC login's JIT provisioning leaves it (`source = OIDC`, no groups). */
fun UserGroupStore.seedOidcUser(principal: String, email: String? = null): AppUser {
    val id = dataSource.connection.use { c ->
        c.prepareStatement("INSERT INTO app_user (principal, email, source, active) VALUES (?, ?, 'OIDC', TRUE) RETURNING id").use { ps ->
            ps.setString(1, principal)
            ps.setString(2, email)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }
    return checkNotNull(getUser(id))
}
