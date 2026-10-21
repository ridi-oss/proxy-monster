package com.ridi.oss.proxymonster.controlplane.source

/** Looks up active proxy-monster principals; an inactive, unknown, or ambiguous match is null. */
interface PrincipalDirectory {
    fun activePrincipal(principal: String): String?

    fun activePrincipalByEmail(email: String): String?
}
