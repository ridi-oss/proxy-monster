package com.ridi.oss.proxymonster.controlplane.support

import java.security.MessageDigest
import java.util.Base64

/** RFC 7636 S256: base64url(SHA-256(verifier)), unpadded. */
fun pkceS256(verifier: String): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)))

fun isValidPkceChallenge(challenge: String): Boolean = challenge.length == 43 && challenge.all { it.isLetterOrDigit() || it == '-' || it == '_' }

fun isValidPkceVerifier(verifier: String): Boolean =
    verifier.length in 43..128 && verifier.all { it.isLetterOrDigit() || it == '-' || it == '.' || it == '_' || it == '~' }
