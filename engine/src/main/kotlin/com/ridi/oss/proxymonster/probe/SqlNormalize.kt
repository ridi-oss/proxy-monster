package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.GoBinding
import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig
import java.security.MessageDigest

/**
 * SQL canonicalization for one-time query-grant hashing, in the dialect the engine builds for the target.
 *
 * The security contract is token-sequence equality with byte-exact literals: equivalent statements
 * may differ only in canonical whitespace, comments, keyword case, and dialect-safe identifier case.
 * Material differences in tables, columns, operators, literals, numbers, or quoted identifiers must
 * remain distinct. Canonical tokenization is performed by the pure sqlglot-go lexer through the JVM
 * FFM binding, with raw lexemes selected in Go; parser coverage is therefore irrelevant. Invalid or
 * unsupported input and every native load, descriptor, encoding, or invocation failure return null
 * so grant decisions fail closed.
 */

/** Normalize [sql] for [config]'s engine and target to its canonical token string, or null on any failure. */
fun normalizeSql(sql: String, config: EngineConfig): String? = try {
    GoBinding.sqlNormalize(sql, config.toByteArray())
} catch (_: Throwable) {
    null
}

/** sha256-hex of [normalizeSql]; null when the SQL can't be normalized (fail-closed at the caller). */
fun sqlGrantHash(sql: String, config: EngineConfig): String? {
    val norm = normalizeSql(sql, config) ?: return null
    val md = MessageDigest.getInstance("SHA-256")
    return md.digest(norm.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}
