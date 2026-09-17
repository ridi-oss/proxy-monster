package com.ridi.oss.proxymonster.probe

import com.ridi.oss.sqlglotgo.Sqlglot
import java.security.MessageDigest

/**
 * Dialect-aware SQL canonicalization for one-time query-grant hashing.
 *
 * The security contract is token-sequence equality with byte-exact literals: equivalent statements
 * may differ only in canonical whitespace, comments, keyword case, and dialect-safe identifier case.
 * Material differences in tables, columns, operators, literals, numbers, or quoted identifiers must
 * remain distinct. Canonical tokenization is performed by the pure sqlglot-go lexer through the JVM
 * FFM binding, with raw lexemes selected in Go; parser coverage is therefore irrelevant. Invalid or
 * unsupported input and every native load, descriptor, encoding, or invocation failure return null
 * so grant decisions fail closed.
 */

/** Normalize [sql] under [dialect] to its canonical token string, or null on any failure. */
fun normalizeSql(sql: String, dialect: Dialect): String? = try {
    Sqlglot.sqlNormalize(sql, dialect.wireName)
} catch (_: Throwable) {
    null
}

/** sha256-hex of [normalizeSql]; null when the SQL can't be normalized (fail-closed at the caller). */
fun sqlGrantHash(sql: String, dialect: Dialect): String? {
    val norm = normalizeSql(sql, dialect) ?: return null
    val md = MessageDigest.getInstance("SHA-256")
    return md.digest(norm.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}
