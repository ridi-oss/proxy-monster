package com.ridi.oss.proxymonster.probe

/**
 * Deterministic value masking. The control plane calls this when a stored result set is viewed (an
 * approval result): the saved result never replays through the wire proxy, so the control plane
 * applies the column masks itself. The data-plane proxy has its own byte-identical Go implementation
 * (`goproxy/relay/masking.go`) for inline wire result-set rewriting; the two must produce identical
 * output. Operates on the rendered string value; `kind` is the mask-function kind from a column policy.
 */
object Masking {
    fun apply(value: String?, kind: String): String? = when {
        value == null -> null
        kind == "NULL" -> null
        kind == "FIXED" -> "####"
        kind == "LAST_N" -> {
            val n = 4
            if (value.length <= n) "*".repeat(value.length) else "*".repeat(value.length - n) + value.takeLast(n)
        }
        kind == "FORMAT_PRESERVING" -> value.map { if (it.isLetterOrDigit()) '*' else it }.joinToString("")
        else -> "****"
    }
}
