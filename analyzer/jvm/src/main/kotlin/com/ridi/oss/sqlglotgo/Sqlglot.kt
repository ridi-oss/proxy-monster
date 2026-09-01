package com.ridi.oss.sqlglotgo

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption

/**
 * In-process JVM binding to sqlglot-go's SQL column-lineage probe, via the Foreign Function &
 * Memory API (java.lang.foreign). The native library (built from `cmd/libsqlglot` by the
 * `buildNativeLib` Gradle task and bundled on the classpath) is loaded once for the JVM's lifetime.
 *
 * Thread-safe: the Go `AnalyzeStatement` is a pure function of its inputs, and each call here uses
 * its own confined [Arena]. Fail-closed: the Go side (`probe.AnalyzeStatementSafe`) never panics and
 * always returns a validly-encoded StatementFacts, so a malformed query yields `resolved=false` rather
 * than an error.
 *
 * Requires JDK 24+ (the module's bytecode target; FFM is java.lang.foreign). Run with
 * `--enable-native-access=ALL-UNNAMED` to silence the restricted-method warning.
 */
object Sqlglot {
    private val linker = Linker.nativeLinker()
    private val analyzeStatementHandle: MethodHandle
    private val splitStatementsHandle: MethodHandle
    private val sqlNormalizeHandle: MethodHandle
    private val freeHandle: MethodHandle

    init {
        val libPath = extractNativeLib()
        val lookup = SymbolLookup.libraryLookup(libPath, Arena.global())
        analyzeStatementHandle = linker.downcallHandle(
            lookup.find("AnalyzeStatement").orElseThrow {
                IllegalStateException("AnalyzeStatement not exported by native lib")
            },
            FunctionDescriptor.of(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,   // reqBytes
                // The native library supports 64-bit Darwin/Linux targets, where C size_t matches JAVA_LONG.
                ValueLayout.JAVA_LONG, // reqLen
                ValueLayout.ADDRESS,   // outLen (an out-parameter pointer this call writes the result length into)
            ),
        )
        splitStatementsHandle = linker.downcallHandle(
            lookup.find("SplitStatements").orElseThrow {
                IllegalStateException("SplitStatements not exported by native lib")
            },
            FunctionDescriptor.of(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_LONG,
                ValueLayout.ADDRESS,
            ),
        )
        sqlNormalizeHandle = linker.downcallHandle(
            lookup.find("SqlNormalize").orElseThrow { IllegalStateException("SqlNormalize not exported by native lib") },
            FunctionDescriptor.of(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                // The native library supports 64-bit Darwin/Linux targets, where C size_t matches JAVA_LONG.
                ValueLayout.JAVA_LONG,
                ValueLayout.ADDRESS,
            ),
        )
        freeHandle = linker.downcallHandle(
            lookup.find("FreeCString").orElseThrow { IllegalStateException("FreeCString not exported by native lib") },
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS),
        )
    }

    /**
     * Analyze one SQL statement. [requestBytes] is a marshaled `analyzerv1.AnalyzeRequest`
     * (proto/src/main/proto/analyzer.proto); the return is a marshaled `analyzerv1.StatementFacts`.
     * Raw bytes in, raw bytes out — this binding has no knowledge of the wire schema (mirrors
     * [sqlNormalize]'s byte-exact argument convention, applied to both directions here); the caller
     * (engine's `SqlglotProbe`) owns building/parsing the actual proto messages. Total: the native
     * side (`probe.AnalyzeStatementSafe`) never panics and always returns a validly-encoded
     * StatementFacts, so a malformed request yields a `resolved=false` message rather than an error.
     */
    fun analyzeStatement(requestBytes: ByteArray): ByteArray = callByteBufferHandle(analyzeStatementHandle, requestBytes)

    /**
     * Cut a multi-statement batch into its statements: a marshaled `analyzerv1.SplitRequest` in, a
     * marshaled `analyzerv1.SplitResponse` out. Same raw-bytes convention as [analyzeStatement].
     */
    fun splitStatements(requestBytes: ByteArray): ByteArray = callByteBufferHandle(splitStatementsHandle, requestBytes)

    /**
     * The byte-buffer FFM calling convention [analyzeStatement] follows: one byte buffer in (a
     * marshaled proto request message), one byte buffer out (a marshaled proto response message).
     * This binding has no knowledge of the wire schema; the caller (engine's `SqlglotProbe`) owns
     * building/parsing the actual proto messages.
     */
    private fun callByteBufferHandle(handle: MethodHandle, requestBytes: ByteArray): ByteArray {
        Arena.ofConfined().use { arena ->
            val reqSeg = arena.allocate(requestBytes.size.toLong().coerceAtLeast(1L))
            if (requestBytes.isNotEmpty()) {
                reqSeg.asSlice(0, requestBytes.size.toLong()).copyFrom(MemorySegment.ofArray(requestBytes))
            }
            val outLenSeg = arena.allocate(ValueLayout.JAVA_LONG)
            val resultPtr = handle.invoke(reqSeg, requestBytes.size.toLong(), outLenSeg) as MemorySegment
            try {
                val outLen = outLenSeg.get(ValueLayout.JAVA_LONG, 0)
                if (outLen == 0L) return ByteArray(0)
                return resultPtr.reinterpret(outLen).toArray(ValueLayout.JAVA_BYTE)
            } finally {
                freeHandle.invoke(resultPtr) // release the Go-malloc'd buffer (free(NULL) is a safe no-op)
            }
        }
    }

    /**
     * Canonicalize one SQL statement for byte-exact query-grant matching, or return null when the
     * dialect or SQL cannot be normalized safely.
     */
    fun sqlNormalize(sql: String, dialect: String): String? {
        if (dialect != "mysql" && dialect != "postgres") return null
        if (!hasWellFormedUtf16(sql)) return null

        val sqlBytes = sql.toByteArray(Charsets.UTF_8)
        Arena.ofConfined().use { arena ->
            val sqlSeg = arena.allocate(sqlBytes.size.toLong().coerceAtLeast(1L))
            if (sqlBytes.isNotEmpty()) {
                sqlSeg.asSlice(0, sqlBytes.size.toLong()).copyFrom(MemorySegment.ofArray(sqlBytes))
            }
            val dialectSeg = arena.allocateFrom(dialect)
            // The C ABI length is the exact UTF-8 byte count, not Kotlin's UTF-16 code-unit count.
            // This is a security requirement: no encoding or embedded-NUL boundary may change the SQL.
            val resultPtr = sqlNormalizeHandle.invoke(sqlSeg, sqlBytes.size.toLong(), dialectSeg) as MemorySegment
            try {
                if (resultPtr.address() == 0L) {
                    throw IllegalStateException("SqlNormalize returned a null pointer")
                }
                return resultPtr.reinterpret(Long.MAX_VALUE).getString(0).ifEmpty { null }
            } finally {
                freeHandle.invoke(resultPtr) // release the Go-malloc'd C string, including deny results
            }
        }
    }

    /** Whether every surrogate in [s] is paired — an unpaired one encodes to `?`, changing the SQL. */
    fun hasWellFormedUtf16(s: String): Boolean {
        var i = 0
        while (i < s.length) {
            val ch = s[i]
            when {
                Character.isHighSurrogate(ch) -> {
                    if (i + 1 >= s.length || !Character.isLowSurrogate(s[i + 1])) return false
                    i += 2
                }
                Character.isLowSurrogate(ch) -> return false
                else -> i++
            }
        }
        return true
    }

    private fun extractNativeLib(): Path {
        val (os, arch, ext) = platform()
        val resource = "/native/$os-$arch/libsqlglot.$ext"
        val stream = Sqlglot::class.java.getResourceAsStream(resource)
            ?: throw IllegalStateException(
                "native library not bundled: $resource — build it with the buildNativeLib Gradle task " +
                    "(needs the Go toolchain + a C compiler)",
            )
        val tmp = Files.createTempFile("libsqlglot", ".$ext")
        tmp.toFile().deleteOnExit()
        stream.use { Files.copy(it, tmp, StandardCopyOption.REPLACE_EXISTING) }
        return tmp
    }

    private data class Platform(val os: String, val arch: String, val ext: String)

    private fun platform(): Platform {
        val osName = System.getProperty("os.name").lowercase()
        val os = when {
            osName.contains("mac") || osName.contains("darwin") -> "darwin"
            osName.contains("linux") -> "linux"
            else -> throw IllegalStateException("unsupported OS for the sqlglot-go native binding: $osName")
        }
        val arch = when (val a = System.getProperty("os.arch").lowercase()) {
            "aarch64", "arm64" -> "arm64"
            "x86_64", "amd64" -> "amd64"
            else -> throw IllegalStateException("unsupported CPU arch for the sqlglot-go native binding: $a")
        }
        return Platform(os, arch, if (os == "darwin") "dylib" else "so")
    }
}
