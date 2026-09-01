package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig as PbEngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.SplitResponse
import com.ridi.oss.proxymonster.analyzer.pb.splitRequest
import com.ridi.oss.sqlglotgo.Sqlglot

/**
 * Cut a batch into its statements at the target's own boundaries — null when it cannot be split safely,
 * and the caller denies. [engineConfig] is the config analysis uses, since the dialect decides where a
 * statement ends: `SELECT "a;b"` is two statements under ANSI_QUOTES and one otherwise.
 *
 *   SELECT 'a;b' FROM t; SELECT 2  ->  ["SELECT 'a;b' FROM t", "SELECT 2"]
 */
fun splitStatements(sql: String, engineConfig: PbEngineConfig): List<String>? = try {
    // Protobuf encodes an unpaired surrogate as `?`, so Go would split SQL the caller never wrote.
    if (!Sqlglot.hasWellFormedUtf16(sql)) return null
    val request = splitRequest {
        this.sql = sql
        this.engineConfig = engineConfig
    }
    val response = SplitResponse.parseFrom(Sqlglot.splitStatements(request.toByteArray()))
    if (response.ok) response.statementsList.toList() else null
} catch (_: Throwable) {
    null
}
