package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.ColumnSpec as PbColumnSpec
import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig as PbEngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.Namespace as PbNamespace
import com.ridi.oss.proxymonster.analyzer.pb.FailureClass
import com.ridi.oss.proxymonster.analyzer.pb.StatementFacts
import com.ridi.oss.proxymonster.analyzer.pb.statementFacts
import com.ridi.oss.proxymonster.analyzer.pb.analyzeRequest
import com.ridi.oss.sqlglotgo.Sqlglot

/**
 * Layer-1 analyzer backed by the **sqlglot-go** column-lineage probe, called in-process through its
 * JVM binding (`com.ridi.oss.sqlglotgo.Sqlglot`, Foreign Function & Memory API → a Go c-shared
 * library). The native probe is a pure, thread-safe function of its inputs, so there is nothing to
 * warm up or serialize. The FFM boundary itself speaks protobuf (analyzer.proto) rather than
 * hand-rolled JSON — this object owns building the request message and parsing the [StatementFacts]
 * response.
 *
 * Fail-closed on every axis: the Go side never panics and returns a valid fail-closed [StatementFacts]
 * for malformed input, and any binding/parse error here also surfaces as an unresolved [StatementFacts]
 * (→ DENY), never an escaped exception (which would bypass the decision/audit contract). Requires a
 * JDK 24+ runtime (the bytecode target; FFM); run/test tasks pass `--enable-native-access=ALL-UNNAMED`.
 */
object SqlglotProbe {
    /**
     * Analyze [sql] against the [namespace], flat [catalog], and [engineConfig] an [Analyzer] built
     * once at construction (reused across calls; only sql varies per call — the engine identity,
     * version, and settings are fixed for the request). Go owns all engine-specific validation from
     * engineConfig alone (e.g. failing MySQL analysis closed without a parseable version). Analyzer
     * output identities are always `catalog.schema.table.column`.
     */
    fun analyze(sql: String, namespace: PbNamespace, catalog: List<PbColumnSpec>, engineConfig: PbEngineConfig): StatementFacts =
        try {
            val request = analyzeRequest {
                this.sql = sql
                this.namespace = namespace
                this.catalog.addAll(catalog)
                this.engineConfig = engineConfig
            }
            StatementFacts.parseFrom(Sqlglot.analyzeStatement(request.toByteArray()))
        } catch (e: Throwable) {
            statementFacts {
                resolved = false
                failureClass = FailureClass.FAILURE_CLASS_UNANALYZABLE
                failedStage = "LINEAGE"
                detail = (e.message ?: e.javaClass.simpleName).take(150)
            }
        }
}
