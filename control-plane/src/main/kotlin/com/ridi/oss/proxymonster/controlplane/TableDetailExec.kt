package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.ControlTableDetailMsg
import com.ridi.oss.proxymonster.grpc.ProxyTableDetailMsg
import com.ridi.oss.proxymonster.grpc.controlTableDetailMsg
import com.ridi.oss.proxymonster.grpc.tableDetailClose
import com.ridi.oss.proxymonster.probe.TableDetail
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

internal const val TABLE_DETAIL_EXCHANGE_TIMEOUT_MS = 30_000L

/** One HTTP table-detail request waiting for the proxy to dial its dedicated stream. */
data class PendingTableDetail(
    val sessionId: String,
    val ready: CompletableDeferred<AttachedTableDetail>,
)

/** The two directions of one claimed table-detail stream. */
data class AttachedTableDetail(
    val outbound: SendChannel<ControlTableDetailMsg>,
    val inbound: Channel<ProxyTableDetailMsg>,
)

/** Claim-once correlation for proxy-dialed `TableDetailExec` streams. */
class TableDetailChannelRegistry {
    private val pending = ConcurrentHashMap<String, PendingTableDetail>()

    fun register(session: PendingTableDetail) {
        check(pending.putIfAbsent(session.sessionId, session) == null) {
            "table-detail session '${session.sessionId}' is already registered"
        }
    }

    fun attach(sessionId: String, outbound: SendChannel<ControlTableDetailMsg>): AttachedTableDetail? {
        val session = pending.remove(sessionId) ?: return null
        val attached = AttachedTableDetail(outbound, Channel(Channel.BUFFERED))
        session.ready.complete(attached)
        return attached
    }

    fun remove(sessionId: String): PendingTableDetail? = pending.remove(sessionId)
}

sealed class TableDetailExecException(message: String, cause: Throwable? = null) : Exception(message, cause)

class NoTableDetailProxyAttachedException : TableDetailExecException("no proxy is attached to this datasource")

class ProxyTableDetailTimeoutException(cause: Throwable? = null) :
    TableDetailExecException("the proxy table-detail channel timed out", cause)

class ProxyTableDetailException(message: String, cause: Throwable? = null) :
    TableDetailExecException(message, cause)

/** Fetches one live table detail over a proxy-dialed channel and overlays persisted classifications. */
class TableDetailService(private val core: ControlPlaneCore) {
    private val json = Json

    suspend fun fetch(dsName: String, schema: String, table: String): TableDetail? {
        val datasource = core.datasourceStore.getByName(dsName) ?: return null
        // The schema the proxy's live detail must report back under: the "public" default selector maps to
        // this engine's default schema (MySQL's database), any other value is an explicit schema/database.
        val expectedSchema = datasource.engine.resolveSchema(schema, datasource.dbName)
        val sessionId = UUID.randomUUID().toString()
        val pending = PendingTableDetail(sessionId, CompletableDeferred())
        var registered = false
        var attached: AttachedTableDetail? = null

        try {
            core.tableDetailChannels.register(pending)
            registered = true
            when (core.proxyEventsHub.requestOpenTableDetail(dsName, sessionId, schema, table)) {
                ProxyEventsHub.Dispatch.SENT -> Unit
                ProxyEventsHub.Dispatch.NOT_ATTACHED, ProxyEventsHub.Dispatch.WEDGED -> {
                throw NoTableDetailProxyAttachedException()
                }
            }

            attached = try {
                withTimeout(DIAL_TIMEOUT_MS) { pending.ready.await() }
            } catch (e: TimeoutCancellationException) {
                throw ProxyTableDetailTimeoutException(e)
            }

            val detail = try {
                withTimeout(TABLE_DETAIL_EXCHANGE_TIMEOUT_MS) { collectResponse(attached.inbound) }
            } catch (e: TimeoutCancellationException) {
                throw ProxyTableDetailTimeoutException(e)
            }
            if (detail == null) return null
            // The proxy's live detail must come back under the resolved schema and for the requested table;
            // anything else is a channel/response mixup.
            if (detail.schema != expectedSchema || detail.table != table) {
                throw ProxyTableDetailException("proxy returned table detail for an unexpected table")
            }

            val classifications = core.datasourceStore.catalog(datasource.id)
                .asSequence()
                .filter { it.schema == detail.schema && it.table == detail.table }
                .associate { it.column to it.classification }
            return detail.copy(
                columns = detail.columns.map { column ->
                    column.copy(classification = classifications[column.name])
                },
            )
        } finally {
            // Resolve the same attach-vs-timeout race as RunExec: either remove wins while pending, or
            // attach already completed [ready] and cleanup obtains the claimed outbound channel.
            if (registered && attached == null && core.tableDetailChannels.remove(sessionId) == null) {
                attached = withContext(NonCancellable) { pending.ready.await() }
            }
            try {
                attached?.outbound?.trySend(controlTableDetailMsg { close = tableDetailClose {} })
            } finally {
                if (registered) core.tableDetailChannels.remove(sessionId)
            }
        }
    }

    private suspend fun collectResponse(inbound: Channel<ProxyTableDetailMsg>): TableDetail? {
        for (message in inbound) {
            when {
                message.hasResult() -> {
                    val payload = message.result.json
                    if (payload == "null") return null
                    return try {
                        json.decodeFromString<TableDetail>(payload)
                    } catch (e: Exception) {
                        currentCoroutineContext().ensureActive()
                        throw ProxyTableDetailException("proxy sent invalid table-detail JSON", e)
                    }
                }

                message.hasError() -> throw ProxyTableDetailException(
                    message.error.message.ifBlank { "proxy table introspection failed" },
                )

                message.hasSessionReady() -> throw ProxyTableDetailException(
                    "proxy sent TableDetailReady more than once",
                )

                else -> throw ProxyTableDetailException("proxy sent an empty table-detail message")
            }
        }
        throw ProxyTableDetailException("proxy table-detail stream closed before a terminal response")
    }
}
