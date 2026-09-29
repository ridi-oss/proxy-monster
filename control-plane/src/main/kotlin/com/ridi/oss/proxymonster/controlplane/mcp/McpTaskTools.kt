package com.ridi.oss.proxymonster.controlplane.mcp

import com.ridi.oss.proxymonster.controlplane.ApiError
import com.ridi.oss.proxymonster.controlplane.ApprovalService
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.CreateApprovalInput
import com.ridi.oss.proxymonster.controlplane.EditorTaskService
import com.ridi.oss.proxymonster.controlplane.EngineWireSerializer
import com.ridi.oss.proxymonster.controlplane.QueryResultMeta
import com.ridi.oss.proxymonster.controlplane.QueryResultView
import com.ridi.oss.proxymonster.controlplane.ResultPage
import com.ridi.oss.proxymonster.controlplane.TaskServiceException
import com.ridi.oss.proxymonster.controlplane.serviceNotFound
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.AuditSource
import com.ridi.oss.proxymonster.controlplane.management.DatasourceManagementService
import com.ridi.oss.proxymonster.controlplane.mayConnect
import com.ridi.oss.proxymonster.grpc.Engine
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
internal data class ConnectableDatasource(
    val name: String,
    @Serializable(with = EngineWireSerializer::class) val engine: Engine,
    val defaultSchemas: List<String>,
)

/** A run_query answer: the task, its per-statement metadata, and the first page of the last result set. */
@Serializable
internal data class RunQueryResult(
    val taskId: Long,
    val status: String,
    val statements: List<QueryResultMeta>,
    val page: QueryResultView? = null,
    val pageError: String? = null,
    val statusError: String? = null,
)

/**
 * The query and approval tools. Each call runs the same service, and so the same Cedar gate on the same REST
 * channel, as the console route it mirrors; only the OAuth scope is checked before it.
 */
internal class McpTaskTools(
    private val core: ControlPlaneCore,
    private val datasources: DatasourceManagementService,
    private val editorTasks: EditorTaskService,
    private val approvals: ApprovalService,
) {
    suspend fun execute(tool: String, args: JsonObject, ctx: McpRequestContext): JsonObject {
        val p = ctx.principal
        val ip = ctx.requesterIp
        return when (tool) {
            "list_connectable_datasources" -> structured(
                core.datasourceStore.list()
                    .filter { mayConnect(core.authz, core.roleResolver, p, ip, it) }
                    .map { ConnectableDatasource(it.name, it.engine, it.defaultSchemas) },
            )
            "describe_datasource" -> {
                val ds = datasource(args.requiredString("datasource"))
                if (!mayConnect(core.authz, core.roleResolver, p, ip, ds)) {
                    throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("datasource.not_connectable"))
                }
                structured(datasources.browseCatalog(ds.name))
            }
            "run_query" -> structured(runQuery(p, ip, args))
            "get_query_result" -> structured(
                editorTasks.result(p, ip, args.requiredLong("taskId"), args.int("statement"), page(args)),
            )
            "get_query_status" -> structured(editorTasks.status(p, ip, args.requiredLong("taskId")))
            "cancel_query" -> structured(editorTasks.cancel(p, ip, args.requiredLong("taskId")))
            "discover_roles" -> structured(
                approvals.discoverRoles(p, ip, datasource(args.requiredString("datasource")).id, args.requiredString("sql")),
            )
            "request_approval" -> {
                val decisionId = args.long("decisionId")
                val dsName = args.string("datasource")
                val sql = args.string("sql")
                // Before any name lookup, so an unknown role or datasource is no oracle past the exclusivity check.
                if ((decisionId != null) == (dsName != null || sql != null)) {
                    throw TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.exactly_one_source_required"))
                }
                val input = CreateApprovalInput(
                    sourceDecisionId = decisionId,
                    datasourceId = dsName?.let { datasource(it).id },
                    sql = sql,
                    title = args.string("title"),
                    reason = args.requiredString("reason"),
                )
                structured(approvals.create(p, ip, actor(ctx), input, roleName = args.requiredString("roleName")))
            }
            "list_my_approvals" -> structured(approvals.listOwn(p, args.string("status")))
            "list_approval_inbox" -> structured(approvals.inbox(p, ip))
            "get_approval" -> structured(approvals.detail(p, ip, args.requiredLong("id")))
            "approve_approval" -> structured(approvals.approve(p, ip, actor(ctx), args.requiredLong("id")))
            "reject_approval" -> structured(
                approvals.reject(p, ip, actor(ctx), args.requiredLong("id"), args.requiredString("reason")),
            )
            "execute_approval" -> structured(approvals.execute(p, ip, args.requiredLong("id")).first)
            "get_approval_result" -> structured(
                approvals.result(p, ip, args.requiredLong("id"), args.int("statement"), page(args)),
            )
            "cancel_approval" -> structured(approvals.cancel(p, ip, args.requiredLong("id")))
            else -> throw McpInputException()
        }
    }

    // Waits briefly so a quick query answers in one call; a slower one returns its taskId to poll.
    private suspend fun runQuery(p: String, ip: String?, args: JsonObject): RunQueryResult {
        val sub = editorTasks.submitOneShot(
            p, ip, args.requiredString("datasource"), args.requiredString("sql"), args.int("maxRows") ?: DEFAULT_MAX_ROWS,
        )
        withTimeoutOrNull(RUN_WAIT_MS) { sub.job.join() }
        val taskId = sub.response.taskId
        // The statements already ran, so a later failure still answers with the taskId rather than an error.
        val st = try {
            editorTasks.status(p, ip, taskId)
        } catch (e: TaskServiceException) {
            return RunQueryResult(taskId, STATUS_UNKNOWN, emptyList(), statusError = e.error.code)
        }
        var page: QueryResultView? = null
        var pageError: String? = null
        if (st.status == "EXECUTED") {
            val done = st.statements.filter { it.status == "DONE" }
            (done.lastOrNull { (it.rowCount ?: 0) > 0 } ?: done.lastOrNull { it.columns.isNotEmpty() })?.let { last ->
                try {
                    page = editorTasks.result(p, ip, taskId, last.ordinal, ResultPage(0, DEFAULT_PAGE))
                } catch (e: TaskServiceException) {
                    pageError = e.error.code
                }
            }
        }
        return RunQueryResult(taskId, st.status, st.statements, page, pageError)
    }

    private fun page(args: JsonObject) = ResultPage(
        offset = args.int("offset")?.coerceAtLeast(0) ?: 0,
        limit = (args.int("limit") ?: DEFAULT_PAGE).coerceIn(1, MAX_PAGE),
    )

    private fun actor(ctx: McpRequestContext) =
        AuditActor(ctx.principal, core.roleResolver.resolve(ctx.principal).sorted(), ctx.requesterIp, AuditSource.MCP)

    private fun datasource(name: String) = core.datasourceStore.getByName(name) ?: throw serviceNotFound("datasource")

    private companion object {
        const val RUN_WAIT_MS = 10_000L
        const val STATUS_UNKNOWN = "UNKNOWN"
        const val DEFAULT_MAX_ROWS = 500
        const val DEFAULT_PAGE = 200
        const val MAX_PAGE = 1000
    }
}
