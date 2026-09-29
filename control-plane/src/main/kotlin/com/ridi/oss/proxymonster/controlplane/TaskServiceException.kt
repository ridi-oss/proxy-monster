package com.ridi.oss.proxymonster.controlplane

import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond
import kotlinx.serialization.Serializable

/** A transport-neutral task/approval failure: the HTTP status REST answers with and the [ApiError] body. */
class TaskServiceException(val status: HttpStatusCode, val error: ApiError) : RuntimeException(error.code)

internal suspend fun ApplicationCall.respondServiceError(e: TaskServiceException) = respond(e.status, e.error)

internal fun notFoundError(resource: String) = ApiError("common.not_found", mapOf("resource" to resource))

internal fun serviceNotFound(resource: String) = TaskServiceException(HttpStatusCode.NotFound, notFoundError(resource))

internal fun serviceForbidden() = TaskServiceException(HttpStatusCode.Forbidden, ApiError("common.forbidden"))

internal fun unsplittableSql() = TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.unsplittable_sql"))

internal fun resultStorageNotConfigured() =
    TaskServiceException(HttpStatusCode.ServiceUnavailable, ApiError("approval.result_storage_not_configured"))

/** A window over a released result: rows [offset, offset + limit). */
@Serializable
data class ResultPage(val offset: Int, val limit: Int)

/** Slices this release to [p]; the Int is the next page's offset, null when there is no page or no more rows. */
internal fun ResultViewDecision.Allowed.page(p: ResultPage?): Pair<ResultViewDecision.Allowed, Int?> {
    if (p == null) return this to null
    val off = p.offset.coerceAtLeast(0)
    val lim = p.limit.coerceAtLeast(1)
    val next = (off.toLong() + lim).takeIf { it < rows.size }?.toInt()
    return copy(rows = rows.drop(off).take(lim)) to next
}
