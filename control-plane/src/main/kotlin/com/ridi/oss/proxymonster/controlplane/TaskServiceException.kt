package com.ridi.oss.proxymonster.controlplane

import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond

/** A transport-neutral task/approval failure: the HTTP status REST answers with and the [ApiError] body. */
class TaskServiceException(val status: HttpStatusCode, val error: ApiError) : RuntimeException(error.code)

internal suspend fun ApplicationCall.respondServiceError(e: TaskServiceException) = respond(e.status, e.error)

internal fun notFoundError(resource: String) = ApiError("common.not_found", mapOf("resource" to resource))

internal fun serviceNotFound(resource: String) = TaskServiceException(HttpStatusCode.NotFound, notFoundError(resource))

internal fun serviceForbidden() = TaskServiceException(HttpStatusCode.Forbidden, ApiError("common.forbidden"))

internal fun unsplittableSql() = TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.unsplittable_sql"))

internal fun resultStorageNotConfigured() =
    TaskServiceException(HttpStatusCode.ServiceUnavailable, ApiError("approval.result_storage_not_configured"))

