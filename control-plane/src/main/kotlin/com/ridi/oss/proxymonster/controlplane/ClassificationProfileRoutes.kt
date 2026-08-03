package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.requireAdmin
import com.ridi.oss.proxymonster.controlplane.management.ClassificationProfileManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put

/**
 * Classification profiles and their datasource attachments.
 *
 * Keyed by name rather than id throughout: a profile is written from a declarative source that knows
 * the name it means, not a generated id. Gated on `admin.datasources` like the per-column
 * classification routes — a profile rule is the same authority applied to many datasources at once.
 */
fun Route.classificationProfileRoutes(
    config: Config,
    authz: Authz,
    store: ClassificationProfileStore,
    datasourceStore: DatasourceStore,
    management: ClassificationProfileManagementService =
        ClassificationProfileManagementService(store, datasourceStore),
) {
    get("/api/classification-profiles") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@get
        call.respond(management.listProfiles())
    }
    post("/api/classification-profiles") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@post
        val input = call.receive<ClassificationProfileInput>()
        try {
            call.respond(HttpStatusCode.Created, management.createProfile(input))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    get("/api/classification-profiles/{name}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@get
        val name = call.parameters["name"] ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(management.getProfile(name))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    put("/api/classification-profiles/{name}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@put
        val name = call.parameters["name"] ?: return@put call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<ClassificationProfileInput>()
        try {
            call.respond(management.updateProfile(name, input))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    delete("/api/classification-profiles/{name}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@delete
        val name = call.parameters["name"] ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            management.deleteProfile(name)
            call.respond(HttpStatusCode.NoContent)
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }

    get("/api/classification-profiles/{name}/rules") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@get
        val name = call.parameters["name"] ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(management.listRules(name))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    put("/api/classification-profiles/{name}/rules") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@put
        val name = call.parameters["name"] ?: return@put call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<ClassificationProfileRuleInput>()
        try {
            call.respond(management.setRule(name, input))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    delete("/api/classification-profiles/{name}/rules") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@delete
        val name = call.parameters["name"] ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val body = call.receive<ClassificationProfileRuleDelete>()
        try {
            management.clearRule(name, body.schema, body.table, body.column)
            call.respond(HttpStatusCode.NoContent)
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }

    get("/api/datasources/{id}/classification-profiles") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@get
        val ds = call.datasourceByIdParam(datasourceStore) ?: return@get
        call.respond(management.listAttachments(ds.name))
    }
    post("/api/datasources/{id}/classification-profiles") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@post
        val ds = call.datasourceByIdParam(datasourceStore) ?: return@post
        val input = call.receive<ProfileAttachmentInput>()
        try {
            call.respond(management.attach(ds.name, input))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    // Detaching reverts every column the profile alone classified to cleartext on the next decision,
    // so the profile to remove is named explicitly and an unknown one is a 404 rather than a no-op.
    delete("/api/datasources/{id}/classification-profiles/{profile}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@delete
        val ds = call.datasourceByIdParam(datasourceStore) ?: return@delete
        val profile = call.parameters["profile"]
            ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        try {
            call.respond(management.detach(ds.name, profile))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
}

private suspend fun io.ktor.server.application.ApplicationCall.datasourceByIdParam(
    store: DatasourceStore,
): Datasource? {
    val id = parameters["id"]?.toLongOrNull()
    if (id == null) {
        respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        return null
    }
    val datasource = store.get(id)
    if (datasource == null) {
        respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
        return null
    }
    return datasource
}
