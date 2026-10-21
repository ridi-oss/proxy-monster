package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.source.GitHubRequestsInput
import com.ridi.oss.proxymonster.controlplane.source.GitHubRequestsResponse
import com.ridi.oss.proxymonster.controlplane.source.GitHubSourceFlow
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post

/** The GitHub Action's call (docs/sql-from-github.md): file a pull request's SQL files. */
fun Route.githubSourceRoutes(config: Config, tokenStore: TokenStore, flow: GitHubSourceFlow) {
    post("/api/github/requests") {
        val workload = call.requireWorkload(config, tokenStore) ?: return@post
        val body = runCatching { call.receive<GitHubRequestsInput>() }.getOrNull()
            ?: return@post call.fieldRequired("repository", "pr", "datasource", "schema", "role", "headSha", "files")
        try {
            call.respond(GitHubRequestsResponse(flow.file(workload, body), flow.checkName))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }
}
