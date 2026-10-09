package com.ridi.oss.proxymonster.controlplane.source

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.ridi.oss.proxymonster.controlplane.GitHubConfig
import com.ridi.oss.proxymonster.controlplane.GitHubIdentityResolver
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.readRawBytes
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.appendPathSegments
import io.ktor.http.content.TextContent
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.Date

/** A [SourceAdapter] acting as a GitHub App installed on the repository owner. All calls are serialized. */
class GitHubAdapter(
    private val config: GitHubConfig,
    private val directory: PrincipalDirectory,
    private val http: HttpClient = githubHttpClient(),
    private val clock: Clock = Clock.systemUTC(),
) : SourceAdapter {
    private val apiUrl = config.apiUrl.trimEnd('/')
    private val graphqlUrl = Url(
        if (apiUrl.endsWith("/api/v3")) apiUrl.removeSuffix("/api/v3") + "/api/graphql" else "$apiUrl/graphql",
    )
    private val appKey: RSAPrivateKey = parseRsaPrivateKey(config.privateKeyPem)
    private val mutex = Mutex()
    private val installations = HashMap<String, Long>()
    private val tokens = HashMap<Long, InstallationToken>()
    private val requiredChecksCache = HashMap<Pair<String, String>, Pair<Instant, Set<String>>>()

    @Volatile
    override var rateLimit: RateLimit? = null
        private set

    private class InstallationToken(val token: String, val expiresAt: Instant)

    override suspend fun readPullRequests(repo: Repo, numbers: List<Int>): Map<Int, PullRequest> {
        if (numbers.isEmpty()) return emptyMap()
        return mutex.withLock {
            val installation = repoInstallation(repo)
            val aliases = numbers.indices.joinToString(" ") { i ->
                "pr$i: pullRequest(number:\$n$i) { ${prSelection("\$n$i")} }"
            }
            val params = numbers.indices.joinToString("") { i -> ", \$n$i: Int!" }
            val query = "query(\$owner: String!, \$name: String!$params) { $RATE_LIMIT " +
                "repository(owner:\$owner, name:\$name) { $aliases } }"
            val variables = buildJsonObject {
                put("owner", repo.owner)
                put("name", repo.name)
                numbers.forEachIndexed { i, n -> put("n$i", n) }
            }
            val response = graphql(installation, query, variables)
            val missing = HashSet<String>()
            val errors = graphqlErrors(response)
            if (errors.isNotEmpty()) {
                val other = errors.filterNot { it.type == "NOT_FOUND" && it.path.size == 2 && PR_ALIAS.matches(it.path[1]) }
                if (other.isNotEmpty()) throw graphqlFailure(other)
                errors.forEach { missing += it.path[1] }
            }
            val repository = response.obj("data")?.obj("repository") ?: error("GitHub returned no repository")
            buildMap {
                numbers.forEachIndexed { i, n ->
                    val alias = "pr$i"
                    val node = repository.obj(alias)
                    if (alias in missing || node == null) return@forEachIndexed
                    put(n, readPullRequest(installation, repo, n, node))
                }
            }
        }
    }

    override suspend fun readFile(repo: Repo, ref: String, path: String): ByteArray = mutex.withLock {
        val segments = listOf("repos", repo.owner, repo.name, "contents") + path.split('/').filter { it.isNotEmpty() }
        val url = rest(segments, mapOf("ref" to ref))
        send(repoInstallation(repo), HttpMethod.Get, url, accept = RAW_ACCEPT).readRawBytes()
    }

    override suspend fun compareCommits(repo: Repo, base: String, head: String): CommitRelation = mutex.withLock {
        val url = rest(listOf("repos", repo.owner, repo.name, "compare", "$base...$head"))
        when (val status = parseObject(send(repoInstallation(repo), HttpMethod.Get, url)).string("status")) {
            "ahead" -> CommitRelation.AHEAD
            "identical" -> CommitRelation.IDENTICAL
            "behind" -> CommitRelation.BEHIND
            "diverged" -> CommitRelation.DIVERGED
            else -> error("GitHub returned an unknown comparison status: $status")
        }
    }

    override suspend fun requiredChecks(repo: Repo, branch: String): Set<String> = mutex.withLock {
        val key = "${repo.owner}/${repo.name}".lowercase() to branch
        val now = clock.instant()
        requiredChecksCache[key]?.takeIf { now < it.first.plus(REQUIRED_CHECKS_TTL) }?.let { return@withLock it.second }
        val installation = repoInstallation(repo)
        val contexts = rulesetContexts(installation, repo, branch) + protectionContexts(installation, repo, branch)
        requiredChecksCache[key] = now to contexts
        contexts
    }

    private suspend fun rulesetContexts(installation: Long, repo: Repo, branch: String): Set<String> {
        val contexts = HashSet<String>()
        var page = 1
        while (true) {
            val url = rest(
                listOf("repos", repo.owner, repo.name, "rules", "branches", branch),
                mapOf("per_page" to "$RULES_PAGE", "page" to "$page"),
            )
            val rules = absentOnNotFound { parseArray(send(installation, HttpMethod.Get, url)) } ?: return contexts
            rules.mapNotNull { it as? JsonObject }.filter { it.string("type") == "required_status_checks" }.forEach { rule ->
                rule.obj("parameters")?.array("required_status_checks")
                    ?.forEach { (it as? JsonObject)?.string("context")?.let(contexts::add) }
            }
            if (rules.size < RULES_PAGE) return contexts
            page++
        }
    }

    // The branch endpoint needs only metadata read; its `/protection` sub-resource needs administration.
    private suspend fun protectionContexts(installation: Long, repo: Repo, branch: String): Set<String> {
        val url = rest(listOf("repos", repo.owner, repo.name, "branches", branch))
        val required = absentOnNotFound { parseObject(send(installation, HttpMethod.Get, url)) }
            ?.obj("protection")?.obj("required_status_checks") ?: return emptySet()
        val contexts = required.array("contexts").orEmpty().mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
        val checks = required.array("checks").orEmpty().mapNotNull { (it as? JsonObject)?.string("context") }
        return (contexts + checks).toSet()
    }

    private suspend fun <T> absentOnNotFound(block: suspend () -> T): T? = try {
        block()
    } catch (_: GitHubException.NotFound) {
        null
    }

    override suspend fun postCheck(
        repo: Repo,
        headSha: String,
        name: String,
        status: CheckStatus,
        conclusion: CheckConclusion?,
        title: String,
        summary: String,
    ) {
        require(status != CheckStatus.COMPLETED || conclusion != null) { "a completed check needs a conclusion" }
        mutex.withLock {
            val installation = repoInstallation(repo)
            val lookup = rest(
                listOf("repos", repo.owner, repo.name, "commits", headSha, "check-runs"),
                mapOf("check_name" to name, "filter" to "latest", "app_id" to config.appId),
            )
            val existing = parseObject(send(installation, HttpMethod.Get, lookup))
                .array("check_runs")
                ?.mapNotNull { it as? JsonObject }
                ?.firstOrNull { it.obj("app")?.string("id") == config.appId }
                ?.long("id")
            val body = buildJsonObject {
                put("name", name)
                if (existing == null) put("head_sha", headSha)
                put("status", status.name.lowercase())
                if (status == CheckStatus.COMPLETED) put("conclusion", conclusion!!.name.lowercase())
                putJsonObject("output") {
                    put("title", title)
                    put("summary", summary)
                }
            }
            if (existing != null) {
                send(installation, HttpMethod.Patch, rest(listOf("repos", repo.owner, repo.name, "check-runs", "$existing")), body = body)
            } else {
                send(installation, HttpMethod.Post, rest(listOf("repos", repo.owner, repo.name, "check-runs")), body = body)
            }
        }
    }

    override suspend fun dismissReview(repo: Repo, pr: Int, reviewId: String, message: String) {
        mutex.withLock {
            val url = rest(listOf("repos", repo.owner, repo.name, "pulls", "$pr", "reviews", reviewId, "dismissals"))
            send(
                repoInstallation(repo),
                HttpMethod.Put,
                url,
                body = buildJsonObject {
                    put("message", message)
                    put("event", "DISMISS")
                },
            )
        }
    }

    override suspend fun postComment(repo: Repo, pr: Int, body: String) {
        mutex.withLock { createComment(repoInstallation(repo), repo, pr, body) }
    }

    override suspend fun upsertComment(repo: Repo, pr: Int, marker: String, body: String) {
        mutex.withLock {
            val installation = repoInstallation(repo)
            val markerLine = "<!-- proxy-monster:$marker -->"
            val text = "$markerLine\n$body"
            val existing = findMarkedComment(installation, repo, pr, markerLine)
            if (existing != null) {
                val url = rest(listOf("repos", repo.owner, repo.name, "issues", "comments", "$existing"))
                send(installation, HttpMethod.Patch, url, body = buildJsonObject { put("body", text) })
            } else {
                createComment(installation, repo, pr, text)
            }
        }
    }

    override suspend fun resolveUser(
        org: String,
        user: SourceUser,
        role: MappingRole,
        commitEmails: List<String>,
    ): String? = mutex.withLock {
        for (resolver in config.identity) {
            val principal = when (resolver) {
                GitHubIdentityResolver.EXTERNAL_IDENTITY -> externalIdentity(org, user)
                GitHubIdentityResolver.VERIFIED_EMAIL -> verifiedEmail(org, user)
                GitHubIdentityResolver.COMMIT_EMAIL ->
                    if (role == MappingRole.REVIEWER) null else uniquePrincipalByEmail(commitEmails)
            }
            if (principal != null) return@withLock principal
        }
        null
    }

    private suspend fun externalIdentity(org: String, user: SourceUser): String? {
        val response = orgGraphql(
            org,
            "query(\$org: String!, \$login: String!) { $RATE_LIMIT organization(login:\$org) { samlIdentityProvider { " +
                "externalIdentities(login:\$login, first:1) { nodes { samlIdentity { nameId } } } } } }",
            user,
        ) ?: return null
        val nameId = response.obj("data")?.obj("organization")?.obj("samlIdentityProvider")
            ?.obj("externalIdentities")?.array("nodes")?.firstOrNull()
            ?.let { it as? JsonObject }?.obj("samlIdentity")?.string("nameId")
            ?: return null
        return directory.activePrincipal(nameId)
    }

    private suspend fun verifiedEmail(org: String, user: SourceUser): String? {
        val response = orgGraphql(
            org,
            "query(\$org: String!, \$login: String!) { $RATE_LIMIT user(login:\$login) { " +
                "organizationVerifiedDomainEmails(login:\$org) } }",
            user,
        ) ?: return null
        val emails = response.obj("data")?.obj("user")?.array("organizationVerifiedDomainEmails")
            ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            .orEmpty()
        return uniquePrincipalByEmail(emails)
    }

    /** Null when GitHub reports the lookup as not permitted or not found, so the next resolver runs. */
    private suspend fun orgGraphql(org: String, query: String, user: SourceUser): JsonObject? {
        val response = graphql(
            orgInstallation(org),
            query,
            buildJsonObject {
                put("org", org)
                put("login", user.login)
            },
        )
        val errors = graphqlErrors(response)
        if (errors.isEmpty()) return response
        if (errors.all { it.type in FALL_THROUGH_ERRORS }) return null
        throw graphqlFailure(errors)
    }

    private fun uniquePrincipalByEmail(emails: List<String>): String? =
        emails.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
            .mapNotNull { directory.activePrincipalByEmail(it) }
            .distinct()
            .singleOrNull()

    private suspend fun readPullRequest(installation: Long, repo: Repo, number: Int, node: JsonObject): PullRequest {
        val headSha = node.string("headRefOid") ?: error("GitHub returned a pull request without a head")
        val reviews = drain(installation, repo, number, node.obj("reviews"), ::reviewsSelection) {
            it.obj("reviews") ?: error("GitHub returned no reviews page")
        }.orEmpty()
        val firstFiles = node.obj("files") ?: error("GitHub returned no files for a pull request")
        val files = drain(installation, repo, number, firstFiles, ::filesSelection) {
            it.obj("files") ?: error("GitHub returned no files page")
        }.orEmpty()
        val commit = headCommit(node)
        val checks = if (commit?.string("oid") != headSha) {
            null
        } else {
            drain(installation, repo, number, commit.obj("statusCheckRollup")?.obj("contexts"), { after ->
                "commits(last:1) { nodes { commit { oid ${rollupSelection("\$n", after)} } } }"
            }) { pr ->
                headCommit(pr)?.takeIf { it.string("oid") == headSha }?.obj("statusCheckRollup")?.obj("contexts")
            }
        }
        val state = node.string("state")
        return PullRequest(
            number = number,
            open = state == "OPEN",
            merged = node.boolean("merged") ?: false,
            mergedAt = node.instant("mergedAt"),
            mergeCommit = node.obj("mergeCommit")?.string("oid"),
            headSha = headSha,
            baseRef = node.string("baseRefName") ?: error("GitHub returned a pull request without a base"),
            author = sourceUser(node.obj("author")),
            autoMerge = node.obj("autoMergeRequest")?.let {
                AutoMerge(enabledBy = sourceUser(it.obj("enabledBy")), enabledAt = it.instant("enabledAt"))
            },
            reviews = reviews.map(::review),
            checks = checks?.map(::check),
            files = files.map {
                ChangedFile(it.string("path") ?: error("GitHub returned a file without a path"), fileChange(it.string("changeType")))
            },
        )
    }

    // The rollup belongs to the last commit, which is only the head when nothing was pushed mid-read.
    private fun headCommit(pr: JsonObject): JsonObject? =
        pr.obj("commits")?.array("nodes")?.firstOrNull()?.let { it as? JsonObject }?.obj("commit")

    /** The connection's nodes, following `hasNextPage` with single-PR queries; null when [connection] gives null. */
    private suspend fun drain(
        installation: Long,
        repo: Repo,
        number: Int,
        first: JsonObject?,
        selection: (after: String) -> String,
        connection: (pr: JsonObject) -> JsonObject?,
    ): List<JsonObject>? {
        val nodes = ArrayList<JsonObject>()
        var page = first ?: return null
        while (true) {
            page.array("nodes")?.forEach { (it as? JsonObject)?.let(nodes::add) }
            val info = page.obj("pageInfo")
            if (info?.boolean("hasNextPage") != true) return nodes
            val cursor = info.string("endCursor") ?: error("GitHub returned hasNextPage without a cursor")
            val query = "query(\$owner: String!, \$name: String!, \$n: Int!, \$after: String!) { $RATE_LIMIT " +
                "repository(owner:\$owner, name:\$name) { pullRequest(number:\$n) { ${selection(", after:\$after")} } } }"
            val response = graphql(
                installation,
                query,
                buildJsonObject {
                    put("owner", repo.owner)
                    put("name", repo.name)
                    put("n", number)
                    put("after", cursor)
                },
            )
            val errors = graphqlErrors(response)
            if (errors.isNotEmpty()) throw graphqlFailure(errors)
            val pr = response.obj("data")?.obj("repository")?.obj("pullRequest") ?: error("GitHub returned no pull request page")
            page = connection(pr) ?: return null
        }
    }

    private fun prSelection(numberVar: String): String =
        "number state merged mergedAt mergeCommit { oid } headRefOid baseRefName url " +
            "author { login ... on User { databaseId } ... on Bot { databaseId } } " +
            "autoMergeRequest { enabledAt enabledBy { login ... on User { databaseId } } } " +
            "${reviewsSelection("")} ${filesSelection("")} " +
            "commits(last:1) { nodes { commit { oid ${rollupSelection(numberVar, "")} } } }"

    private fun reviewsSelection(after: String): String =
        "reviews(first:100$after) { pageInfo { hasNextPage endCursor } " +
            "nodes { databaseId state submittedAt url author { login ... on User { databaseId } } } }"

    private fun filesSelection(after: String): String =
        "files(first:100$after) { pageInfo { hasNextPage endCursor } nodes { path changeType } }"

    private fun rollupSelection(numberVar: String, after: String): String =
        "statusCheckRollup { contexts(first:100$after) { pageInfo { hasNextPage endCursor } nodes { __typename " +
            "... on CheckRun { name status conclusion isRequired(pullRequestNumber:$numberVar) } " +
            "... on StatusContext { context state isRequired(pullRequestNumber:$numberVar) } } } }"

    private fun review(node: JsonObject): Review = Review(
        id = node.long("databaseId")?.toString() ?: error("GitHub returned a review without an id"),
        reviewer = sourceUser(node.obj("author")),
        state = ReviewState.entries.firstOrNull { it.name == node.string("state") }
            ?: error("GitHub returned an unknown review state"),
        submittedAt = node.instant("submittedAt"),
        url = node.string("url").orEmpty(),
    )

    private fun check(node: JsonObject): Check {
        val required = node.boolean("isRequired") ?: false
        return if (node.string("__typename") == "StatusContext") {
            val (status, conclusion) = when (node.string("state")) {
                "SUCCESS" -> CheckStatus.COMPLETED to CheckConclusion.SUCCESS
                "FAILURE", "ERROR" -> CheckStatus.COMPLETED to CheckConclusion.FAILURE
                else -> CheckStatus.IN_PROGRESS to null
            }
            Check(node.string("context").orEmpty(), required, status, conclusion)
        } else {
            val status = when (node.string("status")) {
                "IN_PROGRESS" -> CheckStatus.IN_PROGRESS
                "COMPLETED" -> CheckStatus.COMPLETED
                else -> CheckStatus.QUEUED
            }
            val conclusion = node.string("conclusion")?.let { c ->
                CheckConclusion.entries.firstOrNull { it.name == c } ?: CheckConclusion.FAILURE
            }
            Check(node.string("name").orEmpty(), required, status, conclusion)
        }
    }

    private fun fileChange(type: String?): FileChange =
        FileChange.entries.firstOrNull { it.name == type } ?: FileChange.CHANGED

    private fun sourceUser(actor: JsonObject?): SourceUser? {
        val login = actor?.string("login") ?: return null
        val id = actor.long("databaseId") ?: return null
        if (login == "ghost") return null
        return SourceUser(id.toString(), login)
    }

    private suspend fun findMarkedComment(installation: Long, repo: Repo, pr: Int, markerLine: String): Long? {
        var page = 1
        while (true) {
            val url = rest(
                listOf("repos", repo.owner, repo.name, "issues", "$pr", "comments"),
                mapOf("per_page" to "$COMMENT_PAGE", "page" to "$page"),
            )
            val comments = parseArray(send(installation, HttpMethod.Get, url)).mapNotNull { it as? JsonObject }
            comments.firstOrNull {
                it.obj("performed_via_github_app")?.string("id") == config.appId &&
                    it.string("body")?.startsWith(markerLine) == true
            }?.let { return it.long("id") }
            if (comments.size < COMMENT_PAGE) return null
            page++
        }
    }

    private suspend fun createComment(installation: Long, repo: Repo, pr: Int, body: String) {
        val url = rest(listOf("repos", repo.owner, repo.name, "issues", "$pr", "comments"))
        send(installation, HttpMethod.Post, url, body = buildJsonObject { put("body", body) })
    }

    private suspend fun graphql(installation: Long, query: String, variables: JsonObject): JsonObject {
        val body = buildJsonObject {
            put("query", query)
            put("variables", variables)
        }
        val response = parseObject(send(installation, HttpMethod.Post, graphqlUrl, body = body))
        response.obj("data")?.obj("rateLimit")?.let { limit ->
            val remaining = limit.long("remaining")
            val resetAt = limit.instant("resetAt")
            if (remaining != null && resetAt != null) rateLimit = RateLimit(remaining.toInt(), resetAt)
        }
        return response
    }

    private class GraphqlError(val type: String, val path: List<String>, val message: String)

    private fun graphqlErrors(response: JsonObject): List<GraphqlError> =
        response.array("errors")?.mapNotNull { it as? JsonObject }?.map { e ->
            GraphqlError(
                type = e.string("type") ?: "UNKNOWN",
                path = e.array("path")?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty(),
                message = e.string("message").orEmpty(),
            )
        }.orEmpty()

    private fun graphqlFailure(errors: List<GraphqlError>): GitHubException.Graphql {
        val types = errors.map { it.type }
        return GitHubException.Graphql(
            "POST ${graphqlUrl.encodedPath} -> GraphQL errors $types: ${errors.first().message.take(MESSAGE_LIMIT)}",
            types,
        )
    }

    private suspend fun repoInstallation(repo: Repo): Long =
        installation(repo.owner, rest(listOf("repos", repo.owner, repo.name, "installation")))

    private suspend fun orgInstallation(org: String): Long = installation(org, rest(listOf("orgs", org, "installation")))

    private suspend fun installation(owner: String, lookup: Url): Long {
        val key = owner.lowercase()
        installations[key]?.let { return it }
        val response = exchange(HttpMethod.Get, lookup, appJwt(), JSON_ACCEPT, null)
        checkStatus(response, HttpMethod.Get, lookup)
        val id = parseObject(response).long("id") ?: error("GitHub returned an installation without an id")
        installations[key] = id
        return id
    }

    private suspend fun installationToken(installation: Long): String {
        val now = clock.instant()
        tokens[installation]?.takeIf { now < it.expiresAt.minus(TOKEN_MARGIN) }?.let { return it.token }
        val url = rest(listOf("app", "installations", "$installation", "access_tokens"))
        val response = exchange(HttpMethod.Post, url, appJwt(), JSON_ACCEPT, null)
        checkStatus(response, HttpMethod.Post, url)
        val body = parseObject(response)
        val token = InstallationToken(
            token = body.string("token") ?: error("GitHub returned no installation token"),
            expiresAt = body.instant("expires_at") ?: error("GitHub returned no installation token expiry"),
        )
        tokens[installation] = token
        return token.token
    }

    private fun appJwt(): String {
        val now = clock.instant()
        val claims = JWTClaimsSet.Builder()
            .issuer(config.appId)
            // Backdated for clock drift, as GitHub recommends; GitHub rejects an exp over 10 minutes out.
            .issueTime(Date.from(now.minusSeconds(60)))
            .expirationTime(Date.from(now.plus(Duration.ofMinutes(9))))
            .build()
        return SignedJWT(JWSHeader(JWSAlgorithm.RS256), claims).apply { sign(RSASSASigner(appKey)) }.serialize()
    }

    /** A call with the installation token; a 401 drops the cached token and retries once with a fresh one. */
    private suspend fun send(
        installation: Long,
        method: HttpMethod,
        url: Url,
        accept: String = JSON_ACCEPT,
        body: JsonElement? = null,
    ): HttpResponse {
        var response = exchange(method, url, installationToken(installation), accept, body)
        if (response.status == HttpStatusCode.Unauthorized) {
            tokens.remove(installation)
            response = exchange(method, url, installationToken(installation), accept, body)
        }
        checkStatus(response, method, url)
        return response
    }

    private suspend fun exchange(method: HttpMethod, url: Url, bearer: String, accept: String, body: JsonElement?): HttpResponse =
        http.request(url) {
            this.method = method
            header(HttpHeaders.Accept, accept)
            header("X-GitHub-Api-Version", API_VERSION)
            header(HttpHeaders.UserAgent, USER_AGENT)
            header(HttpHeaders.Authorization, "Bearer $bearer")
            if (body != null) setBody(TextContent(json.encodeToString(JsonElement.serializer(), body), ContentType.Application.Json))
        }

    private suspend fun checkStatus(response: HttpResponse, method: HttpMethod, url: Url) {
        val status = response.status.value
        if (status in 200..299) return
        val detail = runCatching { (json.parseToJsonElement(response.bodyAsText()) as? JsonObject)?.string("message") }
            .getOrNull()?.take(MESSAGE_LIMIT)
        val message = "${method.value} ${url.encodedPath} -> $status" + (detail?.let { ": $it" } ?: "")
        val limited = response.headers["x-ratelimit-remaining"] == "0" || response.headers[HttpHeaders.RetryAfter] != null
        throw when {
            status == 401 -> GitHubException.Unauthorized(message)
            (status == 403 && limited) || status == 429 -> GitHubException.RateLimited(message, rateLimitReset(response))
            status == 403 -> GitHubException.Forbidden(message)
            status == 404 -> GitHubException.NotFound(message)
            status in 400..499 -> GitHubException.Unprocessable(message)
            else -> GitHubException.Server(message, status)
        }
    }

    private fun rateLimitReset(response: HttpResponse): Instant? =
        response.headers["x-ratelimit-reset"]?.toLongOrNull()?.let(Instant::ofEpochSecond)
            ?: response.headers[HttpHeaders.RetryAfter]?.toLongOrNull()?.let { clock.instant().plusSeconds(it) }

    private fun rest(segments: List<String>, query: Map<String, String> = emptyMap()): Url =
        URLBuilder(apiUrl).apply {
            appendPathSegments(segments, encodeSlash = true)
            query.forEach { (k, v) -> parameters.append(k, v) }
        }.build()

    private suspend fun parseObject(response: HttpResponse): JsonObject =
        json.parseToJsonElement(response.bodyAsText()) as? JsonObject ?: error("GitHub returned a non-object body")

    private suspend fun parseArray(response: HttpResponse): JsonArray =
        json.parseToJsonElement(response.bodyAsText()) as? JsonArray ?: error("GitHub returned a non-array body")

    private companion object {
        const val API_VERSION = "2022-11-28"
        const val USER_AGENT = "proxy-monster"
        const val JSON_ACCEPT = "application/vnd.github+json"
        const val RAW_ACCEPT = "application/vnd.github.raw+json"
        const val RATE_LIMIT = "rateLimit { remaining resetAt }"
        const val COMMENT_PAGE = 100
        const val RULES_PAGE = 100
        val REQUIRED_CHECKS_TTL: Duration = Duration.ofMinutes(5)
        const val MESSAGE_LIMIT = 200
        val TOKEN_MARGIN: Duration = Duration.ofSeconds(60)
        val PR_ALIAS = Regex("pr\\d+")
        val FALL_THROUGH_ERRORS = setOf("FORBIDDEN", "NOT_FOUND", "INSUFFICIENT_SCOPES")
        val json = Json { ignoreUnknownKeys = true }

        fun JsonObject.obj(key: String): JsonObject? = this[key] as? JsonObject

        fun JsonObject.array(key: String): JsonArray? = this[key] as? JsonArray

        fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull

        fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.longOrNull

        fun JsonObject.boolean(key: String): Boolean? = (this[key] as? JsonPrimitive)?.booleanOrNull

        fun JsonObject.instant(key: String): Instant? = string(key)?.let(Instant::parse)
    }
}

/** Reads a PKCS#8 (`BEGIN PRIVATE KEY`) or PKCS#1 (`BEGIN RSA PRIVATE KEY`, GitHub's download) PEM. */
internal fun parseRsaPrivateKey(pem: String): RSAPrivateKey {
    try {
        val text = pem.replace("\\n", "\n")
        val der = Base64.getMimeDecoder().decode(
            text.replace(Regex("-----(BEGIN|END) [A-Z ]+-----"), "").replace(Regex("\\s"), ""),
        )
        val pkcs8 = if ("BEGIN RSA PRIVATE KEY" in text) wrapPkcs1(der) else der
        return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(pkcs8)) as RSAPrivateKey
    } catch (_: Exception) {
        throw IllegalArgumentException("invalid GitHub App private key")
    }
}

// The JDK reads only PKCS#8, so PKCS#1 goes in a PrivateKeyInfo envelope with the rsaEncryption algorithm id.
private fun wrapPkcs1(pkcs1: ByteArray): ByteArray {
    val version = der(0x02, byteArrayOf(0))
    val rsaEncryption = byteArrayOf(0x06, 0x09, 0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x01)
    val algorithm = der(0x30, rsaEncryption + byteArrayOf(0x05, 0x00))
    return der(0x30, version + algorithm + der(0x04, pkcs1))
}

private fun der(tag: Int, content: ByteArray): ByteArray {
    val n = content.size
    val length = when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
        n < 0x10000 -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
        else -> byteArrayOf(0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
    }
    return byteArrayOf(tag.toByte()) + length + content
}
