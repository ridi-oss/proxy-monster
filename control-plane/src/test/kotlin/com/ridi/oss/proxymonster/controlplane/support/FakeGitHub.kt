package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.GitHubConfig
import com.ridi.oss.proxymonster.controlplane.GitHubIdentityResolver
import com.ridi.oss.proxymonster.controlplane.source.GitHubAdapter
import com.ridi.oss.proxymonster.controlplane.source.PrincipalDirectory
import com.ridi.oss.proxymonster.controlplane.source.PullRequest
import com.ridi.oss.proxymonster.controlplane.source.SourceUser
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.time.Clock
import java.util.Base64

internal typealias Responder = suspend MockRequestHandleScope.(HttpRequestData) -> HttpResponseData

/**
 * GitHub's REST and GraphQL APIs over a MockEngine, with the App installation routes for `acme` already set.
 * Routes on method + encoded path; a route given several responders answers them in order, then repeats the last.
 */
internal class FakeGitHub(private val clock: Clock) {
    val requests = mutableListOf<HttpRequestData>()
    private val routes = HashMap<String, ArrayDeque<Responder>>()
    private var tokenSerial = 0

    init {
        on(HttpMethod.Get, "/repos/acme/shop/installation", { json("""{"id":42}""") })
        on(HttpMethod.Get, "/orgs/acme/installation", { json("""{"id":42}""") })
        on(HttpMethod.Post, "/app/installations/42/access_tokens", {
            tokenSerial++
            json("""{"token":"ghs_token$tokenSerial","expires_at":"${clock.instant().plusSeconds(3600)}"}""")
        })
    }

    fun on(method: HttpMethod, path: String, vararg responders: Responder) {
        routes["${method.value} $path"] = ArrayDeque(responders.toList())
    }

    fun graphql(vararg responders: Responder) = on(HttpMethod.Post, "/graphql", *responders)

    fun requestsTo(method: HttpMethod, path: String): List<HttpRequestData> =
        requests.filter { it.method == method && it.url.encodedPath == path }

    val client = HttpClient(
        MockEngine { request ->
            requests += request
            val queue = routes["${request.method.value} ${request.url.encodedPath}"]
                ?: error("unrouted ${request.method.value} ${request.url.encodedPath}")
            val responder = if (queue.size > 1) queue.removeFirst() else queue.first()
            responder(this, request)
        },
    ) { expectSuccess = false }

    fun adapter(
        identity: List<GitHubIdentityResolver> = listOf(GitHubIdentityResolver.EXTERNAL_IDENTITY, GitHubIdentityResolver.VERIFIED_EMAIL),
        principals: Map<String, String> = emptyMap(),
        emails: Map<String, String> = emptyMap(),
        pem: String = GitHubFixtures.pkcs8Pem,
        apiUrl: String = "https://api.github.com",
    ) = GitHubAdapter(
        GitHubConfig(appId = GitHubFixtures.APP_ID, privateKeyPem = pem, apiUrl = apiUrl, identity = identity),
        object : PrincipalDirectory {
            override fun activePrincipal(principal: String): String? = principals[principal]

            override fun activePrincipalByEmail(email: String): String? = emails[email]
        },
        client,
        clock,
    )
}

internal fun MockRequestHandleScope.json(
    body: String,
    status: HttpStatusCode = HttpStatusCode.OK,
    headers: Headers = headersOf(HttpHeaders.ContentType, "application/json"),
): HttpResponseData = respond(body, status, headers)

internal fun HttpRequestData.text(): String = (body as TextContent).text

internal fun HttpRequestData.jsonBody(): JsonObject = Json.parseToJsonElement(text()).jsonObject

internal object GitHubFixtures {
    const val APP_ID = "12345"
    const val RATE = """{"remaining":4999,"resetAt":"2026-10-09T01:00:00Z"}"""

    val keys: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    val pkcs8Pem = pem("PRIVATE KEY", keys.private.encoded)

    fun pem(label: String, der: ByteArray): String =
        "-----BEGIN $label-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) + "\n-----END $label-----\n"

    fun prResponse(vararg prs: String): String =
        """{"data":{"rateLimit":$RATE,"repository":{${prs.withIndex().joinToString(",") { (i, pr) -> "\"pr$i\":$pr" }}}}}"""

    private const val CHECKS = """{"__typename":"CheckRun","name":"build","status":"COMPLETED","conclusion":"SUCCESS","isRequired":true},
              {"__typename":"StatusContext","context":"ci/legacy","state":"PENDING","isRequired":false}"""

    /** An open PR; [checks] are the rollup's context nodes, null for no rollup at all. */
    fun pr(number: Int, rollupOid: String = "sha1", filesNext: String? = null, checksNext: String? = null, checks: String? = CHECKS): String {
        val rollup = checks?.let {
            """{"contexts":{"pageInfo":{"hasNextPage":${checksNext != null},"endCursor":${checksNext?.let { "\"$it\"" } ?: "null"}},"nodes":[$it]}}"""
        }
        return """{"number":$number,"state":"OPEN","merged":false,"mergedAt":null,"headRefOid":"sha1","baseRefName":"main",
            "url":"https://github.com/acme/shop/pull/$number",
            "author":{"login":"alice","databaseId":101},
            "autoMergeRequest":{"enabledAt":"2026-10-09T00:10:00Z","enabledBy":{"login":"alice","databaseId":101}},
            "reviews":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[
              {"databaseId":501,"state":"APPROVED","submittedAt":"2026-10-09T00:20:00Z","url":"https://github.com/acme/shop/pull/1#r501","commit":{"oid":"sha1"},"author":{"login":"bob","databaseId":102}},
              {"databaseId":502,"state":"DISMISSED","submittedAt":"2026-10-09T00:05:00Z","url":"https://github.com/acme/shop/pull/1#r502","author":{"login":"carol","databaseId":103}}]},
            "files":{"pageInfo":{"hasNextPage":${filesNext != null},"endCursor":${filesNext?.let { "\"$it\"" } ?: "null"}},"nodes":[
              {"path":"sql/old.sql","changeType":"DELETED"},{"path":"sql/new.sql","changeType":"ADDED"}]},
            "commits":{"nodes":[{"commit":{"oid":"$rollupOid","statusCheckRollup":$rollup}}]},
            "authors":{"nodes":[
              {"commit":{"parents":{"totalCount":1},"author":{"email":"alice@acme.com","user":{"databaseId":101}}}},
              {"commit":{"parents":{"totalCount":1},"author":{"email":" alice@acme.com","user":{"databaseId":101}}}},
              {"commit":{"parents":{"totalCount":1},"author":null}},
              {"commit":{"parents":{"totalCount":1},"author":{"email":"bob@acme.com","user":{"databaseId":102}}}},
              {"commit":{"parents":{"totalCount":2},"author":{"email":"merge@acme.com","user":{"databaseId":101}}}},
              {"commit":{"parents":{"totalCount":1},"author":{"email":"nouser@acme.com","user":null}}}]}}"""
    }

    fun merged(number: Int): String =
        """{"number":$number,"state":"MERGED","merged":true,"mergedAt":"2026-10-08T12:00:00Z","mergeCommit":{"oid":"merge$number"},
            "headRefOid":"sha2","baseRefName":"main",
            "url":"https://github.com/acme/shop/pull/$number","author":null,"autoMergeRequest":null,
            "reviews":{"pageInfo":{"hasNextPage":false},"nodes":[]},"files":{"pageInfo":{"hasNextPage":false},"nodes":[]},
            "commits":{"nodes":[{"commit":{"oid":"sha2","statusCheckRollup":null}}]}}"""

    /** [pr] as GraphQL returns it; null [PullRequest.checks] is a head commit without a rollup. */
    fun pullRequestJson(pr: PullRequest): String = buildJsonObject {
        fun user(u: SourceUser?): JsonElement = u?.let { buildJsonObject { put("login", it.login); put("databaseId", it.id.toLong()) } } ?: JsonNull
        val lastPage = buildJsonObject { put("hasNextPage", false) }
        put("number", pr.number)
        put("state", if (pr.merged) "MERGED" else if (pr.open) "OPEN" else "CLOSED")
        put("merged", pr.merged)
        put("mergedAt", pr.mergedAt?.toString())
        pr.mergeCommit?.let { putJsonObject("mergeCommit") { put("oid", it) } }
        put("headRefOid", pr.headSha)
        put("baseRefName", pr.baseRef)
        put("url", "https://github.com/acme/shop/pull/${pr.number}")
        put("author", user(pr.author))
        put(
            "autoMergeRequest",
            pr.autoMerge?.let { buildJsonObject { put("enabledAt", it.enabledAt?.toString()); put("enabledBy", user(it.enabledBy)) } } ?: JsonNull,
        )
        putJsonObject("reviews") {
            put("pageInfo", lastPage)
            putJsonArray("nodes") {
                for (r in pr.reviews) {
                    addJsonObject {
                        put("databaseId", r.id.toLong())
                        put("state", r.state.name)
                        put("submittedAt", r.submittedAt?.toString())
                        put("url", r.url)
                        r.commit?.let { oid -> putJsonObject("commit") { put("oid", oid) } }
                        put("author", user(r.reviewer))
                    }
                }
            }
        }
        putJsonObject("files") {
            put("pageInfo", lastPage)
            putJsonArray("nodes") { for (f in pr.files) addJsonObject { put("path", f.path); put("changeType", f.change.name) } }
        }
        putJsonObject("commits") {
            putJsonArray("nodes") {
                addJsonObject {
                    putJsonObject("commit") {
                        put("oid", pr.headSha)
                        put(
                            "statusCheckRollup",
                            pr.checks?.let { checks ->
                                buildJsonObject {
                                    putJsonObject("contexts") {
                                        put("pageInfo", lastPage)
                                        putJsonArray("nodes") {
                                            for (c in checks) {
                                                addJsonObject {
                                                    put("__typename", "CheckRun")
                                                    put("name", c.name)
                                                    put("status", c.status.name)
                                                    put("conclusion", c.conclusion?.name)
                                                    put("isRequired", c.required)
                                                }
                                            }
                                        }
                                    }
                                }
                            } ?: JsonNull,
                        )
                    }
                }
            }
        }
    }.toString()
}
