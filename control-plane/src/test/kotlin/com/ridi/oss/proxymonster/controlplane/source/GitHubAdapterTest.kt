package com.ridi.oss.proxymonster.controlplane.source

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.SignedJWT
import com.ridi.oss.proxymonster.controlplane.GitHubIdentityResolver
import com.ridi.oss.proxymonster.controlplane.support.FakeGitHub
import com.ridi.oss.proxymonster.controlplane.support.GitHubFixtures.APP_ID
import com.ridi.oss.proxymonster.controlplane.support.GitHubFixtures.RATE
import com.ridi.oss.proxymonster.controlplane.support.GitHubFixtures.keys
import com.ridi.oss.proxymonster.controlplane.support.GitHubFixtures.merged
import com.ridi.oss.proxymonster.controlplane.support.GitHubFixtures.pem
import com.ridi.oss.proxymonster.controlplane.support.GitHubFixtures.pkcs8Pem
import com.ridi.oss.proxymonster.controlplane.support.GitHubFixtures.pr
import com.ridi.oss.proxymonster.controlplane.support.GitHubFixtures.prResponse
import com.ridi.oss.proxymonster.controlplane.support.Responder
import com.ridi.oss.proxymonster.controlplane.support.json
import com.ridi.oss.proxymonster.controlplane.support.jsonBody
import com.ridi.oss.proxymonster.controlplane.support.text
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.interfaces.RSAPublicKey
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

private class MutableClock(var now: Instant) : Clock() {
    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId): Clock = this

    override fun instant(): Instant = now
}

class GitHubAdapterTest {
    private val clock = MutableClock(Instant.parse("2026-10-09T00:00:00Z"))
    private val fake = FakeGitHub(clock)
    private val repo = Repo("acme", "shop")

    private fun graphql(vararg responders: Responder) = fake.graphql(*responders)

    @Test
    fun `the app JWT is RS256 signed by the app key with a backdated iat`() {
        for (pem in listOf(pkcs8Pem, pkcs1Pem)) {
            fake.requests.clear()
            fake.on(HttpMethod.Get, "/repos/acme/shop/contents/a.sql", { respond("x") })
            runBlocking { fake.adapter(pem = pem).readFile(repo, "main", "a.sql") }
            val bearer = fake.requestsTo(HttpMethod.Get, "/repos/acme/shop/installation").single()
                .headers[HttpHeaders.Authorization]!!.removePrefix("Bearer ")
            val jwt = SignedJWT.parse(bearer)
            assertTrue(jwt.verify(RSASSAVerifier(keys.public as RSAPublicKey)))
            assertEquals(JWSAlgorithm.RS256, jwt.header.algorithm)
            assertEquals(APP_ID, jwt.jwtClaimsSet.issuer)
            assertEquals(clock.now.minusSeconds(60), jwt.jwtClaimsSet.issueTime.toInstant())
            assertTrue(jwt.jwtClaimsSet.expirationTime.toInstant() <= clock.now.plusSeconds(600))
        }
    }

    @Test
    fun `a malformed key is rejected without echoing it`() {
        val e = assertFailsWith<IllegalArgumentException> { fake.adapter(pem = "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----") }
        assertEquals("invalid GitHub App private key", e.message)
    }

    @Test
    fun `installation tokens are exchanged once, reused, and renewed before expiry`() {
        graphql({ json(prResponse(pr(1))) })
        val a = fake.adapter()
        runBlocking { a.readPullRequests(repo, listOf(1)) }
        val exchange = fake.requestsTo(HttpMethod.Post, "/app/installations/42/access_tokens").single()
        assertTrue(exchange.headers[HttpHeaders.Authorization]!!.startsWith("Bearer ey"))
        assertEquals("Bearer ghs_token1", fake.requestsTo(HttpMethod.Post, "/graphql").single().headers[HttpHeaders.Authorization])

        runBlocking { a.readPullRequests(repo, listOf(1)) }
        assertEquals(1, fake.requestsTo(HttpMethod.Post, "/app/installations/42/access_tokens").size)
        assertEquals(1, fake.requestsTo(HttpMethod.Get, "/repos/acme/shop/installation").size)

        clock.now = clock.now.plusSeconds(3600 - 59)
        runBlocking { a.readPullRequests(repo, listOf(1)) }
        assertEquals(2, fake.requestsTo(HttpMethod.Post, "/app/installations/42/access_tokens").size)
        assertEquals("Bearer ghs_token2", fake.requestsTo(HttpMethod.Post, "/graphql").last().headers[HttpHeaders.Authorization])
    }

    @Test
    fun `a 401 evicts the token and retries once`() {
        graphql({ json("""{"message":"Bad credentials"}""", HttpStatusCode.Unauthorized) }, { json(prResponse(pr(1))) })
        val result = runBlocking { fake.adapter().readPullRequests(repo, listOf(1)) }
        assertEquals(setOf(1), result.keys)
        assertEquals(
            listOf("Bearer ghs_token1", "Bearer ghs_token2"),
            fake.requestsTo(HttpMethod.Post, "/graphql").map { it.headers[HttpHeaders.Authorization] },
        )

        fake.requests.clear()
        graphql({ json("""{"message":"Bad credentials"}""", HttpStatusCode.Unauthorized) })
        assertFailsWith<GitHubException.Unauthorized> { runBlocking { fake.adapter().readPullRequests(repo, listOf(1)) } }
        assertEquals(2, fake.requestsTo(HttpMethod.Post, "/graphql").size)
    }

    @Test
    fun `readPullRequests reads every PR in one query and maps each field`() {
        graphql({ json(prResponse(pr(1), merged(2))) })
        val a = fake.adapter()
        val prs = runBlocking { a.readPullRequests(repo, listOf(1, 2)) }

        val request = fake.requestsTo(HttpMethod.Post, "/graphql").single()
        val body = request.jsonBody()
        val query = body["query"]!!.jsonPrimitive.content
        val variables = body["variables"]!!.jsonObject
        assertEquals("acme", variables["owner"]!!.jsonPrimitive.content)
        assertEquals("shop", variables["name"]!!.jsonPrimitive.content)
        assertEquals(1, variables["n0"]!!.jsonPrimitive.int)
        assertEquals(2, variables["n1"]!!.jsonPrimitive.int)
        assertTrue("pr0:" in query && "pr1:" in query)
        assertFalse("acme" in query || "shop" in query)

        val open = prs.getValue(1)
        assertTrue(open.open)
        assertFalse(open.merged)
        assertNull(open.mergedAt)
        assertNull(open.mergeCommit)
        assertEquals("sha1", open.headSha)
        assertEquals("main", open.baseRef)
        assertEquals(SourceUser("101", "alice"), open.author)
        assertEquals(AutoMerge(SourceUser("101", "alice"), Instant.parse("2026-10-09T00:10:00Z")), open.autoMerge)
        assertEquals(
            listOf(
                Review("501", SourceUser("102", "bob"), ReviewState.APPROVED, Instant.parse("2026-10-09T00:20:00Z"), "https://github.com/acme/shop/pull/1#r501"),
                Review("502", SourceUser("103", "carol"), ReviewState.DISMISSED, Instant.parse("2026-10-09T00:05:00Z"), "https://github.com/acme/shop/pull/1#r502"),
            ),
            open.reviews,
        )
        assertEquals(
            listOf(
                Check("build", true, CheckStatus.COMPLETED, CheckConclusion.SUCCESS),
                Check("ci/legacy", false, CheckStatus.IN_PROGRESS, null),
            ),
            open.checks,
        )
        assertEquals(listOf(ChangedFile("sql/old.sql", FileChange.DELETED), ChangedFile("sql/new.sql", FileChange.ADDED)), open.files)

        val closed = prs.getValue(2)
        assertFalse(closed.open)
        assertTrue(closed.merged)
        assertEquals(Instant.parse("2026-10-08T12:00:00Z"), closed.mergedAt)
        assertEquals("merge2", closed.mergeCommit)
        assertNull(closed.author)
        assertNull(closed.autoMerge)
        assertNull(closed.checks)
        assertEquals(RateLimit(4999, Instant.parse("2026-10-09T01:00:00Z")), a.rateLimit)
    }

    @Test
    fun `an empty PR list makes no call`() {
        assertEquals(emptyMap<Int, PullRequest>(), runBlocking { fake.adapter().readPullRequests(repo, emptyList()) })
        assertTrue(fake.requests.isEmpty())
    }

    @Test
    fun `a PR GitHub reports as not found is absent, any other error throws`() {
        graphql({
            json(
                """{"data":{"rateLimit":$RATE,"repository":{"pr0":${pr(1)},"pr1":null}},
                "errors":[{"type":"NOT_FOUND","path":["repository","pr1"],"message":"Could not resolve"}]}""",
            )
        })
        assertEquals(setOf(1), runBlocking { fake.adapter().readPullRequests(repo, listOf(1, 9)) }.keys)

        graphql({ json("""{"data":null,"errors":[{"type":"NOT_FOUND","path":["repository"],"message":"Could not resolve"}]}""") })
        val e = assertFailsWith<GitHubException.Graphql> { runBlocking { fake.adapter().readPullRequests(repo, listOf(1)) } }
        assertEquals(listOf("NOT_FOUND"), e.types)
    }

    @Test
    fun `a rollup for a commit other than the head yields no checks`() {
        graphql({ json(prResponse(pr(1, rollupOid = "older"))) })
        assertNull(runBlocking { fake.adapter().readPullRequests(repo, listOf(1)) }.getValue(1).checks)
    }

    @Test
    fun `a pull request without a rollup yields no checks, and an empty rollup yields none run`() {
        graphql({ json(prResponse(pr(1, checks = null))) })
        assertNull(runBlocking { fake.adapter().readPullRequests(repo, listOf(1)) }.getValue(1).checks)

        graphql({ json(prResponse(pr(1, checks = ""))) })
        assertEquals(emptyList(), runBlocking { fake.adapter().readPullRequests(repo, listOf(1)) }.getValue(1).checks)
    }

    @Test
    fun `a push while the rollup is paged yields no checks`() {
        graphql(
            { json(prResponse(pr(1, checksNext = "c1"))) },
            {
                json(
                    """{"data":{"rateLimit":$RATE,"repository":{"pullRequest":{"commits":{"nodes":[{"commit":{"oid":"sha2",
                    "statusCheckRollup":{"contexts":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]}}}}]}}}}}""",
                )
            },
        )
        assertNull(runBlocking { fake.adapter().readPullRequests(repo, listOf(1)) }.getValue(1).checks)
        assertEquals(2, fake.requestsTo(HttpMethod.Post, "/graphql").size)
    }

    private val rulesPath = "/repos/acme/shop/rules/branches/release%2F1"
    private val branchPath = "/repos/acme/shop/branches/release%2F1"

    @Test
    fun `required checks merge ruleset and branch protection contexts, cached for five minutes`() {
        fake.on(HttpMethod.Get, rulesPath, {
            json(
                """[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"build"},{"context":"lint","integration_id":1}]}},
                {"type":"pull_request","parameters":{}}]""",
            )
        })
        fake.on(HttpMethod.Get, branchPath, {
            json("""{"name":"release/1","protection":{"required_status_checks":{"contexts":["ci/legacy"],"checks":[{"context":"ci/legacy"},{"context":"e2e","app_id":5}]}}}""")
        })
        val a = fake.adapter()
        val want = setOf("build", "lint", "ci/legacy", "e2e")
        assertEquals(want, runBlocking { a.requiredChecks(repo, "release/1") })
        assertEquals("100", fake.requestsTo(HttpMethod.Get, rulesPath).single().url.parameters["per_page"])

        clock.now = clock.now.plusSeconds(299)
        assertEquals(want, runBlocking { a.requiredChecks(repo, "release/1") })
        assertEquals(1, fake.requestsTo(HttpMethod.Get, rulesPath).size)
        assertEquals(1, fake.requestsTo(HttpMethod.Get, branchPath).size)

        clock.now = clock.now.plusSeconds(2)
        assertEquals(want, runBlocking { a.requiredChecks(repo, "release/1") })
        assertEquals(2, fake.requestsTo(HttpMethod.Get, rulesPath).size)
        assertEquals(2, fake.requestsTo(HttpMethod.Get, branchPath).size)
    }

    @Test
    fun `ruleset pages are read until a short page`() {
        val filler = (1..100).joinToString(",", "[", "]") { """{"type":"deletion"}""" }
        fake.on(
            HttpMethod.Get, rulesPath,
            { json(filler) },
            { json("""[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"late"}]}}]""") },
        )
        fake.on(HttpMethod.Get, branchPath, { json("""{"name":"release/1","protection":{"enabled":false}}""") })
        assertEquals(setOf("late"), runBlocking { fake.adapter().requiredChecks(repo, "release/1") })
        assertEquals(listOf("1", "2"), fake.requestsTo(HttpMethod.Get, rulesPath).map { it.url.parameters["page"] })
    }

    @Test
    fun `a missing branch has no required checks, and any other error is not cached`() {
        val notFound: Responder = { json("""{"message":"Not Found"}""", HttpStatusCode.NotFound) }
        fake.on(HttpMethod.Get, rulesPath, notFound)
        fake.on(HttpMethod.Get, branchPath, notFound)
        assertEquals(emptySet(), runBlocking { fake.adapter().requiredChecks(repo, "release/1") })

        val a = fake.adapter()
        fake.on(
            HttpMethod.Get, branchPath,
            { json("""{"message":"boom"}""", HttpStatusCode.InternalServerError) },
            { json("""{"name":"release/1","protection":{"required_status_checks":{"contexts":["build"]}}}""") },
        )
        assertFailsWith<GitHubException.Server> { runBlocking { a.requiredChecks(repo, "release/1") } }
        assertEquals(setOf("build"), runBlocking { a.requiredChecks(repo, "release/1") })
    }

    @Test
    fun `a further page of files is fetched until complete`() {
        graphql(
            { json(prResponse(pr(1, filesNext = "c1"))) },
            {
                json(
                    """{"data":{"rateLimit":$RATE,"repository":{"pullRequest":{"files":{"pageInfo":{"hasNextPage":false,"endCursor":null},
                    "nodes":[{"path":"sql/more.sql","changeType":"MODIFIED"}]}}}}}""",
                )
            },
        )
        val files = runBlocking { fake.adapter().readPullRequests(repo, listOf(1)) }.getValue(1).files
        assertEquals(
            listOf(FileChange.DELETED, FileChange.ADDED, FileChange.MODIFIED) to listOf("sql/old.sql", "sql/new.sql", "sql/more.sql"),
            files.map { it.change } to files.map { it.path },
        )
        val page = fake.requestsTo(HttpMethod.Post, "/graphql")[1].jsonBody()
        assertEquals("c1", page["variables"]!!.jsonObject["after"]!!.jsonPrimitive.content)
        assertTrue("files(first:100, after:\$after)" in page["query"]!!.jsonPrimitive.content)
    }

    @Test
    fun `compareCommits maps each comparison status and fails on any other`() {
        val path = "/repos/acme/shop/compare/aaa...bbb"
        for ((status, relation) in listOf(
            "ahead" to CommitRelation.AHEAD,
            "identical" to CommitRelation.IDENTICAL,
            "behind" to CommitRelation.BEHIND,
            "diverged" to CommitRelation.DIVERGED,
        )) {
            fake.on(HttpMethod.Get, path, { json("""{"status":"$status","ahead_by":1,"behind_by":0}""") })
            assertEquals(relation, runBlocking { fake.adapter().compareCommits(repo, "aaa", "bbb") })
        }
        assertEquals(4, fake.requestsTo(HttpMethod.Get, path).size)

        fake.on(HttpMethod.Get, path, { json("""{"status":"unknown"}""") })
        assertFailsWith<IllegalStateException> { runBlocking { fake.adapter().compareCommits(repo, "aaa", "bbb") } }
        fake.on(HttpMethod.Get, path, { json("""{"message":"Not Found"}""", HttpStatusCode.NotFound) })
        assertFailsWith<GitHubException.NotFound> { runBlocking { fake.adapter().compareCommits(repo, "aaa", "bbb") } }
    }

    @Test
    fun `readFile asks for raw content at an encoded path and ref`() {
        fake.on(HttpMethod.Get, "/repos/acme/shop/contents/sql/a%20b.sql", { respond(byteArrayOf(1, 2, 3)) })
        val bytes = runBlocking { fake.adapter().readFile(repo, "feature/x y", "sql/a b.sql") }
        assertContentEquals(byteArrayOf(1, 2, 3), bytes)
        val request = fake.requestsTo(HttpMethod.Get, "/repos/acme/shop/contents/sql/a%20b.sql").single()
        assertEquals("application/vnd.github.raw+json", request.headers[HttpHeaders.Accept])
        assertEquals("feature/x y", request.url.parameters["ref"])
        assertEquals("2022-11-28", request.headers["X-GitHub-Api-Version"])
        assertEquals("proxy-monster", request.headers[HttpHeaders.UserAgent])
    }

    @Test
    fun `postCheck creates a run, then updates this app's run`() {
        val list = "/repos/acme/shop/commits/sha1/check-runs"
        fake.on(
            HttpMethod.Get,
            list,
            { json("""{"total_count":0,"check_runs":[]}""") },
            { json("""{"total_count":2,"check_runs":[{"id":7,"app":{"id":999}},{"id":8,"app":{"id":$APP_ID}}]}""") },
        )
        fake.on(HttpMethod.Post, "/repos/acme/shop/check-runs", { json("""{"id":8}""", HttpStatusCode.Created) })
        fake.on(HttpMethod.Patch, "/repos/acme/shop/check-runs/8", { json("""{"id":8}""") })
        val a = fake.adapter()

        runBlocking { a.postCheck(repo, "sha1", "proxy-monster", CheckStatus.IN_PROGRESS, null, "Running", "Checking SQL") }
        val lookup = fake.requestsTo(HttpMethod.Get, list).single().url.parameters
        assertEquals("proxy-monster", lookup["check_name"])
        assertEquals("latest", lookup["filter"])
        assertEquals(APP_ID, lookup["app_id"])
        assertEquals(
            Json.parseToJsonElement(
                """{"name":"proxy-monster","head_sha":"sha1","status":"in_progress","output":{"title":"Running","summary":"Checking SQL"}}""",
            ),
            fake.requestsTo(HttpMethod.Post, "/repos/acme/shop/check-runs").single().jsonBody(),
        )

        runBlocking { a.postCheck(repo, "sha1", "proxy-monster", CheckStatus.COMPLETED, CheckConclusion.FAILURE, "Denied", "No grant") }
        assertEquals(1, fake.requestsTo(HttpMethod.Post, "/repos/acme/shop/check-runs").size)
        val patch = fake.requestsTo(HttpMethod.Patch, "/repos/acme/shop/check-runs/8").single().jsonBody()
        assertEquals("completed", patch["status"]!!.jsonPrimitive.content)
        assertEquals("failure", patch["conclusion"]!!.jsonPrimitive.content)
        assertTrue(fake.requests.none { it.url.encodedPath.endsWith("/check-runs/7") })

        assertFailsWith<IllegalArgumentException> {
            runBlocking { a.postCheck(repo, "sha1", "proxy-monster", CheckStatus.COMPLETED, null, "t", "s") }
        }
    }

    @Test
    fun `a run from another app is not updated`() {
        fake.on(HttpMethod.Get, "/repos/acme/shop/commits/sha1/check-runs", {
            json("""{"total_count":1,"check_runs":[{"id":7,"app":{"id":999}}]}""")
        })
        fake.on(HttpMethod.Post, "/repos/acme/shop/check-runs", { json("""{"id":9}""", HttpStatusCode.Created) })
        runBlocking { fake.adapter().postCheck(repo, "sha1", "proxy-monster", CheckStatus.QUEUED, null, "t", "s") }
        assertEquals(1, fake.requestsTo(HttpMethod.Post, "/repos/acme/shop/check-runs").size)
        assertTrue(fake.requests.none { it.method == HttpMethod.Patch })
    }

    @Test
    fun `dismissReview PUTs a dismissal`() {
        fake.on(HttpMethod.Put, "/repos/acme/shop/pulls/1/reviews/501/dismissals", { json("{}") })
        runBlocking { fake.adapter().dismissReview(repo, 1, "501", "SQL changed after approval") }
        assertEquals(
            Json.parseToJsonElement("""{"message":"SQL changed after approval","event":"DISMISS"}"""),
            fake.requests.last().jsonBody(),
        )
    }

    @Test
    fun `postComment posts the body as is`() {
        fake.on(HttpMethod.Post, "/repos/acme/shop/issues/1/comments", { json("{}", HttpStatusCode.Created) })
        runBlocking { fake.adapter().postComment(repo, 1, "hello") }
        assertEquals(Json.parseToJsonElement("""{"body":"hello"}"""), fake.requests.last().jsonBody())
    }

    @Test
    fun `upsertComment creates a marked comment when none exists`() {
        fake.on(HttpMethod.Get, "/repos/acme/shop/issues/1/comments", {
            json("""[{"id":1,"body":"<!-- proxy-monster:status -->\nforged","performed_via_github_app":null}]""")
        })
        fake.on(HttpMethod.Post, "/repos/acme/shop/issues/1/comments", { json("{}", HttpStatusCode.Created) })
        runBlocking { fake.adapter().upsertComment(repo, 1, "status", "all good") }
        assertEquals(
            "<!-- proxy-monster:status -->\nall good",
            fake.requestsTo(HttpMethod.Post, "/repos/acme/shop/issues/1/comments").single().jsonBody()["body"]!!.jsonPrimitive.content,
        )
        assertTrue(fake.requests.none { it.method == HttpMethod.Patch })
    }

    @Test
    fun `upsertComment edits the app's marked comment on a later page`() {
        val firstPage = (1..100).joinToString(",", "[", "]") { """{"id":$it,"body":"chatter","performed_via_github_app":{"id":$APP_ID}}""" }
        fake.on(
            HttpMethod.Get,
            "/repos/acme/shop/issues/1/comments",
            { json(firstPage) },
            { json("""[{"id":500,"body":"<!-- proxy-monster:status -->\nold","performed_via_github_app":{"id":$APP_ID}}]""") },
        )
        fake.on(HttpMethod.Patch, "/repos/acme/shop/issues/comments/500", { json("{}") })
        runBlocking { fake.adapter().upsertComment(repo, 1, "status", "new") }
        val pages = fake.requestsTo(HttpMethod.Get, "/repos/acme/shop/issues/1/comments").map { it.url.parameters["page"] }
        assertEquals(listOf("1", "2"), pages)
        assertEquals("100", fake.requests.first { it.method == HttpMethod.Get && it.url.encodedPath.endsWith("/comments") }.url.parameters["per_page"])
        assertEquals(
            "<!-- proxy-monster:status -->\nnew",
            fake.requestsTo(HttpMethod.Patch, "/repos/acme/shop/issues/comments/500").single().jsonBody()["body"]!!.jsonPrimitive.content,
        )
        assertTrue(fake.requests.none { it.method == HttpMethod.Post && it.url.encodedPath.endsWith("/comments") })
    }

    private fun identityResponder(nameId: String? = null, provider: Boolean = true, emails: List<String> = emptyList()): Responder = { request ->
        val query = request.jsonBody()["query"]!!.jsonPrimitive.content
        when {
            "samlIdentityProvider" in query -> {
                assertTrue("externalIdentities(login:" in query)
                val nodes = nameId?.let { """[{"samlIdentity":{"nameId":"$it"}}]""" } ?: "[]"
                val idp = if (provider) """{"externalIdentities":{"nodes":$nodes}}""" else "null"
                json("""{"data":{"rateLimit":$RATE,"organization":{"samlIdentityProvider":$idp}}}""")
            }
            "organizationVerifiedDomainEmails" in query ->
                json(
                    """{"data":{"rateLimit":$RATE,"user":{"organizationVerifiedDomainEmails":
                    ${emails.joinToString(",", "[", "]") { "\"$it\"" }}}}}""",
                )
            else -> error("unexpected query")
        }
    }

    private val alice = SourceUser("101", "alice")

    @Test
    fun `external identity maps the SAML nameId, and the first match wins`() {
        graphql(identityResponder(nameId = "alice@example.com", emails = listOf("alice@example.com")))
        val a = fake.adapter(principals = mapOf("alice@example.com" to "alice"), emails = mapOf("alice@example.com" to "alice"))
        assertEquals("alice", runBlocking { a.resolveUser("acme", alice, MappingRole.REQUESTER) })
        val requests = fake.requestsTo(HttpMethod.Post, "/graphql")
        assertEquals(1, requests.size)
        val variables = requests.single().jsonBody()["variables"]!!.jsonObject
        assertEquals("acme", variables["org"]!!.jsonPrimitive.content)
        assertEquals("alice", variables["login"]!!.jsonPrimitive.content)
        assertEquals(1, fake.requestsTo(HttpMethod.Get, "/orgs/acme/installation").size)
        assertNotNull(a.rateLimit)
    }

    @Test
    fun `no SAML provider falls through to verified email`() {
        graphql(identityResponder(provider = false, emails = listOf("alice@example.com")))
        val a = fake.adapter(emails = mapOf("alice@example.com" to "alice"))
        assertEquals("alice", runBlocking { a.resolveUser("acme", alice, MappingRole.REVIEWER) })
        assertEquals(2, fake.requestsTo(HttpMethod.Post, "/graphql").size)
    }

    @Test
    fun `a forbidden SAML lookup falls through to verified email`() {
        graphql({ request ->
            if ("samlIdentityProvider" in request.text()) {
                json("""{"data":{"organization":null},"errors":[{"type":"FORBIDDEN","path":["organization"],"message":"no"}]}""")
            } else {
                identityResponder(emails = listOf("alice@example.com")).invoke(this, request)
            }
        })
        assertEquals("alice", runBlocking { fake.adapter(emails = mapOf("alice@example.com" to "alice")).resolveUser("acme", alice, MappingRole.REQUESTER) })
    }

    @Test
    fun `verified emails mapping to two principals are no match`() {
        graphql(identityResponder(provider = false, emails = listOf("a@example.com", "b@example.com")))
        val a = fake.adapter(emails = mapOf("a@example.com" to "alice", "b@example.com" to "bob"))
        assertNull(runBlocking { a.resolveUser("acme", alice, MappingRole.REQUESTER) })
    }

    @Test
    fun `commit email maps a requester but never a reviewer`() {
        graphql(identityResponder(provider = false))
        val a = fake.adapter(
            identity = GitHubIdentityResolver.entries,
            emails = mapOf("alice@example.com" to "alice"),
        )
        assertEquals("alice", runBlocking { a.resolveUser("acme", alice, MappingRole.REQUESTER, listOf("alice@example.com")) })
        assertNull(runBlocking { a.resolveUser("acme", alice, MappingRole.REVIEWER, listOf("alice@example.com")) })
    }

    @Test
    fun `no resolver matching gives null`() {
        graphql(identityResponder(nameId = "unknown@example.com", emails = listOf("unknown@example.com")))
        assertNull(runBlocking { fake.adapter(identity = GitHubIdentityResolver.entries).resolveUser("acme", alice, MappingRole.REQUESTER, listOf("x@example.com")) })
    }

    @Test
    fun `a server error during resolution throws`() {
        graphql({ json("""{"message":"boom"}""", HttpStatusCode.InternalServerError) })
        val e = assertFailsWith<GitHubException.Server> { runBlocking { fake.adapter().resolveUser("acme", alice, MappingRole.REQUESTER) } }
        assertEquals(500, e.status)
    }

    @Test
    fun `HTTP errors map to typed exceptions that carry no credential`() {
        fake.on(HttpMethod.Get, "/repos/acme/shop/contents/missing.sql", { json("""{"message":"Not Found"}""", HttpStatusCode.NotFound) })
        val notFound = assertFailsWith<GitHubException.NotFound> { runBlocking { fake.adapter().readFile(repo, "main", "missing.sql") } }
        assertEquals("GET /repos/acme/shop/contents/missing.sql -> 404: Not Found", notFound.message)

        fake.on(HttpMethod.Get, "/repos/acme/shop/contents/a.sql", {
            json(
                """{"message":"API rate limit exceeded"}""",
                HttpStatusCode.Forbidden,
                headersOf("x-ratelimit-remaining" to listOf("0"), "x-ratelimit-reset" to listOf("1791507600")),
            )
        })
        val limited = assertFailsWith<GitHubException.RateLimited> { runBlocking { fake.adapter().readFile(repo, "main", "a.sql") } }
        assertEquals(Instant.ofEpochSecond(1791507600), limited.resetAt)

        fake.on(HttpMethod.Get, "/repos/acme/shop/contents/b.sql", { json("""{"message":"Resource not accessible"}""", HttpStatusCode.Forbidden) })
        assertFailsWith<GitHubException.Forbidden> { runBlocking { fake.adapter().readFile(repo, "main", "b.sql") } }

        val credentials = fake.requests.mapNotNull { it.headers[HttpHeaders.Authorization]?.removePrefix("Bearer ") }.toSet()
        assertNotEquals(emptySet(), credentials)
        for (e in listOf(notFound, limited)) {
            assertTrue(credentials.none { it in e.message!! })
        }
    }

    @Test
    fun `a GHES api url sends GraphQL to api-graphql`() {
        fake.on(HttpMethod.Post, "/api/graphql", { json(prResponse(pr(1))) })
        fake.on(HttpMethod.Get, "/api/v3/repos/acme/shop/installation", { json("""{"id":42}""") })
        fake.on(HttpMethod.Post, "/api/v3/app/installations/42/access_tokens", {
            json("""{"token":"ghs_ghes","expires_at":"${clock.now.plusSeconds(3600)}"}""")
        })
        runBlocking { fake.adapter(apiUrl = "https://git.example.com/api/v3").readPullRequests(repo, listOf(1)) }
        assertEquals(1, fake.requestsTo(HttpMethod.Post, "/api/graphql").size)
    }

    companion object {
        private val pkcs1Pem = pem("RSA PRIVATE KEY", pkcs1Of(keys.private.encoded))

        /** The RSAPrivateKey inside a PKCS#8 PrivateKeyInfo: its third element's OCTET STRING content. */
        private fun pkcs1Of(pkcs8: ByteArray): ByteArray {
            var i = 0
            fun header(): Pair<Int, Int> {
                val tag = pkcs8[i++].toInt() and 0xff
                var length = pkcs8[i++].toInt() and 0xff
                if (length and 0x80 != 0) {
                    val n = length and 0x7f
                    length = 0
                    repeat(n) { length = (length shl 8) or (pkcs8[i++].toInt() and 0xff) }
                }
                return tag to length
            }
            header()
            repeat(2) {
                val skip = header().second
                i += skip
            }
            val (tag, length) = header()
            check(tag == 0x04)
            return pkcs8.copyOfRange(i, i + length)
        }
    }
}
