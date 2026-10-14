package com.ridi.oss.proxymonster.controlplane.source

import com.google.protobuf.ByteString
import com.google.protobuf.Empty
import com.ridi.oss.proxymonster.controlplane.GitHubIdentityResolver
import com.ridi.oss.proxymonster.controlplane.support.FakeCpGo
import com.ridi.oss.proxymonster.controlplane.support.cpGoPullRequest
import com.ridi.oss.proxymonster.controlplane.support.pb
import com.ridi.oss.proxymonster.cpgo.CompareCommitsRequest
import com.ridi.oss.proxymonster.cpgo.DismissReviewRequest
import com.ridi.oss.proxymonster.cpgo.GitHubError
import com.ridi.oss.proxymonster.cpgo.IdentityRequest
import com.ridi.oss.proxymonster.cpgo.PostCheckRequest
import com.ridi.oss.proxymonster.cpgo.PostCommentRequest
import com.ridi.oss.proxymonster.cpgo.ReadFileRequest
import com.ridi.oss.proxymonster.cpgo.ReadPullRequestsRequest
import com.ridi.oss.proxymonster.cpgo.RequiredChecksRequest
import com.ridi.oss.proxymonster.cpgo.compareCommitsResponse
import com.ridi.oss.proxymonster.cpgo.externalIdentityResponse
import com.ridi.oss.proxymonster.cpgo.gitHubError
import com.ridi.oss.proxymonster.cpgo.rateLimit
import com.ridi.oss.proxymonster.cpgo.readFileResponse
import com.ridi.oss.proxymonster.cpgo.readPullRequestsResponse
import com.ridi.oss.proxymonster.cpgo.requiredChecksResponse
import com.ridi.oss.proxymonster.cpgo.verifiedEmailsResponse
import io.grpc.Status
import io.grpc.protobuf.StatusProto
import kotlinx.coroutines.runBlocking
import java.time.Instant
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import com.google.rpc.Status as RpcStatus
import com.ridi.oss.proxymonster.cpgo.CheckConclusion as CheckConclusionPb
import com.ridi.oss.proxymonster.cpgo.CheckStatus as CheckStatusPb
import com.ridi.oss.proxymonster.cpgo.CommitRelation as CommitRelationPb

class GitHubAdapterTest {
    private val cpGo = FakeCpGo()
    private val repo = Repo("acme", "shop")
    private val alice = SourceUser("101", "alice")

    @AfterTest
    fun close() = cpGo.close()

    private val open = PullRequest(
        number = 1, open = true, merged = false, mergedAt = null, headSha = "sha1", baseRef = "main", author = alice,
        autoMerge = AutoMerge(alice, Instant.parse("2026-10-09T00:10:00Z")),
        reviews = listOf(Review("501", SourceUser("102", "bob"), ReviewState.APPROVED, Instant.parse("2026-10-09T00:20:00Z"), "u", "sha1")),
        checks = listOf(
            Check("build", true, CheckStatus.COMPLETED, CheckConclusion.SUCCESS),
            Check("ci/legacy", false, CheckStatus.IN_PROGRESS, null),
        ),
        files = listOf(ChangedFile("sql/new.sql", FileChange.ADDED)),
        commits = listOf(CommitAuthor("101", "alice@acme.com", merge = false), CommitAuthor(null, null, merge = true)),
    )
    private val merged = open.copy(
        number = 2, open = false, merged = true, mergedAt = Instant.parse("2026-10-08T12:00:00Z"), mergeCommit = "merge2",
        author = null, autoMerge = null, checks = null, reviews = emptyList(), commits = emptyList(),
    )

    private fun failure(kind: GitHubError.Kind, message: String = "m", status: Int = 0, resetAt: Instant? = null): Nothing {
        val detail = gitHubError {
            this.kind = kind
            this.message = message
            this.status = status
            resetAt?.let { this.resetAt = it.pb() }
        }
        throw StatusProto.toStatusException(
            RpcStatus.newBuilder().setCode(Status.Code.UNAVAILABLE.value()).setMessage(message)
                .addDetails(com.google.protobuf.Any.pack(detail)).build(),
        )
    }

    @Test
    fun `readPullRequests asks cp-go with the internal token and decodes every field`() {
        cpGo.readPullRequests = {
            readPullRequestsResponse {
                pullRequests.put(1, cpGoPullRequest(open))
                pullRequests.put(2, cpGoPullRequest(merged))
                pullRequests.put(3, cpGoPullRequest(open.copy(number = 3, checks = emptyList())))
                rateLimit = rateLimit {
                    remaining = 4999
                    resetAt = Instant.parse("2026-10-09T01:00:00Z").pb()
                }
            }
        }
        val adapter = cpGo.adapter()
        val prs = runBlocking { adapter.readPullRequests(repo, listOf(1, 2, 3)) }

        val request = cpGo.requestsOf<ReadPullRequestsRequest>().single()
        assertEquals(listOf<String?>(FakeCpGo.TOKEN), cpGo.tokens.toList())
        assertEquals("acme/shop", "${request.repo.owner}/${request.repo.name}")
        assertEquals(listOf(1, 2, 3), request.numbersList)
        assertEquals(open, prs[1])
        assertEquals(merged, prs[2])
        assertNull(prs.getValue(2).checks)
        assertEquals(emptyList(), prs.getValue(3).checks)
        assertEquals(RateLimit(4999, Instant.parse("2026-10-09T01:00:00Z")), adapter.rateLimit)
    }

    @Test
    fun `an empty PR list makes no call`() {
        assertEquals(emptyMap(), runBlocking { cpGo.adapter().readPullRequests(repo, emptyList()) })
        assertTrue(cpGo.requests.isEmpty())
    }

    @Test
    fun `each operation sends its arguments to cp-go`() {
        cpGo.readFile = { readFileResponse { content = ByteString.copyFrom(byteArrayOf(1, 2, 3)) } }
        cpGo.compareCommits = { compareCommitsResponse { relation = CommitRelationPb.DIVERGED } }
        cpGo.requiredChecks = { requiredChecksResponse { contexts += listOf("build", "lint") } }
        cpGo.postCheck = { Empty.getDefaultInstance() }
        cpGo.dismissReview = { Empty.getDefaultInstance() }
        cpGo.postComment = { Empty.getDefaultInstance() }
        val a = cpGo.adapter()

        assertContentEquals(byteArrayOf(1, 2, 3), runBlocking { a.readFile(repo, "feature/x", "sql/a b.sql") })
        assertEquals(CommitRelation.DIVERGED, runBlocking { a.compareCommits(repo, "aaa", "bbb") })
        assertEquals(setOf("build", "lint"), runBlocking { a.requiredChecks(repo, "release/1") })
        runBlocking { a.postCheck(repo, "sha1", "proxy-monster", CheckStatus.IN_PROGRESS, null, "Running", "Checking SQL") }
        runBlocking { a.postCheck(repo, "sha1", "proxy-monster", CheckStatus.COMPLETED, CheckConclusion.SKIPPED, "No SQL", "") }
        runBlocking { a.dismissReview(repo, 1, "501", "SQL changed") }
        runBlocking { a.postComment(repo, 1, "hello") }
        runBlocking { a.upsertComment(repo, 1, "status", "all good") }

        cpGo.requestsOf<ReadFileRequest>().single().let { assertEquals(Triple("acme", "feature/x", "sql/a b.sql"), Triple(it.repo.owner, it.ref, it.path)) }
        cpGo.requestsOf<CompareCommitsRequest>().single().let { assertEquals("aaa" to "bbb", it.base to it.head) }
        assertEquals("release/1", cpGo.requestsOf<RequiredChecksRequest>().single().branch)
        val checks = cpGo.requestsOf<PostCheckRequest>()
        assertEquals(CheckStatusPb.IN_PROGRESS to CheckConclusionPb.CHECK_CONCLUSION_UNSPECIFIED, checks[0].status to checks[0].conclusion)
        assertEquals(CheckStatusPb.COMPLETED to CheckConclusionPb.SKIPPED, checks[1].status to checks[1].conclusion)
        assertEquals("Running" to "Checking SQL", checks[0].title to checks[0].summary)
        cpGo.requestsOf<DismissReviewRequest>().single().let { assertEquals(Triple(1, "501", "SQL changed"), Triple(it.pr, it.reviewId, it.message)) }
        val comments = cpGo.requestsOf<PostCommentRequest>()
        assertEquals(false to "hello", comments[0].hasMarker() to comments[0].body)
        assertEquals("status" to "all good", comments[1].marker to comments[1].body)
        assertFailsWith<IllegalArgumentException> {
            runBlocking { a.postCheck(repo, "sha1", "proxy-monster", CheckStatus.COMPLETED, null, "t", "s") }
        }
    }

    @Test
    fun `a GitHub failure cp-go reports raises its typed exception`() {
        fun failing(kind: GitHubError.Kind, status: Int = 0, resetAt: Instant? = null, message: String = "m"): Throwable {
            cpGo.compareCommits = { failure(kind, message, status, resetAt) }
            return runCatching { runBlocking { cpGo.adapter().compareCommits(repo, "a", "b") } }.exceptionOrNull()!!
        }
        assertTrue(failing(GitHubError.Kind.UNAUTHORIZED) is GitHubException.Unauthorized)
        assertTrue(failing(GitHubError.Kind.FORBIDDEN) is GitHubException.Forbidden)
        assertEquals("GET /x -> 404: Not Found", failing(GitHubError.Kind.NOT_FOUND, message = "GET /x -> 404: Not Found").message)
        val reset = Instant.parse("2026-10-09T01:00:00Z")
        assertEquals(reset, (failing(GitHubError.Kind.RATE_LIMITED, resetAt = reset) as GitHubException.RateLimited).resetAt)
        assertNull((failing(GitHubError.Kind.RATE_LIMITED) as GitHubException.RateLimited).resetAt)
        assertTrue(failing(GitHubError.Kind.UNPROCESSABLE) is GitHubException.Unprocessable)
        assertEquals(500, (failing(GitHubError.Kind.SERVER, status = 500) as GitHubException.Server).status)
        assertTrue(failing(GitHubError.Kind.GRAPHQL) is GitHubException.Graphql)

        cpGo.compareCommits = { throw Status.INTERNAL.withDescription("boom").asException() }
        assertFailsWith<IllegalStateException> { runBlocking { cpGo.adapter().compareCommits(repo, "a", "b") } }
    }

    private fun identity(nameId: String? = null, emails: List<String> = emptyList()) {
        cpGo.externalIdentity = { externalIdentityResponse { nameId?.let { this.nameId = it } } }
        cpGo.verifiedEmails = { verifiedEmailsResponse { this.emails += emails } }
    }

    @Test
    fun `external identity maps the SAML nameId, and the first match wins`() {
        identity(nameId = "alice@example.com", emails = listOf("alice@example.com"))
        val a = cpGo.adapter(principals = mapOf("alice@example.com" to "alice"), emails = mapOf("alice@example.com" to "alice"))
        assertEquals("alice", runBlocking { a.resolveUser("acme", alice, MappingRole.REQUESTER) })
        val asked = cpGo.requestsOf<IdentityRequest>().single()
        assertEquals("acme" to "alice", asked.org to asked.login)
    }

    @Test
    fun `no SAML identity falls through to verified email`() {
        identity(emails = listOf("alice@example.com"))
        assertEquals("alice", runBlocking { cpGo.adapter(emails = mapOf("alice@example.com" to "alice")).resolveUser("acme", alice, MappingRole.REVIEWER) })
        assertEquals(2, cpGo.requestsOf<IdentityRequest>().size)
    }

    @Test
    fun `verified emails mapping to two principals are no match`() {
        identity(emails = listOf("a@example.com", "b@example.com"))
        val a = cpGo.adapter(emails = mapOf("a@example.com" to "alice", "b@example.com" to "bob"))
        assertNull(runBlocking { a.resolveUser("acme", alice, MappingRole.REQUESTER) })
    }

    @Test
    fun `commit email maps a requester but never a reviewer`() {
        identity()
        val a = cpGo.adapter(identity = GitHubIdentityResolver.entries, emails = mapOf("alice@example.com" to "alice"))
        assertEquals("alice", runBlocking { a.resolveUser("acme", alice, MappingRole.REQUESTER, listOf(" alice@example.com")) })
        assertNull(runBlocking { a.resolveUser("acme", alice, MappingRole.REVIEWER, listOf("alice@example.com")) })
    }

    @Test
    fun `no resolver matching gives null`() {
        identity(nameId = "unknown@example.com", emails = listOf("unknown@example.com"))
        assertNull(runBlocking { cpGo.adapter(identity = GitHubIdentityResolver.entries).resolveUser("acme", alice, MappingRole.REQUESTER, listOf("x@example.com")) })
    }

    @Test
    fun `a failed lookup during resolution throws`() {
        cpGo.externalIdentity = { failure(GitHubError.Kind.SERVER, "boom", 500) }
        val e = assertFailsWith<GitHubException.Server> { runBlocking { cpGo.adapter().resolveUser("acme", alice, MappingRole.REQUESTER) } }
        assertEquals(500, e.status)
    }
}
