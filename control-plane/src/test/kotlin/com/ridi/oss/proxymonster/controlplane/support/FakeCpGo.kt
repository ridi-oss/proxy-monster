package com.ridi.oss.proxymonster.controlplane.support

import com.google.protobuf.Empty
import com.google.protobuf.Timestamp
import com.ridi.oss.proxymonster.controlplane.CpGoBridge
import com.ridi.oss.proxymonster.controlplane.CpGoBridgeConfig
import com.ridi.oss.proxymonster.controlplane.GitHubConfig
import com.ridi.oss.proxymonster.controlplane.GitHubIdentityResolver
import com.ridi.oss.proxymonster.controlplane.source.GitHubAdapter
import com.ridi.oss.proxymonster.controlplane.source.PrincipalDirectory
import com.ridi.oss.proxymonster.controlplane.source.PullRequest
import com.ridi.oss.proxymonster.cpgo.BranchRules
import com.ridi.oss.proxymonster.cpgo.BranchRulesRequest
import com.ridi.oss.proxymonster.cpgo.CompareCommitsRequest
import com.ridi.oss.proxymonster.cpgo.CompareCommitsResponse
import com.ridi.oss.proxymonster.cpgo.DismissReviewRequest
import com.ridi.oss.proxymonster.cpgo.ExternalIdentityResponse
import com.ridi.oss.proxymonster.cpgo.GitHubSourceGrpcKt
import com.ridi.oss.proxymonster.cpgo.IdentityRequest
import com.ridi.oss.proxymonster.cpgo.PostCheckRequest
import com.ridi.oss.proxymonster.cpgo.PostCommentRequest
import com.ridi.oss.proxymonster.cpgo.ReadFileRequest
import com.ridi.oss.proxymonster.cpgo.ReadFileResponse
import com.ridi.oss.proxymonster.cpgo.ReadPullRequestsRequest
import com.ridi.oss.proxymonster.cpgo.ReadPullRequestsResponse
import com.ridi.oss.proxymonster.cpgo.VerifiedEmailsResponse
import com.ridi.oss.proxymonster.cpgo.autoMerge
import com.ridi.oss.proxymonster.cpgo.changedFile
import com.ridi.oss.proxymonster.cpgo.check
import com.ridi.oss.proxymonster.cpgo.checks
import com.ridi.oss.proxymonster.cpgo.commitAuthor
import com.ridi.oss.proxymonster.cpgo.pullRequest
import com.ridi.oss.proxymonster.cpgo.review
import com.ridi.oss.proxymonster.cpgo.sourceUser
import io.grpc.Metadata
import io.grpc.Server
import io.grpc.ServerCall
import io.grpc.ServerCallHandler
import io.grpc.ServerInterceptor
import io.grpc.ServerInterceptors
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder
import java.net.InetSocketAddress
import java.time.Instant
import java.util.Collections
import com.ridi.oss.proxymonster.cpgo.CheckConclusion as CheckConclusionPb
import com.ridi.oss.proxymonster.cpgo.CheckStatus as CheckStatusPb
import com.ridi.oss.proxymonster.cpgo.FileChange as FileChangePb
import com.ridi.oss.proxymonster.cpgo.PullRequest as PullRequestPb
import com.ridi.oss.proxymonster.cpgo.ReviewState as ReviewStatePb
import com.ridi.oss.proxymonster.controlplane.source.SourceUser as SourceUserModel

/**
 * cp-go's GitHubSource bridge service as a gRPC server on loopback. Each RPC answers with its handler, set by
 * the test; [requests] records every request message and [tokens] the internal token each call carried.
 */
internal class FakeCpGo : AutoCloseable {
    val requests: MutableList<Any> = Collections.synchronizedList(mutableListOf())
    val tokens: MutableList<String?> = Collections.synchronizedList(mutableListOf())

    var readPullRequests: (ReadPullRequestsRequest) -> ReadPullRequestsResponse = { unrouted() }
    var readFile: (ReadFileRequest) -> ReadFileResponse = { unrouted() }
    var compareCommits: (CompareCommitsRequest) -> CompareCommitsResponse = { unrouted() }
    var branchRules: (BranchRulesRequest) -> BranchRules = { unrouted() }
    var postCheck: (PostCheckRequest) -> Empty = { unrouted() }
    var dismissReview: (DismissReviewRequest) -> Empty = { unrouted() }
    var postComment: (PostCommentRequest) -> Empty = { unrouted() }
    var externalIdentity: (IdentityRequest) -> ExternalIdentityResponse = { unrouted() }
    var verifiedEmails: (IdentityRequest) -> VerifiedEmailsResponse = { unrouted() }

    private fun unrouted(): Nothing = error("unrouted call")

    private val service = object : GitHubSourceGrpcKt.GitHubSourceCoroutineImplBase() {
        private fun <T : Any, R> record(req: T, handler: (T) -> R): R {
            requests += req
            return handler(req)
        }

        override suspend fun readPullRequests(request: ReadPullRequestsRequest) = record(request, readPullRequests)
        override suspend fun readFile(request: ReadFileRequest) = record(request, readFile)
        override suspend fun compareCommits(request: CompareCommitsRequest) = record(request, compareCommits)
        override suspend fun readBranchRules(request: BranchRulesRequest) = record(request, branchRules)
        override suspend fun postCheck(request: PostCheckRequest) = record(request, postCheck)
        override suspend fun dismissReview(request: DismissReviewRequest) = record(request, dismissReview)
        override suspend fun postComment(request: PostCommentRequest) = record(request, postComment)
        override suspend fun externalIdentity(request: IdentityRequest) = record(request, externalIdentity)
        override suspend fun verifiedEmails(request: IdentityRequest) = record(request, verifiedEmails)
    }

    private val server: Server = NettyServerBuilder.forAddress(InetSocketAddress("127.0.0.1", 0))
        .addService(
            ServerInterceptors.intercept(
                service,
                object : ServerInterceptor {
                    override fun <Q, A> interceptCall(call: ServerCall<Q, A>, headers: Metadata, next: ServerCallHandler<Q, A>): ServerCall.Listener<Q> {
                        tokens += headers.get(Metadata.Key.of("x-pm-internal-token", Metadata.ASCII_STRING_MARSHALLER))
                        return next.startCall(call, headers)
                    }
                },
            ),
        )
        .build()
        .start()

    private val bridge = CpGoBridge(CpGoBridgeConfig("127.0.0.1:${server.port}", TOKEN))

    inline fun <reified T> requestsOf(): List<T> = requests.filterIsInstance<T>()

    fun adapter(
        identity: List<GitHubIdentityResolver> = listOf(GitHubIdentityResolver.EXTERNAL_IDENTITY, GitHubIdentityResolver.VERIFIED_EMAIL),
        principals: Map<String, String> = emptyMap(),
        emails: Map<String, String> = emptyMap(),
    ) = GitHubAdapter(
        GitHubConfig(apiUrl = "https://api.github.com", identity = identity),
        object : PrincipalDirectory {
            override fun activePrincipal(principal: String): String? = principals[principal]

            override fun activePrincipalByEmail(email: String): String? = emails[email]
        },
        bridge.channel,
    )

    override fun close() {
        bridge.close()
        server.shutdownNow()
    }

    companion object {
        const val TOKEN = "internal-token"
    }
}

internal fun Instant.pb(): Timestamp = Timestamp.newBuilder().setSeconds(epochSecond).setNanos(nano).build()

private fun SourceUserModel.pb() = sourceUser {
    id = this@pb.id
    login = this@pb.login
}

/** [pr] as cp-go's bridge returns it; null [PullRequest.checks] is a head commit without a rollup. */
internal fun cpGoPullRequest(pr: PullRequest): PullRequestPb = pullRequest {
    number = pr.number
    open = pr.open
    draft = pr.draft
    merged = pr.merged
    pr.mergedAt?.let { mergedAt = it.pb() }
    pr.mergeCommit?.let { mergeCommit = it }
    headSha = pr.headSha
    baseRef = pr.baseRef
    pr.author?.let { author = it.pb() }
    pr.autoMerge?.let { a ->
        autoMerge = autoMerge {
            a.enabledBy?.let { enabledBy = it.pb() }
            a.enabledAt?.let { enabledAt = it.pb() }
            a.mergeMethod?.let { mergeMethod = it }
        }
    }
    mergeable = pr.mergeable
    mergeState = pr.mergeState
    pr.reviewDecision?.let { reviewDecision = it }
    unresolvedThreads = pr.unresolvedThreads
    canBeRebased = pr.canBeRebased
    for (r in pr.reviews) {
        reviews += review {
            id = r.id
            r.reviewer?.let { reviewer = it.pb() }
            state = ReviewStatePb.valueOf(r.state.name)
            r.submittedAt?.let { submittedAt = it.pb() }
            url = r.url
            r.commit?.let { commit = it }
        }
    }
    pr.checks?.let { list ->
        checks = checks {
            for (c in list) {
                checks += check {
                    name = c.name
                    required = c.required
                    status = CheckStatusPb.valueOf(c.status.name)
                    c.conclusion?.let { conclusion = CheckConclusionPb.valueOf(it.name) }
                }
            }
        }
    }
    for (f in pr.files) files += changedFile {
        path = f.path
        change = FileChangePb.valueOf(f.change.name)
    }
    for (c in pr.commits) {
        commits += commitAuthor {
            c.userId?.let { userId = it }
            c.email?.let { email = it }
            merge = c.merge
        }
    }
}
