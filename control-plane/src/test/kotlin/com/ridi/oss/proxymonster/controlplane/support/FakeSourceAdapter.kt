package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.source.BranchRules
import com.ridi.oss.proxymonster.controlplane.source.CheckConclusion
import com.ridi.oss.proxymonster.controlplane.source.CheckStatus
import com.ridi.oss.proxymonster.controlplane.source.CommitRelation
import com.ridi.oss.proxymonster.controlplane.source.MappingRole
import com.ridi.oss.proxymonster.controlplane.source.PullRequest
import com.ridi.oss.proxymonster.controlplane.source.RateLimit
import com.ridi.oss.proxymonster.controlplane.source.Repo
import com.ridi.oss.proxymonster.controlplane.source.ReviewState
import com.ridi.oss.proxymonster.controlplane.source.SourceAdapter
import com.ridi.oss.proxymonster.controlplane.source.SourceUser
import java.util.Collections

/** An in-memory [SourceAdapter]: pull requests and user mappings the test sets, and every write recorded. */
class FakeSourceAdapter : SourceAdapter {
    data class PostedCheck(
        val repo: Repo,
        val headSha: String,
        val name: String,
        val status: CheckStatus,
        val conclusion: CheckConclusion?,
        val title: String,
    )

    data class Dismissal(val repo: Repo, val pr: Int, val reviewId: String, val message: String)

    data class Comment(val repo: Repo, val pr: Int, val marker: String?, val body: String)

    val pulls: MutableMap<Pair<Repo, Int>, PullRequest> = Collections.synchronizedMap(LinkedHashMap())

    /** [SourceUser.id] → principal; null or absent is unmapped. */
    val users: MutableMap<String, String?> = Collections.synchronizedMap(HashMap())

    /** Principals mapped only by commit email, for requesters. */
    val commitEmailUsers: MutableMap<String, String> = Collections.synchronizedMap(HashMap())

    val checks: MutableList<PostedCheck> = Collections.synchronizedList(ArrayList())
    val dismissals: MutableList<Dismissal> = Collections.synchronizedList(ArrayList())
    val comments: MutableList<Comment> = Collections.synchronizedList(ArrayList())
    val upserts: MutableList<Comment> = Collections.synchronizedList(ArrayList())

    /** Base branch → its rules; absent requires nothing. */
    val branchRules: MutableMap<String, BranchRules> = Collections.synchronizedMap(HashMap())

    /** When set, reading the branch rules throws. */
    @Volatile var branchRulesFail = false

    /** (repo, base, head) → relation; absent is [CommitRelation.AHEAD]. */
    val relations: MutableMap<Triple<Repo, String, String>, CommitRelation> = Collections.synchronizedMap(HashMap())

    @Volatile override var rateLimit: RateLimit? = null

    override suspend fun readPullRequests(repo: Repo, numbers: List<Int>): Map<Int, PullRequest> =
        numbers.mapNotNull { n -> pulls[repo to n]?.let { n to it } }.toMap()

    override suspend fun readFile(repo: Repo, ref: String, path: String): ByteArray = error("readFile is not used")

    override suspend fun compareCommits(repo: Repo, base: String, head: String): CommitRelation =
        relations[Triple(repo, base, head)] ?: CommitRelation.AHEAD

    override suspend fun branchRules(repo: Repo, branch: String): BranchRules {
        if (branchRulesFail) error("branch rules unavailable")
        return branchRules[branch] ?: BranchRules()
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
        checks += PostedCheck(repo, headSha, name, status, conclusion, title)
    }

    /** When set, dismissing a review throws and leaves it as it was. */
    @Volatile var dismissFail = false

    override suspend fun dismissReview(repo: Repo, pr: Int, reviewId: String, message: String) {
        if (dismissFail) error("dismissal refused")
        dismissals += Dismissal(repo, pr, reviewId, message)
        pulls[repo to pr]?.let { current ->
            pulls[repo to pr] = current.copy(
                reviews = current.reviews.map { if (it.id == reviewId) it.copy(state = ReviewState.DISMISSED) else it },
            )
        }
    }

    override suspend fun postComment(repo: Repo, pr: Int, body: String) {
        comments += Comment(repo, pr, null, body)
    }

    override suspend fun upsertComment(repo: Repo, pr: Int, marker: String, body: String) {
        upserts += Comment(repo, pr, marker, body)
    }

    override suspend fun resolveUser(org: String, user: SourceUser, role: MappingRole, commitEmails: List<String>): String? =
        users[user.id] ?: if (role == MappingRole.REQUESTER) commitEmails.firstNotNullOfOrNull { commitEmailUsers[it] } else null
}
