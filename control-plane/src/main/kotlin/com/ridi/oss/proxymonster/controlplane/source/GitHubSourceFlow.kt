package com.ridi.oss.proxymonster.controlplane.source

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.AccessStore
import com.ridi.oss.proxymonster.controlplane.ApiError
import com.ridi.oss.proxymonster.controlplane.ApprovalService
import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.DatasourceStore
import com.ridi.oss.proxymonster.controlplane.PolicyStore
import com.ridi.oss.proxymonster.controlplane.PullRequestRef
import com.ridi.oss.proxymonster.controlplane.RequestOrigin
import com.ridi.oss.proxymonster.controlplane.SOURCE_GITHUB
import com.ridi.oss.proxymonster.controlplane.TaskServiceException
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzPrincipal
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.KeyOrder
import com.ridi.oss.proxymonster.controlplane.changeKey
import com.ridi.oss.proxymonster.controlplane.compareFileKeys
import com.ridi.oss.proxymonster.controlplane.contentHash
import com.ridi.oss.proxymonster.controlplane.dialect
import com.ridi.oss.proxymonster.controlplane.i18n.MessageCatalog
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.notify.NotificationEvent
import com.ridi.oss.proxymonster.controlplane.notify.NotificationService
import com.ridi.oss.proxymonster.controlplane.splitEngineConfig
import com.ridi.oss.proxymonster.probe.splitStatements
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Instant

@Serializable
data class GitHubFileInput(val path: String, val key: String, val content: String)

/** One Action step's filing: the pull request's new files under one directory, in any order. */
@Serializable
data class GitHubRequestsInput(
    val repository: String,
    val pr: Int,
    val scope: String? = null,
    val datasource: String,
    val schema: String,
    val role: String,
    val files: List<GitHubFileInput> = emptyList(),
    /** The commit the files were read from; a filing for any other head is refused. */
    val headSha: String = "",
    val order: KeyOrder = KeyOrder.NUMERIC,
)

@Serializable
data class GitHubRequestsResponse(val requests: List<AccessRequest>)

/**
 * SQL files from GitHub pull requests (docs/sql-from-github.md): files each pull request's new files as
 * requests, follows its reviews, and runs its approved files when it is ready to merge, or once merged, reporting
 * through the required [checkName] check. Every evaluation runs under one lock.
 */
class GitHubSourceFlow(
    private val adapter: SourceAdapter,
    private val approvals: ApprovalService,
    private val accessStore: AccessStore,
    private val datasourceStore: DatasourceStore,
    private val policyStore: PolicyStore,
    private val authz: Authz,
    private val notifications: NotificationService?,
    private val catalog: MessageCatalog = MessageCatalog(DOMAIN),
    private val locale: String,
    private val checkName: String,
    private val clock: Clock = Clock.systemUTC(),
    private val log: Logger = LoggerFactory.getLogger(GitHubSourceFlow::class.java),
    private val webUrl: String = "https://github.com",
) {
    private val mutex = Mutex()

    // The check last posted per pull request, so an unchanged poll posts nothing.
    private val posted = HashMap<Pair<String, Int>, PostedState>()

    private data class PostedState(val headSha: String, val status: CheckStatus, val conclusion: CheckConclusion?, val title: String)

    private class Keyed(val file: GitHubFileInput, val statements: List<String>, val key: String, val contentHash: String)

    suspend fun file(workload: AuthzPrincipal.Workload, input: GitHubRequestsInput): List<AccessRequest> {
        val repository = input.repository.trim()
        val repo = Repo.parse(repository) ?: throw fieldRequired("repository")
        val claimed = workload.claims["repository"]
        if (claimed == null || !claimed.equals(repository, ignoreCase = true)) {
            throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("approval.github_repository_mismatch"))
        }
        if (input.pr <= 0) throw fieldRequired("pr")
        if (input.headSha.isBlank()) throw fieldRequired("headSha")
        for ((field, value) in listOf("datasource" to input.datasource, "schema" to input.schema, "role" to input.role)) {
            if (value.isBlank()) throw fieldRequired(field)
        }
        val paths = input.files.map { it.path }
        if (paths.any { it.isBlank() } || paths.distinct().size != paths.size) throw fieldRequired("files")
        if (input.files.any { it.key.isBlank() }) throw fieldRequired("files")
        if (input.order == KeyOrder.NUMERIC) {
            input.files.firstOrNull { f -> !f.key.all { it in '0'..'9' } }?.let {
                throw TaskServiceException(HttpStatusCode.BadRequest, ApiError("approval.github_key_not_numeric", mapOf("path" to it.path)))
            }
        }
        val order = compareFileKeys(input.order)
        val files = input.files.sortedWith { a, b -> order.compare(a.key to a.path, b.key to b.path) }
        val ds = datasourceStore.list().firstOrNull { it.name == input.datasource } ?: throw notFound("datasource")
        val role = policyStore.getRoleByName(input.role) ?: throw notFound("role")
        val decision = authz.authorizeDatasourceAction(
            workload, AuthzAction.TASK_REQUEST, ds.name, AuthzContext(channel = Channel.GITHUB.contextValue), ds.tags,
        )
        if (decision is AuthzDecision.Deny) throw TaskServiceException(HttpStatusCode.Forbidden, ApiError("common.forbidden"))
        val number = input.pr
        val pr = adapter.readPullRequests(repo, listOf(number))[number] ?: throw notFound("pull request")
        if (!input.headSha.trim().equals(pr.headSha, ignoreCase = true)) {
            throw TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.github_stale_head", mapOf("head" to pr.headSha)))
        }
        val scope = input.scope?.trim()?.takeIf { it.isNotEmpty() } ?: "${ds.name}/${input.schema}"
        val dialect = ds.engine.dialect

        val splitConfig = ds.splitEngineConfig()
        val keyed = files.map { f ->
            val statements = splitStatements(f.content, splitConfig)?.takeIf { it.isNotEmpty() } ?: throw unsplittable()
            val hash = contentHash(f.content, dialect)
            Keyed(f, statements, changeKey(f.key, hash), hash)
        }

        return mutex.withLock {
            val all = accessStore.listGithubRequests(repository, number)
            val existing = all.filter { it.scope == scope }
            if (keyed.isEmpty()) {
                existing.filter { it.status in OPEN }.forEach { accessStore.endUnstarted(it.id, DELETED) }
                accessStore.setPrHead(repository, number, scope, emptyList(), pr.headSha, input.order.wireName)
                val current = dismissIfChanged(repo, pr, existing, keyed)
                if (all.isEmpty()) {
                    postCheck(repo, number, current, CheckStatus.COMPLETED, CheckConclusion.SKIPPED, text("check.no_sql"), "")
                } else {
                    evaluateLocked(repo, number, current)
                }
                return@withLock emptyList()
            }

            val requester = all.firstOrNull()?.principal
                ?: pr.author?.let { adapter.resolveUser(repo.owner, it, MappingRole.REQUESTER, pr.commitEmailsBy(it)) }
            if (requester == null) {
                safely("comment") { adapter.upsertComment(repo, number, "requester", text("comment.requester_unmapped")) }
                postCheck(repo, number, pr, CheckStatus.IN_PROGRESS, null, text("check.requester_unmapped"), "")
                return@withLock emptyList()
            }

            val actor = AuditActor("workload:${workload.name}", clientAddr = null, channel = Channel.GITHUB.contextValue)
            val prUrl = "$webUrl/$repository/pull/$number"
            val taken = HashSet<Long>()
            val filed = keyed.map { k ->
                val origin = RequestOrigin(
                    scope, k.file.key, k.contentHash, k.key,
                    PullRequestRef(
                        repository, number, prUrl = prUrl, path = k.file.path, headSha = pr.headSha,
                        defaultSchema = input.schema, keyOrder = input.order.wireName,
                    ),
                )
                val alreadyRan = { accessStore.changeKeyExecuted(scope, k.key) }
                val free = { r: AccessRequest -> r.id !in taken }
                // A file's request not yet run takes the file as filed now, at its path or, moved, under its key.
                val unrun = existing.firstOrNull { free(it) && it.status in OPEN && it.pullRequest?.path == k.file.path }
                    ?: existing.firstOrNull { free(it) && it.status in OPEN && it.changeKey == k.key }
                (
                    unrun?.let { approvals.editFromPullRequest(it, k.file.content, k.statements, origin, actor, alreadyRan()) }
                        ?: existing.firstOrNull { free(it) && it.changeKey == k.key && it.status !in DEAD }
                        ?: approvals.requestFromPullRequest(requester, actor, ds, role.name, k.statements, origin, SOURCE_GITHUB, alreadyRan())
                    ).also { taken += it.id }
            }

            val keys = keyed.map { it.key }.toSet()
            accessStore.setPrHead(repository, number, scope, keys.toList(), pr.headSha, input.order.wireName)
            existing.filter { it.status in OPEN && it.id !in taken }.forEach { accessStore.endUnstarted(it.id, DELETED) }
            evaluateLocked(repo, number, dismissIfChanged(repo, pr, existing, keyed))
            filed.mapNotNull { accessStore.getRequest(it.id) }
        }
    }

    /**
     * Dismiss [pr]'s approving reviews when this filing's keys differ from the previous filing's, and return
     * [pr] with those dismissals applied, since it was read before them.
     */
    private suspend fun dismissIfChanged(
        repo: Repo,
        pr: PullRequest,
        existing: List<AccessRequest>,
        keyed: List<Keyed>,
    ): PullRequest {
        val keys = keyed.map { it.key }.toSet()
        val previous = existing.filter { it.pullRequest?.filedHead != null && it.pullRequest?.headSha == it.pullRequest?.filedHead }
        val previousKeys = previous.mapNotNull { it.changeKey }.toSet()
        if (existing.isEmpty() || keys == previousKeys) return pr
        val changed = keyed.firstOrNull { it.key !in previousKeys }?.file?.path
            ?: previous.firstOrNull { it.changeKey !in keys }?.pullRequest?.path ?: ""
        val dismissed = HashSet<String>()
        for (review in latestReviews(pr).values.filter { it.state == ReviewState.APPROVED }) {
            safely("dismiss review") {
                adapter.dismissReview(repo, pr.number, review.id, text("review.dismissed", "path" to changed))
                dismissed += review.id
            }
        }
        return pr.copy(reviews = pr.reviews.map { if (it.id in dismissed) it.copy(state = ReviewState.DISMISSED) else it })
    }

    suspend fun pollOnce() {
        val read = accessStore.pullRequestsToPoll().flatMap { (repository, numbers) ->
            val repo = Repo.parse(repository) ?: return@flatMap emptyList()
            val prs = safely("read pull requests") { adapter.readPullRequests(repo, numbers) } ?: return@flatMap emptyList()
            numbers.map { Triple(repo, it, prs[it]) }
        }
        // Merged pull requests first, in merge order, so each sees the merges before it.
        for ((repo, number, pr) in read.sortedBy { it.third?.mergedAt ?: Instant.MAX }) evaluate(repo, number, pr)
    }

    suspend fun runPollLoop() {
        while (true) {
            try {
                pollOnce()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log.warn("github poll failed", e)
            }
            val low = (adapter.rateLimit?.remaining ?: Int.MAX_VALUE) < LOW_RATE_LIMIT
            delay(if (low) SLOW_POLL_MS else POLL_MS)
        }
    }

    internal suspend fun evaluate(repo: Repo, number: Int, pr: PullRequest?) {
        mutex.withLock { evaluateLocked(repo, number, pr) }
    }

    private suspend fun evaluateLocked(repo: Repo, number: Int, pr: PullRequest?) {
        try {
            evaluateUnguarded(repo, number, pr)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            log.warn("github evaluate failed repository={}/{} pr={}", repo.owner, repo.name, number, e)
        }
    }

    private suspend fun evaluateUnguarded(repo: Repo, number: Int, pr: PullRequest?) {
        val repository = repo.fullName
        var rows = accessStore.listGithubRequests(repository, number)
        if (rows.isEmpty() || pr == null) return

        val autoMerge = pr.autoMerge != null
        if (rows.any { it.pullRequest?.prAutoMerge != autoMerge }) accessStore.setPrAutoMerge(repository, number, autoMerge)

        if (pr.merged) {
            rows.filter { it.status == "EXECUTED" && it.mergedAt == null && it.pullRequest?.headSha != pr.headSha }
                .forEach { notifications?.emitEvent(NotificationEvent.TASK_MERGED_WITHOUT_FILE, it) }
            val at = pr.mergedAt ?: clock.instant()
            for ((scope, scoped) in rows.filter { it.scope != null }.groupBy { it.scope!! }) {
                val keys = scoped.filter { it.pullRequest?.headSha == pr.headSha }.mapNotNull { it.changeKey }
                accessStore.markMerged(repository, number, scope, keys, at, pr.mergeCommit)
            }
            // An approved file at the merged commit still runs; one that changed after it was filed cannot.
            rows.filter { it.status in OPEN && it.pullRequest?.headSha != pr.headSha }.forEach { accessStore.endUnstarted(it.id, CANCELLED) }
        } else if (!pr.open) {
            rows.filter { it.status == "EXECUTED" && it.mergedAt == null }
                .forEach { notifications?.emitEvent(NotificationEvent.TASK_CLOSED_AFTER_RUN, it) }
            rows.filter { it.status in OPEN }.forEach { accessStore.endUnstarted(it.id, CANCELLED) }
            return
        }

        // A file whose name and content already ran in its scope, from another pull request, does not run again.
        rows.filter { it.status in OPEN && keyExecuted(it) }.forEach { accessStore.endUnstarted(it.id, ALREADY_RAN) }
        applyReviews(repo, pr, accessStore.listGithubRequests(repository, number))
        rows = accessStore.listGithubRequests(repository, number)
        decideAndRun(repo, number, pr, rows)
    }

    /**
     * A review approves a request filed before it, at the commit the request was filed for; only that review's
     * dismissal, or a later changes-requested from the same reviewer, withdraws the approval.
     */
    private suspend fun applyReviews(repo: Repo, pr: PullRequest, rows: List<AccessRequest>) {
        val latest = latestReviews(pr)
        for (row in rows.filter { it.status == "APPROVED" && it.pullRequest?.approvedReviewId != null }) {
            val review = pr.reviews.firstOrNull { it.id == row.pullRequest?.approvedReviewId } ?: continue
            val later = review.reviewer?.let { latest[it.id] }?.takeIf {
                it.state == ReviewState.CHANGES_REQUESTED && (it.submittedAt ?: Instant.EPOCH) > (review.submittedAt ?: Instant.EPOCH)
            }
            if (review.state == ReviewState.DISMISSED || later != null) approvals.withdrawApproval(row.id, (later ?: review).url)
        }

        val approving = latest.values.filter { it.state == ReviewState.APPROVED && it.submittedAt != null }
        val pending = accessStore.listGithubRequests(repo.fullName, pr.number).filter { it.status == "PENDING" }
        if (approving.isEmpty() || pending.isEmpty()) return
        val principals = approving.associate { review ->
            review.id to safely("map reviewer") { adapter.resolveUser(repo.owner, review.reviewer!!, MappingRole.REVIEWER) }
        }
        for (row in pending) {
            val filedAt = Instant.parse(row.revisedAt ?: row.createdAt)
            // A review started on an older commit and submitted after a push read the older SQL.
            for (review in approving.filter { it.submittedAt!!.isAfter(filedAt) && it.commit == row.pullRequest?.headSha }) {
                val principal = principals[review.id] ?: continue
                if (approvals.approveFromReview(principal, row.id, review.id, review.url) != null) break
            }
        }
    }

    private suspend fun decideAndRun(repo: Repo, number: Int, pr: PullRequest, rows: List<AccessRequest>) {
        fun pending(title: String) = Triple(CheckStatus.IN_PROGRESS, null as CheckConclusion?, title)
        // Each scope's latest filing; a path's newest request in it is its file.
        val filed = rows.filter { it.pullRequest?.headSha != null && it.pullRequest?.headSha == it.pullRequest?.filedHead }
        // Each scope keeps its own key order, so its files run in that order.
        val active = filed.filter { it.status != ALREADY_RAN && it.status != DELETED }
            .groupBy { it.scope to it.pullRequest?.path }.values.map { sameFile -> sameFile.maxBy { it.id } }
            .groupBy { it.scope.orEmpty() }.toSortedMap().values.flatMap { scoped ->
                val order = compareFileKeys(KeyOrder.fromWire(scoped.first().pullRequest?.keyOrder))
                scoped.sortedWith { a, b -> order.compare(a.runKey(), b.runKey()) }
            }
        val filedAtHead = rows.groupBy { it.scope }.values.all { it.first().pullRequest?.filedHead == pr.headSha }
        val summary = rows.joinToString("\n") { "- `${it.pullRequest?.path}`: ${it.status}" }
        suspend fun post(state: Triple<CheckStatus, CheckConclusion?, String>) =
            postCheck(repo, number, pr, state.first, state.second, state.third, summary)

        val green = Triple(CheckStatus.COMPLETED, CheckConclusion.SUCCESS as CheckConclusion?, text("check.executed"))
        val blocked: Triple<CheckStatus, CheckConclusion?, String>? = when {
            !filedAtHead && pr.merged ->
                if (active.isNotEmpty() && active.all { it.status == "EXECUTED" }) green
                else Triple(CheckStatus.COMPLETED, CheckConclusion.FAILURE, text("check.merged_unfiled"))
            !filedAtHead -> pending(text("check.waiting_files"))
            // Every file's key already ran, in this pull request or another.
            active.isEmpty() && filed.any(::keyExecuted) ->
                green
            active.isEmpty() -> Triple(CheckStatus.COMPLETED, CheckConclusion.SKIPPED, text("check.no_sql"))
            active.all { it.status == "EXECUTED" } -> green
            active.any { it.status == "FAILED" } ->
                Triple(CheckStatus.COMPLETED, CheckConclusion.FAILURE, text("check.failed", "path" to active.first { it.status == "FAILED" }.pullRequest?.path))
            active.any { it.status in setOf("REJECTED", "CANCELLED", "DELETED") } ->
                Triple(CheckStatus.COMPLETED, CheckConclusion.FAILURE, text("check.cannot_run"))
            active.any { it.status == "EXECUTING" } -> pending(text("check.running", "path" to active.first { it.status == "EXECUTING" }.pullRequest?.path))
            active.any { it.status == "PENDING" } -> pending(text("check.awaiting_approval", "path" to active.first { it.status == "PENDING" }.pullRequest?.path))
            pr.merged -> null
            pr.draft -> pending(text("check.waiting_draft"))
            pr.autoMerge == null -> pending(text("check.approved_enable_automerge"))
            else -> {
                val rules = safely("read branch rules") { adapter.branchRules(repo, pr.baseRef) }
                if (rules == null || !checksGreen(pr, rules.contexts)) pending(text("check.waiting_checks")) else mergeBlocked(repo, pr, rules)?.let(::pending)
            }
        }
        if (blocked != null) return post(blocked)

        val toRun = active.filter { it.status == "APPROVED" }
        for ((scope, scoped) in toRun.filter { it.scope != null }.groupBy { it.scope!! }) {
            if (scoped.all { it.forceRun }) continue
            val waiting = if (pr.merged) busyTitle(scope, repo, number) else waitingOn(scope, repo, number, pr.headSha)
            waiting?.let { return post(pending(it)) }
        }
        val executor = (if (pr.merged) pr.mergedBy else pr.autoMerge?.enabledBy)?.let {
            safely("map executor") { adapter.resolveUser(repo.owner, it, MappingRole.REQUESTER, pr.commitEmailsBy(it)) }
        } ?: return post(pending(text(if (pr.merged) "check.merger_unmapped" else "check.executor_unmapped")))

        for (row in toRun) {
            if (keyExecuted(row)) {
                accessStore.endUnstarted(row.id, ALREADY_RAN)
                continue
            }
            post(pending(text("check.running", "path" to row.pullRequest?.path)))
            val result = try {
                approvals.runOnMerge(executor, row.id)
            } catch (e: TaskServiceException) {
                if (e.error.code != "approval.scope_busy") {
                    return post(Triple(CheckStatus.COMPLETED, CheckConclusion.FAILURE, text("check.cannot_run")))
                }
                return post(pending(row.scope?.let { busyTitle(it, repo, number) } ?: text("check.update_branch")))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log.warn("github run failed request={}", row.id, e)
                return post(Triple(CheckStatus.COMPLETED, CheckConclusion.FAILURE, text("check.cannot_run")))
            }
            if (result.status != "EXECUTED") {
                return post(Triple(CheckStatus.COMPLETED, CheckConclusion.FAILURE, text("check.failed", "path" to row.pullRequest?.path)))
            }
        }
        post(green)
    }

    private fun AccessRequest.runKey(): Pair<String, String> = (fileKey ?: pullRequest?.path.orEmpty().substringAfterLast('/')) to pullRequest?.path.orEmpty()

    private fun keyExecuted(r: AccessRequest): Boolean =
        r.scope != null && r.changeKey != null && accessStore.changeKeyExecuted(r.scope, r.changeKey)

    /**
     * Why the pull request's files in [scope] cannot run yet, or null when they can. Its head must contain the
     * scope's last merged run from the same repository; a failed comparison keeps it waiting.
     */
    private suspend fun waitingOn(scope: String, repo: Repo, number: Int, headSha: String): String? {
        busyTitle(scope, repo, number)?.let { return it }
        val last = accessStore.lastMergedRun(scope, repo.fullName) ?: return null
        return when (safely("compare commits") { adapter.compareCommits(repo, last.pullRequest!!.mergeSha!!, headSha) }) {
            CommitRelation.AHEAD, CommitRelation.IDENTICAL -> null
            else -> text("check.update_branch_behind", "pr" to last.pullRequest?.pr?.toString())
        }
    }

    /** Why another pull request's unmerged run holds the scope, or null when none does. */
    private fun busyTitle(scope: String, repo: Repo, number: Int): String? =
        accessStore.scopeBlocker(scope, repo.fullName, number)?.let { blocker ->
            val pr = blocker.pullRequest?.pr?.toString() ?: return@let text("check.update_branch")
            text(if (blocker.mergedAt != null) "check.waiting_merged_run" else "check.waiting_merge", "pr" to pr)
        }

    private suspend fun postCheck(
        repo: Repo,
        number: Int,
        pr: PullRequest,
        status: CheckStatus,
        conclusion: CheckConclusion?,
        title: String,
        summary: String,
    ) {
        val key = repo.fullName to number
        val state = PostedState(pr.headSha, status, conclusion, title)
        if (posted[key] == state) return
        safely("post check") {
            adapter.postCheck(repo, pr.headSha, checkName, status, conclusion, title, summary)
            posted[key] = state
        }
    }

    private fun latestReviews(pr: PullRequest): Map<String, Review> =
        pr.reviews
            .filter { it.reviewer != null && it.state in COUNTED_REVIEWS }
            .groupBy { it.reviewer!!.id }
            .mapValues { (_, reviews) -> reviews.maxBy { it.submittedAt ?: Instant.EPOCH } }

    /**
     * Every context [required] or the rollup marks required ran green on the head, and no other check is still
     * running: a branch that requires no checks would otherwise run the SQL before CI that may still fail. Every
     * proxy-monster's check is left out, since each waits for the merge.
     */
    private fun checksGreen(pr: PullRequest, required: Set<String>): Boolean {
        val checks = pr.checks?.filterNot { isQueryCheck(it.name) } ?: return false
        if (checks.any { it.status != CheckStatus.COMPLETED }) return false
        val needed = (required + checks.filter { it.required }.map { it.name }).filterNot(::isQueryCheck)
        return needed.all { name ->
            val runs = checks.filter { it.name == name }
            runs.isNotEmpty() && runs.all { it.conclusion in GREEN }
        }
    }

    /**
     * Why GitHub would refuse to merge [pr] once this flow's check passes, or null when it would merge. While that
     * check is required, GitHub reports every such PR as blocked, so the rules behind that verdict are read here.
     */
    private suspend fun mergeBlocked(repo: Repo, pr: PullRequest, rules: BranchRules): String? {
        val ownRequired = checkName in rules.contexts || pr.checks.orEmpty().any { it.own && it.required }
        val method = pr.autoMerge?.mergeMethod?.lowercase()
        return when {
            pr.mergeable == "CONFLICTING" -> text("check.conflicts")
            pr.mergeable != "MERGEABLE" -> text("check.waiting_mergeable")
            pr.mergeState == "BEHIND" -> text("check.update_branch")
            pr.reviewDecision != null && pr.reviewDecision != "APPROVED" -> text("check.waiting_reviews")
            rules.threadResolution && pr.unresolvedThreads > 0 -> text("check.waiting_threads")
            rules.mergeMethods.isNotEmpty() && method !in rules.mergeMethods -> text("check.merge_method", "method" to method)
            method == "rebase" && !pr.canBeRebased -> text("check.cannot_rebase")
            rules.strict && safely("compare with base") { adapter.compareCommits(repo, pr.baseRef, pr.headSha) }
                .let { it != CommitRelation.AHEAD && it != CommitRelation.IDENTICAL } -> text("check.update_branch")
            !ownRequired -> if (pr.mergeState in MERGEABLE_STATES) null else text("check.waiting_mergeable")
            rules.unchecked.isNotEmpty() -> text("check.unchecked_rule", "rule" to rules.unchecked.joinToString(", "))
            pr.mergeState != "BLOCKED" && pr.mergeState !in MERGEABLE_STATES -> text("check.waiting_mergeable")
            else -> null
        }
    }

    private fun text(key: String, vararg params: Pair<String, String?>): String =
        catalog.text(key, locale, params.associate { (k, v) -> k to (v ?: "") })

    private suspend fun <T> safely(what: String, block: suspend () -> T): T? = try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        log.warn("github {} failed", what, e)
        null
    }

    private fun fieldRequired(field: String) =
        TaskServiceException(HttpStatusCode.BadRequest, ApiError("common.field_required", mapOf("fields" to field)))

    private fun notFound(resource: String) =
        TaskServiceException(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to resource)))

    private fun unsplittable() = TaskServiceException(HttpStatusCode.Conflict, ApiError("approval.unsplittable_sql"))

    companion object {
        private const val CHECK_SUFFIX = "query executed"

        /** The check one instance posts: `<instance>/query executed`. */
        fun checkName(instanceName: String) = "$instanceName/$CHECK_SUFFIX"

        private fun isQueryCheck(name: String) = name == CHECK_SUFFIX || name.endsWith("/$CHECK_SUFFIX")
        const val DOMAIN = "github"
        private const val DELETED = "DELETED"
        private const val ALREADY_RAN = "ALREADY_RAN"
        private const val CANCELLED = "CANCELLED"
        private const val POLL_MS = 15_000L
        private const val SLOW_POLL_MS = 60_000L
        private const val LOW_RATE_LIMIT = 500
        private val OPEN = setOf("PENDING", "APPROVED")
        private val DEAD = setOf(DELETED, CANCELLED, "REJECTED")
        private val GREEN = setOf(CheckConclusion.SUCCESS, CheckConclusion.NEUTRAL, CheckConclusion.SKIPPED)
        private val MERGEABLE_STATES = setOf("CLEAN", "UNSTABLE", "HAS_HOOKS")
        private val COUNTED_REVIEWS = setOf(ReviewState.APPROVED, ReviewState.CHANGES_REQUESTED, ReviewState.DISMISSED)

        /** The web host for pull-request links: github.com for the public API, the server itself for GHES. */
        fun webUrlFor(apiUrl: String): String {
            val trimmed = apiUrl.trimEnd('/')
            return if (trimmed == "https://api.github.com") "https://github.com" else trimmed.removeSuffix("/api/v3")
        }
    }
}
