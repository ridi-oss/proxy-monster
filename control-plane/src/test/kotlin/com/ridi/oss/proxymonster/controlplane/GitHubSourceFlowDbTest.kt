package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.AuthzPrincipal
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.AuditSource
import com.ridi.oss.proxymonster.controlplane.notify.NotificationService
import com.ridi.oss.proxymonster.controlplane.notify.NotificationStore
import com.ridi.oss.proxymonster.controlplane.notify.RecipientResolver
import com.ridi.oss.proxymonster.controlplane.notify.StatementDisclosure
import com.ridi.oss.proxymonster.controlplane.source.AutoMerge
import com.ridi.oss.proxymonster.controlplane.source.BranchRules
import com.ridi.oss.proxymonster.controlplane.source.Check
import com.ridi.oss.proxymonster.controlplane.source.CheckConclusion
import com.ridi.oss.proxymonster.controlplane.source.CheckStatus
import com.ridi.oss.proxymonster.controlplane.source.CommitAuthor
import com.ridi.oss.proxymonster.controlplane.source.CommitRelation
import com.ridi.oss.proxymonster.controlplane.source.GitHubFileInput
import com.ridi.oss.proxymonster.controlplane.source.GitHubRequestsInput
import com.ridi.oss.proxymonster.controlplane.source.GitHubRequestsResponse
import com.ridi.oss.proxymonster.controlplane.source.GitHubSourceFlow
import com.ridi.oss.proxymonster.controlplane.source.PullRequest
import com.ridi.oss.proxymonster.controlplane.source.Repo
import com.ridi.oss.proxymonster.controlplane.source.Review
import com.ridi.oss.proxymonster.controlplane.source.ReviewState
import com.ridi.oss.proxymonster.controlplane.source.SourceUser
import com.ridi.oss.proxymonster.controlplane.support.FakeCpGo
import com.ridi.oss.proxymonster.controlplane.support.FakeSourceAdapter
import com.ridi.oss.proxymonster.controlplane.support.FakeTransport
import com.ridi.oss.proxymonster.controlplane.support.cpGoPullRequest
import com.ridi.oss.proxymonster.cpgo.readPullRequestsResponse
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import com.ridi.oss.proxymonster.controlplane.support.withFakeProxy
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.ProxyRunMsg
import com.ridi.oss.proxymonster.grpc.proxyRunMsg
import com.ridi.oss.proxymonster.grpc.runDecision
import com.ridi.oss.proxymonster.grpc.runDone
import com.ridi.oss.proxymonster.grpc.runError
import io.grpc.ManagedChannel
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.time.Instant
import java.util.Collections
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** SQL files from GitHub end to end: filing, review approval, the merge-triggered run, and the scope rules. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GitHubSourceFlowDbTest {
    private val wireJson = Json { encodeDefaults = true; explicitNulls = false }
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var resultStore: QueryResultStore
    private lateinit var datasource: Datasource
    private lateinit var role: Role
    private lateinit var config: Config
    private lateinit var sessionStore: PrincipalSessionStore
    private lateinit var approvals: ApprovalService
    private lateinit var notifications: NotificationService
    private lateinit var flow: GitHubSourceFlow
    private lateinit var server: GrpcServer
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var rawChannel: ManagedChannel
    private lateinit var appScope: CoroutineScope

    private val adapter = FakeSourceAdapter()
    private val transport = FakeTransport()
    private val repo = Repo("acme", "shop")
    private val seq = AtomicInteger(100)

    private val alice = "alice@example.com"
    private val bob = "bob@example.com"
    private val carol = "carol@example.com"
    private val dave = "dave@example.com"
    private val aliceUser = SourceUser("1", "alice")
    private val bobUser = SourceUser("2", "bob")
    private val carolUser = SourceUser("3", "carol")
    private val malloryUser = SourceUser("9", "mallory")

    private val workload = AuthzPrincipal.Workload("github", "https://token.actions.githubusercontent.com", mapOf("repository" to "acme/shop"))

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_github_source"))
        core = ControlPlaneCore(dataSource)
        resultStore = QueryResultStore(dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        sessionStore = PrincipalSessionStore(dataSource, null)
        datasource = core.datasourceStore.create(
            DatasourceInput(name = "shop-pg", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )
        role = core.policyStore.createRole(RoleInput("schema-migrator"))
        for (p in listOf(alice, bob, carol, dave)) {
            core.userGroupStore.createUser(AppUserInput(principal = p), core.tokenStore, core.accessStore, sessionStore)
        }
        core.policyStore.createAssignment(RoleAssignmentInput(dave, core.policyStore.getRoleByName("system:admin")!!.id))
        // alice holds the permit too, so her own review is refused by the shipped no-self-approval forbid alone.
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "github-test-approvers",
                cedarSrc = """permit(principal, action in [Action::"task.approve", Action::"task.run", Action::"task.read"], resource)
                    when { principal == User::"$bob" || principal == User::"$alice" };""",
            ),
            updatedBy = null,
        )
        adapter.users += mapOf(aliceUser.id to alice, bobUser.id to bob, carolUser.id to carol)

        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "github-source-test-secret-at-least-32", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
            ciOidcIssuers = listOf(CiOidcIssuer("github", workload.issuer, "proxy-monster")),
        )
        appScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        notifications = NotificationService(
            store = NotificationStore(dataSource),
            recipients = RecipientResolver(core.authz, core.roleResolver) { listOf(alice, bob, carol) },
            transports = listOf(transport),
            accessStore = core.accessStore,
            queryResultStore = resultStore,
            webBaseUrl = "https://console.example",
            disclosure = StatementDisclosure.AUTO,
            defaultLocale = "en",
        )
        approvals = ApprovalService(
            config, core.accessStore, core.auditStore, core.datasourceStore, core.policyStore, core.userGroupStore,
            resultStore, core.roleResolver, core.authz, RunExecService(core), appScope, notifications = notifications,
        )
        flow = GitHubSourceFlow(
            adapter, approvals, core.accessStore, core.datasourceStore, core.policyStore, core.authz, notifications,
            locale = "en", checkName = checkName,
        )
        server = GrpcServer(0, ControlPlaneGrpcService(core), secretToken = null).also { it.start() }
        rawChannel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(rawChannel)
    }

    @AfterAll
    fun teardown() {
        if (::rawChannel.isInitialized) rawChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        if (::server.isInitialized) server.shutdown()
        if (::appScope.isInitialized) appScope.cancel()
    }

    private fun schema() = "s${seq.incrementAndGet()}"

    private fun number() = seq.incrementAndGet()

    private val checkName = GitHubSourceFlow.checkName("pm")

    private val green = Check("build", required = true, status = CheckStatus.COMPLETED, conclusion = CheckConclusion.SUCCESS)

    // Ahead of now, so a review added after a filing is later than it even when the database clock runs ahead.
    private fun approval(
        by: SourceUser,
        id: String = "r${seq.incrementAndGet()}",
        state: ReviewState = ReviewState.APPROVED,
        submittedAt: Instant = Instant.now().plusSeconds(5),
        commit: String? = null,
    ) = Review(id, by, state, submittedAt, "https://github.com/acme/shop/pull/1#$id", commit)

    private fun open(n: Int, author: SourceUser? = aliceUser, baseRef: String = "main") {
        adapter.pulls[repo to n] = PullRequest(
            number = n, open = true, merged = false, mergedAt = null, headSha = "sha$n", baseRef = baseRef,
            author = author, autoMerge = null, reviews = emptyList(), checks = listOf(green), files = emptyList(),
        )
    }

    /** A review added without a commit is on the head of the update that adds it, as a reviewer on GitHub would be. */
    private fun update(n: Int, change: (PullRequest) -> PullRequest) {
        val next = change(adapter.pulls.getValue(repo to n))
        adapter.pulls[repo to n] = next.copy(reviews = next.reviews.map { if (it.commit == null) it.copy(commit = next.headSha) else it })
    }

    private fun merge(n: Int) = update(n) { it.copy(open = false, merged = true, mergedAt = Instant.now(), mergeCommit = "merge$n") }

    private fun readyToMerge(n: Int) = update(n) {
        it.copy(reviews = it.reviews + approval(bobUser), autoMerge = AutoMerge(carolUser, Instant.now()))
    }

    private fun input(
        n: Int,
        schema: String,
        files: List<Pair<String, String>>,
        headSha: String = adapter.pulls[repo to n]?.headSha ?: "sha$n",
        scope: String? = null,
        order: KeyOrder = KeyOrder.STRING,
    ) = GitHubRequestsInput(
        repository = "acme/shop", pr = n, scope = scope, datasource = datasource.name, schema = schema, role = role.name,
        files = files.map { (path, content) -> GitHubFileInput(path, fileKey(path), content) }, headSha = headSha, order = order,
    )

    /** The Action's default pattern: a name's leading digits before `_`, else the whole name. */
    private fun fileKey(path: String): String {
        val name = path.substringAfterLast('/')
        return Regex("^([0-9]+)_").find(name)?.groupValues?.get(1) ?: name
    }

    private fun file(
        n: Int,
        schema: String,
        files: List<Pair<String, String>>,
        scope: String? = null,
        order: KeyOrder = KeyOrder.STRING,
    ): List<AccessRequest> = runBlocking { flow.file(workload, input(n, schema, files, scope = scope, order = order)) }

    private fun refused(w: AuthzPrincipal.Workload = workload, input: GitHubRequestsInput): TaskServiceException =
        assertFailsWith<TaskServiceException> { runBlocking { flow.file(w, input) } }

    private fun status(id: Long) = core.accessStore.getRequest(id)?.status

    private suspend fun evaluate(n: Int) = flow.evaluate(repo, n, adapter.readPullRequests(repo, listOf(n))[n])

    private fun recheck(n: Int) = runBlocking { evaluate(n) }

    /** The proxy's answer to one statement: ALLOW and done, or a target error when the SQL contains [fail]. */
    private fun answer(sql: String, fail: String?): List<ProxyRunMsg> {
        val id = core.auditStore.insert(
            AuditEvent(principal = carol, datasource = datasource.name, statement = "ddl", decision = Decision.ALLOW, channel = "workflow-executor"),
        )
        val decided = proxyRunMsg { decision = runDecision { decision = EnfAction.ALLOW; decisionId = id } }
        return if (fail != null && fail in sql) {
            listOf(decided, proxyRunMsg { error = runError { message = "ER_PARSE_ERROR"; rawMessage = "syntax error"; targetDbError = true } })
        } else {
            listOf(decided, proxyRunMsg { done = runDone { rowsAffected = 0 } })
        }
    }

    /** The default schema of every run channel the fake proxy was asked to open. */
    private val openedSchemas = Collections.synchronizedList(mutableListOf<String>())

    private fun withProxy(fail: String? = null, body: suspend () -> Unit) = runBlocking {
        withFakeProxy(core, stub, datasource.name, respond = { _, sql, open ->
            openedSchemas += open.defaultSchema
            answer(sql, fail)
        }) { body() }
    }

    private fun pollWithProxy(fail: String? = null) = withProxy(fail) { flow.pollOnce() }

    private fun lastCheck(n: Int, sha: String = "sha$n") = assertNotNull(adapter.checks.lastOrNull { it.headSha == sha }, "no check on #$n at $sha")

    private fun outboxRecipients(taskId: Long, event: String): List<String> = dataSource.connection.use { c ->
        c.prepareStatement("SELECT recipient FROM notification_outbox WHERE task_id = ? AND event = ?").use { ps ->
            ps.setLong(1, taskId)
            ps.setString(2, event)
            ps.executeQuery().use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } }
        }
    }

    private fun rows(n: Int) = core.accessStore.listGithubRequests("acme/shop", n)

    /** Files [files] on a fresh pull request and runs them to a merge, returning the executed rows. */
    private fun runToMerge(schema: String, files: List<Pair<String, String>>): List<AccessRequest> {
        val n = number()
        open(n)
        file(n, schema, files)
        readyToMerge(n)
        pollWithProxy()
        merge(n)
        recheck(n)
        return rows(n)
    }

    private fun ApplicationTestBuilder.serve(): HttpClient {
        application {
            attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            install(Sessions) { webSessionCookie(sessionStore, config.sessionSecret) }
            routing {
                testLoginRoute(sessionStore, config)
                githubSourceRoutes(config, core.tokenStore, flow)
                approvalRoutes(
                    config, core.accessStore, core.auditStore, core.datasourceStore, core.policyStore,
                    core.userGroupStore, resultStore, core.roleResolver, core.authz, RunExecService(core),
                    service = approvals,
                )
            }
        }
        return createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    private fun workloadToken(): String =
        core.tokenStore.dataSource.inTx { c -> core.tokenStore.issueWorkload("github", workload.claims, 600, c) }.token

    @Test
    fun `a reviewed file runs when its pull request is ready to merge, then records the merge`() = testApplication {
        val client = serve()
        val n = number()
        val schema = schema()
        open(n)
        val response = client.post("/api/github/requests") {
            header(HttpHeaders.Authorization, "Bearer ${workloadToken()}")
            contentType(ContentType.Application.Json)
            setBody(input(n, schema, listOf("db/$schema/001_init.sql" to "create table t (id int)")))
        }
        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.body<GitHubRequestsResponse>()
        assertEquals(checkName, body.checkName)
        val filed = body.requests.single()
        assertEquals("PENDING", filed.status)
        assertEquals("github", filed.source)
        assertEquals(schema, filed.pullRequest!!.defaultSchema)
        assertEquals("${datasource.name}/$schema", filed.scope)
        assertEquals("https://github.com/acme/shop/pull/$n", filed.pullRequest!!.prUrl)
        assertEquals("001", filed.fileKey)
        assertEquals(contentHash("create table t (id int)", datasource.engine.dialect), filed.contentHash)
        assertTrue(filed.contentHash!!.startsWith("n:"))
        assertEquals(changeKey("001", filed.contentHash!!), filed.changeKey)
        assertEquals("string", filed.pullRequest!!.keyOrder)
        assertEquals("acme/shop", filed.pullRequest!!.repository)
        assertEquals(n, filed.pullRequest!!.pr)
        assertEquals("db/$schema/001_init.sql", filed.pullRequest!!.path)
        assertEquals("sha$n", filed.pullRequest!!.headSha)
        val wire = wireJson.encodeToJsonElement(AccessRequest.serializer(), filed).jsonObject
        assertEquals("acme/shop", wire.getValue("pullRequest").jsonObject.getValue("repository").jsonPrimitive.content)
        assertFalse("prUrl" in wire)
        assertEquals(CheckStatus.IN_PROGRESS, lastCheck(n).status)
        assertTrue(lastCheck(n).title.contains("001_init.sql"), lastCheck(n).title)

        readyToMerge(n)
        openedSchemas.clear()
        pollWithProxy()
        assertEquals(listOf(schema), openedSchemas)
        val executed = rows(n).single()
        assertEquals("EXECUTED", executed.status)
        assertEquals(bob, executed.decidedBy)
        assertEquals(carol, executed.executedBy)
        assertEquals(CheckStatus.COMPLETED to CheckConclusion.SUCCESS, lastCheck(n).status to lastCheck(n).conclusion)
        assertNull(executed.mergedAt)

        merge(n)
        pollWithProxy()
        assertNotNull(rows(n).single().mergedAt)
        assertEquals("merge$n", rows(n).single().pullRequest!!.mergeSha)
        Unit
    }

    @Test
    fun `a push that changes a file edits its request and dismisses the approval`() {
        val n = number()
        val schema = schema()
        open(n)
        val first = file(n, schema, listOf("db/a.sql" to "create table a (id int)")).single()
        update(n) { it.copy(reviews = listOf(approval(bobUser, id = "501"))) }
        recheck(n)
        assertEquals("APPROVED", core.accessStore.getRequest(first.id)?.status)

        update(n) { it.copy(headSha = "sha$n-2") }
        val second = file(n, schema, listOf("db/a.sql" to "create table a (id bigint)")).single()
        assertEquals(first.id, second.id, "the file keeps one request")
        assertEquals("PENDING", second.status)
        assertEquals(2, second.revision)
        assertEquals("create table a (id bigint)", second.sql)
        assertEquals(1, rows(n).size)
        val dismissal = adapter.dismissals.single { it.pr == n }
        assertEquals("501", dismissal.reviewId)
        assertTrue(dismissal.message.contains("db/a.sql"), dismissal.message)

        // A push that keeps every key keeps the request and its approval.
        update(n) { it.copy(reviews = it.reviews + approval(bobUser)) }
        recheck(n)
        update(n) { it.copy(headSha = "sha$n-3") }
        val kept = file(n, schema, listOf("db/a.sql" to "CREATE TABLE a (id bigint) -- reformatted")).single()
        assertEquals(second.id, kept.id)
        assertEquals("APPROVED", kept.status)
    }

    @Test
    fun `an edit is credited to the author of the newest commit`() {
        val n = number()
        val schema = schema()
        open(n)
        val first = file(n, schema, listOf("db/e.sql" to "create table e (id int)")).single()
        update(n) {
            it.copy(
                headSha = "sha$n-2",
                commits = listOf(CommitAuthor(aliceUser.id, null, merge = false, login = aliceUser.login), CommitAuthor(carolUser.id, null, merge = false, login = carolUser.login)),
            )
        }
        file(n, schema, listOf("db/e.sql" to "create table e (id bigint)"))
        val edited = RequestEvents.list(dataSource, first.id).single { it.kind == "edited" }
        assertEquals(carol, edited.actor)
    }

    @Test
    fun `a scope waits for another pull request's unmerged run, then for a branch update`() {
        val schema = schema()
        runToMerge(schema, listOf("db/00041.sql" to "create table base (id int)"))

        val a = number()
        open(a)
        file(a, schema, listOf("db/00042_a.sql" to "create table a (id int)"))
        readyToMerge(a)
        pollWithProxy()
        assertEquals("EXECUTED", rows(a).single().status)

        val b = number()
        open(b)
        file(b, schema, listOf("db/00042_b.sql" to "create table b (id int)"))
        readyToMerge(b)
        pollWithProxy()
        assertEquals("APPROVED", rows(b).single().status)
        assertEquals("Waiting for #$a to merge", lastCheck(b).title)

        merge(a)
        adapter.relations[Triple(repo, "merge$a", "sha$b")] = CommitRelation.BEHIND
        pollWithProxy()
        assertEquals("merge$a", rows(a).single().pullRequest!!.mergeSha)
        assertEquals("APPROVED", rows(b).single().status)
        assertEquals("Update your branch — #$a merged first", lastCheck(b).title)

        adapter.relations[Triple(repo, "merge$a", "sha$b")] = CommitRelation.AHEAD
        pollWithProxy()
        assertEquals("EXECUTED", rows(b).single().status)
        assertEquals(CheckConclusion.SUCCESS, lastCheck(b).conclusion)
    }

    private fun forceRun(id: Long) = approvals.forceRun(dave, null, AuditActor(dave, channel = AuditSource.CONSOLE), id)

    @Test
    fun `force-run needs task force_run, and an approver without it is refused`() = testApplication {
        val client = serve()
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/f.sql" to "create table f (id int)")).single()

        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$bob").status)
        val refused = client.post("/api/approvals/${req.id}/force-run")
        assertEquals(HttpStatusCode.Forbidden to "approval.not_approver", refused.status to refused.body<ApiError>().code)
        assertEquals(false, core.accessStore.getRequest(req.id)?.forceRun)

        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$dave").status)
        val forced = client.post("/api/approvals/${req.id}/force-run")
        assertEquals(HttpStatusCode.OK, forced.status)
        val body = forced.body<AccessRequest>()
        assertEquals(true to dave, body.forceRun to body.forceRunBy)
        assertTrue(outboxRecipients(req.id, "task.force_run").isNotEmpty())

        val outbox = outboxRecipients(req.id, "task.force_run").size
        assertEquals(HttpStatusCode.OK, client.post("/api/approvals/${req.id}/force-run").status)
        assertEquals(outbox, outboxRecipients(req.id, "task.force_run").size)
        Unit
    }

    @Test
    fun `a forced request runs while another pull request's run is unmerged`() {
        val schema = schema()
        val a = number()
        open(a)
        file(a, schema, listOf("db/00051_a.sql" to "create table fa (id int)"))
        readyToMerge(a)
        withProxy { evaluate(a) }
        assertEquals("EXECUTED", rows(a).single().status)

        val b = number()
        open(b)
        val req = file(b, schema, listOf("db/00051_b.sql" to "create table fb (id int)")).single()
        readyToMerge(b)
        withProxy { evaluate(b) }
        assertEquals("APPROVED", status(req.id))
        assertEquals("Waiting for #$a to merge", lastCheck(b).title)

        forceRun(req.id)
        assertTrue(outboxRecipients(req.id, "task.force_run").isNotEmpty())
        withProxy { evaluate(b) }
        assertEquals("EXECUTED", status(req.id))
        assertEquals(CheckConclusion.SUCCESS, lastCheck(b).conclusion)
    }

    @Test
    fun `a forced request runs on a branch behind the scope's last merged run`() {
        val schema = schema()
        val merged = runToMerge(schema, listOf("db/00061.sql" to "create table fbase (id int)")).single()
        val n = number()
        open(n)
        val req = file(n, schema, listOf("db/00062.sql" to "create table fbehind (id int)")).single()
        readyToMerge(n)
        adapter.relations[Triple(repo, merged.pullRequest!!.mergeSha!!, "sha$n")] = CommitRelation.BEHIND
        withProxy { evaluate(n) }
        assertEquals("APPROVED", status(req.id))
        assertTrue(lastCheck(n).title.startsWith("Update your branch"), lastCheck(n).title)

        forceRun(req.id)
        withProxy { evaluate(n) }
        assertEquals("EXECUTED", status(req.id))
    }

    @Test
    fun `a forced request still waits for auto-merge and the other checks`() {
        val n = number()
        open(n)
        update(n) { it.copy(checks = null) }
        val req = file(n, schema(), listOf("db/00071.sql" to "create table fwait (id int)")).single()
        update(n) { it.copy(reviews = listOf(approval(bobUser))) }
        recheck(n)
        assertEquals("APPROVED", status(req.id))
        forceRun(req.id)

        withProxy { evaluate(n) }
        assertEquals("APPROVED", status(req.id))
        assertEquals(CheckStatus.IN_PROGRESS, lastCheck(n).status)
        assertTrue(lastCheck(n).title.contains("auto-merge"), lastCheck(n).title)

        update(n) { it.copy(autoMerge = AutoMerge(carolUser, Instant.now())) }
        withProxy { evaluate(n) }
        assertEquals("APPROVED", status(req.id))
        assertEquals("Waiting for other checks", lastCheck(n).title)
    }

    @Test
    fun `a push that edits a forced file clears the force`() {
        val n = number()
        val schema = schema()
        open(n)
        val req = file(n, schema, listOf("db/00072.sql" to "create table fedit (id int)")).single()
        forceRun(req.id)
        assertEquals(true, core.accessStore.getRequest(req.id)?.forceRun)

        update(n) { it.copy(headSha = "sha$n-2") }
        val edited = file(n, schema, listOf("db/00072.sql" to "create table fedit (id bigint)")).single()
        assertEquals(req.id, edited.id)
        assertEquals(false to null, edited.forceRun to edited.forceRunBy)
    }

    @Test
    fun `a failed file does not hold the scope, and its fix runs once approved`() {
        val schema = schema()
        val f = number()
        open(f)
        file(f, schema, listOf("db/001_ok.sql" to "create table ok (id int)", "db/002_bad.sql" to "create table boom (id int)"))
        readyToMerge(f)
        pollWithProxy(fail = "boom")
        assertEquals(listOf("EXECUTED", "FAILED"), rows(f).map { it.status })
        assertEquals(CheckConclusion.FAILURE, lastCheck(f).conclusion)

        val g = number()
        open(g)
        file(g, schema, listOf("db/003_other.sql" to "create table other (id int)"))
        readyToMerge(g)
        pollWithProxy(fail = "boom")
        assertEquals("EXECUTED", rows(g).single().status)

        update(f) { it.copy(headSha = "sha$f-fix") }
        val fixed = file(f, schema, listOf("db/001_ok.sql" to "create table ok (id int)", "db/002_bad.sql" to "create table fixed (id int)"))
        assertEquals(listOf("EXECUTED", "PENDING"), fixed.map { it.status })
        readyToMerge(f)
        pollWithProxy(fail = "boom")
        assertEquals("Waiting for #$g to merge", lastCheck(f, "sha$f-fix").title)

        // Polls visit pull requests in number order, so #f sees #g's merge on the next poll.
        merge(g)
        pollWithProxy(fail = "boom")
        pollWithProxy(fail = "boom")
        assertEquals("EXECUTED", core.accessStore.getRequest(fixed[1].id)?.status)
        assertEquals(CheckConclusion.SUCCESS, lastCheck(f, "sha$f-fix").conclusion)

        // The fix ran, so the earlier failure no longer frees the scope: another pull request waits for #f.
        val h = number()
        open(h)
        file(h, schema, listOf("db/004_next.sql" to "create table next (id int)"))
        readyToMerge(h)
        pollWithProxy(fail = "boom")
        assertEquals("APPROVED", rows(h).single().status)
        assertEquals("Waiting for #$f to merge", lastCheck(h).title)

        merge(f)
        pollWithProxy(fail = "boom")
        assertEquals("EXECUTED", rows(h).single().status)
    }

    @Test
    fun `a file another pull request ran first is not run again`() {
        val schema = schema()
        val a = number()
        val b = number()
        open(a)
        open(b)
        val sql = listOf("db/010_same.sql" to "create table same (id int)")
        val first = file(a, schema, sql).single()
        val second = file(b, schema, sql).single()
        update(b) { it.copy(reviews = listOf(approval(bobUser))) }
        recheck(b)
        assertEquals("APPROVED", core.accessStore.getRequest(second.id)?.status)

        readyToMerge(a)
        pollWithProxy()
        assertEquals("EXECUTED", core.accessStore.getRequest(first.id)?.status)
        assertEquals("ALREADY_RAN", core.accessStore.getRequest(second.id)?.status)
        assertEquals(CheckConclusion.SUCCESS, lastCheck(b).conclusion)

        openedSchemas.clear()
        update(b) { it.copy(autoMerge = AutoMerge(carolUser, Instant.now())) }
        merge(a)
        pollWithProxy()
        assertEquals("ALREADY_RAN", core.accessStore.getRequest(second.id)?.status)
        assertEquals(emptyList(), openedSchemas)
    }

    @Test
    fun `a key that already ran turns green without running and merges the earlier run`() {
        val schema = schema()
        val n = number()
        open(n)
        val ran = file(n, schema, listOf("db/x.sql" to "create table x (id int)")).single()
        readyToMerge(n)
        pollWithProxy()
        update(n) { it.copy(open = false, merged = false) }
        pollWithProxy()
        assertNotNull(core.accessStore.scopeBlocker(schemaScope(schema), "acme/shop", number()))

        val m = number()
        open(m)
        val again = file(m, schema, listOf("db/moved/x.sql" to "create table x (id int)")).single()
        assertEquals("ALREADY_RAN", again.status)
        assertEquals(ran.changeKey, again.changeKey)
        assertEquals(CheckStatus.COMPLETED to CheckConclusion.SUCCESS, lastCheck(m).status to lastCheck(m).conclusion)
        assertTrue(m in core.accessStore.pullRequestsToPoll()["acme/shop"].orEmpty())

        merge(m)
        pollWithProxy()
        assertNotNull(core.accessStore.getRequest(ran.id)?.mergedAt)
        assertNull(core.accessStore.scopeBlocker(schemaScope(schema), "acme/shop", number()))
        assertTrue(m !in core.accessStore.pullRequestsToPoll()["acme/shop"].orEmpty())
        assertTrue(n !in core.accessStore.pullRequestsToPoll()["acme/shop"].orEmpty())
    }

    @Test
    fun `a head that moved without re-filing waits for the files`() {
        val schema = schema()
        val n = number()
        open(n)
        val req = file(n, schema, listOf("db/w.sql" to "create table w (id int)")).single()
        readyToMerge(n)
        update(n) { it.copy(headSha = "sha$n-2") }
        pollWithProxy()
        assertEquals("APPROVED", core.accessStore.getRequest(req.id)?.status)
        assertEquals("Waiting for this commit's SQL files to be filed", lastCheck(n, "sha$n-2").title)

        withProxy { flow.file(workload, input(n, schema, listOf("db/w.sql" to "create table w (id int)"))) }
        assertEquals("EXECUTED", core.accessStore.getRequest(req.id)?.status)
        assertEquals("sha$n-2", core.accessStore.getRequest(req.id)?.pullRequest?.headSha)
        assertEquals(CheckConclusion.SUCCESS, lastCheck(n, "sha$n-2").conclusion)
    }

    @Test
    fun `adding or removing a file dismisses the approvals`() {
        val schema = schema()
        val n = number()
        open(n)
        file(n, schema, listOf("db/a.sql" to "create table a (id int)"))
        update(n) { it.copy(reviews = listOf(approval(bobUser, id = "601"))) }
        recheck(n)

        update(n) { it.copy(headSha = "sha$n-2") }
        file(n, schema, listOf("db/a.sql" to "create table a (id int)", "db/b.sql" to "create table b (id int)"))
        val added = adapter.dismissals.single { it.pr == n }
        assertEquals("601", added.reviewId)
        assertTrue(added.message.contains("db/b.sql"), added.message)

        update(n) { it.copy(reviews = it.reviews + approval(bobUser, id = "602")) }
        recheck(n)
        update(n) { it.copy(headSha = "sha$n-3") }
        file(n, schema, listOf("db/a.sql" to "create table a (id int)"))
        val removed = adapter.dismissals.last { it.pr == n }
        assertEquals("602", removed.reviewId)
        assertTrue(removed.message.contains("db/b.sql"), removed.message)

        update(n) { it.copy(reviews = it.reviews + approval(bobUser, id = "603")) }
        recheck(n)
        update(n) { it.copy(headSha = "sha$n-4") }
        file(n, schema, listOf("db/a.sql" to "CREATE TABLE a (id int) -- same key"))
        assertEquals(2, adapter.dismissals.count { it.pr == n })
    }

    @Test
    fun `a moved file with the same SQL keeps its request and approval under the new path`() {
        val n = number()
        val schema = schema()
        open(n)
        val req = file(n, schema, listOf("db/a/0051_m.sql" to "create table m (id int)")).single()
        update(n) { it.copy(reviews = listOf(approval(bobUser))) }
        recheck(n)
        assertEquals("APPROVED", status(req.id))

        update(n) { it.copy(headSha = "sha$n-2") }
        val moved = file(n, schema, listOf("db/b/0051_m.sql" to "CREATE TABLE m (id int) -- moved")).single()
        assertEquals(req.id, moved.id)
        assertEquals("APPROVED" to 1, moved.status to moved.revision)
        assertEquals("db/b/0051_m.sql", moved.pullRequest?.path)
        assertEquals("create table m (id int)", moved.sql, "the approved text is what runs")
        assertEquals(1, rows(n).size)
    }

    @Test
    fun `removing every file dismisses the approvals`() {
        val n = number()
        val schema = schema()
        open(n)
        val req = file(n, schema, listOf("db/r.sql" to "create table r (id int)")).single()
        update(n) { it.copy(reviews = listOf(approval(bobUser, id = "701"))) }
        recheck(n)
        assertEquals("APPROVED", core.accessStore.getRequest(req.id)?.status)

        update(n) { it.copy(headSha = "sha$n-2") }
        file(n, schema, emptyList())
        val dismissal = adapter.dismissals.single { it.pr == n }
        assertEquals("701", dismissal.reviewId)
        assertTrue(dismissal.message.contains("db/r.sql"), dismissal.message)
        assertEquals("DELETED", core.accessStore.getRequest(req.id)?.status)
    }

    @Test
    fun `a pull request merged without a file that ran alerts`() {
        val schema = schema()
        val n = number()
        open(n)
        val ran = file(n, schema, listOf("db/gone.sql" to "create table gone (id int)")).single()
        readyToMerge(n)
        pollWithProxy()
        assertEquals("EXECUTED", core.accessStore.getRequest(ran.id)?.status)

        update(n) { it.copy(headSha = "sha$n-2") }
        file(n, schema, emptyList())
        merge(n)
        pollWithProxy()
        val alerts = outboxRecipients(ran.id, "task.merged_without_file")
        assertTrue(alerts.containsAll(listOf(alice, bob, carol)), "$alerts")
        assertNotNull(core.accessStore.getRequest(ran.id)?.mergedAt)
    }

    private fun schemaScope(schema: String) = "${datasource.name}/$schema"

    @Test
    fun `a pull request closed after its run alerts and keeps the scope blocked`() {
        val schema = schema()
        val n = number()
        open(n)
        file(n, schema, listOf("db/x.sql" to "create table x (id int)"))
        readyToMerge(n)
        pollWithProxy()
        val ran = rows(n).single()
        assertEquals("EXECUTED", ran.status)

        update(n) { it.copy(open = false, merged = false) }
        pollWithProxy()
        pollWithProxy()
        val alerts = outboxRecipients(ran.id, "task.closed_after_run")
        assertTrue(alerts.containsAll(listOf(alice, bob, carol)), "$alerts")
        assertEquals(alerts.size, alerts.toSet().size, "repeated polls enqueue the alert once per recipient")
        assertNotNull(core.accessStore.scopeBlocker(ran.scope!!, "acme/shop", number()))
    }

    @Test
    fun `an approved file merged before it ran runs after the merge, as whoever merged`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/m.sql" to "create table m (id int)")).single()
        update(n) { it.copy(reviews = it.reviews + approval(bobUser)) }
        pollWithProxy()
        assertEquals("APPROVED", status(req.id))
        assertEquals("Approved — enable auto-merge to run and merge", lastCheck(n).title)

        merge(n)
        update(n) { it.copy(mergedBy = carolUser) }
        pollWithProxy()
        val ran = assertNotNull(core.accessStore.getRequest(req.id))
        assertEquals("EXECUTED", ran.status)
        assertEquals(carol, ran.executedBy)
        assertNotNull(ran.mergedAt)
        assertEquals(checkName to CheckConclusion.SUCCESS, lastCheck(n).name to lastCheck(n).conclusion)
    }

    @Test
    fun `a file merged before approval runs once approved, holding its scope until then`() {
        val schema = schema()
        val n = number()
        open(n)
        val req = file(n, schema, listOf("db/1_first.sql" to "create table first (id int)")).single()
        merge(n)
        update(n) { it.copy(mergedBy = carolUser) }
        pollWithProxy()
        assertEquals("PENDING", status(req.id))
        assertEquals(CheckStatus.IN_PROGRESS, lastCheck(n).status)

        val later = number()
        open(later)
        val next = file(later, schema, listOf("db/2_second.sql" to "create table second (id int)")).single()
        readyToMerge(later)
        pollWithProxy()
        assertEquals("APPROVED", status(next.id))
        assertEquals("Waiting for #$n's merged SQL to run", lastCheck(later).title)

        update(n) { it.copy(reviews = it.reviews + approval(bobUser)) }
        pollWithProxy()
        assertEquals("EXECUTED", status(req.id))
        pollWithProxy()
        assertEquals("EXECUTED", status(next.id))
    }

    @Test
    fun `merged files wait for those merged before them, not after`() {
        val schema = schema()
        val first = number()
        open(first)
        val a = file(first, schema, listOf("db/1_a.sql" to "create table a (id int)")).single()
        merge(first)
        update(first) { it.copy(mergedBy = carolUser) }
        pollWithProxy()

        val second = number()
        open(second)
        val b = file(second, schema, listOf("db/2_b.sql" to "create table b (id int)")).single()
        update(second) { it.copy(reviews = it.reviews + approval(bobUser)) }
        merge(second)
        update(second) { it.copy(mergedBy = carolUser) }
        pollWithProxy()
        assertEquals("APPROVED", status(b.id))
        assertEquals("Waiting for #$first's merged SQL to run", lastCheck(second).title)

        update(first) { it.copy(reviews = it.reviews + approval(bobUser)) }
        pollWithProxy()
        assertEquals("EXECUTED", status(a.id))
        pollWithProxy()
        assertEquals("EXECUTED", status(b.id))
    }

    @Test
    fun `pull requests merged between polls run in merge order`() {
        val schema = schema()
        val (first, second) = number() to number()
        val files = listOf(first to "db/1_a.sql", second to "db/2_b.sql").associate { (n, path) ->
            open(n)
            n to file(n, schema, listOf(path to "create table t$n (id int)")).single()
        }
        val at = Instant.now()
        for ((n, mergedAt) in listOf(second to at, first to at.plusSeconds(10))) {
            update(n) { it.copy(reviews = it.reviews + approval(bobUser)) }
            update(n) { it.copy(open = false, merged = true, mergedAt = mergedAt, mergeCommit = "merge$n", mergedBy = carolUser) }
        }
        pollWithProxy()
        val (a, b) = listOf(first, second).map { assertNotNull(core.accessStore.getRequest(files.getValue(it).id)?.executedAt) }
        assertTrue(Instant.parse(b) < Instant.parse(a), "#$second merged first and ran at $b, #$first at $a")
    }

    @Test
    fun `a merged pull request whose file failed does not hold the scope`() {
        val schema = schema()
        val n = number()
        open(n)
        val filed = file(n, schema, listOf("db/1_bad.sql" to "create table bad (id int) broken", "db/2_after.sql" to "create table after1 (id int)"))
        update(n) { it.copy(reviews = it.reviews + approval(bobUser)) }
        merge(n)
        update(n) { it.copy(mergedBy = carolUser) }
        pollWithProxy(fail = "broken")
        assertEquals(listOf("FAILED", "APPROVED"), filed.map { status(it.id) })

        val later = number()
        open(later)
        val fix = file(later, schema, listOf("db/3_fix.sql" to "create table fix (id int)")).single()
        readyToMerge(later)
        pollWithProxy()
        assertEquals("EXECUTED", status(fix.id))
    }

    @Test
    fun `a merged pull request with a rejected file does not hold the scope`() {
        val schema = schema()
        val n = number()
        open(n)
        val filed = file(n, schema, listOf("db/1_no.sql" to "create table no1 (id int)", "db/2_rest.sql" to "create table rest (id int)"))
        merge(n)
        update(n) { it.copy(mergedBy = carolUser) }
        approvals.reject(bob, null, AuditActor(bob, channel = Channel.WORKFLOW_VIEWER.contextValue), filed.first().id, "not this one")
        pollWithProxy()

        val later = number()
        open(later)
        val next = file(later, schema, listOf("db/3_next.sql" to "create table next1 (id int)")).single()
        readyToMerge(later)
        pollWithProxy()
        assertEquals("EXECUTED", status(next.id))
    }

    @Test
    fun `pull requests merged in the same second run in number order`() {
        val schema = schema()
        val (first, second) = number() to number()
        val a = run { open(first); file(first, schema, listOf("db/1_a.sql" to "create table s$first (id int)")).single() }
        val b = run { open(second); file(second, schema, listOf("db/2_b.sql" to "create table s$second (id int)")).single() }
        val at = Instant.now()
        update(second) { it.copy(reviews = it.reviews + approval(bobUser)) }
        for (n in listOf(first, second)) {
            update(n) { it.copy(open = false, merged = true, mergedAt = at, mergeCommit = "merge$n", mergedBy = carolUser) }
        }
        pollWithProxy()
        assertEquals("APPROVED", status(b.id))

        update(first) { it.copy(reviews = it.reviews + approval(bobUser)) }
        pollWithProxy()
        assertEquals("EXECUTED", status(a.id))
        pollWithProxy()
        assertEquals("EXECUTED", status(b.id))
    }

    @Test
    fun `a merge of a later commit after every file ran stays green`() {
        val n = number()
        open(n)
        file(n, schema(), listOf("db/c.sql" to "create table c (id int)"))
        readyToMerge(n)
        pollWithProxy()
        update(n) { it.copy(headSha = "sha$n-2") }
        merge(n)
        pollWithProxy()
        assertEquals(CheckConclusion.SUCCESS, lastCheck(n, "sha$n-2").conclusion)
    }

    @Test
    fun `a file changed after it was filed and then merged does not run`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/c.sql" to "create table c (id int)")).single()
        update(n) { it.copy(reviews = it.reviews + approval(bobUser)) }
        pollWithProxy()
        update(n) { it.copy(headSha = "sha$n-2") }
        merge(n)
        update(n) { it.copy(mergedBy = carolUser) }
        pollWithProxy()
        assertEquals("CANCELLED", status(req.id))
        val check = lastCheck(n, "sha$n-2")
        assertEquals(CheckConclusion.FAILURE to "Merged before this commit's SQL files were filed", check.conclusion to check.title)
    }

    @Test
    fun `another instance's check does not hold the run`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/c.sql" to "create table c (id int)")).single()
        readyToMerge(n)
        val running = Check("x", required = true, status = CheckStatus.IN_PROGRESS, conclusion = null)
        update(n) { it.copy(checks = listOf(green, running.copy(name = "prod/query executed"))) }
        pollWithProxy()
        assertEquals("EXECUTED", status(req.id))
    }

    @Test
    fun `a pull request closed before its run cancels its requests`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/c.sql" to "create table c (id int)")).single()
        update(n) { it.copy(open = false, merged = false) }
        pollWithProxy()
        assertEquals("CANCELLED", core.accessStore.getRequest(req.id)?.status)
    }

    @Test
    fun `a pull request with no SQL is skipped at once`() {
        val n = number()
        open(n)
        assertEquals(emptyList(), file(n, schema(), emptyList()))
        assertEquals(CheckStatus.COMPLETED to CheckConclusion.SKIPPED, lastCheck(n).status to lastCheck(n).conclusion)
    }

    @Test
    fun `a commit the Action marked skipped gets no check of its own`() {
        val n = number()
        open(n)
        val skipped = Check(checkName, required = true, status = CheckStatus.COMPLETED, conclusion = CheckConclusion.SKIPPED)
        update(n) { it.copy(checks = listOf(green, skipped)) }
        assertEquals(emptyList(), file(n, schema(), emptyList()))
        assertEquals(null, adapter.checks.lastOrNull { it.headSha == "sha$n" })
    }

    @Test
    fun `SQL on a commit another step marked skipped still gets the check`() {
        val n = number()
        open(n)
        val skipped = Check(checkName, required = true, status = CheckStatus.COMPLETED, conclusion = CheckConclusion.SKIPPED)
        update(n) { it.copy(checks = listOf(green, skipped)) }
        file(n, schema(), listOf("db/c.sql" to "create table c (id int)"))
        assertEquals(CheckStatus.IN_PROGRESS to "Waiting for approval of db/c.sql", lastCheck(n).status to lastCheck(n).title)
    }

    @Test
    fun `an unmapped author gets a comment and no request`() {
        val n = number()
        open(n, author = malloryUser)
        assertEquals(emptyList(), file(n, schema(), listOf("db/m.sql" to "create table m (id int)")))
        assertEquals(emptyList(), rows(n))
        assertEquals("requester", adapter.upserts.last { it.pr == n }.marker)
        assertEquals(CheckStatus.IN_PROGRESS, lastCheck(n).status)
    }

    @Test
    fun `the author's own review does not approve`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/self.sql" to "create table self (id int)")).single()
        update(n) { it.copy(reviews = listOf(approval(aliceUser))) }
        recheck(n)
        assertEquals("PENDING", core.accessStore.getRequest(req.id)?.status)
    }

    @Test
    fun `the console execute route refuses a pull-request request`() = testApplication {
        val client = serve()
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/h.sql" to "create table h (id int)")).single()
        update(n) { it.copy(reviews = listOf(approval(bobUser))) }
        recheck(n)
        assertEquals("APPROVED", core.accessStore.getRequest(req.id)?.status)

        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$bob").status)
        val response = client.post("/api/approvals/${req.id}/execute")
        assertEquals(HttpStatusCode.Conflict, response.status)
        assertEquals("approval.github_runs_on_merge", response.body<ApiError>().code)

        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/${req.principal}").status)
        val edit = client.post("/api/approvals/${req.id}/edit") {
            contentType(ContentType.Application.Json)
            setBody(EditQueryRequestInput("create table h (id bigint)"))
        }
        assertEquals(HttpStatusCode.Conflict, edit.status)
        assertEquals("approval.github_edit_by_push", edit.body<ApiError>().code)
        Unit
    }

    @Test
    fun `files run in key order across directories under one auto-merge`() {
        val n = number()
        val schema = schema()
        open(n)
        val filed = file(n, schema, listOf("db/a/002_two.sql" to "create table two (id int)", "db/b/001_one.sql" to "create table one (id int)"))
        assertEquals(listOf("db/b/001_one.sql", "db/a/002_two.sql"), filed.map { it.pullRequest?.path })

        readyToMerge(n)
        pollWithProxy()
        val ran = rows(n).associateBy { it.pullRequest?.path }
        val one = ran.getValue("db/b/001_one.sql")
        val two = ran.getValue("db/a/002_two.sql")
        assertEquals(listOf("EXECUTED", "EXECUTED"), listOf(one.status, two.status))
        assertTrue(Instant.parse(one.executedAt) <= Instant.parse(two.executingAt))
        assertEquals(CheckConclusion.SUCCESS, lastCheck(n).conclusion)
    }

    @Test
    fun `a console request carries no pull request`() {
        val id = core.accessStore.createQueryRequest(
            principal = "alice@example.com", datasourceId = datasource.id, statements = listOf("select 1"),
            denyReason = null, sourceDecisionId = null, reason = null, title = null, evaluatedDecision = "DENY",
        ).id
        val request = assertNotNull(core.accessStore.getRequest(id))
        assertNull(request.pullRequest)
        assertFalse("pullRequest" in wireJson.encodeToJsonElement(AccessRequest.serializer(), request).jsonObject)
    }

    @Test
    fun `numeric key order runs 9 before 10`() {
        val n = number()
        val schema = schema()
        open(n)
        val filed = file(
            n, schema, listOf("db/10_b.sql" to "create table b (id int)", "db/9_a.sql" to "create table a (id int)"),
            order = KeyOrder.NUMERIC,
        )
        assertEquals(listOf("9", "10"), filed.map { it.fileKey })
        assertEquals(listOf("numeric", "numeric"), filed.map { it.pullRequest?.keyOrder })

        readyToMerge(n)
        pollWithProxy()
        val ran = rows(n).associateBy { it.fileKey }
        val nine = ran.getValue("9")
        val ten = ran.getValue("10")
        assertEquals(listOf("EXECUTED", "EXECUTED"), listOf(nine.status, ten.status))
        assertTrue(Instant.parse(nine.executedAt) <= Instant.parse(ten.executingAt))
    }

    @Test
    fun `a key that is not a number under numeric order is refused before anything is written`() {
        val n = number()
        open(n)
        val e = refused(
            input = input(
                n, schema(), listOf("db/0001_a.sql" to "create table a (id int)", "db/init.sql" to "create table i (id int)"),
                order = KeyOrder.NUMERIC,
            ),
        )
        assertEquals(HttpStatusCode.BadRequest to "approval.github_key_not_numeric", e.status to e.error.code)
        assertEquals(mapOf("path" to "db/init.sql"), e.error.params)
        assertEquals(emptyList(), rows(n))
    }

    @Test
    fun `a filing for a head that is no longer the pull request's is refused`() {
        val n = number()
        open(n)
        val e = refused(input = input(n, schema(), listOf("db/s.sql" to "create table s (id int)"), headSha = "0ld"))
        assertEquals(HttpStatusCode.Conflict to "approval.github_stale_head", e.status to e.error.code)
        assertEquals(mapOf("head" to "sha$n"), e.error.params)
        assertEquals(emptyList(), rows(n))
        assertEquals("headSha", refused(input = input(n, schema(), emptyList(), headSha = " ")).error.params["fields"])
    }

    @Test
    fun `a workload from another repository, or naming none, cannot file`() {
        val n = number()
        open(n)
        val body = input(n, schema(), listOf("db/o.sql" to "create table o (id int)"))
        for (claims in listOf(mapOf("repository" to "acme/other"), emptyMap())) {
            val e = refused(workload.copy(claims = claims), body)
            assertEquals(HttpStatusCode.Forbidden to "approval.github_repository_mismatch", e.status to e.error.code)
        }
        assertEquals(emptyList(), rows(n))
        assertEquals(1, runBlocking { flow.file(workload.copy(claims = mapOf("repository" to "ACME/Shop")), body) }.size)
    }

    @Test
    fun `a missing rollup waits for checks`() {
        val n = number()
        open(n)
        update(n) { it.copy(checks = null) }
        val req = file(n, schema(), listOf("db/c.sql" to "create table c (id int)")).single()
        readyToMerge(n)
        pollWithProxy()
        assertEquals("APPROVED", status(req.id))
        assertEquals("Waiting for other checks", lastCheck(n).title)
    }

    @Test
    fun `a pull request without a rollup does not run, through the real decoder`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/r.sql" to "create table r (id int)")).single()
        update(n) { it.copy(reviews = listOf(approval(bobUser, id = "${seq.incrementAndGet()}")), autoMerge = AutoMerge(carolUser, Instant.now())) }
        val wire = cpGoPullRequest(adapter.pulls.getValue(repo to n).copy(checks = null))
        val runs = openedSchemas.size
        FakeCpGo().use { cpGo ->
            cpGo.readPullRequests = { readPullRequestsResponse { pullRequests.put(n, wire) } }
            withProxy { flow.evaluate(repo, n, cpGo.adapter().readPullRequests(repo, listOf(n))[n]) }
        }
        assertEquals("APPROVED", status(req.id))
        assertEquals(runs, openedSchemas.size)
        assertEquals("Waiting for other checks", lastCheck(n).title)
    }

    @Test
    fun `a required context absent from the rollup, or failed, waits for checks`() {
        val n = number()
        open(n, baseRef = "base$n")
        adapter.branchRules["base$n"] = BranchRules(setOf("lint", checkName))
        val req = file(n, schema(), listOf("db/c.sql" to "create table c (id int)")).single()
        readyToMerge(n)
        pollWithProxy()
        assertEquals("APPROVED", status(req.id))
        assertEquals("Waiting for other checks", lastCheck(n).title)

        val lint = Check("lint", required = false, status = CheckStatus.COMPLETED, conclusion = CheckConclusion.SUCCESS)
        update(n) { it.copy(checks = listOf(green, lint, lint.copy(conclusion = CheckConclusion.FAILURE))) }
        pollWithProxy()
        assertEquals("APPROVED", status(req.id))

        update(n) { it.copy(checks = listOf(green, lint)) }
        pollWithProxy()
        assertEquals("EXECUTED", status(req.id))
        assertEquals(CheckConclusion.SUCCESS, lastCheck(n).conclusion)
    }

    @Test
    fun `a check still running waits even when nothing is required, and a failed optional one does not`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/c.sql" to "create table c (id int)")).single()
        readyToMerge(n)
        val test = Check("test", required = false, status = CheckStatus.IN_PROGRESS, conclusion = null)
        update(n) { it.copy(checks = listOf(test)) }
        pollWithProxy()
        assertEquals("APPROVED", status(req.id))
        assertEquals("Waiting for other checks", lastCheck(n).title)

        update(n) { it.copy(checks = listOf(test.copy(status = CheckStatus.COMPLETED, conclusion = CheckConclusion.FAILURE))) }
        pollWithProxy()
        assertEquals("EXECUTED", status(req.id))
    }

    @Test
    fun `an approved draft waits until it is marked ready`() {
        val n = number()
        open(n)
        update(n) { it.copy(draft = true) }
        val req = file(n, schema(), listOf("db/c.sql" to "create table c (id int)")).single()
        readyToMerge(n)
        pollWithProxy()
        assertEquals("APPROVED", status(req.id))
        assertEquals("Waiting for the pull request to be marked ready for review", lastCheck(n).title)

        update(n) { it.copy(draft = false) }
        pollWithProxy()
        assertEquals("EXECUTED", status(req.id))
    }

    @Test
    fun `an approved PR waits until GitHub would merge it`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/c.sql" to "create table c (id int)")).single()
        readyToMerge(n)
        fun waitsOn(title: String, change: (PullRequest) -> PullRequest) {
            update(n, change)
            pollWithProxy()
            assertEquals("APPROVED", status(req.id))
            assertEquals(title, lastCheck(n).title)
        }
        waitsOn("Resolve the conflicts with the base branch") { it.copy(mergeable = "CONFLICTING") }
        waitsOn("Waiting for GitHub to allow the merge") { it.copy(mergeable = "UNKNOWN") }
        waitsOn("Update your branch") { it.copy(mergeable = "MERGEABLE", mergeState = "BEHIND") }
        // An approval from someone other than a required code owner.
        waitsOn("Waiting for the reviews the base branch requires") { it.copy(mergeState = "BLOCKED", reviewDecision = "REVIEW_REQUIRED") }
        waitsOn("Waiting for GitHub to allow the merge") { it.copy(reviewDecision = "APPROVED") }

        update(n) { it.copy(mergeState = "UNSTABLE") }
        pollWithProxy()
        assertEquals("EXECUTED", status(req.id))
    }

    @Test
    fun `with its own check required, a blocked PR runs once every rule it can read allows the merge`() {
        val n = number()
        open(n, baseRef = "base$n")
        val rules = BranchRules(
            setOf(checkName), strict = true, threadResolution = true, mergeMethods = setOf("squash", "rebase"), unchecked = listOf("merge_queue"),
        )
        adapter.branchRules["base$n"] = rules
        val req = file(n, schema(), listOf("db/c.sql" to "create table c (id int)")).single()
        readyToMerge(n)
        fun waitsOn(title: String, change: (PullRequest) -> PullRequest = { it }) {
            update(n, change)
            pollWithProxy()
            assertEquals("APPROVED", status(req.id))
            assertEquals(title, lastCheck(n).title)
        }
        waitsOn("Resolve the review conversations") { it.copy(mergeState = "BLOCKED", unresolvedThreads = 1) }
        waitsOn("The base branch does not allow merging by merge; change the auto-merge method") {
            it.copy(unresolvedThreads = 0, autoMerge = it.autoMerge!!.copy(mergeMethod = "MERGE"))
        }
        waitsOn("GitHub cannot rebase this pull request; change the auto-merge method or rebase it yourself") {
            it.copy(autoMerge = it.autoMerge!!.copy(mergeMethod = "REBASE"), canBeRebased = false)
        }
        adapter.relations[Triple(repo, "base$n", "sha$n")] = CommitRelation.BEHIND
        waitsOn("Update your branch") { it.copy(autoMerge = it.autoMerge!!.copy(mergeMethod = "SQUASH")) }
        adapter.relations.remove(Triple(repo, "base$n", "sha$n"))
        waitsOn("The base branch's merge_queue rule cannot be checked before the merge")
        adapter.branchRules["base$n"] = rules.copy(unchecked = emptyList())
        waitsOn("Waiting for GitHub to allow the merge") { it.copy(mergeState = "UNKNOWN") }
        waitsOn("Waiting for GitHub to allow the merge") { it.copy(mergeState = "DIRTY") }
        update(n) { it.copy(mergeState = "BLOCKED") }

        pollWithProxy()
        assertEquals("EXECUTED", status(req.id))
    }

    @Test
    fun `a failed required-checks lookup waits for checks`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/c.sql" to "create table c (id int)")).single()
        readyToMerge(n)
        adapter.branchRulesFail = true
        try {
            pollWithProxy()
        } finally {
            adapter.branchRulesFail = false
        }
        assertEquals("APPROVED", status(req.id))
        assertEquals("Waiting for other checks", lastCheck(n).title)
    }

    @Test
    fun `a review submitted before the request does not approve it`() {
        val n = number()
        val schema = schema()
        open(n)
        update(n) { it.copy(reviews = listOf(approval(bobUser, submittedAt = Instant.now().minusSeconds(3600)))) }
        val first = file(n, schema, listOf("db/e.sql" to "create table e (id int)")).single()
        recheck(n)
        assertEquals("PENDING", status(first.id))

        update(n) { it.copy(reviews = listOf(approval(bobUser, submittedAt = Instant.parse(first.createdAt).plusMillis(1)))) }
        recheck(n)
        assertEquals("APPROVED", status(first.id))

        // The approving review is still APPROVED on GitHub when its dismissal fails; it predates the edit.
        Thread.sleep(50)
        update(n) { it.copy(headSha = "sha$n-2") }
        adapter.dismissFail = true
        val second = try {
            file(n, schema, listOf("db/e.sql" to "create table e (id bigint)")).single()
        } finally {
            adapter.dismissFail = false
        }
        assertEquals(first.id to 2, second.id to second.revision)
        recheck(n)
        assertEquals("PENDING", status(second.id))

        // A review started on the old commit and submitted after the push read the old SQL.
        update(n) { it.copy(reviews = listOf(approval(bobUser, commit = "sha$n"))) }
        recheck(n)
        assertEquals("PENDING", status(second.id))

        update(n) { it.copy(reviews = listOf(approval(bobUser))) }
        recheck(n)
        assertEquals("APPROVED", status(second.id))
    }

    @Test
    fun `a console approval survives the approver's dismissed or changes-requested review`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/k.sql" to "create table k (id int)")).single()
        approvals.approve(bob, "10.0.0.1", AuditActor(bob, clientAddr = null, channel = "console"), req.id, req.revision)
        assertNull(core.accessStore.getRequest(req.id)?.pullRequest?.approvedReviewId)
        update(n) {
            it.copy(
                reviews = listOf(
                    approval(bobUser, state = ReviewState.DISMISSED),
                    approval(bobUser, state = ReviewState.CHANGES_REQUESTED, submittedAt = Instant.now().plusSeconds(10)),
                ),
            )
        }
        recheck(n)
        assertEquals("APPROVED", status(req.id))
    }

    @Test
    fun `an approval is withdrawn when its review is dismissed`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/d.sql" to "create table d (id int)")).single()
        update(n) { it.copy(reviews = listOf(approval(bobUser, id = "801"))) }
        recheck(n)
        assertEquals("801", core.accessStore.getRequest(req.id)?.pullRequest?.approvedReviewId)

        // Another reviewer's dismissal or change request leaves it alone.
        update(n) {
            it.copy(
                reviews = it.reviews + approval(carolUser, state = ReviewState.DISMISSED) +
                    approval(carolUser, state = ReviewState.CHANGES_REQUESTED, submittedAt = Instant.now().plusSeconds(10)),
            )
        }
        recheck(n)
        assertEquals("APPROVED", status(req.id))

        update(n) { pr -> pr.copy(reviews = pr.reviews.map { if (it.id == "801") it.copy(state = ReviewState.DISMISSED) else it }) }
        recheck(n)
        assertEquals("PENDING", status(req.id))
        assertNull(core.accessStore.getRequest(req.id)?.pullRequest?.approvedReviewId)
    }

    @Test
    fun `an approval is withdrawn when its reviewer later requests changes`() {
        val n = number()
        open(n)
        val req = file(n, schema(), listOf("db/q.sql" to "create table q (id int)")).single()
        val approved = approval(bobUser)
        update(n) { it.copy(reviews = listOf(approved)) }
        recheck(n)
        assertEquals("APPROVED", status(req.id))

        update(n) {
            it.copy(reviews = it.reviews + approval(bobUser, state = ReviewState.CHANGES_REQUESTED, submittedAt = approved.submittedAt!!.plusSeconds(1)))
        }
        recheck(n)
        assertEquals("PENDING", status(req.id))
    }

    @Test
    fun `a failed file a later filing removed no longer fails the check`() {
        val schema = schema()
        val n = number()
        open(n)
        file(n, schema, listOf("db/001_ok.sql" to "create table ok2 (id int)", "db/002_bad.sql" to "create table boom (id int)"))
        readyToMerge(n)
        pollWithProxy(fail = "boom")
        assertEquals(CheckConclusion.FAILURE, lastCheck(n).conclusion)

        update(n) { it.copy(headSha = "sha$n-2") }
        file(n, schema, listOf("db/001_ok.sql" to "create table ok2 (id int)"))
        assertEquals(CheckStatus.COMPLETED to CheckConclusion.SUCCESS, lastCheck(n, "sha$n-2").status to lastCheck(n, "sha$n-2").conclusion)
        assertEquals("Executed", lastCheck(n, "sha$n-2").title)

        // The failure left the latest filing, so #n holds the scope again until it merges.
        val k = number()
        open(k)
        file(k, schema, listOf("db/004_next.sql" to "create table next2 (id int)"))
        readyToMerge(k)
        pollWithProxy(fail = "boom")
        assertEquals("Waiting for #$n to merge", lastCheck(k).title)
        merge(n)
        pollWithProxy(fail = "boom")
        assertEquals("EXECUTED", rows(k).single().status)

        val m = number()
        val other = schema()
        open(m)
        file(m, other, listOf("db/003_bad.sql" to "create table boom (id int)"))
        readyToMerge(m)
        pollWithProxy(fail = "boom")
        assertEquals(CheckConclusion.FAILURE, lastCheck(m).conclusion)
        update(m) { it.copy(headSha = "sha$m-2") }
        file(m, other, emptyList())
        assertEquals("No SQL to run" to CheckConclusion.SKIPPED, lastCheck(m, "sha$m-2").title to lastCheck(m, "sha$m-2").conclusion)
    }

    @Test
    fun `two scopes with the same path each run`() {
        val n = number()
        open(n)
        val path = "db/same.sql"
        file(n, schema(), listOf(path to "create table one (id int)"), scope = "scope-a-$n")
        file(n, schema(), listOf(path to "create table two (id int)"), scope = "scope-b-$n")
        readyToMerge(n)
        pollWithProxy()
        assertEquals(listOf("EXECUTED", "EXECUTED"), rows(n).map { it.status })
        assertEquals(CheckConclusion.SUCCESS, lastCheck(n).conclusion)
    }

    @Test
    fun `files that all ran wait for the new head's filing`() {
        val schema = schema()
        val n = number()
        open(n)
        val ran = file(n, schema, listOf("db/h.sql" to "create table h (id int)")).single()
        readyToMerge(n)
        pollWithProxy()
        assertEquals("EXECUTED", status(ran.id))

        update(n) { it.copy(headSha = "sha$n-2") }
        pollWithProxy()
        assertEquals("Waiting for this commit's SQL files to be filed", lastCheck(n, "sha$n-2").title)

        file(n, schema, listOf("db/h.sql" to "create table h (id int)"))
        assertEquals(CheckConclusion.SUCCESS, lastCheck(n, "sha$n-2").conclusion)
    }

    @Test
    fun `an auto-merge enabler mapped only by its own commit email runs the files`() {
        val n = number()
        val dave = SourceUser("20", "dave")
        open(n)
        adapter.commitEmailUsers["dave-$n@example.com"] = carol
        update(n) { it.copy(commits = listOf(CommitAuthor(dave.id, "dave-$n@example.com", merge = false))) }
        val req = file(n, schema(), listOf("db/v.sql" to "create table v (id int)")).single()
        update(n) { it.copy(reviews = listOf(approval(bobUser)), autoMerge = AutoMerge(dave, Instant.now())) }
        pollWithProxy()
        assertEquals("EXECUTED", status(req.id))
        assertEquals(carol, core.accessStore.getRequest(req.id)?.executedBy)
    }

    @Test
    fun `an auto-merge enabler is not mapped by the author's commits`() {
        val n = number()
        val dave = SourceUser("21", "dave2")
        open(n)
        adapter.commitEmailUsers["borrowed-$n@example.com"] = carol
        update(n) { it.copy(commits = listOf(CommitAuthor(aliceUser.id, "borrowed-$n@example.com", merge = false))) }
        val req = file(n, schema(), listOf("db/u.sql" to "create table u (id int)")).single()
        update(n) { it.copy(reviews = listOf(approval(bobUser)), autoMerge = AutoMerge(dave, Instant.now())) }
        pollWithProxy()
        assertEquals("APPROVED", status(req.id))
        assertEquals("Whoever enabled auto-merge is not mapped to a proxy-monster user", lastCheck(n).title)
    }

    @Test
    fun `the requester stays the principal first mapped for the pull request`() {
        val n = number()
        val erin = SourceUser("30", "erin")
        adapter.users[erin.id] = alice
        try {
            open(n, author = erin)
            assertEquals(alice, file(n, schema(), listOf("db/p.sql" to "create table p (id int)")).single().principal)
            adapter.users[erin.id] = bob
            update(n) { it.copy(headSha = "sha$n-2") }
            assertEquals(alice, file(n, schema(), listOf("db/p2.sql" to "create table p2 (id int)")).single().principal)
        } finally {
            adapter.users.remove(erin.id)
        }
    }

    @Test
    fun `another user's commit or a merge commit does not map the requester`() {
        val n = number()
        val frank = SourceUser("31", "frank")
        open(n, author = frank)
        adapter.commitEmailUsers += mapOf("other-$n@example.com" to alice, "merge-$n@example.com" to alice, "own-$n@example.com" to alice)
        update(n) {
            it.copy(commits = listOf(CommitAuthor("32", "other-$n@example.com", merge = false), CommitAuthor(frank.id, "merge-$n@example.com", merge = true)))
        }
        assertEquals(emptyList(), file(n, schema(), listOf("db/f.sql" to "create table f (id int)")))
        assertEquals("requester", adapter.upserts.last { it.pr == n }.marker)

        update(n) { it.copy(commits = it.commits + CommitAuthor(frank.id, "own-$n@example.com", merge = false)) }
        assertEquals(alice, file(n, schema(), listOf("db/f.sql" to "create table f (id int)")).single().principal)
    }
}
