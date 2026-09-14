package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.google.protobuf.Timestamp
import com.ridi.oss.proxymonster.athena.pb.AthenaCachedContext
import com.ridi.oss.proxymonster.athena.pb.AthenaNativeDescriptor
import com.ridi.oss.proxymonster.athena.pb.AthenaNativeInstruction
import com.ridi.oss.proxymonster.athena.pb.AthenaNativeInstructions
import com.ridi.oss.proxymonster.athena.pb.AthenaObservationSource
import com.ridi.oss.proxymonster.athena.pb.NativeAuthorizationPhase
import com.ridi.oss.proxymonster.athena.pb.athenaCachedContext
import com.ridi.oss.proxymonster.athena.pb.athenaNativeDescriptor
import com.ridi.oss.proxymonster.athena.pb.athenaResourceObservation
import com.ridi.oss.proxymonster.athena.pb.athenaTarget
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.grpc.ColumnMask
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.NativeRequestAuthorization
import com.ridi.oss.proxymonster.grpc.RequestAuthorization
import com.ridi.oss.proxymonster.grpc.Verdict
import java.lang.reflect.Proxy
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AthenaRequestAuthorizerTest {
    private val datasource = Datasource(1, "lake", Engine.ATHENA, "", 0, "analytics", tags = listOf("production"))
    private val now: Instant = Instant.parse("2026-09-14T00:00:00Z")
    private val authorizer = AthenaNativeAuthorizer(Clock.fixed(now, ZoneOffset.UTC))
    private val binding: ByteString = ByteString.copyFrom(ByteArray(32) { 7 })
    private val connect = """permit(principal, action == Action::"datasource.connect", resource);"""
    private val invokeAll = """permit(principal, action == Action::"native.invoke", resource);"""
    private val REQUEST = NativeAuthorizationPhase.NATIVE_AUTHORIZATION_PHASE_REQUEST
    private val RESPONSE = NativeAuthorizationPhase.NATIVE_AUTHORIZATION_PHASE_RESPONSE

    @Test
    fun `unknown operation, wrong service, malformed descriptor and version are denied`() {
        val gate = authz(connect, invokeAll)
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("NotAnOperation"), gate))
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("ListWorkGroups") { service = "glue" }, gate))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("ListWorkGroups"), gate, version = 2))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("ListWorkGroups") { method = "GET" }, gate))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("ListWorkGroups") { rawQuery = "x=1" }, gate))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("ListWorkGroups") { clearTarget() }, gate))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("ListWorkGroups") { phase = NativeAuthorizationPhase.NATIVE_AUTHORIZATION_PHASE_UNSPECIFIED }, gate))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("ListWorkGroups", body = "{"), gate))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("ListWorkGroups", body = "[]"), gate))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("ListWorkGroups", body = "{} {}"), gate))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("GetWorkGroup", body = """{"WorkGroup":"a","WorkGroup":"b"}"""), gate))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("GetWorkGroup", body = """{"WorkGroup":1}"""), gate))
        val garbage = RequestAuthorization.newBuilder().setDatasourceName(datasource.name)
            .setNative(NativeRequestAuthorization.newBuilder().setDescriptorVersion(1).setDescriptorPayload(ByteString.copyFromUtf8("ÿÿ")))
            .build()
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), authorizer.authorize(garbage, datasource, "alice", setOf("reader"), AuthzContext(), gate))
        val other = RequestAuthorization.newBuilder().setDatasourceName("other").setNative(request(descriptor("ListWorkGroups"), 1).native).build()
        assertEquals(RequestAdmission.Denied("native.not_authorized"), authorizer.authorize(other, datasource, "alice", setOf("reader"), AuthzContext(), gate))
        val metadata = catalogRequest()
        assertEquals(RequestAdmission.Denied("native.not_authorized"), authorizer.authorize(metadata, datasource, "alice", setOf("reader"), AuthzContext(), gate))
    }

    @Test
    fun `descriptor with unknown proto fields is denied`() {
        val gate = authz(connect, invokeAll)
        val payload = descriptor("ListWorkGroups").toByteString().concat(ByteString.copyFrom(byteArrayOf(0x7a.toByte(), 0x01, 0x41)))
        val request = RequestAuthorization.newBuilder().setDatasourceName(datasource.name)
            .setNative(NativeRequestAuthorization.newBuilder().setDescriptorVersion(1).setDescriptorPayload(payload))
            .build()
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), authorizer.authorize(request, datasource, "alice", setOf("reader"), AuthzContext(), gate))
    }

    @Test
    fun `SQL submission returns REQUIRE_SQL_ADMISSION and never authorizes the SQL here`() {
        val body = """{"QueryString":"select secret from t","WorkGroup":"primary","QueryExecutionContext":{"Catalog":"awsdatacatalog","Database":"analytics"}}"""
        val gate = authz(connect)
        val admission = admit(descriptor("StartQueryExecution", body = body), gate)
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_REQUIRE_SQL_ADMISSION, instructions(admission).action)
        assertEquals(0, instructions(admission).contextsCount)
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("StartQueryExecution", body = body, phase = RESPONSE), gate))
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("StartQueryExecution", body = body), authz()))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("StartQueryExecution", body = """{"WorkGroup":"primary"}"""), gate))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("StartQueryExecution", body = """{"QueryString":"select 1","ExecutionParameters":[1]}"""), gate))
    }

    @Test
    fun `SQL submission stays inside the configured target scope`() {
        val gate = authz(connect)
        fun submission(body: String) = admit(descriptor("StartQueryExecution", body = body), gate)
        assertTrue(submission("""{"QueryString":"select 1"}""") is RequestAdmission.Allowed)
        assertTrue(submission("""{"QueryString":"select 1","WorkGroup":"PRIMARY"}""") is RequestAdmission.Allowed)
        assertEquals(RequestAdmission.Denied("native.scope_violation"), submission("""{"QueryString":"select 1","WorkGroup":"other"}"""))
        assertEquals(RequestAdmission.Denied("native.scope_violation"), submission("""{"QueryString":"select 1","QueryExecutionContext":{"Catalog":"other"}}"""))
        assertEquals(RequestAdmission.Denied("native.scope_violation"), submission("""{"QueryString":"select 1","QueryExecutionContext":{"Database":"other"}}"""))
        assertEquals(RequestAdmission.Denied("native.scope_violation"), submission("""{"QueryString":"select 1","ResultConfiguration":{"OutputLocation":"s3://elsewhere/"}}"""))
        assertEquals(RequestAdmission.Denied("native.scope_violation"), submission("""{"QueryString":"select 1","ResultReuseConfiguration":{"ResultReuseByAgeConfiguration":{"Enabled":true}}}"""))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), submission("""{"QueryString":"select 1","QueryExecutionContext":{"Catalog":5}}"""))
        val unconfigured = admit(descriptor("StartQueryExecution", body = """{"QueryString":"select 1","WorkGroup":"primary"}""") { target = target.toBuilder().setDefaultWorkgroup("").build() }, gate)
        assertEquals(RequestAdmission.Denied("native.scope_violation"), unconfigured)
    }

    @Test
    fun `metadata request forwards after connect and native invoke on the named resource`() {
        val body = """{"CatalogName":"awsdatacatalog","DatabaseName":"analytics","TableName":"users"}"""
        val scoped = authz(
            connect,
            """permit(principal, action == Action::"native.invoke", resource)
                when { resource.kind == "table" && resource.id == "awsdatacatalog/analytics/users" && context has native_operation && context.native_operation == "athena:GetTableMetadata" };""",
        )
        val admission = admit(descriptor("GetTableMetadata", body = body), scoped)
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST, instructions(admission).action)
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("GetTableMetadata", body = body.replace("users", "salaries")), scoped))
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("GetTableMetadata", body = body), authz(connect)))
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("GetTableMetadata", body = body), authz(invokeAll)))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("GetTableMetadata", body = """{"CatalogName":"awsdatacatalog"}"""), scoped))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("ListWorkGroups") { addObservations(observation("workgroup", "primary")) }, scoped))
    }

    @Test
    fun `metadata response releases only when every observed resource is authorized`() {
        val gate = authz(
            connect,
            """permit(principal, action == Action::"native.invoke", resource) when { resource.kind == "datasource" || resource.kind == "workgroup" && resource.id like "team-*" };""",
        )
        val allowed = admit(descriptor("ListWorkGroups", phase = RESPONSE) { addObservations(observation("workgroup", "team-a")); addObservations(observation("workgroup", "team-b")) }, gate)
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA, instructions(allowed).action)
        val denied = admit(descriptor("ListWorkGroups", phase = RESPONSE) { addObservations(observation("workgroup", "team-a")); addObservations(observation("workgroup", "finance")) }, gate)
        assertEquals(RequestAdmission.Denied("native.not_authorized"), denied)
        val bad = admit(descriptor("ListWorkGroups", phase = RESPONSE) { addObservations(observation("workgroup", "team-a") { source = AthenaObservationSource.ATHENA_OBSERVATION_SOURCE_UNSPECIFIED }) }, gate)
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), bad)
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("ListWorkGroups", phase = RESPONSE) { addObservations(observation("workgroup", "team-a")) }, authz(connect)))
        val datasourceWide = authz(connect, """permit(principal, action == Action::"native.invoke", resource) when { resource.kind == "datasource" };""")
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("ListWorkGroups"), authz(connect)))
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("ListWorkGroups", phase = RESPONSE), authz(connect)))
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST, instructions(admit(descriptor("ListWorkGroups"), datasourceWide)).action)
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA, instructions(admit(descriptor("ListWorkGroups", phase = RESPONSE), datasourceWide)).action)
    }

    @Test
    fun `native mutation operations need native invoke on their specific resource and Spark is refused`() {
        val prepared = authz(connect, """permit(principal, action == Action::"native.invoke", resource) when { resource.kind == "prepared-statement" };""")
        val body = """{"WorkGroup":"primary","StatementName":"top","QueryString":"select 1"}"""
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST, instructions(admit(descriptor("CreatePreparedStatement", body = body), prepared)).action)
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("DeleteWorkGroup", body = """{"WorkGroup":"primary"}"""), prepared))
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("ListPreparedStatements", body = """{"WorkGroup":"primary"}"""), prepared))
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("TagResource", body = """{"ResourceARN":"arn:aws:athena:us-east-1:1:workgroup/primary"}"""), prepared))
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor("CreateDataCatalog", body = """{"Name":"ext"}"""), prepared))
        // Spark sessions, calculations, and notebooks run code the proxy cannot mask; no permit reaches them.
        for (operation in listOf("StartSession", "StartCalculationExecution", "CreateNotebook", "GetSessionEndpoint")) {
            assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(descriptor(operation, body = """{"WorkGroup":"spark","SessionId":"s1"}"""), authz(connect, invokeAll)), operation)
        }
    }

    @Test
    fun `result and status operations require an owned unexpired context bound to the target`() {
        val gate = authz(connect)
        val mine = context("q1")
        val request = descriptor("GetQueryResults", body = """{"QueryExecutionId":"q1"}""") { addCachedContexts(mine) }
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST, instructions(admit(request, gate)).action)
        val response = admit(descriptor("GetQueryResults", body = """{"QueryExecutionId":"q1"}""", phase = RESPONSE) { addCachedContexts(mine) }, gate)
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT, instructions(response).action)
        assertEquals(listOf("q1" to mine.contextId), instructions(response).contextsList.map { it.resourceId to it.contextId })

        fun denied(ctx: AthenaCachedContext?, id: String = "q1") =
            admit(descriptor("GetQueryResults", body = """{"QueryExecutionId":"$id"}""", phase = RESPONSE) { ctx?.let { addCachedContexts(it) } }, gate)
        assertEquals(RequestAdmission.Denied("native.context_unavailable"), denied(null))
        assertEquals(RequestAdmission.Denied("native.context_unavailable"), denied(mine, id = "q2"))
        assertEquals(RequestAdmission.Denied("native.context_unavailable"), denied(context("q1", owner = "bob")))
        assertEquals(RequestAdmission.Denied("native.context_unavailable"), denied(context("q1", expiresAt = now.minusSeconds(1))))
        assertEquals(RequestAdmission.Denied("native.context_unavailable"), denied(context("q1", expiresAt = now)))
        assertEquals(RequestAdmission.Denied("native.context_unavailable"), denied(context("q1", binding = ByteString.copyFrom(ByteArray(32) { 9 }))))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), denied(context("q1", binding = ByteString.copyFrom(ByteArray(16)))))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), denied(mine.toBuilder().setVersion(2).build()))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), denied(mine.toBuilder().clearExpiresAt().build()))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), denied(mine.toBuilder().setContextId("").build()))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), denied(mine.toBuilder().setMetadataDigest(ByteString.copyFrom(ByteArray(5))).build()))
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("GetQueryResults", body = "{}"), gate))
        for (operation in listOf("GetQueryExecution", "GetQueryResultsStream", "StopQueryExecution", "GetQueryRuntimeStatistics")) {
            assertTrue(admit(descriptor(operation, body = """{"QueryExecutionId":"q1"}""") { addCachedContexts(mine) }, gate) is RequestAdmission.Allowed, operation)
            assertEquals(RequestAdmission.Denied("native.context_unavailable"), admit(descriptor(operation, body = """{"QueryExecutionId":"q1"}"""), gate), operation)
        }
    }

    @Test
    fun `a descriptor body claim never substitutes for the proxy-attested context owner`() {
        val gate = authz(connect, invokeAll)
        val forged = descriptor("GetQueryResults", body = """{"QueryExecutionId":"q1","Owner":"alice","CachedContexts":[{"owner":"alice"}]}""", phase = RESPONSE) {
            addCachedContexts(context("q1", owner = "bob"))
        }
        assertEquals(RequestAdmission.Denied("native.context_unavailable"), admit(forged, gate))
    }

    @Test
    fun `batch status requires a context for every execution id`() {
        val gate = authz(connect)
        val body = """{"QueryExecutionIds":["q1","q2"]}"""
        val full = admit(descriptor("BatchGetQueryExecution", body = body, phase = RESPONSE) { addCachedContexts(context("q1")); addCachedContexts(context("q2")) }, gate)
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT, instructions(full).action)
        assertEquals(listOf("q1", "q2"), instructions(full).contextsList.map { it.resourceId })
        val partial = admit(descriptor("BatchGetQueryExecution", body = body, phase = RESPONSE) { addCachedContexts(context("q1")) }, gate)
        assertEquals(RequestAdmission.Denied("native.context_unavailable"), partial)
        val foreign = admit(descriptor("BatchGetQueryExecution", body = body) { addCachedContexts(context("q1")); addCachedContexts(context("q2", owner = "bob")) }, gate)
        assertEquals(RequestAdmission.Denied("native.context_unavailable"), foreign)
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("BatchGetQueryExecution", body = """{"QueryExecutionIds":[]}"""), gate))
        val duplicate = admit(descriptor("BatchGetQueryExecution", body = body) { addCachedContexts(context("q1")); addCachedContexts(context("q1")); addCachedContexts(context("q2")) }, gate)
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), duplicate)
    }

    @Test
    fun `execution response observations must match owned contexts`() {
        val gate = authz(connect)
        val body = """{"QueryExecutionId":"q1"}"""
        val stray = admit(descriptor("GetQueryExecution", body = body, phase = RESPONSE) { addCachedContexts(context("q1")); addObservations(observation("query-execution", "q2")) }, gate)
        assertEquals(RequestAdmission.Denied("native.context_unavailable"), stray)
        val matching = admit(descriptor("GetQueryExecution", body = body, phase = RESPONSE) { addCachedContexts(context("q1")); addObservations(observation("query-execution", "q1")) }, gate)
        assertTrue(matching is RequestAdmission.Allowed)
    }

    @Test
    fun `history listing forwards the request and keeps only owned executions`() {
        val gate = authz(connect)
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST, instructions(admit(descriptor("ListQueryExecutions"), gate)).action)
        val owned = instructions(admit(descriptor("ListQueryExecutions", phase = RESPONSE) {
            addCachedContexts(context("q1")); addCachedContexts(context("q2"))
            addObservations(observation("query-execution", "q1")); addObservations(observation("query-execution", "q2"))
        }, gate))
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT, owned.action)
        assertEquals(listOf("q1", "q2"), owned.contextsList.map { it.resourceId })
        val mixed = instructions(admit(descriptor("ListQueryExecutions", phase = RESPONSE) {
            addCachedContexts(context("q1")); addCachedContexts(context("q3", owner = "bob"))
            addObservations(observation("query-execution", "q1")); addObservations(observation("query-execution", "q3"))
        }, gate))
        assertEquals(listOf("q1"), mixed.contextsList.map { it.resourceId })
        val expired = instructions(admit(descriptor("ListQueryExecutions", phase = RESPONSE) {
            addCachedContexts(context("q1", expiresAt = now.minusSeconds(1)))
            addObservations(observation("query-execution", "q1"))
        }, gate))
        assertEquals(AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT, expired.action)
        assertTrue(expired.contextsList.isEmpty())
    }

    @Test
    fun `cached enforcement instructions admit only the trimmed verdict fields`() {
        val mask = ColumnMask.newBuilder().setColumn("ssn").setMaskFn("hash").setKind("pii").setOrdinal(1).build()
        val trimmed = Verdict.newBuilder().setDecision(EnfAction.MASK).addMasks(mask).setUnmaskablePermitted(true).setSanitizeDiagnostics(true).setDecisionId(42).build()
        assertTrue(isTrimmedVerdict(trimmed.toByteString(), 2))
        assertTrue(isTrimmedVerdict(Verdict.newBuilder().setDecision(EnfAction.ALLOW).build().toByteString(), null))
        val rejected = listOf(
            ByteString.EMPTY,
            ByteString.copyFromUtf8("ÿ"),
            trimmed.toBuilder().addEffectiveRoles("admin").build().toByteString(),
            trimmed.toBuilder().setRewrittenSql("select 1").build().toByteString(),
            trimmed.toBuilder().addResultFingerprint(com.ridi.oss.proxymonster.analyzer.pb.RequireResultReadGrant.getDefaultInstance()).build().toByteString(),
            trimmed.toBuilder().addAfterStatement(com.ridi.oss.proxymonster.grpc.ProxyCommand.getDefaultInstance()).build().toByteString(),
            trimmed.toBuilder().setAthenaSubmission(com.ridi.oss.proxymonster.athena.pb.AthenaSubmission.newBuilder().setQueryString("select 1")).build().toByteString(),
            trimmed.toBuilder().setDenyReason("x").build().toByteString(),
            trimmed.toBuilder().setGeneration(3).build().toByteString(),
            trimmed.toBuilder().setDecision(EnfAction.DENY).build().toByteString(),
            trimmed.toBuilder().setDecision(EnfAction.ALLOW).build().toByteString(),
            trimmed.toBuilder().clearMasks().addMasks(mask.toBuilder().clearOrdinal()).build().toByteString(),
            trimmed.toBuilder().clearMasks().addMasks(mask.toBuilder().setOrdinal(-1)).build().toByteString(),
            trimmed.toByteString().concat(ByteString.copyFrom(byteArrayOf(0x78, 0x01))),
        )
        rejected.forEachIndexed { i, bytes -> assertTrue(!isTrimmedVerdict(bytes, 2), "case $i") }
        assertTrue(!isTrimmedVerdict(trimmed.toByteString(), 1))
        val gate = authz(connect)
        val poisoned = context("q1").toBuilder().setEnforcementInstructions(trimmed.toBuilder().addEffectiveRoles("admin").build().toByteString()).build()
        assertEquals(RequestAdmission.Denied("native.invalid_descriptor"), admit(descriptor("GetQueryResults", body = """{"QueryExecutionId":"q1"}""") { addCachedContexts(poisoned) }, gate))
    }

    @Test
    fun `provider context tags roles and requester IP flow into native decisions`() {
        val gate = authz(
            """permit(principal, action == Action::"context.tag::trusted-network", resource)
                when { context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };""",
            connect,
            """permit(principal in Role::"reader", action == Action::"native.invoke", resource in Tag::"production")
                when { context has tags && context.tags.contains("trusted-network") && !(context has stmt_kind) };""",
        )
        val request = descriptor("GetWorkGroup", body = """{"WorkGroup":"primary"}""")
        val trusted = AuthzContext(requesterIp = "10.2.3.4", stmtKind = "select", tags = setOf("forged"), nativeOperation = "forged")
        assertTrue(admit(request, gate, context = trusted) is RequestAdmission.Allowed)
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(request, gate, context = AuthzContext(requesterIp = "198.51.100.1")))
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(request, gate, roles = emptySet(), context = trusted))
        assertEquals(RequestAdmission.Denied("native.not_authorized"), admit(request, gate, ds = datasource.copy(tags = emptyList()), context = trusted))
    }

    @Test
    fun `engine definition routes Athena through the native authorizer`() {
        assertTrue(AthenaRequestAuthorizer.authorize(catalogRequest(), datasource, "alice", setOf("reader"), AuthzContext(), authz(connect)) is RequestAdmission.Denied)
        assertTrue(AthenaRequestAuthorizer.authorize(request(descriptor("ListWorkGroups"), 1), datasource, "alice", setOf("reader"), AuthzContext(), authz(connect, invokeAll)) is RequestAdmission.Allowed)
    }

    private fun admit(
        descriptor: AthenaNativeDescriptor,
        gate: Authz,
        version: Int = 1,
        ds: Datasource = datasource,
        roles: Set<String> = setOf("reader"),
        context: AuthzContext = AuthzContext(),
    ): RequestAdmission = authorizer.authorize(request(descriptor, version), ds, "alice", roles, context, gate)

    private fun request(descriptor: AthenaNativeDescriptor, version: Int): RequestAuthorization = RequestAuthorization.newBuilder()
        .setDatasourceName(datasource.name)
        .setNative(NativeRequestAuthorization.newBuilder().setDescriptorVersion(version).setDescriptorPayload(descriptor.toByteString()))
        .build()

    private fun instructions(admission: RequestAdmission): AthenaNativeInstructions {
        assertTrue(admission is RequestAdmission.Allowed, admission.toString())
        val parsed = AthenaNativeInstructions.parseFrom(admission.providerInstructions)
        assertEquals(1, parsed.version)
        return parsed
    }

    private fun descriptor(
        operation: String,
        body: String = "{}",
        phase: NativeAuthorizationPhase = REQUEST,
        block: AthenaNativeDescriptor.Builder.() -> Unit = {},
    ): AthenaNativeDescriptor = athenaNativeDescriptor {
        service = "athena"
        this.operation = operation
        method = "POST"
        path = "/"
        this.body = ByteString.copyFromUtf8(body)
        this.phase = phase
        target = athenaTarget {
            region = "ap-northeast-2"
            defaultWorkgroup = "primary"
            defaultCatalog = "awsdatacatalog"
            defaultDatabase = "analytics"
            endpoint = "https://athena.ap-northeast-2.amazonaws.com"
            targetBinding = binding
        }
    }.toBuilder().apply(block).build()

    private fun observation(kind: String, id: String, block: com.ridi.oss.proxymonster.athena.pb.AthenaResourceObservation.Builder.() -> Unit = {}) =
        athenaResourceObservation {
            source = AthenaObservationSource.ATHENA_OBSERVATION_SOURCE_AWS_RESPONSE
            this.kind = kind
            this.id = id
        }.toBuilder().apply(block).build()

    private fun context(
        id: String,
        owner: String = "alice",
        expiresAt: Instant = now.plusSeconds(3600),
        binding: ByteString = this.binding,
    ): AthenaCachedContext = athenaCachedContext {
        version = 1
        contextId = "ctx-$id"
        resourceId = id
        this.owner = owner
        targetBinding = binding
        this.expiresAt = Timestamp.newBuilder().setSeconds(expiresAt.epochSecond).setNanos(expiresAt.nano).build()
        enforcementInstructions = Verdict.newBuilder().setDecision(EnfAction.ALLOW).setDecisionId(7).build().toByteString()
    }

    private fun catalogRequest(): RequestAuthorization = RequestAuthorization.newBuilder()
        .setDatasourceName(datasource.name)
        .setReadCatalog(com.ridi.oss.proxymonster.grpc.readCatalog { namespace = com.ridi.oss.proxymonster.grpc.namespaceRef { catalog = "awsdatacatalog"; schema = "analytics" } })
        .build()

    private fun authz(vararg policies: String): Authz = Authz(
        CedarEngine(policies.mapIndexed { index, source -> index.toLong() + 1 to source }),
        CedarPolicyStore(
            Proxy.newProxyInstance(DataSource::class.java.classLoader, arrayOf(DataSource::class.java)) { _, _, _ ->
                error("native authorization must not access the store")
            } as DataSource,
        ),
        RoleSource { error("native authorization must use the resolved role snapshot") },
    )
}
