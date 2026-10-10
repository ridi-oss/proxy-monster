package grpcsvc

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	apb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	pb "github.com/ridi-oss/proxy-monster/cpgo/internal/pb"
)

const (
	requestPhase  = apb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_REQUEST
	responsePhase = apb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_RESPONSE
	forward       = apb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
	sqlAdmission  = apb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_REQUIRE_SQL_ADMISSION
	release       = apb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA
	applyContext  = apb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
)

var binding = bytes.Repeat([]byte{7}, 32)

func descriptor(op, body string, phase apb.NativeAuthorizationPhase, mods ...func(*apb.AthenaNativeDescriptor)) *apb.AthenaNativeDescriptor {
	d := &apb.AthenaNativeDescriptor{
		Service: "athena", Operation: op, Method: "POST", Path: "/", Body: []byte(body), Phase: phase,
		Target: &apb.AthenaTarget{
			Region: "ap-northeast-2", DefaultWorkgroup: "primary", DefaultCatalog: "awsdatacatalog", DefaultDatabase: "analytics",
			Endpoint: "https://athena.ap-northeast-2.amazonaws.com", TargetBinding: binding,
		},
	}
	for _, m := range mods {
		m(d)
	}
	return d
}

func observation(kind, id string) *apb.AthenaResourceObservation {
	return &apb.AthenaResourceObservation{Source: apb.AthenaObservationSource_ATHENA_OBSERVATION_SOURCE_AWS_RESPONSE, Kind: kind, Id: id}
}

func observe(os ...*apb.AthenaResourceObservation) func(*apb.AthenaNativeDescriptor) {
	return func(d *apb.AthenaNativeDescriptor) { d.Observations = append(d.Observations, os...) }
}

func cached(cs ...*apb.AthenaCachedContext) func(*apb.AthenaNativeDescriptor) {
	return func(d *apb.AthenaNativeDescriptor) { d.CachedContexts = append(d.CachedContexts, cs...) }
}

func verdictBytes(v *pb.Verdict) []byte {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func cachedContext(id, owner string, expires time.Time, mods ...func(*apb.AthenaCachedContext)) *apb.AthenaCachedContext {
	c := &apb.AthenaCachedContext{
		Version: 1, ContextId: "ctx-" + id, ResourceId: id, Owner: owner, TargetBinding: binding, ExpiresAt: timestamppb.New(expires),
		EnforcementInstructions: verdictBytes(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 7}),
	}
	for _, m := range mods {
		m(c)
	}
	return c
}

// outcome is a deny code, or an allow's Athena action with the resource ids of its context refs.
type outcome struct {
	deny     string
	action   apb.AthenaNativeInstruction
	contexts []string
}

func deny(code string) outcome { return outcome{deny: code} }

func act(a apb.AthenaNativeInstruction, ids ...string) outcome {
	return outcome{action: a, contexts: ids}
}

func outcomeOf(deny string, in *apb.AthenaNativeInstructions) outcome {
	o := outcome{deny: deny, action: in.GetAction()}
	for _, c := range in.GetContexts() {
		o.contexts = append(o.contexts, c.GetResourceId())
	}
	return o
}

func (o outcome) equal(p outcome) bool {
	return o.deny == p.deny && o.action == p.action && slices.Equal(o.contexts, p.contexts)
}

// lake is an Athena datasource "lake" tagged production, an untagged twin, alice holding reader, and carol holding nothing.
type lake struct {
	*fixture
	alice, carol string
	now          time.Time
}

func newLake(t *testing.T) *lake {
	f := newFixture(t)
	f.datasource("lake", "athena", "analytics", "production")
	f.datasource("lake-untagged", "athena", "analytics")
	f.grant("alice", "reader")
	return &lake{fixture: f, alice: f.token("USER", "alice"), carol: f.token("USER", "carol"), now: time.Now()}
}

func (l *lake) ctx(id string) *apb.AthenaCachedContext {
	return cachedContext(id, "alice", l.now.Add(time.Hour))
}

func (l *lake) rpc(d *apb.AthenaNativeDescriptor, token, ds, addr string) outcome {
	l.t.Helper()
	res, err := l.authorize(on(athenaOp(d), token, ds, addr))
	if err != nil {
		l.t.Fatal(err)
	}
	if res.GetAllowed() != (res.GetDenyReason() == "") {
		l.t.Errorf("allowed=%v with deny %q", res.GetAllowed(), res.GetDenyReason())
	}
	return outcomeOf(res.GetDenyReason(), res.GetAthena())
}

func (l *lake) admit(d *apb.AthenaNativeDescriptor) outcome { return l.rpc(d, l.alice, "lake", "") }

// direct runs the Athena authorizer at a fixed clock, as alice with reader on "lake".
func (l *lake) direct(r *pb.RequestAuthorization, now time.Time) outcome {
	l.t.Helper()
	if r.DatasourceName == "" {
		r.DatasourceName = "lake"
	}
	a, err := l.s.admitAthena(context.Background(), r, reqDS("lake", "athena", "analytics", "production"),
		caller{principal: "alice", roles: []string{"reader"}, context: authz.Context{Channel: "wire"}}, func() time.Time { return now })
	var d denyError
	if errors.As(err, &d) {
		return deny(string(d))
	}
	if err != nil {
		l.t.Fatal(err)
	}
	return outcomeOf(a.deny, a.athena)
}

type athenaCase struct {
	name     string
	policies []string
	d        *apb.AthenaNativeDescriptor
	want     outcome
}

func (l *lake) run(cases []athenaCase) {
	l.t.Helper()
	for _, tc := range cases {
		l.policies(tc.policies...)
		if got := l.admit(tc.d); !got.equal(tc.want) {
			l.t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestAthenaRejectsMalformedDescriptors(t *testing.T) {
	l := newLake(t)
	gate := []string{connectAll, invokeAll}
	wg := func(mod func(*apb.AthenaNativeDescriptor)) *apb.AthenaNativeDescriptor {
		return descriptor("ListWorkGroups", "{}", requestPhase, mod)
	}
	l.run([]athenaCase{
		{"unknown operation", gate, descriptor("NotAnOperation", "{}", requestPhase), deny(nativeNotAuthorized)},
		{"wrong service", gate, wg(func(d *apb.AthenaNativeDescriptor) { d.Service = "glue" }), deny(nativeNotAuthorized)},
		{"GET method", gate, wg(func(d *apb.AthenaNativeDescriptor) { d.Method = "GET" }), deny(nativeInvalidDescriptor)},
		{"raw query", gate, wg(func(d *apb.AthenaNativeDescriptor) { d.RawQuery = "x=1" }), deny(nativeInvalidDescriptor)},
		{"no target", gate, wg(func(d *apb.AthenaNativeDescriptor) { d.Target = nil }), deny(nativeInvalidDescriptor)},
		{"unspecified phase", gate, wg(func(d *apb.AthenaNativeDescriptor) {
			d.Phase = apb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_UNSPECIFIED
		}), deny(nativeInvalidDescriptor)},
		{"truncated body", gate, descriptor("ListWorkGroups", "{", requestPhase), deny(nativeInvalidDescriptor)},
		{"array body", gate, descriptor("ListWorkGroups", "[]", requestPhase), deny(nativeInvalidDescriptor)},
		{"two objects", gate, descriptor("ListWorkGroups", "{} {}", requestPhase), deny(nativeInvalidDescriptor)},
		{"duplicate key", gate, descriptor("GetWorkGroup", `{"WorkGroup":"a","WorkGroup":"b"}`, requestPhase), deny(nativeInvalidDescriptor)},
		{"non-string resource", gate, descriptor("GetWorkGroup", `{"WorkGroup":1}`, requestPhase), deny(nativeInvalidDescriptor)},
	})
	l.policies(connectAll, invokeAll)
	if got := l.rpcOp(catalogOp(ref("awsdatacatalog", "analytics", ""))); !got.equal(deny(nativeNotAuthorized)) {
		t.Errorf("metadata operation on Athena: %+v", got)
	}
	if got := l.direct(on(athenaOp(descriptor("ListWorkGroups", "{}", requestPhase)), "", "other", ""), l.now); !got.equal(deny(nativeNotAuthorized)) {
		t.Errorf("another datasource: %+v", got)
	}
}

func (l *lake) rpcOp(r *pb.RequestAuthorization) outcome {
	l.t.Helper()
	res, err := l.authorize(on(r, l.alice, "lake", ""))
	if err != nil {
		l.t.Fatal(err)
	}
	return outcomeOf(res.GetDenyReason(), res.GetAthena())
}

func TestAthenaSQLSubmissionRequiresSQLAdmission(t *testing.T) {
	l := newLake(t)
	body := `{"QueryString":"select secret from t","WorkGroup":"primary","QueryExecutionContext":{"Catalog":"awsdatacatalog","Database":"analytics"}}`
	l.run([]athenaCase{
		{"request", []string{connectAll}, descriptor("StartQueryExecution", body, requestPhase), act(sqlAdmission)},
		{"response phase", []string{connectAll}, descriptor("StartQueryExecution", body, responsePhase), deny(nativeNotAuthorized)},
		{"no connect", nil, descriptor("StartQueryExecution", body, requestPhase), deny(nativeNotAuthorized)},
		{"no query string", []string{connectAll}, descriptor("StartQueryExecution", `{"WorkGroup":"primary"}`, requestPhase), deny(nativeInvalidDescriptor)},
		{"non-string parameter", []string{connectAll}, descriptor("StartQueryExecution", `{"QueryString":"select 1","ExecutionParameters":[1]}`, requestPhase), deny(nativeInvalidDescriptor)},
	})
}

func TestAthenaSQLSubmissionScope(t *testing.T) {
	l := newLake(t)
	gate := []string{connectAll}
	sub := func(body string) *apb.AthenaNativeDescriptor {
		return descriptor("StartQueryExecution", body, requestPhase)
	}
	l.run([]athenaCase{
		{"defaults", gate, sub(`{"QueryString":"select 1"}`), act(sqlAdmission)},
		{"workgroup case-insensitive", gate, sub(`{"QueryString":"select 1","WorkGroup":"PRIMARY"}`), act(sqlAdmission)},
		{"other workgroup", gate, sub(`{"QueryString":"select 1","WorkGroup":"other"}`), deny(nativeScopeViolation)},
		{"other catalog", gate, sub(`{"QueryString":"select 1","QueryExecutionContext":{"Catalog":"other"}}`), deny(nativeScopeViolation)},
		{"other database", gate, sub(`{"QueryString":"select 1","QueryExecutionContext":{"Database":"other"}}`), deny(nativeScopeViolation)},
		{"output location", gate, sub(`{"QueryString":"select 1","ResultConfiguration":{"OutputLocation":"s3://elsewhere/"}}`), deny(nativeScopeViolation)},
		{"result reuse", gate, sub(`{"QueryString":"select 1","ResultReuseConfiguration":{"ResultReuseByAgeConfiguration":{"Enabled":true}}}`), deny(nativeScopeViolation)},
		{"non-string catalog", gate, sub(`{"QueryString":"select 1","QueryExecutionContext":{"Catalog":5}}`), deny(nativeInvalidDescriptor)},
		{"unconfigured workgroup", gate, descriptor("StartQueryExecution", `{"QueryString":"select 1","WorkGroup":"primary"}`, requestPhase,
			func(d *apb.AthenaNativeDescriptor) { d.Target.DefaultWorkgroup = "" }), deny(nativeScopeViolation)},
	})
}

func TestAthenaMetadataRequestNeedsInvokeOnNamedResource(t *testing.T) {
	l := newLake(t)
	body := `{"CatalogName":"awsdatacatalog","DatabaseName":"analytics","TableName":"users"}`
	scoped := []string{connectAll, `permit(principal, action == Action::"native.invoke", resource)
		when { resource.kind == "table" && resource.id == "awsdatacatalog/analytics/users" && context has native_operation && context.native_operation == "athena:GetTableMetadata" };`}
	l.run([]athenaCase{
		{"named table", scoped, descriptor("GetTableMetadata", body, requestPhase), act(forward)},
		{"other table", scoped, descriptor("GetTableMetadata", `{"CatalogName":"awsdatacatalog","DatabaseName":"analytics","TableName":"salaries"}`, requestPhase), deny(nativeNotAuthorized)},
		{"connect only", []string{connectAll}, descriptor("GetTableMetadata", body, requestPhase), deny(nativeNotAuthorized)},
		{"invoke only", []string{invokeAll}, descriptor("GetTableMetadata", body, requestPhase), deny(nativeNotAuthorized)},
		{"partial name", scoped, descriptor("GetTableMetadata", `{"CatalogName":"awsdatacatalog"}`, requestPhase), deny(nativeInvalidDescriptor)},
		{"observation in request", scoped, descriptor("ListWorkGroups", "{}", requestPhase, observe(observation("workgroup", "primary"))), deny(nativeInvalidDescriptor)},
	})
}

func TestAthenaMetadataResponseReleasesOnlyAuthorizedObservations(t *testing.T) {
	l := newLake(t)
	gate := []string{connectAll, `permit(principal, action == Action::"native.invoke", resource) when { resource.kind == "datasource" || resource.kind == "workgroup" && resource.id like "team-*" };`}
	datasourceWide := []string{connectAll, `permit(principal, action == Action::"native.invoke", resource) when { resource.kind == "datasource" };`}
	unspecified := observation("workgroup", "team-a")
	unspecified.Source = apb.AthenaObservationSource_ATHENA_OBSERVATION_SOURCE_UNSPECIFIED
	l.run([]athenaCase{
		{"all observed permitted", gate, descriptor("ListWorkGroups", "{}", responsePhase, observe(observation("workgroup", "team-a"), observation("workgroup", "team-b"))), act(release)},
		{"one observed denied", gate, descriptor("ListWorkGroups", "{}", responsePhase, observe(observation("workgroup", "team-a"), observation("workgroup", "finance"))), deny(nativeNotAuthorized)},
		{"unspecified source", gate, descriptor("ListWorkGroups", "{}", responsePhase, observe(unspecified)), deny(nativeInvalidDescriptor)},
		{"connect only with observation", []string{connectAll}, descriptor("ListWorkGroups", "{}", responsePhase, observe(observation("workgroup", "team-a"))), deny(nativeNotAuthorized)},
		{"connect only request", []string{connectAll}, descriptor("ListWorkGroups", "{}", requestPhase), deny(nativeNotAuthorized)},
		{"connect only response", []string{connectAll}, descriptor("ListWorkGroups", "{}", responsePhase), deny(nativeNotAuthorized)},
		{"datasource-wide request", datasourceWide, descriptor("ListWorkGroups", "{}", requestPhase), act(forward)},
		{"datasource-wide response", datasourceWide, descriptor("ListWorkGroups", "{}", responsePhase), act(release)},
	})
}

func TestAthenaMutationsNeedInvokeOnTheirResourceAndSparkIsRefused(t *testing.T) {
	l := newLake(t)
	prepared := []string{connectAll, `permit(principal, action == Action::"native.invoke", resource) when { resource.kind == "prepared-statement" };`}
	cases := []athenaCase{
		{"create prepared statement", prepared, descriptor("CreatePreparedStatement", `{"WorkGroup":"primary","StatementName":"top","QueryString":"select 1"}`, requestPhase), act(forward)},
		{"delete workgroup", prepared, descriptor("DeleteWorkGroup", `{"WorkGroup":"primary"}`, requestPhase), deny(nativeNotAuthorized)},
		{"list prepared statements", prepared, descriptor("ListPreparedStatements", `{"WorkGroup":"primary"}`, requestPhase), deny(nativeNotAuthorized)},
		{"tag resource", prepared, descriptor("TagResource", `{"ResourceARN":"arn:aws:athena:us-east-1:1:workgroup/primary"}`, requestPhase), deny(nativeNotAuthorized)},
		{"create data catalog", prepared, descriptor("CreateDataCatalog", `{"Name":"ext"}`, requestPhase), deny(nativeNotAuthorized)},
	}
	for _, op := range []string{"StartSession", "StartCalculationExecution", "CreateNotebook", "GetSessionEndpoint"} {
		cases = append(cases, athenaCase{op, []string{connectAll, invokeAll}, descriptor(op, `{"WorkGroup":"spark","SessionId":"s1"}`, requestPhase), deny(nativeNotAuthorized)})
	}
	l.run(cases)
}

func TestAthenaExecutionNeedsOwnedUnexpiredBoundContext(t *testing.T) {
	l := newLake(t)
	gate := []string{connectAll}
	mine := l.ctx("q1")
	results := func(id string, phase apb.NativeAuthorizationPhase, cs ...*apb.AthenaCachedContext) *apb.AthenaNativeDescriptor {
		return descriptor("GetQueryResults", `{"QueryExecutionId":"`+id+`"}`, phase, cached(cs...))
	}
	with := func(mod func(*apb.AthenaCachedContext)) *apb.AthenaCachedContext {
		c := proto.Clone(mine).(*apb.AthenaCachedContext)
		mod(c)
		return c
	}
	cases := []athenaCase{
		{"request", gate, results("q1", requestPhase, mine), act(forward)},
		{"response", gate, results("q1", responsePhase, mine), act(applyContext, "q1")},
		{"no context", gate, results("q1", responsePhase), deny(nativeContextUnavailable)},
		{"other execution", gate, results("q2", responsePhase, mine), deny(nativeContextUnavailable)},
		{"other owner", gate, results("q1", responsePhase, cachedContext("q1", "bob", l.now.Add(time.Hour))), deny(nativeContextUnavailable)},
		{"expired", gate, results("q1", responsePhase, cachedContext("q1", "alice", l.now.Add(-time.Second))), deny(nativeContextUnavailable)},
		{"other target", gate, results("q1", responsePhase, with(func(c *apb.AthenaCachedContext) { c.TargetBinding = bytes.Repeat([]byte{9}, 32) })), deny(nativeContextUnavailable)},
		{"short binding", gate, results("q1", responsePhase, with(func(c *apb.AthenaCachedContext) { c.TargetBinding = make([]byte, 16) })), deny(nativeInvalidDescriptor)},
		{"version 2", gate, results("q1", responsePhase, with(func(c *apb.AthenaCachedContext) { c.Version = 2 })), deny(nativeInvalidDescriptor)},
		{"no expiry", gate, results("q1", responsePhase, with(func(c *apb.AthenaCachedContext) { c.ExpiresAt = nil })), deny(nativeInvalidDescriptor)},
		{"no context id", gate, results("q1", responsePhase, with(func(c *apb.AthenaCachedContext) { c.ContextId = "" })), deny(nativeInvalidDescriptor)},
		{"short metadata digest", gate, results("q1", responsePhase, with(func(c *apb.AthenaCachedContext) { c.MetadataDigest = make([]byte, 5) })), deny(nativeInvalidDescriptor)},
		{"no execution id", gate, descriptor("GetQueryResults", "{}", requestPhase), deny(nativeInvalidDescriptor)},
	}
	for _, op := range []string{"GetQueryExecution", "GetQueryResultsStream", "StopQueryExecution", "GetQueryRuntimeStatistics"} {
		cases = append(cases,
			athenaCase{op + " owned", gate, descriptor(op, `{"QueryExecutionId":"q1"}`, requestPhase, cached(mine)), act(forward)},
			athenaCase{op + " no context", gate, descriptor(op, `{"QueryExecutionId":"q1"}`, requestPhase), deny(nativeContextUnavailable)},
		)
	}
	l.run(cases)
	if res, _ := l.authorize(on(athenaOp(results("q1", responsePhase, mine)), l.alice, "lake", "")); len(res.GetAthena().GetContexts()) != 1 ||
		res.GetAthena().GetContexts()[0].GetContextId() != "ctx-q1" {
		t.Errorf("context refs %v", res.GetAthena().GetContexts())
	}
	fixed := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	if got := l.direct(athenaOp(results("q1", responsePhase, cachedContext("q1", "alice", fixed))), fixed); !got.equal(deny(nativeContextUnavailable)) {
		t.Errorf("context expiring now: %+v", got)
	}
}

func TestAthenaBodyClaimNeverSubstitutesForContextOwner(t *testing.T) {
	l := newLake(t)
	l.run([]athenaCase{{"forged owner claim", []string{connectAll, invokeAll},
		descriptor("GetQueryResults", `{"QueryExecutionId":"q1","Owner":"alice","CachedContexts":[{"owner":"alice"}]}`, responsePhase,
			cached(cachedContext("q1", "bob", l.now.Add(time.Hour)))),
		deny(nativeContextUnavailable)}})
}

func TestAthenaBatchStatusNeedsContextForEveryID(t *testing.T) {
	l := newLake(t)
	gate := []string{connectAll}
	body := `{"QueryExecutionIds":["q1","q2"]}`
	l.run([]athenaCase{
		{"all owned", gate, descriptor("BatchGetQueryExecution", body, responsePhase, cached(l.ctx("q1"), l.ctx("q2"))), act(applyContext, "q1", "q2")},
		{"partial", gate, descriptor("BatchGetQueryExecution", body, responsePhase, cached(l.ctx("q1"))), deny(nativeContextUnavailable)},
		{"foreign", gate, descriptor("BatchGetQueryExecution", body, requestPhase, cached(l.ctx("q1"), cachedContext("q2", "bob", l.now.Add(time.Hour)))), deny(nativeContextUnavailable)},
		{"empty ids", gate, descriptor("BatchGetQueryExecution", `{"QueryExecutionIds":[]}`, requestPhase), deny(nativeInvalidDescriptor)},
		{"duplicate contexts", gate, descriptor("BatchGetQueryExecution", body, requestPhase, cached(l.ctx("q1"), l.ctx("q1"), l.ctx("q2"))), deny(nativeInvalidDescriptor)},
	})
}

func TestAthenaExecutionObservationsMatchOwnedContexts(t *testing.T) {
	l := newLake(t)
	gate := []string{connectAll}
	body := `{"QueryExecutionId":"q1"}`
	l.run([]athenaCase{
		{"stray observation", gate, descriptor("GetQueryExecution", body, responsePhase, cached(l.ctx("q1")), observe(observation(queryExecution, "q2"))), deny(nativeContextUnavailable)},
		{"matching observation", gate, descriptor("GetQueryExecution", body, responsePhase, cached(l.ctx("q1")), observe(observation(queryExecution, "q1"))), act(applyContext, "q1")},
	})
}

func TestAthenaHistoryKeepsOnlyOwnedExecutions(t *testing.T) {
	l := newLake(t)
	gate := []string{connectAll}
	executions := func(ids ...string) func(*apb.AthenaNativeDescriptor) {
		var os []*apb.AthenaResourceObservation
		for _, id := range ids {
			os = append(os, observation(queryExecution, id))
		}
		return observe(os...)
	}
	l.run([]athenaCase{
		{"request", gate, descriptor("ListQueryExecutions", "{}", requestPhase), act(forward)},
		{"all owned", gate, descriptor("ListQueryExecutions", "{}", responsePhase, cached(l.ctx("q1"), l.ctx("q2")), executions("q1", "q2")), act(applyContext, "q1", "q2")},
		{"mixed owners", gate, descriptor("ListQueryExecutions", "{}", responsePhase, cached(l.ctx("q1"), cachedContext("q3", "bob", l.now.Add(time.Hour))), executions("q1", "q3")), act(applyContext, "q1")},
		{"expired", gate, descriptor("ListQueryExecutions", "{}", responsePhase, cached(cachedContext("q1", "alice", l.now.Add(-time.Second))), executions("q1")), act(applyContext)},
	})
}

func TestTrimmedVerdict(t *testing.T) {
	mask := &pb.ColumnMask{Column: "ssn", MaskFn: "hash", Kind: "pii", Ordinal: proto.Int32(1)}
	trimmed := &pb.Verdict{Decision: pb.EnfAction_MASK, Masks: []*pb.ColumnMask{mask}, UnmaskablePermitted: true, SanitizeDiagnostics: true, DecisionId: 42}
	variant := func(mod func(*pb.Verdict)) []byte {
		v := proto.Clone(trimmed).(*pb.Verdict)
		mod(v)
		return verdictBytes(v)
	}
	width := func(n uint32) *uint32 { return &n }
	if !trimmedVerdict(verdictBytes(trimmed), width(2)) {
		t.Error("trimmed verdict rejected")
	}
	if !trimmedVerdict(verdictBytes(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil) {
		t.Error("bare ALLOW rejected")
	}
	for _, tc := range []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"not a message", []byte("ÿ")},
		{"effective roles", variant(func(v *pb.Verdict) { v.EffectiveRoles = []string{"admin"} })},
		{"rewritten sql", variant(func(v *pb.Verdict) { v.RewrittenSql = proto.String("select 1") })},
		{"result fingerprint", variant(func(v *pb.Verdict) { v.ResultFingerprint = []*apb.RequireResultReadGrant{{}} })},
		{"after statement", variant(func(v *pb.Verdict) { v.AfterStatement = []*pb.ProxyCommand{{}} })},
		{"submission", variant(func(v *pb.Verdict) {
			v.Submission = &apb.Submission{Engine: &apb.Submission_Athena{Athena: &apb.AthenaSubmission{ExecutionParameters: []string{"1"}}}}
		})},
		{"deny reason", variant(func(v *pb.Verdict) { v.DenyReason = "x" })},
		{"generation", variant(func(v *pb.Verdict) { v.Generation = 3 })},
		{"DENY", variant(func(v *pb.Verdict) { v.Decision = pb.EnfAction_DENY })},
		{"ALLOW with masks", variant(func(v *pb.Verdict) { v.Decision = pb.EnfAction_ALLOW })},
		{"mask without ordinal", variant(func(v *pb.Verdict) { v.Masks = []*pb.ColumnMask{{Column: "ssn", MaskFn: "hash", Kind: "pii"}} })},
		{"negative ordinal", variant(func(v *pb.Verdict) { v.Masks[0].Ordinal = proto.Int32(-1) })},
		{"unknown field", append(verdictBytes(trimmed), 0x78, 0x01)},
	} {
		if trimmedVerdict(tc.b, width(2)) {
			t.Errorf("%s accepted", tc.name)
		}
	}
	if trimmedVerdict(verdictBytes(trimmed), width(1)) {
		t.Error("ordinal past the expected width accepted")
	}

	l := newLake(t)
	poisoned := l.ctx("q1")
	poisoned.EnforcementInstructions = variant(func(v *pb.Verdict) { v.EffectiveRoles = []string{"admin"} })
	l.run([]athenaCase{{"poisoned context", []string{connectAll},
		descriptor("GetQueryResults", `{"QueryExecutionId":"q1"}`, requestPhase, cached(poisoned)), deny(nativeInvalidDescriptor)}})
}

func TestAthenaContextTagsRolesAndRequesterIP(t *testing.T) {
	l := newLake(t)
	l.policies(trustedNetworkTag, connectAll, `permit(principal in Role::"reader", action == Action::"native.invoke", resource in Tag::"production")
		when { context has tags && context.tags.contains("trusted-network") && !(context has stmt_kind) };`)
	d := descriptor("GetWorkGroup", `{"WorkGroup":"primary"}`, requestPhase)
	for _, tc := range []struct {
		name, token, ds, addr string
		want                  outcome
	}{
		{"trusted", l.alice, "lake", "10.2.3.4:49152", act(forward)},
		{"untrusted address", l.alice, "lake", "198.51.100.1:49152", deny(nativeNotAuthorized)},
		{"no roles", l.carol, "lake", "10.2.3.4:49152", deny(nativeNotAuthorized)},
		{"untagged datasource", l.alice, "lake-untagged", "10.2.3.4:49152", deny(nativeNotAuthorized)},
	} {
		if got := l.rpc(d, tc.token, tc.ds, tc.addr); !got.equal(tc.want) {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	forged := authz.Context{Channel: "wire", RequesterIP: "10.2.3.4", StmtKind: "select", Tags: []string{"forged"}, NativeOperation: "forged"}
	if a := l.bounded(athenaOp(d), reqDS("lake", "athena", "analytics", "production"), []string{"reader"}, forged); a.deny != "" || a.athena.GetAction() != forward {
		t.Errorf("forged statement kind, tags and operation: deny %q", a.deny)
	}
}

// Athena datasources route through the native authorizer; MySQL and PostgreSQL through the metadata gate.
func TestEngineRoutesRequests(t *testing.T) {
	l := newLake(t)
	l.datasource("reports", "mysql", "app")
	l.datasource("reports-pg", "postgres", "app")
	l.policies(connectAll)
	if got := l.rpcOp(catalogOp(ref("awsdatacatalog", "analytics", ""))); got.deny == "" {
		t.Error("Athena admitted a metadata read")
	}
	l.want("mysql metadata", on(catalogOp(ref("def", "app", "")), l.alice, "reports", ""), "")
	l.want("postgres metadata", on(catalogOp(ref("app", "app", "")), l.alice, "reports-pg", ""), "")
	l.policies(connectAll, invokeAll)
	if got := l.admit(descriptor("ListWorkGroups", "{}", requestPhase)); !got.equal(act(forward)) {
		t.Errorf("Athena ListWorkGroups: %+v", got)
	}
	l.want("mysql native", on(athenaOp(descriptor("ListWorkGroups", "{}", requestPhase)), l.alice, "reports", ""), nativeNotAuthorized)
}

func TestDecodeBody(t *testing.T) {
	for in, ok := range map[string]bool{
		`{}`:                          true,
		`{"a":{"b":1},"c":[{"b":2}]}`: true,
		` {"a":1} `:                   true,
		`{"a":{"b":1,"b":2}}`:         false,
		`{"a":[{"b":1,"b":2}]}`:       false,
		`{"a":1}{}`:                   false,
		`{"a":1} x`:                   false,
		`[]`:                          false,
		`"x"`:                         false,
		``:                            false,
		`{"a":1e400}`:                 true,
		"{\"a\":\"\xff\"}":            false,
		`{"a":` + strings.Repeat("[", 999) + strings.Repeat("]", 999) + `}`:   true,
		`{"a":` + strings.Repeat("[", 1000) + strings.Repeat("]", 1000) + `}`: false,
		`{"` + strings.Repeat("k", 50000) + `":1}`:                            true,
		`{"` + strings.Repeat("k", 50001) + `":1}`:                            false,
	} {
		if _, err := decodeBody([]byte(in)); (err == nil) != ok {
			t.Errorf("decodeBody(%.40q): %v, want ok=%v", in, err, ok)
		}
	}
}
