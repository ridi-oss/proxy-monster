package grpcsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	athenapb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	pb "github.com/ridi-oss/proxy-monster/cpgo/internal/pb"
)

const (
	athenaContextVersion = 1
	athenaBindingBytes   = 32
	maxExpectedWidth     = 1 << 20
	queryExecution       = "query-execution"
)

// denyError ends an Athena decision with a stable deny code.
type denyError string

func (d denyError) Error() string { return string(d) }

var errMalformed = denyError(nativeInvalidDescriptor)

type athenaCategory int

const (
	sqlSubmission athenaCategory = iota
	athenaMetadata
	athenaExecution
	athenaHistory
	athenaNative
)

type nativeResource struct{ kind, id string }

type athenaOperation struct {
	category  athenaCategory
	resources func(body) ([]nativeResource, error)
}

// authorizeAthena decides one Athena API call from the proxy's descriptor. StartQueryExecution must go through
// SQL admission, status and result reads are bound to the caller's own cached contexts, listings are filtered
// to owned executions, and everything else is native.invoke on its resource. An unknown operation is denied.
func (s *service) authorizeAthena(ctx context.Context, r *pb.RequestAuthorization, ds requestDatasource, c caller) (admission, error) {
	a, err := s.admitAthena(ctx, r, ds, c, time.Now)
	var d denyError
	if errors.As(err, &d) {
		return admission{deny: string(d)}, nil
	}
	return a, err
}

func (s *service) admitAthena(ctx context.Context, r *pb.RequestAuthorization, ds requestDatasource, c caller, now func() time.Time) (admission, error) {
	descriptor := r.GetAthena()
	if blank(r.GetDatasourceName()) || r.GetDatasourceName() != ds.name || descriptor == nil {
		return admission{}, denyError(nativeNotAuthorized)
	}
	if err := validDescriptor(descriptor); err != nil {
		return admission{}, err
	}
	op, ok := athenaOperations[descriptor.GetOperation()]
	if !ok {
		return admission{}, denyError(nativeNotAuthorized)
	}
	b, err := decodeBody(descriptor.GetBody())
	if err != nil {
		return admission{}, err
	}
	g := athenaGate{s: s, ds: ds, c: c, operation: "athena:" + descriptor.GetOperation()}
	if ok, err := s.mayConnect(ctx, ds, c); err != nil {
		return admission{}, err
	} else if !ok {
		return admission{}, denyError(nativeNotAuthorized)
	}
	out := &athenapb.AthenaNativeInstructions{}
	response := descriptor.GetPhase() == athenapb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_RESPONSE
	forward := athenapb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
	switch op.category {
	case sqlSubmission:
		if response {
			return admission{}, denyError(nativeNotAuthorized)
		}
		if err := validateSubmissionScope(descriptor.GetTarget(), b); err != nil {
			return admission{}, err
		}
		out.Action = athenapb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_REQUIRE_SQL_ADMISSION
	case athenaMetadata, athenaNative:
		resources, err := op.resources(b)
		if err != nil {
			return admission{}, err
		}
		if len(resources) == 0 {
			resources = []nativeResource{{"datasource", ds.name}}
		}
		for _, res := range resources {
			if err := g.invoke(ctx, res.kind, res.id, nil); err != nil {
				return admission{}, err
			}
		}
		for _, o := range descriptor.GetObservations() {
			if err := g.observe(ctx, o); err != nil {
				return admission{}, err
			}
		}
		out.Action = forward
		if response {
			out.Action = athenapb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA
		}
	case athenaExecution:
		resources, err := op.resources(b)
		if err != nil {
			return admission{}, err
		}
		var ids []string
		for _, res := range resources {
			if !slices.Contains(ids, res.id) {
				ids = append(ids, res.id)
			}
		}
		owned := ownedContexts(descriptor, c.principal, now())
		var refs []*athenapb.AthenaCachedContext
		for _, id := range ids {
			ctxRef, ok := owned[id]
			if !ok {
				return admission{}, denyError(nativeContextUnavailable)
			}
			refs = append(refs, ctxRef)
		}
		for _, o := range descriptor.GetObservations() {
			if o.GetKind() == queryExecution {
				if _, ok := owned[o.GetId()]; !ok || !slices.Contains(ids, o.GetId()) {
					return admission{}, denyError(nativeContextUnavailable)
				}
			} else if err := g.observe(ctx, o); err != nil {
				return admission{}, err
			}
		}
		out.Action = forward
		if response {
			out.Action = athenapb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
			for _, ref := range refs {
				out.Contexts = append(out.Contexts, &athenapb.AthenaContextRef{ResourceId: ref.GetResourceId(), ContextId: ref.GetContextId()})
			}
		}
	case athenaHistory:
		owned := ownedContexts(descriptor, c.principal, now())
		for _, o := range descriptor.GetObservations() {
			if o.GetKind() == queryExecution {
				if ref, ok := owned[o.GetId()]; ok {
					out.Contexts = append(out.Contexts, &athenapb.AthenaContextRef{ResourceId: ref.GetResourceId(), ContextId: ref.GetContextId()})
				}
			} else if err := g.observe(ctx, o); err != nil {
				return admission{}, err
			}
		}
		out.Action = forward
		if response {
			out.Action = athenapb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
		}
	}
	return admission{athena: out}, nil
}

// athenaGate is native.invoke on one Athena resource, with the datasource's context tags derived for it.
type athenaGate struct {
	s         *service
	ds        requestDatasource
	c         caller
	operation string
}

func (g athenaGate) invoke(ctx context.Context, kind, id string, owner *string) error {
	raw := g.c.context
	raw.NativeOperation = g.operation
	tags, err := g.s.authz.ContextTags(ctx, g.c.principal, g.c.roles, g.ds.name, g.ds.tags, raw)
	if err != nil {
		return err
	}
	raw.Tags = tags
	d, err := g.s.authz.AuthorizeAs(ctx, g.c.principal, g.c.roles, "native.invoke", bridge.Resource{
		Type: "NativeResource", DatasourceName: &g.ds.name, NativeKind: kind, NativeID: id, Owner: owner, DatasourceTags: g.ds.tags,
	}, raw)
	if err != nil {
		return err
	}
	if !d.Allow {
		return denyError(nativeNotAuthorized)
	}
	return nil
}

func (g athenaGate) observe(ctx context.Context, o *athenapb.AthenaResourceObservation) error {
	return g.invoke(ctx, o.GetKind(), o.GetId(), o.Owner)
}

// ownedContexts is the descriptor's cached contexts that are the principal's, bound to this target, and unexpired.
func ownedContexts(d *athenapb.AthenaNativeDescriptor, principal string, now time.Time) map[string]*athenapb.AthenaCachedContext {
	out := map[string]*athenapb.AthenaCachedContext{}
	binding := d.GetTarget().GetTargetBinding()
	for _, c := range d.GetCachedContexts() {
		if c.GetOwner() == principal && bytes.Equal(c.GetTargetBinding(), binding) && c.GetExpiresAt().AsTime().After(now) {
			out[c.GetResourceId()] = c
		}
	}
	return out
}

func blank(s string) bool { return strings.TrimFunc(s, unicode.IsSpace) == "" }

func validDescriptor(d *athenapb.AthenaNativeDescriptor) error {
	if d.GetService() != "athena" || blank(d.GetOperation()) {
		return denyError(nativeNotAuthorized)
	}
	if d.GetMethod() != "POST" || d.GetPath() != "/" || d.GetRawQuery() != "" {
		return errMalformed
	}
	for _, h := range d.GetFunctionalHeaders() {
		if blank(h.GetName()) {
			return errMalformed
		}
	}
	request := d.GetPhase() == athenapb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_REQUEST
	if !request && d.GetPhase() != athenapb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_RESPONSE {
		return errMalformed
	}
	if d.GetTarget() == nil || len(d.GetTarget().GetTargetBinding()) != athenaBindingBytes {
		return errMalformed
	}
	if request && len(d.GetObservations()) > 0 {
		return errMalformed
	}
	for _, o := range d.GetObservations() {
		if o.GetSource() != athenapb.AthenaObservationSource_ATHENA_OBSERVATION_SOURCE_AWS_RESPONSE ||
			blank(o.GetKind()) || blank(o.GetId()) || (o.Owner != nil && blank(*o.Owner)) {
			return errMalformed
		}
	}
	seen := map[string]bool{}
	for _, c := range d.GetCachedContexts() {
		if !wellFormed(c) {
			return errMalformed
		}
		seen[c.GetResourceId()] = true
	}
	if len(seen) != len(d.GetCachedContexts()) {
		return errMalformed
	}
	return nil
}

func wellFormed(c *athenapb.AthenaCachedContext) bool {
	if c.GetVersion() != athenaContextVersion || blank(c.GetContextId()) || blank(c.GetResourceId()) || blank(c.GetOwner()) {
		return false
	}
	ts := c.GetExpiresAt()
	if len(c.GetTargetBinding()) != athenaBindingBytes || ts == nil || ts.GetSeconds() < -62135596800 || ts.GetSeconds() > 253402300799 ||
		ts.GetNanos() < 0 || ts.GetNanos() > 999_999_999 {
		return false
	}
	if c.ExpectedWidth != nil && *c.ExpectedWidth > maxExpectedWidth {
		return false
	}
	if n := len(c.GetMetadataDigest()); n != 0 && n != athenaBindingBytes {
		return false
	}
	if n := len(c.GetRequestBinding()); n != 0 && n != athenaBindingBytes {
		return false
	}
	return trimmedVerdict(c.GetEnforcementInstructions(), c.ExpectedWidth)
}

// trimmedVerdict reports whether b is a canonical Verdict carrying only what the result path applies:
// decision, masks, unmaskable_permitted, sanitize_diagnostics and decision_id.
func trimmedVerdict(b []byte, expectedWidth *uint32) bool {
	if len(b) == 0 {
		return false
	}
	v := &pb.Verdict{}
	if proto.Unmarshal(b, v) != nil || hasUnknownFields(v.ProtoReflect()) {
		return false
	}
	if again, err := (proto.MarshalOptions{Deterministic: true}).Marshal(v); err != nil || !bytes.Equal(again, b) {
		return false
	}
	if v.GetDecision() != pb.EnfAction_ALLOW && v.GetDecision() != pb.EnfAction_MASK {
		return false
	}
	if v.GetDecision() == pb.EnfAction_ALLOW && len(v.GetMasks()) > 0 {
		return false
	}
	trimmed := proto.Clone(v).(*pb.Verdict)
	trimmed.Decision, trimmed.Masks, trimmed.UnmaskablePermitted, trimmed.SanitizeDiagnostics, trimmed.DecisionId = 0, nil, false, false, 0
	if proto.Size(trimmed) != 0 {
		return false
	}
	for _, m := range v.GetMasks() {
		if m.Ordinal == nil || *m.Ordinal < 0 || (expectedWidth != nil && uint32(*m.Ordinal) >= *expectedWidth) {
			return false
		}
	}
	return true
}

func hasUnknownFields(m protoreflect.Message) bool {
	if len(m.GetUnknown()) > 0 {
		return true
	}
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
			return true
		}
		switch {
		case fd.IsList():
			for i := range v.List().Len() {
				if hasUnknownFields(v.List().Get(i).Message()) {
					found = true
				}
			}
		case fd.IsMap():
		default:
			found = hasUnknownFields(v.Message())
		}
		return !found
	})
	return found
}

func validateSubmissionScope(target *athenapb.AthenaTarget, b body) error {
	if q, ok := b["QueryString"]; !ok || !isString(q) {
		return errMalformed
	}
	if params, ok := b["ExecutionParameters"]; ok {
		list, isList := params.([]any)
		if !isList || slices.ContainsFunc(list, func(p any) bool { return !isString(p) }) {
			return errMalformed
		}
	}
	if v, ok := b["WorkGroup"]; ok && !isString(v) {
		return errMalformed
	}
	var execCtx map[string]any
	if v, ok := b["QueryExecutionContext"]; ok {
		if execCtx, ok = v.(map[string]any); !ok {
			return errMalformed
		}
	}
	var result map[string]any
	if v, ok := b["ResultConfiguration"]; ok {
		if result, ok = v.(map[string]any); !ok {
			return errMalformed
		}
	}
	inScope := func(m map[string]any, field, configured string) (bool, error) {
		v, ok := m[field]
		if !ok {
			return true, nil
		}
		s, isText := v.(string)
		if !isText {
			return false, errMalformed
		}
		return !blank(configured) && strings.EqualFold(s, configured), nil
	}
	for _, check := range []struct {
		m                 map[string]any
		field, configured string
	}{
		{b, "WorkGroup", target.GetDefaultWorkgroup()},
		{execCtx, "Catalog", target.GetDefaultCatalog()},
		{execCtx, "Database", target.GetDefaultDatabase()},
	} {
		ok, err := inScope(check.m, check.field, check.configured)
		if err != nil {
			return err
		}
		if !ok {
			return denyError(nativeScopeViolation)
		}
	}
	// A client-chosen output location is an S3 write through the proxy's role, outside the configured scope.
	if _, ok := result["OutputLocation"]; ok {
		return denyError(nativeScopeViolation)
	}
	// Result reuse returns an earlier execution's rows under a new id; today's plan cannot vouch for them.
	if _, ok := b["ResultReuseConfiguration"]; ok {
		return denyError(nativeScopeViolation)
	}
	return nil
}

// body is a decoded Athena request body: a JSON object, numbers kept as json.Number.
type body map[string]any

func isString(v any) bool { _, ok := v.(string); return ok }

// decodeBody accepts exactly one JSON object with no duplicate keys at any depth, as Kotlin's strict reader does.
func decodeBody(raw []byte) (body, error) {
	if !utf8.Valid(raw) {
		return nil, errMalformed
	}
	walk := json.NewDecoder(bytes.NewReader(raw))
	walk.UseNumber()
	if err := noDuplicateKeys(walk, 0); err != nil {
		return nil, errMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errMalformed
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errMalformed
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errMalformed
	}
	return body(m), nil
}

// Jackson's default stream limits: nesting depth 1000, names of 50000 characters.
const (
	maxBodyDepth   = 1000
	maxBodyNameLen = 50000
)

func noDuplicateKeys(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == json.Delim('{') || tok == json.Delim('[') {
		if depth++; depth > maxBodyDepth {
			return errMalformed
		}
	}
	switch tok {
	case json.Delim('{'):
		keys := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return err
			}
			if keys[k.(string)] || utf8.RuneCountInString(k.(string)) > maxBodyNameLen {
				return errMalformed
			}
			keys[k.(string)] = true
			if err := noDuplicateKeys(dec, depth); err != nil {
				return err
			}
		}
		_, err = dec.Token()
	case json.Delim('['):
		for dec.More() {
			if err := noDuplicateKeys(dec, depth); err != nil {
				return err
			}
		}
		_, err = dec.Token()
	}
	return err
}

func (b body) str(field string) (string, error) {
	s, ok := b[field].(string)
	if !ok || blank(s) {
		return "", errMalformed
	}
	return s, nil
}

func (b body) strs(field string) ([]string, error) {
	list, ok := b[field].([]any)
	if !ok || len(list) == 0 {
		return nil, errMalformed
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok || blank(s) {
			return nil, errMalformed
		}
		out = append(out, s)
	}
	return out, nil
}

func (b body) optStr(field, def string) (string, error) {
	if _, ok := b[field]; !ok {
		return def, nil
	}
	return b.str(field)
}

func none(body) ([]nativeResource, error) { return nil, nil }

func one(kind string, id func(body) (string, error)) func(body) ([]nativeResource, error) {
	return func(b body) ([]nativeResource, error) {
		v, err := id(b)
		if err != nil {
			return nil, err
		}
		return []nativeResource{{kind, v}}, nil
	}
}

func many(kind string, ids func(body) ([]string, error)) func(body) ([]nativeResource, error) {
	return func(b body) ([]nativeResource, error) {
		vs, err := ids(b)
		if err != nil {
			return nil, err
		}
		out := make([]nativeResource, 0, len(vs))
		for _, v := range vs {
			out = append(out, nativeResource{kind, v})
		}
		return out, nil
	}
}

func field(name string) func(body) (string, error) {
	return func(b body) (string, error) { return b.str(name) }
}

func joined(names ...string) func(body) (string, error) {
	return func(b body) (string, error) {
		parts := make([]string, 0, len(names))
		for _, n := range names {
			v, err := b.str(n)
			if err != nil {
				return "", err
			}
			parts = append(parts, v)
		}
		return strings.Join(parts, "/"), nil
	}
}

func workgroupOrPrimary(b body) (string, error) { return b.optStr("WorkGroup", "primary") }

// athenaOperations is every Athena API operation by its X-Amz-Target suffix; an operation absent here is denied.
// A list without a named scope authorizes the datasource itself; its response releases only observed resources.
var athenaOperations = map[string]athenaOperation{
	"StartQueryExecution": {sqlSubmission, none},

	"GetQueryExecution":         {athenaExecution, one(queryExecution, field("QueryExecutionId"))},
	"BatchGetQueryExecution":    {athenaExecution, many(queryExecution, func(b body) ([]string, error) { return b.strs("QueryExecutionIds") })},
	"GetQueryResults":           {athenaExecution, one(queryExecution, field("QueryExecutionId"))},
	"GetQueryResultsStream":     {athenaExecution, one(queryExecution, field("QueryExecutionId"))},
	"StopQueryExecution":        {athenaExecution, one(queryExecution, field("QueryExecutionId"))},
	"GetQueryRuntimeStatistics": {athenaExecution, one(queryExecution, field("QueryExecutionId"))},
	"ListQueryExecutions":       {athenaHistory, none},

	"ListDataCatalogs":                   {athenaMetadata, none},
	"GetDataCatalog":                     {athenaMetadata, one("data-catalog", field("Name"))},
	"ListDatabases":                      {athenaMetadata, one("data-catalog", field("CatalogName"))},
	"GetDatabase":                        {athenaMetadata, one("database", joined("CatalogName", "DatabaseName"))},
	"ListTableMetadata":                  {athenaMetadata, one("database", joined("CatalogName", "DatabaseName"))},
	"GetTableMetadata":                   {athenaMetadata, one("table", joined("CatalogName", "DatabaseName", "TableName"))},
	"ListWorkGroups":                     {athenaMetadata, none},
	"GetWorkGroup":                       {athenaMetadata, one("workgroup", field("WorkGroup"))},
	"GetPreparedStatement":               {athenaMetadata, one("prepared-statement", joined("WorkGroup", "StatementName"))},
	"BatchGetPreparedStatement":          {athenaMetadata, many("prepared-statement", preparedStatementNames)},
	"ListPreparedStatements":             {athenaMetadata, one("workgroup", field("WorkGroup"))},
	"GetNamedQuery":                      {athenaMetadata, one("named-query", field("NamedQueryId"))},
	"BatchGetNamedQuery":                 {athenaMetadata, many("named-query", func(b body) ([]string, error) { return b.strs("NamedQueryIds") })},
	"ListNamedQueries":                   {athenaMetadata, one("workgroup", workgroupOrPrimary)},
	"ListEngineVersions":                 {athenaMetadata, none},
	"ListApplicationDPUSizes":            {athenaMetadata, none},
	"GetCapacityReservation":             {athenaMetadata, one("capacity-reservation", field("Name"))},
	"ListCapacityReservations":           {athenaMetadata, none},
	"GetCapacityAssignmentConfiguration": {athenaMetadata, one("capacity-reservation", field("CapacityReservationName"))},
	"ListTagsForResource":                {athenaMetadata, one("tagged-resource", field("ResourceARN"))},
	"GetResourceDashboard":               {athenaMetadata, one("tagged-resource", field("ResourceARN"))},

	"CreatePreparedStatement":            {athenaNative, one("prepared-statement", joined("WorkGroup", "StatementName"))},
	"UpdatePreparedStatement":            {athenaNative, one("prepared-statement", joined("WorkGroup", "StatementName"))},
	"DeletePreparedStatement":            {athenaNative, one("prepared-statement", joined("WorkGroup", "StatementName"))},
	"CreateNamedQuery":                   {athenaNative, one("workgroup", workgroupOrPrimary)},
	"UpdateNamedQuery":                   {athenaNative, one("named-query", field("NamedQueryId"))},
	"DeleteNamedQuery":                   {athenaNative, one("named-query", field("NamedQueryId"))},
	"CreateWorkGroup":                    {athenaNative, one("workgroup", field("Name"))},
	"UpdateWorkGroup":                    {athenaNative, one("workgroup", field("WorkGroup"))},
	"DeleteWorkGroup":                    {athenaNative, one("workgroup", field("WorkGroup"))},
	"CreateDataCatalog":                  {athenaNative, one("data-catalog", field("Name"))},
	"UpdateDataCatalog":                  {athenaNative, one("data-catalog", field("Name"))},
	"DeleteDataCatalog":                  {athenaNative, one("data-catalog", field("Name"))},
	"CreateCapacityReservation":          {athenaNative, one("capacity-reservation", field("Name"))},
	"UpdateCapacityReservation":          {athenaNative, one("capacity-reservation", field("Name"))},
	"CancelCapacityReservation":          {athenaNative, one("capacity-reservation", field("Name"))},
	"DeleteCapacityReservation":          {athenaNative, one("capacity-reservation", field("Name"))},
	"PutCapacityAssignmentConfiguration": {athenaNative, one("capacity-reservation", field("CapacityReservationName"))},
	"TagResource":                        {athenaNative, one("tagged-resource", field("ResourceARN"))},
	"UntagResource":                      {athenaNative, one("tagged-resource", field("ResourceARN"))},
}

// preparedStatementNames is BatchGetPreparedStatement's "<workgroup>/<name>" ids; Kotlin reads the names first.
func preparedStatementNames(b body) ([]string, error) {
	names, err := b.strs("PreparedStatementNames")
	if err != nil {
		return nil, err
	}
	wg, err := b.str("WorkGroup")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, wg+"/"+n)
	}
	return out, nil
}
