package grpcsvc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/cpgo/grpcsvc/pb"
)

const (
	athenaContextVersion = 1
	athenaBindingBytes   = 32
	maxExpectedWidth     = 1 << 20
	queryExecution       = "query-execution"
)

// denyError ends reading an Athena call with a stable deny code.
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

type athenaOperation struct {
	category  athenaCategory
	resources func(body) ([]nativeResource, error)
}

// athenaAccess reads one Athena API call from the proxy's descriptor. StartQueryExecution goes through SQL
// admission, status and result reads bind to the principal's own cached contexts, listings keep only owned
// executions, and everything else is native.invoke on its resource. An unknown operation is denied.
func athenaAccess(r *pb.RequestAuthorization, ds requestDatasource, principal string, now time.Time) access {
	a, err := readAthena(r.GetAthena(), ds.name, principal, now)
	var d denyError
	if errors.As(err, &d) {
		return access{deny: string(d)}
	}
	if err != nil {
		return access{deny: nativeInvalidDescriptor}
	}
	return a
}

func readAthena(descriptor *analyzerpb.AthenaNativeDescriptor, datasource, principal string, now time.Time) (access, error) {
	if descriptor == nil {
		return access{}, denyError(nativeNotAuthorized)
	}
	if err := validDescriptor(descriptor); err != nil {
		return access{}, err
	}
	op, ok := athenaOperations[descriptor.GetOperation()]
	if !ok {
		return access{}, denyError(nativeNotAuthorized)
	}
	b, err := decodeBody(descriptor.GetBody())
	if err != nil {
		return access{}, err
	}
	out := access{native: true, operation: "athena:" + descriptor.GetOperation(), athena: &analyzerpb.AthenaNativeInstructions{}}
	observed := func(o *analyzerpb.AthenaResourceObservation) {
		out.resources = append(out.resources, nativeResource{o.GetKind(), o.GetId(), o.Owner})
	}
	response := descriptor.GetPhase() == analyzerpb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_RESPONSE
	forward := analyzerpb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
	switch op.category {
	case sqlSubmission:
		if response {
			return access{}, denyError(nativeNotAuthorized)
		}
		if err := validateSubmissionScope(descriptor.GetTarget(), b); err != nil {
			return access{}, err
		}
		out.athena.Action = analyzerpb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_REQUIRE_SQL_ADMISSION
	case athenaMetadata, athenaNative:
		named, err := op.resources(b)
		if err != nil {
			return access{}, err
		}
		if len(named) == 0 {
			named = []nativeResource{{kind: "datasource", id: datasource}}
		}
		out.resources = named
		for _, o := range descriptor.GetObservations() {
			observed(o)
		}
		out.athena.Action = forward
		if response {
			out.athena.Action = analyzerpb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA
		}
	case athenaExecution:
		named, err := op.resources(b)
		if err != nil {
			return access{}, err
		}
		var ids []string
		for _, res := range named {
			if !slices.Contains(ids, res.id) {
				ids = append(ids, res.id)
			}
		}
		owned := ownedContexts(descriptor, principal, now)
		var refs []*analyzerpb.AthenaCachedContext
		for _, id := range ids {
			ctxRef, ok := owned[id]
			if !ok {
				return access{}, denyError(nativeContextUnavailable)
			}
			refs = append(refs, ctxRef)
		}
		for _, o := range descriptor.GetObservations() {
			if o.GetKind() != queryExecution {
				observed(o)
			} else if _, ok := owned[o.GetId()]; !ok || !slices.Contains(ids, o.GetId()) {
				return access{}, denyError(nativeContextUnavailable)
			}
		}
		out.athena.Action = forward
		if response {
			out.athena.Action = analyzerpb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
			for _, ref := range refs {
				out.athena.Contexts = append(out.athena.Contexts, &analyzerpb.AthenaContextRef{ResourceId: ref.GetResourceId(), ContextId: ref.GetContextId()})
			}
		}
	case athenaHistory:
		owned := ownedContexts(descriptor, principal, now)
		for _, o := range descriptor.GetObservations() {
			if o.GetKind() != queryExecution {
				observed(o)
			} else if ref, ok := owned[o.GetId()]; ok {
				out.athena.Contexts = append(out.athena.Contexts, &analyzerpb.AthenaContextRef{ResourceId: ref.GetResourceId(), ContextId: ref.GetContextId()})
			}
		}
		out.athena.Action = forward
		if response {
			out.athena.Action = analyzerpb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
		}
	}
	return out, nil
}

// ownedContexts is the descriptor's cached contexts that are the principal's, bound to this target, and unexpired.
func ownedContexts(d *analyzerpb.AthenaNativeDescriptor, principal string, now time.Time) map[string]*analyzerpb.AthenaCachedContext {
	out := map[string]*analyzerpb.AthenaCachedContext{}
	binding := d.GetTarget().GetTargetBinding()
	for _, c := range d.GetCachedContexts() {
		if c.GetOwner() == principal && bytes.Equal(c.GetTargetBinding(), binding) && c.GetExpiresAt().AsTime().After(now) {
			out[c.GetResourceId()] = c
		}
	}
	return out
}

// athenaName is a literal Athena name (an API field, not SQL text) in the analyzer's canonical spelling.
func athenaName(raw string) (name string, err error) {
	defer func() {
		if recover() != nil {
			name, err = "", errMalformed
		}
	}()
	s, err := engines.Athena.NewSession(nil)
	if err != nil {
		return "", errMalformed
	}
	return s.CatalogColumnNames([]*analyzerpb.Column{{Catalog: raw}})[0].Catalog().String(), nil
}

func blank(s string) bool { return strings.TrimFunc(s, unicode.IsSpace) == "" }

func validDescriptor(d *analyzerpb.AthenaNativeDescriptor) error {
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
	request := d.GetPhase() == analyzerpb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_REQUEST
	if !request && d.GetPhase() != analyzerpb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_RESPONSE {
		return errMalformed
	}
	if d.GetTarget() == nil || len(d.GetTarget().GetTargetBinding()) != athenaBindingBytes {
		return errMalformed
	}
	if request && len(d.GetObservations()) > 0 {
		return errMalformed
	}
	for _, o := range d.GetObservations() {
		if o.GetSource() != analyzerpb.AthenaObservationSource_ATHENA_OBSERVATION_SOURCE_AWS_RESPONSE ||
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

func wellFormed(c *analyzerpb.AthenaCachedContext) bool {
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

func validateSubmissionScope(target *analyzerpb.AthenaTarget, b body) error {
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
	exact := func(s string) (string, error) { return s, nil }
	inScope := func(m map[string]any, field, configured string, canonical func(string) (string, error)) (bool, error) {
		v, ok := m[field]
		if !ok {
			return true, nil
		}
		s, isText := v.(string)
		if !isText {
			return false, errMalformed
		}
		if blank(configured) {
			return false, nil
		}
		requested, err := canonical(s)
		if err != nil {
			return false, err
		}
		want, err := canonical(configured)
		return requested == want, err
	}
	// Workgroup names are not identifiers; catalog and database names compare in their canonical spelling.
	for _, check := range []struct {
		m                 map[string]any
		field, configured string
		canonical         func(string) (string, error)
	}{
		{b, "WorkGroup", target.GetDefaultWorkgroup(), exact},
		{execCtx, "Catalog", target.GetDefaultCatalog(), athenaName},
		{execCtx, "Database", target.GetDefaultDatabase(), athenaName},
	} {
		ok, err := inScope(check.m, check.field, check.configured, check.canonical)
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
		return []nativeResource{{kind: kind, id: v}}, nil
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
			out = append(out, nativeResource{kind: kind, id: v})
		}
		return out, nil
	}
}

func field(name string) func(body) (string, error) {
	return func(b body) (string, error) { return b.str(name) }
}

// joined is the named fields joined with "/".
func joined(names ...string) func(body) (string, error) {
	return path(func(s string) (string, error) { return s, nil }, names)
}

// catalogPath is joined with each part an Athena name in its canonical spelling.
func catalogPath(names ...string) func(body) (string, error) { return path(athenaName, names) }

func path(spell func(string) (string, error), names []string) func(body) (string, error) {
	return func(b body) (string, error) {
		parts := make([]string, 0, len(names))
		for _, n := range names {
			v, err := b.str(n)
			if err != nil {
				return "", err
			}
			if v, err = spell(v); err != nil {
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
	"GetDataCatalog":                     {athenaMetadata, one("data-catalog", catalogPath("Name"))},
	"ListDatabases":                      {athenaMetadata, one("data-catalog", catalogPath("CatalogName"))},
	"GetDatabase":                        {athenaMetadata, one("database", catalogPath("CatalogName", "DatabaseName"))},
	"ListTableMetadata":                  {athenaMetadata, one("database", catalogPath("CatalogName", "DatabaseName"))},
	"GetTableMetadata":                   {athenaMetadata, one("table", catalogPath("CatalogName", "DatabaseName", "TableName"))},
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
	"CreateDataCatalog":                  {athenaNative, one("data-catalog", catalogPath("Name"))},
	"UpdateDataCatalog":                  {athenaNative, one("data-catalog", catalogPath("Name"))},
	"DeleteDataCatalog":                  {athenaNative, one("data-catalog", catalogPath("Name"))},
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
