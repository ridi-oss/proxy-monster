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

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/cpgo/grpcsvc/pb"
)

const (
	contextVersion   = 1
	bindingBytes     = 32
	maxExpectedWidth = 1 << 20
)

// denyError ends reading an HTTP-API call with a stable deny code.
type denyError string

func (d denyError) Error() string { return string(d) }

var errMalformed = denyError(nativeInvalidDescriptor)

type callCategory int

const (
	sqlSubmission callCategory = iota
	metadataCall
	executionCall
	historyCall
	invokeCall
)

type httpDbOperation struct {
	category  callCategory
	resources func(body) ([]nativeResource, error)
}

// httpDbEngine is how the control plane reads one HTTP-API engine's calls.
type httpDbEngine struct {
	service string
	// contextKind is the resource kind cached contexts bind to, such as an Athena query execution.
	contextKind string
	operations  map[string]httpDbOperation
	// validCall checks the engine's method, path, and target arm.
	validCall       func(*pb.HttpDbRequest) error
	submissionScope func(*pb.HttpDbRequest, body) error
}

// access reads one call from the proxy's descriptor. A SQL submission goes through SQL admission, status and
// result reads bind to the principal's own cached contexts, listings keep only owned resources, and everything
// else is native.invoke on its resource. An unknown operation is denied.
func (e httpDbEngine) access(r *pb.RequestAuthorization, ds requestDatasource, principal string, now time.Time) access {
	a, err := e.read(r.GetHttpDb(), ds.name, principal, now)
	var d denyError
	if errors.As(err, &d) {
		return access{deny: string(d)}
	}
	if err != nil {
		return access{deny: nativeInvalidDescriptor}
	}
	return a
}

func (e httpDbEngine) read(descriptor *pb.HttpDbRequest, datasource, principal string, now time.Time) (access, error) {
	if descriptor == nil {
		return access{}, denyError(nativeNotAuthorized)
	}
	if err := e.validDescriptor(descriptor); err != nil {
		return access{}, err
	}
	op, ok := e.operations[descriptor.GetOperation()]
	if !ok {
		return access{}, denyError(nativeNotAuthorized)
	}
	b, err := decodeBody(descriptor.GetBody())
	if err != nil {
		return access{}, err
	}
	out := access{native: true, operation: e.service + ":" + descriptor.GetOperation(), instructions: &analyzerpb.HttpDbInstructions{}}
	observed := func(o *pb.HttpDbObservation) {
		out.resources = append(out.resources, nativeResource{o.GetKind(), o.GetId(), o.Owner})
	}
	response := descriptor.GetPhase() == analyzerpb.HttpDbAuthorizationPhase_HTTP_DB_AUTHORIZATION_PHASE_RESPONSE
	forward := analyzerpb.HttpDbInstruction_HTTP_DB_INSTRUCTION_FORWARD_REQUEST
	switch op.category {
	case sqlSubmission:
		if response {
			return access{}, denyError(nativeNotAuthorized)
		}
		if err := e.submissionScope(descriptor, b); err != nil {
			return access{}, err
		}
		out.instructions.Action = analyzerpb.HttpDbInstruction_HTTP_DB_INSTRUCTION_REQUIRE_SQL_ADMISSION
	case metadataCall, invokeCall:
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
		out.instructions.Action = forward
		if response {
			out.instructions.Action = analyzerpb.HttpDbInstruction_HTTP_DB_INSTRUCTION_RELEASE_METADATA
		}
	case executionCall:
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
		var refs []*analyzerpb.HttpDbCachedContext
		for _, id := range ids {
			ctxRef, ok := owned[id]
			if !ok {
				return access{}, denyError(nativeContextUnavailable)
			}
			refs = append(refs, ctxRef)
		}
		for _, o := range descriptor.GetObservations() {
			if o.GetKind() != e.contextKind {
				observed(o)
			} else if _, ok := owned[o.GetId()]; !ok || !slices.Contains(ids, o.GetId()) {
				return access{}, denyError(nativeContextUnavailable)
			}
		}
		out.instructions.Action = forward
		if response {
			out.instructions.Action = analyzerpb.HttpDbInstruction_HTTP_DB_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
			for _, ref := range refs {
				out.instructions.Contexts = append(out.instructions.Contexts, &analyzerpb.HttpDbContextRef{ResourceId: ref.GetResourceId(), ContextId: ref.GetContextId()})
			}
		}
	case historyCall:
		owned := ownedContexts(descriptor, principal, now)
		for _, o := range descriptor.GetObservations() {
			if o.GetKind() != e.contextKind {
				observed(o)
			} else if ref, ok := owned[o.GetId()]; ok {
				out.instructions.Contexts = append(out.instructions.Contexts, &analyzerpb.HttpDbContextRef{ResourceId: ref.GetResourceId(), ContextId: ref.GetContextId()})
			}
		}
		out.instructions.Action = forward
		if response {
			out.instructions.Action = analyzerpb.HttpDbInstruction_HTTP_DB_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
		}
	}
	return out, nil
}

// ownedContexts is the descriptor's cached contexts that are the principal's, bound to this target, and unexpired.
func ownedContexts(d *pb.HttpDbRequest, principal string, now time.Time) map[string]*analyzerpb.HttpDbCachedContext {
	out := map[string]*analyzerpb.HttpDbCachedContext{}
	for _, c := range d.GetCachedContexts() {
		if c.GetOwner() == principal && bytes.Equal(c.GetTargetBinding(), d.GetTargetBinding()) && c.GetExpiresAt().AsTime().After(now) {
			out[c.GetResourceId()] = c
		}
	}
	return out
}

func blank(s string) bool { return strings.TrimFunc(s, unicode.IsSpace) == "" }

func (e httpDbEngine) validDescriptor(d *pb.HttpDbRequest) error {
	if d.GetService() != e.service || blank(d.GetOperation()) {
		return denyError(nativeNotAuthorized)
	}
	if err := e.validCall(d); err != nil {
		return err
	}
	for _, h := range d.GetFunctionalHeaders() {
		if blank(h.GetName()) {
			return errMalformed
		}
	}
	request := d.GetPhase() == analyzerpb.HttpDbAuthorizationPhase_HTTP_DB_AUTHORIZATION_PHASE_REQUEST
	if !request && d.GetPhase() != analyzerpb.HttpDbAuthorizationPhase_HTTP_DB_AUTHORIZATION_PHASE_RESPONSE {
		return errMalformed
	}
	if len(d.GetTargetBinding()) != bindingBytes {
		return errMalformed
	}
	if request && len(d.GetObservations()) > 0 {
		return errMalformed
	}
	for _, o := range d.GetObservations() {
		if o.GetSource() != pb.HttpDbObservationSource_HTTP_DB_OBSERVATION_SOURCE_UPSTREAM_RESPONSE ||
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

func wellFormed(c *analyzerpb.HttpDbCachedContext) bool {
	if c.GetVersion() != contextVersion || blank(c.GetContextId()) || blank(c.GetResourceId()) || blank(c.GetOwner()) {
		return false
	}
	ts := c.GetExpiresAt()
	if len(c.GetTargetBinding()) != bindingBytes || ts == nil || ts.GetSeconds() < -62135596800 || ts.GetSeconds() > 253402300799 ||
		ts.GetNanos() < 0 || ts.GetNanos() > 999_999_999 {
		return false
	}
	if c.ExpectedWidth != nil && *c.ExpectedWidth > maxExpectedWidth {
		return false
	}
	if n := len(c.GetMetadataDigest()); n != 0 && n != bindingBytes {
		return false
	}
	if n := len(c.GetRequestBinding()); n != 0 && n != bindingBytes {
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

// body is a decoded request body: a JSON object, numbers kept as json.Number.
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
