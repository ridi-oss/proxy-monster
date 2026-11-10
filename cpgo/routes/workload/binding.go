package workload

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

const (
	PurposeWire = "wire"
	PurposeMCP  = "mcp"

	defaultBindingTTL = 900
	minBindingTTL     = 60
	maxBindingTTL     = 3600
	maxConditions     = 20
	maxConditionKey   = 200
	maxSubject        = 1000
)

var (
	bindingName      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	servicePrincipal = regexp.MustCompile(`^svc:[a-z0-9][a-z0-9._-]{0,62}$`)
	purposes         = []string{PurposeWire, PurposeMCP}
)

type Binding struct {
	ID          int64               `json:"id"`
	Name        string              `json:"name"`
	Description *string             `json:"description,omitempty"`
	Issuer      string              `json:"issuer"`
	Subject     string              `json:"subject"`
	Conditions  map[string][]string `json:"conditions"`
	Principal   string              `json:"principal"`
	Purposes    []string            `json:"purposes"`
	MCPScopes   []string            `json:"mcpScopes"`
	TTLSeconds  int32               `json:"ttlSeconds"`
	Enabled     bool                `json:"enabled"`
	CreatedAt   string              `json:"createdAt"`
	UpdatedAt   string              `json:"updatedAt"`
}

func (b Binding) ClientID() string { return "workload:" + b.Name }

func toBinding(r db.WorkloadBindingRow) Binding {
	conditions := map[string][]string{}
	_ = json.Unmarshal(r.Conditions, &conditions)
	return Binding{ID: r.ID, Name: r.Name, Description: r.Description, Issuer: r.Issuer, Subject: r.Subject, Conditions: conditions,
		Principal: r.Principal, Purposes: nonNil(r.Purposes), MCPScopes: nonNil(r.McpScopes), TTLSeconds: r.TtlSeconds, Enabled: r.Enabled,
		CreatedAt: api.JavaInstant(r.CreatedAt), UpdatedAt: api.JavaInstant(r.UpdatedAt)}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (b Binding) matches(sub string, claims Claims) bool {
	if !matchPattern(b.Subject, sub) {
		return false
	}
	for key, allowed := range b.Conditions {
		values, ok := claims[key]
		if !ok || !slices.ContainsFunc(values, func(v string) bool {
			return slices.ContainsFunc(allowed, func(p string) bool { return matchPattern(p, v) })
		}) {
			return false
		}
	}
	return true
}

func matchPattern(pattern, value string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(value, prefix)
	}
	return pattern == value
}

func (b Binding) allows(purpose string) bool { return slices.Contains(b.Purposes, purpose) }

func (b Binding) ttl(now time.Time, cap time.Duration) time.Time {
	ttl := time.Duration(b.TTLSeconds) * time.Second
	if cap > 0 && cap < ttl {
		ttl = cap
	}
	return now.Add(ttl)
}

type bindingInput struct {
	Name        *string                    `json:"name"`
	Description *string                    `json:"description"`
	Issuer      *string                    `json:"issuer"`
	Subject     *string                    `json:"subject"`
	Conditions  map[string]json.RawMessage `json:"conditions"`
	Principal   *string                    `json:"principal"`
	Purposes    []string                   `json:"purposes"`
	MCPScopes   []string                   `json:"mcpScopes"`
	TTLSeconds  *int32                     `json:"ttlSeconds"`
	Enabled     *bool                      `json:"enabled"`
}

type validBinding struct {
	name, issuer, subject, principal string
	description                      *string
	conditions                       map[string][]string
	purposes, mcpScopes              []string
	ttl                              int32
	enabled                          bool
}

func (in bindingInput) validate(issuers []Issuer) (validBinding, error) {
	var out validBinding
	for _, f := range []struct {
		name  string
		value *string
	}{{"name", in.Name}, {"issuer", in.Issuer}, {"subject", in.Subject}} {
		if f.value == nil {
			return out, api.CodeFieldRequired.Err("fields", f.name)
		}
		if err := api.Required(f.name, *f.value); err != nil {
			return out, err
		}
	}
	out.name, out.issuer, out.subject = strings.TrimSpace(*in.Name), strings.TrimSpace(*in.Issuer), strings.TrimSpace(*in.Subject)
	if !bindingName.MatchString(out.name) {
		return out, api.CodeInvalidValue.Err("field", "name")
	}
	if !slices.ContainsFunc(issuers, func(i Issuer) bool { return i.Name == out.issuer }) {
		return out, api.CodeInvalidValue.Err("field", "issuer")
	}
	if len(out.subject) > maxSubject || out.subject == "*" {
		return out, api.CodeInvalidValue.Err("field", "subject")
	}
	out.principal = "svc:" + out.name
	if in.Principal != nil && strings.TrimSpace(*in.Principal) != "" {
		out.principal = strings.TrimSpace(*in.Principal)
	}
	if !servicePrincipal.MatchString(out.principal) {
		return out, api.CodeInvalidValue.Err("field", "principal")
	}
	if in.Description != nil && strings.TrimSpace(*in.Description) != "" {
		d := strings.TrimSpace(*in.Description)
		out.description = &d
	}
	conditions, err := parseConditions(in.Conditions)
	if err != nil {
		return out, err
	}
	out.conditions = conditions
	if len(in.Purposes) == 0 {
		return out, api.CodeFieldRequired.Err("fields", "purposes")
	}
	for _, p := range in.Purposes {
		if !slices.Contains(purposes, p) {
			return out, api.CodeInvalidValue.Err("field", "purposes")
		}
	}
	out.purposes = sortedUnique(in.Purposes)
	for _, s := range in.MCPScopes {
		if !slices.Contains(session.MCPScopes(), s) {
			return out, api.CodeInvalidValue.Err("field", "mcpScopes")
		}
	}
	out.mcpScopes = sortedUnique(in.MCPScopes)
	if slices.Contains(out.purposes, PurposeMCP) != (len(out.mcpScopes) > 0) {
		return out, api.CodeInvalidValue.Err("field", "mcpScopes")
	}
	out.ttl = defaultBindingTTL
	if in.TTLSeconds != nil {
		out.ttl = *in.TTLSeconds
	}
	if out.ttl < minBindingTTL || out.ttl > maxBindingTTL {
		return out, api.CodeInvalidValue.Err("field", "ttlSeconds")
	}
	out.enabled = in.Enabled == nil || *in.Enabled
	return out, nil
}

func parseConditions(raw map[string]json.RawMessage) (map[string][]string, error) {
	out := map[string][]string{}
	if len(raw) > maxConditions {
		return nil, api.CodeInvalidValue.Err("field", "conditions")
	}
	for key, v := range raw {
		key = strings.TrimSpace(key)
		if key == "" || len(key) > maxConditionKey {
			return nil, api.CodeInvalidValue.Err("field", "conditions")
		}
		var one string
		var many []string
		switch {
		case json.Unmarshal(v, &one) == nil:
			many = []string{one}
		case json.Unmarshal(v, &many) == nil:
		default:
			return nil, api.CodeInvalidValue.Err("field", "conditions")
		}
		if len(many) == 0 || slices.ContainsFunc(many, func(s string) bool { return s == "" || s == "*" || len(s) > claimValue }) {
			return nil, api.CodeInvalidValue.Err("field", "conditions")
		}
		out[key] = sortedUnique(many)
	}
	return out, nil
}

func sortedUnique(s []string) []string {
	out := append([]string{}, s...)
	slices.Sort(out)
	return slices.Compact(out)
}
