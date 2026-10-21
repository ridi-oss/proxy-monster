package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// UserAttribute is an id_token claim copied onto the Cedar User as an optional attribute of the same name
// (PM_OIDC_USER_ATTRIBUTES=manager:User,department:String). A User attribute holds a principal name, so
// resource.requester.manager == principal compares entities.
type UserAttribute struct {
	Name string
	Type string
}

var (
	attributeTypes = []string{"String", "Long", "Bool", "Set<String>", "User"}
	attributeName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	userDecl       = "entity User in [Role, Group];"
)

// ParseUserAttributes reads "name:Type,…". A malformed entry is an error, so boot fails rather than
// silently dropping an attribute a policy reads.
func ParseUserAttributes(env string) ([]UserAttribute, error) {
	var out []UserAttribute
	seen, dup := map[string]bool{}, []string{}
	for _, entry := range strings.Split(env, ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		name, typ, _ := strings.Cut(entry, ":")
		name, typ = strings.TrimSpace(name), strings.TrimSpace(typ)
		if !attributeName.MatchString(name) || !slices.Contains(attributeTypes, typ) {
			return nil, fmt.Errorf("PM_OIDC_USER_ATTRIBUTES entry must be <name>:<%s>, got '%s'", strings.Join(attributeTypes, "|"), entry)
		}
		if seen[name] && !slices.Contains(dup, name) {
			dup = append(dup, name)
		}
		seen[name] = true
		out = append(out, UserAttribute{Name: name, Type: typ})
	}
	if len(dup) > 0 {
		return nil, fmt.Errorf("PM_OIDC_USER_ATTRIBUTES declares %s twice", strings.Join(dup, ", "))
	}
	return out, nil
}

// Schema is the authorization schema with the declared user attributes on User.
type Schema struct {
	text       string
	attributes []UserAttribute
	validators sync.Map // tag-name key → *validate.Validator
}

// NewSchema declares attrs on the bundled schema's User type.
func NewSchema(attrs []UserAttribute) (*Schema, error) {
	if !strings.Contains(bundledSchema, userDecl) {
		return nil, fmt.Errorf("authz: schema.cedarschema no longer declares `%s`", userDecl)
	}
	decl := userDecl
	if len(attrs) > 0 {
		fields := make([]string, len(attrs))
		for i, a := range attrs {
			fields[i] = a.Name + "?: " + a.Type
		}
		decl = "entity User in [Role, Group] = { " + strings.Join(fields, ", ") + " };"
	}
	text := strings.Replace(bundledSchema, userDecl, decl, 1)
	var s schema.Schema
	if err := s.UnmarshalCedar([]byte(text)); err != nil {
		return nil, fmt.Errorf("PM_OIDC_USER_ATTRIBUTES does not form a valid Cedar schema: %w", err)
	}
	if _, err := s.Resolve(); err != nil {
		return nil, fmt.Errorf("PM_OIDC_USER_ATTRIBUTES does not form a valid Cedar schema: %w", err)
	}
	return &Schema{text: text, attributes: attrs}, nil
}

// Attributes are the attributes login stores and Cedar sees on User.
func (s *Schema) Attributes() []UserAttribute { return s.attributes }

// ClaimAttributes is the declared attributes the id_token claims carry, as stored on app_user.attributes:
// a claim that is absent or not of its declared type is left out.
func (s *Schema) ClaimAttributes(claims map[string]any) []byte {
	out := map[string]any{}
	for _, a := range s.attributes {
		if v, ok := a.fromClaim(claims[a.Name]); ok {
			out[a.Name] = v
		}
	}
	b, _ := json.Marshal(out)
	return b
}

func (a UserAttribute) fromClaim(claim any) (any, bool) {
	switch a.Type {
	case "String", "User":
		s, ok := claim.(string)
		return s, ok && strings.TrimSpace(s) != ""
	case "Long":
		// Claims keep each number's literal, so 3.0 is no Long, as in Kotlin.
		n, ok := claim.(json.Number)
		if !ok {
			return nil, false
		}
		i, err := n.Int64()
		return i, err == nil
	case "Bool":
		b, ok := claim.(bool)
		return b, ok
	case "Set<String>":
		list, ok := claim.([]any)
		if !ok {
			return nil, false
		}
		out := make([]string, 0, len(list))
		for _, v := range list {
			s, ok := v.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// cedarValue is a stored value as its declared Cedar type; false when an earlier declaration stored another type.
func (a UserAttribute) cedarValue(stored json.RawMessage) (types.Value, bool) {
	var v any
	dec := json.NewDecoder(strings.NewReader(string(stored)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	switch a.Type {
	case "String":
		s, ok := v.(string)
		return types.String(s), ok
	case "User":
		s, ok := v.(string)
		return uid("User", s), ok
	case "Long":
		n, ok := v.(json.Number)
		if !ok {
			return nil, false
		}
		i, err := n.Int64()
		return types.Long(i), err == nil
	case "Bool":
		b, ok := v.(bool)
		return types.Boolean(b), ok
	case "Set<String>":
		list, ok := v.([]any)
		if !ok {
			return nil, false
		}
		vals := make([]types.Value, 0, len(list))
		for _, e := range list {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			vals = append(vals, types.String(s))
		}
		return types.NewSet(vals...), true
	}
	return nil, false
}

// userRecord is the declared attributes a user's stored JSON carries, typed for Cedar.
func (s *Schema) userRecord(stored []byte) (types.Record, error) {
	attrs := s.attributes
	if len(attrs) == 0 || len(stored) == 0 {
		return types.NewRecord(nil), nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(stored, &raw); err != nil {
		return types.NewRecord(nil), errors.Join(errors.New("authz: app_user.attributes"), err)
	}
	m := types.RecordMap{}
	for _, a := range attrs {
		if r, ok := raw[a.Name]; ok {
			if v, ok := a.cedarValue(r); ok {
				m[types.String(a.Name)] = v
			}
		}
	}
	return types.NewRecord(m), nil
}
