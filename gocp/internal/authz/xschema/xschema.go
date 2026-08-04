// Package xschema is the ONE place in the control plane that imports cedar-go's x/exp subtree.
//
// To be precise about what "x/exp" means here, because two different things share the name:
// github.com/cedar-policy/cedar-go/x/exp/... is a directory INSIDE the cedar-go module, exempt from
// that module's semantic-versioning promise. It is unrelated to the golang.org/x/exp MODULE (which
// cedar-go v1.8.0 also requires, for its internal mapset — verified in its go.mod). Nothing in this
// port imports golang.org/x/exp.
//
// D5 requires the x/exp surface to be firewalled behind a single wrapper so an upstream break has a
// single blast radius. cedar-go's own README is explicit (v1.8.0 README.md:140): "code in this
// directory is not subject to the semantic versioning constraints of the rest of the module and
// breaking changes may be made at any time." 98-cedar-spike-report.md § S7 measured the actual
// stability — identical verdicts and byte-identical error messages across v1.6.0, v1.6.1, v1.6.2,
// v1.7.0 and v1.8.0 — and concluded: pin exactly, firewall, gate in CI, no Rust sidecar.
//
// The five x/exp identifiers the spike proved sufficient are all named here and nowhere else:
// xast.Policy · xresolved.Schema · xschema.Schema · xvalidate.New · xvalidate.WithStrict.
// authz/firewall_test.go asserts that no other file in the authz tree imports x/exp.
//
// NOTE the one thing the firewall does NOT buy, recorded verbatim by the spike so nobody
// over-reads it: the DECISION path reaches github.com/cedar-policy/cedar-go/x/exp/ast transitively
// through cedar.Authorize, so "only validation touches x/exp" is not quite right. The API surface
// this package names is stable; the internal dependency is not. That is why the CI fingerprint gate
// (56af35d135a2649d975c9674) must cover decisions and not only validation.
//
// # The two-step schema API (spike § "Surprises vs 02-authz.md §9", item 1)
//
// 02-authz.md §9 maps Schema.parse(Cedar, text) to "the x/exp/schema text parser" in one step.
// Measured: UnmarshalCedar yields a *schema.Schema (an AST wrapper) and .Resolve() yields the
// *resolved.Schema that validate.New requires. So the Kotlin's augmentedSchemas cache
// (CedarEngine.kt:72) must hold the RESOLVED form in Go, or the non-trivial resolve cost is paid on
// every validate call. Schema below is that resolved form.
package xschema

import (
	"errors"
	"fmt"

	cedar "github.com/cedar-policy/cedar-go"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	xschema "github.com/cedar-policy/cedar-go/x/exp/schema"
	xresolved "github.com/cedar-policy/cedar-go/x/exp/schema/resolved"
	xvalidate "github.com/cedar-policy/cedar-go/x/exp/schema/validate"
)

// Schema is a parsed AND resolved Cedar schema — the analogue of cedar-java's
// com.cedarpolicy.model.schema.Schema, which is what CedarEngine.kt:67 and :89 hold.
type Schema struct {
	resolved *xresolved.Schema
}

// Parse ports Schema.parse(Schema.JsonOrCedar.Cedar, text): the HUMAN-READABLE .cedarschema text
// syntax, not JSON. filename only feeds position data in error messages.
//
// Errors are returned, never panicked: CedarEngine.kt:119-125 calls schemaFor INSIDE the guarded
// region precisely so a malformed generated declaration surfaces as a validation error rather than
// breaking validate()'s "never throws for policy-shaped input" contract. The spike confirmed cedar-go
// returns a plain error here (a pathological tag name produces "unterminated string literal"), never
// a panic, so the Kotlin `catch (e: Exception)` arm maps 1:1 to an error check.
func Parse(text, filename string) (*Schema, error) {
	var s xschema.Schema
	s.SetFilename(filename)
	if err := s.UnmarshalCedar([]byte(text)); err != nil {
		return nil, fmt.Errorf("schema parse: %w", err)
	}
	rs, err := s.Resolve()
	if err != nil {
		return nil, fmt.Errorf("schema resolve: %w", err)
	}
	return &Schema{resolved: rs}, nil
}

// ValidatePolicy ports engine.validate(ValidationRequest(schema, PolicySet(setOf(policy)))).
//
// 02-authz.md §9 flags "validate.Validator.Policy is per-policy only" as a risk; the spike closed
// that row. CedarEngine.kt:120 already validates exactly one candidate (PolicySet(setOf(policy)))
// and the startup loop already iterates source-by-source, so the per-policy API is an EXACT match.
//
// WithStrict mirrors cedar-java's default. It is also the only mode Cedar 4.3.x's WASM binding
// exposes, and the spike measured that strict and permissive agree on the entire shipped corpus
// (10/10 rejects reject in both, 112/112 accepts accept in both) — the corpus does not depend on the
// mode at all.
//
// The returned strings are the flattened errors.Join tree, one message per element, matching the
// Kotlin's List<String> of validationError messages.
func (s *Schema) ValidatePolicy(policyID string, p *cedar.Policy) []string {
	v := xvalidate.New(s.resolved, xvalidate.WithStrict())
	if err := v.Policy(policyID, (*xast.Policy)(p.AST())); err != nil {
		return collectErrors(err)
	}
	return nil
}

// collectErrors flattens an errors.Join tree into one string per leaf. cedar-go returns a joined
// error when a single policy trips several validation rules, and cedar-java surfaces those as
// separate ValidationError entries, so flattening is what keeps the list shapes comparable.
func collectErrors(err error) []string {
	if err == nil {
		return nil
	}
	if ue, ok := err.(interface{ Unwrap() []error }); ok {
		var out []string
		for _, e := range ue.Unwrap() {
			out = append(out, collectErrors(e)...)
		}
		return out
	}
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		return collectErrors(joined.(error))
	}
	return []string{err.Error()}
}
