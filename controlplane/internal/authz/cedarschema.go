package authz

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

	cedar "github.com/cedar-policy/cedar-go"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz/xschema"
)

// contextTagActionRe ports CedarEngine.kt:24 — Regex("""Action::"context\.tag::([^"]+)"""").
var contextTagActionRe = regexp.MustCompile(`Action::"context\.tag::([^"]+)"`)

// contextTagsConsumedRe ports CedarEngine.kt:35 —
// Regex("""context\.tags\.contains\(\s*"([^"]+)"\s*\)""").
var contextTagsConsumedRe = regexp.MustCompile(`context\.tags\.contains\(\s*"([^"]+)"\s*\)`)

// ExtractContextTagNames returns the tag names a Cedar policy targets via a `context.tag::<name>`
// action — CedarEngine.kt:32-33.
//
// The tag vocabulary is DERIVED from policy source by regex, not predefined (docs/authz-context.md).
// An action EID is always a literal Action::"context.tag::<name>", so scanning the source text is
// exact and cheap. Used both to augment the validation schema (a tag rule must have its action
// declared) and to build the pass-1 vocabulary.
//
// Kotlin returns a Set<String> built with mutableSetOf() — a LinkedHashSet, so first-appearance order.
// Reproduced here as a deduped slice in first-appearance order; every consumer either sorts it
// (SchemaFor) or uses it as a membership set (the vocabulary), so the order is not observable.
//
// The `[^"]+` capture cannot span a raw quote. That is what makes a pathological tag name — a trailing
// backslash from a \" escape — capture as `a\` and produce a MALFORMED generated declaration, which
// Validate must surface as an error rather than a panic. See CedarSchema.Validate.
func ExtractContextTagNames(cedarSrc string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range contextTagActionRe.FindAllStringSubmatch(cedarSrc, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// ContextTagLint is the dangling-tag lint (docs/authz-context.md) — CedarEngine.kt:44-57.
//
// Compares PRODUCED tags (the context.tag::<name> actions the enabled tag rules target) against
// CONSUMED tags (the context.tags.contains("<name>") literals in the real policies) and reports each
// mismatch. Both halves sorted, consumers-without-producers first.
//
// PURELY DIAGNOSTIC — dangling tags are fail-closed-safe, so this WARNS and never blocks a policy write
// or boot. Surfaced in /health diagnostics.
func ContextTagLint(enabledSources []PolicySource) []string {
	produced := map[string]bool{}
	consumed := map[string]bool{}
	for _, s := range enabledSources {
		for _, n := range ExtractContextTagNames(s.Src) {
			produced[n] = true
		}
		for _, m := range contextTagsConsumedRe.FindAllStringSubmatch(s.Src, -1) {
			consumed[m[1]] = true
		}
	}

	out := []string{}
	for _, t := range sortedDifference(consumed, produced) {
		out = append(out, "context tag \""+t+"\" is consumed by a policy but no tag rule produces it (grant can never apply)")
	}
	for _, t := range sortedDifference(produced, consumed) {
		out = append(out, "context tag \""+t+"\" is produced by a tag rule but no policy consumes it (dead tag rule)")
	}
	return out
}

func sortedDifference(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// CedarSchema is the port of CedarEngine.kt:59-135's `object CedarSchema`: the bundled schema plus the
// STATELESS half of Cedar evaluation — parsing the schema once and validating a single candidate policy
// against it. Independent of the live enabled policy set on purpose: CedarPolicyStore uses it to reject
// invalid Cedar at WRITE time (before a bad row could ever become enabled), and CedarEngine uses the
// same logic both to fail fast at construction and to back CedarEngine.Validate.
//
// D5: the cache holds the RESOLVED schema, not the AST — the spike measured that cedar-go's schema API
// is two-step and the resolve cost is non-trivial, so caching the unresolved form would pay it on every
// Validate call.
type CedarSchema struct {
	// Text is the bundled schema source. Exported because /api/policies/schema serves it verbatim to
	// the editor for schema-aware linting (the schema is the authz model, not secret).
	Text string

	base *xschema.Schema

	// mu guards augmented, the validation-only cache of schemas augmented with derived
	// context.tag::<name> action declarations, keyed by the tag-name set. Cedar EVALUATION is
	// schema-free (Authorize takes no schema), so this never touches the authorization path.
	// Kotlin uses a ConcurrentHashMap (CedarEngine.kt:72).
	mu        sync.Mutex
	augmented map[string]*xschema.Schema
}

// DefaultSchema is the process-wide CedarSchema over the embedded SchemaSource — the port of the
// Kotlin `object` singleton, which parses at class-init and error(...)s if the resource is missing.
//
// Panicking here reproduces the JVM's ExceptionInInitializerError: a schema that does not resolve means
// nothing downstream can decide anything, so failing at first touch is the faithful and the safe
// behaviour. D10 keeps this runtime check even though compile-time embedding already makes a MISSING
// file a build error — embedding proves the bytes exist, not that they parse.
var DefaultSchema = mustCedarSchema(SchemaSource)

func mustCedarSchema(text string) *CedarSchema {
	s, err := NewCedarSchema(text)
	if err != nil {
		panic("authz: bundled schema.cedarschema failed to parse: " + err.Error())
	}
	return s
}

// NewCedarSchema parses and resolves the schema text. Ports CedarEngine.kt:67's
// Schema.parse(JsonOrCedar.Cedar, text) — the HUMAN-READABLE Cedar schema syntax, not JSON.
func NewCedarSchema(text string) (*CedarSchema, error) {
	base, err := xschema.Parse(text, "schema.cedarschema")
	if err != nil {
		return nil, err
	}
	return &CedarSchema{Text: text, base: base, augmented: map[string]*xschema.Schema{}}, nil
}

// generatedTagActionDecl is the BYTE-EXACT generated declaration from CedarEngine.kt:86-87.
//
// Two deliberate properties, both load-bearing:
//
//   - It OMITS `tags`. 🔒 INV-A2-12 half 1: a tag rule reading context.tags then fails validation and
//     never loads — no tag-on-tag, no recursion. TagResolutionTest case 6 pins it. The spike warns that
//     case 6 alone does NOT discriminate a correct narrow context from a lazy one that reuses
//     RequestContext, because cedar-go strict rejects the unguarded read either way (by a different
//     rule). That is why schema_test.go asserts the generated context SHAPE directly (W4).
//   - It declares `tailscale_caps?: Set<String>`, which appears nowhere in AuthzContext. Carry it
//     verbatim. docs/authz-context.md:255 documents the inverse shape (has network_zones, lacks
//     tailscale_caps); the CODE is authoritative — port from CedarEngine.kt:87, not from the doc.
//     Vestigial-but-live: nothing injects it, but removing it would change what validates.
func generatedTagActionDecl(name string) string {
	return "action \"context.tag::" + name + "\" appliesTo { principal: [User, Role], resource: [Datasource], " +
		"context: { channel?: String, requester_ip?: ipaddr, tailscale_caps?: Set<String> } };"
}

// AugmentedText is the exact concatenation CedarEngine.kt:85-89 performs: sorted tag names, one
// declaration per line, joined onto the base text with a single "\n".
//
// W4: this stays TEXT concatenation and does NOT become a programmatic AST merge. The spike proved the
// AST path works and is reflect.DeepEqual-identical — and rejected it under PORT POLICY, because the
// AST path REMOVES the malformed-declaration rejection, which is observable Kotlin behaviour
// (CedarEngine.kt:124 emits "invalid context.tag action name: …" and POST /api/policies 400s).
func (c *CedarSchema) AugmentedText(tagNames []string) string {
	sorted := append([]string(nil), tagNames...)
	sort.Strings(sorted)
	decls := make([]string, 0, len(sorted))
	for _, n := range sorted {
		decls = append(decls, generatedTagActionDecl(n))
	}
	return c.Text + "\n" + strings.Join(decls, "\n")
}

// SchemaFor ports CedarEngine.kt:82-91: the bundled schema augmented with one
// `action "context.tag::<name>"` declaration per derived tag name.
//
// Cedar strict validation rejects an UNDECLARED action, so a tag rule is only loadable if its action is
// declared — but tags are not predefined, so the declarations are DERIVED from the rules themselves
// (the vocabulary IS the rule set). An empty set returns the base schema with no re-parse.
func (c *CedarSchema) SchemaFor(tagNames []string) (*xschema.Schema, error) {
	if len(tagNames) == 0 {
		return c.base, nil
	}
	sorted := append([]string(nil), tagNames...)
	sort.Strings(sorted)
	// Kotlin keys augmentedSchemas by the Set itself; a NUL-joined sorted key is the Go equivalent of
	// that set identity (NUL cannot appear in a name captured by [^"]+ from parseable Cedar source,
	// and if it somehow did the worst case is a cache miss, never a wrong schema).
	key := strings.Join(sorted, "\x00")

	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.augmented[key]; ok {
		return s, nil
	}
	s, err := xschema.Parse(c.AugmentedText(sorted), "schema.cedarschema+tags")
	if err != nil {
		return nil, err
	}
	c.augmented[key] = s
	return s, nil
}

// Validate parses and validates a single candidate Cedar policy against the schema, independent of any
// other policy — CedarEngine.kt:105-134. Empty result means valid.
//
// 🔒 CONTRACT: never throws for policy-shaped input. Syntax and semantic errors alike come back as
// messages. The spike put 20 adversarial inputs through this path (embedded NUL, unterminated string,
// unterminated paren, annotation-only, 130-deep nesting) and got a message every time, never a panic —
// so the deferred recover below is a contract assertion, not an expected path.
//
// The five steps follow the Kotlin exactly:
//
//  1. blank => ["cedar policy source must not be blank"] (W5: Java's blankness, not Go's).
//  2. parse (+ W2's statement-count check).
//  3. SELF-AUGMENT: validate against SchemaFor(ExtractContextTagNames(src)), so a not-yet-predefined
//     tag rule is loadable. SchemaFor is INSIDE the guarded region — a pathological tag name makes the
//     generated declaration malformed and schema parsing fail; that must surface as a validation error,
//     not break the never-throws contract.
//  4. a schema failure => ["invalid context.tag action name: …"].
//  5. the validator's errors.
//
// Kotlin concatenates response.errors (PARSE failures, top-level) with
// response.success.validationErrors (SEMANTIC / ill-typed) because either shape can be populated.
// cedar-go splits the two at different call sites — UnmarshalCedar returns the parse error, and
// validate.Validator.Policy returns the semantic one — so the concatenation maps 1:1 onto sequential
// returns and there is never a case where both are non-empty.
func (c *CedarSchema) Validate(cedarSrc string) (errsOut []string) {
	defer func() {
		if r := recover(); r != nil {
			errsOut = []string{fmt.Sprintf("cedar validation panicked (contract violation): %v", r)}
		}
	}()

	// W5: Kotlin's String.isBlank() delegates to Character.isWhitespace, which disagrees with Go's
	// unicode.IsSpace on 8 code points. Which of two wire messages CedarValidateResult.errors carries
	// depends on this, so it is reproduced rather than approximated with strings.TrimSpace.
	if isJavaBlank(cedarSrc) {
		return []string{"cedar policy source must not be blank"}
	}

	var p cedar.Policy
	if err := p.UnmarshalCedar([]byte(cedarSrc)); err != nil {
		return []string{err.Error()}
	}

	// 🔴 W2 — REJECT MULTI-STATEMENT SOURCE EXPLICITLY. cedar-go's UnmarshalCedar accepts
	// `permit(...); forbid(...);` and SILENTLY KEEPS STATEMENT 1, dropping the rest. The spike measured
	// the consequence directly: with the forbid dropped, `sql.ddl` flipped from deny to... deny only
	// because the permit did not cover it — in general a dropped forbid is a security control lost at
	// load time. Rust Cedar (the core cedar-java wraps) REJECTS the same source through the
	// single-named-policy path with "failed to parse policy with id `candidate` from string: unexpected
	// token `permit`", so rejecting is the faithful behaviour as well as the safe one.
	//
	// The error TEXT differs from cedar-java's — W8 defers the whole parse-error text contract, and Go's
	// parse text already differs on every parse error, so nothing is lost by using a self-describing
	// message here.
	if n, err := statementCount(cedarSrc); err == nil && n != 1 {
		return []string{"cedar policy source must contain exactly one statement, found " + strconv.Itoa(n)}
	}

	schema, err := c.SchemaFor(ExtractContextTagNames(cedarSrc))
	if err != nil {
		// Mirrors CedarEngine.kt:123-124's `catch (e: Exception)` arm. cedar-go returns a plain error
		// here rather than panicking, so the mapping is 1:1.
		return []string{"invalid context.tag action name: " + err.Error()}
	}

	return schema.ValidatePolicy("candidate", &p)
}

// statementCount counts the statements in a policy source. Used only by W2's guard; a parse failure is
// reported by the caller's own UnmarshalCedar, so an error here is swallowed at the call site.
func statementCount(cedarSrc string) (int, error) {
	list, err := cedar.NewPolicyListFromBytes("candidate", []byte(cedarSrc))
	if err != nil {
		return 0, err
	}
	return len(list), nil
}

// isJavaBlank reproduces Kotlin's String.isBlank(), i.e. "empty, or every Char satisfies
// Character.isWhitespace" — NOT strings.TrimSpace(s) == "".
//
// W5. The two predicates disagree on 8 code points, and which of two wire messages
// CedarValidateResult.errors carries depends on the answer:
//
//	Java yes / Go no : U+001C U+001D U+001E U+001F (the file/group/record/unit separators)
//	Go yes / Java no : U+0085 (NEL) U+00A0 U+2007 U+202F (the no-break spaces)
//
// Character.isWhitespace is: a Unicode space character (Zs, Zl, Zp) that is NOT a no-break space,
// OR one of \t \n \v \f \r    .
func isJavaBlank(s string) bool {
	for _, r := range s {
		if !isJavaWhitespace(r) {
			return false
		}
	}
	return true // an empty string is blank, matching Kotlin
}

func isJavaWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', 0x0B, '\f', '\r', 0x1C, 0x1D, 0x1E, 0x1F:
		return true
	case 0x00A0, 0x2007, 0x202F: // the three no-break spaces Java explicitly excludes
		return false
	}
	return unicode.In(r, unicode.Zs, unicode.Zl, unicode.Zp)
}
