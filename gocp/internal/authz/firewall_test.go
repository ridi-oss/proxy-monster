package authz

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
)

// TestXExpIsFirewalled enforces D5's firewall: cedar-go's x/exp subtree — which its own README
// (v1.8.0 README.md:140) says "is not subject to the semantic versioning constraints of the rest of the
// module and breaking changes may be made at any time" — may be imported by EXACTLY ONE package.
//
// The pattern below matches any import path containing "/x/exp", which covers both
// github.com/cedar-policy/cedar-go/x/exp/... (the subtree D5 is about) and the separate
// golang.org/x/exp module, which this port does not use at all. Catching both is intentional.
//
// The spike proved this is achievable: 5 identifiers, 1 file (xast.Policy, xresolved.Schema,
// xschema.Schema, xvalidate.New, xvalidate.WithStrict). A guard is what keeps it true, because the
// natural way to add a schema feature is to import x/exp where it is needed.
//
// The gate this does NOT replace: the decision path reaches x/exp/ast TRANSITIVELY through
// cedar.Authorize, so an x/exp break can affect more than validation. CI must run the corpus fingerprint
// (56af35d135a2649d975c9674) over DECISIONS as well as validation.
func TestXExpIsFirewalled(t *testing.T) {
	const allowed = "internal/authz/xschema"

	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var offenders []string

	err = filepath.WalkDir(filepath.Join(root, "authz"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if !strings.Contains(p, "/x/exp") {
				continue
			}
			if strings.Contains(filepath.ToSlash(path), allowed) {
				continue
			}
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, rel+" -> "+p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("D5: x/exp must be named ONLY in %s, found:\n  %s",
			allowed, strings.Join(offenders, "\n  "))
	}
}

// TestGeneratedTagActionContextShape is 🔴 W4's DIRECT assertion, and it exists because the ported
// TagResolutionTest case 6 does NOT cover what it appears to.
//
// Case 6 asserts that an unguarded `context.tags` read on a tag action is rejected. The spike measured
// that cedar-go strict rejects it EITHER WAY — with the correct narrow generated context ("attribute
// `tags` … not found") and with a lazy implementation that reused the RequestContext common type
// ("unable to guarantee safety of access to optional attribute `tags`"). Same verdict, different reason,
// so case 6 cannot discriminate the two in Go. INV-A2-12's schema half therefore needs asserting
// directly, on the generated TEXT.
func TestGeneratedTagActionContextShape(t *testing.T) {
	decl := generatedTagActionDecl("trusted-network")

	const want = `action "context.tag::trusted-network" appliesTo { principal: [User, Role], resource: [Datasource], ` +
		`context: { channel?: String, requester_ip?: ipaddr, tailscale_caps?: Set<String> } };`
	if decl != want {
		t.Errorf("the generated declaration is not byte-exact with CedarEngine.kt:86-87\n got: %s\nwant: %s", decl, want)
	}

	// 🔒 INV-A2-12 half 1 — `tags` MUST NOT appear, and the context must be INLINE rather than a
	// reference to RequestContext (which declares tags?).
	if strings.Contains(decl, "tags?") || strings.Contains(decl, "tags:") {
		t.Error("INV-A2-12: the generated action context must OMIT `tags` — declaring it opens the tag-on-tag hole")
	}
	if strings.Contains(decl, "RequestContext") {
		t.Error("INV-A2-12: the generated action must use its own NARROW inline context, not RequestContext")
	}

	// tailscale_caps is vestigial-but-live: nothing injects it, but removing it changes what validates.
	// docs/authz-context.md:255 documents the INVERSE shape; CedarEngine.kt:87 is authoritative.
	if !strings.Contains(decl, "tailscale_caps?: Set<String>") {
		t.Error("tailscale_caps must be carried verbatim — removing it changes what validates")
	}
}

// TestAugmentedTextIsSortedAndNewlineJoined pins CedarEngine.kt:85-89's exact concatenation: sorted tag
// names, "\n"-joined declarations, appended to the base text after a single "\n".
func TestAugmentedTextIsSortedAndNewlineJoined(t *testing.T) {
	got := DefaultSchema.AugmentedText([]string{"zulu", "alpha"})
	want := DefaultSchema.Text + "\n" + generatedTagActionDecl("alpha") + "\n" + generatedTagActionDecl("zulu")
	if got != want {
		t.Error("AugmentedText must sort the tag names and join with a single newline")
	}
}

// TestSchemaForCachesTheResolvedSchema pins the spike's first "surprise": cedar-go's schema API is
// two-step (UnmarshalCedar -> *schema.Schema, then Resolve -> *resolved.Schema), so the Kotlin's
// augmentedSchemas cache must hold the RESOLVED form or the resolve cost is paid on every Validate.
// Identity of the returned pointer is the observable.
func TestSchemaForCachesTheResolvedSchema(t *testing.T) {
	s, err := NewCedarSchema(SchemaSource)
	if err != nil {
		t.Fatal(err)
	}
	// An empty tag set returns the BASE schema with no re-parse at all (CedarEngine.kt:83).
	if base, _ := s.SchemaFor(nil); base != s.base {
		t.Error("SchemaFor(empty) must return the base schema object, not a re-parse")
	}
	first, err := s.SchemaFor([]string{"trusted-network"})
	if err != nil {
		t.Fatal(err)
	}
	// Keyed by the SET, so a different ORDER is the same cache entry.
	second, err := s.SchemaFor([]string{"trusted-network"})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("SchemaFor must cache the resolved schema keyed by the tag-name set")
	}
	a, _ := s.SchemaFor([]string{"a", "b"})
	b, _ := s.SchemaFor([]string{"b", "a"})
	if a != b {
		t.Error("SchemaFor's cache key must be the SET, so ordering cannot fragment it")
	}
}

// TestValidateNeverThrowsForPolicyShapedInput is CedarSchema.validate's stated CONTRACT
// (CedarEngine.kt:100-104). The spike put 20 adversarial inputs through it and got a message every time.
// A representative spread is kept here so a future change that lets a panic escape fails loudly.
func TestValidateNeverThrowsForPolicyShapedInput(t *testing.T) {
	for _, src := range []string{
		"",
		"   ",
		"this is not cedar at all",
		"permit(",
		`permit(principal, action, resource) when { "unterminated };`,
		"@annotation(\"x\")",
		"permit(principal, action, resource) when { \x00 };",
		strings.Repeat("(", 130),
		`permit(principal, action == Action::"context.tag::a\"b", resource);`,
	} {
		errs := DefaultSchema.Validate(src) // must not panic
		if len(errs) == 0 {
			t.Errorf("expected %q to produce at least one error message", src)
		}
	}
}

// TestValidateBlankMessageUsesJavaWhitespace is W5. Kotlin's isBlank() delegates to
// Character.isWhitespace, which disagrees with Go's unicode.IsSpace on 8 code points. Which of two wire
// messages CedarValidateResult.errors carries depends on the answer.
func TestValidateBlankMessageUsesJavaWhitespace(t *testing.T) {
	const blankMsg = "cedar policy source must not be blank"

	// Java YES / Go NO — these must produce the BLANK message.
	for _, r := range []rune{0x1C, 0x1D, 0x1E, 0x1F} {
		got := DefaultSchema.Validate(string(r))
		if len(got) != 1 || got[0] != blankMsg {
			t.Errorf("U+%04X: got %v, want the blank message (Java treats it as whitespace)", r, got)
		}
	}
	// Go YES / Java NO — these must NOT be blank, so they fall through to a PARSE error.
	for _, r := range []rune{0x0085, 0x00A0, 0x2007, 0x202F} {
		got := DefaultSchema.Validate(string(r))
		if len(got) == 1 && got[0] == blankMsg {
			t.Errorf("U+%04X: got the blank message, but Java does NOT treat it as whitespace", r)
		}
	}
	// Shared whitespace, for the control.
	for _, s := range []string{"", " ", "\t\n\r  ", "\v\f"} {
		got := DefaultSchema.Validate(s)
		if len(got) != 1 || got[0] != blankMsg {
			t.Errorf("%q: got %v, want the blank message", s, got)
		}
	}
}

// TestValidateRejectsMultiStatementSource is 🔴 W2 — REPRODUCE + PIN.
//
// cedar-go's UnmarshalCedar ACCEPTS `permit(...); forbid(...);` and SILENTLY KEEPS STATEMENT 1. If
// statement 2 is the forbid, that is a security control lost at load time. Rust Cedar — the core
// cedar-java wraps — rejects the same source through the single-named-policy path, so rejecting is both
// the faithful and the safe behaviour.
func TestValidateRejectsMultiStatementSource(t *testing.T) {
	two := `permit(principal, action == Action::"sql.select", resource);` +
		`forbid(principal, action == Action::"sql.ddl", resource);`

	if errs := DefaultSchema.Validate(two); len(errs) == 0 {
		t.Fatal("🔴 W2: a two-statement policy source must be REJECTED — cedar-go would keep only " +
			"statement 1 and silently drop the forbid")
	}
	// The premise, so the test still means something if cedar-go's parser changes.
	if n, err := statementCount(two); err != nil || n != 2 {
		t.Errorf("premise: statementCount = %d (err %v), want 2", n, err)
	}
	// A single statement is of course still fine.
	assertValid(t, `permit(principal, action == Action::"sql.select", resource);`)
}

// TestLoadPathRejectsMultiStatementSource is W2's SECOND half — the work item is explicit that the check
// belongs "in the Go validate AND in the policy-load path", and validate alone does not cover the load
// path.
//
// Construction (INV-A2-17) and every create/update/enable path validate first, so the only way a
// two-statement row reaches the rebuild is an out-of-band edit to the `policy` table. Measured before the
// guard existed: with `permit(sql.select); forbid(analyst, sql.ddl);` landing as an enabled row after a
// version bump, the analyst's sql.ddl stayed ALLOWED — the forbid was silently dropped and nothing
// reported it. This test is that measurement, inverted.
func TestLoadPathRejectsMultiStatementSource(t *testing.T) {
	grant := PolicySource{ID: 1, Src: `permit(principal in Role::"analyst", action == Action::"sql.ddl", resource in Datasource::"acme-pg");`}
	store := &fakeStore{sources: []PolicySource{grant}}
	e, err := NewCedarEngine(store)
	if err != nil {
		t.Fatal(err)
	}
	a := New(e, store, stubRoles(nil))
	ddl := func() AuthzDecision {
		return a.AuthorizeDatasourceAction("alice", []string{"analyst"}, ActionSQLDDL, "acme-pg", AuthzContext{}, nil)
	}
	assertAllow(t, ddl(), "the baseline grant, before the out-of-band edit")

	// The out-of-band edit: statement 2 is the forbid that would otherwise vanish.
	store.mutate([]PolicySource{grant, {ID: 2, Src: `permit(principal, action == Action::"sql.select", resource);` +
		`forbid(principal in Role::"analyst", action == Action::"sql.ddl", resource);`}})

	got := ddl()
	if got.Allowed {
		t.Fatal("🔴 W2 (load path): a two-statement enabled row silently dropped its forbid — " +
			"cedar-go's UnmarshalCedar keeps only statement 1, so the rebuild MUST reject the row")
	}
	if !strings.HasPrefix(got.Reason, "authorization engine error: ") {
		t.Errorf("reason = %q, want the branch-1 prefix %q", got.Reason, "authorization engine error: ")
	}
	if !strings.Contains(got.Reason, "exactly one statement") {
		t.Errorf("reason = %q, want it to name the multi-statement cause", got.Reason)
	}

	// And the engine must not publish a PARTIAL policy set: the healthy grant is unreachable too, which is
	// the fail-closed direction. Recovering the good row would mean deciding against a set the operator
	// never wrote.
	store.mutate([]PolicySource{grant})
	assertAllow(t, ddl(), "the rebuild recovers once the bad row is gone")
}

// TestNoUnequalEntityCollision is the W7 guard.
//
// dedupeEntities reproduces Kotlin's FIRST-wins collapse, so first-vs-last-wins cannot diverge by
// construction. This guard covers the other half of W7: that the entity builders never emit two
// UNEQUAL entities for one UID in the first place. The spike proved order IS observable in general
// (a synthetic first-wins `allow` vs last-wins `deny`), and flagged AuthorizeColumns (Authz.kt:502) as
// the one site that appends per-ColumnRef with no identity-keyed dedup.
func TestNoUnequalEntityCollision(t *testing.T) {
	// The live collision: an ApprovalRequest scoped to a role the principal already holds
	// (AuthzTest case 8). Both colliding entities are BARE, so they are structurally equal.
	_, principal, roles := principalEntities("approver1", []string{"pii-reader"})
	_, resourceEntities := marshalResource(ResourceApprovalRequest{
		Requester: "someone-else", RoleName: ptr("pii-reader"),
	})
	assertNoUnequalCollision(t, "authorizeAs / role-scoped request",
		append(append([]types.Entity{principal}, roles...), resourceEntities...))

	// AuthorizeColumns' un-deduped append: two ColumnRefs with the same identity but DIFFERENT tags.
	// Today Query.kt cannot produce this, but it is one refactor away, and it is the case that would
	// silently change a verdict.
	a := authzFor(t, columnAuthzSeedPolicies, nil)
	got := a.AuthorizeColumns("alice", []string{"analyst"}, "acme-pg", []ColumnRef{
		{Key: "a", Catalog: "acme", Schema: "public", Table: "users", Column: "rrn"},
		{Key: "b", Catalog: "acme", Schema: "public", Table: "users", Column: "rrn", Tags: []string{"pii"}},
	}, AuthzContext{}, nil, nil)
	// FIRST-wins: the untagged entity survives, so BOTH keys resolve against an untagged Column and are
	// UNMASKED. Under last-wins the pii-tagged entity would survive and both would be MASKED. Pinning
	// the outcome is what makes the collapse direction observable.
	if got["a"] != ColumnUnmasked || got["b"] != ColumnUnmasked {
		t.Errorf("first-wins collapse not preserved: got a=%s b=%s, want both UNMASKED", got["a"], got["b"])
	}
}

func assertNoUnequalCollision(t *testing.T, what string, ents []types.Entity) {
	t.Helper()
	seen := map[types.EntityUID]types.Entity{}
	for _, e := range ents {
		if prev, ok := seen[e.UID]; ok && !prev.Equal(e) {
			t.Errorf("%s: two UNEQUAL entities share UID %v — first-vs-last-wins would change the decision", what, e.UID)
		}
		seen[e.UID] = e
	}
}
