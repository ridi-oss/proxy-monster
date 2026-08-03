package authz

import (
	"strings"
	"testing"
)

// Port of TagResolutionTest.kt — 182 LOC, 9 cases, unit. 02-authz.md §10.
// Case names verbatim from the Kotlin.

// TagResolutionTest.kt:47-49.
var cidrTagRule = map[int64]string{
	1: `permit(principal, action == Action::"context.tag::trusted-network", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`,
}

// 1. a tag rule loads though its action is not predefined, and fires when its condition holds
//
// S3 KEY CASE — the single most direct test of the schemaFor TEXT-augmentation trick. `context.tag::
// trusted-network` is NOT declared in the bundled schema; it is declared by a generated declaration
// appended to the schema TEXT and re-parsed. If that did not work the whole tag mechanism would need
// rewriting rather than porting.
func TestTagResolution_ATagRuleLoadsThoughItsActionIsNotPredefinedAndFires(t *testing.T) {
	// Half 1: it validates only because SchemaFor self-augments. Against the BASE schema it must not.
	assertValid(t, cidrTagRule[1])
	base, err := DefaultSchema.SchemaFor(nil)
	if err != nil {
		t.Fatalf("base schema: %v", err)
	}
	var p = mustPolicy(t, cidrTagRule[1])
	if errs := base.ValidatePolicy("candidate", p); len(errs) == 0 {
		t.Error("the tag rule must NOT validate against the base schema — otherwise the augmentation is vacuous")
	}

	// Half 2: it fires.
	a := authzFor(t, cidrTagRule, nil)
	got := a.ResolveContextTags("alice", nil, "acme-prod",
		AuthzContext{RequesterIP: ptr("100.100.5.5")}, nil)
	assertStrings(t, got, []string{"trusted-network"}, "resolveContextTags")
}

// 2. 🔒 the tag is absent when the raw signal does not match — fail closed (INV-A2-13)
func TestTagResolution_TheTagIsAbsentWhenTheRawSignalDoesNotMatch(t *testing.T) {
	a := authzFor(t, cidrTagRule, nil)

	outOfRange := a.ResolveContextTags("alice", nil, "acme-prod",
		AuthzContext{RequesterIP: ptr("10.0.0.1")}, nil)
	if len(outOfRange) != 0 {
		t.Errorf("requesterIp 10.0.0.1: got %v, want no tags", outOfRange)
	}

	// requester_ip key omitted entirely -> the `has` guard is false.
	absent := a.ResolveContextTags("alice", nil, "acme-prod", AuthzContext{}, nil)
	if len(absent) != 0 {
		t.Errorf("requesterIp nil: got %v, want no tags", absent)
	}
}

// 3. an empty vocabulary short-circuits to no tags
//
// Asserts the SHORT-CIRCUIT, not just the empty result: with no tag rule enabled the vocabulary is
// empty and NO Cedar evaluation happens at all (the common deployment). EvalCount is the observable
// that makes that assertable — see CedarEngine.EvalCount.
func TestTagResolution_AnEmptyVocabularyShortCircuitsToNoTags(t *testing.T) {
	e := engineFor(t, map[int64]string{
		2: `permit(principal, action == Action::"datasource.connect", resource);`,
	})
	a := New(e, nil, stubRoles(nil))

	vocab, err := e.ContextTagVocabulary()
	if err != nil || len(vocab) != 0 {
		t.Fatalf("vocabulary = %v (err %v), want empty", vocab, err)
	}
	before := e.EvalCount()

	got := a.ResolveContextTags("alice", nil, "acme-prod",
		AuthzContext{RequesterIP: ptr("100.100.5.5")}, nil)
	if len(got) != 0 {
		t.Errorf("got %v, want no tags", got)
	}
	if after := e.EvalCount(); after != before {
		t.Errorf("evaluations went %d -> %d; an empty vocabulary must evaluate NOTHING", before, after)
	}
}

// 4. a datasource-scoped tag rule fires only for the named datasource
func TestTagResolution_ADatasourceScopedTagRuleFiresOnlyForTheNamedDatasource(t *testing.T) {
	a := authzFor(t, map[int64]string{
		1: `permit(principal, action == Action::"context.tag::trusted-network", resource == Datasource::"acme-prod") when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`,
	}, nil)
	raw := AuthzContext{RequesterIP: ptr("100.100.5.5")}

	assertStrings(t, a.ResolveContextTags("alice", nil, "acme-prod", raw, nil),
		[]string{"trusted-network"}, "acme-prod")
	if got := a.ResolveContextTags("alice", nil, "other", raw, nil); len(got) != 0 {
		t.Errorf("other: got %v, want no tags", got)
	}
}

// 5. a derived tag drives a consuming grant end-to-end
//
// The full two-pass loop. Also pins that BOTH policies validate — the CONSUMER against the BASE schema
// (it targets no context.tag action), the PRODUCER against the augmented one.
func TestTagResolution_ADerivedTagDrivesAConsumingGrantEndToEnd(t *testing.T) {
	policies := map[int64]string{
		1: `permit(principal, action == Action::"context.tag::trusted-network", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`,
		2: `permit(principal in Role::"analyst", action == Action::"datasource.connect", resource == Datasource::"acme-prod") when { context has tags && context.tags.contains("trusted-network") };`,
	}
	assertValid(t, policies[1])
	assertValid(t, policies[2])

	a := authzFor(t, policies, nil)
	roles := []string{"analyst"}

	derived := a.ResolveContextTags("alice", roles, "acme-prod",
		AuthzContext{RequesterIP: ptr("100.100.5.5")}, nil)
	assertStrings(t, derived, []string{"trusted-network"}, "pass 1")

	withTag := a.AuthorizeDatasourceAction("alice", roles, ActionDatasourceConnect, "acme-prod",
		AuthzContext{RequesterIP: ptr("100.100.5.5"), Tags: derived}, nil)
	assertAllow(t, withTag, "pass 2 with the derived tag")

	withoutTag := a.AuthorizeDatasourceAction("alice", roles, ActionDatasourceConnect, "acme-prod",
		AuthzContext{RequesterIP: ptr("100.100.5.5")}, nil)
	assertDeny(t, withoutTag, "pass 2 with tags empty")
}

// 6. 🔒 an unguarded tag-on-tag rule is rejected at construction — `tags` absent from the tag-action
// schema (INV-A2-12)
//
// S3 + INV-A2-12 half 1. The sharpest S3 sub-probe: it only rejects if the generated action's NARROWER
// context (channel / requester_ip / tailscale_caps, no tags) actually takes effect.
//
// ⚠️ The spike measured that this case does NOT discriminate a correct narrow context from a lazy one
// that reuses RequestContext, because cedar-go strict rejects the unguarded read EITHER WAY — by a
// different rule ("unable to guarantee safety of access to optional attribute `tags`" instead of
// "attribute `tags` … not found"). Same verdict, different reason. That is why W4 also requires a
// DIRECT assertion on the generated declaration's context shape — see schema_test.go.
func TestTagResolution_AnUnguardedTagOnTagRuleIsRejectedAtConstruction(t *testing.T) {
	unguarded := `permit(principal, action == Action::"context.tag::derived", resource) when { context.tags.contains("other") };`

	if errs := DefaultSchema.Validate(unguarded); len(errs) == 0 {
		t.Fatal("INV-A2-12 half 1: an unguarded read of `tags` on a tag action must NOT validate")
	}
	if _, err := NewCedarEngineFromSources([]PolicySource{{ID: 1, Src: unguarded}}); err == nil {
		t.Fatal("CedarEngine construction must fail on the unguarded tag-on-tag rule")
	}
}

// 7. 🔒 a guarded tag-on-tag rule loads but can never earn a tag — no recursion (INV-A2-12)
//
// INV-A2-12 half 2, and note the ASYMMETRY that must be reproduced exactly: an UNGUARDED read of the
// undeclared `tags` is a validation ERROR (case 6), a GUARDED read is VALID. Both halves must hold.
//
// The rule loads, and the caller even supplies tags=["other"] in the RAW context — but pass 1 marshals
// with includeTags=false, so `context has tags` is false and no tag is ever earned. The spike measured
// the counterfactual directly: leak `tags` into pass 1 and the same rule ALLOWS, opening the recursion
// hole.
func TestTagResolution_AGuardedTagOnTagRuleLoadsButCanNeverEarnATag(t *testing.T) {
	guarded := `permit(principal, action == Action::"context.tag::derived", resource) when { context has tags && context.tags.contains("other") };`
	assertValid(t, guarded)

	a := authzFor(t, map[int64]string{1: guarded}, nil)
	raw := AuthzContext{Tags: []string{"other"}}
	if got := a.ResolveContextTags("alice", nil, "acme-prod", raw, nil); len(got) != 0 {
		t.Errorf("got %v, want no tags — pass 1 must not expose `tags`", got)
	}

	// The counterfactual, asserted so the closure cannot be silently removed: with includeTags=true the
	// key IS present, which is exactly the state pass 1 must never be in.
	if _, ok := raw.ToCedarMap(false).Get("tags"); ok {
		t.Error("INV-A2-12: pass-1's context map must not contain a `tags` key")
	}
	if _, ok := raw.ToCedarMap(true).Get("tags"); !ok {
		t.Error("pass-2's context map must contain a `tags` key")
	}
}

// 8. `effectiveAuthzContext` makes channel authoritative and discards caller-supplied tags (INV-A2-9)
//
// CROSS-AREA: effectiveAuthzContext and Channel live in A6 (Query.kt), not A2. The half that IS A2's —
// and the half INV-A2-9 is actually about — is that pass 1 DERIVES tags from server-attested signals and
// never trusts a caller-supplied set: a context arriving with tags ["injected", "trusted-network"] must
// come back with exactly the derived set, and an out-of-range ip must therefore yield nothing at all.
//
// TODO(A6): the channel-override half ("wire" wins over a caller's "editor") needs A6's
// effectiveAuthzContext overlay — see 06-query-decision.md §3.
func TestTagResolution_CallerSuppliedTagsAreDiscarded(t *testing.T) {
	a := authzFor(t, cidrTagRule, nil)
	caller := AuthzContext{
		Channel:     ptr("editor"),
		Tags:        []string{"injected", "trusted-network"},
		RequesterIP: ptr("10.0.0.1"),
	}

	outOfRange := a.ResolveContextTags("alice", nil, "acme-prod", caller, nil)
	if len(outOfRange) != 0 {
		t.Errorf("ip 10.0.0.1: got %v, want no tags — the injected set must be discarded, not merged", outOfRange)
	}

	inRange := caller
	inRange.RequesterIP = ptr("100.100.5.5")
	assertStrings(t, a.ResolveContextTags("alice", nil, "acme-prod", inRange, nil),
		[]string{"trusted-network"}, "ip 100.100.5.5 earns ONLY the derived tag")
}

// 9. the dangling-tag lint flags a consumer with no producer and a producer with no consumer
//
// No Cedar engine involved — pure regex. The Kotlin assertions use `contains`, so only the quoted tag
// name plus one fixed phrase are pinned; the exact wording is reproduced anyway.
func TestTagResolution_TheDanglingTagLintFlagsBothDirections(t *testing.T) {
	consumerOnly := ContextTagLint([]PolicySource{
		{ID: 1, Src: `permit(principal, action == Action::"datasource.connect", resource) when { context has tags && context.tags.contains("ghost") };`},
	})
	if len(consumerOnly) != 1 ||
		!strings.Contains(consumerOnly[0], `"ghost"`) ||
		!strings.Contains(consumerOnly[0], "no tag rule produces") {
		t.Errorf("consumer with no producer: got %v", consumerOnly)
	}

	producerOnly := ContextTagLint(sourcesOf(cidrTagRule))
	if len(producerOnly) != 1 ||
		!strings.Contains(producerOnly[0], `"trusted-network"`) ||
		!strings.Contains(producerOnly[0], "no policy consumes") {
		t.Errorf("producer with no consumer: got %v", producerOnly)
	}

	matched := ContextTagLint([]PolicySource{
		{ID: 1, Src: cidrTagRule[1]},
		{ID: 2, Src: `permit(principal in Role::"analyst", action == Action::"datasource.connect", resource) when { context has tags && context.tags.contains("trusted-network") };`},
	})
	if len(matched) != 0 {
		t.Errorf("matched producer/consumer pair: got %v, want no warnings", matched)
	}
}
