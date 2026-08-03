package authz

import (
	"strings"
	"testing"
)

// Port of ChannelContextAuthzTest.kt — 86 LOC, 4 cases, unit. 02-authz.md §10.
// Case names verbatim from the Kotlin.

// ChannelContextAuthzTest.kt:30-36.
var channelWireOnlyConnect = map[int64]string{
	1: `permit(principal in Role::"wire-only", action == Action::"datasource.connect", resource in Datasource::"acme-mysql") when { context has channel && context.channel == "wire" };`,
}

// 1. a channel-conditioned grant fires only for the matching channel
func TestChannelContext_AChannelConditionedGrantFiresOnlyForTheMatchingChannel(t *testing.T) {
	a := authzFor(t, channelWireOnlyConnect, nil)
	d := a.AuthorizeDatasourceAction("alice", []string{"wire-only"}, ActionDatasourceConnect,
		"acme-mysql", AuthzContext{Channel: ptr("wire")}, nil)
	assertAllow(t, d, "channel=wire")
}

// 2. the same grant does not apply on a different channel
func TestChannelContext_TheSameGrantDoesNotApplyOnADifferentChannel(t *testing.T) {
	a := authzFor(t, channelWireOnlyConnect, nil)
	d := a.AuthorizeDatasourceAction("alice", []string{"wire-only"}, ActionDatasourceConnect,
		"acme-mysql", AuthzContext{Channel: ptr("editor")}, nil)
	assertDeny(t, d, "channel=editor")
}

// 3. 🔒 an absent channel fails the guard closed (INV-A2-8)
//
// The channel key is OMITTED from the Cedar context map, not set to the empty string — optional-attribute
// ABSENCE is the fail-closed signal. A nil *string is what expresses that; a plain "" would be emitted
// as a present-but-empty channel and would still be a wrong shape even though this policy would deny.
func TestChannelContext_AnAbsentChannelFailsTheGuardClosed(t *testing.T) {
	a := authzFor(t, channelWireOnlyConnect, nil)
	ctx := AuthzContext{} // Channel nil
	d := a.AuthorizeDatasourceAction("alice", []string{"wire-only"}, ActionDatasourceConnect,
		"acme-mysql", ctx, nil)
	assertDeny(t, d, "channel absent")

	// Directly assert the marshalling, since that is the actual invariant: the key must not appear.
	if _, ok := ctx.ToCedarMap(true).Get("channel"); ok {
		t.Error("INV-A2-8: a nil Channel must leave the `channel` key ABSENT from the Cedar context")
	}
}

// 4. 🔒 an unguarded optional-attr policy is rejected at engine construction (INV-A2-17)
//
// S2 KEY CASE — a SEMANTIC (validationErrors) rejection, not a parse error, and the cleanest probe for
// whether cedar-go's strict validator flags an unguarded optional-attribute read. Message text is not
// pinned by the Kotlin; the PREFIX is asserted here because an operator reads it when boot aborts.
func TestChannelContext_AnUnguardedOptionalAttrPolicyIsRejectedAtEngineConstruction(t *testing.T) {
	unguarded := `permit(principal, action == Action::"datasource.connect", resource) when { context.channel == "wire" };`

	if errs := DefaultSchema.Validate(unguarded); len(errs) == 0 {
		t.Fatal("expected the unguarded optional-attribute read to fail schema validation")
	}

	_, err := NewCedarEngineFromSources([]PolicySource{{ID: 1, Src: unguarded}})
	if err == nil {
		t.Fatal("INV-A2-17: CedarEngine construction must FAIL FAST on an enabled policy that does not validate")
	}
	want := "authz: enabled cedar policy failed schema validation at startup: policy #1: "
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("construction error = %q, want prefix %q", err.Error(), want)
	}
}
