package authz

import (
	"github.com/cedar-policy/cedar-go/types"
)

// AuthzContext is the request-scoped context Cedar policies condition on (docs/authz-context.md).
// Port of Authz.kt:161-185.
//
// 🔒 INV-A2-9 — context is SERVER-ATTESTED, never client-asserted. The control plane sets these from
// the entry point plus the observed connection; no client value reaches ToCedarMap. Tags are DERIVED
// by pass-1 (ResolveContextTags), never supplied.
//
// Channel and RequesterIP are POINTERS, not strings: Authz.kt:177-178 writes the Cedar key only when
// the Kotlin value is non-null, and "" is non-null there — so `channel: ""` WOULD be emitted while a
// null channel is omitted. INV-A2-8 makes that distinction load-bearing (absence is the fail-closed
// signal), so a plain string, whose zero value is "", cannot express it.
type AuthzContext struct {
	// NetworkZones is a coarse network-zone list (authz-model.md); requester_ip and the derived Tags
	// are the primary mechanism.
	NetworkZones []string
	// Channel is which surface/phase: wire | editor | workflow-executor | workflow-viewer.
	Channel *string
	// RequesterIP is the end client's source address, a Cedar ipaddr; nil when unknown.
	RequesterIP *string
	// Tags are DERIVED (two-pass tag rules) — the tag names the request earns. Never client-supplied.
	Tags []string
}

// WithTags is the port of Kotlin's `raw.copy(tags = ...)` (Authz.kt:863). Value semantics make this a
// copy already; the method exists so the two-pass call site reads like the Kotlin.
func (c AuthzContext) WithTags(tags []string) AuthzContext {
	c.Tags = tags
	return c
}

// ToCedarMap builds the Cedar `context` record — Authz.kt:174-184.
//
//  1. network_zones — ALWAYS present, empty set if none.
//  2. tags          — present UNLESS includeTags is false.
//  3. channel       — only when non-nil.
//  4. requester_ip  — only when non-nil AND parseable.
//
// 🔒 INV-A2-8 — optional-attribute ABSENCE is the fail-closed signal. A policy conditioning on an
// absent attribute simply does not fire (Cedar skips it), which denies. So a malformed IP must never
// throw: a thrown constructor would error EVERY query. Dropping it is the fail-closed behaviour.
// Kotlin wraps the IpAddress constructor in runCatching; here ParseIPAddr's error is discarded for
// exactly the same reason. ChannelContextAuthzTest case 3 pins the channel half.
//
// 🔒 INV-A2-12 (half 2) — includeTags=false is pass-1's closure of the tag-on-tag hole. The spike
// measured both sides directly: with the guarded tag-on-tag rule, a pass-1 context WITHOUT the `tags`
// key denies, and the same rule with `tags` LEAKED into pass 1 ALLOWS — the recursion hole. Both
// closures (this one and the generated schema omitting `tags`) must exist.
//
// 3. Surprise from the spike worth keeping in view: schema.cedarschema:114-119 declares ALL FOUR
// context fields OPTIONAL, including network_zones — so an UNGUARDED `context.network_zones` read
// fails strict validation even though this always emits the key.
func (c AuthzContext) ToCedarMap(includeTags bool) types.Record {
	m := types.RecordMap{}

	zones := make([]types.Value, 0, len(c.NetworkZones))
	for _, z := range c.NetworkZones {
		zones = append(zones, types.String(z))
	}
	m["network_zones"] = types.NewSet(zones...)

	if includeTags {
		tags := make([]types.Value, 0, len(c.Tags))
		for _, t := range c.Tags {
			tags = append(tags, types.String(t))
		}
		m["tags"] = types.NewSet(tags...)
	}

	if c.Channel != nil {
		m["channel"] = types.String(*c.Channel)
	}

	if c.RequesterIP != nil {
		// Fail-closed: an unparseable value is DROPPED, not propagated and not defaulted.
		if ip, err := types.ParseIPAddr(*c.RequesterIP); err == nil {
			m["requester_ip"] = ip
		}
	}

	return types.NewRecord(m)
}

// AuthzDecision is Authz.kt:187-190's sealed interface: Allow (object) or Deny(reason, code).
//
// Modelled as a struct rather than an interface pair: Kotlin's Allow is a singleton object with no
// state, so the whole discriminant is one boolean, and a struct keeps `if d.Allowed` at call sites
// without a type switch. Reason and Code are only meaningful on a Deny, exactly as in the Kotlin.
type AuthzDecision struct {
	Allowed bool
	Reason  string
	Code    string
}

// Allow is the AuthzDecision.Allow object.
var Allow = AuthzDecision{Allowed: true}

// Deny builds AuthzDecision.Deny(reason) with the Kotlin default code "forbidden".
func Deny(reason string) AuthzDecision {
	return AuthzDecision{Reason: reason, Code: "forbidden"}
}

// RoleSource is Authz's identity port (Layer 1 — RoleResolver, no Cedar). Authz NEVER resolves roles
// itself; the caller wires in a RoleSource backed by RoleResolver.resolve (or a stub, in tests). This
// is what keeps role resolution swappable and Cedar-independent.
//
// Kotlin's `fun interface RoleSource`; in Go a one-method interface, with RoleSourceFunc as the
// function-literal adapter.
//
// TODO(A3): RoleResolver.resolve is A3's — see 03-identity-scim.md. This narrow interface is the whole
// contract Authz needs, so A3 satisfies it without authz importing identity.
type RoleSource interface {
	RolesOf(principal string) []string
}

// RoleSourceFunc adapts a plain function to RoleSource.
type RoleSourceFunc func(principal string) []string

// RolesOf implements RoleSource.
func (f RoleSourceFunc) RolesOf(principal string) []string { return f(principal) }
