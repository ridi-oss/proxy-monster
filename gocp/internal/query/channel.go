package query

import (
	"encoding/json"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// Channel is which surface/phase a decision is in (docs/authz-context.md). Port of
// `enum class Channel(val contextValue: String)` (Query.kt:114-120).
//
// It drives the session-statement gate (only a persistent connection may passthrough BEGIN/SET) and
// is overlaid onto the Cedar `context.channel` a policy conditions on.
//
// 🔒 INV-A6-1 — the channel is SERVER-ATTESTED. It comes from the entry point or the ephemeral-token
// kind and is NEVER client-asserted; [EffectiveAuthzContext] overwrites any caller-supplied
// `channel`.
//
// ⚠️ Channel has FIVE values. MCP was added after the doc comments were written, so several Kotlin
// comments still enumerate four (06-query-decision.md §1, Q4). The code — and step 14 below — is
// unambiguous: MCP refuses session statements, exactly like the two workflow channels.
//
// # Why a string type rather than an int enum
//
// Kotlin's enum has no zero value; Go's does, and an `iota` enum would make it WIRE — the one
// channel that MAY passthrough a session-mutating statement. An unset field silently reading as the
// most permissive channel is fail-OPEN on the gate INV-A6-2 is about. A string type makes the zero
// value "" instead: not a valid channel, so step 14's session dispatch takes its default arm and
// hard-denies. Same reasoning, and the same shape, as internal/types.Decision.
type Channel string

// The five channels. The value IS `contextValue` — the exact Cedar string.
const (
	// ChannelWire is the native wire proxy: a held backend connection.
	ChannelWire Channel = "wire"
	// ChannelEditor is the console SQL editor: also a held connection (one proxy-dialed stream).
	ChannelEditor Channel = "editor"
	// ChannelWorkflowExecutor runs an approved task. Fresh connection per run.
	ChannelWorkflowExecutor Channel = "workflow-executor"
	// ChannelWorkflowViewer views a stored result. Fresh connection per run.
	ChannelWorkflowViewer Channel = "workflow-viewer"
	// ChannelMCP is the MCP server surface. Fresh connection per run.
	ChannelMCP Channel = "mcp"
)

// ContextValue is the Kotlin property of the same name — the exact Cedar `context.channel` string.
// The identity function is deliberate: call sites read the same as the Kotlin's.
func (c Channel) ContextValue() string { return string(c) }

// holdsConnection reports whether this channel holds a persistent backend connection, and so may
// relay a TX_CONTROL / SESSION_MUTATING statement (step 14).
//
// 🔒 INV-A6-2 — only WIRE and EDITOR qualify. WORKFLOW_EXECUTOR, WORKFLOW_VIEWER and MCP refuse
// session statements because each of their runs uses a FRESH connection, so the session state the
// statement sets would silently not carry. The zero Channel ("") is not in the set — fail-closed.
func (c Channel) holdsConnection() bool { return c == ChannelWire || c == ChannelEditor }

// KnownOrDeny is fail-closed normalization of a proto EnfAction — `EnfAction.knownOrDeny()`
// (Query.kt:85-88).
//
// 🔒 INV-A6-3 — anything that is not an explicit ALLOW / MASK / DENY collapses to DENY, so an
// unknown verdict arriving from the wire never falls open. **Call this at every point a proto
// EnfAction enters from an untrusted source.**
//
// ⚠️ Go shape (06-query-decision.md §2): protobuf-go exposes an unknown enum value as the raw int32
// with NO `UNRECOGNIZED` sentinel, so this switches on the three known values and defaults to DENY.
// An exhaustiveness check over the generated constants would silently accept `EnfAction(7)`.
func KnownOrDeny(a pb.EnfAction) pb.EnfAction {
	switch a {
	case pb.EnfAction_ALLOW, pb.EnfAction_MASK, pb.EnfAction_DENY:
		return a
	default:
		return pb.EnfAction_DENY
	}
}

// WireEnfAction is the REST JSON codec for the proto EnfAction enum — the port of
// `object EnfActionSerializer : KSerializer<EnfAction>` (Query.kt:69-77).
//
// The proto enum is not itself kotlinx-@Serializable, so the Kotlin (de)serializes it BY NAME to keep
// REST JSON at exactly "ALLOW" / "MASK" / "DENY".
//
// 🔒 INV-A6-3 — DESERIALIZATION FAILS CLOSED. Anything that is not the literal "ALLOW" or "MASK" —
// including "DENY", an unknown string, "ENF_ACTION_UNSPECIFIED" or "UNRECOGNIZED" — becomes DENY. A
// verdict never falls open.
//
// ⚠️ LANGUAGE-FORCED DEVIATION on the SERIALIZE half only. Kotlin emits `value.name`, which for the
// generated `UNRECOGNIZED` sentinel is the string "UNRECOGNIZED". protobuf-go has no such sentinel:
// `EnfAction(7).String()` renders "7". Both are non-round-trippable values that deserialize back to
// DENY, so the fail-closed contract is unchanged; only the rendering of an unrepresentable input
// differs, and no production path can produce one (every EnfAction on this side is set from a
// [DecisionContext.Action] this package built).
type WireEnfAction pb.EnfAction

// MarshalJSON encodes the enum by NAME.
func (a WireEnfAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(pb.EnfAction(a).String())
}

// UnmarshalJSON decodes by name, fail-closed to DENY. See INV-A6-3 above.
func (a *WireEnfAction) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	switch name {
	case "ALLOW":
		*a = WireEnfAction(pb.EnfAction_ALLOW)
	case "MASK":
		*a = WireEnfAction(pb.EnfAction_MASK)
	default:
		*a = WireEnfAction(pb.EnfAction_DENY)
	}
	return nil
}
