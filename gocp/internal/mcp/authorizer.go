package mcp

import (
	"context"
	"sort"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A11 §3 — `McpAuthorizer`, the TWO-STAGE gate.
// ---------------------------------------------------------------------------------------------

// authorizationError is `private class McpAuthorizationException(val error: ApiError, val roles:
// Set<String>)`.
//
// 🔒 INV-A11-9 — IT CARRIES THE ROLES ON PURPOSE, and the scope-failure arm carries the EMPTY set
// because at that point no roles had been resolved. The audit row for an insufficient-scope denial
// must therefore record no roles: the exception exists in this shape precisely so the trail can be
// honest about what was known at the moment of refusal, rather than back-filling a resolution that
// never happened.
type authorizationError struct {
	err   types.ApiError
	roles []string
}

func (e *authorizationError) Error() string { return e.err.Code }

// Authorizer is `private class McpAuthorizer(config, core)`.
type Authorizer struct {
	authDebug bool
	roles     Roles
	cedar     Cedar
}

// NewAuthorizer builds the authorizer. `cedar` may be nil ONLY when authDebug is true, which is the
// one configuration in which it is never called.
func NewAuthorizer(authDebug bool, roles Roles, cedar Cedar) *Authorizer {
	return &Authorizer{authDebug: authDebug, roles: roles, cedar: cedar}
}

// Authorize is `fun authorize(context, capability): Set<String>`, in the Kotlin's order:
//
//  1. scope ∉ context.scopes ⇒ `mcp.insufficient_scope{scope}` with roles = ∅.
//  2. roles = roleResolver.resolve(principal)  — 🔒 INV-A11-8, LIVE, every call.
//  3. unless authDebug: `authorizeAs(principal, roles, action, resource, AuthzContext(channel = mcp,
//     requesterIp))`; a Deny ⇒ `common.forbidden{detail: <reason>}` carrying the RESOLVED roles.
//  4. return the roles, so the caller can put them on the audit row.
//
// 🔒 INV-A11-7 — SCOPE IS NECESSARY BUT NEVER SUFFICIENT. Step 1 can only ever REFUSE; it cannot
// admit. What the principal may do is step 3's answer, and an OAuth consent covering
// `mcp:identity:write` buys nothing if Cedar does not grant `admin.identity`. The ordering also means
// a token with the wrong scope is refused WITHOUT a role lookup or a Cedar evaluation — cheaper, and
// it is why the empty role set in step 1 is correct rather than lazy.
//
// ⚠️ Step 3 is skipped entirely under `authDebug`. That is INV-A2-16's shape: the dev bypass does not
// SKIP Cedar, it prevents Cedar from being REACHED — and note the scope check in step 1 still runs, so
// even a debug control plane enforces the OAuth scope.
//
// ⚠️ The returned roles are UNSORTED here; `auditRecord` sorts them. Kotlin does the same
// (`roles.sorted()` at the record, not at the resolver), and the split matters because the resolver's
// order is what a Cedar decision saw.
func (a *Authorizer) Authorize(ctx context.Context, rc RequestContext, capability Capability) ([]string, error) {
	if !rc.hasScope(capability.RequiredScope) {
		return nil, &authorizationError{
			err:   types.ApiError{Code: "mcp.insufficient_scope", Params: map[string]string{"scope": capability.RequiredScope}},
			roles: nil,
		}
	}
	roles, err := a.roles.Resolve(ctx, rc.Principal)
	if err != nil {
		// Kotlin's resolve() throws on a DB failure and the exception escapes `authorize`, landing in
		// the tool handler's catch-all as `mcp.internal_error`. Returning the raw error reaches the
		// same arm — it is neither an authorizationError nor a management failure.
		return nil, err
	}
	if !a.authDebug {
		channel := string(query.ChannelMCP)
		decision := a.cedar.AuthorizeAs(rc.Principal, roles, capability.Action, capability.Resource, authz.AuthzContext{
			Channel:     &channel,
			RequesterIP: rc.RequesterIP,
		})
		if !decision.Allowed {
			return nil, &authorizationError{
				err:   types.ApiError{Code: "common.forbidden", Params: map[string]string{"detail": decision.Reason}},
				roles: roles,
			}
		}
	}
	return roles, nil
}

// ---------------------------------------------------------------------------------------------
// A11 §4 — `mcpAuditRecord`, shared by every audit write in this area.
// ---------------------------------------------------------------------------------------------

// auditRecord is `private fun mcpAuditRecord(context, capability, roles, datasource, detail, decision,
// outcome)`.
//
// Every field below is asserted by some case in `McpServerDbTest`, and three of them are the reason
// an MCP row is recognisable in the trail at all:
//
//	statement      "[MCP <toolName>]"   — the bracketed literal is how the suites select MCP rows
//	channel        "mcp"                — query.ChannelMCP.contextValue
//	authzResource  System::"system"     — a STRING LITERAL in the Kotlin, not marshalled from the
//	                                      AuthzResource, so it stays "System" even if a capability
//	                                      ever carried a different resource. Reproduced verbatim.
//
// 🔒 `roles.sorted()` — the row records the resolved roles in SORTED order, so two runs of the same
// call produce byte-identical rows and the audit hash chain (A8) is stable. The resolver's own order
// is deliberately not preserved.
//
// `datasource` is [safeDatasource]'s answer, which is `"control-plane"` for 36 of the 38 tools.
func auditRecord(
	rc RequestContext,
	capability Capability,
	roles []string,
	datasource string,
	detail string,
	decision types.Decision,
	outcome string,
) types.AuditEvent {
	event := types.NewAuditEvent(rc.Principal, datasource, "[MCP "+capability.ToolName+"]", decision)
	sorted := append([]string{}, roles...)
	sort.Strings(sorted)
	event.Roles = sorted
	event.ClientAddr = rc.RequesterIP
	event.Detail = &detail
	event.Channel = types.Ptr(string(query.ChannelMCP))
	event.AuthzAction = types.Ptr(capability.Action.CedarID())
	event.AuthzResource = types.Ptr(`System::"system"`)
	event.Outcome = &outcome
	return event
}

// mutationDetail is `private fun mutationDetail(tool, args)`:
//
//	buildString {
//	    append(tool)
//	    targetKeys.mapNotNull { key -> args[key] as string? -> "$key=$it" }
//	        .joinToString(",", prefix = " ").takeIf { it.isNotBlank() }?.let(::append)
//	}
//
// 🔒 IT IS A FIXED KEY LIST, NEVER THE WHOLE ARGUMENT OBJECT. `cedarSrc`, `email`, `displayName`,
// `tags` and `maskFnName` are all absent from it by construction, so a policy body or an email address
// cannot land in the audit trail through this path. Widening the list is a data-exposure change.
//
// ⚠️ The `prefix = " "` is applied by joinToString BEFORE the `isNotBlank` test, so when no target key
// is present the candidate string is `" "` — blank — and NOTHING is appended, not even the space. The
// detail for such a call is the bare tool name. Reproduced exactly; a naive port that appended
// `" " + joined` would emit a trailing space on every argument-less tool.
//
// ⚠️ Only STRING primitives contribute. A `datasource` passed as an object is silently skipped rather
// than rendered or rejected — which is what lets the audit row for a malformed-argument failure still
// be written (McpServerDbTest case 5's `set_column_classification` with an object `datasource`).
func mutationDetail(tool string, args argValue) string {
	targetKeys := []string{"datasource", "name", "principal", "groupName", "roleName", "table", "column"}
	parts := make([]string, 0, len(targetKeys))
	for _, key := range targetKeys {
		if v, ok := args.stringPrimitive(key); ok {
			parts = append(parts, key+"="+v)
		}
	}
	if len(parts) == 0 {
		return tool
	}
	out := tool + " "
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

// classificationTools is `setOf("set_column_classification", "clear_column_classification")` —
// [safeDatasource]'s allowlist.
var classificationTools = map[string]struct{}{
	"set_column_classification":   {},
	"clear_column_classification": {},
}

// safeDatasource is `private fun safeDatasource(capability, args)`.
//
// 🔒 The real datasource name reaches `audit_event.datasource` for EXACTLY TWO TOOLS — the two that
// act on a datasource's columns. Everything else audits as the literal `"control-plane"`, even when
// the arguments happen to carry a `datasource` key, because `audit_event.datasource` is a scoping
// column the console filters and the per-datasource audit views read: attributing
// `list_role_assignments` to whatever string a client put in an undeclared argument would let a caller
// choose which datasource's trail their action appears in.
//
// A blank or non-string `datasource` falls back to `"control-plane"` rather than writing an empty
// scope.
func safeDatasource(capability Capability, args argValue) string {
	if _, ok := classificationTools[capability.ToolName]; !ok {
		return "control-plane"
	}
	if v, ok := args.stringPrimitive("datasource"); ok && !isBlank(v) {
		return v
	}
	return "control-plane"
}
