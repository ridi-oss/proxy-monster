package mcp

import (
	"context"
	"errors"
	"fmt"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/management"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A11 §5 — tool dispatch: a FRESH Server per request, and the READ/WRITE split.
// ---------------------------------------------------------------------------------------------

// serverName / serverVersion are `Implementation("proxy-monster-access-control", "1.0.0")`. Both are
// wire-visible in the `initialize` response's `serverInfo`.
const (
	serverName    = "proxy-monster-access-control"
	serverVersion = "1.0.0"
)

// MaskFns is `core.policyStore.getMaskFnByName(name, connection)` — the ONE store read
// `set_column_classification` does outside the management layer, to turn a mask-function NAME into
// the id the classification row stores. *policy.PolicyStore satisfies it.
//
// ⚠️ It goes to the STORE, not to PolicyService.GetMaskFnByNameManaged, and the difference is
// observable: the store returns nil for an unknown name, and the tool raises
// `common.not_found{resource: "mask function"}` ITSELF (McpServer.kt:491), whereas the management
// method would raise the same code from a different call site. Reproduced through the store so the
// error stays this file's.
type MaskFns interface {
	GetMaskFnByNameOn(ctx context.Context, c store.Queryer, name string) (*policy.MaskFn, error)
}

// Services is the three A11 §8 management services plus the one narrow store seam a tool body reaches
// past them for.
//
// 🔒 ONE INSTANCE OF EACH, SHARED WITH THE REST SURFACE (INV-A1-1). PolicyService in particular
// carries the CedarPolicyStore whose post-commit version counter INV-A11-31 bumps; a second instance
// would bump a counter nobody reads.
//
// ⚠️ THE MCP SURFACE IS NAME-KEYED THROUGHOUT while REST is id-keyed, which is why every call below is
// a `…ByName…On` overload. A11 §8: "~28 methods over Cedar policies, roles, assignments, and mask
// functions — each in name-keyed, id-keyed, and connection-taking variants (the MCP surface is
// name-keyed, REST is id-keyed)." A tool that reached for an id-keyed overload would be asking the
// client to know a database id.
type Services struct {
	Datasources *management.DatasourceService
	Policies    *management.PolicyService
	Identities  *management.IdentityService
	// MaskFns is the raw policy store — see [MaskFns].
	MaskFns MaskFns
}

// newServer is `private fun createMcpServer(...)`: a FRESH `Server` per request.
//
// 🔒 THE PER-REQUEST CONSTRUCTION IS THE STATELESS STREAMABLE-HTTP MODEL, not an efficiency choice.
// The server closes over THIS request's [RequestContext] and locale, so the identity a tool acts under
// is bound at construction and cannot be confused with another in-flight request's. Verified this
// session that the Go SDK supports it: `NewStreamableHTTPHandler(getServer func(*http.Request)
// *Server, …)` calls getServer per request, and `StreamableHTTPOptions.Stateless` turns off session
// ids entirely — D18/§11 Q7 answered YES.
//
// Every tool gets:
//   - `description` from the `mcp_tools` bundle in the REQUEST's locale (so `Accept-Language: ko`
//     changes what `tools/list` returns);
//   - `inputSchema` from [schemaFor], the same function `validateArguments` reads (INV-A11-16);
//   - four annotation hints, two stored and two DERIVED:
//     `idempotentHint = classification == READ` and
//     🔒 INV-A11-13 `openWorldHint = toolName == "get_table_detail"` — TRUE FOR EXACTLY ONE TOOL,
//     because it reaches the live target database through the proxy rather than reading the CP store.
//
// `Server.AddTool` (the low-level, untyped form) is used rather than the generic `mcp.AddTool`,
// because the generic one infers a schema from a Go type and validates against it — which would put a
// SECOND schema authority next to schemaFor and break INV-A11-16's no-drift property.
func (rt *Routes) newServer(rc RequestContext, locale Locale, ctl *responseControl) (*sdk.Server, error) {
	server := sdk.NewServer(
		&sdk.Implementation{Name: serverName, Version: serverVersion},
		&sdk.ServerOptions{Capabilities: &sdk.ServerCapabilities{Tools: &sdk.ToolCapabilities{ListChanged: false}}},
	)
	for _, capability := range Entries {
		description, err := toolDescription(capability.ToolName, locale)
		if err != nil {
			// `ResourceBundle.getString` throws MissingResourceException while BUILDING the server,
			// before any tool runs, so the whole request fails rather than one tool misbehaving.
			return nil, err
		}
		destructive := capability.Annotations.DestructiveHint
		openWorld := capability.ToolName == "get_table_detail"
		schema := schemaFor(capability.ToolName)
		server.AddTool(&sdk.Tool{
			Name:        capability.ToolName,
			Description: description,
			InputSchema: schema,
			Annotations: &sdk.ToolAnnotations{
				ReadOnlyHint:    capability.Annotations.ReadOnlyHint,
				DestructiveHint: &destructive,
				IdempotentHint:  capability.Classification == ClassificationRead,
				OpenWorldHint:   &openWorld,
			},
		}, rt.handlerFor(capability, rc, locale, ctl))
	}
	return server, nil
}

// handlerFor is the Kotlin's per-tool lambda: the READ/WRITE fork plus the five-arm catch chain.
//
// 🔒 INV-A11-14 — READ AND WRITE HAVE DIFFERENT AUDIT SHAPES. A successful READ writes NO audit row
// (only a denial does, via [Routes.authorizeRead]); a WRITE always writes one. `list_datasources` on
// every tool refresh would otherwise flood the trail — and the trail is what an auditor reads to find
// changes.
//
// The catch chain, in the Kotlin's order:
//
//	CedarValidationManagementException  ⇒ isError, body `{errors: [...]}` — the validator's RAW array
//	McpAuthorizationException           ⇒ localizedError(error, metadataUri)
//	ManagementException                 ⇒ localizedError(error, metadataUri)
//	McpInputException                   ⇒ localizedError(mcp.invalid_request)   [no metadata]
//	any Exception                       ⇒ localizedError(mcp.internal_error)    [no metadata]
//
// ⚠️ The Cedar-validation arm is the ONE failure that is not an ApiError: its body is a bare
// `{errors: [...]}` so the policy editor can render the compiler's output line by line. Folding it
// into an ApiError param would both lose the array and put compiler prose into a field the web treats
// as an i18n interpolation.
//
// ⚠️ The last arm catches EVERYTHING, including a database failure, and reports `mcp.internal_error`
// with no detail. That is deliberate: an MCP client is a language model, and a raw driver message is
// both useless to it and a disclosure risk.
func (rt *Routes) handlerFor(capability Capability, rc RequestContext, locale Locale, ctl *responseControl) sdk.ToolHandler {
	return func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		args, err := parseArguments(req.Params.Arguments)
		if err != nil {
			// The Kotlin SDK refuses a non-object `arguments` during deserialization, before the
			// handler exists. Returning the error produces the same protocol-level failure here.
			return nil, err
		}

		payload, err := rt.invoke(ctx, capability, rc, args)
		if err == nil {
			return toolResult(payload), nil
		}

		var cedarErr *management.CedarValidationError
		if errors.As(err, &cedarErr) {
			return cedarValidationResult(cedarErr)
		}
		var authErr *authorizationError
		if errors.As(err, &authErr) {
			return rt.localizedError(ctl, locale, authErr.err, true)
		}
		var mgmtErr *management.Error
		if errors.As(err, &mgmtErr) {
			return rt.localizedError(ctl, locale, mgmtErr.Err, true)
		}
		if errors.Is(err, errInvalidInput) {
			return rt.localizedError(ctl, locale, types.ApiError{Code: "mcp.invalid_request"}, false)
		}
		rt.log.Error("mcp tool failed", "tool", capability.ToolName, "principal", rc.Principal, "err", err)
		return rt.localizedError(ctl, locale, types.ApiError{Code: "mcp.internal_error"}, false)
	}
}

// invoke is the `if (classification == READ) … else …` fork.
//
// ⚠️ THE READ PATH'S ORDER IS authorize → validate → execute, and the WRITE path's is
// authorize → validate → transaction, with authorize and validate INSIDE the executor. So a READ with
// an unknown argument is refused only AFTER its authorization check, and audits nothing extra; a WRITE
// with the same problem audits `mcp.invalid_request`. That asymmetry follows from INV-A11-14 and is
// reproduced rather than smoothed.
func (rt *Routes) invoke(ctx context.Context, capability Capability, rc RequestContext, args argValue) ([]byte, error) {
	if capability.Classification == ClassificationRead {
		if err := rt.authorizeRead(ctx, rc, capability, args); err != nil {
			return nil, err
		}
		if err := validateArguments(capability, args); err != nil {
			return nil, err
		}
		return rt.executeRead(ctx, capability.ToolName, args)
	}
	return rt.executeWrite(ctx, capability, rc, args)
}

// authorizeRead is `private fun authorizeRead(context, capability, arguments, authorizer, auditStore)`.
//
// 🔒 A DENIED READ IS AUDITED; AN ALLOWED ONE IS NOT (INV-A11-14). The audit write is wrapped so its
// own failure cannot mask the authorization failure — same `runCatching` discipline as
// [MutationExecutor.auditFailure], and for the same reason.
func (rt *Routes) authorizeRead(ctx context.Context, rc RequestContext, capability Capability, args argValue) error {
	_, err := rt.authorizer.Authorize(ctx, rc, capability)
	if err == nil {
		return nil
	}
	var authErr *authorizationError
	if errors.As(err, &authErr) {
		_, _ = rt.audit.Insert(ctx, auditRecord(
			rc, capability, authErr.roles, safeDatasource(capability, args),
			mutationDetail(capability.ToolName, args), types.DecisionDeny, authErr.err.Code,
		))
	}
	return err
}

// executeRead is `private suspend fun executeRead(tool, args, datasources, policies, identities)`.
//
// ⚠️ Every arm goes through the MANAGEMENT services, never a store, so the REST and MCP transports
// answer from one implementation. The `else` arm is unreachable — the dispatcher only ever calls this
// for a READ capability, and all 14 are listed — and raises `mcp.invalid_request` rather than
// panicking, exactly as the Kotlin does.
//
// ⚠️ `list_role_assignments` takes TWO OPTIONAL filters through `args.string(...)`, so an absent
// filter and an explicit null are the same thing (no filter). Both other read tools with arguments use
// `requiredString`.
func (rt *Routes) executeRead(ctx context.Context, tool string, args argValue) ([]byte, error) {
	switch tool {
	case "list_datasources":
		return structured(rt.services.Datasources.ListDatasources(ctx))
	case "get_datasource_liveness":
		name, err := args.requiredString("datasource")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Datasources.GetDatasourceLiveness(ctx, name))
	case "browse_catalog":
		name, err := args.requiredString("datasource")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Datasources.BrowseCatalog(ctx, name))
	case "get_table_detail":
		name, err := args.requiredString("datasource")
		if err != nil {
			return nil, err
		}
		schema, err := args.requiredString("schema")
		if err != nil {
			return nil, err
		}
		table, err := args.requiredString("table")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Datasources.GetTableDetail(ctx, name, schema, table))
	case "list_column_tags":
		name, err := args.requiredString("datasource")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Datasources.ListColumnTags(ctx, name))
	case "list_policies":
		return structured(rt.services.Policies.ListPolicies(ctx))
	case "get_policy":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Policies.GetPolicyByName(ctx, name))
	case "validate_policy":
		src, err := args.requiredString("cedarSrc")
		if err != nil {
			return nil, err
		}
		return structuredValue(rt.services.Policies.ValidatePolicy(src))
	case "get_policy_schema":
		return structured(rt.services.Policies.PolicySchema(ctx))
	case "list_roles":
		return structured(rt.services.Policies.ListRoles(ctx))
	case "list_role_assignments":
		principal, err := args.optString("principal")
		if err != nil {
			return nil, err
		}
		roleName, err := args.optString("roleName")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Policies.ListAssignmentsByRoleName(ctx, principal, roleName))
	case "list_users":
		return structured(rt.services.Identities.ListUsers(ctx))
	case "list_groups":
		return structured(rt.services.Identities.ListGroups(ctx))
	case "list_mask_fns":
		return structured(rt.services.Policies.ListMaskFns(ctx))
	default:
		return nil, management.Fail("mcp.invalid_request", nil)
	}
}

// executeWrite is `private fun executeWrite(capability, args, context, mutations, …)`: it computes the
// audit scope and detail, then hands the whole tool body to [MutationExecutor.Execute] as a closure
// over the caller's transaction.
//
// 🔒 EVERY LINE OF THE CLOSURE RUNS ON `tx`, including the mask-function lookup, so INV-A11-10's
// "the mutation and its audit row commit together" covers the tool's reads as well as its writes. A
// tool body that reached the pool directly would read outside its own transaction and could act on a
// row its own earlier statement had already changed.
func (rt *Routes) executeWrite(ctx context.Context, capability Capability, rc RequestContext, args argValue) ([]byte, error) {
	datasourceName := safeDatasource(capability, args)
	detail := mutationDetail(capability.ToolName, args)
	return rt.mutations.Execute(ctx, rc, capability, args, datasourceName, detail,
		func(ctx context.Context, tx store.Queryer) ([]byte, error) {
			return rt.mutate(ctx, tx, capability, rc, args)
		})
}

// mutate is the `when (capability.toolName)` inside `mutations.execute`'s lambda — the 24 WRITE tools.
//
// The three shapes worth naming, because they recur:
//
//   - READ-THEN-UPDATE (`update_policy`, `update_role`, `update_user`, `update_group`,
//     `update_mask_fn`): the current row is fetched ON THE SAME TRANSACTION and its values supply the
//     defaults for every field the client omitted. 🔒 INV-A11-17 is what makes "omitted" and
//     "explicitly null" different here: `if (args.has("x")) args.string("x") else current.x`.
//   - PLAIN DELEGATION (`create_*`, `delete_*`, `assign_*`): one management call.
//   - `set_column_classification`, the only one that resolves a foreign key itself.
func (rt *Routes) mutate(
	ctx context.Context, tx store.Queryer, capability Capability, rc RequestContext, args argValue,
) ([]byte, error) {
	switch capability.ToolName {

	case "set_column_classification":
		// The mask function is resolved by NAME to an id, and an unknown name is
		// `common.not_found{resource: "mask function"}` raised HERE rather than by the store.
		var maskFnID *int64
		if name, err := args.optString("maskFnName"); err != nil {
			return nil, err
		} else if name != nil {
			fn, err := rt.services.MaskFns.GetMaskFnByNameOn(ctx, tx, *name)
			if err != nil {
				return nil, err
			}
			if fn == nil {
				return nil, management.NotFound("mask function")
			}
			maskFnID = &fn.ID
		}
		datasourceName, err := args.requiredString("datasource")
		if err != nil {
			return nil, err
		}
		schema, err := args.optString("schema")
		if err != nil {
			return nil, err
		}
		table, err := args.requiredString("table")
		if err != nil {
			return nil, err
		}
		column, err := args.requiredString("column")
		if err != nil {
			return nil, err
		}
		tags, err := args.stringSet("tags")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Datasources.SetColumnClassificationByNameOn(
			ctx, tx, datasourceName, schema, table, column, tags, maskFnID))

	case "clear_column_classification":
		datasourceName, err := args.requiredString("datasource")
		if err != nil {
			return nil, err
		}
		schema, err := args.optString("schema")
		if err != nil {
			return nil, err
		}
		table, err := args.requiredString("table")
		if err != nil {
			return nil, err
		}
		column, err := args.requiredString("column")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Datasources.ClearColumnClassificationByNameOn(
			ctx, tx, datasourceName, schema, table, column))

	case "create_policy":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		src, err := args.requiredString("cedarSrc")
		if err != nil {
			return nil, err
		}
		// `args.boolean("enabled") ?: true` — absent OR explicitly null means enabled.
		enabled := true
		if v, err := args.boolean("enabled"); err != nil {
			return nil, err
		} else if v != nil {
			enabled = *v
		}
		return structured(rt.services.Policies.CreatePolicyByNameOn(ctx, tx, name, src, enabled, &rc.Principal))

	case "update_policy":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		current, err := rt.services.Policies.GetPolicyByNameOn(ctx, tx, name)
		if err != nil {
			return nil, err
		}
		newName, err := args.optString("newName")
		if err != nil {
			return nil, err
		}
		src, err := args.requiredString("cedarSrc")
		if err != nil {
			return nil, err
		}
		// `if (args.has("enabled")) args.boolean("enabled") ?: current.enabled else current.enabled`
		// — three-way: omitted keeps, explicit null ALSO keeps, an actual boolean sets. The
		// null-keeps arm is why this cannot collapse to `boolean() ?: current`.
		enabled := current.Enabled
		if args.has("enabled") {
			if v, err := args.boolean("enabled"); err != nil {
				return nil, err
			} else if v != nil {
				enabled = *v
			}
		}
		return structured(rt.services.Policies.UpdatePolicyByNameOn(
			ctx, tx, current.Name, newName, src, enabled, &rc.Principal))

	case "enable_policy", "disable_policy":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Policies.SetPolicyEnabledByNameOn(
			ctx, tx, name, capability.ToolName == "enable_policy", &rc.Principal))

	case "delete_policy":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Policies.DeletePolicyByNameOn(ctx, tx, name))

	case "create_role":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		description, err := args.optString("description")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Policies.CreateRoleByNameOn(ctx, tx, name, description))

	case "update_role":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		current, err := rt.services.Policies.GetRoleByNameManaged(ctx, tx, name)
		if err != nil {
			return nil, err
		}
		newName, err := args.optString("newName")
		if err != nil {
			return nil, err
		}
		description := current.Description
		if args.has("description") {
			if description, err = args.optString("description"); err != nil {
				return nil, err
			}
		}
		return structured(rt.services.Policies.UpdateRoleByNameOn(ctx, tx, current.Name, newName, description))

	case "delete_role":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Policies.DeleteRoleByNameOn(ctx, tx, name))

	case "assign_role":
		principal, err := args.requiredString("principal")
		if err != nil {
			return nil, err
		}
		roleName, err := args.requiredString("roleName")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Policies.AssignRoleByNameOn(ctx, tx, principal, roleName))

	case "unassign_role":
		principal, err := args.requiredString("principal")
		if err != nil {
			return nil, err
		}
		roleName, err := args.requiredString("roleName")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Policies.UnassignRoleByNameOn(ctx, tx, principal, roleName))

	case "create_user":
		principal, err := args.requiredString("principal")
		if err != nil {
			return nil, err
		}
		displayName, err := args.optString("displayName")
		if err != nil {
			return nil, err
		}
		email, err := args.optString("email")
		if err != nil {
			return nil, err
		}
		active := true
		if v, err := args.boolean("active"); err != nil {
			return nil, err
		} else if v != nil {
			active = *v
		}
		return structured(rt.services.Identities.CreateUserOn(ctx, tx, identity.AppUserInput{
			Principal: principal, DisplayName: displayName, Email: email, Active: active,
		}))

	case "update_user":
		principal, err := args.requiredString("principal")
		if err != nil {
			return nil, err
		}
		current, err := rt.services.Identities.GetUserOn(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		newPrincipal, err := args.optString("newPrincipal")
		if err != nil {
			return nil, err
		}
		displayName := current.DisplayName
		if args.has("displayName") {
			if displayName, err = args.optString("displayName"); err != nil {
				return nil, err
			}
		}
		email := current.Email
		if args.has("email") {
			if email, err = args.optString("email"); err != nil {
				return nil, err
			}
		}
		active := current.Active
		if args.has("active") {
			if v, err := args.boolean("active"); err != nil {
				return nil, err
			} else if v != nil {
				active = *v
			}
		}
		return structured(rt.services.Identities.UpdateUserByPrincipalOn(
			ctx, tx, current.Principal, newPrincipal, displayName, email, active))

	case "deprovision_user":
		principal, err := args.requiredString("principal")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Identities.DeprovisionUserOn(ctx, tx, principal))

	case "create_group":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		description, err := args.optString("description")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Identities.CreateGroupOn(ctx, tx, identity.AppGroupInput{
			Name: name, Description: description,
		}))

	case "update_group":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		current, err := rt.services.Identities.GetGroupOn(ctx, tx, name)
		if err != nil {
			return nil, err
		}
		newName, err := args.optString("newName")
		if err != nil {
			return nil, err
		}
		description := current.Description
		if args.has("description") {
			if description, err = args.optString("description"); err != nil {
				return nil, err
			}
		}
		return structured(rt.services.Identities.UpdateGroupByNameOn(ctx, tx, current.Name, newName, description))

	case "delete_group":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Identities.DeleteGroupByNameOn(ctx, tx, name))

	case "add_group_member":
		groupName, err := args.requiredString("groupName")
		if err != nil {
			return nil, err
		}
		principal, err := args.requiredString("principal")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Identities.AddGroupMemberByNameOn(ctx, tx, groupName, principal))

	case "remove_group_member":
		groupName, err := args.requiredString("groupName")
		if err != nil {
			return nil, err
		}
		principal, err := args.requiredString("principal")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Identities.RemoveGroupMemberByNameOn(ctx, tx, groupName, principal))

	case "set_group_roles":
		groupName, err := args.requiredString("groupName")
		if err != nil {
			return nil, err
		}
		roleNames, err := args.stringSet("roleNames")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Identities.SetGroupRolesOn(ctx, tx, groupName, roleNames))

	case "create_mask_fn":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		kind, err := args.requiredString("kind")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Policies.CreateMaskFnOn(ctx, tx, policy.MaskFnInput{Name: name, Kind: kind}))

	case "update_mask_fn":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		current, err := rt.services.Policies.GetMaskFnByNameManaged(ctx, tx, name)
		if err != nil {
			return nil, err
		}
		newName, err := args.optString("newName")
		if err != nil {
			return nil, err
		}
		kind, err := args.requiredString("kind")
		if err != nil {
			return nil, err
		}
		// ⚠️ `args.string("newName") ?: current.name` — NOT the has()/else pattern the other update
		// tools use. An explicit `"newName": null` therefore keeps the current name here, where on
		// `update_user` an explicit null CLEARS the field. The inconsistency is the Kotlin's.
		resolvedName := current.Name
		if newName != nil {
			resolvedName = *newName
		}
		return structured(rt.services.Policies.UpdateMaskFnByNameOn(
			ctx, tx, current.Name, policy.MaskFnInput{Name: resolvedName, Kind: kind}))

	case "delete_mask_fn":
		name, err := args.requiredString("name")
		if err != nil {
			return nil, err
		}
		return structured(rt.services.Policies.DeleteMaskFnByNameOn(ctx, tx, name))

	default:
		return nil, management.Fail("mcp.invalid_request", nil)
	}
}

// ---------------------------------------------------------------------------------------------
// Result and error envelopes
// ---------------------------------------------------------------------------------------------

// resultEnvelope is `structured(value) = buildJsonObject { put("result", encoded) }`.
type resultEnvelope struct {
	Result any `json:"result"`
}

// structured wraps a `(T, error)` pair, which is how every management call returns, so a tool body
// reads `return structured(service.Whatever(...))` exactly as the Kotlin reads
// `structured(service.whatever(...))`.
func structured[T any](value T, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return structuredValue(value)
}

// structuredValue is the same envelope for a call that cannot fail.
//
// 🔒 It encodes through types.MarshalWire, NOT json.Marshal: kotlinx does not HTML-escape, and
// `cedarSrc` in a policy body is full of `<` and `>` on essentially every condition the product exists
// to express. See MarshalWire's own note.
//
// ⚠️ The JSON-RPC envelope AROUND this value is marshalled by the MCP SDK with encoding/json's
// defaults, so `<`, `>` and `&` ARE escaped there — a byte-level divergence from the Kotlin that
// cannot be closed without vendoring the SDK's encoder. Semantically identical JSON; recorded rather
// than hidden.
func structuredValue(value any) ([]byte, error) {
	return types.MarshalWire(resultEnvelope{Result: value})
}

// toolResult is `CallToolResult(content = [TextContent(structured.toString())], structuredContent =
// structured)` — THE SAME JSON TWICE, once as text and once as structure.
//
// The duplication is the MCP protocol's, not this port's: `structuredContent` is the machine-readable
// half and `content` is what a client that predates it renders. Both are built from the same bytes
// here so they cannot disagree.
func toolResult(payload []byte) *sdk.CallToolResult {
	return &sdk.CallToolResult{
		Content:           []sdk.Content{&sdk.TextContent{Text: string(payload)}},
		StructuredContent: rawJSON(payload),
	}
}

// rawJSON hands pre-encoded bytes to the SDK's marshaller. json.RawMessage is passed through as-is
// (modulo the outer encoder's HTML escaping, noted on structuredValue).
func rawJSON(payload []byte) any { return jsonRaw(payload) }

type jsonRaw []byte

func (r jsonRaw) MarshalJSON() ([]byte, error) {
	if len(r) == 0 {
		return []byte("null"), nil
	}
	return r, nil
}

// cedarValidationResult is the `CedarValidationManagementException` arm:
// `buildJsonObject { put("errors", JsonArray(e.errors.map(::JsonPrimitive))) }`, isError = true.
//
// 🔒 The array is the validator's RAW output, one element per compiler diagnostic, and it is emitted
// with NO `code`, NO `params` and NO localization — it is the one MCP failure that is not an ApiError.
// It also does NOT set an HTTP status: a policy that fails validation is a 200 with `isError`, because
// the request itself was well-formed and authorized.
func cedarValidationResult(e *management.CedarValidationError) (*sdk.CallToolResult, error) {
	errs := e.Errors
	if errs == nil {
		// INV-A1-4: an empty validator array is `[]`, never `null`.
		errs = []string{}
	}
	payload, err := types.MarshalWire(struct {
		Errors []string `json:"errors"`
	}{Errors: errs})
	if err != nil {
		return nil, err
	}
	return &sdk.CallToolResult{
		Content:           []sdk.Content{&sdk.TextContent{Text: string(payload)}},
		IsError:           true,
		StructuredContent: rawJSON(payload),
	}, nil
}

// errorBody is `localizedError`'s object, in its `buildJsonObject` insertion order — code, params,
// message_en, message_ko. The order is wire-visible in the `content[0].text` rendering.
type errorBody struct {
	Code      string            `json:"code"`
	Params    map[string]string `json:"params"`
	MessageEN string            `json:"message_en"`
	MessageKO string            `json:"message_ko"`
}

// localizedError is `private fun localizedError(call, error, metadataUri?)`.
//
// 🔒 INV-A11-15 — BOTH LOCALES, INLINE. REST answers a bare code for `web/` to look up (INV-A1-13);
// an MCP client has no message catalog, so the server resolves `message_en` AND `message_ko` from the
// `mcp_errors` bundle and ships them in the body. `docs/l10n.md`'s rule is satisfied differently on
// each transport, and this is the difference.
//
// Two HTTP side effects, on a JSON-RPC RESULT rather than an error — which is legal because the
// stateless streamable transport writes the HTTP response after the handler returns:
//
//   - status 403 for `mcp.insufficient_scope` AND `common.forbidden`. Everything else stays 200: a
//     not-found or a validation failure is a successful tool call reporting a failure.
//   - for insufficient scope only, `WWW-Authenticate: Bearer error="insufficient_scope", scope="<s>",
//     resource_metadata="<uri>"`, which is how a client learns WHICH scope to ask for and where the
//     resource metadata lives. RFC 9728's discovery loop depends on it.
//
// ⚠️ `requireNotNull(metadataUri)` — the Kotlin THROWS if an insufficient-scope error arrives without
// a metadata URI. Unreachable (the two arms that omit it are `mcp.invalid_request` and
// `mcp.internal_error`), and reproduced as a returned error rather than a nil-pointer challenge
// header.
//
// ⚠️ A missing bundle key propagates as an error, which the SDK turns into a JSON-RPC protocol error —
// see [errMissingBundleKey].
func (rt *Routes) localizedError(ctl *responseControl, locale Locale, e types.ApiError, withMetadata bool) (*sdk.CallToolResult, error) {
	if e.Code == "mcp.insufficient_scope" || e.Code == "common.forbidden" {
		ctl.setStatus(403)
	}
	if e.Code == "mcp.insufficient_scope" {
		if !withMetadata {
			return nil, fmt.Errorf("mcp: insufficient_scope error raised without a metadata URI")
		}
		ctl.setHeader("WWW-Authenticate", fmt.Sprintf(
			"Bearer error=\"insufficient_scope\", scope=\"%s\", resource_metadata=\"%s\"",
			e.Params["scope"], rt.metadataURI))
	}
	en, err := messageFor(e, LocaleEnglish)
	if err != nil {
		return nil, err
	}
	ko, err := messageFor(e, LocaleKorean)
	if err != nil {
		return nil, err
	}
	params := e.Params
	if params == nil {
		params = map[string]string{}
	}
	payload, err := types.MarshalWire(errorBody{Code: e.Code, Params: params, MessageEN: en, MessageKO: ko})
	if err != nil {
		return nil, err
	}
	// `locale` is deliberately unused for the BODY: both messages are always emitted regardless of
	// what the client asked for. It selects the tool DESCRIPTIONS only. Named here so the parameter's
	// presence is not read as a bug.
	_ = locale
	return &sdk.CallToolResult{
		Content:           []sdk.Content{&sdk.TextContent{Text: string(payload)}},
		IsError:           true,
		StructuredContent: rawJSON(payload),
	}, nil
}
