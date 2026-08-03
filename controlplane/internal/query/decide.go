package query

import (
	"context"
	"errors"
	"strings"

	probepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/datasource"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/engine"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
)

// ---- the seams ------------------------------------------------------------------------------

// RoleResolver is the one method step 6 calls — `roleResolver.resolve(principal)`
// (RoleResolver.kt:48). *identity.RoleResolver satisfies it structurally.
type RoleResolver interface {
	Resolve(ctx context.Context, principal string) ([]string, error)
}

// UserGroupStore is the one method step 5 calls — `userGroupStore.isDeactivated(principal)`
// (Users.kt:647). *identity.UserGroupStore satisfies it structurally.
type UserGroupStore interface {
	IsDeactivated(ctx context.Context, principal string) (bool, error)
}

// MaskFn is the (name, kind) pair step 19 reads off a `mask_fn` row. It carries no id because
// `listMaskFns().associate { it.name to it.kind }` (Query.kt:569) reads exactly these two columns.
type MaskFn struct {
	Name string
	Kind string
}

// MaskFnLister is step 19's seam — `policyStore.listMaskFns()`.
//
// See doc.go on why the seams are structural rather than concrete: naming policy.MaskFn here would
// make internal/query import internal/policy, and internal/policy's IN-PACKAGE DB test imports
// internal/dbtest, so `policy [policy.test] → dbtest → query → policy` would be an import cycle and
// every A6 DB suite would stop building.
//
// An error from the lister reproduces the Kotlin's thrown SQLException: step 19 catches it and
// returns `structuralDeny(CATALOG_CONFIGURATION_DENY, stage="catalog", catalogMiss=true)`.
type MaskFnLister func(ctx context.Context) ([]MaskFn, error)

// SystemClassifier is the shipped system classifier, as decideQuery consumes it —
// SystemClassificationService's three lookup methods (05-datasources-catalog.md §7).
// *datasource.SystemClassificationService satisfies it structurally.
//
// A NIL value means "no manifest governs anything": no system tags are marshalled, so system schemas
// stay deny-by-default and step 13 hard-denies every utility. Pass a genuinely nil interface — a
// typed nil pointer in a non-nil interface is NOT nil and would panic on the first call.
type SystemClassifier interface {
	TagForTable(e datasource.Engine, engineVersion *string, catalog, schema, table string) (string, bool)
	TagForFunction(e datasource.Engine, engineVersion *string, name string) (string, bool)
	TagForCommand(e datasource.Engine, engineVersion *string, command string) (string, bool)
}

// DecideQueryInput is `decideQuery`'s parameter list (Query.kt:271-306) as a named-field struct.
//
// ⚠️ LANGUAGE-FORCED DEVIATION: Kotlin gives seven of the seventeen parameters DEFAULT VALUES, which
// Go has no equivalent for. A struct expresses them exactly — every Kotlin default is the
// corresponding Go zero value (nil pointer = null, nil slice = emptyList(), false = false) — and it
// answers 06-query-decision.md §8 Q2's "confirm no test binds positionally" BY CONSTRUCTION: a Go
// struct literal with field names cannot silently rebind arguments when a parameter is dropped.
//
// ⚠️ F12 — **OMIT.** The Kotlin's `accessStore: AccessStore` parameter is never read in the body
// (Query.kt:278), so it has no observable behaviour and is not carried here. 00-INDEX.md records the
// disposition; this is the "confirm first" half discharged.
type DecideQueryInput struct {
	Principal  string
	Datasource datasource.Datasource
	SQL        string
	Channel    Channel
	// Catalog is the datasource's persisted config catalog.
	Catalog []datasource.CatalogColumn

	// MaskFns / UserGroups / Roles are the three store seams (see above). Authz is concrete.
	MaskFns    MaskFnLister
	UserGroups UserGroupStore
	Roles      RoleResolver
	Authz      *authz.Authz

	// ProvidedRoles is `providedRoles: Set<String>? = null`. Almost always nil (resolve server-side
	// at step 6). Tests that already resolved roles once and want decideQuery and
	// authz.AuthorizeColumns to see the EXACT same set may pass them explicitly.
	//
	// ⚠️ It is a POINTER TO A SLICE because Kotlin's `Set<String>?` distinguishes null ("resolve")
	// from the EMPTY set ("this principal has no roles"), and a plain nil slice cannot: a deactivated
	// principal legitimately resolves to the empty set.
	ProvidedRoles *[]string

	// Context is `context: AuthzContext = AuthzContext()` — the CALLER's raw context. Its `channel`
	// and `tags` are both overwritten by [EffectiveAuthzContext] (INV-A6-16).
	Context authz.AuthzContext

	// LiveSearchPath is the wire connection's live effective namespace, probed as PostgreSQL
	// search_path or MySQL current database by the proxy. Nil resolves under ds.DefaultSchemas
	// (editor / callers that supply no live namespace). A NON-NIL EMPTY slice is a distinct,
	// fail-closed state — see step 1 — which is why this is a pointer.
	LiveSearchPath *[]string

	// LiveAnsiQuotes is whether the wire connection's live MySQL sql_mode has ANSI_QUOTES active
	// (observed per statement). Forwarded to the analyzer's EngineConfig so a masked column quoted
	// with `"` is parsed as the column and still masked; false for PostgreSQL and default MySQL mode.
	LiveAnsiQuotes bool

	// SystemClassification is the shipped classifier, or nil. See [SystemClassifier].
	SystemClassification SystemClassifier

	// TempColumns is the connection's session/temp columns (proxy-introspected off its held
	// connection), overlaid onto the base catalog so a bare name resolves to the temp the backend
	// binds. Empty for one-shot / wire.
	//
	// 🔒 INV-A6-11 — a row reaching step 24 with IsTemp set is forced UNMASKED, BYPASSING column
	// authz. Only this overlay may set it (INV-A5-1); a base-catalog column carrying IsTemp would
	// turn every column into an ungranted cleartext read.
	TempColumns []datasource.CatalogColumn

	// FactsOverride is the TEST-ONLY seam. When non-nil the grant walk runs over these StatementFacts
	// instead of analyzing SQL — the ONLY way to exercise the fail-closed contract branches
	// (UNSPECIFIED action/disposition/class, invalid ordinal, malformed grant) that a resolved Go
	// analyzer can never emit. Production callers leave it nil; the catalog and analyzer are STILL
	// built, so column-grant resolution stays real.
	FactsOverride *probepb.StatementFacts
}

// EffectiveAuthzContext builds the effective request context for a decision (docs/authz-context.md).
// Port of `internal fun effectiveAuthzContext` (Query.kt:249-260):
//
//	raw = caller.copy(channel = channel.contextValue)
//	return raw.copy(tags = authz.resolveContextTags(principal, roles, datasource, raw, datasourceTags))
//
// 🔒 INV-A6-16 — `channel` AND `tags` are both AUTHORITATIVE OVERWRITES. channel overrides any
// caller-supplied value; tags is derived by pass-1 and OVERWRITES any caller-supplied value. So
// neither is ever client-asserted, even if a caller (or a client upstream) puts them in the context.
// Raw inputs the control plane attests — RequesterIP, NetworkZones — are PRESERVED from the caller.
//
// Pass-1 runs over the CHANNEL-OVERLAID raw context with tags omitted (no recursion — A2 INV-A2-12).
// TagResolutionTest case 8 pins it.
func EffectiveAuthzContext(
	caller authz.AuthzContext,
	channel Channel,
	az *authz.Authz,
	principal string,
	roles []string,
	ds string,
	datasourceTags []string,
) authz.AuthzContext {
	raw := caller
	value := channel.ContextValue()
	raw.Channel = &value
	return raw.WithTags(az.ResolveContextTags(principal, roles, ds, raw, datasourceTags))
}

// resolvedStatementClasses is Query.kt:710-714. A resolved statement always classifies as one of
// these; anything else (UNSPECIFIED, or an unrecognised number) on a resolved fact is a malformed
// analyzer contract and fails closed at step 9.
var resolvedStatementClasses = map[probepb.StatementClass]bool{
	probepb.StatementClass_STATEMENT_CLASS_ANALYZED: true,
	probepb.StatementClass_STATEMENT_CLASS_METADATA: true,
	probepb.StatementClass_STATEMENT_CLASS_SESSION:  true,
}

// isMalformedDisposition is Query.kt:718-721's MALFORMED_DISPOSITIONS set, inverted for Go.
//
// A column grant must carry a REAL masking disposition; an absent or unrecognised one is a malformed
// effect the walk would otherwise treat as a plain unmasked read, so it fails closed. Kotlin
// enumerates {UNSPECIFIED, UNRECOGNIZED}; protobuf-go has no UNRECOGNIZED sentinel, so this tests
// membership of the three KNOWN-GOOD values and treats everything else as malformed — which covers
// both the proto3 zero and any unknown number.
func isMalformedDisposition(d probepb.MaskedDisposition) bool {
	switch d {
	case probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
		probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT,
		probepb.MaskedDisposition_MASKED_DISPOSITION_REDACT_OUTPUT_NULL:
		return false
	default:
		return true
	}
}

// The five oneof presence predicates — Kotlin's generated `hasColumn()`/`hasTable()`/… .
//
// ⚠️ They test the ONEOF CASE, never the value. `grant.GetDatasource()` returns the bool payload and
// is false BOTH for "no datasource resource" and for an explicitly-set `datasource = false`; only the
// oneof case distinguishes them, and step 8's "exactly one resource" count is exactly that question
// (INV-A6-10).
func hasColumn(g *probepb.RequiredGrant) bool {
	_, ok := g.GetResource().(*probepb.RequiredGrant_Column)
	return ok
}

func hasTable(g *probepb.RequiredGrant) bool {
	_, ok := g.GetResource().(*probepb.RequiredGrant_Table)
	return ok
}

func hasFunction(g *probepb.RequiredGrant) bool {
	_, ok := g.GetResource().(*probepb.RequiredGrant_Function)
	return ok
}

func hasUtility(g *probepb.RequiredGrant) bool {
	_, ok := g.GetResource().(*probepb.RequiredGrant_Utility)
	return ok
}

func hasDatasource(g *probepb.RequiredGrant) bool {
	_, ok := g.GetResource().(*probepb.RequiredGrant_Datasource)
	return ok
}

// ErrSeamNotWired is returned when a required store seam is nil. Kotlin's parameters are non-null
// types, so this state is unrepresentable there; in Go it would be a nil-pointer panic in the middle
// of the enforcement path, which is strictly worse than an error the caller must handle.
var ErrSeamNotWired = errors.New("decideQuery: required store seam is not wired")

// DecideQuery is THE enforcement decision — analysis only, no execution. Port of Query.kt:271-706.
//
// An INADMISSIBLE statement hard-denies BEFORE role resolution or any grant walk; otherwise effective
// roles (base ∪ active JIT grants ∪ group-derived roles) authorize the analyzer-emitted required
// grants in category order. Wire-safe metadata/session chatter is passthrough-classified; the wire
// and editor channels may passthrough connection-scoped (TX_CONTROL/SESSION_MUTATING) statements on
// their held connection — re-decided per statement — while the workflow and MCP channels refuse them,
// since each of their runs uses a fresh connection.
//
// # The step order is the security contract
//
// Every block below carries its `// STEP n` from 06-query-decision.md §3's ordered table, and the
// seven load-bearing orderings are named in doc.go. Do not reorder anything here without changing
// that table first.
//
// # The (DecisionContext, error) shape
//
// Kotlin returns a bare DecisionContext and lets three things THROW out of it: the engine mappings
// (`ds.engine.dialect`, `ds.engine.catalogName`), `userGroupStore.isDeactivated` and
// `roleResolver.resolve`. Those throws are observable — the caller renders a 500 / gRPC INTERNAL, not
// a DENY — so they are reproduced as an error return, following the convention
// internal/datasource/engine.go set for the same situation. Everything the Kotlin CATCHES
// (step 3's analyzer construction, step 19's listMaskFns) stays a DecisionContext, exactly as there.
func DecideQuery(ctx context.Context, in DecideQueryInput) (DecisionContext, error) {
	ds := in.Datasource

	// Query.kt:307-308 binds two locals the body never reads. `val id = ds.id` is inert and is not
	// carried. `val dialect = ds.engine.dialect` is NOT inert: its `else -> error(...)` THROWS for an
	// engine that is neither MySQL nor Postgres, before anything else in the function runs. That
	// throw is observable, so it is reproduced — as an error, never a panic (engine.go's convention).
	if _, err := datasource.EngineDialect(ds.Engine); err != nil {
		return DecisionContext{}, err
	}

	// STEP 1 — a live search path that is non-nil but EMPTY, against a non-empty catalog. The
	// connection reported a namespace it could not resolve; deny before anything is analyzed.
	if in.LiveSearchPath != nil && len(*in.LiveSearchPath) == 0 && len(in.Catalog) > 0 {
		d := structuralDeny(catalogConfigurationDeny, nil, stageCatalog, nil)
		d.CatalogMiss = true
		return d, nil
	}

	// STEP 2 — resolvedSearchPath = (liveSearchPath ?: ds.defaultSchemas).ifEmpty { [dbName|"public"] }
	resolvedSearchPath := ds.DefaultSchemas
	if in.LiveSearchPath != nil {
		resolvedSearchPath = *in.LiveSearchPath
	}
	if len(resolvedSearchPath) == 0 {
		fallback := ds.DBName
		if engine.IsBlank(fallback) {
			fallback = "public"
		}
		resolvedSearchPath = []string{fallback}
	}
	engineVersion := ds.EngineVersion
	// Query.kt:314 — OUTSIDE the try, so its `else -> error(...)` propagates rather than becoming a
	// catalog deny. Unreachable after the dialect check above, which rejects the same engines.
	catalogName, err := datasource.CatalogName(ds.Engine, ds.DBName)
	if err != nil {
		return DecisionContext{}, err
	}

	// STEP 3 — namespace + EngineConfig + effectiveCatalog + specs + analyzerFor +
	// buildCatalogColumnIndex + facts. ANY failure in this block is a catalog deny with
	// catalogMiss = true (Kotlin wraps the whole thing in one try/catch).
	catalogIndex, facts, buildErr := buildAnalyzerAndFacts(in, catalogName, resolvedSearchPath, engineVersion)
	if buildErr != nil {
		d := structuralDeny(catalogConfigurationDeny+": "+buildErr.Error(), nil, stageCatalog, nil)
		d.CatalogMiss = true
		return d, nil
	}

	// STEP 4 — admission. INADMISSIBLE, or UNSPECIFIED-and-unresolved, hard-denies HERE.
	//
	// 🔒 INV-A6-7 — this runs BEFORE role resolution (step 6) and before any grant walk. Moving
	// resolution earlier would let an inadmissible statement trigger role/grant work and — worse —
	// would change the ordering guarantee the deactivation gate depends on. No contextTags: nothing
	// has been derived yet (INV-A6-4's legitimate exception #1).
	if facts.GetFailureClass() == probepb.FailureClass_FAILURE_CLASS_INADMISSIBLE ||
		(facts.GetFailureClass() == probepb.FailureClass_FAILURE_CLASS_UNSPECIFIED && !facts.GetResolved()) {
		return structuralDeny(ifBlank(facts.GetDetail(), "statement is inadmissible"), nil, stageAdmission, nil), nil
	}

	// STEP 5 — the deactivation gate.
	//
	// 🔒 INV-A6-8 — it sits BEFORE the metadata/session passthrough dispatch (step 14), so a
	// deprovisioned principal cannot ride a readonly-meta passthrough to an ALLOW.
	// DeactivationEnforcementDbTest case 3 pins exactly this. No contextTags (exception #2).
	if in.UserGroups == nil {
		return DecisionContext{}, ErrSeamNotWired
	}
	deactivated, err := in.UserGroups.IsDeactivated(ctx, in.Principal)
	if err != nil {
		return DecisionContext{}, err
	}
	if deactivated {
		return structuralDeny(deactivatedPrincipalDeny, nil, stageDeprovisioned, nil), nil
	}

	// STEP 6 — role resolution. Deliberately AFTER admission and deactivation (INV-A6-7).
	var roles []string
	if in.ProvidedRoles != nil {
		roles = *in.ProvidedRoles
	} else {
		if in.Roles == nil {
			return DecisionContext{}, ErrSeamNotWired
		}
		resolved, rerr := in.Roles.Resolve(ctx, in.Principal)
		if rerr != nil {
			return DecisionContext{}, rerr
		}
		roles = resolved
	}
	// Kotlin's `roles.toList()`. ONE snapshot threaded through pass-1 tag derivation, every Cedar
	// call and the returned effectiveRoles, so a role revoked mid-decision cannot make the two
	// disagree (A2 INV-A2-10 states the same rule for AuthorizeWithContext).
	roleList := roles

	// STEP 7 — the effective context. channel and tags are authoritative overwrites (INV-A6-16).
	authzCtx := EffectiveAuthzContext(in.Context, in.Channel, in.Authz, in.Principal, roles, ds.Name, ds.Tags)
	derivedTags := authzCtx.Tags

	grants := facts.GetRequiredGrants()

	// STEP 8 — fail-closed contract validation: every emitted grant names EXACTLY ONE resource, and a
	// non-datasource resource grant MUST carry RESULT_READ.
	//
	// 🔒 INV-A6-10 — a grant with NO resource is INVISIBLE to the has*-filtered category walk below,
	// so it would silently ride a resolved-METADATA statement to a passthrough ALLOW. And a
	// column/table/function/utility grant with an unexpected action is a malformed effect the walk
	// would otherwise authorize as a plain read. A resolved analyzer never emits either, so both are
	// a fail-closed DENY, never a skipped grant.
	for _, g := range grants {
		count := 0
		for _, present := range []bool{hasColumn(g), hasTable(g), hasFunction(g), hasUtility(g), hasDatasource(g)} {
			if present {
				count++
			}
		}
		if count != 1 || (!hasDatasource(g) && g.GetAction() != probepb.GrantAction_GRANT_ACTION_RESULT_READ) {
			return structuralDeny("fail-closed: analyzer emitted a malformed required grant", roleList, stagePolicy, derivedTags), nil
		}
	}

	// STEPS 9-11 — contract validation continued.
	//
	// 🔒 INV-A6-9 — these run UP FRONT and INDEPENDENTLY of any later Cedar verdict, NOT only inside
	// the eventual MASKED branch, so an allowed/UNMASKED column can never ride a malformed
	// disposition or a bogus ordinal to ALLOW. StatementFactsGrantLoopTest cases 15-16 pin the
	// UNMASKED variants specifically. A resolved Go analyzer always satisfies all three.

	// STEP 9 — a resolved statement must carry a recognized statement class.
	if facts.GetResolved() && !resolvedStatementClasses[facts.GetStatementClass()] {
		return structuralDeny("fail-closed: resolved statement has no statement class", roleList, stagePolicy, derivedTags), nil
	}
	// STEP 10 — every output ordinal is an in-range index into outputColumns.
	outputColumns := facts.GetOutputColumns()
	for _, g := range grants {
		for _, ordinal := range g.GetOutputOrdinals() {
			if ordinal < 0 || int(ordinal) >= len(outputColumns) {
				return structuralDeny("invalid mask output ordinal", roleList, stageMaskBinding, derivedTags), nil
			}
		}
	}
	// STEP 11 — every column grant carries a recognized maskedDisposition.
	for _, g := range grants {
		if hasColumn(g) && isMalformedDisposition(g.GetMaskedDisposition()) {
			return structuralDeny("fail-closed: column grant has no masking disposition", roleList, stagePolicy, derivedTags), nil
		}
	}

	schemaCandidates := distinct(facts.GetSchemaQualifierCandidates())

	// The local `deny` closure (Query.kt:407-409). A policy DENY on the DATA — an uncovered table
	// scan, or the column/table verdict — fails closed: a denied query stays denied.
	//
	// 🔒 INV-A6-14 — a catalog-miss deny MUST carry the schema qualifiers. Without them the connection
	// layer cannot issue its bounded refetch of a possibly-newly-created schema, and the query stays
	// denied until an unrelated refresh (ConnectionDecide.markCatalogMiss, A5).
	deny := func(reason string, catalogMiss bool) DecisionContext {
		d := policyDeny(reason, roleList, derivedTags)
		d.CatalogMiss = catalogMiss
		d.SchemaCandidates = schemaCandidates
		return d
	}

	// STEP 12 — Cedar datasource.connect on ds.name. The first once-per-query gate.
	if !in.Authz.AuthorizeDatasourceAction(
		in.Principal, roles, authz.ActionDatasourceConnect, ds.Name, authzCtx, ds.Tags,
	).Allowed {
		return policyDeny("no access to datasource '"+ds.Name+"'", roleList, derivedTags), nil
	}

	// STEP 13 — the utility gate, in four sub-steps, each its own exit.
	var utilityGrants []*probepb.RequiredGrant
	for _, g := range grants {
		if hasUtility(g) {
			utilityGrants = append(utilityGrants, g)
		}
	}
	if len(utilityGrants) > 0 {
		// 13a — no classifier, or no engine_version, means nothing can be classified. Hard-deny.
		// 🔒 INV-A5-60 / A2 INV-A2-11: for a UTILITY, absent does NOT mean safe — an untagged Utility
		// entity (Datasource parent only, no forbid) would be PERMITTED by a datasource-scoped read
		// grant, INVERTING the decision from deny to allow. The upstream hard-deny is load-bearing.
		if in.SystemClassification == nil || engineVersion == nil || engine.IsBlank(*engineVersion) {
			return structuralDeny(
				systemUtilityDeny+" '"+utilityGrants[0].GetUtility().GetCommand()+"'",
				roleList, stagePolicy, derivedTags,
			), nil
		}
		// 13b — classify every command; keep the (command → tag) pairs that resolved.
		utilityTags := map[string]string{}
		for _, g := range utilityGrants {
			command := g.GetUtility().GetCommand()
			if tag, ok := in.SystemClassification.TagForCommand(ds.Engine, engineVersion, command); ok {
				utilityTags[command] = tag
			}
		}
		// 13c — any command that resolved no `system:` tag is hard-denied, never marshalled.
		for _, g := range utilityGrants {
			if _, ok := utilityTags[g.GetUtility().GetCommand()]; !ok {
				return structuralDeny(
					systemUtilityDeny+" '"+g.GetUtility().GetCommand()+"'",
					roleList, stagePolicy, derivedTags,
				), nil
			}
		}
		// 13d — Cedar must return USE for every one of them.
		utilRefs := make([]authz.UtilityRef, 0, len(utilityTags))
		for _, command := range utilityCommandsInOrder(utilityGrants, utilityTags) {
			utilRefs = append(utilRefs, authz.UtilityRef{Command: command})
		}
		verdicts := in.Authz.AuthorizeUtilities(in.Principal, roles, ds.Name, utilRefs, authzCtx, utilityTags, ds.Tags)
		for _, ref := range utilRefs {
			if verdicts[ref.Command] != authz.UtilityUse {
				return structuralDeny(
					systemUtilityDeny+" '"+ref.Command+"'",
					roleList, stagePolicy, derivedTags,
				), nil
			}
		}
	}

	// STEP 14 — the passthrough dispatch, for a RESOLVED statement with no column/table/function/
	// datasource grant.
	//
	// 🔒 INV-A6-8 — reached only after the deactivation gate (step 5), so a deprovisioned principal
	// cannot arrive here.
	// 🔒 INV-A6-10 — the `none { has… }` filter is exactly the walk a resourceless grant would be
	// invisible to; step 8 is what keeps one from reaching this line.
	if facts.GetResolved() && !anyGrant(grants, func(g *probepb.RequiredGrant) bool {
		return hasColumn(g) || hasTable(g) || hasFunction(g) || hasDatasource(g)
	}) {
		switch facts.GetStatementClass() {
		case probepb.StatementClass_STATEMENT_CLASS_METADATA:
			// Built as a literal, not through passthroughAllow, exactly as Query.kt:452-463 does.
			return DecisionContext{
				Action:           pb.EnfAction_ALLOW,
				DenyReason:       nil,
				Masks:            nil,
				PIITouched:       nil,
				EffectiveRoles:   roleList,
				FailedStage:      nil,
				Detail:           strptr("passthrough (readonly-meta)"),
				Passthrough:      true,
				ContextTags:      derivedTags,
				SchemaCandidates: schemaCandidates,
			}, nil
		case probepb.StatementClass_STATEMENT_CLASS_SESSION:
			// 🔒 INV-A6-2 — only a channel that HOLDS a connection may relay a session statement.
			// WORKFLOW_EXECUTOR / WORKFLOW_VIEWER / MCP each run on a FRESH connection, so the
			// session state would silently not carry. The zero Channel falls here too — fail-closed.
			if in.Channel.holdsConnection() {
				d := passthroughAllow(roleList, "passthrough (session-mutating)", derivedTags)
				d.SchemaCandidates = schemaCandidates
				return d, nil
			}
			return structuralDeny(editorSessionStatementDeny, roleList, stageAdmission, derivedTags), nil
		case probepb.StatementClass_STATEMENT_CLASS_ANALYZED:
			// Fall through to the grant walk.
		default:
			// STATEMENT_CLASS_UNSPECIFIED and any unrecognised number.
			return structuralDeny("statement class is unspecified", roleList, stageAdmission, derivedTags), nil
		}
	}

	// STEP 15 — the datasource grants: map the analyzer action to a Cedar action, then gate it.
	for _, g := range grants {
		if !hasDatasource(g) {
			continue
		}
		action, ok := grantAction(g.GetAction())
		if !ok {
			return policyDeny("statement kind 'other' is not permitted", roleList, derivedTags), nil
		}
		if !in.Authz.AuthorizeDatasourceAction(in.Principal, roles, action, ds.Name, authzCtx, ds.Tags).Allowed {
			return policyDeny("no "+action.CedarID()+" grant for datasource '"+ds.Name+"'", roleList, derivedTags), nil
		}
	}

	// STEP 16 — the unresolved path.
	if !facts.GetResolved() {
		// Anything but UNANALYZABLE at this point is a structural deny. (INADMISSIBLE and the
		// unresolved-UNSPECIFIED pair already exited at step 4, so this is the residual guard.)
		if facts.GetFailureClass() != probepb.FailureClass_FAILURE_CLASS_UNANALYZABLE {
			return structuralDeny(ifBlank(facts.GetDetail(), "statement analysis failed"), roleList, stageAdmission, derivedTags), nil
		}
		// The dangerous-function floor still applies to a statement nobody could analyze: names are
		// recovered from the parsed-but-unresolved statement. tagForFunction FIRST, then the
		// version-independent baseline (INV-A5-59: the baseline is a FLOOR, it never lowers).
		if len(facts.GetFunctions()) > 0 {
			functionTags := classifyFunctions(in, engineVersion, facts.GetFunctions())
			if len(functionTags) > 0 {
				refs := functionRefsInOrder(facts.GetFunctions(), functionTags)
				verdicts := in.Authz.AuthorizeFunctions(in.Principal, roles, ds.Name, refs, authzCtx, functionTags, ds.Tags)
				for _, ref := range refs {
					if verdicts[ref.Name] != authz.FunctionAllowed {
						return structuralDeny(systemFunctionDeny+" '"+ref.Name+"'", roleList, stagePolicy, derivedTags), nil
					}
				}
			}
		}
		stage := "null" // Kotlin interpolates a null String? as the four characters "null".
		if facts.FailedStage != nil {
			stage = strings.ToLower(facts.GetFailedStage())
		}
		reason := "fail-closed: could not analyze (" + stage + ")"
		if in.Authz.AuthorizeDatasourceAction(
			in.Principal, roles, authz.ActionSQLUnanalyzable, ds.Name, authzCtx, ds.Tags,
		).Allowed {
			return DecisionContext{
				Action:           pb.EnfAction_ALLOW,
				DenyReason:       nil,
				Masks:            nil,
				PIITouched:       nil,
				EffectiveRoles:   roleList,
				FailedStage:      nil,
				Detail:           strptr("unanalyzable relay (sql.unanalyzable): " + reason),
				Passthrough:      true,
				ContextTags:      derivedTags,
				CatalogChanging:  facts.GetCatalogChanging() || len(facts.GetFunctions()) > 0,
				SchemaCandidates: schemaCandidates,
			}, nil
		}
		return deny(reason, true), nil
	}

	// STEP 17 — the column keys, key = "$catalog.$schema.$table.$column", putIfAbsent (so the FIRST
	// grant for a key owns the ColumnResource, and the key order is grant order).
	var columnGrants []*probepb.RequiredGrant
	for _, g := range grants {
		if hasColumn(g) {
			columnGrants = append(columnGrants, g)
		}
	}
	var columnKeyOrder []string
	seenColumnKey := map[string]bool{}
	for _, g := range columnGrants {
		key := columnKeyOf(g.GetColumn())
		if !seenColumnKey[key] {
			seenColumnKey[key] = true
			columnKeyOrder = append(columnKeyOrder, key)
		}
	}

	// STEP 18 — catalog coverage. See CoverageOf's doc for why a miss routes through sql.unanalyzable
	// rather than hard-denying.
	if coverage := CoverageOf(catalogIndex, columnKeyOrder); !coverage.Covered {
		if in.Authz.AuthorizeDatasourceAction(
			in.Principal, roles, authz.ActionSQLUnanalyzable, ds.Name, authzCtx, ds.Tags,
		).Allowed {
			return DecisionContext{
				Action:           pb.EnfAction_ALLOW,
				DenyReason:       nil,
				Masks:            nil,
				PIITouched:       nil,
				EffectiveRoles:   roleList,
				FailedStage:      nil,
				Detail:           strptr("uncovered-column relay (sql.unanalyzable): " + coverage.Reason),
				Passthrough:      true,
				ContextTags:      derivedTags,
				CatalogChanging:  facts.GetCatalogChanging() || len(facts.GetFunctions()) > 0,
				CatalogMiss:      true,
				SchemaCandidates: schemaCandidates,
			}, nil
		}
		d := structuralDeny(coverage.Reason, roleList, stageCatalog, derivedTags)
		d.CatalogMiss = true
		d.SchemaCandidates = schemaCandidates
		return d, nil
	}

	// STEP 19 — the mask-fn kind vocabulary. A store failure is a CATALOG deny with catalogMiss, not
	// an escaped exception (Kotlin catches it here and nowhere else).
	maskKinds, mkErr := listMaskFnKinds(ctx, in.MaskFns)
	if mkErr != nil {
		d := structuralDeny(catalogConfigurationDeny, roleList, stageCatalog, derivedTags)
		d.CatalogMiss = true
		d.SchemaCandidates = schemaCandidates
		return d, nil
	}

	// STEP 20 — the ColumnRefs, carrying each row's classification tags (A2 resolves tag-scoped
	// grants off these; Authz never queries the catalog itself).
	columnRefs := make([]authz.ColumnRef, 0, len(columnKeyOrder))
	for _, key := range columnKeyOrder {
		row, ok := catalogIndex.RowsByKey[key]
		if !ok {
			// Kotlin's `getValue` throws here; step 18 has already proved it cannot.
			return DecisionContext{}, errors.New("decideQuery: catalog index lost key '" + key + "' after coverage")
		}
		var tags []string
		if row.Classification != nil {
			tags = row.Classification.Tags
		}
		columnRefs = append(columnRefs, authz.ColumnRef{
			Key: key, Catalog: row.Catalog, Schema: row.Schema, Table: row.Table, Column: row.Column, Tags: tags,
		})
	}

	// STEP 21 — every table identity the statement touches, then its shipped `system:` tag.
	// Kotlin's buildSet is a LinkedHashSet: columnRef tables first, then facts.sources, then the
	// table grants, deduplicated in that order.
	var allTableIDs []authz.TableIdentity
	seenTable := map[authz.TableIdentity]bool{}
	addTable := func(id authz.TableIdentity) {
		if !seenTable[id] {
			seenTable[id] = true
			allTableIDs = append(allTableIDs, id)
		}
	}
	for _, ref := range columnRefs {
		addTable(authz.TableIdentity{Catalog: ref.Catalog, Schema: ref.Schema, Table: ref.Table})
	}
	for _, src := range facts.GetSources() {
		addTable(authz.TableIdentity{Catalog: src.GetCatalog(), Schema: src.GetSchema(), Table: src.GetTable()})
	}
	for _, g := range grants {
		if hasTable(g) {
			t := g.GetTable()
			addTable(authz.TableIdentity{Catalog: t.GetCatalog(), Schema: t.GetSchema(), Table: t.GetTable()})
		}
	}
	systemTags := map[authz.TableIdentity]string{}
	if in.SystemClassification != nil {
		for _, id := range allTableIDs {
			if tag, ok := in.SystemClassification.TagForTable(ds.Engine, engineVersion, id.Catalog, id.Schema, id.Table); ok {
				systemTags[id] = tag
			}
		}
	}

	// STEP 22 — the function gate on the resolved path. Names = function grants ∪ facts.functions.
	var functionGrants []*probepb.RequiredGrant
	for _, g := range grants {
		if hasFunction(g) {
			functionGrants = append(functionGrants, g)
		}
	}
	if len(functionGrants) > 0 || len(facts.GetFunctions()) > 0 {
		names := make([]string, 0, len(functionGrants)+len(facts.GetFunctions()))
		for _, g := range functionGrants {
			names = append(names, g.GetFunction().GetName())
		}
		names = append(names, facts.GetFunctions()...)
		names = distinct(names)
		functionTags := classifyFunctions(in, engineVersion, names)
		// A FUNCTION GRANT whose name resolved no tag is denied. (A name that only appeared in
		// facts.functions is NOT: absent means safe there — INV-A5-56.)
		for _, g := range functionGrants {
			if _, ok := functionTags[g.GetFunction().GetName()]; !ok {
				return structuralDeny(systemFunctionDeny+" '"+g.GetFunction().GetName()+"'", roleList, stagePolicy, derivedTags), nil
			}
		}
		if len(functionTags) > 0 {
			refs := functionRefsInOrder(names, functionTags)
			verdicts := in.Authz.AuthorizeFunctions(in.Principal, roles, ds.Name, refs, authzCtx, functionTags, ds.Tags)
			for _, ref := range refs {
				if verdicts[ref.Name] != authz.FunctionAllowed {
					return structuralDeny(systemFunctionDeny+" '"+ref.Name+"'", roleList, stagePolicy, derivedTags), nil
				}
			}
		}
	}

	// STEP 23 — the per-column Cedar verdicts. Skipped entirely when nothing was traced.
	columnVerdicts := map[string]authz.ColumnVerdict{}
	if len(columnRefs) > 0 {
		columnVerdicts = in.Authz.AuthorizeColumns(in.Principal, roles, ds.Name, columnRefs, authzCtx, systemTags, ds.Tags)
	}

	// STEP 24 — the mask binding loop.
	var masks []*pb.ColumnMask
	// 🔒 INV-A6-12 — FIRST-WINS per output ordinal. Kotlin scans the accumulated list
	// (`masks.none { it.ordinal == ordinal }`); this presence map is the same predicate in O(1).
	// Appending and letting the LAST win inverts the semantics.
	maskedOrdinals := map[int32]bool{}
	for _, g := range columnGrants {
		key := columnKeyOf(g.GetColumn())
		row, ok := catalogIndex.RowsByKey[key]
		if !ok {
			return DecisionContext{}, errors.New("decideQuery: catalog index lost key '" + key + "' after coverage")
		}

		// 🔒 INV-A6-11, HALF 1 — a TEMP row is forced UNMASKED, BYPASSING column authz entirely.
		// This is safe ONLY because a write cannot launder a masked value into a temp, which is
		// enforced by the MASKED + DENY_STATEMENT write branch ~30 lines below plus the analyzer's
		// read-set membership rules. THE TWO ARE ONE COUPLED INVARIANT: a port that keeps this bypass
		// but weakens that write rule opens a cleartext exfiltration path. Pinned together in
		// unmasked_temp_linchpin_db_test.go, and by ChannelDecideAuditDbTest case 6 in the Kotlin.
		verdict := authz.ColumnDenied
		if row.IsTemp {
			verdict = authz.ColumnUnmasked
		} else if v, present := columnVerdicts[key]; present {
			verdict = v
		}

		switch verdict {
		case authz.ColumnUnmasked:
			// Nothing.
		case authz.ColumnDenied:
			return deny("policy denies column "+key, false), nil
		case authz.ColumnMasked:
			switch g.GetMaskedDisposition() {
			case probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT,
				probepb.MaskedDisposition_MASKED_DISPOSITION_REDACT_OUTPUT_NULL:
				// Ordinals were bounds-checked up front (step 10), so each is a valid index here.
				for _, ordinal := range g.GetOutputOrdinals() {
					if maskedOrdinals[ordinal] {
						continue // first-wins (INV-A6-12)
					}
					maskedOrdinals[ordinal] = true
					ord := ordinal
					if g.GetMaskedDisposition() == probepb.MaskedDisposition_MASKED_DISPOSITION_REDACT_OUTPUT_NULL {
						masks = append(masks, &pb.ColumnMask{
							Column: outputColumns[ordinal], MaskFn: "redact", Kind: "NULL", Ordinal: &ord,
						})
						continue
					}
					// MASK_OUTPUT: `maskFn = fn ?: "mask"`, `kind = fn?.let { maskKinds[it] } ?: "FIXED"`
					// — so a classification naming a mask fn the vocabulary does not know still lands
					// on "FIXED", it does NOT fall through to no mask.
					maskFn, kind := "mask", "FIXED"
					if row.Classification != nil && row.Classification.MaskFnName != nil {
						maskFn = *row.Classification.MaskFnName
						if k, known := maskKinds[maskFn]; known {
							kind = k
						}
					}
					masks = append(masks, &pb.ColumnMask{
						Column: outputColumns[ordinal], MaskFn: maskFn, Kind: kind, Ordinal: &ord,
					})
				}
			default:
				// 🔒 INV-A6-11, HALF 2 — DENY_STATEMENT (plus UNSPECIFIED / unrecognised, which step
				// 11 already rejected for a column grant) is the WRITE RULE the temp bypass above
				// depends on: a masked value can never become the payload of a write, so it can never
				// be laundered into a temp and read back unmasked. Do not weaken this branch.
				if facts.GetIsWrite() {
					return deny("write references protected column "+key+" (a write cannot be masked)", false), nil
				}
				return deny("sensitive column "+key+" used in a subquery/reference position (cannot be masked)", false), nil
			}
		}
	}

	// STEP 25 — the table gate: table grants EXCLUDING temp tables must authorize to READ.
	tempTableIDs := map[authz.TableIdentity]bool{}
	for _, c := range in.TempColumns {
		tempTableIDs[authz.TableIdentity{Catalog: c.Catalog, Schema: c.Schema, Table: c.Table}] = true
	}
	var tableRefs []authz.TableRef
	seenTableRefKey := map[string]bool{}
	for _, g := range grants {
		if !hasTable(g) {
			continue
		}
		t := g.GetTable()
		if tempTableIDs[(authz.TableIdentity{Catalog: t.GetCatalog(), Schema: t.GetSchema(), Table: t.GetTable()})] {
			continue
		}
		key := t.GetCatalog() + "." + t.GetSchema() + "." + t.GetTable()
		if seenTableRefKey[key] { // Kotlin's distinctBy { it.key }
			continue
		}
		seenTableRefKey[key] = true
		tableRefs = append(tableRefs, authz.TableRef{Key: key, Catalog: t.GetCatalog(), Schema: t.GetSchema(), Table: t.GetTable()})
	}
	if len(tableRefs) > 0 {
		verdicts := in.Authz.AuthorizeTables(in.Principal, roles, ds.Name, tableRefs, authzCtx, systemTags, ds.Tags)
		for _, ref := range tableRefs {
			if verdicts[ref.Key] != authz.TableRead {
				return deny("no read grant for scanned table '"+ref.Schema+"."+ref.Table+"'", false), nil
			}
		}
	}

	// STEP 26 — the verdict.
	action := pb.EnfAction_ALLOW
	if len(masks) > 0 {
		action = pb.EnfAction_MASK
	}

	// STEP 27 — an EXPLAIN of a masked query is refused: the plan would describe columns the
	// principal may not read in the clear, and there is no result stream to mask.
	if facts.GetExplainOfQuery() && action == pb.EnfAction_MASK {
		return structuralDeny(explainMaskDeny, roleList, stageExplainMasked, derivedTags), nil
	}

	// STEP 28 — the PII set. ⚠️ This is the REAL pii question — `classification.tags contains "pii"` —
	// and is NOT the same predicate as ColumnSpec.pii ("has ANY classification", step 3). Two meanings
	// of the same word, one function apart; reconciling them is a separate decision (F23).
	var pii []string
	for _, key := range columnKeyOrder {
		row := catalogIndex.RowsByKey[key]
		if row.Classification != nil && containsString(row.Classification.Tags, "pii") {
			pii = append(pii, key)
		}
	}

	// STEP 29 — referenced schemas: facts.sources ∪ column-grant schemas, MINUS anything starting
	// "pg_temp" (case-insensitive).
	var referencedSchemas []string
	seenSchema := map[string]bool{}
	addSchema := func(s string) {
		if !seenSchema[s] {
			seenSchema[s] = true
			referencedSchemas = append(referencedSchemas, s)
		}
	}
	for _, src := range facts.GetSources() {
		addSchema(src.GetSchema())
	}
	for _, g := range columnGrants {
		addSchema(g.GetColumn().GetIdentity().GetSchema())
	}
	filtered := referencedSchemas[:0]
	for _, s := range referencedSchemas {
		if !strings.HasPrefix(strings.ToLower(s), "pg_temp") {
			filtered = append(filtered, s)
		}
	}
	referencedSchemas = filtered

	// STEP 30 — the unmaskable capability grant. MASK-only, and fail-closed (INV-A6-6).
	unmaskablePermitted := action == pb.EnfAction_MASK && in.Authz.AuthorizeDatasourceAction(
		in.Principal, roles, authz.ActionSQLUnmaskable, ds.Name, authzCtx, ds.Tags,
	).Allowed

	// STEP 31 — diagnostic redaction. mayReadUnmasked stays a THUNK so the Cedar call is skipped
	// when the diagnostic could not carry a protected value anyway (INV-A6-15).
	sanitizeDiagnostics := RedactsDiagnostics(ds.Engine, action, func() bool {
		return in.Authz.AuthorizeDatasourceAction(
			in.Principal, roles, authz.ActionResultReadUnmasked, ds.Name, authzCtx, ds.Tags,
		).Allowed
	})

	// STEP 32 — the full DecisionContext.
	var failedStage *string
	if facts.FailedStage != nil {
		failedStage = strptr(strings.ToLower(facts.GetFailedStage()))
	}
	var rewritten *string
	if facts.RewrittenSql != nil && !facts.GetExplainOfQuery() {
		rewritten = strptr(facts.GetRewrittenSql())
	}
	return DecisionContext{
		Action:              action,
		DenyReason:          nil,
		Masks:               masks,
		PIITouched:          pii,
		EffectiveRoles:      roleList,
		FailedStage:         failedStage,
		Detail:              strptr(facts.GetDetail()),
		Passthrough:         false,
		RewrittenSQL:        rewritten,
		OutputColumns:       outputColumns,
		ContextTags:         derivedTags,
		UnmaskablePermitted: unmaskablePermitted,
		SanitizeDiagnostics: sanitizeDiagnostics,
		CatalogChanging:     facts.GetCatalogChanging() || len(facts.GetFunctions()) > 0,
		ReferencedSchemas:   referencedSchemas,
		SchemaCandidates:    schemaCandidates,
	}, nil
}

// buildAnalyzerAndFacts is step 3's whole try-block (Query.kt:316-351). Kotlin catches Exception
// around ALL of it — the case-mode requirement, the analyzer construction, the index build — and
// turns any of them into one catalog deny, so the Go form returns one error for the same set.
//
// 🔒 INV-A13-34 — the Analyzer is rebuilt per STATEMENT, never cached per datasource:
// mysql_ansi_quotes is a LIVE per-session observation, and a memoized analyzer would freeze a stale
// value and parse a quoted masked column as a string literal. The probe is pure, so this is cheap.
func buildAnalyzerAndFacts(
	in DecideQueryInput,
	catalogName string,
	resolvedSearchPath []string,
	engineVersion *string,
) (*CatalogColumnIndex, *probepb.StatementFacts, error) {
	var lowerCase *int
	if in.Datasource.MysqlLowerCaseTableNames != nil {
		v := int(*in.Datasource.MysqlLowerCaseTableNames)
		lowerCase = &v
	}
	// 🔒 INV-A5-5 — MySQL REFUSES to analyze without a captured case mode; guessing the fold would
	// resolve a name to a DIFFERENT table.
	mysqlCaseMode, err := datasource.RequireCaseMode(in.Datasource.Engine, lowerCase)
	if err != nil {
		return nil, nil, err
	}

	namespace := &probepb.Namespace{Catalog: catalogName, SearchPath: resolvedSearchPath}

	engineConfig := &probepb.EngineConfig{Engine: in.Datasource.Engine}
	if engineVersion != nil {
		engineConfig.EngineVersion = *engineVersion
	}
	if mysqlCaseMode != nil {
		v := int32(*mysqlCaseMode)
		engineConfig.MysqlLowerCaseTableNames = &v
	}
	// Only meaningful for MySQL; PostgreSQL ignores it. Set ONLY when true, as the Kotlin does — the
	// field is `optional`, so writing false would be a different message than leaving it absent.
	if in.LiveAnsiQuotes {
		t := true
		engineConfig.MysqlAnsiQuotes = &t
	}

	effectiveCatalog := make([]datasource.CatalogColumn, 0, len(in.Catalog)+len(in.TempColumns))
	effectiveCatalog = append(effectiveCatalog, in.Catalog...)
	effectiveCatalog = append(effectiveCatalog, in.TempColumns...)

	specs := make([]*probepb.ColumnSpec, 0, len(effectiveCatalog))
	for _, col := range effectiveCatalog {
		specs = append(specs, &probepb.ColumnSpec{
			Catalog: col.Catalog,
			Identity: &probepb.RelationIdentity{
				Schema: col.Schema, Table: col.Table, Column: col.Column,
			},
			DataType: col.SQLType,
			// ⚠️ `pii = col.classification != null` — "has ANY classification", NOT "is tagged pii".
			// Step 28 asks the real question. See F23.
			Pii: col.Classification != nil,
		})
	}

	analyzer, err := engine.AnalyzerFor(namespace, specs, engineConfig)
	if err != nil {
		return nil, nil, err
	}
	index, err := BuildCatalogColumnIndex(effectiveCatalog, specs, analyzer)
	if err != nil {
		return nil, nil, err
	}
	facts := in.FactsOverride
	if facts == nil {
		facts = analyzer.Analyze(in.SQL)
	}
	return index, facts, nil
}

// listMaskFnKinds is step 19's `listMaskFns().associate { it.name to it.kind }`. The associate is
// LAST-WINS on a duplicate name, which is what Kotlin's Map builder does; mask_fn.name is unique in
// the schema, so it is unobservable — reproduced anyway rather than reasoned away.
func listMaskFnKinds(ctx context.Context, lister MaskFnLister) (map[string]string, error) {
	if lister == nil {
		return nil, ErrSeamNotWired
	}
	fns, err := lister(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(fns))
	for _, f := range fns {
		out[f.Name] = f.Kind
	}
	return out, nil
}

// classifyFunctions is the shared body of steps 16 and 22 —
// `systemClassification?.tagForFunction(...) ?: BaselineDangerousFunctions.classify(name)?.id`,
// keeping only the names that resolved a tag.
//
// ⚠️ Both call sites are REPRODUCED as two call sites, not factored into one gate: they are two
// distinct steps of the pipeline with different inputs (step 16 sees only facts.functions; step 22
// sees the function grants too) and different deny conditions. The shared expression is what this
// helper is; the steps stay apart.
//
// 🔒 INV-A5-59 / INV-A13-31 — the elvis is a FLOOR, not a fallback chain to skip: the baseline still
// classifies its curated set on a datasource with no governing manifest, so both are consulted.
func classifyFunctions(in DecideQueryInput, engineVersion *string, names []string) map[string]string {
	out := map[string]string{}
	for _, name := range names {
		if in.SystemClassification != nil {
			if tag, ok := in.SystemClassification.TagForFunction(in.Datasource.Engine, engineVersion, name); ok {
				out[name] = tag
				continue
			}
		}
		if tag, ok := engine.ClassifyBaselineDangerousFunction(name); ok {
			out[name] = tag.ID()
		}
	}
	return out
}

// functionRefsInOrder materialises `functionTags.keys.map(::FunctionRef)`. Kotlin's map preserves
// insertion order, which is the order the names were classified in, so the refs are rebuilt by
// walking `names` rather than a Go map (whose iteration order is randomised) — the order decides
// WHICH function name appears in the deny message when several are forbidden.
func functionRefsInOrder(names []string, tags map[string]string) []authz.FunctionRef {
	out := make([]authz.FunctionRef, 0, len(tags))
	seen := map[string]bool{}
	for _, name := range names {
		if _, ok := tags[name]; !ok || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, authz.FunctionRef{Name: name})
	}
	return out
}

// utilityCommandsInOrder materialises `utilityTags.keys` in the order the utility grants were emitted
// — same reasoning as [functionRefsInOrder]: it decides which command names the deny message.
func utilityCommandsInOrder(grantsInOrder []*probepb.RequiredGrant, tags map[string]string) []string {
	out := make([]string, 0, len(tags))
	seen := map[string]bool{}
	for _, g := range grantsInOrder {
		command := g.GetUtility().GetCommand()
		if _, ok := tags[command]; !ok || seen[command] {
			continue
		}
		seen[command] = true
		out = append(out, command)
	}
	return out
}

// columnKeyOf renders a column grant's four-part analyzer key —
// `listOf(catalog, schema, table, column).joinToString(".")` (Query.kt:526).
//
// 🔒 This is the SAME rendering internal/engine's validateUniqueness performs over the catalog, and
// it must stay so: the key is what looks a grant up in the catalog index. INV-A13-13 guards the
// injectivity of that rendering on the catalog side.
func columnKeyOf(c *probepb.ColumnResource) string {
	return c.GetCatalog() + "." + c.GetIdentity().GetSchema() + "." +
		c.GetIdentity().GetTable() + "." + c.GetIdentity().GetColumn()
}

// anyGrant is Kotlin's `List.any { }`, spelled out so the step-14 filter reads like its source.
func anyGrant(grants []*probepb.RequiredGrant, pred func(*probepb.RequiredGrant) bool) bool {
	for _, g := range grants {
		if pred(g) {
			return true
		}
	}
	return false
}

// distinct is Kotlin's `toSet()` / `distinct()` over a String list: deduplicated, INSERTION-ORDERED.
// A Go map would randomise the order, and these values reach the wire.
func distinct(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ifBlank is Kotlin's `String.ifBlank { fallback }`, over [engine.IsBlank] so there is exactly one
// definition of "blank" in the port.
func ifBlank(s, fallback string) string {
	if engine.IsBlank(s) {
		return fallback
	}
	return s
}
