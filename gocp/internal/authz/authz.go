package authz

import (
	"sort"
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// Authz is the authz decision service (docs/authz-model.md — the "authz boundary": Cedar, the schema,
// entity marshalling and the policy store all stay internal; consumers see only the Authorize surface).
// Ported from Authz.kt:286-429.
//
// 🔒 INV-A2-16 — every call here evaluates Cedar for real. There is NO bypass in Authz itself; the
// PM_AUTH_DEBUG dev bypass lives in the route gate and short-circuits BEFORE ever reaching Authorize.
// The dev bypass never SKIPS Cedar, it prevents Cedar from being REACHED.
type Authz struct {
	// engine is package-visible, not private: the batch entry points below are free functions in the
	// Kotlin (top-level extensions) and need the raw engine for their two-actions-per-item marshalling,
	// which Authorize's single-resource shape does not fit.
	engine *CedarEngine
	// policyStore is constructor-retained only — @Suppress("unused") in the Kotlin. Kept so the Go
	// constructor has the same shape and so a future caller does not have to re-thread it.
	policyStore PolicyStore
	roleSource  RoleSource
}

// New builds an Authz. policyStore may be nil in the in-memory/unit configuration, matching the Kotlin
// unit tests that construct CedarEngine(List) and never touch JDBC.
func New(engine *CedarEngine, policyStore PolicyStore, roleSource RoleSource) *Authz {
	return &Authz{engine: engine, policyStore: policyStore, roleSource: roleSource}
}

// Engine exposes the raw engine to the batch entry points and to /health diagnostics.
func (a *Authz) Engine() *CedarEngine { return a.engine }

// RolesOf is the accessor over the private roleSource — Authz.kt:298.
//
// 🔒 INV-A2-10 — this exists so AuthorizeWithContext can take ONE role snapshot and thread it through
// BOTH pass-1 tag derivation and pass-2 authorization. A role revoked, or a JIT grant expiring, between
// the two passes can then never earn a context.tag the final decision no longer sees. Mirrors
// decideQuery's invariant (A6). ElevationContextTagTest case 7 pins it.
func (a *Authz) RolesOf(principal string) []string { return a.roleSource.RolesOf(principal) }

// toAuthzDecision ports Authz.kt:267-278 — with ONE deliberate, measured change of shape at branch 1.
//
// 🔴 ERRORS-FIRST. This is the single most important line in the area, and getting it backwards is
// FAIL-OPEN.
//
// cedar-java's AuthorizationResponse is present-or-absent: an engine error means there is NO success
// payload at all, so "error" and "allowed" are mutually exclusive states and branch order cannot
// matter. cedar-go's Diagnostic.Errors is a SEPARATE slice from Diagnostic.Reasons, PER-POLICY and
// NON-FATAL — it can and does return Allow AND an error simultaneously, a state cedar-java cannot
// express. The spike measured it verbatim:
//
//	RAW: decision=allow reasons=[policy-ok] errors=[{policy-bad: `User::"alice"` does not have the attribute `dept`}]
//	  errors-first mapping : Deny("authorization engine error: ...")
//	  verdict-first mapping: Allow
//
// Replayed against the ACTUALLY SHIPPED policy set with the Request entity omitted — the class of
// failure a port is most likely to introduce — the system:no-self-approval FORBID (-2) errors out,
// cedar-go drops it, and the system:admin PERMIT (-3) stands. A verdict-first mapping therefore lets a
// system-admin approve their own request: precisely the hole AuthzTest case 6 exists to keep closed.
//
// So: ANY len(Diagnostic.Errors) > 0 means DENY, checked BEFORE the verdict. This preserves INV-A2-8's
// fail-closed branch 1 and INV-A2-13's pass-1 fail-closed. NO Kotlin test pins either mapping (the
// spike grepped: zero test-source hits for "authorization engine error", "denied by policy" or
// "no policy permits this action"), so under PORT POLICY this is REPRODUCE + PIN — see
// errors_first_test.go, the assertion the Kotlin suite never had.
//
// Blast radius, measured and bounded: scope (principal/action/resource) is evaluated first and
// short-circuits, so a broken policy injects nothing into a request whose scope it does not match —
// errors-first is not a global fail-shut. And a has-guarded read never errors, not even when the whole
// entity is absent, so the only production-reachable error surface is an unguarded read of a
// schema-REQUIRED attribute.
//
// Branches 2, 3 and 4 reproduce byte-exact; the spike verified each against the Kotlin.
func toAuthzDecision(d types.Decision, diag types.Diagnostic, err error) AuthzDecision {
	// Branch 1a: the engine could not produce a verdict at all (a policy-set rebuild failure — what the
	// Kotlin signals by letting Policy()'s throw propagate out of isAuthorized).
	if err != nil {
		return Deny("authorization engine error: " + err.Error())
	}
	// Branch 1b: ERRORS-FIRST.
	if len(diag.Errors) > 0 {
		return Deny("authorization engine error: " + joinDiagnosticErrors(diag.Errors))
	}
	if d == cedar.Allow {
		return Allow
	}
	if len(diag.Reasons) == 0 {
		return Deny("no policy permits this action")
	}
	ids := make([]string, 0, len(diag.Reasons))
	for _, r := range diag.Reasons {
		ids = append(ids, string(r.PolicyID))
	}
	return Deny("denied by policy: " + strings.Join(ids, ", "))
}

// joinDiagnosticErrors renders branch 1's detail. Kotlin joins the error MESSAGES with "; ".
//
// The one enrichment: each entry is prefixed with its PolicyID, because cedar-go's errors are
// per-policy where cedar-java's are request-level, and "which policy erred" is the first thing an
// operator needs. The "authorization engine error: " PREFIX — the part that is greppable and that
// callers key off — is unchanged.
func joinDiagnosticErrors(errs []types.DiagnosticError) string {
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, string(e.PolicyID)+": "+e.Message)
	}
	return strings.Join(parts, "; ")
}

// allowedByCedar is the batch paths' inline verdict read — Kotlin's
// `.success.orElse(null)?.isAllowed == true` (Authz.kt:525, 603, 672, 737) plus
// `.success.orElse(null)?.isAllowed == true` in resolveContextTags (Authz.kt:825).
//
// The Kotlin idiom is already FALSE-on-absent, so its intent is unambiguous even where cedar-go's
// mechanism differs: the errors-first rule applies at all five batch call sites too. W1 is explicit
// that the mapping must land in toAuthzDecision AND at every one of them.
func allowedByCedar(d types.Decision, diag types.Diagnostic, err error) bool {
	return err == nil && len(diag.Errors) == 0 && d == cedar.Allow
}

// EvaluatesInCedar answers whether the ENGINE can evaluate ip as a requester_ip — Authz.kt:307-315.
//
// 🔴 W3 / D5 constraint 2. The Kotlin runs one throwaway decision (User::"ip-probe", sql.select,
// System::"system") and returns whether the engine produced a verdict at all. That round-trip does NOT
// survive the port, and the spike reached the conclusion twice independently (S4 §15 and S5 §7): the
// probe request matches no policy scope under the shipped set, so len(Errors) == 0 is true for EVERY
// parseable IP, and it would error SPURIOUSLY if any policy read a context key the probe omits. It
// collapses to types.ParseIPAddr.
//
// 🔴 THIS FUNCTION IS ONLY HALF THE CHECK, and the other half is what keeps it correct.
// RequesterIp.kt:209-214's isStorableIpLiteral is TWO-STAGE and already takes evaluatesInCedar as a
// parameter:
//
//	if (candidate.isEmpty()) return false
//	if (!candidate.all { it.isDigit() || it == '.' || it == ':' || it in 'a'..'f' || it in 'A'..'F' }) return false   // L1
//	if (runCatching { IpAddress(candidate) }.isFailure) return false                                                  // L2
//	return evaluatesInCedar(candidate)                                                                                // L3
//
// The L1 charset allowlist MUST stay in front of this call. Measured against
// DebugRequesterIpDbTest.kt:156-195's 16 pinned literals: faithful (L1 + range guard, then ParseIPAddr)
// = 16/16; naive (delegate wholly to ParseIPAddr) = 15/16, failing on 100.100.1.0/24 — which
// ParseIPAddr ACCEPTS as an ipaddr value (Cedar's ipaddr type covers prefixes) and the Kotlin allowlist
// REJECTS because '/' is not in the allowed set. Go's parser is stricter almost everywhere; the ONE
// place it is LAXER is exactly where the allowlist is load-bearing, so "Go is stricter, collapse the
// layers" is wrong. ip_test.go pins that this function accepts 100.100.1.0/24, which is the evidence.
//
// Corollary, also from S5: NEVER persist IPAddr.String(). It is not round-trip safe for v4-mapped v6 —
// ::ffff:6464:010a renders as ::ffff:100.100.1.10, which ParseIPAddr then rejects.
//
// TODO(A12): isStorableIpLiteral, the L1 allowlist and cidrContains live in RequesterIp.kt — see
// 12-request-context.md. Port them with the two-stage structure intact.
func (a *Authz) EvaluatesInCedar(ip string) bool {
	_, err := types.ParseIPAddr(ip)
	return err == nil
}

// Authorize is the single-resolution entry point — Authz.kt:323-328. Resolves the principal's roles
// once, then delegates to AuthorizeAs. The common case: System / AuditLog resources with no
// datasource-scoped tags.
//
// When a datasource-scoped context.tags derivation must AGREE with the final decision on the same role
// snapshot (the approval-authority routes), go through AuthorizeWithContext instead.
func (a *Authz) Authorize(principal string, action AuthzAction, resource AuthzResource, context AuthzContext) AuthzDecision {
	return a.AuthorizeAs(principal, a.roleSource.RolesOf(principal), action, resource, context)
}

// AuthorizeAs authorizes with an EXPLICIT, already-resolved role set — no second, out-of-band
// RoleSource resolution. Authz.kt:338-360.
func (a *Authz) AuthorizeAs(
	principal string,
	roles []string,
	action AuthzAction,
	resource AuthzResource,
	context AuthzContext,
) AuthzDecision {
	principalEuid, principalEntity, roleEntities := principalEntities(principal, roles)
	resourceEuid, resourceEntities := marshalResource(resource)

	entities := dedupeEntities([]types.Entity{principalEntity}, roleEntities, resourceEntities)
	d, diag, err := a.engine.Authorize(
		principalEuid,
		types.NewEntityUID(typeAction, types.String(action.CedarID())),
		resourceEuid,
		entities,
		context.ToCedarMap(true),
	)
	return toAuthzDecision(d, diag, err)
}

// AuthorizeColumns is per-column authz (docs/authz-model.md: masking is column config, not
// authorization) — Authz.kt:450-537.
//
// Builds ONE Entities set for the whole batch — principal + roles + the datasource + every touched
// column (each carrying its table/tag membership, table and tag entities deduped across columns) — then
// asks Cedar twice per column: result.read.unmasked FIRST, then result.read.masked. The order is the
// verdict: unmasked wins when both allow. Neither permitting is DENIED.
//
// roles is the caller's EXPLICIT, already-resolved set: unlike Authorize this does NOT call RoleSource
// itself. decideQuery resolves roles once (deliberately AFTER admission) and threads that same set
// through both the engine and this call, so a second out-of-band resolution cannot disagree.
//
// systemTags maps (catalog, schema, table) to the shipped system: classification, attached to the TABLE
// entity so its Columns inherit it transitively — a column of pg_authid is in Tag::"system:critical"
// through its Table parent, never through a second direct tag on the column (INV-A2-7).
func (a *Authz) AuthorizeColumns(
	principal string,
	roles []string,
	datasource string,
	columns []ColumnRef,
	context AuthzContext,
	systemTags map[TableIdentity]string,
	datasourceTags []string,
) map[string]ColumnVerdict {
	principalEuid, principalEntity, roleEntities := principalEntities(principal, roles)

	dsEuid := types.NewEntityUID(typeDatasource, types.String(datasource))
	tags := newTagEuidCache()
	dsEntity := datasourceEntity(dsEuid, datasource, datasourceTags, tags)

	// 🔒 INV-A2-6 — a delimiter-bearing identity builds NO EUID and is DENIED below. Because such
	// identities never reach the join, the EUID slash-join stays injective.
	tableEuids := map[TableIdentity]types.EntityUID{}
	var tableOrder []TableIdentity
	columnEuids := map[string]types.EntityUID{}
	var columnEntities []types.Entity
	for _, col := range columns {
		if hasColumnDelim(datasource) || hasColumnDelim(col.Catalog) || hasColumnDelim(col.Schema) ||
			hasColumnDelim(col.Table) || hasColumnDelim(col.Column) {
			continue // no EUID built -> denied in the final mapping below
		}
		identity := TableIdentity{Catalog: col.Catalog, Schema: col.Schema, Table: col.Table}
		tableEuid, ok := tableEuids[identity]
		if !ok {
			tableEuid = types.NewEntityUID(typeTable, types.String(
				datasource+"/"+col.Catalog+"/"+col.Schema+"/"+col.Table))
			tableEuids[identity] = tableEuid
			tableOrder = append(tableOrder, identity)
		}
		colEuid := types.NewEntityUID(typeColumn, types.String(
			datasource+"/"+col.Catalog+"/"+col.Schema+"/"+col.Table+"/"+col.Column))
		columnEuids[col.Key] = colEuid

		// #78 — NO TAG IS STRIPPED. A column carries every tag its catalog row holds, reserved-looking or
		// not; the shipped `system:` classification is resolved per statement from the manifest and
		// attached separately, so a tag row cannot forge one. See internal/authz/entities.go's package
		// note for what the operator owns instead.
		parents := []types.EntityUID{tableEuid, dsEuid}
		for _, t := range col.Tags {
			parents = append(parents, tags.getOrPut(t))
		}
		columnEntities = append(columnEntities, types.Entity{
			UID:     colEuid,
			Parents: types.NewEntityUIDSet(parents...),
		})
	}

	// Each Table entity carries its datasource parent plus its system tag, so a Column inherits the
	// system classification through its Table parent.
	tableEntities := make([]types.Entity, 0, len(tableOrder))
	for _, identity := range tableOrder {
		parents := []types.EntityUID{dsEuid}
		if st, ok := systemTags[identity]; ok {
			parents = append(parents, tags.getOrPut(st))
		}
		tableEntities = append(tableEntities, types.Entity{
			UID:     tableEuids[identity],
			Parents: types.NewEntityUIDSet(parents...),
		})
	}

	entities := dedupeEntities(
		[]types.Entity{principalEntity, dsEntity},
		roleEntities, tableEntities, tags.entities(), columnEntities,
	)
	contextMap := context.ToCedarMap(true)
	unmasked := types.NewEntityUID(typeAction, types.String(ActionResultReadUnmasked.CedarID()))
	masked := types.NewEntityUID(typeAction, types.String(ActionResultReadMasked.CedarID()))

	allowed := func(action, resource types.EntityUID) bool {
		return allowedByCedar(a.engine.Authorize(principalEuid, action, resource, entities, contextMap))
	}

	// 🔒 INV-A2-5 — every entry gets an explicit verdict; there is no "absent = allow".
	out := make(map[string]ColumnVerdict, len(columns))
	for _, col := range columns {
		colEuid, ok := columnEuids[col.Key]
		if !ok {
			out[col.Key] = ColumnDenied // delimiter in the resolved identity -> deny-closed
			continue
		}
		switch {
		case allowed(unmasked, colEuid):
			out[col.Key] = ColumnUnmasked
		case allowed(masked, colEuid):
			out[col.Key] = ColumnMasked
		default:
			out[col.Key] = ColumnDenied
		}
	}
	return out
}

// AuthorizeTables is table-scan authz (docs/facts-emission.md) — Authz.kt:552-614.
//
// An UNCOVERED scanned table — read with zero traced columns (count(*), SELECT 1, EXISTS, a cross-join
// side) — leaks the relation's existence and row count unless a result.read grant covers its Table.
// EITHER result.read.unmasked OR result.read.masked permits the scan: a masked reader already observes
// the table's rows through masked projections, so existence and cardinality are not additionally
// protected.
//
// Note the one structural difference from AuthorizeColumns, reproduced deliberately: the EUID cache is
// keyed by t.Key here (Authz.kt:586) and by the (catalog, schema, table) triple there (Authz.kt:493),
// while systemTags is looked up by the triple in both. So two TableRefs with different Keys but the
// same identity produce two entries in this cache and one in that one.
func (a *Authz) AuthorizeTables(
	principal string,
	roles []string,
	datasource string,
	tables []TableRef,
	context AuthzContext,
	systemTags map[TableIdentity]string,
	datasourceTags []string,
) map[string]TableVerdict {
	principalEuid, principalEntity, roleEntities := principalEntities(principal, roles)

	dsEuid := types.NewEntityUID(typeDatasource, types.String(datasource))
	tags := newTagEuidCache()
	dsEntity := datasourceEntity(dsEuid, datasource, datasourceTags, tags)

	tableEuids := map[string]types.EntityUID{}
	var tableEntities []types.Entity
	for _, t := range tables {
		if hasColumnDelim(datasource) || hasColumnDelim(t.Catalog) || hasColumnDelim(t.Schema) ||
			hasColumnDelim(t.Table) {
			continue // no EUID built -> denied in the final mapping below
		}
		euid, ok := tableEuids[t.Key]
		if !ok {
			euid = types.NewEntityUID(typeTable, types.String(
				datasource+"/"+t.Catalog+"/"+t.Schema+"/"+t.Table))
			tableEuids[t.Key] = euid
		}
		parents := []types.EntityUID{dsEuid}
		if st, ok := systemTags[TableIdentity{Catalog: t.Catalog, Schema: t.Schema, Table: t.Table}]; ok {
			parents = append(parents, tags.getOrPut(st))
		}
		tableEntities = append(tableEntities, types.Entity{UID: euid, Parents: types.NewEntityUIDSet(parents...)})
	}

	entities := dedupeEntities(
		[]types.Entity{principalEntity, dsEntity}, roleEntities, tableEntities, tags.entities(),
	)
	contextMap := context.ToCedarMap(true)
	unmasked := types.NewEntityUID(typeAction, types.String(ActionResultReadUnmasked.CedarID()))
	masked := types.NewEntityUID(typeAction, types.String(ActionResultReadMasked.CedarID()))

	allowed := func(action, resource types.EntityUID) bool {
		return allowedByCedar(a.engine.Authorize(principalEuid, action, resource, entities, contextMap))
	}

	out := make(map[string]TableVerdict, len(tables))
	for _, t := range tables {
		euid, ok := tableEuids[t.Key]
		if !ok {
			out[t.Key] = TableDenied
			continue
		}
		if allowed(unmasked, euid) || allowed(masked, euid) {
			out[t.Key] = TableRead
		} else {
			out[t.Key] = TableDenied
		}
	}
	return out
}

// AuthorizeFunctions authorizes the DANGEROUS functions a query calls — Authz.kt:626-683.
//
// 🔒 INV-A2-11 — the caller passes ONLY DANGEROUS-classified functions. A safe function has no tag and
// no permit, so marshalling it would deny-by-default and break every now()/user-UDF query.
//
// Delimiter guard is '/' ONLY (a function name cannot carry the analyzer's dot-qualification). The
// asymmetry with AuthorizeColumns is intentional — do not unify.
func (a *Authz) AuthorizeFunctions(
	principal string,
	roles []string,
	datasource string,
	functions []FunctionRef,
	context AuthzContext,
	systemTags map[string]string,
	datasourceTags []string,
) map[string]FunctionVerdict {
	principalEuid, principalEntity, roleEntities := principalEntities(principal, roles)

	dsEuid := types.NewEntityUID(typeDatasource, types.String(datasource))
	tags := newTagEuidCache()
	dsEntity := datasourceEntity(dsEuid, datasource, datasourceTags, tags)

	fnEuids := map[string]types.EntityUID{}
	var fnEntities []types.Entity
	for _, f := range functions {
		if hasNameDelim(datasource) || hasNameDelim(f.Name) {
			continue
		}
		euid, ok := fnEuids[f.Name]
		if !ok {
			euid = types.NewEntityUID(typeFunction, types.String(datasource+"/"+f.Name))
			fnEuids[f.Name] = euid
		}
		parents := []types.EntityUID{dsEuid}
		if st, ok := systemTags[f.Name]; ok {
			parents = append(parents, tags.getOrPut(st))
		}
		fnEntities = append(fnEntities, types.Entity{UID: euid, Parents: types.NewEntityUIDSet(parents...)})
	}

	entities := dedupeEntities(
		[]types.Entity{principalEntity, dsEntity}, roleEntities, fnEntities, tags.entities(),
	)
	contextMap := context.ToCedarMap(true)
	unmasked := types.NewEntityUID(typeAction, types.String(ActionResultReadUnmasked.CedarID()))
	masked := types.NewEntityUID(typeAction, types.String(ActionResultReadMasked.CedarID()))

	allowed := func(action, resource types.EntityUID) bool {
		return allowedByCedar(a.engine.Authorize(principalEuid, action, resource, entities, contextMap))
	}

	out := make(map[string]FunctionVerdict, len(functions))
	for _, f := range functions {
		euid, ok := fnEuids[f.Name]
		if !ok {
			out[f.Name] = FunctionDenied
			continue
		}
		if allowed(unmasked, euid) || allowed(masked, euid) {
			out[f.Name] = FunctionAllowed
		} else {
			out[f.Name] = FunctionDenied
		}
	}
	return out
}

// AuthorizeUtilities authorizes the resource-bearing UTILITY commands a query performs —
// Authz.kt:697-748.
//
// 🔒 INV-A2-11, the subtlest rule in the area. The caller passes ONLY CLASSIFIED utilities; an
// unclassifiable one is HARD-denied UPSTREAM, never marshalled here, because an untagged Utility
// (Datasource parent only, no forbid) would be PERMITTED by a datasource-scoped read grant. Marshalling
// an unclassified utility INVERTS the decision from deny to allow. The deny-by-default on an untagged
// EUID below remains a defensive backstop but is NOT the load-bearing path — the Go port must keep the
// upstream hard-deny.
func (a *Authz) AuthorizeUtilities(
	principal string,
	roles []string,
	datasource string,
	utilities []UtilityRef,
	context AuthzContext,
	systemTags map[string]string,
	datasourceTags []string,
) map[string]UtilityVerdict {
	principalEuid, principalEntity, roleEntities := principalEntities(principal, roles)

	dsEuid := types.NewEntityUID(typeDatasource, types.String(datasource))
	tags := newTagEuidCache()
	dsEntity := datasourceEntity(dsEuid, datasource, datasourceTags, tags)

	utilEuids := map[string]types.EntityUID{}
	var utilEntities []types.Entity
	for _, u := range utilities {
		if hasNameDelim(datasource) || hasNameDelim(u.Command) {
			continue
		}
		euid, ok := utilEuids[u.Command]
		if !ok {
			euid = types.NewEntityUID(typeUtility, types.String(datasource+"/"+u.Command))
			utilEuids[u.Command] = euid
		}
		parents := []types.EntityUID{dsEuid}
		if st, ok := systemTags[u.Command]; ok {
			parents = append(parents, tags.getOrPut(st))
		}
		utilEntities = append(utilEntities, types.Entity{UID: euid, Parents: types.NewEntityUIDSet(parents...)})
	}

	entities := dedupeEntities(
		[]types.Entity{principalEntity, dsEntity}, roleEntities, utilEntities, tags.entities(),
	)
	contextMap := context.ToCedarMap(true)
	unmasked := types.NewEntityUID(typeAction, types.String(ActionResultReadUnmasked.CedarID()))
	masked := types.NewEntityUID(typeAction, types.String(ActionResultReadMasked.CedarID()))

	allowed := func(action, resource types.EntityUID) bool {
		return allowedByCedar(a.engine.Authorize(principalEuid, action, resource, entities, contextMap))
	}

	out := make(map[string]UtilityVerdict, len(utilities))
	for _, u := range utilities {
		euid, ok := utilEuids[u.Command]
		if !ok {
			out[u.Command] = UtilityDenied
			continue
		}
		if allowed(unmasked, euid) || allowed(masked, euid) {
			out[u.Command] = UtilityUse
		} else {
			out[u.Command] = UtilityDenied
		}
	}
	return out
}

// AuthorizeDatasourceAction is the two once-per-query gates ahead of the catalog/analyzer/column loop
// (datasource.connect, then sql.<kind>) — Authz.kt:760-783.
//
// 🔒 INV-A2-2 — the datasource resource EUID is keyed off its NAME, not its numeric id:
// Datasource::"acme-mysql", matching AuthorizeColumns and every seed policy and doc example. This
// function deliberately does NOT route through Authorize or marshalResource. AuthzDatasourceActionTest
// case 5 pins that the same grant on a DIFFERENT name does not apply.
func (a *Authz) AuthorizeDatasourceAction(
	principal string,
	roles []string,
	action AuthzAction,
	datasource string,
	context AuthzContext,
	datasourceTags []string,
) AuthzDecision {
	principalEuid, principalEntity, roleEntities := principalEntities(principal, roles)

	dsEuid := types.NewEntityUID(typeDatasource, types.String(datasource))
	tags := newTagEuidCache()
	dsEntity := datasourceEntity(dsEuid, datasource, datasourceTags, tags)

	entities := dedupeEntities(
		[]types.Entity{principalEntity, dsEntity}, roleEntities, tags.entities(),
	)
	d, diag, err := a.engine.Authorize(
		principalEuid,
		types.NewEntityUID(typeAction, types.String(action.CedarID())),
		dsEuid,
		entities,
		context.ToCedarMap(true),
	)
	return toAuthzDecision(d, diag, err)
}

// ResolveContextTags is pass-1 of the two-pass mechanism (docs/authz-context.md) — Authz.kt:799-827.
//
// For every tag name T in the vocabulary (the context.tag::<name> actions the enabled rules target —
// DERIVED, not predefined), evaluate isAuthorized(principal, Action::"context.tag::T", <Datasource>,
// rawContext). Each ALLOW earns T. The result is SORTED (Kotlin collects into sortedSetOf()).
//
// 🔒 INV-A2-12 — no tag-on-tag, enforced on BOTH sides. includeTags=false means a tag rule cannot read
// context.tags at evaluation time; the generated tag-action schema also omits tags, so such a rule
// fails validation and never loads. Two INDEPENDENT closures of the same hole — keep both.
// TagResolutionTest cases 6 and 7 pin each side. The spike measured the leak directly: the same guarded
// rule denies with the tags key absent from pass 1 and ALLOWS with it leaked in.
//
// 🔒 INV-A2-13 — pass-1 fail-closed. A tag exists only if a rule PERMITTED it. An engine error is a
// non-allow (allowedByCedar's errors-first rule), so the tag is ABSENT — never "present on error".
//
// An empty vocabulary returns nothing WITH NO EVALUATION AT ALL (the common deployment).
func (a *Authz) ResolveContextTags(
	principal string,
	roles []string,
	datasource string,
	rawContext AuthzContext,
	datasourceTags []string,
) []string {
	vocab, err := a.engine.ContextTagVocabulary()
	if err != nil || len(vocab) == 0 {
		// A vocabulary that cannot be computed derives no tags — the same fail-closed direction.
		return nil
	}

	principalEuid, principalEntity, roleEntities := principalEntities(principal, roles)

	dsEuid := types.NewEntityUID(typeDatasource, types.String(datasource))
	tags := newTagEuidCache()
	dsEntity := datasourceEntity(dsEuid, datasource, datasourceTags, tags)

	entities := dedupeEntities(
		[]types.Entity{principalEntity, dsEntity}, roleEntities, tags.entities(),
	)
	// includeTags = false. See INV-A2-12 above.
	contextMap := rawContext.ToCedarMap(false)

	var earned []string
	for _, tag := range vocab {
		if allowedByCedar(a.engine.Authorize(
			principalEuid,
			types.NewEntityUID(typeAction, types.String("context.tag::"+tag)),
			dsEuid, entities, contextMap,
		)) {
			earned = append(earned, tag)
		}
	}
	sort.Strings(earned) // sortedSetOf() — result order is sorted
	return earned
}

// AuthorizeWithContext is the coherent non-query decision — Authz.kt:851-866.
//
//  1. roles = RolesOf(principal) — ONCE.
//  2. context = raw, unless datasourceName is non-nil, in which case raw with derived tags.
//  3. AuthorizeAs(principal, roles, action, resource, context).
//
// 🔒 INV-A2-10 — one role snapshot through BOTH passes.
//
// 🔒 INV-A2-14 — tags derive ONLY when a datasource is in scope, and no pseudo-datasource is ever
// synthesized. The tag mechanism is Datasource-scoped by construction: pass-1's Cedar action is
// declared appliesTo { resource: [Datasource] }, so it needs a REAL Datasource to evaluate against. A
// nil datasourceName authorizes over raw UNCHANGED — RequesterIP and every other raw signal still reach
// Cedar, but Tags stays empty. Fail-closed: a tag-conditioned policy simply does not fire; it never
// invents a tag from a fabricated resource. ElevationContextTagTest cases 3 and 4 pin both halves.
//
// INV-A2-15 — Channel is deliberately never set on this path. These admin/audit/approval routes have no
// query-decision channel, and inventing one for a route that is not deciding a query would be
// dishonest.
func (a *Authz) AuthorizeWithContext(
	principal string,
	action AuthzAction,
	resource AuthzResource,
	raw AuthzContext,
	datasourceName *string,
	datasourceTags []string,
) AuthzDecision {
	roles := a.RolesOf(principal)
	context := raw
	if datasourceName != nil {
		context = raw.WithTags(a.ResolveContextTags(principal, roles, *datasourceName, raw, datasourceTags))
	}
	return a.AuthorizeAs(principal, roles, action, resource, context)
}

// TODO(A2): the route gates requireAdmin / requireAuthz (02-authz.md §6) land with the HTTP layer —
// they need Config.authDebug, userSession() and ApiError, which A1/A4/D6 own. INV-A2-16 is the contract:
// authDebug short-circuits to true BEFORE Cedar is reached, a missing session is 401
// ApiError("common.unauthenticated"), and a Deny is 403 ApiError("common.forbidden", {detail: reason}).
//
// TODO(A6): decideQuery's effectiveAuthzContext — which makes the query channel authoritative and
// DISCARDS caller-supplied tags (INV-A2-9) — lives in Query.kt. See 06-query-decision.md §3.
