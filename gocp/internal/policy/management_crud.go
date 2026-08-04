package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The CRUD slice of `PolicyManagementService` — the methods the nineteen routes in cedarroutes.go
// and routes.go delegate to. It EXTENDS the [PolicyManagement] declared in management.go rather
// than declaring a second service, exactly as that file's TODO(A11) demands.
//
// 🔴 THIS IS STILL NOT A11's PORT. What is here is the id-keyed REST half; A11 owes the name-keyed
// half the MCP tools call, and the remaining ~20 methods over datasources and identity.
//
//	TODO(A11): the name-keyed variants (`updateRole(currentName)`, `deleteRole(name, c)` —
//	           ManagementServices.kt:370,389), the datasource and identity services, and the MCP
//	           tool surface that shares this layer. EXTEND this type; do not declare a second one.
// ---------------------------------------------------------------------------------------------

// CedarValidationError is `class CedarValidationManagementException(val errors: List<String>)`
// (11-mcp-oauth-management.md:432) — the ONE management failure that does not carry an ApiError.
//
// 🔒 It is separate from [ManagementError] because its WIRE BODY is separate. 02-authz.md:511:
// "the validation-error body is `{errors: [...]}` — a **bare map**, not `ApiError`. An exception to
// INV-A1-13; the messages are Cedar's own compiler output. Preserve the shape." Folding it into a
// ManagementError with a joined `detail` param would lose the array the policy editor renders one
// line at a time, and would put Cedar compiler prose into a param the web treats as an i18n
// interpolation. See [CedarPolicyErrors] for the body and cedarroutes.go for the one place it is
// caught.
//
// Kotlin throws; Go returns — so every route that can produce it matches with errors.As, and one
// that forgets returns it as a plain error, which StatusPages answers 500 common.fallback. Failing
// visibly beats answering 400 with the wrong body.
type CedarValidationError struct{ Errors []string }

func (e *CedarValidationError) Error() string {
	return fmt.Sprintf("management: cedar policy failed validation (%d error(s))", len(e.Errors))
}

// managementAlreadyExists is `private inline fun <T> unique(resource, name, body): T`
// (ManagementServices.kt:726) — the SQLSTATE 23505 arm, as a value rather than a wrapper.
//
// 03-identity-scim.md:203-208 records the trap: the `resource` literal is per-call-site and is NOT
// the route path — user routes pass `unique("principal", …)` but `notFound("user")`. So each caller
// below names its own, and the ones this file introduces are marked ⚠️ where the Kotlin literal is
// not quoted anywhere in the spec set.
//
// ⚠️ Note where this lands on the wire: `common.already_exists` is not an arm of
// `respondManagementError`'s switch, so it answers **400**, not the 409 [types.AlreadyExists] gives a
// route that responds directly. See httpapi.RespondManagementError.
func managementAlreadyExists(resource string, name *string) *ManagementError {
	params := map[string]string{"resource": resource}
	if name != nil {
		params["name"] = *name
	}
	return &ManagementError{Err: types.ApiError{Code: "common.already_exists", Params: params}}
}

// The `resource` literals this file passes to notFound / unique.
//
// ⚠️ ALL SIX ARE INFERRED, not quoted. The spec set quotes A3's literals ("user", "group",
// "group member", "group role mapping", "principal") and A2's one policy literal
// (`common.already_exists{resource: policy}`, 11-mcp-oauth-management.md:463) but never A9's. They
// are wire-visible: `web/` interpolates `{resource}` into a localized sentence and a missing key
// renders as the raw code. Chosen to match A3's house style — lowercase, spaced, human-readable
// prose rather than a table name.
//
//	TODO(A11): confirm all six against ManagementServices.kt at cutover. They are one-line changes
//	here and nowhere else, and TestManagementResourceLiterals pins them so a change is deliberate.
const (
	// ResourcePolicy is the one literal the spec DOES quote (11-mcp-oauth-management.md:463).
	ResourcePolicy = "policy"
	// ResourceRole matches internal/types.NotFound's own doc example ("datasource", "group", "role").
	ResourceRole = "role"
	// ResourceRoleAssignment follows A3's "group role mapping" phrasing for a join row.
	ResourceRoleAssignment = "role assignment"
	// ResourceMaskFn spells the table name out, as A3 spells `group_role` "group role mapping".
	ResourceMaskFn = "mask function"
)

// ---------------------------------------------------------------------------------------------
// Cedar policies — A2 §8's eight routes
// ---------------------------------------------------------------------------------------------

// ListPolicies is `fun listPolicies(): List<CedarPolicy>`.
func (m *PolicyManagement) ListPolicies(ctx context.Context) ([]CedarPolicy, error) {
	out, err := m.policies.List(ctx)
	if err != nil {
		return nil, mapPolicyErrors(err, nil)
	}
	// `[]`, never nil — INV-A1-4. The store's query helper returns a nil slice for no rows and the
	// route marshals whatever it is handed.
	if out == nil {
		out = []CedarPolicy{}
	}
	return out, nil
}

// CreatePolicy is `fun createPolicy(input, updatedBy): CedarPolicy`, with the two `required` checks
// A11 §8 opens `createPolicy` with (ManagementServices.kt:246-247).
func (m *PolicyManagement) CreatePolicy(
	ctx context.Context, input CedarPolicyInput, updatedBy *string,
) (CedarPolicy, error) {
	if err := managementRequired("name", input.Name); err != nil {
		return CedarPolicy{}, err
	}
	if err := managementRequired("cedarSrc", input.CedarSrc); err != nil {
		return CedarPolicy{}, err
	}
	created, err := m.policies.Create(ctx, input, updatedBy)
	if err != nil {
		return CedarPolicy{}, mapPolicyErrors(err, &input.Name)
	}
	return created, nil
}

// UpdatePolicy is `fun updatePolicy(id, input, updatedBy): CedarPolicy`.
//
// The store answers nil for an absent row (INV-A2-20's step 1); this layer is where that becomes
// `common.not_found{resource: policy}` — 404. `CedarPolicyRoutesTest` case 5 ("REST-shaped policy
// mutation remains bound to its numeric id after name reuse") depends on the update being keyed by
// id all the way down, which is why nothing here re-resolves by name.
//
// 🔒 A11 §8: the two `required` calls come FIRST, before the id is even looked up
// (ManagementServices.kt:275-277). A blank name with a nonexistent id answers
// `common.field_required`, not `common.not_found`.
func (m *PolicyManagement) UpdatePolicy(
	ctx context.Context, id int64, input CedarPolicyInput, updatedBy *string,
) (CedarPolicy, error) {
	if err := managementRequired("name", input.Name); err != nil {
		return CedarPolicy{}, err
	}
	if err := managementRequired("cedarSrc", input.CedarSrc); err != nil {
		return CedarPolicy{}, err
	}
	updated, err := m.policies.Update(ctx, id, input, updatedBy)
	if err != nil {
		return CedarPolicy{}, mapPolicyErrors(err, &input.Name)
	}
	if updated == nil {
		return CedarPolicy{}, managementNotFound(ResourcePolicy)
	}
	return *updated, nil
}

// SetPolicyEnabled is `fun setPolicyEnabled(id, enabled, updatedBy): CedarPolicy` — both
// `POST /{id}/enable` and `POST /{id}/disable`.
//
// 🔒 The enable direction can fail with [InvalidCedarPolicyError] (INV-A2-21, revalidate-on-enable),
// which mapPolicyErrors turns into the `{errors: […]}` 400 — the same body a create or update
// rejection produces. That is deliberate: from the editor's point of view "this source does not
// compile" is one failure with one rendering, whichever verb surfaced it.
func (m *PolicyManagement) SetPolicyEnabled(
	ctx context.Context, id int64, enabled bool, updatedBy *string,
) (CedarPolicy, error) {
	toggled, err := m.policies.SetEnabled(ctx, id, enabled, updatedBy)
	if err != nil {
		return CedarPolicy{}, mapPolicyErrors(err, nil)
	}
	if toggled == nil {
		return CedarPolicy{}, managementNotFound(ResourcePolicy)
	}
	return *toggled, nil
}

// DeletePolicy is `fun deletePolicy(id)`.
//
// ⚠️ THE MISSING-ROW ANSWER IS INFERRED. 02-authz.md §8's route table gives DELETE only a success
// column (204) and 09-policies.md §3's table has no error column at all, so neither says what a
// delete of a nonexistent id answers. Two readings are consistent with the spec set:
//
//	(a) 404 common.not_found — what `notFound(resource)` exists for, and what A3's identical
//	    management layer does for DELETE /api/users/{id} (03-identity-scim.md:220).
//	(b) an unconditional 204 — the precedent F76 records for DELETE {id}/classification
//	    (99-reconciliation-report.md:285), where the DeleteResult is deliberately discarded.
//
// (a) is reproduced, because A3's table is the closest parallel — same layer, same helper, an
// id-keyed REST delete — while F76 is explicitly filed as a contract INCONSISTENCY rather than the
// house rule. PINNED by TestDeletePolicyAnswersNotFoundForMissingId so a cutover correction is a
// deliberate edit to a named test rather than a silent status change.
//
//	TODO(A11): settle at cutover — DELETE a nonexistent policy id against a running Kotlin control
//	plane and read the status.
func (m *PolicyManagement) DeletePolicy(ctx context.Context, id int64) error {
	deleted, err := m.policies.Delete(ctx, id)
	if err != nil {
		return mapPolicyErrors(err, nil)
	}
	if !deleted {
		return managementNotFound(ResourcePolicy)
	}
	return nil
}

// ValidatePolicy is `fun validatePolicy(cedarSrc): CedarValidateResult` — the editor's dry run.
//
// 🔒 It NEVER returns an error: 02-authz.md:399 is "Contract: never throws for policy-shaped input.
// Empty list = valid." So a syntactically broken source is a 200 with `valid: false`, not a 400 —
// the route asked "would this compile", and the answer "no" is a successful answer. Only a
// validate-on-WRITE turns the same list into a 400.
func (m *PolicyManagement) ValidatePolicy(cedarSrc string) CedarValidateResult {
	errs := authz.DefaultSchema.Validate(cedarSrc)
	return CedarValidateResult{Valid: len(errs) == 0, Errors: errs}
}

// PolicySchema is `fun policySchema(): CedarSchemaResult` (ManagementServices.kt:292-295) — the bundled
// schema text AUGMENTED with one `action "context.tag::<name>"` declaration per tag name any stored
// policy targets.
//
// ⚠️ IT IS NOT SERVED VERBATIM, and an earlier version of this said it was. The editor uses this schema
// for schema-aware linting, and Cedar strict validation rejects an UNDECLARED action — so a schema without
// the derived tag actions makes the editor flag every working `context.tag::` rule as invalid. The tag
// vocabulary is derived from the rules themselves, which is why the augmentation has to happen here rather
// than living in the bundled file.
//
// 🔒 EVERY policy, not just the enabled ones — `policyStore.list()`. A disabled tag rule is still shown in
// the editor, so its action still has to be declared for the lint to pass.
//
// Found by the differential harness (policies-schema / policies-schema-anon): the Kotlin's body carried
// `action "context.tag::trusted-network"` — derived from the shipped -300 policy — and Go's did not.
func (m *PolicyManagement) PolicySchema(ctx context.Context) (CedarSchemaResult, error) {
	all, err := m.policies.List(ctx)
	if err != nil {
		return CedarSchemaResult{}, err
	}
	seen := map[string]bool{}
	var names []string
	for _, p := range all {
		for _, n := range authz.ExtractContextTagNames(p.CedarSrc) {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	return CedarSchemaResult{Schema: authz.DefaultSchema.AugmentedText(names)}, nil
}

// mapPolicyErrors is `private fun <T> mapPolicyErrors(body: () -> T): T`
// (11-mcp-oauth-management.md:461-463), as a translation of an already-returned error:
//
//	InvalidCedarPolicyException   ⇒ CedarValidationManagementException  (the raw error array)
//	ReservedPolicyNameException   ⇒ policy.reserved_name
//	SystemPolicyImmutableException ⇒ policy.system_immutable            (409)
//	SQLSTATE 23505                ⇒ common.already_exists{resource: policy}
//
// name is the candidate policy name for the 23505 arm, or nil where the operation has none (a
// toggle, a delete). `policy.name` is UNIQUE (V3__policy.sql:25), so a create or a rename onto an
// existing name is the only way to reach that arm.
//
// Anything unrecognised passes through untouched and StatusPages answers 500 common.fallback, which
// is right: an unmapped SQLSTATE is a bug in this function, not a caller error.
func mapPolicyErrors(err error, name *string) error {
	if err == nil {
		return nil
	}
	var invalid InvalidCedarPolicyError
	if errors.As(err, &invalid) {
		return &CedarValidationError{Errors: invalid.Errors}
	}
	var reserved ReservedPolicyNameError
	if errors.As(err, &reserved) {
		return &ManagementError{Err: types.ApiError{
			Code:   "policy.reserved_name",
			Params: map[string]string{"name": reserved.Name},
		}}
	}
	if errors.Is(err, ErrSystemPolicyImmutable) {
		return &ManagementError{Err: types.ApiError{Code: "policy.system_immutable"}}
	}
	if store.IsUniqueViolation(err) {
		return managementAlreadyExists(ResourcePolicy, name)
	}
	return err
}

// ---------------------------------------------------------------------------------------------
// Roles — A9's four routes
// ---------------------------------------------------------------------------------------------

// ListRoles is `fun listRoles(): List<Role>`.
//
// 🔒 INV-A9-3 — the ROUTE that calls this is `requireApi`, not `requireAdmin`, and that is
// deliberate. See RegisterPolicyRoutes in routes.go for the whole argument; it is repeated there
// rather than here because the gate is a property of the route, not of this method (A11's MCP
// `list_roles` tool reaches the same data behind ADMIN_POLICIES).
func (m *PolicyManagement) ListRoles(ctx context.Context) ([]Role, error) {
	out, err := m.store.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Role{}
	}
	return out, nil
}

// CreateRole is `fun createRole(input): Role` — `required("name", name)` then
// `unique("role", input.name)` (ManagementServices.kt:353-354).
func (m *PolicyManagement) CreateRole(ctx context.Context, input RoleInput) (Role, error) {
	if err := managementRequired("name", input.Name); err != nil {
		return Role{}, err
	}
	created, err := m.store.CreateRole(ctx, input)
	if err != nil {
		if store.IsUniqueViolation(err) {
			return Role{}, managementAlreadyExists(ResourceRole, &input.Name)
		}
		return Role{}, err
	}
	return created, nil
}

// UpdateRole is `fun updateRole(id, input): Role` (ManagementServices.kt:362).
//
// 🔒 INV-A11-30 / F6 — THE `isSystemRole` GUARD IS HERE, NOT IN THE STORE. 09-policies.md §2 filed
// it as a possible live gap because `Policies.kt` declares `isSystemRole` and never calls it;
// 09-policies.md Q1 closed it: the four call sites are ManagementServices.kt:362, :370, :382, :389,
// each throwing `role.system_immutable`. Without it a system role — one granted by a
// `source = 'SYSTEM'` group, e.g. `system:admin` — is renameable through the API, and renaming it
// silently detaches every Cedar policy that names it.
//
// ⚠️ It has NO Kotlin test (00-INDEX.md F19: "the largest untested surface in the control plane"),
// so TestUpdateRoleRejectsASystemRole below is NEW.
//
// 🔒 INV-A9-1 — "system role" is DERIVED: the guard asks whether any `source = 'SYSTEM'` group grants
// this role, so a role STOPS being protected the moment the last SYSTEM group mapping is removed.
// That is the Kotlin's semantics and adding an `app_role.is_system` column would change it.
//
// The guard and the update share ONE transaction. The Kotlin's per-method transaction shape is not
// quoted in the spec set for this method, but the two statements are a check-then-act on the same
// row, and A11's parallel group paths take a row lock for exactly that reason (INV-A11-32). ⚠️ Note
// this is NOT the `SELECT … FOR UPDATE` those use: `isSystemRole` reads `group_role`/`app_group`, not
// `app_role`, so there is no single row to lock. A concurrent SYSTEM mapping insert can still race a
// rename. REPRODUCE — closing it would need a lock the Kotlin does not take.
func (m *PolicyManagement) UpdateRole(ctx context.Context, id int64, input RoleInput) (Role, error) {
	return store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (Role, error) {
		system, err := m.store.IsSystemRoleOn(ctx, tx, id)
		if err != nil {
			return Role{}, err
		}
		if system {
			return Role{}, roleSystemImmutable()
		}
		// 🔒 AFTER the SYSTEM guard, not before (ManagementServices.kt:362-363): renaming a system
		// role to blank answers `role.system_immutable`, not `common.field_required`. The caller has
		// no business editing that row at all, and telling them their name is blank invites a retry.
		if err := managementRequired("name", input.Name); err != nil {
			return Role{}, err
		}
		updated, err := m.store.UpdateRoleOn(ctx, tx, id, input)
		if err != nil {
			if store.IsUniqueViolation(err) {
				return Role{}, managementAlreadyExists(ResourceRole, &input.Name)
			}
			return Role{}, err
		}
		if updated == nil {
			return Role{}, managementNotFound(ResourceRole)
		}
		return *updated, nil
	})
}

// DeleteRole is `fun deleteRole(id)` (ManagementServices.kt:382) — the same guard, same order.
//
// The missing-row answer is the inferred 404 [PolicyManagement.DeletePolicy] documents.
//
// ⚠️ Deleting a role that IS deletable cascades: V1__identity.sql:62 declares
// `principal_role.role_id … ON DELETE CASCADE` and `group_role.role_id` likewise, so every direct
// assignment and every group mapping goes with it, silently. That is the migration's behaviour, not
// this layer's, and it is why the SYSTEM guard matters more here than on update.
func (m *PolicyManagement) DeleteRole(ctx context.Context, id int64) error {
	return store.InTxDo(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) error {
		system, err := m.store.IsSystemRoleOn(ctx, tx, id)
		if err != nil {
			return err
		}
		if system {
			return roleSystemImmutable()
		}
		deleted, err := m.store.DeleteRoleOn(ctx, tx, id)
		if err != nil {
			return err
		}
		if !deleted {
			return managementNotFound(ResourceRole)
		}
		return nil
	})
}

// roleSystemImmutable is the `role.system_immutable` failure all four A11 call sites raise. 409 at
// the edge — httpapi.RespondManagementError's third arm.
func roleSystemImmutable() *ManagementError {
	return &ManagementError{Err: types.ApiError{Code: "role.system_immutable"}}
}

// ---------------------------------------------------------------------------------------------
// Role assignments — A9's three routes
// ---------------------------------------------------------------------------------------------

// ListAssignments is `fun listAssignments(principal?, roleId?): List<RoleAssignment>`.
func (m *PolicyManagement) ListAssignments(
	ctx context.Context, principal *string, roleID *int64,
) ([]RoleAssignment, error) {
	out, err := m.store.ListAssignments(ctx, principal, roleID)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []RoleAssignment{}
	}
	return out, nil
}

// CreateAssignment is `fun createAssignment(input): RoleAssignment`.
//
// 🔒 INV-A9-2 — the store's `ON CONFLICT (principal, role_id) DO UPDATE SET principal=EXCLUDED.principal
// RETURNING id` makes this IDEMPOTENT: re-assigning an existing pair returns the EXISTING row's id
// and a 201, not a conflict. So there is no `unique(...)` wrapper here and there must not be one —
// the only unique constraint on `principal_role` is the one the upsert already absorbs.
//
// ⚠️ An unknown `roleId` violates the `principal_role.role_id` foreign key (SQLSTATE 23503), which
// store.IsUniqueViolation deliberately does NOT match (F29) and which nothing else here maps either,
// so it would reach StatusPages as 500 common.fallback.
//
// 🔒 THIS IS NOT THE REST PATH, and an earlier note here wrongly said it was. `POST
// /api/role-assignments` calls the VALIDATING [PolicyManagement.AssignRoleByID] (Policies.kt:197 →
// ManagementServices.kt:395), which resolves the role first and answers 404. This method is the raw
// store passthrough, kept because the Kotlin store exposes the same unvalidated `createAssignment` for
// composing inside a caller's transaction. Its 500-on-unknown-role is reachable only through a caller
// that skips the check — which the REST surface no longer does. Measured in
// internal/conformance/differential; the route wiring was the divergence, not this method.
func (m *PolicyManagement) CreateAssignment(
	ctx context.Context, input RoleAssignmentInput,
) (RoleAssignment, error) {
	return m.store.CreateAssignment(ctx, input)
}

// DeleteAssignment is `fun deleteAssignment(id)`; the missing-row answer is the inferred 404.
func (m *PolicyManagement) DeleteAssignment(ctx context.Context, id int64) error {
	deleted, err := m.store.DeleteAssignment(ctx, id)
	if err != nil {
		return err
	}
	if !deleted {
		return managementNotFound(ResourceRoleAssignment)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------
// Mask functions — A9's four routes
// ---------------------------------------------------------------------------------------------

// ListMaskFns is `fun listMaskFns(): List<MaskFn>`.
func (m *PolicyManagement) ListMaskFns(ctx context.Context) ([]MaskFn, error) {
	out, err := m.store.ListMaskFns(ctx)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []MaskFn{}
	}
	return out, nil
}

// CreateMaskFn is `fun createMaskFn(input): MaskFn`.
//
// ⚠️ `kind` is NOT validated — free-form TEXT with no CHECK (V2__catalog.sql:70) and no check in
// `Policies.kt`. 09-policies.md Q4 is open on whether anything validates it anywhere; nothing does,
// so an admin can create a mask fn whose kind the engine cannot apply. REPRODUCE.
func (m *PolicyManagement) CreateMaskFn(ctx context.Context, input MaskFnInput) (MaskFn, error) {
	// `required("name", input.name); required("kind", input.kind)` — ManagementServices.kt:461-462.
	// The `kind` check is a BLANK check only; its VALUE is still unvalidated, per the ⚠️ above.
	if err := managementRequired("name", input.Name); err != nil {
		return MaskFn{}, err
	}
	if err := managementRequired("kind", input.Kind); err != nil {
		return MaskFn{}, err
	}
	created, err := m.store.CreateMaskFn(ctx, input)
	if err != nil {
		if store.IsUniqueViolation(err) {
			return MaskFn{}, managementAlreadyExists(ResourceMaskFn, &input.Name)
		}
		return MaskFn{}, err
	}
	return created, nil
}

// UpdateMaskFn is `fun updateMaskFn(id, input): MaskFn`.
//
// There is NO system-immutability guard here, unlike roles: `mask_fn` has no origin column and no
// SYSTEM-sourced equivalent, so every row is a user row.
func (m *PolicyManagement) UpdateMaskFn(ctx context.Context, id int64, input MaskFnInput) (MaskFn, error) {
	// `required("name", input.name); required("kind", input.kind)` — ManagementServices.kt:470-471.
	// ⚠️ The NAME-keyed overload reports the same blank input field as `newName`, not `name`
	// (ManagementServices.kt:478). Two spellings of one validation; both are on the wire.
	if err := managementRequired("name", input.Name); err != nil {
		return MaskFn{}, err
	}
	if err := managementRequired("kind", input.Kind); err != nil {
		return MaskFn{}, err
	}
	updated, err := m.store.UpdateMaskFn(ctx, id, input)
	if err != nil {
		if store.IsUniqueViolation(err) {
			return MaskFn{}, managementAlreadyExists(ResourceMaskFn, &input.Name)
		}
		return MaskFn{}, err
	}
	if updated == nil {
		return MaskFn{}, managementNotFound(ResourceMaskFn)
	}
	return *updated, nil
}

// DeleteMaskFn is `fun deleteMaskFn(id)`; the missing-row answer is the inferred 404.
//
// ⚠️ `column_classification.mask_fn_id` references this row; whether that FK cascades or restricts
// decides whether deleting an IN-USE mask fn 500s. Not this layer's call either way — it reproduces
// whatever the migration declares.
func (m *PolicyManagement) DeleteMaskFn(ctx context.Context, id int64) error {
	deleted, err := m.store.DeleteMaskFn(ctx, id)
	if err != nil {
		return err
	}
	if !deleted {
		return managementNotFound(ResourceMaskFn)
	}
	return nil
}
