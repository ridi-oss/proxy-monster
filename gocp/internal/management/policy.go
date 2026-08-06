package management

import "github.com/ridi-oss/proxy-monster/gocp/internal/policy"

// PolicyService is A11 §8's `PolicyManagementService` — ~28 methods over Cedar policies, roles,
// assignments and mask functions, each in name-keyed, id-keyed and connection-taking variants.
//
// 🔴 IT IS AN ALIAS FOR policy.PolicyManagement, and the methods are declared in internal/policy:
// management_crud.go holds the id-keyed half, management_named.go the name-keyed and
// connection-taking half, management.go `ReplaceDirectRoles`. Go can only declare a method in the
// package that declares the receiver's type, and that type already existed — A1's `/auth/debug`
// needed `replaceDirectRoles` before A11 was written, so internal/policy/management.go landed it
// with the instruction "EXTEND [PolicyManagement]; do not declare a second service type".
//
// The alias exists so a caller of this layer imports ONE package for all three §8 services and
// cannot end up holding two names for the same thing. It is a true alias, so
// `management.PolicyService` and `policy.PolicyManagement` are interchangeable everywhere, including
// in a type switch.
type PolicyService = policy.PolicyManagement

// NewPolicyService is `PolicyManagementService(CedarPolicyStore(dataSource), policyStore)` — the
// constructor, argument order included. ONE instance is shared by the HTTP and MCP surfaces
// (INV-A1-1), because the Cedar store carries the post-commit version counter INV-A11-31 bumps and a
// second instance would bump a counter nobody reads.
var NewPolicyService = policy.NewPolicyManagement

// The `resource` literals PolicyService passes to notFound / unique, re-exported so a caller
// asserting on a management failure names the same constant the service raised.
const (
	// ResourcePolicy is `common.already_exists{resource: policy}` — the one literal the area doc
	// quotes (11-mcp-oauth-management.md:463).
	ResourcePolicy = policy.ResourcePolicy
	// ResourceRoleAssignment is `notFound("role assignment")`.
	ResourceRoleAssignment = policy.ResourceRoleAssignment
	// ResourceMaskFn is `notFound("mask function")` / `unique("mask function", …)`.
	ResourceMaskFn = policy.ResourceMaskFn
)
