package authz

import "testing"

// Port of AuthzDatasourceActionTest.kt — 144 LOC, 6 cases, unit. 02-authz.md §10.
// Case names verbatim from the Kotlin.

// AuthzDatasourceActionTest.kt:29-40.
var dsActionSeedPolicies = map[int64]string{
	1: `permit(principal in Role::"batch-writer", action in [Action::"datasource.connect", Action::"sql.select", Action::"sql.insert"], resource in Datasource::"acme-mysql");`,
	2: `permit(principal, action == Action::"sql.unmaskable", resource) when { resource in Tag::"system:development" };`,
}

// 1. a granted role may connect to the named datasource
func TestDatasourceAction_AGrantedRoleMayConnectToTheNamedDatasource(t *testing.T) {
	a := authzFor(t, dsActionSeedPolicies, nil)
	d := a.AuthorizeDatasourceAction("alice", []string{"batch-writer"},
		ActionDatasourceConnect, "acme-mysql", AuthzContext{}, nil)
	assertAllow(t, d, "datasource.connect on acme-mysql")
}

// 2. a granted role may run a granted sql kind on the named datasource
func TestDatasourceAction_AGrantedRoleMayRunAGrantedSQLKind(t *testing.T) {
	a := authzFor(t, dsActionSeedPolicies, nil)
	d := a.AuthorizeDatasourceAction("alice", []string{"batch-writer"},
		ActionSQLInsert, "acme-mysql", AuthzContext{}, nil)
	assertAllow(t, d, "sql.insert on acme-mysql")
}

// 3. `sql.unmaskable` follows the preset-development datasource tag (INV-A2-1)
//
// INV-A2-1 + INV-A2-7: the posture tag becomes a Tag parent on the Datasource entity, and the exception
// gate is a Cedar decision rather than a hardcoded deny.
func TestDatasourceAction_SQLUnmaskableFollowsThePresetDevelopmentTag(t *testing.T) {
	a := authzFor(t, dsActionSeedPolicies, nil)

	withTag := a.AuthorizeDatasourceAction("alice", []string{"batch-writer"},
		ActionSQLUnmaskable, "acme-mysql", AuthzContext{}, []string{"system:development"})
	assertAllow(t, withTag, "sql.unmaskable with system:development")

	withoutTag := a.AuthorizeDatasourceAction("alice", []string{"batch-writer"},
		ActionSQLUnmaskable, "acme-mysql", AuthzContext{}, nil)
	assertDeny(t, withoutTag, "sql.unmaskable with no posture tag")
}

// 4. 🔒 an ungranted sql kind is denied — deny-by-default, not absent-equals-allow
func TestDatasourceAction_AnUngrantedSQLKindIsDenied(t *testing.T) {
	a := authzFor(t, dsActionSeedPolicies, nil)
	d := a.AuthorizeDatasourceAction("alice", []string{"batch-writer"},
		ActionSQLDelete, "acme-mysql", AuthzContext{}, nil)
	assertDeny(t, d, "sql.delete is not in the grant")
}

// 5. 🔒 the same grant on a different datasource name does not apply — NAME-keyed, not blanket
// (INV-A2-2)
func TestDatasourceAction_TheSameGrantOnADifferentDatasourceNameDoesNotApply(t *testing.T) {
	a := authzFor(t, dsActionSeedPolicies, nil)
	d := a.AuthorizeDatasourceAction("alice", []string{"batch-writer"},
		ActionDatasourceConnect, "other", AuthzContext{}, nil)
	assertDeny(t, d, "datasource.connect on `other`")
}

// 6. no roles at all is denied
func TestDatasourceAction_NoRolesAtAllIsDenied(t *testing.T) {
	a := authzFor(t, dsActionSeedPolicies, nil)
	d := a.AuthorizeDatasourceAction("nobody", nil,
		ActionDatasourceConnect, "acme-mysql", AuthzContext{}, nil)
	assertDeny(t, d, "no roles")
}
