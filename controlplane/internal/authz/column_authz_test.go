package authz

import "testing"

// Port of ColumnAuthzTest.kt — 215 LOC, 11 cases, unit. 02-authz.md §10.
// Case names verbatim from the Kotlin.
//
// Cases 9-11 are the EUID-INJECTIVITY SUITE. Together with case 3 they are the whole defence against
// wrong-grant collisions — 02-authz.md §10 says to port them as a group, and they are kept adjacent
// here for that reason.

// ColumnAuthzTest.kt:28-32.
var columnAuthzSeedPolicies = map[int64]string{
	1: `permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource in Table::"acme-pg/acme/public/users") unless { resource in Tag::"pii" };`,
	2: `permit(principal in Role::"analyst", action == Action::"result.read.masked", resource in Table::"acme-pg/acme/public/users") when { resource in Tag::"pii" };`,
	3: `permit(principal in Role::"column-reader", action == Action::"result.read.unmasked", resource == Column::"acme-pg/acme/public/users/region");`,
}

func assertVerdicts(t *testing.T, got map[string]ColumnVerdict, want map[string]ColumnVerdict) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("verdict count: got %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for k, w := range want {
		if g, ok := got[k]; !ok {
			t.Errorf("%s: no verdict returned (INV-A2-5: every input gets an explicit verdict)", k)
		} else if g != w {
			t.Errorf("%s: got %s, want %s", k, g, w)
		}
	}
}

// 1. an untagged column in the granted table is unmasked
func TestColumnAuthz_AnUntaggedColumnInTheGrantedTableIsUnmasked(t *testing.T) {
	a := authzFor(t, columnAuthzSeedPolicies, nil)
	got := a.AuthorizeColumns("alice", []string{"analyst"}, "acme-pg", []ColumnRef{
		{Key: "acme.public.users.region", Catalog: "acme", Schema: "public", Table: "users", Column: "region"},
	}, AuthzContext{}, nil, nil)
	assertVerdicts(t, got, map[string]ColumnVerdict{"acme.public.users.region": ColumnUnmasked})
}

// 2. a fully-qualified `Column` EUID grant matches its exact column
func TestColumnAuthz_AFullyQualifiedColumnEUIDGrantMatchesItsExactColumn(t *testing.T) {
	a := authzFor(t, columnAuthzSeedPolicies, nil)
	got := a.AuthorizeColumns("bob", []string{"column-reader"}, "acme-pg", []ColumnRef{
		{Key: "acme.public.users.region", Catalog: "acme", Schema: "public", Table: "users", Column: "region"},
	}, AuthzContext{}, nil, nil)
	assertVerdicts(t, got, map[string]ColumnVerdict{"acme.public.users.region": ColumnUnmasked})
}

// 3. 🔒 an identifier containing a key delimiter is denied fail-closed (INV-A2-6)
//
// The two DENIED verdicts are decided BEFORE Cedar — the guard, not the engine, produces them. Note the
// policy is a BLANKET permit, so without the guard both would be UNMASKED.
func TestColumnAuthz_AnIdentifierContainingAKeyDelimiterIsDeniedFailClosed(t *testing.T) {
	a := authzFor(t, map[int64]string{
		9: `permit(principal in Role::"r", action == Action::"result.read.unmasked", resource);`,
	}, nil)
	got := a.AuthorizeColumns("u", []string{"r"}, "acme-pg", []ColumnRef{
		{Key: "slash", Catalog: "acme", Schema: "public", Table: "a/users", Column: "rrn"},
		{Key: "dot", Catalog: "acme", Schema: "pub.lic", Table: "users", Column: "rrn"},
		{Key: "clean", Catalog: "acme", Schema: "public", Table: "users", Column: "rrn"},
	}, AuthzContext{}, nil, nil)
	assertVerdicts(t, got, map[string]ColumnVerdict{
		"slash": ColumnDenied,
		"dot":   ColumnDenied,
		"clean": ColumnUnmasked,
	})
}

// 4. a pii-tagged column in the granted table is masked, not unmasked
//
// ORDERED: unmasked is asked first, masked second; unmasked wins when both allow.
func TestColumnAuthz_APiiTaggedColumnInTheGrantedTableIsMaskedNotUnmasked(t *testing.T) {
	a := authzFor(t, columnAuthzSeedPolicies, nil)
	got := a.AuthorizeColumns("alice", []string{"analyst"}, "acme-pg", []ColumnRef{
		{Key: "acme.public.users.rrn", Catalog: "acme", Schema: "public", Table: "users", Column: "rrn", Tags: []string{"pii"}},
	}, AuthzContext{}, nil, nil)
	assertVerdicts(t, got, map[string]ColumnVerdict{"acme.public.users.rrn": ColumnMasked})
}

// 5. 🔒 a column in an ungranted table is denied — deny-by-default, not absent-equals-cleartext
func TestColumnAuthz_AColumnInAnUngrantedTableIsDenied(t *testing.T) {
	a := authzFor(t, columnAuthzSeedPolicies, nil)
	got := a.AuthorizeColumns("alice", []string{"analyst"}, "acme-pg", []ColumnRef{
		{Key: "acme.public.orders.amount", Catalog: "acme", Schema: "public", Table: "orders", Column: "amount"},
	}, AuthzContext{}, nil, nil)
	assertVerdicts(t, got, map[string]ColumnVerdict{"acme.public.orders.amount": ColumnDenied})
}

// 6. 🔒 a pii-tagged column in an UNGRANTED table is denied, not masked — the masked grant is
// table-scoped
func TestColumnAuthz_APiiTaggedColumnInAnUngrantedTableIsDeniedNotMasked(t *testing.T) {
	a := authzFor(t, columnAuthzSeedPolicies, nil)
	got := a.AuthorizeColumns("alice", []string{"analyst"}, "acme-pg", []ColumnRef{
		{Key: "acme.public.orders.card", Catalog: "acme", Schema: "public", Table: "orders", Column: "card", Tags: []string{"pii"}},
	}, AuthzContext{}, nil, nil)
	assertVerdicts(t, got, map[string]ColumnVerdict{"acme.public.orders.card": ColumnDenied})
}

// 7. no roles at all is denied on every column
func TestColumnAuthz_NoRolesAtAllIsDeniedOnEveryColumn(t *testing.T) {
	a := authzFor(t, columnAuthzSeedPolicies, nil)
	got := a.AuthorizeColumns("nobody", nil, "acme-pg", []ColumnRef{
		{Key: "acme.public.users.region", Catalog: "acme", Schema: "public", Table: "users", Column: "region"},
	}, AuthzContext{}, nil, nil)
	assertVerdicts(t, got, map[string]ColumnVerdict{"acme.public.users.region": ColumnDenied})
}

// 8. a batch of columns resolves independent verdicts in one call (INV-A2-5)
//
// ONE Entities batch, two isAuthorized per column.
func TestColumnAuthz_ABatchOfColumnsResolvesIndependentVerdictsInOneCall(t *testing.T) {
	a := authzFor(t, columnAuthzSeedPolicies, nil)
	got := a.AuthorizeColumns("alice", []string{"analyst"}, "acme-pg", []ColumnRef{
		{Key: "acme.public.users.region", Catalog: "acme", Schema: "public", Table: "users", Column: "region"},
		{Key: "acme.public.users.rrn", Catalog: "acme", Schema: "public", Table: "users", Column: "rrn", Tags: []string{"pii"}},
		{Key: "acme.public.orders.amount", Catalog: "acme", Schema: "public", Table: "orders", Column: "amount"},
	}, AuthzContext{}, nil, nil)
	assertVerdicts(t, got, map[string]ColumnVerdict{
		"acme.public.users.region":  ColumnUnmasked,
		"acme.public.users.rrn":     ColumnMasked,
		"acme.public.orders.amount": ColumnDenied,
	})
}

// 9. 🔒 a permit on `public.users` does not cover `analytics.users` with the same table name
func TestColumnAuthz_APermitOnPublicUsersDoesNotCoverAnalyticsUsers(t *testing.T) {
	a := authzFor(t, columnAuthzSeedPolicies, nil)
	got := a.AuthorizeColumns("alice", []string{"analyst"}, "acme-pg", []ColumnRef{
		{Key: "acme.analytics.users.region", Catalog: "acme", Schema: "analytics", Table: "users", Column: "region"},
	}, AuthzContext{}, nil, nil)
	assertVerdicts(t, got, map[string]ColumnVerdict{"acme.analytics.users.region": ColumnDenied})
}

// 10. 🔒 a permit in one catalog does not cover the same schema+table in another catalog
func TestColumnAuthz_APermitInOneCatalogDoesNotCoverAnotherCatalog(t *testing.T) {
	a := authzFor(t, columnAuthzSeedPolicies, nil)
	got := a.AuthorizeColumns("alice", []string{"analyst"}, "acme-pg", []ColumnRef{
		{Key: "other.public.users.region", Catalog: "other", Schema: "public", Table: "users", Column: "region"},
	}, AuthzContext{}, nil, nil)
	assertVerdicts(t, got, map[string]ColumnVerdict{"other.public.users.region": ColumnDenied})
}

// 11. 🔒 a different datasource with the same qualified table is not covered by the grant
func TestColumnAuthz_ADifferentDatasourceWithTheSameQualifiedTableIsNotCovered(t *testing.T) {
	a := authzFor(t, columnAuthzSeedPolicies, nil)
	got := a.AuthorizeColumns("alice", []string{"analyst"}, "other-ds", []ColumnRef{
		{Key: "acme.public.users.region", Catalog: "acme", Schema: "public", Table: "users", Column: "region"},
	}, AuthzContext{}, nil, nil)
	assertVerdicts(t, got, map[string]ColumnVerdict{"acme.public.users.region": ColumnDenied})
}
