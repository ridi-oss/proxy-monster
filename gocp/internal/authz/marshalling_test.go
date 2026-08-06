package authz

import (
	"sort"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
)

// Not ported cases — these cover the parts of 02-authz.md the Kotlin suite leaves untested but which
// §3 calls "the complete marshalling contract" and §10 lists as coverage gaps.

// TestActionVocabulary — 02-authz.md §2's 24 values with their exact cedarId strings. Every string here
// is a wire contract: it is the literal Action:: id the seed policies and the schema use.
func TestActionVocabulary(t *testing.T) {
	want := []string{
		"admin.datasources", "admin.policies", "admin.identity",
		"task.approve", "task.request", "task.read", "task.assume", "task.cancel", "task.delete",
		"grant.revoke",
		"token.mint", "token.list", "token.revoke",
		"audit.read",
		"result.read.unmasked", "result.read.masked",
		"datasource.connect",
		"sql.select", "sql.insert", "sql.update", "sql.delete", "sql.ddl",
		"sql.unanalyzable", "sql.unmaskable",
	}
	if len(allAuthzActions) != 24 {
		t.Fatalf("AuthzAction has %d values, want 24", len(allAuthzActions))
	}
	for i, a := range allAuthzActions {
		if a.CedarID() != want[i] {
			t.Errorf("action %d: cedarId = %q, want %q", i, a.CedarID(), want[i])
		}
	}
	// Every action must be declared by the bundled schema — the check that would have caught the five
	// retired workflow.* ids (AuthzTest case 13) at the vocabulary level rather than per-policy.
	for _, a := range allAuthzActions {
		assertValid(t, `permit(principal, action == Action::"`+a.CedarID()+`", resource);`)
	}
}

// TestEUIDMarshallingTable is 02-authz.md §3's table, asserted entry by entry. Every EUID FORMAT is a
// contract: the seed policies match on these exact strings.
func TestEUIDMarshallingTable(t *testing.T) {
	kind := TokenKindUser
	cases := []struct {
		name     string
		resource AuthzResource
		euid     string
	}{
		{"System", ResourceSystem{}, `System::"system"`},
		{"AuditRecord", ResourceAuditRecord{Principal: "alice"}, `AuditRecord::"alice"`},
		{"AuditLog", ResourceAuditLog{}, `AuditLog::"all"`},
		{"ApprovalRequest, no datasource", ResourceApprovalRequest{Requester: "alice"}, `Request::"alice#-"`},
		{"ApprovalRequest, datasource", ResourceApprovalRequest{Requester: "alice", DatasourceName: ptr("acme-mysql")}, `Request::"alice#acme-mysql"`},
		{"AccessGrant", ResourceAccessGrant{Owner: "alice", ID: 42}, `AccessGrant::"alice#42"`},
		{"Token, no kind", ResourceToken{Owner: "alice"}, `Token::"alice#-"`},
		{"Token, kind", ResourceToken{Owner: "alice", Kind: &kind}, `Token::"alice#USER"`},
	}
	for _, c := range cases {
		euid, _ := marshalResource(c.resource)
		if got := euid.String(); got != c.euid {
			t.Errorf("%s: EUID = %s, want %s", c.name, got, c.euid)
		}
	}
}

// TestTokenKindAbsenceIsMeaningful — 🔒 INV-A2-3. A nil Kind leaves the Cedar `kind` attribute ABSENT,
// which is what lets a policy permit short sessions while forbidding long-lived PATs. Emitting
// kind: "" or kind: "null" would break those policies.
func TestTokenKindAbsenceIsMeaningful(t *testing.T) {
	_, ents := marshalResource(ResourceToken{Owner: "alice"})
	if _, ok := ents[0].Attributes.Get("kind"); ok {
		t.Error("INV-A2-3: a nil Kind must leave the `kind` attribute ABSENT, not empty")
	}
	if _, ok := ents[0].Attributes.Get("owner"); !ok {
		t.Error("`owner` is required and must always be present")
	}

	kind := TokenKindSession
	_, ents = marshalResource(ResourceToken{Owner: "alice", Kind: &kind})
	v, ok := ents[0].Attributes.Get("kind")
	if !ok || v != types.String("SESSION") {
		t.Errorf("kind attribute = %v (present %v), want the enum NAME \"SESSION\"", v, ok)
	}

	// And end-to-end: a kind-scoped forbid must not fire when the kind is absent.
	a := authzFor(t, map[int64]string{
		1: `permit(principal, action == Action::"token.list", resource);`,
		2: `forbid(principal, action == Action::"token.list", resource) when { resource has kind && resource.kind == "USER" };`,
	}, nil)
	assertAllow(t, a.Authorize("alice", ActionTokenList, ResourceToken{Owner: "alice"}, AuthzContext{}),
		"listing with no kind in scope")
	userKind := TokenKindUser
	assertDeny(t, a.Authorize("alice", ActionTokenList, ResourceToken{Owner: "alice", Kind: &userKind}, AuthzContext{}),
		"a USER token is covered by the kind-scoped forbid")
}

// TestApprovalRequestOptionalAttributes — approver and executedBy do not exist until the task is
// decided/executed, so they are marshalled only when present. Every policy reading one must has-guard
// it, and the validator rejects an unguarded read — which is what closes the fail-open where an operator
// forbid conditioned on `approver` would silently permit a PRE-DECISION task.
func TestApprovalRequestOptionalAttributes(t *testing.T) {
	_, ents := marshalResource(ResourceApprovalRequest{Requester: "alice"})
	for _, absent := range []types.String{"approver", "executedBy"} {
		if _, ok := ents[0].Attributes.Get(absent); ok {
			t.Errorf("%s must be ABSENT when nil", absent)
		}
	}
	if _, ok := ents[0].Attributes.Get("requester"); !ok {
		t.Error("requester is schema-required and must always be present")
	}

	// The unguarded read is rejected by the schema — the mechanism the comment above describes.
	assertInvalid(t, `forbid(principal, action == Action::"task.approve", resource) when { resource.approver == principal };`)
	assertValid(t, `forbid(principal, action == Action::"task.approve", resource) when { resource has approver && resource.approver == principal };`)
}

// TestDatasourcePostureTagsAreTypeScoped — 🔒 INV-A2-7 on the Datasource side. Only
// system:development / system:production become Tag PARENTS; every other tag is dropped as a parent,
// though free-form tags are carried by the caller and inert.
func TestADatasourceCarriesEveryTagItHolds(t *testing.T) {
	tags := newTagEuidCache()
	dsEuid := types.NewEntityUID(typeDatasource, "acme-pg")
	ent := datasourceEntity(dsEuid, "acme-pg", []string{
		"system:development", "system:critical", "pii", "team-analytics",
	}, tags)

	var parents []string
	for p := range ent.Parents.All() {
		parents = append(parents, p.String())
	}
	// #78 — every tag becomes a Tag parent, reserved-looking or not. This used to assert that only
	// `system:development` survived and the other three were dropped.
	sort.Strings(parents)
	want := []string{`Tag::"pii"`, `Tag::"system:critical"`, `Tag::"system:development"`, `Tag::"team-analytics"`}
	if len(parents) != len(want) {
		t.Fatalf("Datasource parents = %v, want all four: %v", parents, want)
	}
	for i := range want {
		if parents[i] != want[i] {
			t.Errorf("Datasource parents = %v, want %v — a tag is a tag (#78); none is filtered at marshalling",
				parents, want)
			break
		}
	}
	if v, ok := ent.Attributes.Get("name"); !ok || v != types.String("acme-pg") {
		t.Errorf("the Datasource `name` attribute must be set: got %v", v)
	}
}

// TestForgedSystemTagIsStrippedOffAColumn is the A2-level half of PresetPolicyDbTest case 9 — "a forged
// preset-development tag is honored on a datasource but stripped off a column".
//
// 🔒 INV-A2-7, and it is the attack the whole invariant exists to prevent: a Column whose CATALOG ROW
// carried a hand-written system:development would satisfy a preset permit and LEAK CLEARTEXT.
func TestAColumnCarriesEveryTagItHolds(t *testing.T) {
	// A preset-shaped permit conditioned on the development posture.
	policies := map[int64]string{
		1: `permit(principal in Role::"dev", action == Action::"result.read.unmasked", resource) when { resource in Tag::"system:development" };`,
	}
	a := authzFor(t, policies, nil)
	forged := []ColumnRef{{
		Key: "acme.public.users.rrn", Catalog: "acme", Schema: "public", Table: "users", Column: "rrn",
		Tags: []string{"system:development", "system:critical", "udf:output-vouched"},
	}}

	// Honoured on the DATASOURCE: the real posture reaches the Column through its Datasource parent.
	honoured := a.AuthorizeColumns("alice", []string{"dev"}, "acme-pg", forged, AuthzContext{}, nil,
		[]string{"system:development"})
	if honoured["acme.public.users.rrn"] != ColumnUnmasked {
		t.Errorf("a genuine datasource posture tag must reach the column: got %s",
			honoured["acme.public.users.rrn"])
	}

	// #78 — THE COLUMN'S OWN TAGS NOW COUNT, with no manifest classification in play at all. This used
	// to assert the opposite: that a `system:*` tag written onto a column row was stripped before the
	// Cedar graph was built, so the permit could not fire. Upstream removed that filter, so the same
	// input is now UNMASKED.
	//
	// ⚠️ That is a real widening, and it is the trade upstream made deliberately: the shipped `system:`
	// classification is resolved per statement from the manifest rather than read from a tag row, so a
	// tag row cannot forge a classification — but it CAN match a policy that keys on the tag's name,
	// which is what happens here. See internal/authz/entities.go's package note.
	ownTags := a.AuthorizeColumns("alice", []string{"dev"}, "acme-pg", forged, AuthzContext{}, nil, nil)
	if ownTags["acme.public.users.rrn"] != ColumnUnmasked {
		t.Errorf("a column's own system:development tag must reach the permit (#78): got %s",
			ownTags["acme.public.users.rrn"])
	}
}

// TestSystemTagInheritedThroughTheTableParent is the other half of INV-A2-7: a column's REAL system
// classification arrives from the shipped manifest, attached to the TABLE, and is inherited
// transitively — never from a direct tag on the column.
func TestSystemTagInheritedThroughTheTableParent(t *testing.T) {
	a := authzFor(t, map[int64]string{
		1: `permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource in Datasource::"acme-pg");`,
		2: `forbid(principal, action == Action::"result.read.unmasked", resource) when { resource in Tag::"system:critical" };`,
	}, nil)
	cols := []ColumnRef{
		{Key: "critical", Catalog: "acme", Schema: "pg_catalog", Table: "pg_authid", Column: "rolpassword"},
		{Key: "ordinary", Catalog: "acme", Schema: "public", Table: "users", Column: "region"},
	}
	got := a.AuthorizeColumns("alice", []string{"analyst"}, "acme-pg", cols, AuthzContext{},
		map[TableIdentity]string{
			{Catalog: "acme", Schema: "pg_catalog", Table: "pg_authid"}: "system:critical",
		}, nil)

	if got["critical"] != ColumnDenied {
		t.Errorf("a column of a system:critical table must inherit the forbid through its Table parent: got %s", got["critical"])
	}
	if got["ordinary"] != ColumnUnmasked {
		t.Errorf("an ordinary column under the same datasource grant must be unmasked: got %s", got["ordinary"])
	}
}

// TestDelimiterGuardAsymmetry — 🔒 INV-A2-6. Columns and tables reject BOTH '/' and '.'; functions and
// utilities reject '/' ONLY. §4 calls the asymmetry intentional but "a sharp edge — replicate exactly",
// so it is asserted rather than assumed.
func TestDelimiterGuardAsymmetry(t *testing.T) {
	// A blanket permit, so anything that BUILDS an EUID is allowed and only the guard can deny.
	blanket := map[int64]string{
		1: `permit(principal in Role::"r", action == Action::"result.read.unmasked", resource);`,
	}
	a := authzFor(t, blanket, nil)
	roles := []string{"r"}

	tables := a.AuthorizeTables("u", roles, "acme-pg", []TableRef{
		{Key: "slash", Catalog: "acme", Schema: "public", Table: "a/users"},
		{Key: "dot", Catalog: "acme", Schema: "pub.lic", Table: "users"},
		{Key: "clean", Catalog: "acme", Schema: "public", Table: "users"},
	}, AuthzContext{}, nil, nil)
	if tables["slash"] != TableDenied || tables["dot"] != TableDenied || tables["clean"] != TableRead {
		t.Errorf("tables guard both '/' and '.': got %v", tables)
	}

	// Functions: '/' denies, '.' does NOT — a dotted function name still builds an EUID.
	fns := a.AuthorizeFunctions("u", roles, "acme-pg", []FunctionRef{
		{Name: "pg/read_file"},
		{Name: "pg.read_file"},
		{Name: "pg_read_file"},
	}, AuthzContext{}, nil, nil)
	if fns["pg/read_file"] != FunctionDenied {
		t.Errorf("a '/' in a function name must deny: got %s", fns["pg/read_file"])
	}
	if fns["pg.read_file"] != FunctionAllowed {
		t.Errorf("INV-A2-6 asymmetry: '.' must NOT be guarded for functions: got %s", fns["pg.read_file"])
	}
	if fns["pg_read_file"] != FunctionAllowed {
		t.Errorf("a clean function name must be allowed under a blanket permit: got %s", fns["pg_read_file"])
	}

	// Utilities: same asymmetry.
	utils := a.AuthorizeUtilities("u", roles, "acme-pg", []UtilityRef{
		{Command: "SHOW/PROCESSLIST"},
		{Command: "SHOW.PROCESSLIST"},
		{Command: "SHOW_PROCESSLIST"},
	}, AuthzContext{}, nil, nil)
	if utils["SHOW/PROCESSLIST"] != UtilityDenied {
		t.Errorf("a '/' in a command must deny: got %s", utils["SHOW/PROCESSLIST"])
	}
	if utils["SHOW.PROCESSLIST"] != UtilityUse {
		t.Errorf("INV-A2-6 asymmetry: '.' must NOT be guarded for utilities: got %s", utils["SHOW.PROCESSLIST"])
	}
	if utils["SHOW_PROCESSLIST"] != UtilityUse {
		t.Errorf("a clean command must be allowed under a blanket permit: got %s", utils["SHOW_PROCESSLIST"])
	}
}

// TestDelimiterGuardCoversTheDatasourceName — INV-A2-6 explicitly INCLUDES the datasource name. A
// delimiter there denies EVERY item in the batch, on all four paths.
func TestDelimiterGuardCoversTheDatasourceName(t *testing.T) {
	a := authzFor(t, map[int64]string{
		1: `permit(principal in Role::"r", action == Action::"result.read.unmasked", resource);`,
	}, nil)
	roles := []string{"r"}

	cols := a.AuthorizeColumns("u", roles, "acme/pg", []ColumnRef{
		{Key: "k", Catalog: "acme", Schema: "public", Table: "users", Column: "region"},
	}, AuthzContext{}, nil, nil)
	if cols["k"] != ColumnDenied {
		t.Errorf("a delimiter in the DATASOURCE name must deny every column: got %s", cols["k"])
	}

	fns := a.AuthorizeFunctions("u", roles, "acme/pg", []FunctionRef{{Name: "now"}}, AuthzContext{}, nil, nil)
	if fns["now"] != FunctionDenied {
		t.Errorf("a delimiter in the DATASOURCE name must deny every function: got %s", fns["now"])
	}
}

// TestUtilityInversionIsTheCallersProblem is the executable form of INV-A2-11's warning, and 02-authz.md
// §10 names it a SECURITY coverage gap in the Kotlin suite ("the utility-marshalling inversion").
//
// It asserts the DANGEROUS behaviour, not a fix: an UNCLASSIFIED utility marshalled under a
// datasource-scoped read grant is PERMITTED. That is exactly why the caller must hard-deny an
// unclassifiable utility UPSTREAM and never pass it here. Reproduce, do not repair.
func TestUtilityInversionIsTheCallersProblem(t *testing.T) {
	a := authzFor(t, map[int64]string{
		1: `permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource in Datasource::"acme-pg");`,
		2: `forbid(principal, action == Action::"result.read.unmasked", resource) when { resource in Tag::"system:activity" };`,
	}, nil)
	roles := []string{"analyst"}

	classified := a.AuthorizeUtilities("u", roles, "acme-pg", []UtilityRef{{Command: "SHOW_PROCESSLIST"}},
		AuthzContext{}, map[string]string{"SHOW_PROCESSLIST": "system:activity"}, nil)
	if classified["SHOW_PROCESSLIST"] != UtilityDenied {
		t.Errorf("a system:activity utility must be denied by the shipped forbid: got %s", classified["SHOW_PROCESSLIST"])
	}

	// 🔴 The inversion. No systemTags entry -> no Tag parent -> the datasource read grant PERMITS.
	unclassified := a.AuthorizeUtilities("u", roles, "acme-pg", []UtilityRef{{Command: "SHOW_SOMETHING_NEW"}},
		AuthzContext{}, nil, nil)
	if unclassified["SHOW_SOMETHING_NEW"] != UtilityUse {
		t.Fatalf("premise changed: an unclassified utility is no longer PERMITTED by a datasource read "+
			"grant (got %s). INV-A2-11's upstream hard-deny requirement should be re-derived.",
			unclassified["SHOW_SOMETHING_NEW"])
	}
	t.Log("INV-A2-11 reproduced: marshalling an UNCLASSIFIED utility inverts the decision from deny " +
		"to allow. The caller MUST hard-deny an unclassifiable utility upstream — the deny-by-default " +
		"on an untagged EUID is a defensive backstop, not the load-bearing path.")
}

// TestTablesReadIsGrantedByEitherAction — §4: TableVerdict.READ is granted by EITHER
// result.read.unmasked OR result.read.masked, because a masked reader already observes the table's rows
// through masked projections, so existence and cardinality are not additionally protected.
func TestTablesReadIsGrantedByEitherAction(t *testing.T) {
	maskedOnly := authzFor(t, map[int64]string{
		1: `permit(principal in Role::"analyst", action == Action::"result.read.masked", resource in Datasource::"acme-pg");`,
	}, nil)
	got := maskedOnly.AuthorizeTables("u", []string{"analyst"}, "acme-pg", []TableRef{
		{Key: "t", Catalog: "acme", Schema: "public", Table: "users"},
	}, AuthzContext{}, nil, nil)
	if got["t"] != TableRead {
		t.Errorf("a masked-only grant must still permit the scan: got %s", got["t"])
	}

	none := authzFor(t, map[int64]string{
		1: `permit(principal in Role::"analyst", action == Action::"datasource.connect", resource in Datasource::"acme-pg");`,
	}, nil)
	got = none.AuthorizeTables("u", []string{"analyst"}, "acme-pg", []TableRef{
		{Key: "t", Catalog: "acme", Schema: "public", Table: "users"},
	}, AuthzContext{}, nil, nil)
	if got["t"] != TableDenied {
		t.Errorf("no result.read grant means DENIED, deny-by-default: got %s", got["t"])
	}
}
