package mcp

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
)

// ---------------------------------------------------------------------------------------------
// 🔴 NEW COVERAGE — 00-INDEX.md F19 / 11-mcp-oauth-management.md §9.
//
// "Eight cases for 38 tools. Case 7 covers 'representative tool families' — i.e. MOST OF THE 38 TOOLS
// HAVE NO INDIVIDUAL TEST." Sixteen of the 38 are never invoked by the Kotlin suite at all, and a
// dispatch arm that was never invoked is a `when` branch nobody has ever run: a wrong management
// overload, a swapped argument, a `requiredString` where the Kotlin used `string` — none of those
// would fail a single existing test.
//
// This file drives EVERY tool in the catalog at least once against the real services, in an order
// where each tool's precondition is another tool's effect, and asserts the specific shape each one
// returns rather than merely "no error".
// ---------------------------------------------------------------------------------------------

// TestEveryToolInTheCatalogDispatches is the coverage floor: after this runs, the set of tools it
// exercised must EQUAL [ApprovedToolNames]. The final assertion is what makes it a floor rather than a
// long list — adding a 39th tool to the catalog fails here until someone drives it.
//
// It is a STRICT SUPERSET of McpServerDbTest case 7, which drives ten tools it calls "representative
// tool families" and then asserts the structured liveness shape. Every one of those ten is driven here,
// the liveness shape is asserted below (including the two absent error keys the Kotlin checks), and the
// audit half of the Kotlin case — a write audits, a read does not — is
// TestASuccessfulReadWritesNoAuditRowAndEveryWriteDoes.
// KT: McpServerDbTest.kt#representative tool families dispatch successfully with structured liveness and audit — dispatch + liveness half
func TestEveryToolInTheCatalogDispatches(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-every-tool@example.com"
	f.grantRole(principal, "system:admin")
	f.seedDatasource("every-tool-ds")
	f.attached.names["every-tool-ds"] = struct{}{}
	f.tableDetails.fetch = func(_ context.Context, _, schema, table string) (*engine.TableDetail, error) {
		return &engine.TableDetail{
			Schema: schema, Table: table,
			Columns: []engine.TableDetailColumn{{
				Name: "rrn", DataType: "text", Ordinal: 1, Nullable: true,
			}},
			Indexes: []engine.TableIndex{}, ForeignKeys: []engine.TableRelation{},
			ReferencedBy: []engine.TableRelation{},
		}, nil
	}
	token := f.mintToken(principal, ScopeRead, ScopeDatasourcesWrite, ScopePoliciesWrite, ScopeIdentityWrite)

	exercised := map[string]struct{}{}
	// ok drives one tool and asserts it did NOT come back as an MCP error. The tool name is recorded
	// whether or not the assertion holds, so a failing tool is reported as a failure and not also as a
	// coverage hole.
	//
	// It also asserts STRUCTURED CONTENT, which is the Kotlin `assertToolSuccess`'s second half
	// (`assertNotNull(result.structuredContent)`): every arm answers through `structured(...)` /
	// `structuredValue(...)`, so a tool that came back with prose in `content` and nothing machine-
	// readable would be a success no MCP client could consume.
	ok := func(tool string, args map[string]any) callResult {
		t.Helper()
		exercised[tool] = struct{}{}
		_, result := f.call(token, tool, args)
		if result.isError {
			t.Errorf("%s: unexpected MCP error: %s", tool, result.text)
		}
		if len(result.structured) == 0 {
			t.Errorf("%s: no structuredContent — a successful tool call must answer a machine-readable "+
				"object, not only text", tool)
		}
		return result
	}

	// ---- datasources (7) ------------------------------------------------------------------------
	ok("list_datasources", nil)
	liveness := ok("get_datasource_liveness", map[string]any{"datasource": "every-tool-ds"}).resultObject(t)
	var attached bool
	if err := json.Unmarshal(liveness["attached"], &attached); err != nil || !attached {
		t.Errorf("get_datasource_liveness attached = %s, want true (the fixture registered it)", liveness["attached"])
	}
	// 🔒 McpServerDbTest case 7's "STRUCTURED liveness", which is a claim about what is ABSENT: the
	// result carries the datasource and `attached`, and neither `detail` nor `message`. Those two are the
	// ERROR shape, so a liveness answer carrying one means the tool degraded into a diagnostic string
	// that a caller parsing the structured object would silently read as "not attached".
	if _, present := liveness["detail"]; present {
		t.Errorf("get_datasource_liveness carries `detail`, the ERROR shape's key: %v", liveness)
	}
	if _, present := liveness["message"]; present {
		t.Errorf("get_datasource_liveness carries `message`, the ERROR shape's key: %v", liveness)
	}
	// And it names the datasource it is ABOUT, by value: the Kotlin pins the string, because a liveness
	// answer echoing a different (or empty) datasource would let a console attribute one datasource's
	// attachment state to another.
	var livenessName string
	if raw, present := liveness["datasource"]; !present {
		t.Errorf("get_datasource_liveness omits `datasource`; the answer must name what it is about: %v", liveness)
	} else if err := json.Unmarshal(raw, &livenessName); err != nil {
		t.Errorf("decode get_datasource_liveness datasource: %v", err)
	} else if livenessName != "every-tool-ds" {
		t.Errorf("get_datasource_liveness datasource = %q, want every-tool-ds", livenessName)
	}
	ok("browse_catalog", map[string]any{"datasource": "every-tool-ds"})
	detail := ok("get_table_detail", map[string]any{
		"datasource": "every-tool-ds", "schema": "public", "table": "users"}).resultObject(t)
	if _, present := detail["columns"]; !present {
		t.Errorf("get_table_detail returned no columns: %v", detail)
	}
	ok("list_column_tags", map[string]any{"datasource": "every-tool-ds"})

	ok("create_mask_fn", map[string]any{"name": "every-tool-mask", "kind": "FIXED"})
	ok("set_column_classification", map[string]any{
		"datasource": "every-tool-ds", "schema": "public", "table": "users", "column": "rrn",
		"tags": []string{"pii"}, "maskFnName": "every-tool-mask"})
	if n := f.scalar(
		`SELECT count(*) FROM column_classification WHERE column_name='rrn'`); n != 1 {
		t.Errorf("set_column_classification wrote %d rows, want 1", n)
	}
	// 🔒 McpServerDbTest case 7's read-back half: the classification the write just made must be what
	// `list_column_tags` PROJECTS — one entry, naming the column. The DB count above proves the row
	// exists; only the tool's own answer proves the read path reports it, and an MCP client has nothing
	// but that answer.
	classified := ok("list_column_tags", map[string]any{"datasource": "every-tool-ds"})
	var tagEntries []struct {
		Datasource string   `json:"datasource"`
		Schema     string   `json:"schema"`
		Table      string   `json:"table"`
		Column     string   `json:"column"`
		Tags       []string `json:"tags"`
		MaskFnName *string  `json:"maskFnName"`
	}
	if err := json.Unmarshal(classified.structured["result"], &tagEntries); err != nil {
		t.Fatalf("decode list_column_tags result: %v (%s)", err, classified.text)
	}
	if len(tagEntries) != 1 {
		t.Fatalf("list_column_tags returned %d entries, want exactly the one classified column: %s",
			len(tagEntries), classified.text)
	}
	if tagEntries[0].Column != "rrn" {
		t.Errorf("list_column_tags column = %q, want rrn", tagEntries[0].Column)
	}
	if !slices.Contains(tagEntries[0].Tags, "pii") {
		t.Errorf("list_column_tags tags = %v, want them to carry the pii tag just written", tagEntries[0].Tags)
	}
	if tagEntries[0].MaskFnName == nil || *tagEntries[0].MaskFnName != "every-tool-mask" {
		t.Errorf("list_column_tags maskFnName = %v, want every-tool-mask", tagEntries[0].MaskFnName)
	}
	ok("clear_column_classification", map[string]any{
		"datasource": "every-tool-ds", "schema": "public", "table": "users", "column": "rrn"})
	if n := f.scalar(
		`SELECT count(*) FROM column_classification WHERE column_name='rrn'`); n != 0 {
		t.Errorf("clear_column_classification left %d rows, want 0", n)
	}

	// ---- policies (9) ---------------------------------------------------------------------------
	ok("get_policy_schema", nil)
	validated := ok("validate_policy", map[string]any{
		"cedarSrc": `permit(principal, action == Action::"admin.policies", resource);`})
	if strings.Contains(validated.text, `"valid":false`) {
		t.Errorf("validate_policy rejected a valid source: %s", validated.text)
	}
	ok("create_policy", map[string]any{
		"name":     "every-tool-policy",
		"cedarSrc": `permit(principal in Role::"every-tool-role", action == Action::"admin.identity", resource);`})
	ok("get_policy", map[string]any{"name": "every-tool-policy"})
	ok("list_policies", nil)
	ok("update_policy", map[string]any{
		"name":     "every-tool-policy",
		"cedarSrc": `permit(principal in Role::"every-tool-role", action == Action::"admin.policies", resource);`})
	ok("disable_policy", map[string]any{"name": "every-tool-policy"})
	if enabled := f.scalar(
		`SELECT count(*) FROM policy WHERE name='every-tool-policy' AND enabled`); enabled != 0 {
		t.Error("disable_policy left the policy enabled")
	}
	ok("enable_policy", map[string]any{"name": "every-tool-policy"})
	if enabled := f.scalar(
		`SELECT count(*) FROM policy WHERE name='every-tool-policy' AND enabled`); enabled != 1 {
		t.Error("enable_policy did not re-enable the policy")
	}
	ok("delete_policy", map[string]any{"name": "every-tool-policy"})

	// ---- roles and assignments (7) --------------------------------------------------------------
	ok("create_role", map[string]any{"name": "every-tool-role", "description": "made by the tool suite"})
	ok("list_roles", nil)
	ok("update_role", map[string]any{"name": "every-tool-role", "description": "renamed description"})
	ok("create_user", map[string]any{"principal": "every-tool-user@example.com"})
	ok("assign_role", map[string]any{
		"principal": "every-tool-user@example.com", "roleName": "every-tool-role"})
	assignments := ok("list_role_assignments", map[string]any{"roleName": "every-tool-role"})
	if !strings.Contains(assignments.text, "every-tool-user@example.com") {
		t.Errorf("list_role_assignments did not report the assignment: %s", assignments.text)
	}
	ok("unassign_role", map[string]any{
		"principal": "every-tool-user@example.com", "roleName": "every-tool-role"})

	// ---- users and groups (10) ------------------------------------------------------------------
	ok("list_users", nil)
	ok("update_user", map[string]any{
		"principal": "every-tool-user@example.com", "displayName": "Every Tool"})
	ok("create_group", map[string]any{"name": "every-tool-group"})
	ok("list_groups", nil)
	ok("update_group", map[string]any{"name": "every-tool-group", "description": "grouped"})
	ok("add_group_member", map[string]any{
		"groupName": "every-tool-group", "principal": "every-tool-user@example.com"})
	ok("set_group_roles", map[string]any{
		"groupName": "every-tool-group", "roleNames": []string{"every-tool-role"}})
	ok("remove_group_member", map[string]any{
		"groupName": "every-tool-group", "principal": "every-tool-user@example.com"})
	ok("delete_group", map[string]any{"name": "every-tool-group"})
	ok("deprovision_user", map[string]any{"principal": "every-tool-user@example.com"})
	if active := f.scalar(
		`SELECT count(*) FROM app_user WHERE principal='every-tool-user@example.com' AND active`); active != 0 {
		t.Error("deprovision_user left the user active")
	}

	// ---- mask functions (4) and the role teardown ------------------------------------------------
	ok("list_mask_fns", nil)
	ok("update_mask_fn", map[string]any{"name": "every-tool-mask", "kind": "HASH"})
	ok("delete_mask_fn", map[string]any{"name": "every-tool-mask"})
	ok("delete_role", map[string]any{"name": "every-tool-role"})

	// 🔒 THE FLOOR. Adding a tool to the catalog without driving it fails here.
	got := make([]string, 0, len(exercised))
	for name := range exercised {
		got = append(got, name)
	}
	slices.Sort(got)
	want := slices.Clone(ApprovedToolNames)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("tools exercised (%d) do not match the approved catalog (%d).\nmissing: %v\nextra:   %v",
			len(got), len(want), missing(want, got), missing(got, want))
	}
}

func missing(want, got []string) []string {
	out := []string{}
	for _, w := range want {
		if !slices.Contains(got, w) {
			out = append(out, w)
		}
	}
	return out
}

// TestASuccessfulReadWritesNoAuditRowAndEveryWriteDoes is 🔒 INV-A11-14, isolated.
//
// Case 7 asserts it as one number at the end of a long sequence. Here it is the only variable: the
// same principal drives every READ tool that needs no fixture and then one WRITE, and the trail must
// hold exactly one row.
//
// KT: McpServerDbTest.kt#representative tool families dispatch successfully with structured liveness and audit — the audit half, which the Kotlin states as a bare count of 8
func TestASuccessfulReadWritesNoAuditRowAndEveryWriteDoes(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-audit-shape@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite)

	for _, tool := range []string{
		"list_datasources", "list_policies", "get_policy_schema", "list_roles",
		"list_role_assignments", "list_users", "list_groups", "list_mask_fns",
	} {
		_, result := f.call(token, tool, nil)
		if result.isError {
			t.Fatalf("%s failed: %s", tool, result.text)
		}
	}
	if n := f.scalar(`SELECT count(*) FROM audit_event WHERE principal=$1`, principal); n != 0 {
		t.Fatalf("eight successful READs wrote %d audit rows, want 0", n)
	}

	_, created := f.call(token, "create_role", map[string]any{"name": "audit-shape-role"})
	if created.isError {
		t.Fatalf("create_role failed: %s", created.text)
	}
	if n := f.scalar(`SELECT count(*) FROM audit_event WHERE principal=$1`, principal); n != 1 {
		t.Fatalf("one WRITE produced %d audit rows, want 1", n)
	}

	// The row's shape, since this is the only place the real store writes it.
	//
	// ⚠️ The COLUMNS are `action` and `resource` while the DTO fields are `AuthzAction` /
	// `AuthzResource` — audit/store.go:180-181 flags the same mismatch at the insert. Reading by
	// column name here is what makes this an end-to-end assertion rather than a re-reading of the
	// struct the test just built.
	var statement, channel, action, resource, datasource string
	var roles []string
	if err := f.pool.QueryRow(f.ctx,
		`SELECT statement, channel, action, resource, datasource, roles
		   FROM audit_event WHERE principal=$1`, principal,
	).Scan(&statement, &channel, &action, &resource, &datasource, &roles); err != nil {
		t.Fatalf("read the audit row: %v", err)
	}
	if statement != "[MCP create_role]" {
		t.Errorf("statement = %q, want [MCP create_role]", statement)
	}
	if channel != "mcp" {
		t.Errorf("channel = %q, want mcp", channel)
	}
	if action != "admin.policies" {
		t.Errorf("authz_action = %q, want admin.policies", action)
	}
	if resource != `System::"system"` {
		t.Errorf(`authz_resource = %q, want System::"system"`, resource)
	}
	// `safeDatasource` names the real datasource for the two classification tools ONLY; everything
	// else audits against the control plane itself.
	if datasource != "control-plane" {
		t.Errorf("datasource = %q, want control-plane", datasource)
	}
	if !slices.Contains(roles, "system:admin") {
		t.Errorf("roles = %v, want them to include system:admin", roles)
	}
	if !slices.IsSorted(roles) {
		t.Errorf("roles = %v, want them sorted", roles)
	}
}

// TestTheTwoClassificationToolsAuditAgainstTheirRealDatasource is `safeDatasource`'s only observable
// consequence, and it is a security-relevant one: an auditor filtering the trail by datasource must
// see a classification change against the datasource it changed, and must NOT see every unrelated
// admin action attributed to it.
func TestTheTwoClassificationToolsAuditAgainstTheirRealDatasource(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-safe-datasource@example.com"
	f.grantRole(principal, "system:admin")
	f.seedDatasource("scoped-ds")
	token := f.mintToken(principal, ScopeRead, ScopeDatasourcesWrite, ScopeIdentityWrite)

	if _, r := f.call(token, "set_column_classification", map[string]any{
		"datasource": "scoped-ds", "schema": "public", "table": "users", "column": "rrn",
		"tags": []string{"pii"}}); r.isError {
		t.Fatalf("set_column_classification failed: %s", r.text)
	}
	if _, r := f.call(token, "clear_column_classification", map[string]any{
		"datasource": "scoped-ds", "schema": "public", "table": "users", "column": "rrn"}); r.isError {
		t.Fatalf("clear_column_classification failed: %s", r.text)
	}
	if _, r := f.call(token, "create_group", map[string]any{"name": "scoped-group"}); r.isError {
		t.Fatalf("create_group failed: %s", r.text)
	}

	scoped := f.strings(
		`SELECT statement FROM audit_event WHERE principal=$1 AND datasource='scoped-ds' ORDER BY id`, principal)
	if !slices.Equal(scoped, []string{"[MCP set_column_classification]", "[MCP clear_column_classification]"}) {
		t.Errorf("rows scoped to the datasource = %v, want exactly the two classification tools", scoped)
	}
	control := f.strings(
		`SELECT statement FROM audit_event WHERE principal=$1 AND datasource='control-plane' ORDER BY id`, principal)
	if !slices.Equal(control, []string{"[MCP create_group]"}) {
		t.Errorf("rows scoped to the control plane = %v, want exactly [MCP create_group]", control)
	}
}

// TestTheAuditDetailNamesTheSubjectAndNeverTheCedarSource pins `mutationDetail`'s fixed key list
// against the real trail.
//
// 🔒 The list exists so a secret never lands in the audit trail through this path: `create_policy`
// carries a whole Cedar source and `create_user` an email, and neither key is in the list. A future
// tool that added `cedarSrc` to the detail would leak policy text into a table many more people can
// read than can read the policy store.
func TestTheAuditDetailNamesTheSubjectAndNeverTheCedarSource(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-detail@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite, ScopeIdentityWrite)

	src := `permit(principal in Role::"nobody", action == Action::"admin.identity", resource);`
	if _, r := f.call(token, "create_policy", map[string]any{
		"name": "detail-policy", "cedarSrc": src}); r.isError {
		t.Fatalf("create_policy failed: %s", r.text)
	}
	if _, r := f.call(token, "create_user", map[string]any{
		"principal": "detail-user@example.com", "email": "secret@example.com"}); r.isError {
		t.Fatalf("create_user failed: %s", r.text)
	}

	details := f.strings(`SELECT detail FROM audit_event WHERE principal=$1 ORDER BY id`, principal)
	if len(details) != 2 {
		t.Fatalf("audit rows = %d, want 2", len(details))
	}
	if details[0] != "create_policy name=detail-policy" {
		t.Errorf("create_policy detail = %q", details[0])
	}
	if strings.Contains(details[0], "permit(") {
		t.Errorf("🔴 the Cedar source reached the audit detail: %q", details[0])
	}
	if details[1] != "create_user principal=detail-user@example.com" {
		t.Errorf("create_user detail = %q", details[1])
	}
	if strings.Contains(details[1], "secret@example.com") {
		t.Errorf("🔴 the email reached the audit detail: %q", details[1])
	}
}

// TestAnUpdateToolPreservesAnOmittedFieldAndClearsAnExplicitlyNullOne is 🔒 INV-A11-17, end to end.
//
// A plain `map[string]any` port would collapse "absent" and "null" into the same zero value and this
// distinction would vanish silently — the client's only way to CLEAR a field would stop working while
// every other test stayed green.
func TestAnUpdateToolPreservesAnOmittedFieldAndClearsAnExplicitlyNullOne(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-tri-state@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopeIdentityWrite)

	if _, r := f.call(token, "create_user", map[string]any{
		"principal": "tri-state@example.com", "displayName": "Original", "email": "keep@example.com",
	}); r.isError {
		t.Fatalf("create_user failed: %s", r.text)
	}

	// OMITTED `displayName` — preserved. EXPLICIT null `email` — cleared.
	if _, r := f.call(token, "update_user", map[string]any{
		"principal": "tri-state@example.com", "email": nil,
	}); r.isError {
		t.Fatalf("update_user failed: %s", r.text)
	}
	var displayName, email *string
	if err := f.pool.QueryRow(f.ctx,
		`SELECT display_name, email FROM app_user WHERE principal='tri-state@example.com'`,
	).Scan(&displayName, &email); err != nil {
		t.Fatalf("read the user: %v", err)
	}
	if displayName == nil || *displayName != "Original" {
		t.Errorf("display_name = %v, want the omitted field to be PRESERVED", displayName)
	}
	if email != nil {
		t.Errorf("email = %v, want an explicit null to CLEAR it", *email)
	}
}

// TestUpdateMaskFnTreatsAnExplicitNullNewNameAsKeepUnlikeTheOtherUpdateTools is the reproduced
// INCONSISTENCY dispatch.go:677 flags.
//
// Every other update tool uses `if (args.has("x")) … else current.x`, so an explicit null CLEARS.
// `update_mask_fn`'s `newName` uses `args.string("newName") ?: current.name`, so an explicit null
// KEEPS. It is the Kotlin's, it is observable, and the PORT POLICY makes it a REPRODUCE — the test
// exists so a later tidy has to argue with a failing assertion instead of a comment.
func TestUpdateMaskFnTreatsAnExplicitNullNewNameAsKeepUnlikeTheOtherUpdateTools(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-masknull@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite)

	if _, r := f.call(token, "create_mask_fn", map[string]any{
		"name": "null-newname-mask", "kind": "FIXED"}); r.isError {
		t.Fatalf("create_mask_fn failed: %s", r.text)
	}
	if _, r := f.call(token, "update_mask_fn", map[string]any{
		"name": "null-newname-mask", "newName": nil, "kind": "HASH"}); r.isError {
		t.Fatalf("update_mask_fn failed: %s", r.text)
	}
	if n := f.scalar(
		`SELECT count(*) FROM mask_fn WHERE name='null-newname-mask' AND kind='HASH'`); n != 1 {
		t.Errorf("an explicit null newName did not KEEP the current name (rows=%d)", n)
	}
}

// TestAReservedPrefixTagCannotBeSetThroughTheMcpSurface is 🔒 INV-A11-28 reached over the wire.
//
// internal/management's own suite proves the service refuses it. This proves the MCP transport does
// not have a path around the service — the write-side half of A2 INV-A2-7 is only worth anything if
// every transport goes through it.
func TestAReservedPrefixTagCannotBeSetThroughTheMcpSurface(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-reserved-tag@example.com"
	f.grantRole(principal, "system:admin")
	f.seedDatasource("reserved-tag-ds")
	token := f.mintToken(principal, ScopeRead, ScopeDatasourcesWrite)

	_, result := f.call(token, "set_column_classification", map[string]any{
		"datasource": "reserved-tag-ds", "schema": "public", "table": "users", "column": "rrn",
		"tags": []string{"pii", "system:internal"}})
	if !result.isError {
		t.Fatal("a reserved-prefix tag was accepted")
	}
	if got := result.errorCode(t); got != "datasource.reserved_tag" {
		t.Errorf("code = %q, want datasource.reserved_tag", got)
	}
	// The whole list is refused, not just the offending member.
	if n := f.scalar(`SELECT count(*) FROM column_classification`); n != 0 {
		t.Errorf("the refused call wrote %d classification rows", n)
	}
	// 🔒 The failure is a management error, so it audits with its OWN code, not a generic one.
	if got := f.auditOutcomes(principal, "[MCP set_column_classification]"); !slices.Equal(
		got, []string{"datasource.reserved_tag"}) {
		t.Errorf("audit outcomes = %v, want [datasource.reserved_tag]", got)
	}
}

// TestAnInvalidCedarSourceComesBackAsTheValidatorsRawArray is the ONE MCP failure that is not an
// ApiError: `{errors: [...]}`, isError, HTTP 200, no code, no localization.
//
// It is 200 because the request itself was well-formed and authorized — a policy that fails to compile
// is a successful tool call reporting a failure — and the array is raw so the policy editor can render
// the compiler's diagnostics line by line.
func TestAnInvalidCedarSourceComesBackAsTheValidatorsRawArray(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-cedar-validation@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite)

	res, result := f.call(token, "create_policy", map[string]any{
		"name": "broken-policy", "cedarSrc": "this is not cedar"})
	if res.status != 200 {
		t.Errorf("status = %d, want 200 — a validation failure is not an HTTP error", res.status)
	}
	if !result.isError {
		t.Fatal("an invalid Cedar source was accepted")
	}
	if _, hasCode := result.structured["code"]; hasCode {
		t.Errorf("the Cedar-validation body carries a `code`: %v", result.structured)
	}
	var body struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(result.text), &body); err != nil {
		t.Fatalf("decode the validation body: %v (%s)", err, result.text)
	}
	if len(body.Errors) == 0 {
		t.Errorf("errors = %v, want at least one diagnostic", body.Errors)
	}
	if n := f.scalar(`SELECT count(*) FROM policy WHERE name='broken-policy'`); n != 0 {
		t.Errorf("the rejected policy was stored (%d rows)", n)
	}
	// The failure audits as CEDAR_VALIDATION, which is its own outcome string and not the failure's
	// code — there is no code.
	if got := f.auditOutcomes(principal, "[MCP create_policy]"); !slices.Equal(got, []string{"CEDAR_VALIDATION"}) {
		t.Errorf("audit outcomes = %v, want [CEDAR_VALIDATION]", got)
	}
}

// TestAnUnknownMaskFunctionNameIsNotFoundRaisedByTheToolItself pins dispatch.go's one
// reach-past-the-service: `set_column_classification` resolves a mask-function NAME to an id through
// the raw store and raises `common.not_found{resource: "mask function"}` ITSELF.
func TestAnUnknownMaskFunctionNameIsNotFoundRaisedByTheToolItself(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-unknown-mask@example.com"
	f.grantRole(principal, "system:admin")
	f.seedDatasource("unknown-mask-ds")
	token := f.mintToken(principal, ScopeRead, ScopeDatasourcesWrite)

	_, result := f.call(token, "set_column_classification", map[string]any{
		"datasource": "unknown-mask-ds", "schema": "public", "table": "users", "column": "rrn",
		"tags": []string{"pii"}, "maskFnName": "no-such-mask"})
	if !result.isError {
		t.Fatal("an unknown mask-function name was accepted")
	}
	if got := result.errorCode(t); got != "common.not_found" {
		t.Fatalf("code = %q, want common.not_found", got)
	}
	var params map[string]string
	if err := json.Unmarshal(result.structured["params"], &params); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if params["resource"] != "mask function" {
		t.Errorf("params.resource = %q, want \"mask function\"", params["resource"])
	}
	if n := f.scalar(`SELECT count(*) FROM column_classification`); n != 0 {
		t.Errorf("the refused call wrote %d classification rows", n)
	}
}

// TestSetGroupRolesIsADiffAndRefusesAnUnknownRoleWithoutTouchingTheCurrentSet reaches
// INV-A11-32's third guard through the tool surface.
//
// The two halves are one property: the diff is only safe because the resolve happens FIRST. A version
// that removed `current - requested` before resolving would strip a group's roles and then fail.
func TestSetGroupRolesIsADiffAndRefusesAnUnknownRoleWithoutTouchingTheCurrentSet(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-group-roles@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite, ScopeIdentityWrite)

	for _, role := range []string{"gr-a", "gr-b", "gr-c"} {
		if _, r := f.call(token, "create_role", map[string]any{"name": role}); r.isError {
			t.Fatalf("create_role %s failed: %s", role, r.text)
		}
	}
	if _, r := f.call(token, "create_group", map[string]any{"name": "gr-group"}); r.isError {
		t.Fatalf("create_group failed: %s", r.text)
	}
	if _, r := f.call(token, "set_group_roles", map[string]any{
		"groupName": "gr-group", "roleNames": []string{"gr-a", "gr-b"}}); r.isError {
		t.Fatalf("set_group_roles failed: %s", r.text)
	}

	// A diff: gr-a stays, gr-b goes, gr-c arrives.
	_, diffed := f.call(token, "set_group_roles", map[string]any{
		"groupName": "gr-group", "roleNames": []string{"gr-a", "gr-c"}})
	if diffed.isError {
		t.Fatalf("the diffing call failed: %s", diffed.text)
	}
	if got := f.strings(
		`SELECT r.name FROM group_role gr JOIN app_role r ON r.id = gr.role_id
		   JOIN app_group g ON g.id = gr.group_id WHERE g.name='gr-group' ORDER BY r.name`,
	); !slices.Equal(got, []string{"gr-a", "gr-c"}) {
		t.Errorf("group roles = %v, want [gr-a gr-c]", got)
	}

	// An unknown name refuses the WHOLE request.
	_, refused := f.call(token, "set_group_roles", map[string]any{
		"groupName": "gr-group", "roleNames": []string{"gr-a", "typoed-role"}})
	if !refused.isError {
		t.Fatal("an unknown role name was accepted")
	}
	if got := refused.errorCode(t); got != "common.not_found" {
		t.Errorf("code = %q, want common.not_found", got)
	}
	// ⚠️ REPRODUCED ASYMMETRY. `replaceDirectRoles` raises `notFound("role '$it'")` — it NAMES the
	// offender, because "the caller asked for a set and the whole request fails on any one member"
	// (A11 §8). `setGroupRoles`, which is the same shape of operation, raises the bare
	// `notFound("role")` (ManagementServices.kt:694). Two set-replacements, two error qualities. The
	// port reproduces both; this assertion is here so a later "consistency" pass has to argue with it.
	var params map[string]string
	if err := json.Unmarshal(refused.structured["params"], &params); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if params["resource"] != "role" {
		t.Errorf("params.resource = %q, want the BARE \"role\" — setGroupRoles does not name the offender",
			params["resource"])
	}
	if got := f.strings(
		`SELECT r.name FROM group_role gr JOIN app_role r ON r.id = gr.role_id
		   JOIN app_group g ON g.id = gr.group_id WHERE g.name='gr-group' ORDER BY r.name`,
	); !slices.Equal(got, []string{"gr-a", "gr-c"}) {
		t.Errorf("the refused call changed the set to %v; it must be untouched", got)
	}
}

// TestASystemGroupCannotBeMutatedThroughTheMcpSurface is 🔒 INV-A11-32 reached over the wire, for the
// two mechanisms the MCP tools can hit: `rejectSystem` (update/delete/member) and the inline
// FOR UPDATE in `setGroupRoles`.
//
// There is no tool that CREATES a SYSTEM group — that is the point of the guard — so the row is seeded
// directly, exactly as internal/management's own suite does.
func TestASystemGroupCannotBeMutatedThroughTheMcpSurface(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-system-group@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopeIdentityWrite)
	// 🔒 F34 — the guard keys on the `source` COLUMN, never on a `system:` name prefix, so the fixture
	// deliberately uses a name that does not start with `system:`.
	f.exec(`INSERT INTO app_group (name, source) VALUES ('idp-managed', 'SYSTEM')`)
	if _, r := f.call(token, "create_user", map[string]any{"principal": "sg-user@example.com"}); r.isError {
		t.Fatalf("create_user failed: %s", r.text)
	}

	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"update_group", map[string]any{"name": "idp-managed", "description": "hijacked"}},
		{"delete_group", map[string]any{"name": "idp-managed"}},
		{"add_group_member", map[string]any{"groupName": "idp-managed", "principal": "sg-user@example.com"}},
		{"remove_group_member", map[string]any{"groupName": "idp-managed", "principal": "sg-user@example.com"}},
		{"set_group_roles", map[string]any{"groupName": "idp-managed", "roleNames": []string{}}},
	} {
		_, result := f.call(token, c.tool, c.args)
		if !result.isError {
			t.Errorf("%s mutated a SYSTEM group", c.tool)
			continue
		}
		if got := result.errorCode(t); got != "group.system_immutable" {
			t.Errorf("%s: code = %q, want group.system_immutable", c.tool, got)
		}
	}
	if n := f.scalar(`SELECT count(*) FROM app_group WHERE name='idp-managed' AND source='SYSTEM'`); n != 1 {
		t.Errorf("the SYSTEM group is gone or changed (rows=%d)", n)
	}
}

// TestASystemRoleCannotBeUpdatedOrDeletedThroughTheMcpSurface is 🔒 INV-A11-30 (F6, resolved) over the
// wire. `system:admin` is derived — a role is a system role because a SYSTEM group maps to it
// (INV-A9-1) — so this is also a check that the derivation reaches the MCP transport.
func TestASystemRoleCannotBeUpdatedOrDeletedThroughTheMcpSurface(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-system-role@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite)

	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"update_role", map[string]any{"name": "system:admin", "description": "hijacked"}},
		{"delete_role", map[string]any{"name": "system:admin"}},
	} {
		_, result := f.call(token, c.tool, c.args)
		if !result.isError {
			t.Errorf("%s mutated a SYSTEM role", c.tool)
			continue
		}
		if got := result.errorCode(t); got != "role.system_immutable" {
			t.Errorf("%s: code = %q, want role.system_immutable", c.tool, got)
		}
	}
	if n := f.scalar(`SELECT count(*) FROM app_role WHERE name='system:admin'`); n != 1 {
		t.Fatalf("system:admin is gone (rows=%d)", n)
	}
}

// TestADuplicateNameIsAlreadyExistsNotAnInternalError pins `unique`'s SQLSTATE-23505 mapping through
// the MCP transport, which §9 lists as untested. A 23505 that escaped unmapped would surface as
// `mcp.internal_error` and an operator would file a bug instead of picking another name.
func TestADuplicateNameIsAlreadyExistsNotAnInternalError(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-duplicate@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite, ScopeIdentityWrite)

	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"create_role", map[string]any{"name": "dup-role"}},
		{"create_group", map[string]any{"name": "dup-group"}},
		{"create_user", map[string]any{"principal": "dup-user@example.com"}},
		{"create_mask_fn", map[string]any{"name": "dup-mask", "kind": "FIXED"}},
	} {
		if _, r := f.call(token, c.tool, c.args); r.isError {
			t.Fatalf("%s first call failed: %s", c.tool, r.text)
		}
		_, again := f.call(token, c.tool, c.args)
		if !again.isError {
			t.Errorf("%s: a duplicate was accepted", c.tool)
			continue
		}
		if got := again.errorCode(t); got != "common.already_exists" {
			t.Errorf("%s: code = %q, want common.already_exists", c.tool, got)
		}
	}
}

// TestABlankRequiredArgumentIsFieldRequiredNotAnEmptyRow pins the accessors' blank test, which is
// Java's `isBlank` (every Unicode whitespace, not just ASCII) and not Go's `== ""`. A port that used
// `len(s) == 0` would let a single ideographic space through and create a role named " ".
func TestABlankRequiredArgumentIsFieldRequiredNotAnEmptyRow(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-blank@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite)

	for _, blank := range []string{"", "   ", "　", "\t\n"} {
		_, result := f.call(token, "create_role", map[string]any{"name": blank})
		if !result.isError {
			t.Errorf("a name of %q was accepted", blank)
			continue
		}
		if got := result.errorCode(t); got != "common.field_required" {
			t.Errorf("name %q: code = %q, want common.field_required", blank, got)
		}
	}
	if n := f.scalar(`SELECT count(*) FROM app_role WHERE name <> trim(name) OR trim(name) = ''`); n != 0 {
		t.Errorf("%d blank-named roles were created", n)
	}
}
