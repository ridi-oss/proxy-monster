package authz

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
)

const managerPolicy = `permit(principal, action in [Action::"task.approve", Action::"task.read"], resource is Request)
when { resource.requester has manager && resource.requester.manager == principal };`

func declare(t *testing.T, env string) {
	t.Helper()
	attrs, err := ParseUserAttributes(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := DeclareUserAttributes(attrs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = DeclareUserAttributes(nil) })
}

func TestParseUserAttributes(t *testing.T) {
	got, err := ParseUserAttributes("manager:User, department:String,teams:Set<String>,level:Long,contractor:Bool")
	want := []UserAttribute{{"manager", "User"}, {"department", "String"}, {"teams", "Set<String>"}, {"level", "Long"}, {"contractor", "Bool"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed %v %v", got, err)
	}
	if got, err := ParseUserAttributes(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	for _, bad := range []string{"manager", "manager:Email", "1x:String", "a-b:String", "manager:User,manager:String"} {
		if _, err := ParseUserAttributes(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestClaimAttributesKeepOnlyTheDeclaredType(t *testing.T) {
	declare(t, "manager:User,department:String,teams:Set<String>,level:Long,contractor:Bool")
	claims := func(src string) map[string]any {
		dec := json.NewDecoder(strings.NewReader(src))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if got := string(ClaimAttributes(claims(`{"manager":"lead@example.com","department":["not","a","string"],"teams":["backend","infra"],
		"level":3,"contractor":"true","undeclared":"dropped"}`))); got != `{"level":3,"manager":"lead@example.com","teams":["backend","infra"]}` {
		t.Fatalf("stored %s", got)
	}
	for src, want := range map[string]string{
		`{"level":3.0}`:              `{}`,
		`{"level":3.5}`:              `{}`,
		`{"level":3e0}`:              `{}`,
		`{"level":9007199254740993}`: `{"level":9007199254740993}`,
	} {
		if got := string(ClaimAttributes(claims(src))); got != want {
			t.Errorf("%s stored %s, want %s", src, got, want)
		}
	}
}

func TestDeclaredAttributesReachTheSchema(t *testing.T) {
	unguarded := `permit(principal, action == Action::"task.approve", resource) when { principal.department == "data" };`
	if len(Validate(unguarded)) == 0 {
		t.Fatal("an undeclared attribute validated")
	}
	declare(t, "manager:User")
	if errs := Validate(managerPolicy); len(errs) != 0 {
		t.Fatalf("declared manager: %v", errs)
	}
	if !strings.Contains(schemaText, "manager?: User") || bundledSchema == schemaText {
		t.Fatal("schema text does not declare manager")
	}
	declare(t, "manager:String")
	if len(Validate(managerPolicy)) == 0 {
		t.Fatal("a String manager compared to a User validated")
	}
}

func TestAnAttributeNameCedarRejectsFailsAtDeclaration(t *testing.T) {
	attrs, err := ParseUserAttributes("in:String")
	if err != nil {
		t.Fatal(err)
	}
	if err := DeclareUserAttributes(attrs); err == nil {
		_ = DeclareUserAttributes(nil)
		t.Fatal("`in` declared")
	}
	if len(DeclaredUserAttributes()) != 0 {
		t.Fatal("a rejected declaration was kept")
	}
}

func TestUserAttributeDecisions(t *testing.T) {
	declare(t, "manager:User,department:String,teams:Set<String>")
	st := dbtest.Open(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := st.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	login := func(principal string, attrs string) {
		exec(`INSERT INTO app_user (principal, email, attributes) VALUES ($1, $1, $2::jsonb)
			ON CONFLICT (principal) DO UPDATE SET attributes = EXCLUDED.attributes`, principal, attrs)
	}
	exec(`INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ('manager', $1, true, 'USER')`, managerPolicy)
	exec(`INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ('reviewers', $1, true, 'USER')`,
		`permit(principal, action == Action::"task.approve", resource is Request)
		when { principal has department && resource.requester has department && resource.requester has teams &&
		       principal.department == resource.requester.department && resource.requester.teams.contains("db-review") };`)
	login("lead", `{}`)
	login("other", `{}`)
	login("member", `{"manager":"lead"}`)
	login("wrongly-typed", `{"manager":["lead"]}`)
	login("reviewer", `{"department":"data"}`)
	login("in-team", `{"department":"data","teams":["db-review","backend"]}`)
	login("not-in-team", `{"department":"data","teams":["backend"]}`)
	login("other-department", `{"department":"web","teams":["db-review"]}`)
	login("lapsed", `{"manager":"lead"}`)
	exec(`INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ('data-decided', $1, true, 'USER')`,
		`permit(principal == User::"auditor", action == Action::"task.read", resource is Request)
		when { resource has approver && resource.approver has department && resource.approver.department == "data" &&
		       resource has executedBy && resource.executedBy has department && resource.executedBy.department == "data" };`)
	exec(`UPDATE app_user SET active = false WHERE principal = 'lapsed'`)

	l := Local{Engine: New(st.Pool)}
	ds, role := "ds", "unrelated"
	allow := func(principal, action, requester string) bool {
		t.Helper()
		ok, _, err := l.Authorize(ctx, principal, action,
			bridge.Resource{Type: "ApprovalRequest", Principal: requester, DatasourceName: &ds, RoleName: &role}, "")
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for _, tc := range []struct {
		name                         string
		principal, action, requester string
		want                         bool
	}{
		{"the manager approves", "lead", "task.approve", "member", true},
		{"the manager reads", "lead", "task.read", "member", true},
		{"another approver", "other", "task.approve", "member", false},
		{"another reader", "other", "task.read", "member", false},
		{"a claim stored as the wrong type", "lead", "task.approve", "wrongly-typed", false},
		{"same department, in the team", "reviewer", "task.approve", "in-team", true},
		{"same department, not in the team", "reviewer", "task.approve", "not-in-team", false},
		{"another department", "reviewer", "task.approve", "other-department", false},
		{"a deactivated requester carries no attributes", "lead", "task.approve", "lapsed", false},
	} {
		if got := allow(tc.principal, tc.action, tc.requester); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}

	decided := func(approver, executor string) bool {
		t.Helper()
		ok, _, err := l.Authorize(ctx, "auditor", "task.read", bridge.Resource{Type: "ApprovalRequest", Principal: "member",
			DatasourceName: &ds, RoleName: &role, Approver: &approver, ExecutedBy: &executor}, "")
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !decided("reviewer", "in-team") || decided("reviewer", "other-department") || decided("other-department", "reviewer") {
		t.Error("the approver's and executor's attributes do not reach the request")
	}

	login("member", `{}`)
	if allow("lead", "task.approve", "member") {
		t.Error("a login without the claim still let the manager approve")
	}
	p, err := l.Engine.Parents(ctx, "reviewer")
	if err != nil || !slices.Equal(p.Roles, []string{}) || string(p.Attributes) == "" {
		t.Errorf("a user in no group keeps its attributes: %+v %v", p, err)
	}
}
