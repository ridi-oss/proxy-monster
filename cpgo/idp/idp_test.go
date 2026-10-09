package idp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/fakeidp"
)

func TestGroupMappingResolve(t *testing.T) {
	m := ParseGroupMapping(" idp-admins = system:admin ,broken, =x,y=, okta-eng=eng", "okta-")
	got := strings.Join(m.Resolve([]string{"idp-admins", "system:admin", "SYSTEM:developer", "okta-eng", "okta-sales", "  ", "okta-", "sales", "okta-sales"}), ",")
	if got != "system:admin,eng,sales" {
		t.Fatalf("resolved %q", got)
	}
	if got := strings.Join(ParseGroupMapping("", "").Resolve([]string{"system:admin", "eng"}), ","); got != "eng" {
		t.Fatalf("an unmapped system: claim must not become a group: %q", got)
	}
}

func TestProvision(t *testing.T) {
	st := dbtest.Open(t)
	ctx := context.Background()
	exec := func(sql string) {
		t.Helper()
		if _, err := st.Pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	groupsOf := func(principal string) string {
		var s string
		_ = st.Pool.QueryRow(ctx, `SELECT coalesce(string_agg(g.name, ',' ORDER BY g.name), '') FROM app_user u
			JOIN group_member gm ON gm.user_id = u.id JOIN app_group g ON g.id = gm.group_id WHERE u.principal = $1`, principal).Scan(&s)
		return s
	}
	mapping := ParseGroupMapping("idp-admins=system:admin", "")
	email := "alice@example.com"

	if err := Provision(ctx, st.Pool, "alice@example.com", &email, []string{"idp-admins", "eng"}, mapping); err != nil {
		t.Fatal(err)
	}
	if g := groupsOf("alice@example.com"); g != "eng,system:admin" {
		t.Fatalf("first login groups %q", g)
	}
	exec(`INSERT INTO app_group (name, source) VALUES ('manual', 'LOCAL');
		INSERT INTO group_member (group_id, user_id) SELECT g.id, u.id FROM app_group g, app_user u WHERE g.name = 'manual' AND u.principal = 'alice@example.com'`)
	if err := Provision(ctx, st.Pool, "alice@example.com", nil, []string{"eng"}, mapping); err != nil {
		t.Fatal(err)
	}
	var keptEmail, source string
	_ = st.Pool.QueryRow(ctx, `SELECT email, source FROM app_user WHERE principal = 'alice@example.com'`).Scan(&keptEmail, &source)
	if g := groupsOf("alice@example.com"); g != "eng" || keptEmail != email || source != "OIDC" {
		t.Fatalf("a later login must leave exactly the IdP's groups and keep the email: %q %q %q", g, keptEmail, source)
	}

	exec(`INSERT INTO app_user (principal, email, source, external_id, active) VALUES ('scim@example.com', 'old@example.com', 'SCIM', 'ext-1', false)`)
	other := "new@example.com"
	if err := Provision(ctx, st.Pool, "scim@example.com", &other, []string{"eng"}, mapping); err != nil {
		t.Fatal(err)
	}
	var active bool
	_ = st.Pool.QueryRow(ctx, `SELECT email, source, active FROM app_user WHERE principal = 'scim@example.com'`).Scan(&keptEmail, &source, &active)
	if keptEmail != "old@example.com" || source != "SCIM" || active {
		t.Fatalf("a SCIM-owned user must be left alone and stay deactivated: %q %q %v", keptEmail, source, active)
	}
}

func TestValidate(t *testing.T) {
	fake := fakeidp.New(t)
	fake.Issuer = fake.URL + "/"
	p := NewProvider(Config{Issuer: fake.Issuer, ClientID: fake.ClientID, ClientSecret: fake.ClientSecret})
	ctx := context.Background()
	alice := fakeidp.Identity{Subject: "s-alice", Email: "alice@example.com", Groups: []string{"eng"}}

	claims, err := p.Validate(ctx, fake.Sign(jose.RS256, alice, "n1", time.Time{}), "n1")
	if err != nil || claims.Principal() != "alice@example.com" || strings.Join(claims.Groups, ",") != "eng" {
		t.Fatalf("an issuer with a trailing slash: %+v %v", claims, err)
	}
	if noEmail, err := p.Validate(ctx, fake.Sign(jose.RS256, fakeidp.Identity{Subject: "s-x"}, "", time.Time{}), ""); err != nil || noEmail.Principal() != "s-x" || noEmail.Email != nil {
		t.Fatalf("no email claim: %+v %v", noEmail, err)
	}
	for name, token := range map[string]string{
		"PS256":       fake.Sign(jose.PS256, alice, "n1", time.Time{}),
		"wrong nonce": fake.Sign(jose.RS256, alice, "n2", time.Time{}),
		"not yet":     fake.Sign(jose.RS256, alice, "n1", time.Now().Add(30*time.Minute)),
		"shared aud":  fake.Sign(jose.RS256, fakeidp.Identity{Subject: "s-alice", Audience: []string{fake.ClientID, "other"}}, "n1", time.Time{}),
	} {
		if _, err := p.Validate(ctx, token, "n1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := p.Validate(ctx, fake.Sign(jose.RS256, alice, "from-login", time.Time{}), ""); err != nil {
		t.Fatalf("a refreshed id_token's nonce is not checked: %v", err)
	}
}
