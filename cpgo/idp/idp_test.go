package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/ridi-oss/proxy-monster/cpgo/authz"
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

	sourceOf := func(group string) string {
		var s string
		_ = st.Pool.QueryRow(ctx, `SELECT source FROM app_group WHERE name = $1`, group).Scan(&s)
		return s
	}
	isAdmin := func(principal string) bool {
		t.Helper()
		roles, err := authz.New(st.Pool).Roles(ctx, principal)
		if err != nil {
			t.Fatal(err)
		}
		return slices.Contains(roles, "system:admin")
	}
	exec(`INSERT INTO app_group (name, source) VALUES ('ops', 'LOCAL')`)

	if err := Provision(ctx, st.Pool, "alice@example.com", &email, []string{"idp-admins", "eng", "ops"}, mapping, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if g := groupsOf("alice@example.com"); g != "eng,ops,system:admin" || sourceOf("eng") != "OIDC" || sourceOf("ops") != "LOCAL" || !isAdmin("alice@example.com") {
		t.Fatalf("first login groups %q, eng %s, ops %s, admin %v", g, sourceOf("eng"), sourceOf("ops"), isAdmin("alice@example.com"))
	}
	exec(`INSERT INTO app_group (name, source) VALUES ('manual', 'LOCAL');
		INSERT INTO group_member (group_id, user_id) SELECT g.id, u.id FROM app_group g, app_user u WHERE g.name = 'manual' AND u.principal = 'alice@example.com'`)
	if err := Provision(ctx, st.Pool, "alice@example.com", nil, []string{"eng"}, mapping, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	var keptEmail, source string
	_ = st.Pool.QueryRow(ctx, `SELECT email, source FROM app_user WHERE principal = 'alice@example.com'`).Scan(&keptEmail, &source)
	if g := groupsOf("alice@example.com"); g != "eng" || keptEmail != email || source != "OIDC" {
		t.Fatalf("a later login must leave exactly the IdP's groups and keep the email: %q %q %q", g, keptEmail, source)
	}
	if isAdmin("alice@example.com") || sourceOf("ops") != "LOCAL" {
		t.Fatalf("dropping the IdP admin group must revoke system:admin: admin %v, ops %s", isAdmin("alice@example.com"), sourceOf("ops"))
	}

	if err := Provision(ctx, st.Pool, "analyst@example.com", nil, []string{"proxy-monster-analysts"}, ParseGroupMapping("", "proxy-monster-"), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if g, src := groupsOf("analyst@example.com"), sourceOf("analysts"); g != "analysts" || src != "OIDC" {
		t.Fatalf("an unmapped group is created with the prefix stripped, not SYSTEM: %q %q", g, src)
	}

	exec(`INSERT INTO app_user (principal, email, source, external_id, active) VALUES ('scim@example.com', 'old@example.com', 'SCIM', 'ext-1', false)`)
	other := "new@example.com"
	if err := Provision(ctx, st.Pool, "scim@example.com", &other, []string{"eng"}, mapping, []byte("{}")); err != nil {
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
	if noGroups, err := p.Validate(ctx, fake.Sign(jose.RS256, fakeidp.Identity{Subject: "s-alice", Email: "alice@example.com"}, "n1", time.Time{}), "n1"); err != nil || len(noGroups.Groups) != 0 {
		t.Fatalf("no groups claim: %+v %v", noGroups, err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{
		"wrong aud":       fake.Sign(jose.RS256, fakeidp.Identity{Subject: "s-alice", Audience: []string{"some-other-client"}}, "n1", time.Time{}),
		"wrong iss":       fake.Sign(jose.RS256, fakeidp.Identity{Subject: "s-alice", Issuer: "http://not-the-real-issuer"}, "n1", time.Time{}),
		"expired":         fake.Sign(jose.RS256, fakeidp.Identity{Subject: "s-alice", Expires: time.Now().Add(-60 * time.Second)}, "n1", time.Time{}),
		"same kid, other": fake.SignWith(otherKey, jose.RS256, alice, "n1", time.Time{}),
		"PS256":           fake.Sign(jose.PS256, alice, "n1", time.Time{}),
		"wrong nonce":     fake.Sign(jose.RS256, alice, "n2", time.Time{}),
		"not yet":         fake.Sign(jose.RS256, alice, "n1", time.Now().Add(30*time.Minute)),
		"shared aud":      fake.Sign(jose.RS256, fakeidp.Identity{Subject: "s-alice", Audience: []string{fake.ClientID, "other"}}, "n1", time.Time{}),
	} {
		if _, err := p.Validate(ctx, token, "n1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := p.Validate(ctx, fake.Sign(jose.RS256, alice, "from-login", time.Time{}), ""); err != nil {
		t.Fatalf("a refreshed id_token's nonce is not checked: %v", err)
	}
}

func TestDiscovery(t *testing.T) {
	fake := fakeidp.New(t)
	ctx := context.Background()
	p := NewProvider(Config{Issuer: fake.URL + "/", ClientID: fake.ClientID})
	for range 3 {
		d, err := p.Discovery(ctx)
		if err != nil || d.Issuer != fake.URL || !p.SupportsS256(d) {
			t.Fatalf("a configured issuer with a trailing slash: %+v %v", d, err)
		}
	}
	if n := fake.Discoveries(); n != 1 {
		t.Fatalf("discovery fetched %d times", n)
	}

	for _, tc := range []struct {
		methods []string
		want    bool
	}{{nil, false}, {[]string{"plain"}, false}, {[]string{"s256"}, true}} {
		fake := fakeidp.New(t)
		fake.PKCEMethods = tc.methods
		d, err := NewProvider(Config{Issuer: fake.URL}).Discovery(ctx)
		if err != nil {
			t.Fatalf("%v: %v", tc.methods, err)
		}
		if got := (&Provider{}).SupportsS256(d); got != tc.want {
			t.Errorf("%v: S256 %v, want %v", tc.methods, got, tc.want)
		}
	}
}
