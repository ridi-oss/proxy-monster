package policies_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestPolicySchema(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	admin := e.St.WebSession(t, "admin@example.com", "k-admin", "dev-1")
	plain := e.St.WebSession(t, "plain@example.com", "k-plain", "dev-2")
	e.Authz.Allow = map[string]bool{"admin@example.com admin.policies System:": true}
	base, err := os.ReadFile("../../../control-plane/src/main/resources/authz/schema.cedarschema")
	if err != nil {
		t.Fatal(err)
	}
	decl := func(name string) string {
		return "\naction \"context.tag::" + name + "\" appliesTo { principal: [User, Role], resource: [Datasource], " +
			"context: { channel?: String, requester_ip?: ipaddr, tailscale_caps?: Set<String>, native_operation?: String } };"
	}
	body := func(text string) string {
		var b strings.Builder
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]string{"schema": text})
		return strings.TrimSuffix(b.String(), "\n")
	}
	get := func(want string) {
		t.Helper()
		if status, got := e.Do(t, http.MethodGet, "/api/policies/schema", "", admin); status != http.StatusOK || got != want {
			t.Fatalf("schema: %d %.300s", status, got)
		}
	}

	if status, got := e.Do(t, http.MethodGet, "/api/policies/schema", "", nil); status != http.StatusUnauthorized ||
		got != `{"code":"common.unauthenticated","params":{}}` {
		t.Fatalf("no session: %d %s", status, got)
	}
	if status, got := e.Do(t, http.MethodGet, "/api/policies/schema", "", plain); status != http.StatusForbidden ||
		got != `{"code":"common.forbidden","params":{"detail":"no permit for admin.policies"}}` {
		t.Fatalf("non-admin: %d %s", status, got)
	}
	get(body(string(base) + decl("trusted-network")))

	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO policy (name, cedar_src, enabled, deleted_at) VALUES
		('zz-alias', 'permit (principal, action == Action::"context.tag::\u{61}lpha", resource);', false, NULL),
		('zz-two', 'permit (principal, action in [Action::"context.tag::pii", Action::"context.tag::alpha"], resource);', false, NULL),
		('zz-gone', 'permit (principal, action == Action::"context.tag::zeta", resource);', false, now())`); err != nil {
		t.Fatal(err)
	}
	tagged := body(string(base) + decl(`\u{61}lpha`) + decl("pii") + decl("trusted-network"))
	get(tagged)

	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO policy (name, cedar_src, enabled) VALUES
		('zz-bad', 'permit (principal, action == Action::"context.tag::bad\", resource);', false)`); err != nil {
		t.Fatal(err)
	}
	get(body(string(base)))
	if _, err := e.St.Pool.Exec(ctx, `UPDATE policy SET deleted_at = now() WHERE name = 'zz-bad'`); err != nil {
		t.Fatal(err)
	}
	get(tagged)
}
