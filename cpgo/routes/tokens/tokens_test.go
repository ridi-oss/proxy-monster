package tokens_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestTokenRoutes(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	carol := e.St.WebSession(t, "carol@example.com", "k-carol", "dev-1")
	do := func(method, path, body string, c []*http.Cookie, wantStatus int) string {
		t.Helper()
		status, resp := e.Do(t, method, path, body, c)
		if status != wantStatus {
			t.Fatalf("%s %s: %d %s, want %d", method, path, status, resp, wantStatus)
		}
		return resp
	}
	var issued struct {
		Token     string `json:"token"`
		ID        int64  `json:"id"`
		Kind      string `json:"kind"`
		ExpiresAt string `json:"expiresAt"`
	}
	stored := func(id int64) (hash, kind, roles string, ttl time.Duration) {
		t.Helper()
		var created, expires time.Time
		if err := e.St.Pool.QueryRow(ctx, `SELECT token_hash, kind, roles::text, created_at, expires_at FROM proxy_token WHERE id = $1`, id).
			Scan(&hash, &kind, &roles, &created, &expires); err != nil {
			t.Fatal(err)
		}
		return hash, kind, roles, expires.Sub(created).Round(time.Second)
	}
	hashOf := func(token string) string { sum := sha256.Sum256([]byte(token)); return hex.EncodeToString(sum[:]) }

	for _, c := range []struct{ method, path string }{{http.MethodGet, "/api/tokens"}, {http.MethodPost, "/api/tokens"}, {http.MethodPost, "/api/wire-tokens"}} {
		do(c.method, c.path, "{}", nil, http.StatusUnauthorized)
	}
	if body := do(http.MethodPost, "/api/tokens", `{}`, carol, http.StatusForbidden); body != `{"code":"common.forbidden","params":{"detail":"no permit for token.mint"}}` {
		t.Fatalf("mint without a permit: %s", body)
	}
	e.Authz.Allow = map[string]bool{
		"carol@example.com token.mint Token:carol@example.com":   true,
		"carol@example.com token.list Token:carol@example.com":   true,
		"carol@example.com token.revoke Token:carol@example.com": true,
	}

	user := do(http.MethodPost, "/api/tokens", `{"name":" ","ttlSeconds":5}`, carol, http.StatusCreated)
	if err := json.Unmarshal([]byte(user), &issued); err != nil || !strings.HasPrefix(issued.Token, "pmk_") || issued.Kind != "USER" || strings.Contains(user, `"name"`) {
		t.Fatalf("user token %s", user)
	}
	if hash, kind, roles, ttl := stored(issued.ID); hash != hashOf(issued.Token) || kind != "USER" || roles != "[]" || ttl != time.Minute {
		t.Fatalf("stored %s %s %s %v", hash, kind, roles, ttl)
	}
	userID := issued.ID
	minted, secrets := []int64{issued.ID}, []string{issued.Token}
	session := do(http.MethodPost, "/api/wire-tokens", `{}`, carol, http.StatusOK)
	if err := json.Unmarshal([]byte(session), &issued); err != nil || !strings.HasPrefix(issued.Token, "pmt_") || issued.Kind != "SESSION" {
		t.Fatalf("session token %s", session)
	}
	if _, _, _, ttl := stored(issued.ID); ttl != 12*time.Hour {
		t.Fatalf("session default ttl %v", ttl)
	}
	minted, secrets = append(minted, issued.ID), append(secrets, issued.Token)
	_ = json.Unmarshal([]byte(do(http.MethodPost, "/api/wire-tokens", `{"ttlSeconds":999999}`, carol, http.StatusOK)), &issued)
	if _, _, _, ttl := stored(issued.ID); ttl != 24*time.Hour {
		t.Fatalf("clamped ttl %v", ttl)
	}
	minted, secrets = append(minted, issued.ID), append(secrets, issued.Token)
	named := do(http.MethodPost, "/api/tokens", `{"name":"laptop"}`, carol, http.StatusCreated)
	if !strings.Contains(named, `"kind":"USER","name":"laptop","expiresAt":"`) {
		t.Fatalf("named %s", named)
	}
	_ = json.Unmarshal([]byte(named), &issued)
	minted, secrets = append(minted, issued.ID), append(secrets, issued.Token)

	listed := do(http.MethodGet, "/api/tokens", "", carol, http.StatusOK)
	if strings.Count(listed, `"id":`) != 4 || strings.Contains(listed, `"token"`) || !strings.HasPrefix(listed, `[{"id":`) {
		t.Fatalf("listed %s", listed)
	}
	do(http.MethodGet, "/api/tokens?principal=dave@example.com", "", carol, http.StatusForbidden)

	if body := do(http.MethodDelete, "/api/tokens/x", "", nil, http.StatusBadRequest); body != `{"code":"common.bad_id","params":{}}` {
		t.Fatalf("bad id: %s", body)
	}
	if body := do(http.MethodDelete, "/api/tokens/999999", "", nil, http.StatusNotFound); body != `{"code":"common.not_found","params":{"resource":"token"}}` {
		t.Fatalf("missing unauthenticated: %s", body)
	}
	do(http.MethodDelete, fmt.Sprintf("/api/tokens/%d", userID), "", nil, http.StatusUnauthorized)
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO proxy_token (token_hash, principal, kind, expires_at) VALUES ('h-dave', 'dave@example.com', 'USER', now() + interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	var dave int64
	_ = e.St.Pool.QueryRow(ctx, `SELECT id FROM proxy_token WHERE token_hash = 'h-dave'`).Scan(&dave)
	do(http.MethodDelete, fmt.Sprintf("/api/tokens/%d", dave), "", carol, http.StatusForbidden)
	do(http.MethodDelete, fmt.Sprintf("/api/tokens/%d", userID), "", carol, http.StatusNoContent)
	do(http.MethodDelete, fmt.Sprintf("/api/tokens/%d", userID), "", carol, http.StatusNotFound)
	admin := e.St.WebSession(t, "admin@example.com", "k-admin", "dev-2")
	e.Authz.Allow["admin@example.com token.revoke Token:dave@example.com"] = true
	do(http.MethodDelete, fmt.Sprintf("/api/tokens/%d", dave), "", admin, http.StatusNoContent)
	if n := e.Count(t, `SELECT count(*) FROM proxy_token WHERE id = $1 AND revoked_at IS NOT NULL`, dave); n != 1 {
		t.Fatalf("an admin revoke left the token live")
	}
	do(http.MethodDelete, fmt.Sprintf("/api/tokens/%d", dave), "", admin, http.StatusNotFound)

	asked := map[string]bool{}
	for i, key := range e.Authz.Asked {
		r := e.Authz.Resources[i]
		asked[strings.Fields(key)[1]+" "+r.Principal+"#"+r.Kind] = true
	}
	for _, want := range []string{"token.mint carol@example.com#USER", "token.mint carol@example.com#SESSION",
		"token.list carol@example.com#", "token.list dave@example.com#", "token.revoke carol@example.com#USER", "token.revoke dave@example.com#USER"} {
		if !asked[want] {
			t.Errorf("never asked %s; asked %v", want, asked)
		}
	}
	if len(asked) != 6 {
		t.Errorf("asked %v", asked)
	}

	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO app_user (principal, active) VALUES ('carol@example.com', false)`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ path, want string }{{"/api/tokens", ""}, {"/api/wire-tokens", ""}} {
		if body := do(http.MethodPost, c.path, `{}`, carol, http.StatusForbidden); body != `{"code":"auth.principal_deprovisioned","params":{}}` {
			t.Fatalf("deprovisioned mint %s: %s", c.path, body)
		}
	}

	rows, err := e.St.Pool.Query(ctx, `SELECT kind || '|' || principal || '|' || action || '|' || resource || '|' || statement || '|' || channel || '|' || outcome || '|' || decision || '|' || datasource || '|' || coalesce(client_addr, '')
		FROM audit_event ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		got = append(got, s)
	}
	row := func(principal, action string, id int64, statement string) string {
		return fmt.Sprintf(`auth|%s|%s|Token::"%d"|%s|wire|SUCCESS|ALLOW|control-plane|127.0.0.1`, principal, action, id, statement)
	}
	want := []string{
		row("carol@example.com", "auth.token.mint", minted[0], "Minted USER wire token"),
		row("carol@example.com", "auth.token.mint", minted[1], "Minted SESSION wire token"),
		row("carol@example.com", "auth.token.mint", minted[2], "Minted SESSION wire token"),
		row("carol@example.com", "auth.token.mint", minted[3], "Minted USER wire token"),
		row("carol@example.com", "auth.token.revoke", userID, "Revoked USER wire token owned by carol@example.com"),
		row("admin@example.com", "auth.token.revoke", dave, "Revoked USER wire token owned by dave@example.com"),
	}
	for _, s := range secrets {
		if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE strpos(statement, $1) > 0 OR strpos(coalesce(detail, ''), $1) > 0`, s); n != 0 {
			t.Fatalf("a token secret reached %d audit rows", n)
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	routetest.VerifyChain(t, e)
}

func TestTokenAuditRollback(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	carol := e.St.WebSession(t, "carol@example.com", "k-carol", "dev-1")
	e.Authz.Allow = map[string]bool{
		"carol@example.com token.mint Token:carol@example.com":   true,
		"carol@example.com token.revoke Token:carol@example.com": true,
	}
	head := func() string {
		var s string
		if err := e.St.Pool.QueryRow(ctx, `SELECT last_id || ':' || encode(head_hash, 'hex') FROM audit_chain_head WHERE id = 1`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	reject := func(action string) {
		e.Exec(t, `CREATE OR REPLACE FUNCTION pm_test_reject_auth_audit() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'forced auth audit failure'; END $$ LANGUAGE plpgsql`)
		e.Exec(t, `CREATE TRIGGER pm_test_reject_auth_audit BEFORE INSERT ON audit_event FOR EACH ROW
			WHEN (NEW.kind = 'auth' AND NEW.action = '`+action+`') EXECUTE FUNCTION pm_test_reject_auth_audit()`)
	}
	allow := func() { e.Exec(t, `DROP TRIGGER pm_test_reject_auth_audit ON audit_event`) }
	tokens := func() int {
		return e.Count(t, `SELECT count(*) FROM proxy_token WHERE principal = 'carol@example.com'`)
	}

	reject("auth.token.mint")
	before := head()
	for _, path := range []string{"/api/tokens", "/api/wire-tokens"} {
		if status, body := e.Do(t, http.MethodPost, path, `{}`, carol); status != http.StatusInternalServerError {
			t.Fatalf("%s with a rejected audit insert: %d %s", path, status, body)
		}
	}
	if n, after := tokens(), head(); n != 0 || after != before {
		t.Fatalf("a rejected mint audit left %d tokens, head %s -> %s", n, before, after)
	}
	allow()

	_, body := e.Do(t, http.MethodPost, "/api/tokens", `{}`, carol)
	var issued struct{ ID int64 }
	_ = json.Unmarshal([]byte(body), &issued)
	reject("auth.token.revoke")
	before = head()
	if status, _ := e.Do(t, http.MethodDelete, fmt.Sprintf("/api/tokens/%d", issued.ID), "", carol); status != http.StatusInternalServerError {
		t.Fatalf("revoke with a rejected audit insert: %d", status)
	}
	if n, after := e.Count(t, `SELECT count(*) FROM proxy_token WHERE id = $1 AND revoked_at IS NULL`, issued.ID), head(); n != 1 || after != before {
		t.Fatalf("a rejected revoke audit revoked the token (%d live) or moved the head %s -> %s", n, before, after)
	}
	allow()
	routetest.VerifyChain(t, e)
}
