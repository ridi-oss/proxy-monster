package routes

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
)

func TestTokenRoutes(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	carol := e.st.WebSession(t, "carol@example.com", "k-carol", "dev-1")
	do := func(method, path, body string, c []*http.Cookie, wantStatus int) string {
		t.Helper()
		status, resp := e.do(t, method, path, body, c)
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
		if err := e.st.Pool.QueryRow(ctx, `SELECT token_hash, kind, roles::text, created_at, expires_at FROM proxy_token WHERE id = $1`, id).
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
	e.authz.allow = map[string]bool{
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
	session := do(http.MethodPost, "/api/wire-tokens", `{}`, carol, http.StatusOK)
	if err := json.Unmarshal([]byte(session), &issued); err != nil || !strings.HasPrefix(issued.Token, "pmt_") || issued.Kind != "SESSION" {
		t.Fatalf("session token %s", session)
	}
	if _, _, _, ttl := stored(issued.ID); ttl != 12*time.Hour {
		t.Fatalf("session default ttl %v", ttl)
	}
	_ = json.Unmarshal([]byte(do(http.MethodPost, "/api/wire-tokens", `{"ttlSeconds":999999}`, carol, http.StatusOK)), &issued)
	if _, _, _, ttl := stored(issued.ID); ttl != 24*time.Hour {
		t.Fatalf("clamped ttl %v", ttl)
	}
	named := do(http.MethodPost, "/api/tokens", `{"name":"laptop"}`, carol, http.StatusCreated)
	if !strings.Contains(named, `"kind":"USER","name":"laptop","expiresAt":"`) {
		t.Fatalf("named %s", named)
	}

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
	if _, err := e.st.Pool.Exec(ctx, `INSERT INTO proxy_token (token_hash, principal, kind, expires_at) VALUES ('h-dave', 'dave@example.com', 'USER', now() + interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	var dave int64
	_ = e.st.Pool.QueryRow(ctx, `SELECT id FROM proxy_token WHERE token_hash = 'h-dave'`).Scan(&dave)
	do(http.MethodDelete, fmt.Sprintf("/api/tokens/%d", dave), "", carol, http.StatusForbidden)
	do(http.MethodDelete, fmt.Sprintf("/api/tokens/%d", userID), "", carol, http.StatusNoContent)
	do(http.MethodDelete, fmt.Sprintf("/api/tokens/%d", userID), "", carol, http.StatusNotFound)

	asked := map[string]bool{}
	for i, key := range e.authz.asked {
		r := e.authz.resources[i]
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

	if _, err := e.st.Pool.Exec(ctx, `INSERT INTO app_user (principal, active) VALUES ('carol@example.com', false)`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ path, want string }{{"/api/tokens", ""}, {"/api/wire-tokens", ""}} {
		if body := do(http.MethodPost, c.path, `{}`, carol, http.StatusForbidden); body != `{"code":"auth.principal_deprovisioned","params":{}}` {
			t.Fatalf("deprovisioned mint %s: %s", c.path, body)
		}
	}

	rows, err := e.st.Pool.Query(ctx, `SELECT kind || '|' || principal || '|' || action || '|' || statement || '|' || channel || '|' || outcome || '|' || datasource
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
	want := []string{
		"auth|carol@example.com|auth.token.mint|Minted USER wire token|wire|SUCCESS|control-plane",
		"auth|carol@example.com|auth.token.mint|Minted SESSION wire token|wire|SUCCESS|control-plane",
		"auth|carol@example.com|auth.token.mint|Minted SESSION wire token|wire|SUCCESS|control-plane",
		"auth|carol@example.com|auth.token.mint|Minted USER wire token|wire|SUCCESS|control-plane",
		"auth|carol@example.com|auth.token.revoke|Revoked USER wire token owned by carol@example.com|wire|SUCCESS|control-plane",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	verifyChain(t, e)
}
