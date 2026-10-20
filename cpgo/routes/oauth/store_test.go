package oauth

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
)

const (
	testClientID = "https://client.example/client.json"
	testResource = "http://127.0.0.1:8080/mcp"
	testRedirect = "http://127.0.0.1:43110/callback"
)

var testVerifier = strings.Repeat("v", 43)

func noHook(context.Context, pgx.Tx) error { return nil }

// grant runs the code flow for principal and returns the pair and its consent.
func grant(t *testing.T, s store, principal string) (*tokenPair, int64) {
	t.Helper()
	ctx := context.Background()
	consent, err := s.grantConsent(ctx, principal, testClientID, testResource, "mcp:read", func(context.Context, pgx.Tx, int64) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	code, err := s.createCode(ctx, codeGrant{testClientID, principal, testRedirect, testResource, "mcp:read", pkceS256(testVerifier), consent})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := s.redeemCode(ctx, code, testClientID, testRedirect, testResource, testVerifier, ttls{600, 3600}, noHook)
	if err != nil || pair == nil {
		t.Fatalf("redeem: %v %v", pair, err)
	}
	return pair, consent
}

func live(t *testing.T, st dbtest.Store, token string) bool {
	t.Helper()
	var n int
	_ = st.Pool.QueryRow(context.Background(), `SELECT count(*) FROM proxy_token WHERE token_hash = encode(sha256($1::bytea), 'hex') AND revoked_at IS NULL`, token).Scan(&n)
	return n == 1
}

func TestRevokedConsentBlocksTheCodeAndItsTokens(t *testing.T) {
	st := dbtest.Open(t)
	s := store{st.Pool}
	ctx := context.Background()
	pair, consent := grant(t, s, "alice@example.com")
	code, err := s.createCode(ctx, codeGrant{testClientID, "alice@example.com", testRedirect, testResource, "mcp:read", pkceS256(testVerifier), consent})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.revokeConsent(ctx, consent, "alice@example.com", noHook); !ok || err != nil {
		t.Fatalf("revoke: %v %v", ok, err)
	}
	if live(t, st, pair.access) || live(t, st, pair.refresh) {
		t.Fatal("tokens under a revoked consent are still live")
	}
	if p, err := s.redeemCode(ctx, code, testClientID, testRedirect, testResource, testVerifier, ttls{600, 3600}, noHook); p != nil || err != nil {
		t.Fatalf("a code under a revoked consent redeemed: %v %v", p, err)
	}
	if _, err := s.createCode(ctx, codeGrant{testClientID, "alice@example.com", testRedirect, testResource, "mcp:read", pkceS256(testVerifier), consent}); err == nil {
		t.Fatal("a code was issued under a revoked consent")
	}
	if ok, _ := s.revokeConsent(ctx, consent, "alice@example.com", noHook); ok {
		t.Fatal("a second revoke reported a transition")
	}
}

func TestRevokingARefreshTokenClosesItsFamily(t *testing.T) {
	st := dbtest.Open(t)
	s := store{st.Pool}
	ctx := context.Background()
	first, _ := grant(t, s, "alice@example.com")
	second, err := s.rotate(ctx, first.refresh, testClientID, testResource, ttls{600, 3600}, noHook, nil)
	if err != nil || second == nil {
		t.Fatalf("rotate: %v %v", second, err)
	}
	other, _ := grant(t, s, "bob@example.com")
	var revoked []int64
	record := func(_ context.Context, _ pgx.Tx, id int64) error { revoked = append(revoked, id); return nil }
	if err := s.revoke(ctx, second.access, record); err != nil || len(revoked) != 1 || live(t, st, second.access) || !live(t, st, second.refresh) {
		t.Fatalf("an access revoke must close only itself: %v %v", revoked, err)
	}
	if !live(t, st, first.access) {
		t.Fatal("rotation revoked the access token it replaced")
	}
	if err := s.revoke(ctx, second.refresh, record); err != nil || len(revoked) != 2 || live(t, st, second.refresh) || live(t, st, first.access) {
		t.Fatalf("refresh revoke: %v %v", revoked, err)
	}
	if err := s.revoke(ctx, second.refresh, record); err != nil || len(revoked) != 2 {
		t.Fatalf("a repeated revoke reported a transition: %v %v", revoked, err)
	}
	if err := s.revoke(ctx, "pmr_unknown", record); err != nil || len(revoked) != 2 {
		t.Fatalf("an unknown token reported a transition: %v %v", revoked, err)
	}
	if !live(t, st, other.access) || !live(t, st, other.refresh) {
		t.Fatal("revoking one family closed another")
	}
}

func TestACodeCannotBorrowAnotherConsent(t *testing.T) {
	st := dbtest.Open(t)
	s := store{st.Pool}
	ctx := context.Background()
	_, consent := grant(t, s, "alice@example.com")
	for name, g := range map[string]codeGrant{
		"other principal": {testClientID, "bob@example.com", testRedirect, testResource, "mcp:read", pkceS256(testVerifier), consent},
		"other client":    {"https://other.example/c.json", "alice@example.com", testRedirect, testResource, "mcp:read", pkceS256(testVerifier), consent},
		"wider scope":     {testClientID, "alice@example.com", testRedirect, testResource, "mcp:read mcp:tokens", pkceS256(testVerifier), consent},
		"other resource":  {testClientID, "alice@example.com", testRedirect, "http://other/mcp", "mcp:read", pkceS256(testVerifier), consent},
	} {
		if _, err := s.createCode(ctx, g); err == nil {
			t.Errorf("%s: a code was issued", name)
		}
	}
}

func TestCreatingACodePrunesStaleOnes(t *testing.T) {
	st := dbtest.Open(t)
	s := store{st.Pool}
	ctx := context.Background()
	_, consent := grant(t, s, "alice@example.com")
	if _, err := st.Pool.Exec(ctx, `INSERT INTO oauth_authorization_code
		(code_hash, client_id, principal, redirect_uri, resource, scope, code_challenge, expires_at, consent_id)
		VALUES ('expired', $1, 'alice@example.com', $2, $3, 'mcp:read', $4, now() - interval '1 second', $5)`,
		testClientID, testRedirect, testResource, pkceS256(testVerifier), consent); err != nil {
		t.Fatal(err)
	}
	if _, err := s.createCode(ctx, codeGrant{testClientID, "alice@example.com", testRedirect, testResource, "mcp:read", pkceS256(testVerifier), consent}); err != nil {
		t.Fatal(err)
	}
	var left int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM oauth_authorization_code`).Scan(&left)
	if left != 1 {
		t.Fatalf("%d codes left, want only the new one", left)
	}
}
