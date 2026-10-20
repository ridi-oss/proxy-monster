package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

const (
	accessKind  = "MCP_ACCESS"
	refreshKind = "MCP_REFRESH"
	codeTTL     = 300
)

// tokenPair is a granted access and refresh token.
type tokenPair struct {
	access, refresh string
	expiresIn       int64
	scope           string
}

// grantHook runs inside a grant's transaction before it commits, so its audit row commits or rolls back with it.
type grantHook func(ctx context.Context, tx pgx.Tx) error

type store struct{ pool *pgxpool.Pool }

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func validChallenge(c string) bool {
	return len(c) == 43 && strings.IndexFunc(c, func(r rune) bool { return !alnum(r) && r != '-' && r != '_' }) < 0
}

func validVerifier(v string) bool {
	return len(v) >= 43 && len(v) <= 128 &&
		strings.IndexFunc(v, func(r rune) bool { return !alnum(r) && r != '-' && r != '.' && r != '_' && r != '~' }) < 0
}

func alnum(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' }

type codeGrant struct {
	clientID, principal, redirectURI, resource, scope, challenge string
	consentID                                                    int64
}

// createCode stores a single-use authorization code under a live consent matching the grant exactly.
func (s store) createCode(ctx context.Context, g codeGrant) (string, error) {
	code := "pmc_" + api.RandomToken(32)
	q := db.New(s.pool)
	if err := q.DeleteStaleAuthorizationCodes(ctx); err != nil {
		return "", err
	}
	n, err := q.InsertAuthorizationCode(ctx, db.InsertAuthorizationCodeParams{CodeHash: session.TokenHash(code), ClientID: g.clientID,
		Principal: g.principal, RedirectUri: g.redirectURI, Resource: g.resource, Scope: g.scope, CodeChallenge: g.challenge,
		TtlSeconds: codeTTL, ConsentID: g.consentID})
	if err != nil {
		return "", err
	}
	if n != 1 {
		return "", errors.New("authorization code consent is absent, revoked, or mismatched")
	}
	return code, nil
}

// redeemCode trades a code for a token pair, or nil when the code, client, redirect, resource or verifier
// does not match, the code was used or expired, or its consent was revoked.
func (s store) redeemCode(ctx context.Context, code, clientID, redirectURI, resource, verifier string, ttl ttls, onGrant grantHook) (*tokenPair, error) {
	var pair *tokenPair
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := db.New(tx)
		row, err := q.AuthorizationCodeForUpdate(ctx, session.TokenHash(code))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !row.Usable || row.ClientID != clientID || row.RedirectUri != redirectURI || row.Resource != resource ||
			!validVerifier(verifier) || pkceS256(verifier) != row.CodeChallenge {
			return nil
		}
		if n, err := q.UseAuthorizationCode(ctx, row.ID); err != nil || n != 1 {
			return err
		}
		active, err := consentActive(ctx, q, row.ConsentID, row.Principal, row.ClientID, row.Resource, row.Scope)
		if err != nil || !active {
			return err
		}
		p, err := issuePair(ctx, q, row.Principal, row.ClientID, row.Resource, row.Scope, row.ConsentID, "pmf_"+api.RandomToken(24), ttl, nil)
		if err != nil {
			return err
		}
		if err := onGrant(ctx, tx); err != nil {
			return err
		}
		pair = p
		return nil
	})
	return pair, err
}

// rotate trades a refresh token for a new pair in the same family. A refresh token presented again after
// rotation revokes its whole family; onReplay records that, keyed by the presented token's id.
func (s store) rotate(ctx context.Context, refresh, clientID, resource string, ttl ttls, onGrant grantHook,
	onReplay func(ctx context.Context, tx pgx.Tx, tokenID int64) error) (*tokenPair, error) {
	var pair *tokenPair
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := db.New(tx)
		row, err := q.McpTokenForUpdate(ctx, session.TokenHash(refresh))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil || row.Kind != refreshKind || row.ClientID != clientID || row.Resource != resource {
			return err
		}
		if row.Rotated {
			n, err := q.RevokeTokenFamily(ctx, row.RefreshFamily)
			if err != nil || n == 0 {
				return err
			}
			return onReplay(ctx, tx, row.ID)
		}
		if row.Revoked || row.Expired {
			return nil
		}
		active, err := consentActive(ctx, q, row.ConsentID, row.Principal, row.ClientID, row.Resource, row.Scope)
		if err != nil || !active {
			return err
		}
		if n, err := q.RotateMcpRefreshToken(ctx, row.ID); err != nil || n != 1 {
			return err
		}
		p, err := issuePair(ctx, q, row.Principal, row.ClientID, row.Resource, row.Scope, row.ConsentID, *row.RefreshFamily, ttl, &row.ID)
		if err != nil {
			return err
		}
		if err := onGrant(ctx, tx); err != nil {
			return err
		}
		pair = p
		return nil
	})
	return pair, err
}

type ttls struct{ access, refresh int64 }

func issuePair(ctx context.Context, q *db.Queries, principal, clientID, resource, scope string, consentID int64, family string,
	ttl ttls, rotatedFrom *int64) (*tokenPair, error) {
	access, refresh := "pma_"+api.RandomToken(32), "pmr_"+api.RandomToken(32)
	for _, t := range []struct {
		token, kind string
		ttl         int64
		from        *int64
	}{{access, accessKind, ttl.access, nil}, {refresh, refreshKind, ttl.refresh, rotatedFrom}} {
		if err := q.InsertMcpToken(ctx, db.InsertMcpTokenParams{TokenHash: session.TokenHash(t.token), Kind: t.kind, Principal: principal,
			TtlSeconds: clamp(t.ttl), Resource: &resource, ClientID: &clientID, Scope: &scope, RefreshFamily: &family,
			ConsentID: &consentID, RotatedFrom: t.from}); err != nil {
			return nil, err
		}
	}
	return &tokenPair{access: access, refresh: refresh, expiresIn: clamp(ttl.access), scope: scope}, nil
}

func clamp(ttl int64) int64 { return min(max(ttl, 60), 24*3600) }

func consentActive(ctx context.Context, q *db.Queries, id int64, principal, clientID, resource, scope string) (bool, error) {
	active, err := q.ConsentActive(ctx, db.ConsentActiveParams{ID: id, Principal: principal, ClientID: clientID, Resource: resource, Scope: scope})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return active, err
}

// activeConsent is the live consent for exactly this grant, or 0.
func (s store) activeConsent(ctx context.Context, principal, clientID, resource, scope string) (int64, error) {
	id, err := db.New(s.pool).ActiveConsent(ctx, db.ActiveConsentParams{Principal: principal, ClientID: clientID, Resource: resource, Scope: scope})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// grantConsent is the live consent for this grant, created with onCreate in its transaction when there is none.
func (s store) grantConsent(ctx context.Context, principal, clientID, resource, scope string,
	onCreate func(ctx context.Context, tx pgx.Tx, id int64) error) (int64, error) {
	if id, err := s.activeConsent(ctx, principal, clientID, resource, scope); err != nil || id != 0 {
		return id, err
	}
	var id int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		if id, err = db.New(tx).UpsertConsent(ctx, db.UpsertConsentParams{Principal: principal, ClientID: clientID, Resource: resource, Scope: scope}); err != nil {
			return err
		}
		return onCreate(ctx, tx, id)
	})
	return id, err
}

// revokeConsent revokes the principal's consent and its MCP tokens, reporting whether it was live.
func (s store) revokeConsent(ctx context.Context, id int64, principal string, onRevoke grantHook) (bool, error) {
	revoked := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := db.New(tx)
		n, err := q.RevokeConsent(ctx, db.RevokeConsentParams{ID: id, Principal: principal})
		if err != nil || n == 0 {
			return err
		}
		if err := q.RevokeConsentTokens(ctx, &id); err != nil {
			return err
		}
		revoked = true
		return onRevoke(ctx, tx)
	})
	return revoked, err
}

// revoke is RFC 7009: an access token closes only itself, a refresh token its whole family. onRevoke runs
// only when a token actually closed, with the presented token's id.
func (s store) revoke(ctx context.Context, token string, onRevoke func(ctx context.Context, tx pgx.Tx, id int64) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := db.New(tx)
		row, err := q.McpTokenForUpdate(ctx, session.TokenHash(token))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var closed int64
		switch row.Kind {
		case refreshKind:
			closed, err = q.RevokeTokenFamily(ctx, row.RefreshFamily)
		case accessKind:
			closed, err = q.RevokeToken(ctx, row.ID)
		}
		if err != nil || closed == 0 {
			return err
		}
		return onRevoke(ctx, tx, row.ID)
	})
}
