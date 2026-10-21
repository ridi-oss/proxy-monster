// Package tokens serves the wire-token routes: the daemon's SESSION token and the USER tokens a person
// generates, lists and revokes.
package tokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

func Register(mux *http.ServeMux, pool *pgxpool.Pool, gate api.Gate) {
	tk := tokens{pool: pool, authz: gate.Authz}
	mux.HandleFunc("POST /api/wire-tokens", gate.RequireAPI(api.Serve(tk.mintSession)))
	mux.HandleFunc("GET /api/tokens", gate.RequireAPI(api.Serve(tk.list)))
	mux.HandleFunc("POST /api/tokens", gate.RequireAPI(api.Serve(tk.mintUser)))
	mux.HandleFunc("DELETE /api/tokens/{id}", gate.RequireAPIElse(api.Serve(api.WithID(tk.unauthenticatedRevoke)), api.Serve(api.WithID(tk.revoke))))
}

// Every wire token expires; a requested lifetime is clamped into [TokenMinTTL, TokenMaxTTL].
const (
	TokenMinTTL     = 60
	TokenMaxTTL     = 24 * 3600
	SessionTokenTTL = 12 * 3600
	userTokenTTL    = 3600
)

// wireToken is Kotlin's WireTokenInfo: a token row without its secret.
type wireToken struct {
	ID         int64   `json:"id"`
	Kind       string  `json:"kind"`
	Principal  string  `json:"principal"`
	Name       *string `json:"name,omitempty"`
	CreatedAt  string  `json:"createdAt"`
	ExpiresAt  string  `json:"expiresAt"`
	RevokedAt  *string `json:"revokedAt,omitempty"`
	LastUsedAt *string `json:"lastUsedAt,omitempty"`
}

// IssuedToken is Kotlin's IssuedToken: the secret, shown once.
type IssuedToken struct {
	Token     string  `json:"token"`
	ID        int64   `json:"id"`
	Kind      string  `json:"kind"`
	Name      *string `json:"name,omitempty"`
	ExpiresAt string  `json:"expiresAt"`
}

func toWireToken(r db.WireTokensRow) wireToken {
	return wireToken{ID: r.ID, Kind: r.Kind, Principal: r.Principal, Name: r.Name, CreatedAt: api.JavaInstant(r.CreatedAt),
		ExpiresAt: api.JavaInstant(r.ExpiresAt), RevokedAt: api.OptInstant(r.RevokedAt), LastUsedAt: api.OptInstant(r.LastUsedAt)}
}

type tokens struct {
	pool  *pgxpool.Pool
	authz api.Authorizer
}

// tokenActor is the caller, never the token's owner, on the wire channel.
func tokenActor(ctx context.Context) audit.Actor {
	return audit.Actor{Principal: api.Principal(ctx), ClientAddr: api.RequesterIP(ctx), Channel: "wire"}
}

// authorize is TokenService.authorize: 403 common.forbidden with Cedar's reason on a deny.
func (t tokens) authorize(ctx context.Context, action, owner, kind string) error {
	ok, reason, err := t.authz.Authorize(ctx, api.Principal(ctx), action, bridge.Resource{Type: "Token", Principal: owner, Kind: kind}, api.RequesterIP(ctx))
	if err != nil {
		return err
	}
	if !ok {
		return api.CodeForbidden.Err("detail", reason)
	}
	return nil
}

// decode reads the body; Kotlin answers one that does not decode with 500, not DecodeBody's 400.
func decode(r *http.Request, v any) error {
	if api.DecodeBody(r, v) != nil {
		return errors.New("token body does not decode")
	}
	return nil
}

// mint issues a token of kind for the caller, unless the caller is deprovisioned. The check and the insert
// share the principal's advisory lock with every credential teardown, so neither can slip between the two.
func (t tokens) mint(w http.ResponseWriter, r *http.Request, status int, kind string, name *string, ttl int64) error {
	ctx := r.Context()
	principal := api.Principal(ctx)
	ttl = min(max(ttl, TokenMinTTL), TokenMaxTTL)
	var out IssuedToken
	err := pgx.BeginFunc(ctx, t.pool, func(tx pgx.Tx) error {
		q := db.New(tx)
		if err := q.LockPrincipal(ctx, principal); err != nil {
			return err
		}
		deactivated, err := q.IsDeactivated(ctx, principal)
		if err != nil {
			return err
		}
		if deactivated {
			return api.CodeDeprovisioned.Err()
		}
		prefix := "pmk_"
		if kind == "SESSION" {
			prefix = "pmt_"
		}
		token, hash := NewSecret(prefix)
		minted, err := q.MintToken(ctx, db.MintTokenParams{TokenHash: hash, Kind: kind, Principal: principal, Name: name, Ttl: ttl})
		if err != nil {
			return err
		}
		out = IssuedToken{Token: token, ID: minted.ID, Kind: kind, Name: name, ExpiresAt: api.JavaInstant(minted.ExpiresAt)}
		return audit.Auth(ctx, tx, tokenActor(ctx), "auth.token.mint", audit.Entity("Token", strconv.FormatInt(out.ID, 10)),
			"Minted "+kind+" wire token")
	})
	if err != nil {
		return err
	}
	api.WriteJSON(w, status, out)
	return nil
}

// NewSecret is a fresh token under prefix and the hash proxy_token stores for it.
func NewSecret(prefix string) (token, hash string) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	token = prefix + base64.RawURLEncoding.EncodeToString(secret)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:])
}

// mintSession is the daemon's SESSION token for `pmon login`.
func (t tokens) mintSession(w http.ResponseWriter, r *http.Request) error {
	if err := t.authorize(r.Context(), "token.mint", api.Principal(r.Context()), "SESSION"); err != nil {
		return err
	}
	var in struct {
		TTLSeconds *int64 `json:"ttlSeconds"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	ttl := int64(SessionTokenTTL)
	if in.TTLSeconds != nil {
		ttl = *in.TTLSeconds
	}
	return t.mint(w, r, http.StatusOK, "SESSION", nil, ttl)
}

// mintUser is a generated USER token, the password a client pastes or pmon injects.
func (t tokens) mintUser(w http.ResponseWriter, r *http.Request) error {
	if err := t.authorize(r.Context(), "token.mint", api.Principal(r.Context()), "USER"); err != nil {
		return err
	}
	var in struct {
		Name       *string `json:"name"`
		TTLSeconds *int64  `json:"ttlSeconds"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	ttl := int64(userTokenTTL)
	if in.TTLSeconds != nil {
		ttl = *in.TTLSeconds
	}
	if in.Name != nil && strings.TrimSpace(*in.Name) == "" {
		in.Name = nil
	}
	return t.mint(w, r, http.StatusCreated, "USER", in.Name, ttl)
}

// list is the SESSION and USER tokens of ?principal (the caller by default), under token.list on that owner.
func (t tokens) list(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	owner := api.Principal(ctx)
	if q := r.URL.Query(); q.Has("principal") {
		owner = q.Get("principal")
	}
	if err := t.authorize(ctx, "token.list", owner, ""); err != nil {
		return err
	}
	rows, err := db.New(t.pool).WireTokens(ctx, owner)
	return api.WriteRows(w, rows, err, toWireToken)
}

func (t tokens) get(ctx context.Context, id int64) (wireToken, error) {
	row, err := db.New(t.pool).WireToken(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return wireToken{}, api.NotFound("token")
	}
	if err != nil {
		return wireToken{}, err
	}
	return toWireToken(db.WireTokensRow(row)), nil
}

// unauthenticatedRevoke answers a revoke without a session: 404 for a missing token, before anything else
// is revealed, else 401.
func (t tokens) unauthenticatedRevoke(_ http.ResponseWriter, r *http.Request, id int64) error {
	if _, err := t.get(r.Context(), id); err != nil {
		return err
	}
	return api.CodeUnauthenticated.Err()
}

// revoke is token.revoke on the token's real owner and kind; the actor is the caller.
func (t tokens) revoke(w http.ResponseWriter, r *http.Request, id int64) error {
	ctx := r.Context()
	tok, err := t.get(ctx, id)
	if err != nil {
		return err
	}
	if err := t.authorize(ctx, "token.revoke", tok.Principal, tok.Kind); err != nil {
		return err
	}
	return api.Mutate(t.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, _ audit.Actor) (any, error) {
		n, err := db.New(tx).RevokeWireToken(ctx, db.RevokeWireTokenParams{ID: id, Principal: tok.Principal})
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, api.NotFound("token")
		}
		return nil, audit.Auth(ctx, tx, tokenActor(ctx), "auth.token.revoke", audit.Entity("Token", strconv.FormatInt(id, 10)),
			"Revoked "+tok.Kind+" wire token owned by "+tok.Principal)
	})
}
