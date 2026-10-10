package routes

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

// Every wire token expires; a requested lifetime is clamped into [tokenMinTTL, tokenMaxTTL].
const (
	tokenMinTTL     = 60
	tokenMaxTTL     = 24 * 3600
	sessionTokenTTL = 12 * 3600
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

// issuedToken is Kotlin's IssuedToken: the secret, shown once.
type issuedToken struct {
	Token     string  `json:"token"`
	ID        int64   `json:"id"`
	Kind      string  `json:"kind"`
	Name      *string `json:"name,omitempty"`
	ExpiresAt string  `json:"expiresAt"`
}

func toWireToken(r db.WireTokensRow) wireToken {
	return wireToken{ID: r.ID, Kind: r.Kind, Principal: r.Principal, Name: r.Name, CreatedAt: javaInstant(r.CreatedAt),
		ExpiresAt: javaInstant(r.ExpiresAt), RevokedAt: optInstant(r.RevokedAt), LastUsedAt: optInstant(r.LastUsedAt)}
}

type tokens struct {
	pool  *pgxpool.Pool
	authz api.Authorizer
}

// tokenActor is the caller, never the token's owner, on the wire channel.
func tokenActor(ctx context.Context) audit.Actor {
	return audit.Actor{Principal: api.Principal(ctx), ClientAddr: api.RequesterIP(ctx), Channel: "wire"}
}

// authorizeToken is TokenService.authorize: 403 common.forbidden with Cedar's reason on a deny.
func (t tokens) authorizeToken(ctx context.Context, action, owner, kind string) error {
	ok, reason, err := t.authz.Authorize(ctx, api.Principal(ctx), action, bridge.Resource{Type: "Token", Principal: owner, Kind: kind}, api.RequesterIP(ctx))
	if err == nil && !ok {
		err = forbidden("common.forbidden", api.Params{{"detail", reason}})
	}
	return err
}

// mint issues a token of kind for the caller, unless the caller is deprovisioned. The check and the insert
// share the principal's advisory lock with every credential teardown, so neither can slip between the two.
func (t tokens) mint(w http.ResponseWriter, r *http.Request, status int, kind string, name *string, ttl int64) {
	ctx := r.Context()
	principal := api.Principal(ctx)
	ttl = min(max(ttl, tokenMinTTL), tokenMaxTTL)
	var out issuedToken
	err := pgx.BeginFunc(ctx, t.pool, func(tx pgx.Tx) error {
		if err := lockPrincipal(ctx, tx, principal); err != nil {
			return err
		}
		q := db.New(tx)
		deactivated, err := q.IsDeactivated(ctx, principal)
		if err != nil {
			return err
		}
		if deactivated {
			return forbidden("auth.principal_deprovisioned", nil)
		}
		prefix := "pmk_"
		if kind == "SESSION" {
			prefix = "pmt_"
		}
		secret := make([]byte, 32)
		_, _ = rand.Read(secret)
		token := prefix + base64.RawURLEncoding.EncodeToString(secret)
		sum := sha256.Sum256([]byte(token))
		minted, err := q.MintToken(ctx, db.MintTokenParams{TokenHash: hex.EncodeToString(sum[:]), Kind: kind, Principal: principal, Name: name, Ttl: ttl})
		if err != nil {
			return err
		}
		out.ID, out.Token, out.Kind, out.Name, out.ExpiresAt = minted.ID, token, kind, name, javaInstant(minted.ExpiresAt)
		return audit.Auth(ctx, tx, tokenActor(ctx), "auth.token.mint", audit.Entity("Token", strconv.FormatInt(out.ID, 10)),
			"Minted "+kind+" wire token")
	})
	if err != nil {
		writeMutationError(w, err)
		return
	}
	api.WriteJSON(w, status, out)
}

// mintSession is the daemon's SESSION token for `pmon login`.
func (t tokens) mintSession(w http.ResponseWriter, r *http.Request) {
	if err := t.authorizeToken(r.Context(), "token.mint", api.Principal(r.Context()), "SESSION"); err != nil {
		writeMutationError(w, err)
		return
	}
	var in struct {
		TTLSeconds *int64 `json:"ttlSeconds"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeMutationError(w, err)
		return
	}
	ttl := int64(sessionTokenTTL)
	if in.TTLSeconds != nil {
		ttl = *in.TTLSeconds
	}
	t.mint(w, r, http.StatusOK, "SESSION", nil, ttl)
}

// mintUser is a generated USER token, the password a client pastes or pmon injects.
func (t tokens) mintUser(w http.ResponseWriter, r *http.Request) {
	if err := t.authorizeToken(r.Context(), "token.mint", api.Principal(r.Context()), "USER"); err != nil {
		writeMutationError(w, err)
		return
	}
	var in struct {
		Name       *string `json:"name"`
		TTLSeconds *int64  `json:"ttlSeconds"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeMutationError(w, err)
		return
	}
	ttl := int64(userTokenTTL)
	if in.TTLSeconds != nil {
		ttl = *in.TTLSeconds
	}
	if in.Name != nil && strings.TrimSpace(*in.Name) == "" {
		in.Name = nil
	}
	t.mint(w, r, http.StatusCreated, "USER", in.Name, ttl)
}

// list is the SESSION and USER tokens of ?principal (the caller by default), under token.list on that owner.
func (t tokens) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	owner := api.Principal(ctx)
	if q := r.URL.Query(); q.Has("principal") {
		owner = q.Get("principal")
	}
	if err := t.authorizeToken(ctx, "token.list", owner, ""); err != nil {
		writeMutationError(w, err)
		return
	}
	rows, err := db.New(t.pool).WireTokens(ctx, owner)
	writeRows(w, rows, err, toWireToken)
}

func (t tokens) get(ctx context.Context, id int64) (*wireToken, error) {
	row, err := db.New(t.pool).WireToken(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("token")
	}
	tok := toWireToken(db.WireTokensRow(row))
	return &tok, err
}

// unauthenticatedRevoke answers a revoke without a session: 404 for a missing token, before anything else
// is revealed, else 401.
func (t tokens) unauthenticatedRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		api.WriteError(w, http.StatusBadRequest, "common.bad_id", nil)
		return
	}
	if _, err := t.get(r.Context(), id); err != nil {
		writeMutationError(w, err)
		return
	}
	api.WriteError(w, http.StatusUnauthorized, "common.unauthenticated", nil)
}

// revoke is token.revoke on the token's real owner and kind; the actor is the caller.
func (t tokens) revoke(w http.ResponseWriter, r *http.Request, id int64) {
	ctx := r.Context()
	tok, err := t.get(ctx, id)
	if err == nil {
		err = t.authorizeToken(ctx, "token.revoke", tok.Principal, tok.Kind)
	}
	if err != nil {
		writeMutationError(w, err)
		return
	}
	mutate(t.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, _ audit.Actor) (any, error) {
		n, err := db.New(tx).RevokeWireToken(ctx, db.RevokeWireTokenParams{ID: id, Principal: tok.Principal})
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, notFound("token")
		}
		return nil, audit.Auth(ctx, tx, tokenActor(ctx), "auth.token.revoke", audit.Entity("Token", strconv.FormatInt(id, 10)),
			"Revoked "+tok.Kind+" wire token owned by "+tok.Principal)
	})
}
