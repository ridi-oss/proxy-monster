package routes

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/idp"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// Liveness is the IdP recheck: every live session whose last check is stale is refreshed through its own
// refresh token. invalid_grant ends that one session; a principal left with no roles loses every web
// session; any other failure changes nothing.
type Liveness struct {
	Pool     *pgxpool.Pool
	Sessions *session.Resolver
	Kotlin   api.Kotlin
	Provider *idp.Provider
	Crypto   *idp.Crypto
}

// Run sweeps once per recheck interval until ctx ends.
func (l Liveness) Run(ctx context.Context) {
	t := time.NewTicker(l.Provider.Config().RecheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.Sweep(ctx)
		}
	}
}

type candidate struct {
	id         int64
	kind       string
	principal  string
	refreshEnc []byte
}

// Sweep rechecks every stale live session once.
func (l Liveness) Sweep(ctx context.Context) {
	stale, err := db.New(l.Pool).StaleSessions(ctx, l.Provider.Config().RecheckInterval.Seconds())
	if err != nil {
		slog.Warn("liveness: listing stale sessions", "err", err)
		return
	}
	for _, row := range stale {
		c := candidate{row.ID, row.Kind, row.Principal, row.RefreshTokenEnc}
		if err := l.recheck(ctx, c); err != nil {
			slog.Warn("liveness: recheck failed", "principal", c.principal, "session", c.id, "err", err)
		}
	}
}

func (l Liveness) recheck(ctx context.Context, c candidate) error {
	if c.refreshEnc == nil || l.Crypto == nil {
		return nil
	}
	refresh, err := l.Crypto.Decrypt(c.refreshEnc)
	if err != nil {
		return err
	}
	outcome, err := l.Provider.Refresh(ctx, refresh)
	if err != nil {
		slog.Warn("liveness: IdP check failed transiently", "principal", c.principal, "session", c.id, "err", err)
		return nil
	}
	if outcome.Inactive {
		return l.rejected(ctx, c)
	}
	if outcome.Rotated != "" {
		if err := db.New(l.Pool).RotateRefreshToken(ctx, db.RotateRefreshTokenParams{RefreshTokenEnc: l.Crypto.Encrypt(outcome.Rotated), ID: c.id}); err != nil {
			return err
		}
	}
	if outcome.IDToken == "" {
		slog.Warn("liveness: IdP check returned no id_token", "principal", c.principal, "session", c.id)
		return nil
	}
	claims, err := l.Provider.Validate(ctx, outcome.IDToken, "")
	if err != nil {
		slog.Warn("liveness: IdP check returned an invalid id_token", "principal", c.principal, "session", c.id, "err", err)
		return nil
	}
	if claims.Principal() != c.principal {
		slog.Warn("liveness: identity mismatch", "principal", c.principal, "session", c.id, "got", claims.Principal())
		return nil
	}
	if err := idp.Provision(ctx, l.Pool, c.principal, claims.Email, claims.Groups, l.Provider.Config().Groups); err != nil {
		return err
	}
	roles, err := authz.New(l.Pool).Roles(ctx, c.principal)
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		if err := l.groupRevoked(ctx, c.principal); err != nil {
			return err
		}
	}
	return db.New(l.Pool).MarkIdpChecked(ctx, c.id)
}

// rejected ends the one session the IdP refused: a web session ends, a daemon session's renewal window closes.
func (l Liveness) rejected(ctx context.Context, c candidate) error {
	var ended string
	err := pgx.BeginFunc(ctx, l.Pool, func(tx pgx.Tx) error {
		switch c.kind {
		case "WEB":
			p, err := l.Sessions.End(ctx, tx, c.id, "IDP_REJECTED")
			if err != nil || p == "" {
				return err
			}
			ended = p
		case "DAEMON":
			n, err := db.New(tx).CloseDaemonRenewal(ctx, c.id)
			if err != nil || n == 0 {
				return err
			}
		default:
			slog.Warn("liveness: ignoring unknown session kind", "kind", c.kind, "session", c.id)
			return nil
		}
		kind := "web"
		if c.kind == "DAEMON" {
			kind = "daemon"
		}
		return audit.AuthDetail(ctx, tx, audit.Actor{Principal: c.principal, Channel: "session"}, "auth.session.expire",
			audit.Entity("Session", strconv.FormatInt(c.id, 10)), "IdP rejected "+kind+" session", "idp_rejected")
	})
	if err == nil && ended != "" {
		err = l.Kotlin.SessionsEnded(ctx, ended)
	}
	return err
}

// groupRevoked ends every live web session of a principal the IdP's groups no longer give any role.
func (l Liveness) groupRevoked(ctx context.Context, principal string) error {
	var n int64
	err := pgx.BeginFunc(ctx, l.Pool, func(tx pgx.Tx) error {
		var err error
		if n, err = db.New(tx).EndGroupRevokedSessions(ctx, principal); err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		if err := l.Sessions.DropEditorResults(ctx, tx, principal); err != nil {
			return err
		}
		return audit.AuthDetail(ctx, tx, audit.Actor{Principal: principal, Channel: "session"}, "auth.session.expire",
			audit.Entity("User", principal), "IdP liveness ended "+strconv.FormatInt(n, 10)+" web session(s)", "group_revoked")
	})
	if err == nil && n > 0 {
		err = l.Kotlin.SessionsEnded(ctx, principal)
	}
	return err
}
