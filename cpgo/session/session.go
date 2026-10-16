// Package session resolves the console's web session the way the Kotlin control plane does, so a route
// served by Go accepts exactly the sessions a Kotlin route would.
package session

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

const (
	cookieName       = "pm_session"
	deviceCookieName = "pm_did"
)

// ErrDeviceMismatch means the session exists but the request's device cookie does not match it; Resolve
// returns the session alongside it so the caller can end it.
var ErrDeviceMismatch = errors.New("session: device binding mismatch")

// Web is a live console session.
type Web struct {
	ID                int64
	Principal         string
	CreatedAt         time.Time
	AbsoluteExpiresAt time.Time
	IdleExpiresAt     time.Time
	Now               time.Time
	// DebugRequesterIP is the address chosen at a PM_AUTH_DEBUG login, if any.
	DebugRequesterIP string
}

// Resolver reads sessions without extending them; only the heartbeat route slides idle.
type Resolver struct {
	pool     *pgxpool.Pool
	settings Settings
}

func NewResolver(pool *pgxpool.Pool, settings Settings) *Resolver {
	return &Resolver{pool: pool, settings: settings}
}

func (r *Resolver) Settings() Settings { return r.settings }

// Resolve returns the request's live session, nil when there is none, or the session with
// ErrDeviceMismatch when the request's device cookie is not the one it was opened on.
func (r *Resolver) Resolve(ctx context.Context, req *http.Request) (*Web, error) {
	ref, err := r.Ref(ctx, req)
	if err != nil || ref == nil || ref.ID == 0 {
		return nil, err
	}
	w, err := r.byID(ctx, ref.ID)
	if err != nil || w == nil {
		return nil, err
	}
	device, ok := Device(req)
	if w.device == nil || !ok || *w.device != device {
		return &w.Web, ErrDeviceMismatch
	}
	return &w.Web, nil
}

// Device is the request's pm_did cookie.
func Device(req *http.Request) (string, bool) {
	c, err := req.Cookie(deviceCookieName)
	if err != nil {
		return "", false
	}
	v, err := url.PathUnescape(c.Value)
	return v, err == nil
}

type liveRow struct {
	Web
	device *string
}

// byID is web session id when it is live.
func (r *Resolver) byID(ctx context.Context, id int64) (*liveRow, error) {
	row, err := db.New(r.pool).LiveWebSession(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	w := liveRow{Web{ID: row.ID, Principal: row.Principal, CreatedAt: row.CreatedAt, AbsoluteExpiresAt: row.AbsoluteExpiresAt,
		IdleExpiresAt: *row.IdleExpiresAt, Now: row.DbNow, DebugRequesterIP: row.DebugRequesterIp}, row.DeviceID}
	return &w, nil
}

// trackerID verifies Ktor's signed pm_session cookie, "<tracker id>/<hex HMAC-SHA256 of the id>".
func (r *Resolver) trackerID(req *http.Request) (string, bool) {
	c, err := req.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	value, err := url.PathUnescape(c.Value)
	if err != nil {
		return "", false
	}
	i := strings.LastIndexByte(value, '/')
	if i < 0 {
		return "", false
	}
	id, sig := value[:i], value[i+1:]
	mac := hmac.New(sha256.New, []byte(r.settings.Secret))
	mac.Write([]byte(id))
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig)) {
		return "", false
	}
	return id, true
}

// WirePrincipal resolves a native wire token (SESSION or USER, not retired) the way Kotlin's
// resolveActiveToken does for HTTP discovery, or "" when it is not a live one or its principal is deactivated.
func (r *Resolver) WirePrincipal(ctx context.Context, token string) (string, error) {
	sum := sha256.Sum256([]byte(token))
	principal, err := db.New(r.pool).WirePrincipal(ctx, hex.EncodeToString(sum[:]))
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return principal, err
}
