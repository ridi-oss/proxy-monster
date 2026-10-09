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
)

const (
	cookieName       = "pm_session"
	deviceCookieName = "pm_did"
)

// ErrDeviceMismatch means the session exists but the request's device cookie does not match it. The
// Kotlin control plane ends such a session and clears the principal's editor state, so the caller hands
// the request to Kotlin rather than deciding it here.
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
	pool   *pgxpool.Pool
	secret []byte
}

func NewResolver(pool *pgxpool.Pool, secret string) *Resolver {
	return &Resolver{pool: pool, secret: []byte(secret)}
}

// Resolve returns the request's live session, nil when there is none, or ErrDeviceMismatch.
func (r *Resolver) Resolve(ctx context.Context, req *http.Request) (*Web, error) {
	key, ok := r.trackerID(req)
	if !ok {
		return nil, nil
	}
	var device *string
	if c, err := req.Cookie(deviceCookieName); err == nil {
		if v, err := url.PathUnescape(c.Value); err == nil {
			device = &v
		}
	}
	var (
		w         Web
		rowDevice *string
	)
	err := r.pool.QueryRow(ctx, `
		SELECT id, principal, created_at, absolute_expires_at, idle_expires_at, device_id,
		       coalesce(debug_requester_ip, ''), clock_timestamp()
		FROM principal_session
		WHERE session_key = $1 AND kind = 'WEB' AND ended_at IS NULL
		  AND absolute_expires_at > clock_timestamp()
		  AND idle_expires_at > clock_timestamp()`, key,
	).Scan(&w.ID, &w.Principal, &w.CreatedAt, &w.AbsoluteExpiresAt, &w.IdleExpiresAt, &rowDevice, &w.DebugRequesterIP, &w.Now)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if rowDevice == nil || device == nil || *rowDevice != *device {
		return nil, ErrDeviceMismatch
	}
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
	mac := hmac.New(sha256.New, r.secret)
	mac.Write([]byte(id))
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig)) {
		return "", false
	}
	return id, true
}
