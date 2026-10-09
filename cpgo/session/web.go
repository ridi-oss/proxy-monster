package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// Reasons a web session ends, stored in principal_session.ended_reason.
const (
	EndedSignedOut      = "SIGNED_OUT"
	EndedDisplaced      = "DISPLACED"
	EndedDeviceMismatch = "DEVICE_BIND_MISMATCH"
)

// Ref is a signed pm_session cookie's tracker id and the row it names, live or not.
type Ref struct {
	Key string
	// ID is 0 when the key names no row.
	ID int64
}

// Ref reads the request's signed tracker id and the session row it is linked to, ended rows included.
func (r *Resolver) Ref(ctx context.Context, req *http.Request) (*Ref, error) {
	key, ok := r.trackerID(req)
	if !ok {
		return nil, nil
	}
	ref := &Ref{Key: key}
	id, err := db.New(r.pool).WebSessionIDByKey(ctx, &key)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	ref.ID = id
	return ref, err
}

// EndedReason is the 401 reason for a session that did not resolve: displaced, bind_mismatch, else expired.
func (r *Resolver) EndedReason(ctx context.Context, id int64) (string, error) {
	reason, err := db.New(r.pool).WebSessionEndedReason(ctx, id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	switch {
	case reason != nil && *reason == EndedDisplaced:
		return "displaced", nil
	case reason != nil && *reason == EndedDeviceMismatch:
		return "bind_mismatch", nil
	}
	return "expired", nil
}

// Mint opens a web session for principal, ending the principal's other live web sessions (newest wins).
// It returns the new id and whether another session was ended.
func (r *Resolver) Mint(ctx context.Context, tx pgx.Tx, principal string, refreshEnc []byte, device string, debugIP *string) (int64, bool, error) {
	q := db.New(tx)
	if err := q.LockPrincipal(ctx, principal); err != nil {
		return 0, false, err
	}
	id, err := q.MintWebSession(ctx, db.MintWebSessionParams{Principal: principal, DeviceID: &device, RefreshTokenEnc: refreshEnc,
		AbsoluteSeconds: float64(r.settings.AbsoluteSeconds), IdleSeconds: float64(r.settings.IdleSeconds), DebugRequesterIp: debugIP})
	if err != nil {
		return 0, false, err
	}
	n, err := q.DisplaceWebSessions(ctx, db.DisplaceWebSessionsParams{Principal: principal, ID: id})
	if err != nil {
		return 0, false, err
	}
	displaced := n > 0
	if displaced {
		err = r.DropEditorResults(ctx, tx, principal)
	}
	return id, displaced, err
}

// DropEditorResults deletes the principal's editor tasks when a web session of theirs ends, as Kotlin's
// end hook does; only when results are stored at all.
func (r *Resolver) DropEditorResults(ctx context.Context, tx pgx.Tx, principal string) error {
	if !r.settings.ResultKey {
		return nil
	}
	return db.New(tx).DeleteEditorRequests(ctx, principal)
}

// Link moves the tracker key onto session id, taking it from whichever row held it.
func (r *Resolver) Link(ctx context.Context, tx pgx.Tx, id int64, key string) error {
	q := db.New(tx)
	if err := q.UnlinkSessionKey(ctx, db.UnlinkSessionKeyParams{SessionKey: &key, ID: id}); err != nil {
		return err
	}
	return q.LinkSessionKey(ctx, db.LinkSessionKeyParams{SessionKey: &key, ID: id})
}

// End ends live web session id for reason, returning its principal, or "" when it was not live.
func (r *Resolver) End(ctx context.Context, tx pgx.Tx, id int64, reason string) (string, error) {
	principal, err := db.New(tx).EndWebSession(ctx, db.EndWebSessionParams{EndedReason: &reason, ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return principal, r.DropEditorResults(ctx, tx, principal)
}

// Owner is the principal of web session id, ended or not.
func (r *Resolver) Owner(ctx context.Context, id int64) (string, error) {
	return db.New(r.pool).WebSessionOwner(ctx, id)
}

// EndNow is End in its own transaction.
func (r *Resolver) EndNow(ctx context.Context, id int64, reason string) (string, error) {
	var principal string
	err := pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		var err error
		principal, err = r.End(ctx, tx, id, reason)
		return err
	})
	return principal, err
}

// Touch slides the session's idle deadline, at most once per slide interval, and re-resolves it.
func (r *Resolver) Touch(ctx context.Context, id int64, device string) (*Web, error) {
	if err := db.New(r.pool).TouchWebSession(ctx, db.TouchWebSessionParams{IdleSeconds: float64(r.settings.IdleSeconds), ID: id,
		DeviceID: &device, SlideSeconds: float64(r.settings.SlideSeconds)}); err != nil {
		return nil, err
	}
	w, err := r.byID(ctx, id)
	if err != nil || w == nil || w.device == nil || *w.device != device {
		return nil, err
	}
	return &w.Web, nil
}

// NewKey is a fresh tracker id: 64 hex characters, the shape Ktor generates.
func NewKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// SetSessionCookie writes pm_session for key the way Ktor does, signed and URI-encoded.
func (r *Resolver) SetSessionCookie(w http.ResponseWriter, key string) {
	mac := hmac.New(sha256.New, []byte(r.settings.Secret))
	mac.Write([]byte(key))
	value := url.PathEscape(key + "/" + hex.EncodeToString(mac.Sum(nil)))
	value = strings.ReplaceAll(value, "/", "%2F")
	expires := time.Now().Add(time.Duration(r.settings.AbsoluteSeconds) * time.Second)
	r.setCookie(w, cookieName, value, fmt.Sprintf("Max-Age=%d; Expires=%s", r.settings.AbsoluteSeconds, httpDate(expires)))
}

// ClearSessionCookie expires pm_session.
func (r *Resolver) ClearSessionCookie(w http.ResponseWriter) {
	r.setCookie(w, cookieName, "", "Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
}

// EnsureDevice keeps the request's pm_did when it is a UUID, else mints one, and always re-sends it.
func (r *Resolver) EnsureDevice(w http.ResponseWriter, req *http.Request) string {
	device := ""
	if c, err := req.Cookie(deviceCookieName); err == nil {
		if v, err := url.PathUnescape(c.Value); err == nil {
			if _, err := uuid.Parse(v); err == nil && len(v) == 36 {
				device = v
			}
		}
	}
	if device == "" {
		device = uuid.NewString()
	}
	r.setCookie(w, deviceCookieName, device, "Max-Age=7776000")
	return device
}

// setCookie renders Ktor's Set-Cookie attribute order, including its $x-enc marker.
func (r *Resolver) setCookie(w http.ResponseWriter, name, value, lifetime string) {
	secure := ""
	if r.settings.Secure {
		secure = "; Secure"
	}
	w.Header().Add("Set-Cookie", name+"="+value+"; "+lifetime+"; Path=/"+secure+"; HttpOnly; SameSite=Lax; $x-enc=URI_ENCODING")
}

func httpDate(t time.Time) string { return t.UTC().Format(http.TimeFormat) }
