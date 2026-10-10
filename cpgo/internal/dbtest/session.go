package dbtest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
	"net/http"
	"net/url"
	"testing"
)

// Secret signs the session cookies these helpers mint.
const Secret = "test-session-secret-at-least-32-chars"

// Settings are the session settings tests run with: the default lifetimes, debug login on.
var Settings = session.Settings{
	Secret: Secret, AuthDebug: true, ResultKey: true,
	AbsoluteSeconds: 7200, IdleSeconds: 900, SlideSeconds: 120,
	IdleWarnLeadSeconds: 60, AbsoluteWarnLeadSeconds: 300, HeartbeatSeconds: 90,
}

// WebSession inserts a live WEB session for principal bound to device and returns the request cookies
// that present it, signed the way Ktor signs pm_session.
func (s Store) WebSession(t testing.TB, principal, key, device string) []*http.Cookie {
	t.Helper()
	if _, err := s.Pool.Exec(context.Background(), `
		INSERT INTO principal_session (kind, principal, session_key, device_id, idle_expires_at, absolute_expires_at)
		VALUES ('WEB', $1, $2, $3, now() + interval '15 minutes', now() + interval '2 hours')`,
		principal, key, device); err != nil {
		t.Fatal(err)
	}
	return []*http.Cookie{SessionCookie(key, Secret), {Name: "pm_did", Value: device}}
}

// SessionCookie is a pm_session cookie for tracker id key, signed with secret.
func SessionCookie(key, secret string) *http.Cookie {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(key))
	return &http.Cookie{Name: "pm_session", Value: url.PathEscape(key + "/" + hex.EncodeToString(mac.Sum(nil)))}
}
