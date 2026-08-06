package session_test

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The cookie codec — 01-bootstrap.md §"Cookies" and 04-auth-session-tokens.md §1.4, §1.5, §2.3.
//
// No DB, no container. These are the cheapest assertions in the area and they cover the one thing a
// cookie implementation gets silently wrong: the MAC.
// ---------------------------------------------------------------------------------------------

const testSecret = "a-test-session-secret-at-least-32-chars-long"

func TestCookieRoundTrip(t *testing.T) {
	c := session.NewCookieCodec(testSecret, "https://pm.example.com")

	for _, tc := range []struct {
		name    string
		payload any
		into    func() any
		check   func(t *testing.T, got any)
	}{
		{
			name:    "WebSessionRef",
			payload: session.WebSessionRef{SessionID: 4242},
			into:    func() any { return &session.WebSessionRef{} },
			check: func(t *testing.T, got any) {
				if v := got.(*session.WebSessionRef); v.SessionID != 4242 {
					t.Errorf("sessionId = %d, want 4242", v.SessionID)
				}
			},
		},
		{
			name:    "OAuthStateSession with returnTo",
			payload: session.OAuthStateSession{State: "s-1", ReturnTo: ptr("/auth/device/authorize?user_code=ABCD-EFGH")},
			into:    func() any { return &session.OAuthStateSession{} },
			check: func(t *testing.T, got any) {
				v := got.(*session.OAuthStateSession)
				if v.State != "s-1" || v.ReturnTo == nil || *v.ReturnTo != "/auth/device/authorize?user_code=ABCD-EFGH" {
					t.Errorf("round trip = %+v", v)
				}
			},
		},
		{
			name:    "OAuthNonceSession",
			payload: session.OAuthNonceSession{Nonce: "n-1"},
			into:    func() any { return &session.OAuthNonceSession{} },
			check: func(t *testing.T, got any) {
				if v := got.(*session.OAuthNonceSession); v.Nonce != "n-1" {
					t.Errorf("nonce = %q", v.Nonce)
				}
			},
		},
		{
			name:    "DeviceVerifySession",
			payload: session.DeviceVerifySession{UserCode: "ABCD-EFGH"},
			into:    func() any { return &session.DeviceVerifySession{} },
			check: func(t *testing.T, got any) {
				if v := got.(*session.DeviceVerifySession); v.UserCode != "ABCD-EFGH" {
					t.Errorf("userCode = %q", v.UserCode)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := c.Encode(tc.payload)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			dst := tc.into()
			if err := c.Decode(value, dst); err != nil {
				t.Fatalf("Decode: %v", err)
			}
			tc.check(t, dst)
		})
	}
}

// 🔒 A tampered payload, a tampered MAC, a wrong key and a truncated value all fail authentication —
// and they all fail the SAME way, because distinguishing them tells an attacker which half of a
// forgery attempt was wrong.
func TestCookieRejectsEveryTamper(t *testing.T) {
	c := session.NewCookieCodec(testSecret, "https://pm.example.com")
	value, err := c.Encode(session.WebSessionRef{SessionID: 1})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		t.Fatalf("encoded value %q is not v1.<payload>.<mac>", value)
	}

	// A forged payload claiming a different session row, re-encoded but NOT re-MACed.
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"sessionId":999}`))
	cases := map[string]string{
		"a forged payload":          parts[0] + "." + forged + "." + parts[2],
		"a tampered MAC":            parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-2] + "AA",
		"a dropped MAC":             parts[0] + "." + parts[1],
		"an unknown scheme version": "v2." + parts[1] + "." + parts[2],
		"empty":                     "",
		"no separator at all":       "garbage",
		"a non-base64 MAC":          parts[0] + "." + parts[1] + ".!!!!",
	}
	for name, bad := range cases {
		var dst session.WebSessionRef
		if err := c.Decode(bad, &dst); !errors.Is(err, session.ErrCookieAuthentication) {
			t.Errorf("%s: Decode = %v, want ErrCookieAuthentication (got session %d)", name, err, dst.SessionID)
		}
	}

	// A different signing secret cannot verify a cookie this one produced.
	other := session.NewCookieCodec("a-DIFFERENT-session-secret-32-chars-plus", "https://pm.example.com")
	var dst session.WebSessionRef
	if err := other.Decode(value, &dst); !errors.Is(err, session.ErrCookieAuthentication) {
		t.Errorf("a cookie verified under a different sessionSecret: %v", err)
	}
	// ...and the MAC covers the VERSION MARKER as well as the payload, so neither can be swapped
	// independently. (Asserted above through "an unknown scheme version" — restated here because it
	// is the property, not the case.)
}

// 🔒 INV-A4-2 — a stale cookie holding the OLD `{principal, roles}` UserSession shape must resolve to
// UNAUTHENTICATED, not to a session with those roles.
//
// The cookie is AUTHENTIC (this codec signed it), so the MAC passes; what must fail is the DECODE,
// because `WebSessionRef.sessionId` is non-nullable with no default and kotlinx throws
// MissingFieldException. encoding/json would instead leave SessionID at 0 and hand the caller a
// session for row 0 — WebSessionRoutesDbTest case 8, inverted.
func TestAStaleUserSessionShapedCookieDoesNotResolveToSessionZero(t *testing.T) {
	c := session.NewCookieCodec(testSecret, "https://pm.example.com")
	// Signed by this very codec, so authentication is not what rejects it.
	stale, err := c.Encode(session.UserSession{Principal: principalA, Roles: []string{"admin"}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var ref session.WebSessionRef
	err = c.Decode(stale, &ref)
	if err == nil {
		t.Fatalf("🔒 INV-A4-2 BROKEN: a stale {principal, roles} cookie decoded to WebSessionRef{%d}. "+
			"Go's encoding/json has no required fields, so the port MUST enforce sessionId explicitly "+
			"— otherwise every old cookie resolves to session row 0.", ref.SessionID)
	}
	if !errors.Is(err, session.ErrMissingField) {
		t.Errorf("Decode = %v, want ErrMissingField (the Go form of MissingFieldException)", err)
	}
	// It is NOT an authentication failure — the caller must be able to tell "forged" from "stale",
	// because only the first is worth logging.
	if errors.Is(err, session.ErrCookieAuthentication) {
		t.Error("a stale-but-authentic cookie was reported as an authentication failure")
	}
	if ref.SessionID != 0 {
		t.Errorf("the partially-decoded ref leaked sessionId %d", ref.SessionID)
	}
}

// The five shared attributes, from 01-bootstrap.md: `path=/`, `httpOnly`, `secure` per the issuer
// scheme, `SameSite=Lax`, plus each cookie's own maxAge.
func TestCookieAttributes(t *testing.T) {
	https := session.NewCookieCodec(testSecret, "https://pm.example.com")
	httpOnly := session.NewCookieCodec(testSecret, "http://localhost:8080")

	if !https.Secure() {
		t.Error("an https issuer must produce secure cookies")
	}
	if httpOnly.Secure() {
		t.Error("🔒 an http issuer must NOT produce secure cookies — a secure cookie over plain http " +
			"is never sent, so every dev login would silently fail")
	}

	for _, tc := range []struct {
		spec       session.CookieSpec
		wantMaxAge int
	}{
		{session.SessionSpec(7200), 7200},
		{session.OAuthStateSpec, 300},
		{session.OAuthNonceSpec, 300},
		{session.DeviceVerifySpec, 600},
	} {
		ck := https.NewCookie(tc.spec, "v")
		if ck.Path != "/" {
			t.Errorf("%s: path = %q, want /", tc.spec.Name, ck.Path)
		}
		if !ck.HttpOnly {
			t.Errorf("%s: not httpOnly", tc.spec.Name)
		}
		if !ck.Secure {
			t.Errorf("%s: not secure under an https issuer", tc.spec.Name)
		}
		if ck.SameSite != http.SameSiteLaxMode {
			t.Errorf("🔒 %s: SameSite = %v, want Lax. Strict would withhold the OAuth state and nonce "+
				"on the IdP's top-level cross-site callback navigation and fail every SSO login.",
				tc.spec.Name, ck.SameSite)
		}
		if ck.MaxAge != tc.wantMaxAge {
			t.Errorf("%s: maxAge = %d, want %d", tc.spec.Name, ck.MaxAge, tc.wantMaxAge)
		}
	}

	// Clearing repeats the attributes, because a browser matches a deletion on (name, domain, path).
	w := httptest.NewRecorder()
	https.Clear(w, session.SessionSpec(7200))
	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "Path=/") {
		t.Errorf("Clear wrote %q without Path=/; the browser would not match the cookie to delete", setCookie)
	}
	if !strings.Contains(setCookie, "Max-Age=0") {
		t.Errorf("Clear wrote %q, want an expiring cookie", setCookie)
	}
}

// 🔒 INV-A4-8 — pm_did is a bearer-free correlator: unsigned, httpOnly, 90 days, and STABLE across
// requests once minted.
func TestEnsureDeviceCookie(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	if got := session.DeviceCookieID(r); got != nil {
		t.Fatalf("DeviceCookieID on a bare request = %v, want nil", got)
	}
	id, err := session.EnsureDeviceCookie(w, r, true)
	if err != nil {
		t.Fatalf("EnsureDeviceCookie: %v", err)
	}
	if len(id) != 36 || strings.Count(id, "-") != 4 {
		t.Errorf("device id %q is not a canonical UUID", id)
	}
	if id[14] != '4' {
		t.Errorf("device id %q is not version 4", id)
	}
	set := w.Header().Get("Set-Cookie")
	for _, want := range []string{session.DeviceCookie + "=" + id, "Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age=7776000"} {
		if !strings.Contains(set, want) {
			t.Errorf("Set-Cookie %q is missing %q", set, want)
		}
	}
	// It is NOT signed: the value is the bare UUID. Signing it would convert a bind-mismatch — a
	// session kill, which is the point — into a parse failure, i.e. a silent no-op.
	if strings.Contains(set, session.DeviceCookie+"=v1.") {
		t.Error("🔒 pm_did was signed. Its only consumer is an equality test against the session " +
			"row's device_id; a MAC there weakens INV-A4-19 rather than strengthening it.")
	}

	// A second call on a request that already carries it returns the SAME id and sets nothing new.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(&http.Cookie{Name: session.DeviceCookie, Value: id})
	w2 := httptest.NewRecorder()
	again, err := session.EnsureDeviceCookie(w2, r2, true)
	if err != nil {
		t.Fatalf("EnsureDeviceCookie(existing): %v", err)
	}
	if again != id {
		t.Errorf("EnsureDeviceCookie minted a NEW id (%q → %q); every request would then look like a "+
			"different device and end the session", id, again)
	}
	if w2.Header().Get("Set-Cookie") != "" {
		t.Errorf("EnsureDeviceCookie re-set an existing cookie: %q", w2.Header().Get("Set-Cookie"))
	}
}

// Set/Read compose over a real *http.Request — the shape the middleware uses.
func TestCookieSetAndRead(t *testing.T) {
	c := session.NewCookieCodec(testSecret, "https://pm.example.com")
	w := httptest.NewRecorder()
	if err := c.Set(w, session.SessionSpec(7200), session.WebSessionRef{SessionID: 7}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	written := w.Result().Cookies()
	if len(written) != 1 {
		t.Fatalf("Set wrote %d cookies", len(written))
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(written[0])

	var ref session.WebSessionRef
	if err := c.Read(r, session.SessionSpec(7200), &ref); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if ref.SessionID != 7 {
		t.Errorf("sessionId = %d, want 7", ref.SessionID)
	}
	// A MISSING cookie is http.ErrNoCookie, kept distinct from an authentication failure: "the
	// browser sent nothing" and "the browser sent something forged" are different events.
	bare := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := c.Read(bare, session.SessionSpec(7200), &ref); !errors.Is(err, http.ErrNoCookie) {
		t.Errorf("Read with no cookie = %v, want http.ErrNoCookie", err)
	}
}

// 🔒 INV-A1-4 — the cookie payload goes through types.MarshalWire, so `<`, `>` and `&` are NOT
// HTML-escaped (kotlinx does not escape them) and an absent optional is OMITTED rather than null.
//
// A `returnTo` carrying a query string is exactly the value encoding/json would silently rewrite, and
// a payload whose bytes differ from the Kotlin's is a payload whose MAC no longer matches.
func TestCookiePayloadFollowsTheWireJSONContract(t *testing.T) {
	// Absent optional ⇒ the key is OMITTED, not `"returnTo":null`.
	got, err := types.MarshalWire(session.OAuthStateSession{State: "s"})
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	if want := `{"state":"s"}`; string(got) != want {
		t.Errorf("OAuthStateSession with no returnTo = %s, want %s (explicitNulls=false)", got, want)
	}

	// No HTML escaping.
	got, err = types.MarshalWire(session.OAuthStateSession{State: "a<b>c&d"})
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	if want := `{"state":"a<b>c&d"}`; string(got) != want {
		t.Errorf("the payload was HTML-escaped: %s, want %s. encoding/json rewrites < > & as "+
			`< > & by default; kotlinx does not, and the bytes are what the MAC covers.`,
			got, want)
	}

	// `roles` defaults to emptyList() and encodeDefaults=true emits it, so it is `[]`, never absent
	// and never null — the console's roles.map would throw on null.
	got, err = types.MarshalWire(session.UserSession{Principal: principalA})
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	if want := `{"principal":"` + principalA + `","roles":[]}`; string(got) != want {
		t.Errorf("UserSession = %s, want %s", got, want)
	}
}

// The four wire reasons A1's respondSessionUnauthorized emits (INV-A4-3), including the collapse of
// the three reasons the browser must NOT see.
func TestWireReasonCollapsesSixStoredReasonsIntoFour(t *testing.T) {
	if got := session.WireReason(nil); got != session.WireReasonNone {
		t.Errorf("WireReason(nil) = %q, want none", got)
	}
	for stored, want := range map[string]string{
		session.EndedDisplaced:          session.WireReasonDisplaced,
		session.EndedDeviceBindMismatch: session.WireReasonBindMismatch,
		// 🔒 The collapse. Not surfacing DEACTIVATED avoids telling an unauthenticated caller that a
		// specific account was deprovisioned; the stored reason keeps the full detail for operators.
		session.EndedSignedOut:    session.WireReasonExpired,
		session.EndedDeactivated:  session.WireReasonExpired,
		session.EndedGroupRevoked: session.WireReasonExpired,
		session.EndedIdpRejected:  session.WireReasonExpired,
		// Anything unrecognized also lands on "expired" — the default arm is total.
		"SOMETHING_NEW": session.WireReasonExpired,
	} {
		if got := session.WireReason(&stored); got != want {
			t.Errorf("WireReason(%s) = %q, want %q", stored, got, want)
		}
	}
}
