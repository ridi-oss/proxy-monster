package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The six cookie names — 04-auth-session-tokens.md §1.5 and §2.3, 01-bootstrap.md §"Cookies"
// ---------------------------------------------------------------------------------------------

const (
	// SessionCookie is `SESSION_COOKIE` (Auth.kt:15). Payload [WebSessionRef]; maxAge is
	// `webSessionAbsoluteSeconds`, so it is the ONE cookie whose lifetime comes from config.
	SessionCookie = "pm_session"
	// DeviceCookie is `DEVICE_COOKIE` (Auth.kt:16) — the SIXTH cookie, set by hand OUTSIDE the Ktor
	// Sessions block. Not signed, not a session. See [EnsureDeviceCookie].
	DeviceCookie = "pm_did"
	// OAuthStateCookie is `OAUTH_STATE_COOKIE` (Oidc.kt:22). Payload [OAuthStateSession].
	OAuthStateCookie = "pm_oauth_state"
	// OAuthNonceCookie is `OAUTH_NONCE_COOKIE` (Oidc.kt:39). Payload [OAuthNonceSession].
	// 🔒 The id_token nonce — the defence against authorization-code injection.
	OAuthNonceCookie = "pm_oauth_nonce"
	// DeviceVerifyCookie is `DEVICE_VERIFY_COOKIE` (Oidc.kt:33). Payload [DeviceVerifySession].
	// 🔒 It proves the browser viewed `/device` for a specific user_code, and it is the ONLY thing
	// binding a device login to SSO — the device-phishing defence.
	DeviceVerifyCookie = "pm_device_verify"
)

// DeviceCookieMaxAgeSeconds is `DEVICE_COOKIE_MAX_AGE_SECONDS` (Auth.kt:17) — 90 days.
const DeviceCookieMaxAgeSeconds = 7_776_000

// The four non-session signed cookies' fixed lifetimes (01-bootstrap.md:211-215).
const (
	// OAuthStateMaxAgeSeconds and OAuthNonceMaxAgeSeconds bound one redirect round trip.
	OAuthStateMaxAgeSeconds = 300
	OAuthNonceMaxAgeSeconds = 300
	// DeviceVerifyMaxAgeSeconds matches DEVICE_LOGIN_TTL_SEC (600) so the anti-phishing proof cannot
	// outlive the login it proves.
	DeviceVerifyMaxAgeSeconds = 600
	// MCPOAuthPendingMaxAgeSeconds is `MCP_OAUTH_PENDING_COOKIE`'s.
	//
	//	TODO(A11): the cookie's NAME literal is not recorded in any area doc — 01-bootstrap.md:215
	//	lists the constant, the payload (McpPendingAuthorization) and the maxAge, but no value, and
	//	grep across the whole spec set finds no `pm_mcp*` string. Deliberately NOT invented here: a
	//	guessed cookie name is a silent cutover break that no test would catch. A11 supplies it.
	MCPOAuthPendingMaxAgeSeconds = 600
)

// CookieSpec is one registered cookie: its name and its maxAge. Every other attribute is shared and
// lives on [CookieCodec], because 01-bootstrap.md fixes them for all five: `path=/`, `httpOnly`,
// `secure = mcpIssuer.startsWith("https://")`, `SameSite=Lax`.
type CookieSpec struct {
	Name          string
	MaxAgeSeconds int
}

// The four specs whose names the spec records. [SessionSpec] is a function because its lifetime is
// `config.webSessionAbsoluteSeconds`.
var (
	OAuthStateSpec   = CookieSpec{Name: OAuthStateCookie, MaxAgeSeconds: OAuthStateMaxAgeSeconds}
	OAuthNonceSpec   = CookieSpec{Name: OAuthNonceCookie, MaxAgeSeconds: OAuthNonceMaxAgeSeconds}
	DeviceVerifySpec = CookieSpec{Name: DeviceVerifyCookie, MaxAgeSeconds: DeviceVerifyMaxAgeSeconds}
)

// SessionSpec is the `pm_session` spec at a given absolute window.
func SessionSpec(webSessionAbsoluteSeconds int64) CookieSpec {
	return CookieSpec{Name: SessionCookie, MaxAgeSeconds: int(webSessionAbsoluteSeconds)}
}

// ---------------------------------------------------------------------------------------------
// Cookie payload DTOs — 04-auth-session-tokens.md §1.4
// ---------------------------------------------------------------------------------------------

// WebSessionRef is the `pm_session` payload: `@Serializable data class WebSessionRef(val sessionId:
// Long)` (Auth.kt:34).
//
// 🔒 INV-A4-2 — `sessionId` is NON-NULLABLE with NO DEFAULT, so kotlinx throws
// MissingFieldException on a payload that lacks it, `webSession()`'s `runCatching` swallows the
// throw, and the request resolves UNAUTHENTICATED. That is exactly what must happen to a stale
// cookie still holding the OLD `{principal, roles}` UserSession shape — WebSessionRoutesDbTest case
// 8. encoding/json would instead leave SessionID at its zero value and hand the caller a session for
// row 0, so the required-ness is reproduced explicitly in [WebSessionRef.UnmarshalJSON].
type WebSessionRef struct {
	SessionID int64 `json:"sessionId"`
}

// ErrMissingField is the Go form of kotlinx's MissingFieldException. Callers treat it exactly as the
// Kotlin's `runCatching { … }.getOrNull()` treats the throw: no session, not an error page.
var ErrMissingField = errors.New("missing required field")

// UnmarshalJSON reproduces kotlinx's required-field enforcement for `sessionId`. See [WebSessionRef].
func (r *WebSessionRef) UnmarshalJSON(b []byte) error {
	var raw struct {
		SessionID *int64 `json:"sessionId"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw.SessionID == nil {
		return fmt.Errorf("%w: sessionId (WebSessionRef)", ErrMissingField)
	}
	r.SessionID = *raw.SessionID
	return nil
}

// OAuthStateSession is the `pm_oauth_state` payload (Oidc.kt). `returnTo` is nullable with a null
// default, so INV-A1-4's explicitNulls=false OMITS it when absent — hence *string, never "".
type OAuthStateSession struct {
	State    string  `json:"state"`
	ReturnTo *string `json:"returnTo,omitempty"`
}

// OAuthNonceSession is the `pm_oauth_nonce` payload.
type OAuthNonceSession struct {
	Nonce string `json:"nonce"`
}

// DeviceVerifySession is the `pm_device_verify` payload.
//
// ⚠️ A4-F22 — `POST /auth/device/confirm` stores the NORMALIZED user code here while
// `GET /auth/device/authorize` compares it to the RAW `?user_code=` query parameter with exact `!=`,
// so a lowercase or punctuated URL never authorizes even after a successful confirm. REPRODUCE: the
// normalization belongs at the confirm route, not in this type, and this type must NOT normalize on
// read.
type DeviceVerifySession struct {
	UserCode string `json:"userCode"`
}

// UserSession is `@Serializable data class UserSession(principal, roles, requesterIp)` (Auth.kt:27).
//
// 🔒 INV-A4-2 — IT IS A RESPONSE DTO, NEVER AN AUTHORITY. It used to BE the cookie payload; it no
// longer is. Auth.kt:20-26: "Roles remain a response-compatibility field; authorization resolves
// effective roles server-side." Nothing may reinstate it as a cookie payload — see
// [WebSessionRef]. `requesterIp` is populated only for a debug-login session and reported only while
// the bypass is on, "so the console never shows a simulated address the decision path is in fact
// ignoring".
//
// `roles` defaults to emptyList() and encodeDefaults=true emits it, so it is `[]` on the wire and
// NEVER absent — INV-A1-4. The slice is therefore normalized in [UserSession.MarshalJSON].
type UserSession struct {
	Principal   string   `json:"principal"`
	Roles       []string `json:"roles"`
	RequesterIP *string  `json:"requesterIp,omitempty"`
}

// MarshalJSON emits `roles: []` for a nil slice — encodeDefaults=true over `emptyList()`. Without it
// encoding/json writes `null` and the console's `roles.map` throws.
//
// Encodes through types.MarshalWire, NOT json.Marshal: kotlinx does not HTML-escape, and a principal
// carrying '<' '&' '>' would otherwise be sealed into the cookie as `<`. That is not merely
// cosmetic here — the cookie payload is signed, so a Kotlin-issued and a Go-issued cookie for the same
// principal must be BYTE-identical for either side to validate the other's during a phased cutover.
// Found by the encoding/json/v2 differential (conformance/wire_jsonv2_oracle_test.go).
func (u UserSession) MarshalJSON() ([]byte, error) {
	type alias UserSession
	out := alias(u)
	if out.Roles == nil {
		out.Roles = []string{}
	}
	return types.MarshalWire(alias(out))
}

// DebugLogin is `POST /auth/debug`'s request body (Auth.kt:50). Inbound only.
//
// 🔒 `principal` is NON-NULLABLE WITH NO DEFAULT, so kotlinx throws MissingFieldException on a body
// that omits it — and unlike [WebSessionRef]'s throw, which `webSession()`'s runCatching swallows
// into "unauthenticated", THIS one has no catch anywhere: `call.receive<DebugLogin>()` (App.kt:691)
// lets it reach StatusPages, which answers 500 `common.fallback`. `roles` and `requesterIp` DO carry
// defaults and are genuinely optional.
//
// encoding/json would instead leave Principal at "" and hand the route a login for the empty
// principal — which `replaceDirectRoles`' `required("principal", …)` would then answer as 400
// common.field_required. Same request, two different codes, and the 400 is the one that looks
// deliberate. The required-ness is therefore reproduced explicitly, exactly as WebSessionRef's is.
type DebugLogin struct {
	Principal   string   `json:"principal"`
	Roles       []string `json:"roles"`
	RequesterIP *string  `json:"requesterIp,omitempty"`
}

// UnmarshalJSON reproduces kotlinx's required-field enforcement for `principal`. See [DebugLogin].
//
// A PRESENT-BUT-BLANK principal is deliberately NOT rejected here: kotlinx only checks presence, and
// the blank case is `required("principal", …)`'s 400 further in. Collapsing the two would turn that
// 400 into a 500.
func (d *DebugLogin) UnmarshalJSON(b []byte) error {
	var raw struct {
		Principal   *string  `json:"principal"`
		Roles       []string `json:"roles"`
		RequesterIP *string  `json:"requesterIp"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw.Principal == nil {
		return fmt.Errorf("%w: principal (DebugLogin)", ErrMissingField)
	}
	d.Principal = *raw.Principal
	d.Roles = raw.Roles
	d.RequesterIP = raw.RequesterIP
	return nil
}

// ---------------------------------------------------------------------------------------------
// The codec
// ---------------------------------------------------------------------------------------------

// cookieSchemeVersion prefixes every signed value so a future scheme change is detectable rather
// than a decode failure of unknown cause. Ktor's own encoding has no such marker; adding one is part
// of the DEFER below.
const cookieSchemeVersion = "v1"

// ErrCookieAuthentication is returned when a cookie's MAC does not verify, when it is malformed, or
// when its scheme version is unknown. All three collapse into one error on purpose: distinguishing
// them tells an attacker which half of a forgery attempt was wrong.
var ErrCookieAuthentication = errors.New("session: cookie failed authentication")

// CookieCodec encodes and decodes the five signed cookies.
//
// # DEFER — Ktor byte-compatibility is NOT attempted
//
// 01-bootstrap.md:222-226 leaves this open: "HMAC-authenticated, tamper-evident cookie encoding,
// byte-compatible with Ktor's SessionTransportTransformerMessageAuthentication IF existing browser
// sessions must survive cutover — otherwise a fresh scheme is fine and every user re-logs in.
// Decide explicitly." 00-INDEX.md:38 lists cookie compatibility under DEFER.
//
// 🔴 THE DECISION RECORDED HERE: this is a CLEAN scheme, not a Ktor-compatible one.
// EXISTING BROWSER SESSIONS WILL NOT SURVIVE CUTOVER — every console user is signed out once, at the
// moment the Go control plane starts serving, and re-authenticates through SSO. Nothing else breaks:
// `pm_did` is unsigned and unchanged (so device bindings survive), `pm_session` is only a pointer to
// a server-side row, and the OAuth state/nonce/device-verify cookies live 5-10 minutes, so at most
// one in-flight login per user is interrupted.
//
// The alternative — reimplementing Ktor's transform — was rejected because its exact wire form
// (field separators, the `/` delimiter, the base64 alphabet, whether the MAC covers the name) cannot
// be verified on this machine: there is no JVM and no Ktor jar here, so a "compatible" implementation
// would be an unverified guess that fails silently for every user rather than visibly for all of them
// at once. If cutover requirements change, this decision is one type's worth of work to revisit.
//
// # The scheme
//
//	value := "v1." + base64url_nopad(payload_json) + "." + base64url_nopad(HMAC_SHA256(key, "v1." + b64_payload))
//
// The MAC covers the version marker AND the encoded payload, so neither can be swapped
// independently. Verification is [hmac.Equal] — a CONSTANT-TIME compare. A byte-by-byte `==` here
// leaks the correct MAC through timing one byte at a time, which is a forgery oracle, not a
// micro-optimization.
type CookieCodec struct {
	key []byte
	// secure is `config.mcpIssuer.startsWith("https://")` — the SAME derivation all five signed
	// cookies and the unsigned pm_did use (INV-A4-8).
	secure bool
}

// NewCookieCodec builds the codec. sessionSecret is `config.sessionSecret` (PM_SESSION_SECRET, whose
// >=32-char / not-the-dev-default rule internal/config already enforces); issuer is
// `config.mcpIssuer`.
func NewCookieCodec(sessionSecret, issuer string) *CookieCodec {
	return &CookieCodec{
		// `sessionSecret.toByteArray()` — the raw UTF-8 bytes, not a derived key. Kotlin hands the
		// same bytes to Ktor's transform.
		key:    []byte(sessionSecret),
		secure: strings.HasPrefix(issuer, "https://"),
	}
}

// Secure reports the `secure` attribute every cookie this codec writes carries.
func (c *CookieCodec) Secure() bool { return c.secure }

// Encode serialises payload and authenticates it.
//
// The payload goes through types.MarshalWire, not json.Marshal: INV-A1-4 requires kotlinx's
// encodeDefaults=true / explicitNulls=false shape AND its non-escaping of `<`, `>` and `&`. A
// `returnTo` carrying a query string is exactly the value encoding/json would silently rewrite, and a
// cookie whose bytes differ from the Kotlin's is a cookie the MAC no longer matches.
func (c *CookieCodec) Encode(payload any) (string, error) {
	raw, err := types.MarshalWire(payload)
	if err != nil {
		return "", err
	}
	return c.EncodeRaw(raw), nil
}

// EncodeRaw authenticates already-encoded bytes, for the ONE cookie whose value is not a JSON
// payload: `pm_session` carries a server-side TRACKER ID, not a serialized [WebSessionRef].
//
// Ktor's `cookie<WebSessionRef>(SESSION_COOKIE, webSessionStorage)` form installs a tracker: the
// browser holds an opaque id, the id is MAC'd, and the ref itself lives in the storage
// (99-library-decisions.md D7: "the MAC'd value is a server-side session id, not the payload; the
// other four carry JSON payloads"). Encoding the id as a JSON string instead would put two bytes of
// quoting inside the MAC for no reason and make the cookie's contents look like a payload it is not.
//
// [Encode] is this function over types.MarshalWire's output, so both share one framing and one MAC —
// a second copy of the framing is how the two halves drift and every cookie stops verifying at once.
func (c *CookieCodec) EncodeRaw(raw []byte) string {
	body := cookieSchemeVersion + "." + base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + base64.RawURLEncoding.EncodeToString(c.mac(body))
}

// Decode verifies the MAC and unmarshals into dst.
//
// Order matters: the MAC is checked BEFORE the payload is parsed, so a forged cookie never reaches
// the JSON decoder. Returns [ErrCookieAuthentication] for anything that fails authentication, and
// the decoder's own error (possibly [ErrMissingField]) for an authentic cookie whose payload no
// longer fits the type — the second case is INV-A4-2's stale-shape path, and callers must map it to
// "no session", never to a 500.
func (c *CookieCodec) Decode(value string, dst any) error {
	raw, err := c.DecodeRaw(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}

// DecodeRaw verifies the MAC and returns the authenticated bytes — the read half of [EncodeRaw], and
// the only way to read `pm_session`'s tracker id.
//
// Order matters: the MAC is checked BEFORE anything is done with the payload, so a forged cookie
// never reaches a parser. Everything that fails authentication — a missing separator, an unknown
// scheme version, bad base64, a wrong MAC — collapses to [ErrCookieAuthentication], because telling
// an attacker WHICH half of a forgery was wrong is a free oracle.
func (c *CookieCodec) DecodeRaw(value string) ([]byte, error) {
	idx := strings.LastIndexByte(value, '.')
	if idx < 0 {
		return nil, ErrCookieAuthentication
	}
	body, macB64 := value[:idx], value[idx+1:]
	if !strings.HasPrefix(body, cookieSchemeVersion+".") {
		return nil, ErrCookieAuthentication
	}
	got, err := base64.RawURLEncoding.DecodeString(macB64)
	if err != nil {
		return nil, ErrCookieAuthentication
	}
	// 🔒 Constant-time. hmac.Equal, never bytes.Equal and never ==.
	if !hmac.Equal(got, c.mac(body)) {
		return nil, ErrCookieAuthentication
	}
	raw, err := base64.RawURLEncoding.DecodeString(body[len(cookieSchemeVersion)+1:])
	if err != nil {
		return nil, ErrCookieAuthentication
	}
	return raw, nil
}

func (c *CookieCodec) mac(body string) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(body))
	return m.Sum(nil)
}

// NewCookie builds the *http.Cookie for spec with an already-encoded value. Every attribute here is
// fixed by 01-bootstrap.md for all five: `path=/`, `httpOnly`, `secure` per the issuer scheme,
// `SameSite=Lax`.
//
// SameSite=Lax rather than Strict is load-bearing, not a default: the OIDC callback and the OAuth
// resume arrive as TOP-LEVEL cross-site GET navigations from the IdP, and Strict would withhold
// `pm_oauth_state` and `pm_oauth_nonce` on exactly those requests — making every SSO login fail its
// CSRF check.
func (c *CookieCodec) NewCookie(spec CookieSpec, value string) *http.Cookie {
	return &http.Cookie{
		Name:     spec.Name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   spec.MaxAgeSeconds,
	}
}

// Set encodes payload and writes the Set-Cookie header.
func (c *CookieCodec) Set(w http.ResponseWriter, spec CookieSpec, payload any) error {
	value, err := c.Encode(payload)
	if err != nil {
		return err
	}
	http.SetCookie(w, c.NewCookie(spec, value))
	return nil
}

// Read reads, authenticates and decodes spec's cookie from r.
//
// A MISSING cookie returns [http.ErrNoCookie] unchanged, kept distinct from
// [ErrCookieAuthentication]: "the browser sent nothing" and "the browser sent something forged" are
// different events, and only the second is worth logging.
func (c *CookieCodec) Read(r *http.Request, spec CookieSpec, dst any) error {
	ck, err := r.Cookie(spec.Name)
	if err != nil {
		return err
	}
	return c.Decode(ck.Value, dst)
}

// Clear expires spec's cookie — `sessions.clear(SESSION_COOKIE)`.
//
// 🔒 INV-A4-7 — clearing the cookie is NOT ending the session. A1's `/auth/logout` calls this AND
// [Store.EndWebBySessionKey]; dropping the second leaves a "signed out" row resolvable from a
// replayed cookie.
//
// The attributes are repeated because a browser matches Set-Cookie deletions on
// (name, domain, path) — a delete written without `path=/` silently leaves the cookie in place.
func (c *CookieCodec) Clear(w http.ResponseWriter, spec CookieSpec) {
	ck := c.NewCookie(spec, "")
	ck.MaxAge = -1
	http.SetCookie(w, ck)
}

// ---------------------------------------------------------------------------------------------
// pm_did — the sixth cookie, unsigned and hand-rolled
// ---------------------------------------------------------------------------------------------

// DeviceCookieID is `ApplicationCall.deviceCookieId()` (Auth.kt): the raw `pm_did` value, or nil.
// It is NOT authenticated and never parsed — see [EnsureDeviceCookie].
func DeviceCookieID(r *http.Request) *string {
	ck, err := r.Cookie(DeviceCookie)
	if err != nil || ck.Value == "" {
		return nil
	}
	v := ck.Value
	return &v
}

// EnsureDeviceCookie is `ApplicationCall.ensureDeviceCookie(secure)` (Auth.kt:76-91): return the
// existing `pm_did`, or mint a fresh random UUID, set it for 90 days, and return that.
//
// 🔒 INV-A4-8 — `pm_did` IS A BEARER-FREE CORRELATOR, AND ITS UNSIGNED-NESS IS FINE BECAUSE IT IS
// NEVER TRUSTED ALONE. It carries a random UUID and is only ever compared for EQUALITY with the
// `device_id` stored on the session row. Forging it cannot authenticate anything; the only thing an
// attacker gains by guessing it is not being detected as a different device — and to use that they
// still need the signed `pm_session`. Conversely a stolen `pm_session` replayed without (or with a
// wrong) `pm_did` ENDS the session (INV-A4-19). Do not "harden" this by signing it: the sole
// consumer is [Store.resolveWebOn]'s equality test, and a MAC there would only convert a
// bind-mismatch (a session kill, which is the point) into a parse failure (a silent no-op).
//
// It is deliberately outside the signed-cookie block, so it carries the same attributes by hand:
// `path=/`, `httpOnly`, `secure` per the argument, `SameSite=Lax`, maxAge 90 days.
func EnsureDeviceCookie(w http.ResponseWriter, r *http.Request, secure bool) (string, error) {
	if existing := DeviceCookieID(r); existing != nil {
		return *existing, nil
	}
	id, err := randomUUIDv4()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     DeviceCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   DeviceCookieMaxAgeSeconds,
	})
	return id, nil
}

// randomUUIDv4 is `UUID.randomUUID().toString()` — 122 random bits in the canonical 8-4-4-4-12 hex
// form, version nibble 4, variant bits 10.
//
// Hand-rolled rather than pulling github.com/google/uuid in as a direct dependency: the module has it
// only as an indirect one today, and promoting a dependency to write sixteen bytes of CSPRNG output
// is not a trade worth making. The FORM is what matters — the value is compared for equality and
// nothing parses it.
func randomUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session: device-id CSPRNG read failed: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, v := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hexDigits[v>>4], hexDigits[v&0x0f])
	}
	return string(out), nil
}
