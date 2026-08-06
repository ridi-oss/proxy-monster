package oidc

import "github.com/ridi-oss/proxy-monster/gocp/internal/session"

// The three signed cookies the authorization-code flow and the device flow ride on.
//
// 🔴 THEY ARE NOT DEFINED HERE. All six control-plane cookies — names, payload DTOs, lifetimes and
// the HMAC codec — live in internal/session, which owns `Auth.kt` + the `App.kt` Sessions block (A4 /
// A1). Defining a second copy of `OAuthStateSession` or a second cookie codec in this package would
// be two independently-evolving encodings of the same browser cookie: a login written by one and read
// by the other fails authentication, and the symptom is "SSO stopped working" with no error anywhere.
//
// What lives here is the ALIASES, so this package's own API and its ported suites read the way
// control-plane/Oidc.kt reads — that file is where OAUTH_STATE_COOKIE, OAUTH_NONCE_COOKIE,
// DEVICE_VERIFY_COOKIE and their three payload classes are declared in the Kotlin, including the
// device-verify one that internal/device consumes. A Go type ALIAS is the same type, so there is
// exactly one definition and exactly one wire encoding.
type (
	// OAuthStateSession is the `pm_oauth_state` payload: the CSRF state plus its allowlisted
	// continuation. 🔒 INV-A4-59 — ReturnTo is never an echo; see [ReturnTarget].
	OAuthStateSession = session.OAuthStateSession
	// OAuthNonceSession is the `pm_oauth_nonce` payload.
	//
	// 🔒 Quoted from Oidc.kt:41-46, the nonce is "bound into the authorize request and echoed back
	// inside the id_token; [IdTokenValidator] checks the two match, which is what actually defends
	// against authorization-code injection — `state` alone only proves the response came back to the
	// browser that started the flow."
	OAuthNonceSession = session.OAuthNonceSession
	// DeviceVerifySession is the `pm_device_verify` payload.
	//
	// 🔒 INV-A4-46 — the ONLY thing binding a device login to an SSO session, and the
	// device-phishing defence. internal/device is its only consumer.
	DeviceVerifySession = session.DeviceVerifySession
)

// The three cookie specs (name + maxAge), re-exported for the same reason as the payloads above.
var (
	StateCookieSpec        = session.OAuthStateSpec
	NonceCookieSpec        = session.OAuthNonceSpec
	DeviceVerifyCookieSpec = session.DeviceVerifySpec
)
