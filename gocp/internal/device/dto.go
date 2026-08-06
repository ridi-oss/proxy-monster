package device

// The wire DTOs. DeviceAuth.kt's header calls this the "SHARED CONTRACT REGISTRY — pmon + web consume
// these", so every field name, every default and every optionality below is contract, not style.
//
// 🔒 INV-A1-4 governs the JSON shape: kotlinx runs with `encodeDefaults = true; explicitNulls = false`,
// so a non-null default IS emitted while a null field is ABSENT (not `null`). In Go that is *T +
// omitempty for optionals and NO omitempty for anything else. All five response DTOs here are
// all-required, so the rule shows up as the ABSENCE of omitempty — which is the easy thing to add by
// reflex and the reason internal/conformance carries golden bytes for each of them.
//
// ⚠️ `DevicePollResult.expiresAt` and `.sessionExpiresAt` are Java `Instant.toString()` — VARIABLE
// fractional-second precision (`…:06Z` when the nanos are zero, `…:06.123Z` otherwise). internal/instant
// reproduces exactly that rendering; do not substitute time.RFC3339Nano, which strips trailing zeros
// one digit at a time. 04-auth-session-tokens.md §8 Q1 leaves changing the format explicitly OPEN.

// StartInput is `DeviceStartInput(ttlSeconds: Long? = null)`.
//
// The only optional field in the whole flow, and the route reads it leniently: a missing or garbage
// body is NOT a 400, it is this struct's zero value. See [Routes.Start].
type StartInput struct {
	TTLSeconds *int64 `json:"ttlSeconds,omitempty"`
}

// StartResponse is `DeviceStartResponse`.
//
// 🔒 INV-A4-45 — VerificationURI is the WEB origin, not the control plane's. Quoted from
// DeviceAuth.kt:275-277: "The verification page is a WEB route, so this must be the console's origin —
// same as the control plane in the usual single-edge deployment, or PM_WEB_ORIGIN when the console is
// served elsewhere."
//
// ⚠️ `Interval` is the POLL interval (2 s), unrelated to the 600 s handle lifetime. Two different
// durations, one of which is on the wire.
type StartResponse struct {
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	UserCode                string `json:"userCode"`
	Handle                  string `json:"handle"`
	Interval                int    `json:"interval"`
}

// PollInput is `DevicePollInput(handle: String)`.
//
// The handle IS the authentication for `POST /auth/device/poll` (INV-A4-4): 192 bits, and the only
// device-login identifier pmon ever sees.
type PollInput struct {
	Handle string `json:"handle"`
}

// ConfirmInput is `DeviceConfirmInput(userCode: String)` — what the web /device page POSTs when the
// human confirms the code it shows.
type ConfirmInput struct {
	UserCode string `json:"userCode"`
}

// ConfirmAck is `DeviceConfirmAck(ok: Boolean = true)`.
//
// The `true` is a kotlinx DEFAULT, and `encodeDefaults = true` means it is emitted. A Go `bool` with
// omitempty would drop it; without omitempty the zero value would emit `false`. Hence the constructor
// [NewConfirmAck] and the absence of omitempty — the only correct combination.
type ConfirmAck struct {
	OK bool `json:"ok"`
}

// NewConfirmAck is `DeviceConfirmAck()` — the defaulted constructor.
func NewConfirmAck() ConfirmAck { return ConfirmAck{OK: true} }

// PollPending is `DevicePollPending(status: String = "authorization_pending")` — the 202 "still
// waiting on the user" shape. Same defaulted-constant reasoning as [ConfirmAck].
type PollPending struct {
	Status string `json:"status"`
}

// AuthorizationPending is RFC 8628 §3.5's status value, and the only value PollPending ever carries.
const AuthorizationPending = "authorization_pending"

// NewPollPending is `DevicePollPending()`.
func NewPollPending() PollPending { return PollPending{Status: AuthorizationPending} }

// PollResult is `DevicePollResult` — the 200 "done" shape.
//
// 🔒 RenewalToken is the ONLY time the `pmr_` secret is ever visible. Quoted from DeviceAuth.kt:52-58:
// "Returned EXACTLY ONCE, here — the control plane persists only its SHA-256 hash and can never hand
// it back out again." Combined with INV-A4-43's one-time consume, that is what bounds a device handle
// to exactly one credential set.
type PollResult struct {
	Token            string `json:"token"`
	ExpiresAt        string `json:"expiresAt"`
	Principal        string `json:"principal"`
	SessionExpiresAt string `json:"sessionExpiresAt"`
	RenewalToken     string `json:"renewalToken"`
}
