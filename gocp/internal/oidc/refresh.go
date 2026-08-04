package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// RefreshOutcomeKind is `private sealed interface RefreshOutcome` (DaemonSession.kt:775-782),
// flattened into a kind + payload because Go has no sealed hierarchies and the three arms carry
// disjoint fields.
type RefreshOutcomeKind int

const (
	// RefreshActive is `Active(rotatedRefreshToken, idToken)` — the IdP still recognises the account.
	RefreshActive RefreshOutcomeKind = iota
	// RefreshInactive is `Inactive(reason)` — the IdP's DEFINITIVE "this refresh token/account is no
	// longer valid". The ONLY outcome that may revoke a session.
	RefreshInactive
	// RefreshTransient is `Transient(reason)` — anything else. Last-known-good is preserved and
	// `last_idp_check_at` is NOT stamped, so the next sweep retries rather than waiting a full
	// interval (INV-A4-39).
	RefreshTransient
)

// RefreshOutcome carries the arm plus its payload.
type RefreshOutcome struct {
	Kind RefreshOutcomeKind
	// RotatedRefreshToken and IDToken are set only on RefreshActive; both may still be nil.
	RotatedRefreshToken *string
	IDToken             *string
	// Reason is set on RefreshInactive / RefreshTransient. It is a LOG field, never a wire value.
	Reason string
}

// refreshTokenResponse is `@Serializable private data class RefreshTokenResponse`
// (DaemonSession.kt:765-770).
//
// 🔒 INV-A4-65 — `access_token` is REQUIRED-BY-PARSE and NEVER READ, and that turns a missing
// `access_token` into Transient, not Active. The field has no default in Kotlin, so kotlinx throws
// MissingFieldException when the IdP omits it; the shared client installs only
// `Json { ignoreUnknownKeys = true }` — no coerceInputValues, no isLenient — so there is no leniency
// to fall back on. The throw is caught by [RefreshGrant]'s generic catch ⇒ Transient ⇒ last-known-good
// preserved and no markCheck.
//
// RFC 6749 §5.1 makes `access_token` REQUIRED so a compliant IdP always sends it, and the field is
// otherwise unused — but a Go port modelling the response with all-optional fields would classify the
// same response as ACTIVE and then proceed to validate a nil id_token. F34. The pointer + the
// explicit nil check in [RefreshGrant] reproduce the required-ness.
//
// Corroboration that this is load-bearing rather than theoretical: DaemonSessionLivenessIdpTest's
// fake IdP emits `{"access_token":"unused", …}` on BOTH of its 200 branches — the literal string
// "unused" is there only because the parse demands the key. That suite would fail without it.
type refreshTokenResponse struct {
	AccessToken  *string `json:"access_token"`
	RefreshToken *string `json:"refresh_token"`
	IDToken      *string `json:"id_token"`
}

// refreshErrorBody is `@Serializable private data class RefreshErrorBody(error, error_description)`
// (DaemonSession.kt:772-773).
//
// ⚠️ `error_description` is parsed and NEVER READ (only `error` is inspected, DaemonSession.kt:798).
// Dead field, harmless — do not invent a use for it.
type refreshErrorBody struct {
	Error            *string `json:"error"`
	ErrorDescription *string `json:"error_description"`
}

// InvalidGrant is the ONE OAuth error code that means "revoke".
const InvalidGrant = "invalid_grant"

// RefreshGrant is
// `private suspend fun refreshGrant(http, tokenEndpoint, clientId, clientSecret, refreshToken): RefreshOutcome`
// (DaemonSession.kt:785-805).
//
// 🔒 INV-A4-40 — ONLY `invalid_grant` REVOKES; EVERY OTHER ERROR IS TRANSIENT. Quoted from
// DaemonSession.kt:792-796: "Only `invalid_grant` is the IdP's definitive 'this refresh token/account
// is no longer valid' signal. The rest of the 4xx space — `invalid_client` (a rotated client_secret),
// `unsupported_grant_type` (IdP-side config drift), etc. — is OUR-side/config trouble, not proof the
// account is gone, and must NOT revoke a live session."
//
// The Kotlin gets that split for free from ktor's `expectSuccess = true`: a 4xx raises
// ClientRequestException (parse the body, compare to invalid_grant, fall back to `http_<status>`),
// while a 5xx raises ServerResponseException — which is NOT a ClientRequestException, so it lands in
// the generic catch and becomes Transient. Go's http.Client does not error on non-2xx at all, so the
// branch has to be explicit; 04-auth-session-tokens.md's "Go shape" note spells out the exact ladder
// and warns that "getting this inverted mass-logs-out a fleet during an IdP incident."
//
// DaemonSessionLivenessIdpTest case 6 pins `invalid_client` (401) and a raw 500 as transient; case 4
// pins invalid_grant as the revoking one.
//
// This function is the IdP-facing HALF of `revalidateSession`. The other half — staleSessions,
// updateRefresh, markCheck, endWeb, closeDaemonWindow, endAllWebForPrincipal — is A4's
// PrincipalSessionStore and is deliberately NOT here.
//
//	TODO(A4): sweepSessionLiveness / revalidateSession compose this with the session store. Two
//	          orderings inside revalidateSession are load-bearing and must not be lost: the rotated
//	          refresh token is persisted BEFORE the id_token is validated (INV-A4-37's note — a
//	          rotating IdP invalidates the old token the moment it issues the new one), and the
//	          refreshed principal is compared to the row's principal BEFORE provisioning.
func RefreshGrant(
	ctx context.Context, hc *http.Client, tokenEndpoint, clientID, clientSecret, refreshToken string,
) RefreshOutcome {
	var resp refreshTokenResponse
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	err := postFormJSON(ctx, hc, tokenEndpoint, form, &resp)
	if err != nil {
		var status *StatusError
		if errors.As(err, &status) && status.IsClientError() {
			return classify4xx(status)
		}
		// 5xx, a network failure, a decode failure — every one of these is the Kotlin's generic
		// `catch (e: Exception)`.
		return RefreshOutcome{Kind: RefreshTransient, Reason: err.Error()}
	}
	// INV-A4-65 / F34 — the required-by-parse field. A 200 without `access_token` is a kotlinx parse
	// failure over there, i.e. Transient, NOT Active.
	if resp.AccessToken == nil {
		return RefreshOutcome{Kind: RefreshTransient, Reason: "token endpoint response is missing required field access_token"}
	}
	return RefreshOutcome{Kind: RefreshActive, RotatedRefreshToken: resp.RefreshToken, IDToken: resp.IDToken}
}

// classify4xx is the Kotlin's ClientRequestException arm: parse the body as RefreshErrorBody, fall
// back to `http_<status>` when it will not parse, and compare to invalid_grant.
func classify4xx(status *StatusError) RefreshOutcome {
	reason := fmt.Sprintf("http_%d", status.StatusCode)
	var body refreshErrorBody
	if err := json.Unmarshal(status.Body, &body); err == nil && body.Error != nil {
		reason = *body.Error
	}
	if reason == InvalidGrant {
		return RefreshOutcome{Kind: RefreshInactive, Reason: reason}
	}
	return RefreshOutcome{Kind: RefreshTransient, Reason: reason}
}
