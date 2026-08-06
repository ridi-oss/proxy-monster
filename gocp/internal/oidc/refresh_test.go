package oidc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Partial port of DaemonSessionLivenessIdpTest.kt — the IdP-FACING half.
//
// 🔴 SCOPE, stated so the gap is visible rather than assumed. That suite's 8 cases each drive
// `sweepSessionLiveness` end to end: a fake IdP, plus PrincipalSessionStore.staleSessions /
// updateRefresh / markCheck / endWeb / closeDaemonWindow / endAllWebForPrincipal, plus A3's
// provisionFromOidc. Every one of those store methods is A4's PrincipalSessionStore, which this
// increment does NOT own. What IS portable today is [RefreshGrant] — the classification that decides
// each case's OUTCOME — and the `expectedNonce = nil` validator mode the sweep depends on.
//
// So: cases 4 and 6's CLASSIFICATION is ported here (invalid_grant ⇒ revoke; invalid_client and a raw
// 500 ⇒ transient), and case 3's "an omitted groups claim is authoritative-empty" is covered by
// TestValidate_MissingGroupsClaimIsAnEmptyList. Cases 1, 2, 5, 7 and 8 are DB+store tests and are
// listed as todos, not silently dropped.
//
// ORACLE: 04-auth-session-tokens.md §3.6 (read this session), quoting DaemonSession.kt:785-805 for
// the classification ladder and :792-796 for INV-A4-40's rationale.
//
//	TODO(A4): port the remaining 5 cases once PrincipalSessionStore lands. The fake IdP below already
//	          selects its response from the presented refresh_token exactly as the Kotlin's does, so
//	          those cases need only the store, not a new fixture.
//
// 🔴 THE BLOCKER, RESTATED NOW THAT THE STORE HAS LANDED. PrincipalSessionStore IS ported
// (internal/session.Store, with staleSessions / updateRefresh / markCheck / endWeb /
// closeDaemonWindow / endAllWebForPrincipal all present) and so is provisionFromOidc
// (internal/oidc.DirectoryProvisioner). What is NOT ported is the FUNCTION UNDER TEST:
// `sweepSessionLiveness` itself — the loop that reads the candidate set, presents each refresh token,
// classifies the outcome, and then writes the per-outcome consequences. internal/session/doc.go
// carries it as `TODO(A4): sweepSessionLiveness.` and no Go symbol implements it.
//
// All 8 of DaemonSessionLivenessIdpTest's cases were KT-DEFER here for exactly that reason. The sweep
// landed (internal/oidc/liveness.go) and they are ported in liveness_db_test.go, so the deferrals are
// gone. The division of labour stands: this file covers the CLASSIFICATION (`invalid_grant` ⇒
// Inactive), which says nothing about whether the sweep then closes only the rejected daemon row and
// spares its sibling — that consequence is the other file's.

// livenessIdP is the Kotlin fixture's `/token` endpoint: it selects its response from the PRESENTED
// refresh_token string. `rt-invalid-grant`, `rt-invalid-client`, `rt-http-500`, `rt-no-groups:<p>`,
// `rt-active:<p>:<groups>` — the same vocabulary, so the remaining cases can reuse it verbatim.
func livenessIdP(t *testing.T) (tokenEndpoint string, requests *int) {
	t.Helper()
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch rt := r.PostForm.Get("refresh_token"); {
		case rt == "rt-invalid-grant":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"the user is gone"}`)
		case rt == "rt-invalid-client":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
		case rt == "rt-http-500":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"server_error"}`)
		case rt == "rt-html-4xx":
			// A 4xx whose body will NOT parse — the `http_<status>` fallback.
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `<html>go away</html>`)
		case rt == "rt-no-access-token":
			// INV-A4-65 / F34: a 200 with no `access_token`.
			_, _ = io.WriteString(w, `{"id_token":"an-id-token"}`)
		case rt == "rt-rotating":
			_, _ = io.WriteString(w, `{"access_token":"unused","refresh_token":"rt-rotated","id_token":"an-id-token"}`)
		case strings.HasPrefix(rt, "rt-active"):
			// The literal "unused" is the Kotlin's, and it is there ONLY because the parse demands
			// the key (INV-A4-65).
			_, _ = io.WriteString(w, `{"access_token":"unused","id_token":"an-id-token"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_request"}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/token", &count
}

func grant(t *testing.T, endpoint, refreshToken string) RefreshOutcome {
	t.Helper()
	return RefreshGrant(context.Background(), NewHTTPClient(), endpoint, "client", "secret", refreshToken)
}

// --- Case 4 / 6 🔒 · `only invalid_grant revokes; every other error is transient` (INV-A4-40)
//
// This is the single highest-blast-radius classification in the area. Quoted from
// DaemonSession.kt:792-796: the rest of the 4xx space "is OUR-side/config trouble, not proof the
// account is gone, and must NOT revoke a live session". 04-auth-session-tokens.md's Go-shape note:
// "getting this inverted mass-logs-out a fleet during an IdP incident."
func TestRefreshGrant_OnlyInvalidGrantRevokes(t *testing.T) {
	endpoint, _ := livenessIdP(t)

	// The 4xx ladder is exact: parse the body, else `http_<status>`, then compare to invalid_grant.
	//
	// ⚠️ The 5xx arm is NOT part of that ladder and its reason string is deliberately unpinned. In the
	// Kotlin a 5xx raises ServerResponseException, which is not a ClientRequestException, so it lands
	// in `catch (e: Exception) { Transient(e.message ?: …) }` (DaemonSession.kt:799-801) — a ktor
	// exception message, not `http_500`. The port's equivalent is the StatusError's own message. What
	// is CONTRACT is the KIND; what the reason string reads like is a log detail on both sides, so
	// asserting an exact 5xx reason would pin a ktor message format the port cannot and should not
	// reproduce.
	cases := []struct {
		refreshToken string
		want         RefreshOutcomeKind
		wantReason   string // "" ⇒ unpinned, see above
		why          string
	}{
		{"rt-invalid-grant", RefreshInactive, InvalidGrant, "the IdP's definitive account-is-gone signal"},
		{"rt-invalid-client", RefreshTransient, "invalid_client", "a rotated client_secret is OUR problem, not proof the account is gone"},
		{"rt-http-500", RefreshTransient, "", "a 5xx is ServerResponseException in Kotlin, which is not a ClientRequestException"},
		{"rt-html-4xx", RefreshTransient, "http_403", "an unparseable 4xx body falls back to http_<status>, which is not invalid_grant"},
	}
	for _, tc := range cases {
		t.Run(tc.refreshToken, func(t *testing.T) {
			got := grant(t, endpoint, tc.refreshToken)
			if got.Kind != tc.want {
				t.Fatalf("Kind = %v, want %v — %s", got.Kind, tc.want, tc.why)
			}
			if tc.wantReason != "" && got.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
		})
	}

	t.Run("a 5xx carrying a JSON error body is STILL transient and is never classified from it", func(t *testing.T) {
		// The trap a status-blind port falls into: rt-http-500's body says "server_error", and a
		// port that parsed the body regardless of status would classify on the string. The Kotlin
		// never even looks — a 5xx is a different exception type. So the reason must NOT be the
		// body's `error` value, which is what proves the body was not consulted.
		got := grant(t, endpoint, "rt-http-500")
		if got.Kind != RefreshTransient {
			t.Fatalf("Kind = %v, want RefreshTransient", got.Kind)
		}
		if got.Reason == "server_error" {
			t.Error("the 5xx body was parsed for classification; the Kotlin never reads it")
		}
		if !strings.Contains(got.Reason, "500") {
			t.Errorf("Reason = %q, want it to name the status so an operator can see it", got.Reason)
		}
	})
}

// --- 🔒 INV-A4-65 / F34 · a 200 with no `access_token` is TRANSIENT, not Active.
//
// The field is required-by-parse and never read. A Go port modelling the response with all-optional
// fields would classify this as Active and then proceed to validate the id_token — a materially
// different outcome, because Active also stamps markCheck and can end a session.
func TestRefreshGrant_F34_MissingAccessTokenIsTransient(t *testing.T) {
	endpoint, _ := livenessIdP(t)

	got := grant(t, endpoint, "rt-no-access-token")
	if got.Kind != RefreshTransient {
		t.Fatalf("Kind = %v, want RefreshTransient (INV-A4-65) — a missing access_token is a kotlinx parse failure", got.Kind)
	}
	if !strings.Contains(got.Reason, "access_token") {
		t.Errorf("Reason = %q, want it to name access_token", got.Reason)
	}
}

// --- · a healthy grant is Active and surfaces the rotated refresh token.
//
// The rotation is what `revalidateSession` persists BEFORE validating the id_token — an ordering
// 04-auth-session-tokens.md calls load-bearing and the Kotlin suite never exercises (its fake IdP
// never rotates, §4.17 gap 17). Surfacing it here at least pins the plumbing.
func TestRefreshGrant_ActiveSurfacesRotationAndIDToken(t *testing.T) {
	endpoint, count := livenessIdP(t)

	got := grant(t, endpoint, "rt-active:alice@example.com")
	if got.Kind != RefreshActive {
		t.Fatalf("Kind = %v, want RefreshActive", got.Kind)
	}
	if got.IDToken == nil || *got.IDToken != "an-id-token" {
		t.Errorf("IDToken = %v", got.IDToken)
	}
	if got.RotatedRefreshToken != nil {
		t.Errorf("RotatedRefreshToken = %q, want nil when the IdP does not rotate", *got.RotatedRefreshToken)
	}

	rotated := grant(t, endpoint, "rt-rotating")
	if rotated.Kind != RefreshActive {
		t.Fatalf("Kind = %v, want RefreshActive", rotated.Kind)
	}
	if rotated.RotatedRefreshToken == nil || *rotated.RotatedRefreshToken != "rt-rotated" {
		t.Fatalf("RotatedRefreshToken = %v, want rt-rotated", rotated.RotatedRefreshToken)
	}
	if *count != 2 {
		t.Errorf("token endpoint saw %d requests, want 2", *count)
	}
}

// --- · a network failure (no server at all) is TRANSIENT, never Inactive.
//
// The Kotlin's generic `catch (e: Exception)` arm. A port that treated an unreachable IdP as "the
// account is gone" would revoke every session in the fleet during a DNS outage.
func TestRefreshGrant_NetworkFailureIsTransient(t *testing.T) {
	got := grant(t, "http://127.0.0.1:1/token", "rt-active:alice@example.com")
	if got.Kind != RefreshTransient {
		t.Fatalf("Kind = %v, want RefreshTransient for an unreachable IdP", got.Kind)
	}
}

// --- 🔒 the sweep's validator mode: `expectedNonce = nil`.
//
// INV-A14-31 again, from the sweep's side: a refresh-grant id_token legitimately carries no nonce, so
// `revalidateSession` passes nil. Making the nonce check unconditional would break daemon liveness
// silently — every session would go stale and be re-warned forever. This asserts the composition, not
// just the validator: a token with NO nonce claim, validated the way the sweep validates it.
func TestRefreshGrant_SweepValidatesWithoutANonce(t *testing.T) {
	idp, v := newValidatorFixture(t)
	opts := idp.defaultClaims(testClientID)
	opts.nonce = nil
	opts.email = "alice@example.com"
	opts.groups = []any{"engineering"}

	got := v.Validate(context.Background(), idp.sign(opts, nil), nil)
	if got == nil {
		t.Fatal("the sweep's expectedNonce = nil mode must accept a nonce-less refresh id_token")
	}
	// INV-A4-37's step 3c compares this to the row's principal; `claims.email ?: claims.subject`.
	principal := got.Subject
	if got.Email != nil {
		principal = *got.Email
	}
	if principal != "alice@example.com" {
		t.Errorf("refreshed principal = %q, want the email claim", principal)
	}
	if want := []string{"engineering"}; len(got.Groups) != 1 || got.Groups[0] != want[0] {
		t.Errorf("Groups = %v, want %v", got.Groups, want)
	}
}

// --- · StatusError's 4xx/5xx split, directly. It is the whole mechanism INV-A4-40 rests on.
func TestStatusError_ClientErrorSplit(t *testing.T) {
	for _, tc := range []struct {
		status int
		client bool
	}{{400, true}, {401, true}, {403, true}, {499, true}, {500, false}, {502, false}, {503, false}} {
		e := &StatusError{StatusCode: tc.status, URL: "http://idp.test/token"}
		if e.IsClientError() != tc.client {
			t.Errorf("HTTP %d IsClientError = %v, want %v", tc.status, e.IsClientError(), tc.client)
		}
	}
	// The message must not carry the body, which can hold an IdP's error text.
	e := &StatusError{StatusCode: 401, Body: []byte(`{"error":"invalid_client"}`), URL: "http://idp.test/token"}
	if strings.Contains(e.Error(), "invalid_client") {
		t.Errorf("Error() = %q — the body belongs in the classification, not the message", e.Error())
	}
}
