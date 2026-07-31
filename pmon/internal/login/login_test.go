package login

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// noSleep runs the poll loop without real delays.
func noSleep(context.Context, time.Duration) {}

// TestRunOpensBrowserAndPollsUntilDone walks the happy path: start, open the complete verification URI, then
// poll past a pending response to the completed one.
func TestRunOpensBrowserAndPollsUntilDone(t *testing.T) {
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/device/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verificationUri":         "https://idp.example/activate",
				"verificationUriComplete": "https://idp.example/activate?code=ABCD-EFGH",
				"userCode":                "ABCD-EFGH",
				"handle":                  "h-1",
				"interval":                1,
			})
		case "/auth/device/poll":
			polls++
			if polls == 1 {
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorization_pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"principal":        "you@example.com",
				"token":            "pmk_tok",
				"expiresAt":        "2026-07-26T00:00:00Z",
				"sessionExpiresAt": "2026-07-26T12:00:00Z",
				"renewalToken":     "pmr_abc123",
			})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	var prompt Prompt
	res, err := Run(context.Background(), Options{
		ControlPlane: srv.URL,
		OnPrompt:     func(p Prompt) { prompt = p },
		Sleep:        noSleep,
		HTTPClient:   srv.Client(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The peer opens the COMPLETE URI, so the page prefills the code — the flow must hand it over.
	if prompt.VerificationURIComplete != "https://idp.example/activate?code=ABCD-EFGH" {
		t.Errorf("prompt.VerificationURIComplete = %q, want the complete URI", prompt.VerificationURIComplete)
	}
	// What a peer SHOWS is the plain URI: a user who opens the link by hand types the code themselves,
	// which is what makes them read it off the terminal and confirm it's their own login.
	if prompt.VerificationURI != "https://idp.example/activate" {
		t.Errorf("prompt.VerificationURI = %q, want the plain URI (the code is typed, not carried)", prompt.VerificationURI)
	}
	if prompt.UserCode != "ABCD-EFGH" {
		t.Errorf("prompt = %+v, want the user code", prompt)
	}
	if res.Principal != "you@example.com" || res.Token != "pmk_tok" || res.RenewalToken != "pmr_abc123" {
		t.Errorf("result = %+v, want the polled identity + tokens", res)
	}
	if polls != 2 {
		t.Errorf("polled %d times, want 2 (one pending, one done)", polls)
	}
}

// TestRunHandsBackTheURIWhenNoBrowser covers a headless box: the browser launcher fails, so the flow must
// report the URI as un-opened for the peer to print rather than aborting.
func TestRunHandsBackTheURIWhenNoBrowser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/device/start" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verificationUri": "https://idp.example/activate", "userCode": "WXYZ", "handle": "h", "interval": 1,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"principal": "you@example.com", "token": "t", "renewalToken": "pmr_x",
		})
	}))
	defer srv.Close()

	var prompt Prompt
	if _, err := Run(context.Background(), Options{
		ControlPlane: srv.URL,
		OnPrompt:     func(p Prompt) { prompt = p },
		Sleep:        noSleep,
		HTTPClient:   srv.Client(),
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if prompt.VerificationURI != "https://idp.example/activate" {
		t.Errorf("VerificationURI = %q, want the plain URI to print", prompt.VerificationURI)
	}
}

// TestRunRefusesALoginWithNoRenewalToken locks the fail-closed choice: without a renewal token the daemon
// could never renew silently and would die at the wire token's expiry with no path back, so the flow refuses
// rather than degrading to that session.
func TestRunRefusesALoginWithNoRenewalToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/device/start" {
			_ = json.NewEncoder(w).Encode(map[string]any{"userCode": "C", "handle": "h", "interval": 1})
			return
		}
		// Deliberately omits renewalToken.
		_ = json.NewEncoder(w).Encode(map[string]any{"principal": "you@example.com", "token": "tok-norenew"})
	}))
	defer srv.Close()

	if _, err := Run(context.Background(), Options{
		ControlPlane: srv.URL,
		Sleep:        noSleep,
		HTTPClient:   srv.Client(),
	}); err == nil {
		t.Fatal("expected an error when the poll response omits renewalToken, got nil")
	}
}

// TestRenewSendsBearerAndReturnsFreshToken covers the silent-renewal path the daemon runs before expiry.
func TestRenewSendsBearerAndReturnsFreshToken(t *testing.T) {
	var gotAuth, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotMethod = r.Header.Get("Authorization"), r.Method
		if r.URL.Path != "/auth/session/renew" {
			t.Errorf("path = %q, want /auth/session/renew", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "pmk_fresh", "expiresAt": "2026-07-26T12:00:00Z"})
	}))
	defer srv.Close()

	res, err := Renew(context.Background(), srv.Client(), srv.URL, "pmr_abc123")
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if gotAuth != "Bearer pmr_abc123" {
		t.Errorf("Authorization = %q, want the renewal token as a bearer", gotAuth)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if res.Token != "pmk_fresh" {
		t.Errorf("token = %q, want the freshly minted one", res.Token)
	}
}

// TestRenewTreats401AsTerminal locks the distinction the daemon acts on: a 401 means the session window closed
// (only a fresh login recovers), so it must be a sentinel the renewal loop can stop on, not a transient error
// it retries forever.
func TestRenewTreats401AsTerminal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := Renew(context.Background(), srv.Client(), srv.URL, "pmr_stale")
	if !errors.Is(err, ErrRenewalRefused) {
		t.Fatalf("Renew error = %v, want ErrRenewalRefused", err)
	}
}

// TestRenewRetriesATransientFailure: a 500 is NOT terminal — the daemon should keep its current token and try
// again, so the error must be distinguishable from a refusal.
func TestRenewRetriesATransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := Renew(context.Background(), srv.Client(), srv.URL, "pmr_x")
	if err == nil {
		t.Fatal("expected an error on HTTP 500")
	}
	if errors.Is(err, ErrRenewalRefused) {
		t.Error("a 500 was reported as a terminal refusal; the daemon would stop renewing on a transient fault")
	}
}
