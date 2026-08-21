// Package login drives the control-plane-brokered OIDC device-authorization flow. The DAEMON runs this — a
// CLI or tray login is a request to the daemon's control socket, so there is exactly one implementation and
// two concurrent login attempts cannot race each other into two device flows.
package login

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// DefaultControlPlane is used only on a first login where neither the request nor saved state names one. It
// matches the control plane's own PM_HTTP_PORT default; a local dev loop that moves that port must pass --url
// once, which is then saved.
const DefaultControlPlane = "http://localhost:8080"

// DefaultTTL is the requested wire-token lifetime (12h). The control plane clamps it.
const DefaultTTL = 43200

// RequestTimeout bounds each control-plane HTTP request.
const RequestTimeout = 15 * time.Second

// Prompt is what the user must do to complete a login: open [VerificationURI] and confirm [UserCode]. The
// daemon emits one to whichever peer asked, so a CLI can print it and a tray can raise a notification from
// the same flow.
type Prompt struct {
	VerificationURI string `json:"verificationUri"`
	// VerificationURIComplete carries the code. A peer opens this one and prints the plain one, so a
	// user following the printed link types the code themselves.
	VerificationURIComplete string `json:"verificationUriComplete"`
	UserCode                string `json:"userCode"`
}

// Result is a completed device-auth flow.
type Result struct {
	Principal        string `json:"principal"`
	Token            string `json:"token"`
	ExpiresAt        string `json:"expiresAt"`
	SessionExpiresAt string `json:"sessionExpiresAt"`
	RenewalToken     string `json:"renewalToken"`
}

// deviceStartResponse is the body of POST {cp}/auth/device/start.
type deviceStartResponse struct {
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	UserCode                string `json:"userCode"`
	Handle                  string `json:"handle"`
	Interval                int    `json:"interval"`
}

// devicePollResponse is the body of POST {cp}/auth/device/poll: either the 202 "still waiting" shape
// ({status: "authorization_pending"}) or the 200 "done" shape.
type devicePollResponse struct {
	Status           string `json:"status"`
	Token            string `json:"token"`
	ExpiresAt        string `json:"expiresAt"`
	Principal        string `json:"principal"`
	SessionExpiresAt string `json:"sessionExpiresAt"`
	RenewalToken     string `json:"renewalToken"`
}

// Options configures one device-auth run. Sleep is injected so tests can supply a no-op.
type Options struct {
	ControlPlane string
	TTLSeconds   int
	// OnPrompt receives the verification URI + user code as soon as the flow starts, before polling. It must
	// not block for long — the poll loop is waiting on it.
	OnPrompt   func(Prompt)
	Sleep      func(context.Context, time.Duration)
	HTTPClient *http.Client
}

// Run drives the flow: start -> open (or hand back) the verification URL -> poll until it completes or ctx
// ends. The cookie jar carries the control plane's device-flow cookies across the two calls.
func Run(ctx context.Context, opts Options) (*Result, error) {
	cp := opts.ControlPlane
	if cp == "" {
		cp = DefaultControlPlane
	}
	ttl := opts.TTLSeconds
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	client := opts.HTTPClient
	if client == nil {
		jar, _ := cookiejar.New(nil)
		client = &http.Client{Jar: jar, Timeout: RequestTimeout}
	}
	sleep := opts.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}

	var start deviceStartResponse
	if err := postJSON(ctx, client, cp+"/auth/device/start", map[string]any{"ttlSeconds": ttl}, &start); err != nil {
		return nil, fmt.Errorf("could not start device login: %w", err)
	}

	if opts.OnPrompt != nil {
		uri := start.VerificationURI
		if uri == "" {
			uri = start.VerificationURIComplete
		}
		opts.OnPrompt(Prompt{
			VerificationURI:         uri,
			VerificationURIComplete: start.VerificationURIComplete,
			UserCode:                start.UserCode,
		})
	}

	interval := time.Duration(start.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	for {
		sleep(ctx, interval)
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		var poll devicePollResponse
		if err := postJSON(ctx, client, cp+"/auth/device/poll", map[string]any{"handle": start.Handle}, &poll); err != nil {
			return nil, fmt.Errorf("device poll failed: %w", err)
		}
		if poll.Status == "authorization_pending" {
			continue
		}
		if poll.RenewalToken == "" {
			// Refuse a session with no way to renew silently rather than degrading to one that dies at the
			// wire token's expiry with no path back.
			return nil, fmt.Errorf("device login succeeded but returned no renewal token")
		}
		return &Result{
			Principal:        poll.Principal,
			Token:            poll.Token,
			ExpiresAt:        poll.ExpiresAt,
			SessionExpiresAt: poll.SessionExpiresAt,
			RenewalToken:     poll.RenewalToken,
		}, nil
	}
}

// RenewResult is a successful silent renewal: a fresh wire token within the same session window.
type RenewResult struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

// ErrRenewalRefused reports that the control plane declined to renew — the session window closed, the
// principal was deprovisioned, or IdP liveness went inactive. The daemon's only recovery is a fresh login.
var ErrRenewalRefused = fmt.Errorf("renewal refused: a fresh login is required")

// Renew silently re-mints the wire token via POST /auth/session/renew, authenticating with the renewal token
// as a bearer. A 401 is [ErrRenewalRefused] — a terminal condition, not a transient error, so the caller
// stops renewing and asks the user to log in again.
func Renew(ctx context.Context, client *http.Client, controlPlane, renewalToken string) (*RenewResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, controlPlane+"/auth/session/renew", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+renewalToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrRenewalRefused
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("renew: HTTP %d", resp.StatusCode)
	}
	var out RenewResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Token == "" {
		return nil, fmt.Errorf("renew returned no token")
	}
	return &out, nil
}

// postJSON POSTs body as JSON and, if out is non-nil, decodes the response into it. HTTP 202 is treated as
// success — the device poll endpoint uses it for "still waiting on the user".
func postJSON(ctx context.Context, client *http.Client, url string, body, out any) error {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// sleepCtx sleeps for d, or returns early when ctx ends, so a shutdown mid-poll is prompt.
func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
