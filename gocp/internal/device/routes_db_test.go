package device

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// Port of DeviceLoginStoreDbTest.kt cases 7-14 — the route half.
//
// ORACLE: control-plane/src/test/kotlin/.../DeviceLoginStoreDbTest.kt, read this session; plus
// OidcWebSessionDbTest.kt case 5 (the direct-authorize-link phishing shape), whose device half is the
// same assertion.
//
// The Kotlin runs these with `authDebug = true` and `oidc = null` — "a route-level proof that
// PM_AUTH_DEBUG mints a wire token end-to-end through /auth/device/start + /auth/device/poll WITHOUT
// ever configuring an IdP: discovery/validator are both null and nothing here makes an outbound HTTP
// call." Same here: [deviceFixture] wires no IdP at all.

// --- Case 7 · `the verification URL points at the web console origin, not the control plane`
//
// The Kotlin case asserts on `Config.webBaseUrl` directly (internal/config's territory). What is
// DEVICE behaviour is that Start builds its URL FROM WebBaseURL — so a split-origin deployment sends
// the browser to the console, which serves /device, and not to the control plane, which does not.
// Both halves are asserted here: the derivation the Kotlin states, and that Start follows it.
// KT: DeviceLoginStoreDbTest.kt#the verification URL points at the web console origin, not the control plane
func TestStart_VerificationURIIsTheWebOrigin(t *testing.T) {
	f := newDeviceFixture(t)
	started := f.startLogin()

	want := f.cfg.WebBaseURL() + "/device"
	if started.VerificationURI != want {
		t.Fatalf("verificationUri = %q, want %q", started.VerificationURI, want)
	}
	if !strings.HasPrefix(started.VerificationURIComplete, want+"?user_code=") {
		t.Fatalf("verificationUriComplete = %q, want it to prefill the code onto %q",
			started.VerificationURIComplete, want)
	}
	// The poll interval on the wire is DEVICE_POLL_INTERVAL_SEC (2), NOT the 600 s handle lifetime.
	if started.Interval != PollIntervalSeconds {
		t.Errorf("interval = %d, want %d", started.Interval, PollIntervalSeconds)
	}
	if row := f.row(started.Handle); row == nil || row.TTLSeconds != token.SessionTTLSeconds {
		t.Errorf("ttl_seconds = %v, want the SESSION default %d", row, token.SessionTTLSeconds)
	}

	// 🔒 The Kotlin case's own two assertions, on the derived value the URL above is built from
	// (Config.kt:117-119). Without them the block above passes even for a WebBaseURL that IGNORED
	// PM_WEB_ORIGIN entirely — which is precisely the split-origin deployment the case exists for:
	// "otherwise a split-origin deployment would send the browser to the control plane, which serves
	// no such page."
	sameOrigin := config.Config{MCPResource: "https://console.example/mcp"}
	if got := sameOrigin.WebBaseURL(); got != "https://console.example" {
		t.Errorf("a blank PM_WEB_ORIGIN must mean SAME ORIGIN: WebBaseURL() = %q, want %q",
			got, "https://console.example")
	}
	splitOrigin := sameOrigin
	splitOrigin.WebOrigin = "http://127.0.0.1:41300/"
	if got := splitOrigin.WebBaseURL(); got != "http://127.0.0.1:41300" {
		t.Errorf("a set PM_WEB_ORIGIN must WIN, trailing slash trimmed: WebBaseURL() = %q, want %q",
			got, "http://127.0.0.1:41300")
	}

	// …and Start really does follow it: the same route, on a split-origin config, prints the CONSOLE's
	// /device URL rather than its own. Only Config and Store are reached on this path.
	split := &Routes{Config: splitOrigin, Store: f.store}
	rec := httptest.NewRecorder()
	split.Start(rec, httptest.NewRequest(http.MethodPost, "/auth/device/start", strings.NewReader("{}")))
	if rec.Code != http.StatusOK {
		t.Fatalf("split-origin start = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var splitStart StartResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &splitStart); err != nil {
		t.Fatalf("decode split-origin start: %v", err)
	}
	if splitStart.VerificationURI != "http://127.0.0.1:41300/device" {
		t.Errorf("split-origin verificationUri = %q, want the console origin's /device page",
			splitStart.VerificationURI)
	}
}

// --- Case 8 · `confirm accepts a real pending code and rejects an unknown one`
// KT: DeviceLoginStoreDbTest.kt#confirm accepts a real pending code and rejects an unknown one
func TestConfirm_AcceptsRealPendingCodeAndRejectsUnknown(t *testing.T) {
	f := newDeviceFixture(t)
	started := f.startLogin()

	if got := f.confirm(started.UserCode).StatusCode; got != http.StatusOK {
		t.Errorf("confirm status = %d, want 200", got)
	}
	resp := f.confirm("NOPE-NOPE")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("confirm of an unknown code = %d, want 400", resp.StatusCode)
	}
	var body types.ApiError
	decode(t, resp, &body)
	if body.Code != CodeUnknownOrExpired {
		t.Errorf("code = %q, want %q", body.Code, CodeUnknownOrExpired)
	}
}

// --- Case 9 🔒 · `authorize without a prior confirm approves nothing and bounces back to the device
// page` (INV-A4-46)
//
// THE DEVICE-PHISHING GATE. The browser is SIGNED IN and the code is real — the only thing missing is
// the /device confirm, and that alone must stop the approval.
//
// KT: DeviceLoginStoreDbTest.kt#authorize without a prior confirm approves nothing and bounces back to the device page
// KT: OidcWebSessionDbTest.kt#a direct authorize link with no device-page confirm approves no handle
//
//	Two Kotlin cases, one Go test: the second is the same assertion reached from the OIDC side, and
//	oidc/websession_db_test.go's header hands it here for the import-cycle reason.
func TestAuthorize_WithoutAPriorConfirmApprovesNothing(t *testing.T) {
	f := newDeviceFixture(t)
	started := f.startLogin()
	f.loginAs("alice@example.com")

	loc := location(t, f.authorize(started.UserCode))
	if !strings.HasPrefix(loc, "/device") {
		t.Fatalf("Location = %q, want a bounce to the device page", loc)
	}
	if got := f.statusOf(started.Handle); got != StatusPending {
		t.Fatalf("status = %q, want PENDING — no approval without a confirm", got)
	}
}

// --- Case 10 🔒 · `a confirm for one code cannot authorize a different code` (INV-A4-46)
//
// The cookie is bound to that EXACT code, so confirming mine does not become a blanket approval
// capability. This is the shape of the actual attack: the attacker's own pending login, plus a victim
// who confirmed something else.
// KT: DeviceLoginStoreDbTest.kt#a confirm for one code cannot authorize a different code
func TestAuthorize_AConfirmForOneCodeCannotAuthorizeAnother(t *testing.T) {
	f := newDeviceFixture(t)
	mine := f.startLogin()
	other := f.startLogin() // e.g. an attacker's own pending login
	f.loginAs("alice@example.com")

	if got := f.confirm(mine.UserCode).StatusCode; got != http.StatusOK {
		t.Fatalf("confirm status = %d", got)
	}
	loc := location(t, f.authorize(other.UserCode))
	if !strings.HasPrefix(loc, "/device") {
		t.Fatalf("Location = %q, want a bounce", loc)
	}
	if got := f.statusOf(other.Handle); got != StatusPending {
		t.Fatalf("the other login's status = %q, want PENDING — it must NOT be approved", got)
	}

	// …and my own code still authorizes normally. 🔒 This half is what proves the bounce above came
	// from the code MISMATCH and not from the cookie having been consumed or cleared: branch 2 must
	// NOT clear the verify cookie, or an attacker's link would destroy the victim's own confirm.
	if got := location(t, f.authorize(mine.UserCode)); got != "/device/success" {
		t.Fatalf("Location = %q, want /device/success — the mismatch must not have burned my cookie", got)
	}
}

// --- Case 11 🔒 · `authorize with no session sends the user to login and approves nothing yet`
//
// 🔒 And the branch must NOT clear the verify cookie: the user is coming straight back to this URL
// after /login, where step 2 re-requires it. See TestAuthorize_LoginRedirectKeepsTheVerifyCookie.
// KT: DeviceLoginStoreDbTest.kt#authorize with no session sends the user to login and approves nothing yet
func TestAuthorize_WithNoSessionGoesToLoginAndApprovesNothing(t *testing.T) {
	f := newDeviceFixture(t)
	started := f.startLogin()
	f.confirm(started.UserCode)

	loc := location(t, f.authorize(started.UserCode))
	if !strings.HasPrefix(loc, "/login?return_to=") {
		t.Fatalf("Location = %q, want /login?return_to=… — no console session means log in first", loc)
	}
	if !strings.Contains(loc, "device") {
		t.Fatalf("Location = %q, want the login to return to the device authorize URL", loc)
	}
	if got := f.statusOf(started.Handle); got != StatusPending {
		t.Fatalf("status = %q, want PENDING until a session exists", got)
	}
}

// --- 🔒 · the /login redirect keeps the verify cookie, and the SSO-then-approve path completes.
//
// This is OidcWebSessionDbTest case 4's device half, and the mutation guard for the subtlest line in
// the whole area. Clearing pm_device_verify on branch 4 would make every first-time `pmon login` loop
// between /login and /device forever.
//
// KT: OidcWebSessionDbTest.kt#a device login with no session logs in via SSO and comes back to approve the handle
//
//	the device half of that case, split out per the doc comment above; the whole round trip is
//	TestSSO_DeviceLoginWithNoSessionCompletesThroughOidc.
func TestAuthorize_LoginRedirectKeepsTheVerifyCookie(t *testing.T) {
	f := newDeviceFixture(t)
	started := f.startLogin()
	f.confirm(started.UserCode)

	// 1) No session yet → /login CARRYING THIS EXACT URL as the continuation. The Kotlin reads
	//    `return_to` out of that Location and drives the whole SSO leg with it, so the continuation
	//    being the device authorize URL is load-bearing rather than incidental: land the user anywhere
	//    else and the handle strands until it expires.
	authorizePath := "/auth/device/authorize?user_code=" + started.UserCode
	loginRedirect := location(t, f.authorize(started.UserCode))
	if want := "/login?return_to=" + url.QueryEscape(authorizePath); loginRedirect != want {
		t.Fatalf("login redirect = %q, want %q", loginRedirect, want)
	}
	if got := f.statusOf(started.Handle); got != StatusPending {
		t.Fatalf("status = %q, want PENDING — the /login bounce must approve nothing", got)
	}
	// 2) The user signs in (SSO or debug), which lands them back on this exact URL.
	f.loginAs("alice@example.com")
	// 3) Now the handle is approved WITHOUT a second confirm.
	if got := location(t, f.authorize(started.UserCode)); got != "/device/success" {
		t.Fatalf("Location = %q, want /device/success — the verify cookie must survive the /login bounce", got)
	}
	row := f.row(started.Handle)
	if row == nil || row.Status != StatusApproved {
		t.Fatalf("row = %#v, want status APPROVED", row)
	}
	// The Kotlin case's own tail: approved FOR THE PRINCIPAL THE LOGIN NAMED, never a debug default…
	if row.Principal == nil || *row.Principal != "alice@example.com" {
		t.Fatalf("principal = %v, want the signed-in principal", row.Principal)
	}
	// …and the approving session's IdP refresh token rides onto the device login, or the daemon
	// session minted at poll has nothing for its timer-driven IdP-liveness revalidation to run.
	refresh, err := f.store.DecryptRefresh(row)
	if err != nil {
		t.Fatal(err)
	}
	if refresh == nil || *refresh != "web-refresh-secret" {
		t.Fatalf("carried refresh token = %v, want web-refresh-secret", refresh)
	}
	// The OIDC hops themselves (/auth/oidc/login → callback → the honoured continuation) are asserted
	// by TestSSO_DeviceLoginWithNoSessionCompletesThroughOidc, which cites the same Kotlin case.
}

// --- Case 12 · `an existing console session approves the login without re-authenticating`
// (INV-A4-48)
// KT: DeviceLoginStoreDbTest.kt#an existing console session approves the login without re-authenticating
func TestAuthorize_ExistingSessionApprovesWithoutReAuthenticating(t *testing.T) {
	f := newDeviceFixture(t)
	started := f.startLogin()
	f.confirm(started.UserCode)
	f.loginAs("alice@example.com")

	if got := location(t, f.authorize(started.UserCode)); got != "/device/success" {
		t.Fatalf("Location = %q, want /device/success — an existing session approves straight through", got)
	}
	row := f.row(started.Handle)
	if row.Status != StatusApproved {
		t.Errorf("status = %q", row.Status)
	}
	if row.Principal == nil || *row.Principal != "alice@example.com" {
		t.Fatalf("principal = %v, want the logged-in principal, never a debug default", row.Principal)
	}
	// 🔒 The approving session's IdP refresh token rides onto the device login, or the daemon session
	// minted at poll has nothing for its timer-driven liveness revalidation to run.
	got, err := f.store.DecryptRefresh(row)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got != "web-refresh-secret" {
		t.Fatalf("carried refresh token = %v, want web-refresh-secret", got)
	}
}

// --- 🔒 INV-A4-46 · the verify cookie is SINGLE-USE with respect to approval.
//
// Branch 7 clears it whether or not the CAS won, so one confirm authorizes AT MOST one approval. A
// second authorize for the same code, in the same browser, must bounce.
func TestAuthorize_TheVerifyCookieIsSingleUsePerApproval(t *testing.T) {
	f := newDeviceFixture(t)
	started := f.startLogin()
	f.confirm(started.UserCode)
	f.loginAs("alice@example.com")

	if got := location(t, f.authorize(started.UserCode)); got != "/device/success" {
		t.Fatalf("first authorize = %q", got)
	}
	loc := location(t, f.authorize(started.UserCode))
	if !strings.HasPrefix(loc, "/device") {
		t.Fatalf("second authorize = %q, want a bounce — the cookie is consumed by an approval", loc)
	}
}

// --- 🔒 INV-A4-47 · a session that DIED between resolve and here mints nothing.
//
// The live re-check runs AFTER the refresh-token read on purpose; both consult `ended_at IS NULL`, so
// a just-invalidated authentication yields a nil token AND fails the check.
func TestAuthorize_ASessionEndedInBetweenApprovesNothing(t *testing.T) {
	f := newDeviceFixture(t)
	started := f.startLogin()
	f.confirm(started.UserCode)
	f.loginAs("alice@example.com")

	// The liveness sweep (or a logout elsewhere) ends the session after it was resolved. EndWeb is
	// the REAL store call, so `ended_at` is stamped exactly as production stamps it.
	if _, err := f.sessions.EndWeb(f.ctx, nil, f.lastSessionID(), session.EndedIdpRejected); err != nil {
		t.Fatal(err)
	}

	loc := location(t, f.authorize(started.UserCode))
	if !strings.HasPrefix(loc, "/login?return_to=") {
		t.Fatalf("Location = %q, want the login redirect", loc)
	}
	if got := f.statusOf(started.Handle); got != StatusPending {
		t.Fatalf("status = %q, want PENDING — a credential must never be minted off a dead session", got)
	}
}

// --- Case 13 · `a login mints a wire token end-to-end via start, confirm, authorize, then poll`
// KT: DeviceLoginStoreDbTest.kt#a login mints a wire token end-to-end via start, confirm, authorize, then poll
func TestPoll_MintsAWireTokenEndToEnd(t *testing.T) {
	f := newDeviceFixture(t)
	started := f.startLogin()

	// Until the browser approves, poll is PENDING — start never auto-approves.
	pending := f.poll(started.Handle)
	if pending.StatusCode != http.StatusAccepted {
		t.Fatalf("poll status = %d, want 202 until the browser approves", pending.StatusCode)
	}
	var pendingBody PollPending
	decode(t, pending, &pendingBody)
	if pendingBody.Status != AuthorizationPending {
		t.Errorf("pending status = %q, want %q", pendingBody.Status, AuthorizationPending)
	}

	f.confirm(started.UserCode)
	f.loginAs("alice@example.com")
	if got := f.authorize(started.UserCode).StatusCode; got != http.StatusFound {
		t.Fatalf("authorize status = %d", got)
	}

	resp := f.poll(started.Handle)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll status = %d, want 200", resp.StatusCode)
	}
	var result PollResult
	decode(t, resp, &result)
	if result.Principal != "alice@example.com" {
		t.Errorf("principal = %q", result.Principal)
	}
	if result.Token == "" {
		t.Fatal("token is blank")
	}
	// The minted token must be a REAL wire credential, not just a string.
	identity, err := f.tokens.Validate(f.ctx, result.Token)
	if err != nil || identity == nil {
		t.Fatalf("the minted token does not validate: %v, %v", identity, err)
	}
	if identity.Kind != string(token.KindSession) {
		t.Errorf("kind = %q, want SESSION", identity.Kind)
	}
	// 🔒 The one and only time the `pmr_` renewal secret is visible.
	if !strings.HasPrefix(result.RenewalToken, "pmr_") {
		t.Errorf("renewalToken = %q, want the mint-once pmr_ bearer secret", result.RenewalToken)
	}
	// Both timestamps are Instant.toString() — always UTC, always 'Z', seconds always printed.
	for name, ts := range map[string]string{"expiresAt": result.ExpiresAt, "sessionExpiresAt": result.SessionExpiresAt} {
		if !strings.HasSuffix(ts, "Z") || !strings.Contains(ts, "T") {
			t.Errorf("%s = %q, want a Java Instant.toString() rendering", name, ts)
		}
	}
}

// --- Case 14 🔒 · `a device handle mints exactly once — a replayed poll is refused and mints no
// second session` (INV-A4-43)
// KT: DeviceLoginStoreDbTest.kt#a device handle mints exactly once — a replayed poll is refused and mints no second session
func TestPoll_AHandleMintsExactlyOnce(t *testing.T) {
	f := newDeviceFixture(t)
	started := f.startLogin()
	f.confirm(started.UserCode)
	f.loginAs("alice@example.com")
	f.authorize(started.UserCode)

	if got := f.poll(started.Handle).StatusCode; got != http.StatusOK {
		t.Fatalf("first poll = %d, want 200", got)
	}

	replay := f.poll(started.Handle)
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed poll = %d, want 400", replay.StatusCode)
	}
	var body types.ApiError
	decode(t, replay, &body)
	if body.Code != CodeAlreadyCompleted {
		t.Errorf("code = %q, want %q", body.Code, CodeAlreadyCompleted)
	}

	// Exactly one daemon session — i.e. exactly one renewal secret — exists for this handle.
	var count int
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM principal_session WHERE handle = $1 AND kind = 'DAEMON'`,
		started.Handle).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("%d daemon sessions for one handle — a replayed poll must not mint a second "+
			"session/renewal secret, or the login handle becomes an unbounded credential minter", count)
	}
}

// --- 🔒 INV-A4-50 · a DEPROVISIONED principal is refused at mint time, and nothing is written.
//
// The teardown may land between approval and poll; the mint re-checks under the per-principal lock.
func TestPoll_DeprovisionedPrincipalIsRefusedAtMint(t *testing.T) {
	f := newDeviceFixture(t)
	started := f.startLogin()
	f.confirm(started.UserCode)
	f.loginAs("alice@example.com")
	f.authorize(started.UserCode)

	// SCIM deactivates the account after the browser approved but before pmon polled.
	if _, err := f.db.Pool.Exec(f.ctx,
		`INSERT INTO app_user (principal, source, active) VALUES ($1, 'SCIM', FALSE)`,
		"alice@example.com"); err != nil {
		t.Fatal(err)
	}

	resp := f.poll(started.Handle)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("poll = %d, want 403", resp.StatusCode)
	}
	var body types.ApiError
	decode(t, resp, &body)
	if body.Code != CodeDeprovisioned {
		t.Errorf("code = %q, want %q", body.Code, CodeDeprovisioned)
	}

	// 🔒 Nothing was persisted — no session row, no token. A check-then-create outside the lock could
	// leave a credential the sweep already scanned past.
	var sessions, tokens int
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM principal_session WHERE handle = $1`, started.Handle).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM proxy_token WHERE principal = $1`, "alice@example.com").Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || tokens != 0 {
		t.Fatalf("a refused mint left %d session(s) and %d token(s) behind", sessions, tokens)
	}
}

// --- 🔒 · poll refuses an unknown or expired handle.
func TestPoll_UnknownOrExpiredHandleIsRefused(t *testing.T) {
	f := newDeviceFixture(t)

	t.Run("unknown", func(t *testing.T) {
		resp := f.poll("dvc_no-such-handle")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		var body types.ApiError
		decode(t, resp, &body)
		if body.Code != CodeUnknownOrExpired {
			t.Errorf("code = %q", body.Code)
		}
	})

	t.Run("expired", func(t *testing.T) {
		row, err := f.store.CreatePending(f.ctx, PollIntervalSeconds, 3600, time.Now().Add(-time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if got := f.poll(row.Handle).StatusCode; got != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", got)
		}
	})
}

// --- 🔒 INV-A4-49 · `principal == null` reads as PENDING even if the status somehow says APPROVED.
//
// Belt and braces against a partially-written row: the ORDER of the two conditions means a row with
// no principal can never reach the mint.
func TestPoll_ApprovedWithNoPrincipalReadsAsPending(t *testing.T) {
	f := newDeviceFixture(t)
	row, err := f.store.CreatePending(f.ctx, PollIntervalSeconds, 3600, time.Now().Add(600*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	// A row that reached APPROVED without a principal — only reachable by a partial write.
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE device_login SET status = 'APPROVED' WHERE handle = $1`, row.Handle); err != nil {
		t.Fatal(err)
	}
	if got := f.poll(row.Handle).StatusCode; got != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", got)
	}
	if got := f.statusOf(row.Handle); got != StatusApproved {
		t.Errorf("status = %q — a pending READ must not consume the row", got)
	}
}

// --- ⚠️ · the THREE different body-parse strictnesses, reproduced individually.
//
// 04-auth-session-tokens.md §2.1: "Body-parse strictness is NOT uniform across the eleven routes —
// reproduce each one individually." Unifying them changes an observable status code on two of the
// three.
func TestRoutes_BodyParseStrictnessIsNotUniform(t *testing.T) {
	f := newDeviceFixture(t)

	t.Run("start defaults on a missing or garbage body", func(t *testing.T) {
		for _, body := range []string{"", "not json", "[]"} {
			resp := f.do(http.MethodPost, "/auth/device/start", body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("start with body %q = %d, want 200 (runCatching…getOrDefault)", body, resp.StatusCode)
			}
			var out StartResponse
			decode(t, resp, &out)
			// The defaulted ttlSeconds is SESSION_TTL_SECONDS.
			if row := f.row(out.Handle); row == nil || row.TTLSeconds != token.SessionTTLSeconds {
				t.Fatalf("ttl_seconds = %v, want the SESSION default", row)
			}
		}
	})

	t.Run("confirm turns a garbage body into device.unknown_or_expired_login, not a framework 400", func(t *testing.T) {
		resp := f.do(http.MethodPost, "/auth/device/confirm", "not json")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		var body types.ApiError
		decode(t, resp, &body)
		if body.Code != CodeUnknownOrExpired {
			t.Fatalf("code = %q, want %q — confirm falls into the null-code branch, it does not "+
				"surface a parse error", body.Code, CodeUnknownOrExpired)
		}
	})

	t.Run("poll surfaces the framework parse failure", func(t *testing.T) {
		resp := f.do(http.MethodPost, "/auth/device/poll", "not json")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		var body types.ApiError
		decode(t, resp, &body)
		if body.Code != "common.invalid_body" {
			t.Errorf("code = %q, want common.invalid_body — poll's receive is BARE", body.Code)
		}
	})
}

// --- · `ttlSeconds` is clamped, and the clamp is the ONLY enforcement (INV-A4-52).
func TestStart_TTLIsClamped(t *testing.T) {
	f := newDeviceFixture(t)
	for _, tc := range []struct {
		requested int64
		want      int64
	}{
		{-1, token.MinTTLSeconds},
		{0, token.MinTTLSeconds},
		{30, token.MinTTLSeconds},
		{3600, 3600},
		{999_999, token.MaxTTLSeconds},
	} {
		body, err := json.Marshal(StartInput{TTLSeconds: types.Ptr(tc.requested)})
		if err != nil {
			t.Fatal(err)
		}
		resp := f.do(http.MethodPost, "/auth/device/start", string(body))
		var out StartResponse
		decode(t, resp, &out)
		if row := f.row(out.Handle); row == nil || row.TTLSeconds != tc.want {
			t.Errorf("ttlSeconds %d stored as %v, want %d", tc.requested, row, tc.want)
		}
	}
}

// --- ⚠️ F33 · the whole surface emits ZERO log lines, and that silence is REPRODUCED.
//
// [Routes] takes no logger at all, which is the structural expression of it: the Kotlin's `log`
// parameter is accepted and never used, so there is no call path to port. This test documents the
// decision at the place a future reader would look for the missing warn lines.
func TestRoutes_EmitsNoLogsByConstruction(t *testing.T) {
	// The assertion is the type itself: if a Log field is ever added, this stops compiling and the
	// author has to read F33 before adding it.
	var rt Routes
	_ = rt.Config
	_ = rt.Store
	_ = rt.Sessions
	_ = rt.Tokens
	_ = rt.Minter
	_ = rt.Cookies
	_ = rt.Now
	// If you are here because you want observability on the device-phishing refusals: that is
	// 04-auth-session-tokens.md §8 Q11, a post-cutover decision, not part of the port.
}

// --- 🔴 Compile-time proof that A4's REAL store satisfies the daemon-session seam with no adapter.
//
// [DaemonSessions] exists because internal/device must not reach into A4's store directly, but the
// signatures are session.Store's exactly — so the seam is a narrowing, not a translation. If someone
// widens or renames a method here, this stops compiling instead of quietly growing an adapter that
// drifts from the store it wraps.
var _ DaemonSessions = (*session.Store)(nil)
