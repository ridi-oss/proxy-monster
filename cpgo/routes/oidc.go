package routes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/idp"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

// The short-lived signed cookies that carry a login across the IdP redirect.
const (
	stateCookie    = "pm_oauth_state"
	nonceCookie    = "pm_oauth_nonce"
	verifierCookie = "pm_oauth_verifier"
	flowCookieAge  = 300
)

type oauthState struct {
	State    string  `json:"state"`
	ReturnTo *string `json:"returnTo,omitempty"`
}

// oidcLogin serves the authorization-code login: /auth/oidc/login and /auth/oidc/callback.
type oidcLogin struct {
	auth
	provider *idp.Provider
	crypto   *idp.Crypto
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

var deviceReturn = regexp.MustCompile(`^/device\?user_code=[A-Za-z0-9-]{1,16}$`)

// returnTarget keeps only the fixed local continuations, so the login can never redirect elsewhere.
func returnTarget(raw string) *string {
	if raw == "/oauth/resume" || raw == "/auth/reauth-complete" || raw == "/device" || deviceReturn.MatchString(raw) {
		return &raw
	}
	return nil
}

func (o oidcLogin) notConfigured(w http.ResponseWriter) bool {
	if o.provider == nil {
		api.WriteError(w, http.StatusNotImplemented, "common.oidc_not_configured", nil)
		return true
	}
	return false
}

func (o oidcLogin) login(w http.ResponseWriter, r *http.Request) {
	if o.notConfigured(w) {
		return
	}
	state, nonce := randomToken(24), randomToken(24)
	_ = o.sessions.SetSigned(w, stateCookie, oauthState{State: state, ReturnTo: returnTarget(r.URL.Query().Get("return_to"))}, flowCookieAge)
	_ = o.sessions.SetSigned(w, nonceCookie, struct {
		Nonce string `json:"nonce"`
	}{nonce}, flowCookieAge)
	d, err := o.provider.Discovery(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	challenge := ""
	if o.provider.SupportsS256(d) {
		verifier := randomToken(32)
		_ = o.sessions.SetSigned(w, verifierCookie, struct {
			Verifier string `json:"verifier"`
		}{verifier}, flowCookieAge)
		sum := sha256.Sum256([]byte(verifier))
		challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	} else {
		o.sessions.Clear(w, r, verifierCookie)
	}
	found(w, o.provider.AuthorizeURL(d, state, nonce, challenge))
}

// redirectTarget keeps /oauth/ continuations on this origin and sends everything else to the console.
func (o oidcLogin) redirectTarget(path string) string {
	if strings.HasPrefix(path, "/oauth/") {
		return path
	}
	return o.sessions.Settings().WebRedirect(path)
}

// failureTarget is where a failed login lands: back to its continuation with the error, else the login page.
func failureTarget(st *oauthState, oauthErr, consoleErr string) string {
	q := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
	switch {
	case st != nil && st.ReturnTo != nil && *st.ReturnTo == "/oauth/resume":
		return "/oauth/resume?error=" + q(oauthErr)
	case st != nil && st.ReturnTo != nil && *st.ReturnTo == "/auth/reauth-complete":
		return "/login?error=" + q(consoleErr) + "&callbackUrl=%2Fauth%2Freauth-complete"
	case st != nil && st.ReturnTo != nil:
		return "/login?error=" + q(consoleErr) + "&return_to=" + q(*st.ReturnTo)
	}
	return "/login?error=" + q(consoleErr)
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func (o oidcLogin) callback(w http.ResponseWriter, r *http.Request) {
	if o.notConfigured(w) {
		return
	}
	ctx := r.Context()
	params := r.URL.Query()
	var (
		st       *oauthState
		nonce    struct{ Nonce string }
		verifier struct{ Verifier string }
	)
	var s oauthState
	if o.sessions.ReadSigned(r, stateCookie, &s) {
		st = &s
	}
	haveNonce := o.sessions.ReadSigned(r, nonceCookie, &nonce)
	o.sessions.ReadSigned(r, verifierCookie, &verifier)
	for _, c := range []string{stateCookie, nonceCookie, verifierCookie} {
		o.sessions.Clear(w, r, c)
	}
	clientID := o.provider.Config().ClientID
	failed := func(detail, principal, oauthErr, consoleErr string) {
		resource := audit.Entity("Client", clientID)
		actor := principal
		if principal == "" {
			actor = "unknown"
		} else {
			resource = audit.Entity("User", principal)
		}
		audit.AuthFailure(context.WithoutCancel(ctx), o.pool, audit.Actor{Principal: actor, ClientAddr: o.requesterIP(r), Channel: "oidc"},
			"auth.oidc.login", resource, "OIDC login failed", detail)
		found(w, o.redirectTarget(failureTarget(st, oauthErr, consoleErr)))
	}

	code, state := params.Get("code"), params.Get("state")
	if !params.Has("state") || st == nil || state != st.State {
		slog.Warn("oidc: callback state validation failed")
		target := "/login?error=state"
		if st != nil && st.ReturnTo != nil && *st.ReturnTo == "/auth/reauth-complete" {
			target = failureTarget(st, "access_denied", "state")
		}
		audit.AuthFailure(context.WithoutCancel(ctx), o.pool, audit.Actor{Principal: "unknown", ClientAddr: o.requesterIP(r), Channel: "oidc"},
			"auth.oidc.login", audit.Entity("Client", clientID), "OIDC login failed", "invalid_state")
		found(w, o.redirectTarget(target))
		return
	}
	if params.Has("error") {
		failed("idp_error="+truncate(params.Get("error"), 200), "", "access_denied", "oidc")
		return
	}
	if !params.Has("code") {
		failed("missing_code", "", "server_error", "state")
		return
	}
	if !haveNonce {
		failed("missing_nonce", "", "access_denied", "nonce")
		return
	}
	idToken, refresh, err := o.provider.Exchange(ctx, code, verifier.Verifier)
	if err != nil {
		slog.Error("oidc: token exchange failed", "err", err)
		failed("token_exchange_failed", "", "server_error", "oidc")
		return
	}
	claims, err := o.provider.Validate(ctx, idToken, nonce.Nonce)
	if err != nil {
		slog.Warn("oidc: id_token validation failed", "err", err)
		failed("invalid_id_token", "", "access_denied", "nonce")
		return
	}
	principal := claims.Principal()
	if err := idp.Provision(ctx, o.pool, principal, claims.Email, claims.Groups, o.provider.Config().Groups); err != nil {
		slog.Error("oidc: provisioning failed", "err", err)
		failed("provisioning_failed", principal, "server_error", "oidc")
		return
	}
	roles, err := authz.New(o.pool).Roles(ctx, principal)
	if err != nil {
		slog.Error("oidc: role resolution failed", "err", err)
		failed("provisioning_failed", principal, "server_error", "oidc")
		return
	}
	if len(roles) == 0 {
		slog.Warn("oidc: principal has no effective roles", "principal", principal)
		failed("no_effective_roles", principal, "access_denied", "no_access")
		return
	}
	var refreshEnc []byte
	if refresh != "" && o.provider.Config().OfflineAccess() && o.crypto != nil {
		refreshEnc = o.crypto.Encrypt(refresh)
	}
	device := o.sessions.EnsureDevice(w, r)
	actor := audit.Actor{Principal: principal, ClientAddr: o.requesterIP(r), Channel: "oidc"}
	var (
		id        int64
		displaced bool
	)
	err = pgx.BeginFunc(ctx, o.pool, func(tx pgx.Tx) error {
		var err error
		if id, displaced, err = o.sessions.Mint(ctx, tx, principal, refreshEnc, device, nil); err != nil {
			return err
		}
		return audit.Auth(ctx, tx, actor, "auth.oidc.login", audit.Entity("Session", strconv.FormatInt(id, 10)), "OIDC login established session")
	})
	if err != nil {
		slog.Error("oidc: session mint failed", "err", err)
		failed("session_mint_failed", principal, "server_error", "oidc")
		return
	}
	if err := o.establish(w, r, id, principal, displaced); err != nil {
		fail(w, err)
		return
	}
	target := "/"
	if st.ReturnTo != nil {
		target = *st.ReturnTo
	}
	found(w, o.redirectTarget(target))
}

// establish links the request's tracker (or a fresh one) to the committed session, sets the cookie, and
// tells Kotlin when the login displaced an older session.
func (a auth) establish(w http.ResponseWriter, r *http.Request, id int64, principal string, displaced bool) error {
	ctx := r.Context()
	ref, err := a.sessions.Ref(ctx, r)
	if err != nil {
		return err
	}
	key := session.NewKey()
	if ref != nil {
		key = ref.Key
	}
	if err := pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error { return a.sessions.Link(ctx, tx, id, key) }); err != nil {
		return err
	}
	if displaced {
		a.signalEnded(ctx, principal)
	}
	a.sessions.SetSessionCookie(w, key)
	return nil
}

// found is Ktor's respondRedirect: a 302 with a Location and no body.
func found(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}
