package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/idp"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/websession"
)

func Register(mux *http.ServeMux, login Login, au websession.Auth) {
	oi := oidcLogin{Auth: au, provider: login.Provider, crypto: login.Crypto, schema: login.Schema}
	mux.HandleFunc("GET /auth/oidc/login", api.Serve(oi.login))
	mux.HandleFunc("GET /auth/oidc/callback", api.Serve(oi.callback))
}

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
	websession.Auth
	provider *idp.Provider
	crypto   *idp.Crypto
	schema   *authz.Schema
}

// returnTarget keeps only the fixed local continuations, so the login can never redirect elsewhere.
func returnTarget(raw string) *string {
	if raw == "/oauth/resume" || raw == "/auth/reauth-complete" || raw == "/device" || deviceReturn(raw) {
		return &raw
	}
	return nil
}

// deviceReturn is /device?user_code= with a 1-16 character code of letters, digits and dashes.
func deviceReturn(raw string) bool {
	code, ok := strings.CutPrefix(raw, "/device?user_code=")
	if !ok || len(code) == 0 || len(code) > 16 {
		return false
	}
	for _, c := range code {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (o oidcLogin) login(w http.ResponseWriter, r *http.Request) error {
	if o.provider == nil {
		return api.CodeOIDCNotConfigured.Err()
	}
	state, nonce := api.RandomToken(24), api.RandomToken(24)
	_ = o.Sessions.SetSigned(w, stateCookie, oauthState{State: state, ReturnTo: returnTarget(r.URL.Query().Get("return_to"))}, flowCookieAge)
	_ = o.Sessions.SetSigned(w, nonceCookie, struct {
		Nonce string `json:"nonce"`
	}{nonce}, flowCookieAge)
	d, err := o.provider.Discovery(r.Context())
	if err != nil {
		return err
	}
	challenge := ""
	if o.provider.SupportsS256(d) {
		verifier := api.RandomToken(32)
		_ = o.Sessions.SetSigned(w, verifierCookie, struct {
			Verifier string `json:"verifier"`
		}{verifier}, flowCookieAge)
		sum := sha256.Sum256([]byte(verifier))
		challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	} else {
		o.Sessions.Clear(w, r, verifierCookie)
	}
	api.Found(w, o.provider.AuthorizeURL(d, state, nonce, challenge))
	return nil
}

// redirectTarget keeps /oauth/ continuations on this origin and sends everything else to the console.
func (o oidcLogin) redirectTarget(path string) string {
	if strings.HasPrefix(path, "/oauth/") {
		return path
	}
	return o.Sessions.Settings().WebRedirect(path)
}

// failureTarget is where a failed login lands: back to its continuation with the error, else the login page.
func failureTarget(st *oauthState, oauthErr, consoleErr string) string {
	switch {
	case st != nil && st.ReturnTo != nil && *st.ReturnTo == "/oauth/resume":
		return "/oauth/resume?error=" + api.URLParameter(oauthErr)
	case st != nil && st.ReturnTo != nil && *st.ReturnTo == "/auth/reauth-complete":
		return "/login?error=" + api.URLParameter(consoleErr) + "&callbackUrl=%2Fauth%2Freauth-complete"
	case st != nil && st.ReturnTo != nil:
		return "/login?error=" + api.URLParameter(consoleErr) + "&return_to=" + api.URLParameter(*st.ReturnTo)
	}
	return "/login?error=" + api.URLParameter(consoleErr)
}

func (o oidcLogin) callback(w http.ResponseWriter, r *http.Request) error {
	if o.provider == nil {
		return api.CodeOIDCNotConfigured.Err()
	}
	ctx := r.Context()
	params := r.URL.Query()
	var (
		st       *oauthState
		nonce    struct{ Nonce string }
		verifier struct{ Verifier string }
	)
	var s oauthState
	if o.Sessions.ReadSigned(r, stateCookie, &s) {
		st = &s
	}
	haveNonce := o.Sessions.ReadSigned(r, nonceCookie, &nonce)
	o.Sessions.ReadSigned(r, verifierCookie, &verifier)
	for _, c := range []string{stateCookie, nonceCookie, verifierCookie} {
		o.Sessions.Clear(w, r, c)
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
		audit.AuthFailure(context.WithoutCancel(ctx), o.Pool, audit.Actor{Principal: actor, ClientAddr: o.RequesterIP(r), Channel: "oidc"},
			"auth.oidc.login", resource, "OIDC login failed", detail)
		api.Found(w, o.redirectTarget(failureTarget(st, oauthErr, consoleErr)))
	}

	code, state := params.Get("code"), params.Get("state")
	if !params.Has("state") || st == nil || state != st.State {
		slog.Warn("oidc: callback state validation failed")
		target := "/login?error=state"
		if st != nil && st.ReturnTo != nil && *st.ReturnTo == "/auth/reauth-complete" {
			target = failureTarget(st, "access_denied", "state")
		}
		audit.AuthFailure(context.WithoutCancel(ctx), o.Pool, audit.Actor{Principal: "unknown", ClientAddr: o.RequesterIP(r), Channel: "oidc"},
			"auth.oidc.login", audit.Entity("Client", clientID), "OIDC login failed", "invalid_state")
		api.Found(w, o.redirectTarget(target))
		return nil
	}
	if params.Has("error") {
		failed("idp_error="+api.Truncate(params.Get("error"), 200), "", "access_denied", "oidc")
		return nil
	}
	if !params.Has("code") {
		failed("missing_code", "", "server_error", "state")
		return nil
	}
	if !haveNonce {
		failed("missing_nonce", "", "access_denied", "nonce")
		return nil
	}
	idToken, refresh, err := o.provider.Exchange(ctx, code, verifier.Verifier)
	if err != nil {
		slog.Error("oidc: token exchange failed", "err", err)
		failed("token_exchange_failed", "", "server_error", "oidc")
		return nil
	}
	claims, err := o.provider.Validate(ctx, idToken, nonce.Nonce)
	if err != nil {
		slog.Warn("oidc: id_token validation failed", "err", err)
		failed("invalid_id_token", "", "access_denied", "nonce")
		return nil
	}
	principal := claims.Principal()
	if err := idp.Provision(ctx, o.Pool, principal, claims.Email, claims.Name, claims.Groups, o.provider.Config().Groups,
		o.schema.ClaimAttributes(claims.Raw)); err != nil {
		slog.Error("oidc: provisioning failed", "err", err)
		failed("provisioning_failed", principal, "server_error", "oidc")
		return nil
	}
	roles, err := authz.Roles(ctx, o.Pool, principal)
	if err != nil {
		slog.Error("oidc: role resolution failed", "err", err)
		failed("provisioning_failed", principal, "server_error", "oidc")
		return nil
	}
	if len(roles) == 0 {
		slog.Warn("oidc: principal has no effective roles", "principal", principal)
		failed("no_effective_roles", principal, "access_denied", "no_access")
		return nil
	}
	var refreshEnc []byte
	if refresh != "" && o.provider.Config().OfflineAccess() && o.crypto != nil {
		refreshEnc = o.crypto.Encrypt(refresh)
	}
	device := o.Sessions.EnsureDevice(w, r)
	actor := audit.Actor{Principal: principal, ClientAddr: o.RequesterIP(r), Channel: "oidc"}
	var (
		id        int64
		displaced bool
	)
	err = pgx.BeginFunc(ctx, o.Pool, func(tx pgx.Tx) error {
		var err error
		if id, displaced, err = o.Sessions.Mint(ctx, tx, principal, refreshEnc, device, nil); err != nil {
			return err
		}
		return audit.Auth(ctx, tx, actor, "auth.oidc.login", audit.Entity("Session", strconv.FormatInt(id, 10)), "OIDC login established session")
	})
	if err != nil {
		slog.Error("oidc: session mint failed", "err", err)
		failed("session_mint_failed", principal, "server_error", "oidc")
		return nil
	}
	if err := o.Establish(w, r, id, principal, displaced); err != nil {
		return err
	}
	target := "/"
	if st.ReturnTo != nil {
		target = *st.ReturnTo
	}
	api.Found(w, o.redirectTarget(target))
	return nil
}

// Login is the OIDC relying party; a nil Provider leaves OIDC login unconfigured (501).
type Login struct {
	Provider *idp.Provider
	Crypto   *idp.Crypto
	// Schema declares which id_token claims a login stores as user attributes.
	Schema *authz.Schema
}
