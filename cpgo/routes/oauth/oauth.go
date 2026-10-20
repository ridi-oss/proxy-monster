// Package oauth is the MCP OAuth 2.1 authorization server: discovery, authorize with client ID metadata
// documents (CIMD), consent, token, revoke, and the user's consent list.
package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/device"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/websession"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

const (
	pendingCookie    = "pm_oauth_pending"
	pendingCookieAge = 600
)

// pending is the authorization request carried across the login and consent pages.
type pending struct {
	ClientID      string  `json:"clientId"`
	RedirectURI   string  `json:"redirectUri"`
	Resource      string  `json:"resource"`
	Scope         string  `json:"scope"`
	State         string  `json:"state"`
	CodeChallenge string  `json:"codeChallenge"`
	Principal     *string `json:"principal,omitempty"`
	CSRF          string  `json:"csrf"`
}

type server struct {
	websession.Auth
	store    store
	resolver Resolver
}

func Register(mux *http.ServeMux, au websession.Auth, resolver Resolver) {
	s := server{Auth: au, store: store{au.Pool}, resolver: resolver}
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", serve(s.metadata))
	mux.HandleFunc("GET /oauth/authorize", serve(s.authorize))
	mux.HandleFunc("GET /oauth/resume", serve(s.resume))
	mux.HandleFunc("GET /oauth/pending", serve(s.pendingConsent))
	mux.HandleFunc("POST /oauth/consent", serve(s.consent))
	mux.HandleFunc("POST /oauth/token", serve(s.token))
	mux.HandleFunc("POST /oauth/revoke", serve(s.revoke))
	mux.HandleFunc("GET /oauth/consents", serve(s.consents))
	mux.HandleFunc("DELETE /oauth/consents/{id}", serve(s.revokeConsent))
}

type oauthError struct {
	status int
	code   string
}

func (e oauthError) Error() string { return e.code }

func badRequest(code string) error { return oauthError{http.StatusBadRequest, code} }

// serve answers an OAuth route's failure as {"error"}, and keeps every /oauth/ answer out of caches.
func serve(route api.Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/oauth/") {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
		}
		err := route(w, r)
		var oe oauthError
		switch {
		case err == nil:
		case errors.As(err, &oe):
			writeError(w, oe.status, oe.code)
		default:
			slog.Error("oauth: request failed", "method", r.Method, "path", r.URL.Path, "err", err)
			writeError(w, http.StatusInternalServerError, "server_error")
		}
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	api.WriteJSON(w, status, struct {
		Error string `json:"error"`
	}{code})
}

func (s server) settings() session.Settings { return s.Sessions.Settings() }

func (s server) metadata(w http.ResponseWriter, _ *http.Request) error {
	issuer := s.settings().Issuer()
	api.WriteJSON(w, http.StatusOK, struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		RevocationEndpoint                string   `json:"revocation_endpoint"`
		ResponseTypesSupported            []string `json:"response_types_supported"`
		GrantTypesSupported               []string `json:"grant_types_supported"`
		CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		ScopesSupported                   []string `json:"scopes_supported"`
		CIMDSupported                     bool     `json:"client_id_metadata_document_supported"`
	}{issuer, s.settings().WebBase() + "/oauth/authorize", issuer + "/oauth/token", issuer + "/oauth/revoke",
		[]string{"code"}, []string{"authorization_code", "refresh_token"}, []string{"S256"}, []string{"none"},
		session.MCPScopes(), true})
	return nil
}

// principal is the request's live web session's principal, or "".
func (s server) principal(r *http.Request) (string, error) {
	w, err := s.Live(r)
	if err != nil || w == nil {
		return "", err
	}
	return w.Principal, nil
}

func (s server) authorize(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	q := r.URL.Query()
	has := func(k string) bool { return strings.TrimSpace(q.Get(k)) != "" }
	clientID, redirect, state, resource, challenge := q.Get("client_id"), q.Get("redirect_uri"), q.Get("state"), q.Get("resource"), q.Get("code_challenge")
	var requested []string
	for _, sc := range strings.Split(q.Get("scope"), " ") {
		if strings.TrimSpace(sc) != "" && !slices.Contains(requested, sc) {
			requested = append(requested, sc)
		}
	}
	valid := q.Get("response_type") == "code" && has("client_id") && has("redirect_uri") && has("state") &&
		resource == s.settings().MCPResource && q.Get("code_challenge_method") == "S256" &&
		validChallenge(challenge) && len(requested) > 0 &&
		!slices.ContainsFunc(requested, func(sc string) bool { return !slices.Contains(session.MCPScopes(), sc) })
	if !valid {
		return badRequest("invalid_request")
	}
	client, err := s.resolver.Resolve(ctx, clientID)
	if err != nil {
		slog.Info("oauth: client metadata rejected", "err", err)
		return badRequest("invalid_client")
	}
	if err := client.validate(redirect, requested); err != nil {
		slog.Info("oauth: authorization request rejected by client metadata", "err", err)
		return badRequest("invalid_client")
	}
	p := pending{ClientID: clientID, RedirectURI: redirect, Resource: resource, Scope: session.CanonicalScopes(requested),
		State: state, CodeChallenge: challenge, CSRF: csrfToken()}
	current, err := s.Live(r)
	if err != nil {
		return err
	}
	if s.settings().AuthDebug {
		return s.debugAuthorize(w, r, p, current)
	}
	if current != nil {
		p.Principal = &current.Principal
	}
	if p.Principal == nil {
		if err := s.Sessions.SetSigned(w, pendingCookie, p, pendingCookieAge); err != nil {
			return err
		}
		// The OIDC login on this origin returns to /oauth/resume.
		api.Found(w, "/auth/oidc/login?return_to="+api.URLParameter("/oauth/resume"))
		return nil
	}
	return s.continueAuthorization(w, r, p)
}

// debugAuthorize is a login, like /auth/debug: it mints a real web session, so it must be told who, by
// ?principal= or the current session. The new session replaces the console's and keeps its simulated
// address when the principal is unchanged.
func (s server) debugAuthorize(w http.ResponseWriter, r *http.Request, p pending, current *session.Web) error {
	ctx := r.Context()
	principal := r.URL.Query().Get("principal")
	if strings.TrimSpace(principal) == "" {
		if current == nil {
			return badRequest("login_required")
		}
		principal = current.Principal
	}
	p.Principal = &principal
	// Read before the mint: the request's cookies name the session it replaces.
	actor := s.actor(r, principal)
	var debugIP *string
	if current != nil && current.Principal == principal && current.DebugRequesterIP != "" {
		debugIP = &current.DebugRequesterIP
	}
	deviceID := s.Sessions.EnsureDevice(w, r)
	var (
		id        int64
		displaced bool
	)
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		id, displaced, err = s.Sessions.Mint(ctx, tx, principal, nil, deviceID, debugIP)
		return err
	})
	if err != nil {
		return err
	}
	if err := s.Establish(w, r, id, principal, displaced); err != nil {
		return err
	}
	if s.settings().OAuthDebugAutoConsent || r.URL.Query().Get("auto_consent") == "true" {
		consentID, err := s.grantConsent(r.Context(), p, actor)
		if err != nil {
			return err
		}
		return s.issueCode(w, r, p, consentID)
	}
	return s.askConsent(w, p)
}

func (s server) resume(w http.ResponseWriter, r *http.Request) error {
	var p pending
	havePending := s.Sessions.ReadSigned(r, pendingCookie, &p)
	if q := r.URL.Query(); q.Has("error") {
		upstream := q.Get("error")
		if !havePending || upstream != "access_denied" && upstream != "server_error" {
			return badRequest("invalid_request")
		}
		client, err := s.resolver.Resolve(r.Context(), p.ClientID)
		if err != nil || client.validate(p.RedirectURI, strings.Fields(p.Scope)) != nil {
			return badRequest("invalid_client")
		}
		s.Sessions.Clear(w, r, pendingCookie)
		api.Found(w, redirectWith(p.RedirectURI, "error", upstream, "state", p.State))
		return nil
	}
	principal, err := s.principal(r)
	if err != nil {
		return err
	}
	if !havePending || principal == "" || p.Principal != nil && *p.Principal != principal {
		return badRequest("invalid_request")
	}
	p.Principal, p.CSRF = &principal, csrfToken()
	return s.continueAuthorization(w, r, p)
}

// continueAuthorization issues a code when the principal already consented to exactly this grant, else asks.
func (s server) continueAuthorization(w http.ResponseWriter, r *http.Request, p pending) error {
	client, err := s.resolver.Resolve(r.Context(), p.ClientID)
	if err != nil {
		return err
	}
	if err := client.validate(p.RedirectURI, strings.Fields(p.Scope)); err != nil {
		return err
	}
	consentID, err := s.store.activeConsent(r.Context(), *p.Principal, p.ClientID, p.Resource, p.Scope)
	if err != nil {
		return err
	}
	if consentID != 0 {
		return s.issueCode(w, r, p, consentID)
	}
	return s.askConsent(w, p)
}

func (s server) consent(w http.ResponseWriter, r *http.Request) error {
	var p pending
	havePending := s.Sessions.ReadSigned(r, pendingCookie, &p)
	if err := r.ParseForm(); err != nil {
		return err
	}
	principal, err := s.principal(r)
	if err != nil {
		return err
	}
	if !havePending || p.Principal == nil || principal != *p.Principal || !r.PostForm.Has("csrf") || r.PostForm.Get("csrf") != p.CSRF {
		return badRequest("invalid_request")
	}
	if r.PostForm.Get("decision") != "approve" {
		s.Sessions.Clear(w, r, pendingCookie)
		api.Found(w, redirectWith(p.RedirectURI, "error", "access_denied", "state", p.State))
		return nil
	}
	// A double-submitted approval finds the consent the first one created and records no second grant.
	consentID, err := s.grantConsent(r.Context(), p, s.actor(r, principal))
	if err != nil {
		return err
	}
	return s.issueCode(w, r, p, consentID)
}

// grantConsent is the live consent for the pending grant, recording a new one as the user's grant.
func (s server) grantConsent(ctx context.Context, p pending, actor audit.Actor) (int64, error) {
	return s.store.grantConsent(ctx, *p.Principal, p.ClientID, p.Resource, p.Scope, func(ctx context.Context, tx pgx.Tx, id int64) error {
		return audit.Auth(ctx, tx, actor, "auth.oauth.consent", audit.Entity("Consent", strconv.FormatInt(id, 10)),
			"OAuth consent granted to client "+api.Truncate(p.ClientID, 200)+" for "+p.Scope)
	})
}

func (s server) actor(r *http.Request, principal string) audit.Actor {
	return audit.Actor{Principal: principal, ClientAddr: s.RequesterIP(r), Channel: "oauth"}
}

func (s server) issueCode(w http.ResponseWriter, r *http.Request, p pending, consentID int64) error {
	client, err := s.resolver.Resolve(r.Context(), p.ClientID)
	if err != nil {
		return err
	}
	if err := client.validate(p.RedirectURI, strings.Fields(p.Scope)); err != nil {
		return err
	}
	code, err := s.store.createCode(r.Context(), codeGrant{clientID: p.ClientID, principal: *p.Principal, redirectURI: p.RedirectURI,
		resource: p.Resource, scope: p.Scope, challenge: p.CodeChallenge, consentID: consentID})
	if err != nil {
		return err
	}
	s.Sessions.Clear(w, r, pendingCookie)
	api.Found(w, redirectWith(p.RedirectURI, "code", code, "state", p.State))
	return nil
}

func (s server) token(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	form := r.PostForm
	clientID, grantType := api.Truncate(form.Get("client_id"), 200), form.Get("grant_type")
	actor := s.actor(r, "unknown")
	detail := "grant_type=" + grantType
	onGrant := func(ctx context.Context, tx pgx.Tx) error {
		return audit.AuthDetail(ctx, tx, actor, "auth.oauth.token", audit.Entity("Client", clientID),
			"OAuth token granted to client "+clientID, detail)
	}
	onReplay := func(ctx context.Context, tx pgx.Tx, tokenID int64) error {
		return audit.AuthDetail(ctx, tx, actor, "auth.oauth.revoke", audit.Entity("Token", strconv.FormatInt(tokenID, 10)),
			"OAuth refresh family revoked on replay", detail)
	}
	require := func(keys ...string) bool {
		return !slices.ContainsFunc(keys, func(k string) bool { return !form.Has(k) })
	}
	settings := s.settings()
	ttl := ttls{settings.MCPAccessTTL, settings.MCPRefreshTTL}
	var (
		pair *tokenPair
		err  error
	)
	switch grantType {
	case "authorization_code":
		if !require("code", "client_id", "redirect_uri", "resource", "code_verifier") {
			return badRequest("invalid_request")
		}
		if form.Get("resource") == settings.MCPResource {
			pair, err = s.store.redeemCode(r.Context(), form.Get("code"), form.Get("client_id"), form.Get("redirect_uri"),
				form.Get("resource"), form.Get("code_verifier"), ttl, onGrant)
		}
	case "refresh_token":
		if !require("refresh_token", "client_id", "resource") {
			return badRequest("invalid_request")
		}
		if form.Get("resource") == settings.MCPResource {
			pair, err = s.store.rotate(r.Context(), form.Get("refresh_token"), form.Get("client_id"), form.Get("resource"), ttl, onGrant, onReplay)
		}
	default:
		return badRequest("unsupported_grant_type")
	}
	if err != nil {
		return err
	}
	if pair == nil {
		// The denied grant changed nothing, so a failed audit insert must not turn invalid_grant into a 500.
		audit.AuthFailure(context.WithoutCancel(r.Context()), s.Pool, actor, "auth.oauth.token", audit.Entity("Client", clientID),
			"OAuth token grant denied", detail)
		return badRequest("invalid_grant")
	}
	api.WriteJSON(w, http.StatusOK, struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}{pair.access, "Bearer", pair.expiresIn, pair.refresh, pair.scope})
	return nil
}

// revoke answers 200 whatever the token was (RFC 7009 §2.2). It is unauthenticated, so only a call that
// closed a token is recorded; otherwise replaying one once-valid token would append a row per call.
func (s server) revoke(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	if r.PostForm.Has("token") {
		actor := s.actor(r, "unknown")
		err := s.store.revoke(r.Context(), r.PostForm.Get("token"), func(ctx context.Context, tx pgx.Tx, id int64) error {
			return audit.Auth(ctx, tx, actor, "auth.oauth.revoke", audit.Entity("Token", strconv.FormatInt(id, 10)), "OAuth token revoked")
		})
		if err != nil {
			slog.Warn("oauth: token revoke did not record; RFC 7009 answers 200 regardless", "err", err)
		}
	}
	api.WriteJSON(w, http.StatusOK, struct{}{})
	return nil
}

type consentJSON struct {
	ID        int64  `json:"id"`
	Principal string `json:"principal"`
	ClientID  string `json:"clientId"`
	Resource  string `json:"resource"`
	Scope     string `json:"scope"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

func (s server) consents(w http.ResponseWriter, r *http.Request) error {
	principal, err := s.principal(r)
	if err != nil {
		return err
	}
	if principal == "" {
		return oauthError{http.StatusUnauthorized, "login_required"}
	}
	rows, err := db.New(s.Pool).ListConsents(r.Context(), principal)
	if err != nil {
		return err
	}
	out := []consentJSON{}
	for _, c := range rows {
		out = append(out, consentJSON{c.ID, c.Principal, c.ClientID, c.Resource, c.Scope, api.JavaInstant(c.CreatedAt), api.JavaInstant(c.UpdatedAt)})
	}
	api.WriteJSON(w, http.StatusOK, struct {
		Consents  []consentJSON `json:"consents"`
		CSRFToken string        `json:"csrfToken"`
	}{out, s.consentCSRF(principal)})
	return nil
}

func (s server) revokeConsent(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	principal, err := s.principal(r)
	if err != nil {
		return err
	}
	if principal == "" {
		return oauthError{http.StatusUnauthorized, "login_required"}
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-PM-CSRF")), []byte(s.consentCSRF(principal))) != 1 {
		return badRequest("invalid_request")
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return badRequest("invalid_request")
	}
	actor := s.actor(r, principal)
	revoked, err := s.store.revokeConsent(ctx, id, principal, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Auth(ctx, tx, actor, "auth.oauth.revoke", audit.Entity("Consent", strconv.FormatInt(id, 10)), "OAuth consent revoked")
	})
	if err != nil {
		slog.Warn("oauth: consent revoke did not record", "err", err)
		revoked = true
	}
	if !revoked {
		return oauthError{http.StatusNotFound, "invalid_request"}
	}
	if err := device.EndByConsent(ctx, s.Pool, id, principal); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// consentCSRF is the per-principal token the consent list hands out and the revoke checks.
func (s server) consentCSRF(principal string) string {
	mac := hmac.New(sha256.New, []byte(s.settings().Secret))
	mac.Write([]byte("mcp-oauth-consent\x00" + principal))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func csrfToken() string { return "csrf_" + api.RandomToken(18) }

// redirectWith appends the parameters to a client's redirect URI, as Kotlin's oauthRedirect does.
func redirectWith(uri string, kv ...string) string {
	sep := "?"
	if strings.Contains(uri, "?") {
		sep = "&"
	}
	var b strings.Builder
	b.WriteString(uri)
	for i := 0; i < len(kv); i += 2 {
		b.WriteString(sep + api.URLParameter(kv[i]) + "=" + api.URLParameter(kv[i+1]))
		sep = "&"
	}
	return b.String()
}
