package oauth

import (
	"net/http"
	"strings"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
)

// askConsent keeps the request in the pending cookie and sends the browser to the web console's consent page,
// which reads it from /oauth/pending and posts the decision to /oauth/consent.
func (s server) askConsent(w http.ResponseWriter, p pending) error {
	if err := s.Sessions.SetSigned(w, pendingCookie, p, pendingCookieAge); err != nil {
		return err
	}
	api.Found(w, s.settings().WebRedirect("/consent"))
	return nil
}

// pendingConsent is what the consent page shows: the signed-in principal's pending request.
func (s server) pendingConsent(w http.ResponseWriter, r *http.Request) error {
	var p pending
	havePending := s.Sessions.ReadSigned(r, pendingCookie, &p)
	principal, err := s.principal(r)
	if err != nil {
		return err
	}
	if !havePending || p.Principal == nil || principal != *p.Principal {
		return badRequest("invalid_request")
	}
	scopes := strings.Fields(p.Scope)
	client, err := s.resolver.Resolve(r.Context(), p.ClientID)
	if err != nil || client.validate(p.RedirectURI, scopes) != nil {
		return badRequest("invalid_client")
	}
	redirect, err := redirectURI(p.RedirectURI)
	if err != nil {
		return err
	}
	api.WriteJSON(w, http.StatusOK, struct {
		ClientName  string   `json:"clientName"`
		ClientID    string   `json:"clientId"`
		RedirectURI string   `json:"redirectUri"`
		Loopback    bool     `json:"loopback"`
		Scopes      []string `json:"scopes"`
		CSRF        string   `json:"csrf"`
	}{client.ClientName, client.ClientID, p.RedirectURI, loopbackHost(redirect.Hostname()), scopes, p.CSRF})
	return nil
}
