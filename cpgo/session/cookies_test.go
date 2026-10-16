package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadSignedRefusesAnotherCookiesValue(t *testing.T) {
	r := NewResolver(nil, Settings{Secret: "s"})
	w := httptest.NewRecorder()
	if err := r.SetSigned(w, "pm_oauth_state", struct {
		State string `json:"state"`
	}{"st"}, 300); err != nil {
		t.Fatal(err)
	}
	value := w.Result().Cookies()[0].Value
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "pm_oauth_state", Value: value})
	req.AddCookie(&http.Cookie{Name: "pm_oauth_nonce", Value: value})

	var state struct {
		State string `json:"state"`
	}
	if !r.ReadSigned(req, "pm_oauth_state", &state) || state.State != "st" {
		t.Fatalf("own cookie: %+v", state)
	}
	var nonce struct {
		Nonce string `json:"nonce"`
	}
	if r.ReadSigned(req, "pm_oauth_nonce", &nonce) {
		t.Fatal("a state cookie's value read as a nonce cookie")
	}
}
