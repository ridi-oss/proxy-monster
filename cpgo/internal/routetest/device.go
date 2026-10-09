package routetest

import (
	"encoding/json"
	"net/http"
	"net/url"
)

type startResponse struct {
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	UserCode                string `json:"userCode"`
	Handle                  string `json:"handle"`
	Interval                int    `json:"interval"`
}

func (b *Browser) StartDevice(body string) startResponse {
	b.t.Helper()
	resp, out := b.Do(http.MethodPost, "/auth/device/start", body)
	var s startResponse
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &s) != nil {
		b.t.Fatalf("start: %d %s", resp.StatusCode, out)
	}
	return s
}

// AuthorizeDevice answers where /auth/device/authorize sent the browser.
func (b *Browser) AuthorizeDevice(userCode string) string {
	b.t.Helper()
	resp, body := b.NoFollow(http.MethodGet, "/auth/device/authorize?user_code="+url.QueryEscape(userCode))
	if resp.StatusCode != http.StatusFound || body != "" {
		b.t.Fatalf("authorize: %d %q", resp.StatusCode, body)
	}
	return resp.Header.Get("Location")
}

func (b *Browser) Bearer(path, secret string) (*http.Response, string) {
	b.t.Helper()
	return b.Do(http.MethodPost, path, "", "Authorization", "Bearer "+secret)
}
