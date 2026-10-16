package routetest

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

type Browser struct {
	t   *testing.T
	e   *Env
	Jar *cookiejar.Jar
}

func (e *Env) Browser(t *testing.T) *Browser {
	jar, _ := cookiejar.New(nil)
	return &Browser{t, e, jar}
}

func (b *Browser) Do(method, path, body string, header ...string) (*http.Response, string) {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.e.Srv.URL+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := (&http.Client{Jar: b.Jar}).Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, string(out)
}

func (b *Browser) Expect(method, path, body string, status int, want string) *http.Response {
	b.t.Helper()
	resp, got := b.Do(method, path, body)
	if resp.StatusCode != status || (want != "" && got != want) {
		b.t.Fatalf("%s %s: %d %s, want %d %s", method, path, resp.StatusCode, got, status, want)
	}
	return resp
}

func (b *Browser) SetDevice(device string) {
	u, _ := url.Parse(b.e.Srv.URL)
	b.Jar.SetCookies(u, []*http.Cookie{{Name: "pm_did", Value: device, Path: "/"}})
}
