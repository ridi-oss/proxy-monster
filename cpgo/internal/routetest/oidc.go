package routetest

import (
	"net/http"
	"strings"
)

func (b *Browser) NoFollow(method, path string) (*http.Response, string) {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.e.Srv.URL+path, nil)
	c := &http.Client{Jar: b.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 512)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, sb.String()
}
