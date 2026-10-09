package routes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDatasourceDetailAndWireCert(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	const chain = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	var gated, bare, other int64
	if err := e.st.Pool.QueryRow(ctx, `INSERT INTO datasource (name, host, port, db_name, advertise_addr, advertise_cert_chain)
		VALUES ('gated', 'h', 1, 'd', 'proxy:3306', $1) RETURNING id`, chain).Scan(&gated); err != nil {
		t.Fatal(err)
	}
	_ = e.st.Pool.QueryRow(ctx, `INSERT INTO datasource (name, host, port, db_name) VALUES ('bare', 'h', 1, 'd') RETURNING id`).Scan(&bare)
	_ = e.st.Pool.QueryRow(ctx, `INSERT INTO datasource (name, host, port, db_name, advertise_cert_chain) VALUES ('other', 'h', 1, 'd', $1) RETURNING id`, chain).Scan(&other)
	e.authz.allow = map[string]bool{
		fmt.Sprintf("connector@example.com datasource.connect %d", gated): true,
		fmt.Sprintf("connector@example.com datasource.connect %d", bare):  true,
	}
	connector := e.st.WebSession(t, "connector@example.com", "k-c", "dev-c")
	stranger := e.st.WebSession(t, "stranger@example.com", "k-s", "dev-s")
	const token = "wire-token-for-connector"
	sum := sha256.Sum256([]byte(token))
	if _, err := e.st.Pool.Exec(ctx, `INSERT INTO proxy_token (token_hash, principal, kind, expires_at) VALUES ($1, 'connector@example.com', 'USER', now() + interval '1 hour')`,
		hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	get := func(path string, cookies []*http.Cookie, bearer string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	expect := func(path string, cookies []*http.Cookie, bearer string, status int, body string) {
		t.Helper()
		resp, got := get(path, cookies, bearer)
		if resp.StatusCode != status || (body != "" && got != body) || (status != http.StatusOK && strings.Contains(got, "BEGIN CERTIFICATE")) {
			t.Fatalf("GET %s: %d %s, want %d %s", path, resp.StatusCode, got, status, body)
		}
	}
	row, cert := fmt.Sprintf("/api/datasources/%d", gated), fmt.Sprintf("/api/datasources/%d/wire-cert", gated)

	for _, path := range []string{row, cert} {
		expect(path, nil, "", http.StatusUnauthorized, `{"code":"common.unauthenticated","params":{}}`)
		expect(path, stranger, "", http.StatusForbidden, `{"code":"datasource.not_connectable","params":{}}`)
	}
	for _, path := range []string{fmt.Sprintf("/api/datasources/%d", other), fmt.Sprintf("/api/datasources/%d/wire-cert", other)} {
		expect(path, connector, "", http.StatusForbidden, `{"code":"datasource.not_connectable","params":{}}`)
		expect(path, nil, token, http.StatusForbidden, `{"code":"datasource.not_connectable","params":{}}`)
	}
	expect("/api/datasources/999999", connector, "", http.StatusNotFound, `{"code":"common.not_found","params":{"resource":"datasource"}}`)
	expect("/api/datasources/x", connector, "", http.StatusBadRequest, `{"code":"common.bad_id","params":{}}`)
	expect(fmt.Sprintf("/api/datasources/%d/wire-cert", bare), connector, "", http.StatusNotFound, `{"code":"datasource.no_wire_cert","params":{}}`)

	for _, c := range []struct {
		cookies []*http.Cookie
		bearer  string
	}{{connector, ""}, {nil, token}} {
		if _, body := get(row, c.cookies, c.bearer); !strings.Contains(body, `"advertiseAddr":"proxy:3306","advertiseCertChain":"-----BEGIN CERTIFICATE-----\nMIIB`) {
			t.Fatalf("row %s", body)
		}
		resp, body := get(cert, c.cookies, c.bearer)
		if resp.StatusCode != http.StatusOK || body != chain || resp.Header.Get("Content-Type") != "application/x-pem-file" ||
			resp.Header.Get("Content-Disposition") != fmt.Sprintf(`attachment; filename="datasource-%d-wire-cert.pem"`, gated) {
			t.Fatalf("wire cert: %d %v %q", resp.StatusCode, resp.Header, body)
		}
	}
}
