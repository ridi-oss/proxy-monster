package datasources_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestDatasourceList(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	var open, closed int64
	if err := e.St.Pool.QueryRow(ctx, `INSERT INTO datasource (name, engine, host, port, db_name, tags, advertise_addr, connection_info, description)
		VALUES ('acme', 'mysql', 'db', 3306, 'acme', '["pii"]', 'proxy:6033', '{"properties": {"tls": "on", "aa": "b", "z": "c"}, "endpoint": "proxy:6033"}', 'orders')
		RETURNING id`).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if err := e.St.Pool.QueryRow(ctx, `INSERT INTO datasource (name, engine, host, port, db_name, description,
		advertise_addr, advertise_cert_chain, current_catalog_name, connection_info)
		VALUES ('lake', 'athena', 'athena', 443, 'lake', 'secret lake', 'lake-proxy:443', 'BEGIN CERTIFICATE lake', 'AwsDataCatalog',
		'{"endpoint": "lake-proxy:443", "properties": {}}') RETURNING id`).Scan(&closed); err != nil {
		t.Fatal(err)
	}
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO datasource (name, host, port, db_name, deleted_at) VALUES ('gone', 'h', 1, 'd', now())`); err != nil {
		t.Fatal(err)
	}
	alice := e.St.WebSession(t, "alice@example.com", "k-a", "dev-a")
	e.Authz.Allow = map[string]bool{fmt.Sprintf("alice@example.com datasource.connect %d", open): true}

	status, body := e.Do(t, http.MethodGet, "/api/datasources", "", alice)
	want := fmt.Sprintf(`[{"id":%d,"name":"acme","engine":"mysql","host":"db","port":3306,"dbName":"acme","tags":["pii"],"defaultSchemas":[],`+
		`"advertiseAddr":"proxy:6033","advertiseWireTls":false,"connectionInfo":{"endpoint":"proxy:6033","properties":{"z":"c","aa":"b","tls":"on"}},"description":"orders","defaultSchemaSettable":true},`+
		`{"id":%d,"name":"lake","engine":"athena","host":"","port":0,"dbName":"","tags":[],"defaultSchemas":[],"advertiseWireTls":false,"description":"","defaultSchemaSettable":false}]`, open, closed)
	if status != http.StatusOK || body != want {
		t.Fatalf("list:\n got %s\nwant %s", body, want)
	}
	if _, body = e.Do(t, http.MethodGet, "/api/datasources?connectable=TRUE", "", alice); strings.Count(body, `"id"`) != 1 || strings.Contains(body, "lake") {
		t.Fatalf("connectable only: %s", body)
	}

	// A session wins over a bearer, and a wrong-device session falls through to the bearer, as in Kotlin.
	carolSum := sha256.Sum256([]byte("carol-token"))
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO proxy_token (token_hash, principal, kind, expires_at) VALUES ($1, 'carol@example.com', 'USER', now() + interval '1 hour')`,
		hex.EncodeToString(carolSum[:])); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cookies []*http.Cookie
		want    string
	}{
		{alice, "alice@example.com"},
		{[]*http.Cookie{alice[0], {Name: "pm_did", Value: "stolen"}}, "carol@example.com"},
	} {
		e.Authz.Asked = nil
		req, _ := http.NewRequest(http.MethodGet, e.Srv.URL+"/api/datasources", nil)
		req.Header.Set("Authorization", "Bearer carol-token")
		for _, c := range tc.cookies {
			req.AddCookie(c)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(e.Authz.Asked[0], tc.want+" ") {
			t.Fatalf("want %s: %d asked %v", tc.want, resp.StatusCode, e.Authz.Asked)
		}
	}
	if len(e.Ended) != 1 {
		t.Fatalf("the wrong-device session must still be ended: %v", e.Ended)
	}
	alice = e.St.WebSession(t, "alice@example.com", "k-a2", "dev-a")

	var token = "wire-token-for-bob"
	sum := sha256.Sum256([]byte(token))
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO proxy_token (token_hash, principal, kind, expires_at) VALUES ($1, 'bob@example.com', 'SESSION', now() + interval '1 hour')`,
		hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	e.Authz.Asked = nil
	req, _ := http.NewRequest(http.MethodGet, e.Srv.URL+"/api/datasources", nil)
	req.Header.Set("Authorization", "bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(e.Authz.Asked) != 2 || !strings.HasPrefix(e.Authz.Asked[0], "bob@example.com datasource.connect") ||
		!strings.HasSuffix(e.Authz.Asked[0], " @127.0.0.1") {
		t.Fatalf("pmon bearer: %d asked %v", resp.StatusCode, e.Authz.Asked)
	}
	for _, tc := range []struct{ token, kind, extra string }{
		{"editor-token", "EDITOR", ""},
		{"retired-token", "SESSION", ", retired_at = now()"},
		{"revoked-token", "SESSION", ", revoked_at = now()"},
		{"expired-token", "USER", ", expires_at = now() - interval '1 second'"},
	} {
		sum := sha256.Sum256([]byte(tc.token))
		if _, err := e.St.Pool.Exec(ctx, `INSERT INTO proxy_token (token_hash, principal, kind, expires_at) VALUES ($1, 'carol@example.com', $2, now() + interval '1 hour')`,
			hex.EncodeToString(sum[:]), tc.kind); err != nil {
			t.Fatal(err)
		}
		if tc.extra != "" {
			if _, err := e.St.Pool.Exec(ctx, `UPDATE proxy_token SET principal = principal`+tc.extra+` WHERE token_hash = $1`, hex.EncodeToString(sum[:])); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tok := range []string{"editor-token", "retired-token", "revoked-token", "expired-token", "pmk_not-a-real-token"} {
		r, _ := http.NewRequest(http.MethodGet, e.Srv.URL+"/api/datasources", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bearer %s: %d, want 401", tok, resp.StatusCode)
		}
	}
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO app_user (principal, active) VALUES ('bob@example.com', false)`); err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a deactivated principal's wire token: %d", resp.StatusCode)
	}
}
