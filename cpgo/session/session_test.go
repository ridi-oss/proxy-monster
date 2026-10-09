package session_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

func request(cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

func TestResolve(t *testing.T) {
	st := dbtest.Open(t)
	ctx := context.Background()
	res := session.NewResolver(st.Pool, dbtest.Secret)
	live := st.WebSession(t, "alice@example.com", "k-live", "dev-1")

	expired := st.WebSession(t, "bob@example.com", "k-expired", "dev-2")
	ended := st.WebSession(t, "carol@example.com", "k-ended", "dev-3")
	capped := st.WebSession(t, "dave@example.com", "k-capped", "dev-4")
	if _, err := st.Pool.Exec(ctx, `UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE session_key = 'k-capped'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE session_key = 'k-expired'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE principal_session SET ended_at = now(), ended_reason = 'SIGNED_OUT' WHERE session_key = 'k-ended'`); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		req       *http.Request
		principal string
		err       error
	}{
		{"live session", request(live...), "alice@example.com", nil},
		{"no cookie", request(), "", nil},
		{"wrong signing secret", request(dbtest.SessionCookie("k-live", "another-secret-of-enough-length!!"), live[1]), "", nil},
		{"unsigned tracker id", request(&http.Cookie{Name: "pm_session", Value: "k-live"}, live[1]), "", nil},
		{"idle deadline passed", request(expired...), "", nil},
		{"ended", request(ended...), "", nil},
		{"absolute cap passed", request(capped...), "", nil},
		{"URI-encoded device cookie", request(live[0], &http.Cookie{Name: "pm_did", Value: "%64ev-1"}), "alice@example.com", nil},
		{"other device", request(live[0], &http.Cookie{Name: "pm_did", Value: "dev-9"}), "", session.ErrDeviceMismatch},
		{"no device cookie", request(live[0]), "", session.ErrDeviceMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := res.Resolve(ctx, tc.req)
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			got := ""
			if w != nil {
				got = w.Principal
			}
			if got != tc.principal {
				t.Fatalf("principal = %q, want %q", got, tc.principal)
			}
		})
	}

	// Resolving never slides idle; only the heartbeat does.
	var before, after string
	q := `SELECT idle_expires_at::text FROM principal_session WHERE session_key = 'k-live'`
	_ = st.Pool.QueryRow(ctx, q).Scan(&before)
	if _, err := res.Resolve(ctx, request(live...)); err != nil {
		t.Fatal(err)
	}
	_ = st.Pool.QueryRow(ctx, q).Scan(&after)
	if before != after {
		t.Fatalf("idle moved from %s to %s", before, after)
	}
}
