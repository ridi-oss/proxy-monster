package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAuthorize(t *testing.T) {
	var got map[string]any
	kotlin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/authorize" || r.Header.Get(TokenHeader) != "tok" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"allow":true}`))
	}))
	defer kotlin.Close()
	u, _ := url.Parse(kotlin.URL)

	ok, err := New(u, "tok").Authorize(context.Background(), "alice", "audit.read", AuditRecord("bob"), "203.0.113.9")
	if err != nil || !ok {
		t.Fatalf("allow %v err %v", ok, err)
	}
	want := map[string]any{
		"principal": "alice", "action": "audit.read", "requesterIp": "203.0.113.9",
		"resource": map[string]any{"type": "AuditRecord", "principal": "bob"},
	}
	if b1, _ := json.Marshal(got); string(b1) != mustJSON(want) {
		t.Fatalf("sent %s", b1)
	}

	if _, err := New(u, "wrong").Authorize(context.Background(), "alice", "audit.read", AuditLog, ""); err == nil {
		t.Fatal("a rejected token must be an error, not a deny")
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
