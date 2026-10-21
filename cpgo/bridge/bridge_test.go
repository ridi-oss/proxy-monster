package bridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestPoliciesChanged(t *testing.T) {
	var paths []string
	kotlin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(TokenHeader) != "tok" {
			http.NotFound(w, r)
			return
		}
		paths = append(paths, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer kotlin.Close()
	u, _ := url.Parse(kotlin.URL)
	if err := New(u, "tok").PoliciesChanged(context.Background()); err != nil {
		t.Fatalf("a 204 is a delivered signal: %v", err)
	}
	if err := New(u, "wrong").PoliciesChanged(context.Background()); err == nil {
		t.Fatal("a rejected signal must be an error")
	}
	if len(paths) != 1 || paths[0] != "/internal/policies-changed" {
		t.Fatalf("paths %v", paths)
	}
}
