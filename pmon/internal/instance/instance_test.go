package instance

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/instance":
			_, _ = w.Write([]byte(`{"name":"hr-pmon","version":"0.1.31","mcpUrl":"https://hr/mcp","installName":"pmon-hr-pmon"}`))
		case "/old/api/instance":
			http.NotFound(w, r)
		case "/redirect/api/instance":
			http.Redirect(w, r, "/api/instance", http.StatusFound)
		}
	}))
	defer srv.Close()
	if info, err := Fetch(context.Background(), srv.URL+"/"); err != nil || info.Name != "hr-pmon" || info.Version != "0.1.31" {
		t.Errorf("Fetch = %+v, %v", info, err)
	}
	if _, err := Fetch(context.Background(), srv.URL+"/old"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("an older server: %v", err)
	}
	if _, err := Fetch(context.Background(), srv.URL+"/redirect"); err == nil {
		t.Error("followed a redirect")
	}
}
