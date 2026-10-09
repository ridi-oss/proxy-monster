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

	ok, _, err := New(u, "tok").Authorize(context.Background(), "alice", "audit.read", AuditRecord("bob"), "203.0.113.9")
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

	if _, _, err := New(u, "wrong").Authorize(context.Background(), "alice", "audit.read", AuditLog, ""); err == nil {
		t.Fatal("a rejected token must be an error, not a deny")
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestAuthorizeDenyCarriesCedarsReason(t *testing.T) {
	kotlin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"allow":false,"reason":"no policy permits this action"}`))
	}))
	defer kotlin.Close()
	u, _ := url.Parse(kotlin.URL)
	ok, reason, err := New(u, "tok").Authorize(context.Background(), "alice", "admin.policies", System, "")
	if err != nil || ok || reason != "no policy permits this action" {
		t.Fatalf("allow %v reason %q err %v", ok, reason, err)
	}
}

func TestAuthorizeEach(t *testing.T) {
	var got struct {
		Principal, Action string
		Resources         []Resource
	}
	kotlin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/authorize-batch" || r.Header.Get(TokenHeader) != "tok" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		if len(got.Resources) == 3 {
			_, _ = w.Write([]byte(`{"allow":[true,false,true]}`))
		} else {
			_, _ = w.Write([]byte(`{"allow":[true]}`))
		}
	}))
	defer kotlin.Close()
	u, _ := url.Parse(kotlin.URL)
	c := New(u, "tok")
	role := "jit"
	res := []Resource{{Type: "AccessGrant", Principal: "a", ID: 1, RoleName: &role}, AuditLog, System}

	allow, err := c.AuthorizeEach(context.Background(), "alice", "task.read", res, "")
	if err != nil || len(allow) != 3 || !allow[0] || allow[1] || !allow[2] {
		t.Fatalf("allow %v err %v", allow, err)
	}
	if got.Principal != "alice" || got.Action != "task.read" || got.Resources[0].ID != 1 || *got.Resources[0].RoleName != "jit" {
		t.Fatalf("sent %+v", got)
	}
	if _, err := c.AuthorizeEach(context.Background(), "alice", "task.read", res[:2], ""); err == nil {
		t.Fatal("a decision count that does not match the resources must be an error")
	}
	if allow, err := c.AuthorizeEach(context.Background(), "alice", "task.read", nil, ""); err != nil || allow != nil {
		t.Fatalf("no resources makes no call: %v %v", allow, err)
	}
}

func TestMayConnect(t *testing.T) {
	var got struct {
		Principal     string
		DatasourceIDs []int64
		RequesterIP   string
	}
	kotlin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/may-connect" || r.Header.Get(TokenHeader) != "tok" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"allow":[false,true]}`))
	}))
	defer kotlin.Close()
	u, _ := url.Parse(kotlin.URL)
	allow, err := New(u, "tok").MayConnect(context.Background(), "alice", []int64{7, 9}, "203.0.113.4")
	if err != nil || len(allow) != 2 || allow[0] || !allow[1] {
		t.Fatalf("allow %v err %v", allow, err)
	}
	if got.Principal != "alice" || len(got.DatasourceIDs) != 2 || got.DatasourceIDs[1] != 9 || got.RequesterIP != "203.0.113.4" {
		t.Fatalf("sent %+v", got)
	}
}

func TestValidateAndPoliciesChanged(t *testing.T) {
	var paths []string
	kotlin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(TokenHeader) != "tok" {
			http.NotFound(w, r)
			return
		}
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/internal/cedar-validate":
			_, _ = w.Write([]byte(`{"valid":false,"errors":["bad action"]}`))
		case "/internal/policies-changed":
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer kotlin.Close()
	u, _ := url.Parse(kotlin.URL)
	c := New(u, "tok")
	errs, err := c.Validate(context.Background(), "permit(...)")
	if err != nil || len(errs) != 1 || errs[0] != "bad action" {
		t.Fatalf("validate %v %v", errs, err)
	}
	if err := c.PoliciesChanged(context.Background()); err != nil {
		t.Fatalf("a 204 is a delivered signal: %v", err)
	}
	if err := New(u, "wrong").PoliciesChanged(context.Background()); err == nil {
		t.Fatal("a rejected signal must be an error")
	}
	if len(paths) != 2 {
		t.Fatalf("paths %v", paths)
	}
}
