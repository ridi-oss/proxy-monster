package github

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const appID = "12345"

const rate = `{"remaining":4999,"resetAt":"2026-10-09T01:00:00Z"}`

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func pkcs8PEM() string {
	der, _ := x509.MarshalPKCS8PrivateKey(testKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func pkcs1PEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)}))
}

type request struct {
	method, path string
	query        url.Values
	header       http.Header
	body         []byte
}

func (r request) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("request body %q: %v", r.body, err)
	}
	return m
}

type reply struct {
	status int
	body   string
	header map[string]string
	link   string // path and query of the next page
}

type responder func(r request) reply

func ok(body string) responder { return func(request) reply { return reply{status: 200, body: body} } }

func status(code int, body string) responder {
	return func(request) reply { return reply{status: code, body: body} }
}

// fakeGitHub serves GitHub's REST and GraphQL APIs with the App installation routes for `acme` already set.
// A route given several responders answers them in order, then repeats the last.
type fakeGitHub struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	routes   map[string][]responder
	requests []request
	serial   int
	now      time.Time
	tokenTTL time.Duration
}

func newFake(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{t: t, routes: map[string][]responder{}, now: time.Now().UTC(), tokenTTL: time.Hour}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	f.on("GET", "/repos/acme/shop/installation", ok(`{"id":42}`))
	f.on("GET", "/orgs/acme/installation", ok(`{"id":42}`))
	f.on("POST", "/app/installations/42/access_tokens", func(request) reply {
		f.serial++
		return reply{status: 201, body: fmt.Sprintf(`{"token":"ghs_token%d","expires_at":%q}`, f.serial, time.Now().Add(f.tokenTTL).UTC().Format(time.RFC3339))}
	})
	return f
}

func (f *fakeGitHub) on(method, path string, rs ...responder) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[method+" "+path] = rs
}

func (f *fakeGitHub) graphql(rs ...responder) { f.on("POST", "/graphql", rs...) }

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	req := request{method: r.Method, path: r.URL.EscapedPath(), query: r.URL.Query(), header: r.Header.Clone(), body: body}
	f.mu.Lock()
	f.requests = append(f.requests, req)
	key := r.Method + " " + req.path
	rs, found := f.routes[key]
	var rp responder
	if found {
		rp = rs[0]
		if len(rs) > 1 {
			f.routes[key] = rs[1:]
		}
	}
	f.mu.Unlock()
	if !found {
		f.t.Errorf("unrouted %s", key)
		http.Error(w, "unrouted", 500)
		return
	}
	out := rp(req)
	if out.link != "" {
		w.Header().Set("Link", "<"+f.srv.URL+out.link+`>; rel="next"`)
	}
	for k, v := range out.header {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(out.status)
	_, _ = io.WriteString(w, out.body)
}

func (f *fakeGitHub) to(method, path string) []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []request
	for _, r := range f.requests {
		if r.method == method && r.path == path {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeGitHub) clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = nil
}

func (f *fakeGitHub) client(t *testing.T) *Client {
	t.Helper()
	return f.clientAt(t, f.srv.URL, pkcs8PEM())
}

func (f *fakeGitHub) clientAt(t *testing.T, apiURL, key string) *Client {
	t.Helper()
	s, err := NewPEMSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(appID, apiURL, s)
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return f.now }
	return c
}

func prResponse(prs ...string) string {
	parts := make([]string, len(prs))
	for i, p := range prs {
		parts[i] = fmt.Sprintf(`"pr%d":%s`, i, p)
	}
	return `{"data":{"rateLimit":` + rate + `,"repository":{` + strings.Join(parts, ",") + `}}}`
}

const defaultChecks = `{"__typename":"CheckRun","name":"build","status":"COMPLETED","conclusion":"SUCCESS","isRequired":true,"checkSuite":{"app":{"databaseId":777}}},
  {"__typename":"CheckRun","name":"pm/query executed","status":"IN_PROGRESS","conclusion":null,"isRequired":true,"checkSuite":{"app":{"databaseId":12345}}},
  {"__typename":"StatusContext","context":"ci/legacy","state":"PENDING","isRequired":false}`

type prOpts struct {
	rollupOID   string
	filesNext   string
	threadsNext string
	checksNext  string
	checks      *string // nil: the default checks; pointer to "null": no rollup
}

func nextCursor(c string) string {
	if c == "" {
		return "null"
	}
	return `"` + c + `"`
}

// pr is an open PR as GraphQL returns it.
func pr(number int, o prOpts) string {
	if o.rollupOID == "" {
		o.rollupOID = "sha1"
	}
	checks := defaultChecks
	if o.checks != nil {
		checks = *o.checks
	}
	rollup := "null"
	if checks != "null" {
		rollup = fmt.Sprintf(`{"contexts":{"pageInfo":{"hasNextPage":%t,"endCursor":%s},"nodes":[%s]}}`, o.checksNext != "", nextCursor(o.checksNext), checks)
	}
	return fmt.Sprintf(`{"state":"OPEN","merged":false,"mergedAt":null,"mergeCommit":null,"headRefOid":"sha1","baseRefName":"main",
  "author":{"login":"alice","databaseId":101},
  "autoMergeRequest":{"enabledAt":"2026-10-09T00:10:00Z","enabledBy":{"login":"alice","databaseId":101},"mergeMethod":"SQUASH"},
  "isDraft":true,"mergeable":"MERGEABLE","canBeRebased":true,"mergeStateStatus":"BLOCKED","reviewDecision":"REVIEW_REQUIRED",
  "reviewThreads":{"pageInfo":{"hasNextPage":%t,"endCursor":%s},"nodes":[{"isResolved":true},{"isResolved":false},{"isResolved":false}]},
  "reviews":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[
    {"databaseId":501,"state":"APPROVED","submittedAt":"2026-10-09T00:20:00Z","url":"https://github.com/acme/shop/pull/1#r501","commit":{"oid":"sha1"},"author":{"login":"bob","databaseId":102}},
    {"databaseId":502,"state":"DISMISSED","submittedAt":"2026-10-09T00:05:00Z","url":"https://github.com/acme/shop/pull/1#r502","author":{"login":"carol","databaseId":103}}]},
  "files":{"pageInfo":{"hasNextPage":%t,"endCursor":%s},"nodes":[
    {"path":"sql/old.sql","changeType":"DELETED"},{"path":"sql/new.sql","changeType":"ADDED"}]},
  "commits":{"nodes":[{"commit":{"oid":%q,"statusCheckRollup":%s}}]},
  "authors":{"nodes":[
    {"commit":{"parents":{"totalCount":1},"author":{"email":"alice@acme.com","user":{"databaseId":101}}}},
    {"commit":{"parents":{"totalCount":1},"author":{"email":" alice@acme.com","user":{"databaseId":101}}}},
    {"commit":{"parents":{"totalCount":1},"author":null}},
    {"commit":{"parents":{"totalCount":1},"author":{"email":"bob@acme.com","user":{"databaseId":102}}}},
    {"commit":{"parents":{"totalCount":2},"author":{"email":"merge@acme.com","user":{"databaseId":101}}}},
    {"commit":{"parents":{"totalCount":1},"author":{"email":"nouser@acme.com","user":null}}}]}}`,
		o.threadsNext != "", nextCursor(o.threadsNext), o.filesNext != "", nextCursor(o.filesNext), o.rollupOID, rollup)
}

func merged(number int) string {
	return fmt.Sprintf(`{"state":"MERGED","merged":true,"mergedAt":"2026-10-08T12:00:00Z","mergeCommit":{"oid":"merge%d"},
  "mergedBy":{"login":"dave","databaseId":104},"headRefOid":"sha2","baseRefName":"main","author":null,"autoMergeRequest":null,
  "isDraft":false,"mergeable":"UNKNOWN","canBeRebased":false,"mergeStateStatus":"UNKNOWN","reviewDecision":null,"reviewThreads":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]},
  "reviews":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]},"files":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]},
  "commits":{"nodes":[{"commit":{"oid":"sha2","statusCheckRollup":null}}]},"authors":{"nodes":[]}}`, number)
}
