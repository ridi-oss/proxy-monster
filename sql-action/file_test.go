package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/alecthomas/kong"
)

type testRepo struct {
	t   *testing.T
	dir string
}

func gitRepo(t *testing.T) *testRepo {
	t.Helper()
	r := &testRepo{t: t, dir: t.TempDir()}
	r.git("init", "-q")
	return r
}

func (r *testRepo) git(args ...string) string {
	r.t.Helper()
	full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
		"-c", "init.defaultBranch=main"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *testRepo) write(files map[string]string) {
	r.t.Helper()
	for p, c := range files {
		full := filepath.Join(r.dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			r.t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
}

func (r *testRepo) commit(msg string) string {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "-q", "--allow-empty", "-m", msg)
	return r.git("rev-parse", "HEAD")
}

// branchRepo commits base files on main, branches, applies change on the branch, then advances main so only the
// branch's changes count. It returns the advanced main SHA and the branch head SHA.
func branchRepo(t *testing.T, baseFiles map[string]string, change func(r *testRepo)) (*testRepo, string, string) {
	t.Helper()
	r := gitRepo(t)
	r.write(baseFiles)
	r.commit("base")
	r.git("checkout", "-q", "-b", "feature")
	change(r)
	head := r.commit("change")
	r.git("checkout", "-q", "main")
	r.write(map[string]string{"db/orders/00099_main_only.sql": "select 99;", "other.txt": "x"})
	base := r.commit("main moves")
	return r, base, head
}

var sqlFilesRe = regexp.MustCompile(`\.sql$`)

var longSQL = strings.Repeat("insert into t values (1, 'a long enough line to keep the rename similar');\n", 10)

func filePaths(fs []fileInput) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Path)
	}
	return out
}

func TestAddedFiles(t *testing.T) {
	base := map[string]string{
		"db/orders/00001_init.sql":   "create table o(id int);",
		"db/orders/golden.sql":       "-- golden",
		"db/orders/old.sql":          "select 'old';",
		"db/users/00001_init.sql":    "create table u(id int);",
		"db/orders/sub/00001_x.sql":  "select 1;",
		"db/orders/README.md":        "readme",
		"db/orders/00002_second.sql": "select 2;",
		"db/orders/00004_long.sql":   longSQL,
		"db/staging/00005_long.sql":  longSQL,
	}
	cases := []struct {
		name     string
		dir      string
		re       *regexp.Regexp
		change   func(r *testRepo)
		want     []string
		wantKeys []string
		wantErr  string
	}{
		{
			name: "only direct children of dir",
			dir:  "db/orders",
			change: func(r *testRepo) {
				r.write(map[string]string{
					"db/orders/00010_a.sql":     "select 10;",
					"db/orders/sub/00011_b.sql": "select 11;",
					"db/users/00012_c.sql":      "select 12;",
					"db/orders/notes.txt":       "n",
				})
			},
			want: []string{"db/orders/00010_a.sql"},
		},
		{
			name: "files regex filters names",
			dir:  "./db/orders/",
			re:   regexp.MustCompile(`^[0-9]+_.+\.sql$`),
			change: func(r *testRepo) {
				r.write(map[string]string{
					"db/orders/00010_a.sql": "select 10;",
					"db/orders/init.sql":    "select 0;",
				})
			},
			want: []string{"db/orders/00010_a.sql"},
		},
		{
			name: "the key group is the file key",
			dir:  "db/orders",
			re:   regexp.MustCompile(`^(?P<key>[0-9]+)_.+\.sql$`),
			change: func(r *testRepo) {
				r.write(map[string]string{"db/orders/0010_b.sql": "b", "db/orders/9_a.sql": "a", "db/orders/init.sql": "i"})
			},
			want:     []string{"db/orders/0010_b.sql", "db/orders/9_a.sql"},
			wantKeys: []string{"0010", "9"},
		},
		{
			name: "without a key group the whole name is the key",
			dir:  "db/orders",
			re:   regexp.MustCompile(`^V[0-9]+_.+\.sql$`),
			change: func(r *testRepo) {
				r.write(map[string]string{"db/orders/V10_b.sql": "b"})
			},
			want:     []string{"db/orders/V10_b.sql"},
			wantKeys: []string{"V10_b.sql"},
		},
		{
			name: "sorted by path",
			dir:  "db/orders",
			change: func(r *testRepo) {
				r.write(map[string]string{"db/orders/00043_b.sql": "b", "db/orders/00042_a.sql": "a"})
			},
			want: []string{"db/orders/00042_a.sql", "db/orders/00043_b.sql"},
		},
		{
			name:    "modifying a merged file fails",
			dir:     "db/orders",
			change:  func(r *testRepo) { r.write(map[string]string{"db/orders/00001_init.sql": "drop table o;"}) },
			wantErr: "modified db/orders/00001_init.sql",
		},
		{
			name:    "deleting a merged file fails",
			dir:     "db/orders",
			change:  func(r *testRepo) { r.git("rm", "-q", "db/orders/00002_second.sql") },
			wantErr: "deleted db/orders/00002_second.sql",
		},
		{
			name:   "pure rename within dir passes",
			dir:    "db/orders",
			change: func(r *testRepo) { r.git("mv", "db/orders/old.sql", "db/orders/00003_old.sql") },
			want:   []string{},
		},
		{
			name: "renaming a file into dir with an edit fails",
			dir:  "db/orders",
			change: func(r *testRepo) {
				r.git("mv", "db/staging/00005_long.sql", "db/orders/00005_long.sql")
				r.write(map[string]string{"db/orders/00005_long.sql": longSQL + "select 'edit';\n"})
			},
			wantErr: "renamed and modified db/staging/00005_long.sql -> db/orders/00005_long.sql",
		},
		{
			name: "renaming a file within dir with an edit fails",
			dir:  "db/orders",
			change: func(r *testRepo) {
				r.git("mv", "db/orders/00004_long.sql", "db/orders/00006_long.sql")
				r.write(map[string]string{"db/orders/00006_long.sql": longSQL + "select 'edit';\n"})
			},
			wantErr: "renamed and modified db/orders/00004_long.sql -> db/orders/00006_long.sql",
		},
		{
			name: "renaming a file out of dir with an edit passes",
			dir:  "db/orders",
			change: func(r *testRepo) {
				r.git("mv", "db/orders/00004_long.sql", "db/staging/00004_long.sql")
				r.write(map[string]string{"db/staging/00004_long.sql": longSQL + "select 'edit';\n"})
			},
			want: []string{},
		},
		{
			name:   "directory move passes",
			dir:    "db/orders2",
			change: func(r *testRepo) { r.git("mv", "db/orders", "db/orders2") },
			want:   []string{},
		},
		{
			name:   "modifying a non-matching file passes",
			dir:    "db/orders",
			re:     regexp.MustCompile(`^[0-9]+_.+\.sql$`),
			change: func(r *testRepo) { r.write(map[string]string{"db/orders/golden.sql": "-- new golden"}) },
			want:   []string{},
		},
		{
			name:   "nothing added",
			dir:    "db/orders",
			change: func(r *testRepo) { r.write(map[string]string{"README.md": "docs"}) },
			want:   []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, baseSHA, head := branchRepo(t, base, tc.change)
			re := tc.re
			if re == nil {
				re = sqlFilesRe
			}
			got, err := addedFiles(context.Background(), r.dir, tc.dir, re, baseSHA, head)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) ||
					!strings.Contains(err.Error(), "files already merged must not change") {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got == nil {
				t.Fatal("got nil slice, want non-nil")
			}
			if g, w := strings.Join(filePaths(got), ","), strings.Join(tc.want, ","); g != w {
				t.Fatalf("got %q, want %q", g, w)
			}
			if tc.wantKeys != nil {
				keys := make([]string, 0, len(got))
				for _, f := range got {
					keys = append(keys, f.Key)
				}
				if g, w := strings.Join(keys, ","), strings.Join(tc.wantKeys, ","); g != w {
					t.Fatalf("keys %q, want %q", g, w)
				}
			}
		})
	}
}

func TestAddedFilesContentFromHead(t *testing.T) {
	r, base, head := branchRepo(t, map[string]string{"db/a/00001.sql": "x"}, func(r *testRepo) {
		r.write(map[string]string{"db/a/00002.sql": "select 2;\n"})
	})
	got, err := addedFiles(context.Background(), r.dir, "db/a", sqlFilesRe, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Content != "select 2;\n" {
		t.Fatalf("got %+v", got)
	}
}

func TestAddedFilesUnknownCommit(t *testing.T) {
	r, _, head := branchRepo(t, map[string]string{"a.sql": "x"}, func(r *testRepo) {})
	missing := "0123456789abcdef0123456789abcdef01234567"
	_, err := addedFiles(context.Background(), r.dir, "db", sqlFilesRe, missing, head)
	if err == nil || !strings.Contains(err.Error(), "fetch-depth: 0") || !strings.Contains(err.Error(), missing) {
		t.Fatalf("err = %v", err)
	}
}

func TestAddedFilesRejectsDirOutsideRepo(t *testing.T) {
	for _, d := range []string{"../x", "/etc", ".."} {
		if _, err := addedFiles(context.Background(), t.TempDir(), d, sqlFilesRe, "a", "b"); err == nil {
			t.Fatalf("dir %q: want error", d)
		}
	}
}

const (
	testJWT      = "eyJhbGciOiJSUzI1NiJ9.secret-jwt.sig"
	testOIDCAuth = "gh-request-token"
	testBearer   = "pmw_secret_workload_token"
)

type fakeSQLServer struct {
	srv          *httptest.Server
	mu           sync.Mutex
	requests     []map[string]any
	auth         []string
	requestsCode int
	requestsBody string
	audience     string
}

func newFakeSQLServer(t *testing.T) *fakeSQLServer {
	f := &fakeSQLServer{audience: "pm-ci"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oidc", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testOIDCAuth {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("audience") != f.audience || r.URL.Query().Get("api-version") != "2.0" {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": testJWT})
	})
	mux.HandleFunc("POST /api/workload/token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["token"] != testJWT {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"code":"auth.invalid_token","params":{}}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": testBearer, "id": "w1", "kind": "workload", "expiresAt": "2030-01-01T00:00:00Z"})
	})
	mux.HandleFunc("POST /api/github/requests", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.requests = append(f.requests, body)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		code, resp := f.requestsCode, f.requestsBody
		f.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			_, _ = io.WriteString(w, resp)
			return
		}
		files, _ := body["files"].([]any)
		reqs := []map[string]any{}
		for i, file := range files {
			reqs = append(reqs, map[string]any{"id": 101 + i, "status": "PENDING", "pullRequest": map[string]any{"path": file.(map[string]any)["path"]}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"requests": reqs})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSQLServer) env(gitDir string, out io.Writer) sqlEnv {
	vars := map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   f.srv.URL + "/oidc?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": testOIDCAuth,
	}
	return sqlEnv{getenv: func(k string) string { return vars[k] }, http: f.srv.Client(), out: out, gitDir: gitDir}
}

func assertNoSecrets(t *testing.T, texts ...string) {
	t.Helper()
	for _, s := range texts {
		for _, secret := range []string{testJWT, testBearer, testOIDCAuth, "pmw_"} {
			if strings.Contains(s, secret) {
				t.Fatalf("output leaks %q: %s", secret, s)
			}
		}
	}
}

func fileCmd(f *fakeSQLServer, base, head string) *sqlFileCmd {
	return &sqlFileCmd{
		sqlConn:    sqlConn{Server: f.srv.URL + "/", Audience: "pm-ci"},
		prRef:      prRef{Repository: "acme/shop", PR: 7},
		Dir:        "db/orders",
		Datasource: "shop-mysql",
		Schema:     "shop",
		Role:       "migrator",
		Files:      `\.sql$`,
		Order:      "string",
		Base:       base,
		Head:       head,
	}
}

func TestSQLFile(t *testing.T) {
	f := newFakeSQLServer(t)
	r, base, head := branchRepo(t, map[string]string{"db/orders/00001.sql": "x"}, func(r *testRepo) {
		r.write(map[string]string{"db/orders/00043_b.sql": "select 43;", "db/orders/00042_a.sql": "select 42;"})
	})
	var out bytes.Buffer
	c := fileCmd(f, base, "feature")
	c.Files, c.Order = `^(?P<key>[0-9]+)_.+\.sql$`, "numeric"
	if err := c.run(context.Background(), f.env(r.dir, &out)); err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 1 {
		t.Fatalf("requests = %d", len(f.requests))
	}
	body := f.requests[0]
	if len(head) != 40 || body["headSha"] != head {
		t.Fatalf("headSha = %v, want %q", body["headSha"], head)
	}
	if _, ok := body["pr"].(float64); !ok || body["pr"].(float64) != 7 {
		t.Fatalf("pr = %#v, want number 7", body["pr"])
	}
	if _, ok := body["scope"]; ok {
		t.Fatalf("scope present when unset: %v", body)
	}
	for k, v := range map[string]string{"repository": "acme/shop", "datasource": "shop-mysql", "schema": "shop", "role": "migrator", "order": "numeric"} {
		if body[k] != v {
			t.Fatalf("%s = %v, want %q", k, body[k], v)
		}
	}
	files := body["files"].([]any)
	if len(files) != 2 || files[0].(map[string]any)["path"] != "db/orders/00042_a.sql" ||
		files[0].(map[string]any)["key"] != "00042" || files[0].(map[string]any)["content"] != "select 42;" {
		t.Fatalf("files = %v", files)
	}
	if f.auth[0] != "Bearer "+testBearer {
		t.Fatal("requests call did not use the exchanged workload token")
	}
	want := "filed db/orders/00042_a.sql as request 101 (PENDING)\nfiled db/orders/00043_b.sql as request 102 (PENDING)\n"
	if out.String() != want {
		t.Fatalf("stdout = %q, want %q", out.String(), want)
	}
	assertNoSecrets(t, out.String())
}

func TestSQLFileScopeAndEmptyFiles(t *testing.T) {
	f := newFakeSQLServer(t)
	r, base, head := branchRepo(t, map[string]string{"db/orders/00001.sql": "x"}, func(r *testRepo) {})
	var out bytes.Buffer
	c := fileCmd(f, base, head)
	c.Scope = "release-1"
	if err := c.run(context.Background(), f.env(r.dir, &out)); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.requests[0]["files"])
	if string(raw) != "[]" {
		t.Fatalf("files = %s, want []", raw)
	}
	if f.requests[0]["scope"] != "release-1" {
		t.Fatalf("scope = %v", f.requests[0]["scope"])
	}
	if !strings.Contains(out.String(), "no new files in db/orders match") {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestSQLFileNoRequestsFiled(t *testing.T) {
	f := newFakeSQLServer(t)
	f.requestsCode, f.requestsBody = http.StatusOK, `{"requests":[]}`
	r, base, head := branchRepo(t, map[string]string{"db/orders/00001.sql": "x"}, func(r *testRepo) {
		r.write(map[string]string{"db/orders/00002.sql": "select 2;"})
	})
	var out bytes.Buffer
	if err := fileCmd(f, base, head).run(context.Background(), f.env(r.dir, &out)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "filed no requests") {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestSQLFileGitErrorBeforeAuth(t *testing.T) {
	f := newFakeSQLServer(t)
	r, base, head := branchRepo(t, map[string]string{"db/orders/00001.sql": "x"}, func(r *testRepo) {
		r.write(map[string]string{"db/orders/00001.sql": "y"})
	})
	err := fileCmd(f, base, head).run(context.Background(), f.env(r.dir, io.Discard))
	if err == nil || !strings.Contains(err.Error(), "modified db/orders/00001.sql") {
		t.Fatalf("err = %v", err)
	}
	if len(f.requests) != 0 || len(f.auth) != 0 {
		t.Fatal("contacted the control plane after a git check failed")
	}
}

func TestSQLFileValidation(t *testing.T) {
	f := newFakeSQLServer(t)
	for _, tc := range []struct {
		mut  func(c *sqlFileCmd)
		want string
	}{
		{func(c *sqlFileCmd) { c.Repository = "acme" }, "invalid --repository"},
		{func(c *sqlFileCmd) { c.Repository = "acme/shop/x" }, "invalid --repository"},
		{func(c *sqlFileCmd) { c.PR = 0 }, "invalid --pr"},
		{func(c *sqlFileCmd) { c.Files = "(" }, "invalid --files regex"},
	} {
		c := fileCmd(f, "a", "b")
		tc.mut(c)
		if err := c.run(context.Background(), f.env(t.TempDir(), io.Discard)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("err = %v, want %q", err, tc.want)
		}
	}
}

func TestSQLFileForbidden(t *testing.T) {
	f := newFakeSQLServer(t)
	f.requestsCode, f.requestsBody = http.StatusForbidden, `{"code":"common.forbidden","params":{}}`
	r, base, head := branchRepo(t, map[string]string{"db/orders/00001.sql": "x"}, func(r *testRepo) {
		r.write(map[string]string{"db/orders/00002.sql": "y"})
	})
	var out bytes.Buffer
	err := fileCmd(f, base, head).run(context.Background(), f.env(r.dir, &out))
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "common.forbidden") {
		t.Fatalf("err = %v", err)
	}
	assertNoSecrets(t, out.String(), err.Error())
}

func TestSQLNonJSONError(t *testing.T) {
	f := newFakeSQLServer(t)
	f.requestsCode, f.requestsBody = http.StatusBadGateway, "<html>"+strings.Repeat("x", 500)+"</html>"
	err := postJSON(context.Background(), f.env(".", io.Discard), f.srv.URL, "/api/github/requests", testBearer, map[string]any{}, nil)
	if err == nil || !strings.Contains(err.Error(), "502") || len(err.Error()) > 300 {
		t.Fatalf("err = %v", err)
	}
	assertNoSecrets(t, err.Error())
}

func TestSQLMissingOIDCEnv(t *testing.T) {
	f := newFakeSQLServer(t)
	r, base, head := branchRepo(t, map[string]string{"db/orders/00001.sql": "x"}, func(r *testRepo) {
		r.write(map[string]string{"db/orders/00002.sql": "y"})
	})
	env := f.env(r.dir, io.Discard)
	env.getenv = func(string) string { return "" }
	err := fileCmd(f, base, head).run(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Fatalf("err = %v", err)
	}
}

func TestSQLBadAudienceErrorNamesOnlyStatus(t *testing.T) {
	f := newFakeSQLServer(t)
	_, err := fetchOIDCToken(context.Background(), f.env(".", io.Discard), "wrong")
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("err = %v", err)
	}
	assertNoSecrets(t, err.Error())
}

func TestSQLAudienceDefaultsToServerOrigin(t *testing.T) {
	f := newFakeSQLServer(t)
	f.audience = f.srv.URL
	if _, err := authenticate(context.Background(), f.env(".", io.Discard), sqlConn{Server: f.srv.URL + "/"}); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestKongGrammar(t *testing.T) {
	t.Setenv("PM_CI_SERVER_URL", "https://pm.example.com")
	t.Setenv("PM_CI_AUDIENCE", "pm-ci")
	var r root
	p, err := kong.New(&r, kong.Vars{"version": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Parse([]string{"file", "--dir", "db", "--datasource", "d", "--schema", "s", "--role", "r",
		"--repository", "acme/shop", "--pr", "3", "--base", "a", "--head", "b"}); err != nil {
		t.Fatal(err)
	}
	c := r.File
	if c.Files != `^(?P<key>[0-9]+)_.+\.sql$` || c.Order != "numeric" || c.Server != "https://pm.example.com" || c.Audience != "pm-ci" || c.PR != 3 || c.Repository != "acme/shop" {
		t.Fatalf("parsed %+v", c)
	}
	if _, err := p.Parse([]string{"file", "--dir", "db", "--datasource", "d", "--schema", "s", "--role", "r",
		"--repository", "acme/shop", "--pr", "3", "--base", "a", "--head", "b", "--order", "string"}); err != nil || r.File.Order != "string" {
		t.Fatalf("--order string: %v, parsed %q", err, r.File.Order)
	}
	if _, err := p.Parse([]string{"file", "--dir", "db", "--datasource", "d", "--schema", "s", "--role", "r",
		"--repository", "acme/shop", "--pr", "3", "--base", "a", "--head", "b", "--order", "date"}); err == nil {
		t.Fatal("--order date parsed")
	}
}

func TestSQLFileLargeResponse(t *testing.T) {
	f := newFakeSQLServer(t)
	big := strings.Repeat("x", 100<<10)
	f.requestsCode = http.StatusOK
	f.requestsBody = `{"requests":[{"id":101,"status":"PENDING","pullRequest":{"path":"db/orders/00042_a.sql"},"sql":"` + big + `"}]}`
	r, base, head := branchRepo(t, map[string]string{"db/orders/00001.sql": "x"}, func(r *testRepo) {
		r.write(map[string]string{"db/orders/00042_a.sql": "select 42;"})
	})
	var out bytes.Buffer
	if err := fileCmd(f, base, head).run(context.Background(), f.env(r.dir, &out)); err != nil {
		t.Fatal(err)
	}
	if out.String() != "filed db/orders/00042_a.sql as request 101 (PENDING)\n" {
		t.Fatalf("stdout = %q", out.String())
	}
}
