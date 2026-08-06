//go:build differential

// The differential run. Build-tagged because it needs the KOTLIN control-plane's installDist, which is
// a Gradle build the ordinary `go test ./...` must not depend on.
//
//	cd proxy-monster && ./gradlew :control-plane:installDist        # once
//	cd gocp && go test -tags differential ./internal/conformance/differential/ -v
//
// Both control-planes read the same env vars (PM_HTTP_PORT / PM_DB_URL / …), which is what makes them
// drop-in swappable here — a fact worth stating because it is also what makes the comparison fair: the
// harness changes nothing but which binary is listening.
package differential

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
)

// plane is one running control-plane, reachable over HTTP.
type plane struct {
	name    string
	baseURL string
	client  *http.Client
	// cookies is the debug-login jar, populated by login().
	cookies []*http.Cookie
}

// response is what the harness compares.
type response struct {
	status int
	body   string
	// contentType is compared too: a plane answering text/plain where the other answers
	// application/json is a divergence the body diff alone can miss when both are empty.
	contentType string
}

func (p *plane) do(t *testing.T, c Case) response {
	t.Helper()
	var body io.Reader
	if c.Body != "" {
		body = strings.NewReader(c.Body)
	}
	req, err := http.NewRequest(c.Method, p.baseURL+c.Path, body)
	if err != nil {
		t.Fatalf("[%s] build %s %s: %v", p.name, c.Method, c.Path, err)
	}
	if c.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Authed {
		for _, ck := range p.cookies {
			req.AddCookie(ck)
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatalf("[%s] %s %s: %v", p.name, c.Method, c.Path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("[%s] read body: %v", p.name, err)
	}
	return response{
		status:      resp.StatusCode,
		body:        string(raw),
		contentType: strings.Split(resp.Header.Get("Content-Type"), ";")[0],
	}
}

// login performs the authDebug login and keeps the session cookies.
//
// 🔒 IT MUST SUCCEED ON BOTH, and identically. If one plane's login failed the authed half of the corpus
// would silently compare two 401s and report zero divergences — the exact false-green this harness has to
// avoid — so the status is asserted rather than assumed.
func (p *plane) login(t *testing.T) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, p.baseURL+"/auth/debug",
		strings.NewReader(`{"principal":"diff-admin@example.com","roles":["system:admin"]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatalf("[%s] debug login: %v", p.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("[%s] debug login = %d, want 200 (%s) — the authed corpus would compare two 401s",
			p.name, resp.StatusCode, raw)
	}
	p.cookies = resp.Cookies()
	if len(p.cookies) == 0 {
		t.Fatalf("[%s] debug login set no cookies; the authed corpus would run unauthenticated", p.name)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitHealthy(t *testing.T, name, baseURL string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("[%s] never became healthy at %s", name, baseURL)
}

// bootPlane starts one control-plane subprocess against its own fresh database.
//
// ⚠️ SEPARATE DATABASES, NOT A SHARED ONE. Both planes WRITE — sessions, audit chain rows, the write
// corpus — so a shared store would have each plane observing the other's effects and the diff would be
// meaningless. The migrations are identical, so a freshly-migrated pair is the closest thing to the same
// starting state that two writers can have.
func bootPlane(t *testing.T, name, bin string, extraEnv []string) *plane {
	t.Helper()
	backend := dbtest.Postgres(t)
	dbName := dbtest.FreshPostgresDatabase(t, "diff_"+name)
	httpPort := freePort(t)

	// ⚠️ THE JDBC URL CARRIES NO CREDENTIALS (dbtest.Backend.PostgresJDBCURL builds a bare
	// jdbc:postgresql://host:port/db), so both planes need PM_DB_USER / PM_DB_PASSWORD explicitly —
	// the in-process Go tests get them via credsFromJDBC instead. Reading them off the DSN keeps the
	// image's credentials in one place rather than hardcoded here.
	user, pass := credsFromDSN(t, backend.PostgresDSN(dbName))

	env := append(os.Environ(),
		"PM_DB_USER="+user,
		"PM_DB_PASSWORD="+pass,
		"PM_HTTP_PORT="+fmt.Sprint(httpPort),
		"PM_GRPC_PORT="+fmt.Sprint(freePort(t)),
		"PM_DB_URL="+backend.PostgresJDBCURL(dbName),
		// PM_DEV keeps authDebug legal (validation rule V5 permits it only in a non-production-looking
		// context), which is what lets the corpus log in without an IdP.
		"PM_DEV=true",
	)
	env = append(env, extraEnv...)

	logPath := filepath.Join(t.TempDir(), name+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s (%s): %v", name, bin, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		logFile.Close()
		if t.Failed() {
			if raw, err := os.ReadFile(logPath); err == nil {
				t.Logf("--- %s log (tail) ---\n%s", name, tail(string(raw), 3000))
			}
		}
	})

	base := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
	waitHealthy(t, name, base, 90*time.Second)
	return &plane{
		name: name, baseURL: base,
		// No redirect following: a 302 vs a 200 is a divergence, not something to resolve away.
		client: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// credsFromDSN pulls user/password out of the container DSN dbtest already built.
func credsFromDSN(t *testing.T, dsn string) (string, string) {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse container DSN: %v", err)
	}
	pass, _ := u.User.Password()
	if u.User.Username() == "" {
		t.Fatalf("container DSN %q carries no user; both planes need PM_DB_USER", dsn)
	}
	return u.User.Username(), pass
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// canonical applies Normalize plus, for cases whose array order is NOT contractual, SortArrays.
func canonical(c Case, r response) string {
	norm := Normalize(r.body)
	if _, sensitive := OrderSensitive[c.Name]; sensitive {
		return norm
	}
	var v any
	if err := json.Unmarshal([]byte(norm), &v); err != nil {
		return norm
	}
	out, err := json.Marshal(SortArrays(v))
	if err != nil {
		return norm
	}
	return string(out)
}

// TestDifferential is the run.
func TestDifferential(t *testing.T) {
	goBin := os.Getenv("PM_DIFF_GO_BIN")
	ktBin := os.Getenv("PM_DIFF_KOTLIN_BIN")
	if goBin == "" || ktBin == "" {
		t.Fatal("set PM_DIFF_GO_BIN (a built gocp binary) and PM_DIFF_KOTLIN_BIN " +
			"(control-plane/build/install/control-plane/bin/control-plane)")
	}

	kt := bootPlane(t, "kotlin", ktBin, nil)
	gp := bootPlane(t, "go", goBin, nil)
	kt.login(t)
	gp.login(t)

	corpus := All()
	var diverged, agreed int
	for _, c := range corpus {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			ktResp := kt.do(t, c)
			goResp := gp.do(t, c)

			ktBody, goBody := canonical(c, ktResp), canonical(c, goResp)
			same := ktResp.status == goResp.status &&
				ktResp.contentType == goResp.contentType &&
				ktBody == goBody

			// A case flagged WantDivergence must ACTUALLY diverge: a documented difference that has been
			// fixed must not stay documented, or the list rots into fiction.
			if c.WantDivergence != "" {
				if same {
					t.Errorf("this case is recorded as a KNOWN DIVERGENCE (%s) but the two planes now AGREE — "+
						"delete the WantDivergence note", c.WantDivergence)
				}
				return
			}

			if same {
				agreed++
				return
			}
			diverged++
			if ktResp.status != goResp.status {
				t.Errorf("STATUS  kotlin=%d  go=%d", ktResp.status, goResp.status)
			}
			if ktResp.contentType != goResp.contentType {
				t.Errorf("CONTENT-TYPE  kotlin=%q  go=%q", ktResp.contentType, goResp.contentType)
			}
			if ktBody != goBody {
				t.Errorf("BODY\n  kotlin: %s\n  go:     %s", truncate(ktBody, 900), truncate(goBody, 900))
			}
		})
	}
	t.Logf("differential corpus: %d cases · %d agreed · %d diverged", len(corpus), agreed, diverged)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// TestNormaliserDoesNotHideARealDifference is the harness's own non-vacuity check.
//
// 🔒 THE NORMALISER IS THE ONE PLACE A DIVERGENCE CAN VANISH, and a too-aggressive rule makes the whole
// run a green light that proves nothing. These pairs MUST still compare unequal after normalisation.
func TestNormaliserDoesNotHideARealDifference(t *testing.T) {
	mustDiffer := []struct{ name, a, b string }{
		{"a different error code", `{"code":"common.bad_id","params":{}}`, `{"code":"common.not_found","params":{}}`},
		{"an omitted params map", `{"code":"x","params":{}}`, `{"code":"x"}`},
		{"a flipped boolean", `{"isAdmin":true}`, `{"isAdmin":false}`},
		{"a renamed field", `{"advertiseWireTls":true}`, `{"advertiseWireTLS":true}`},
		{"a shorter array", `[{"name":"a"},{"name":"b"}]`, `[{"name":"a"}]`},
		{"null vs a volatile value", `{"expiresAt":null}`, `{"expiresAt":"2026-01-01T00:00:00Z"}`},
		{"a different string value", `{"principal":"a@example.com"}`, `{"principal":"b@example.com"}`},
		{"a missing nested key", `{"session":{"heartbeatMs":90000}}`, `{"session":{}}`},
	}
	for _, tc := range mustDiffer {
		t.Run(tc.name, func(t *testing.T) {
			if Normalize(tc.a) == Normalize(tc.b) {
				t.Errorf("the normaliser collapsed a REAL difference:\n  %s\n  %s\nnormalised both to: %s",
					tc.a, tc.b, Normalize(tc.a))
			}
		})
	}

	// And the converse: the three admissible classes MUST normalise equal, or the run drowns in noise.
	mustAgree := []struct{ name, a, b string }{
		{"differing ids", `{"id":1,"name":"r"}`, `{"id":97,"name":"r"}`},
		{"differing timestamps", `{"createdAt":"2026-01-01T00:00:00Z"}`, `{"createdAt":"2027-06-02T11:22:33.44Z"}`},
		{"differing secrets", `{"token":"pmr_aaa"}`, `{"token":"pmr_zzz"}`},
		{"differing key order", `{"a":1,"b":2}`, `{"b":2,"a":1}`},
	}
	for _, tc := range mustAgree {
		t.Run(tc.name, func(t *testing.T) {
			if Normalize(tc.a) != Normalize(tc.b) {
				t.Errorf("the normaliser reported noise as a difference:\n  %s → %s\n  %s → %s",
					tc.a, Normalize(tc.a), tc.b, Normalize(tc.b))
			}
		})
	}
}
