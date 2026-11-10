package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
)

func tokenEnv(t *testing.T, f *fakeSQLServer, out io.Writer) (sqlEnv, string) {
	t.Helper()
	outputs := filepath.Join(t.TempDir(), "github_output")
	env := f.env(".", out)
	base := env.getenv
	env.getenv = func(k string) string {
		if k == "GITHUB_OUTPUT" {
			return outputs
		}
		return base(k)
	}
	return env, outputs
}

func TestTokenWritesAMaskedServiceTokenToTheStepOutputs(t *testing.T) {
	f := newFakeSQLServer(t)
	var out bytes.Buffer
	env, outputs := tokenEnv(t, f, &out)
	cmd := &tokenCmd{sqlConn{Server: f.srv.URL + "/", Audience: "pm-ci"}}
	if err := cmd.run(context.Background(), env); err != nil {
		t.Fatalf("run: %v", err)
	}
	written, err := os.ReadFile(outputs)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(written); got != "token="+testServiceToken+"\nexpires-at=2030-01-01T00:15:00Z\nbinding=shop-ci\n" {
		t.Errorf("outputs = %q", got)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || lines[0] != "::add-mask::"+testServiceToken || strings.Contains(lines[1], testServiceToken) {
		t.Errorf("stdout = %q, want the mask command first and the token nowhere else", out.String())
	}
	assertNoSecrets(t, lines[1])
}

func TestTokenNeverLogsWithoutAStepOutput(t *testing.T) {
	f := newFakeSQLServer(t)
	var out bytes.Buffer
	env := f.env(".", &out)
	err := (&tokenCmd{sqlConn{Server: f.srv.URL, Audience: "pm-ci"}}).run(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "GITHUB_OUTPUT") || out.Len() != 0 {
		t.Fatalf("err = %v, out = %q", err, out.String())
	}
}

func TestTokenReportsAnUnboundWorkload(t *testing.T) {
	f := newFakeSQLServer(t)
	f.noBinding = true
	var out bytes.Buffer
	env, outputs := tokenEnv(t, f, &out)
	err := (&tokenCmd{sqlConn{Server: f.srv.URL, Audience: "pm-ci"}}).run(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "workload.no_binding") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(outputs); !os.IsNotExist(statErr) || out.Len() != 0 {
		t.Errorf("wrote something for a refused exchange: %v %q", statErr, out.String())
	}
	assertNoSecrets(t, err.Error())
}

func TestKongGrammarToken(t *testing.T) {
	t.Setenv("PM_CI_SERVER_URL", "https://pm.example.com")
	var r root
	p, err := kong.New(&r, kong.Vars{"version": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Parse([]string{"token"}); err != nil || r.Token.Server != "https://pm.example.com" || r.Token.Audience != "" {
		t.Fatalf("parsed %+v %v", r.Token, err)
	}
}
