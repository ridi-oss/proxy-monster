package workload

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestParseNamesEverySource(t *testing.T) {
	if got, err := Parse("aws"); err != nil || got.(AWS).Client != nil {
		t.Errorf("aws = %#v %v", got, err)
	}
	if got, err := Parse("file:/var/run/token"); err != nil || got != (File{Path: "/var/run/token"}) {
		t.Errorf("file = %#v %v", got, err)
	}
	if got, err := Parse("env:PM_WORKLOAD_TOKEN"); err != nil || got.(Env).Name != "PM_WORKLOAD_TOKEN" {
		t.Errorf("env = %#v %v", got, err)
	}
	if got, err := Parse("github"); err != nil || got.(GitHub).Getenv == nil {
		t.Errorf("github = %#v %v", got, err)
	}
	for _, bad := range []string{"", "gcp", "file:", "env:"} {
		if _, err := Parse(bad); err == nil || !strings.Contains(err.Error(), "unknown workload token source") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestAudienceIsTheControlPlaneOrigin(t *testing.T) {
	if got, err := Audience("https://pm.example.com:8443/base"); err != nil || got != "https://pm.example.com:8443" {
		t.Errorf("got %q %v", got, err)
	}
	if _, err := Audience("pm.example.com"); err == nil {
		t.Error("a URL with no scheme should not yield an audience")
	}
}

func TestFileIsReReadEveryTime(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	src := File{Path: p}
	for _, want := range []string{"jwt-1", "jwt-2"} {
		if err := os.WriteFile(p, []byte(want+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := src.Token(context.Background(), "aud"); err != nil || got != want {
			t.Errorf("got %q %v, want %q", got, err, want)
		}
	}
	if err := os.WriteFile(p, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Token(context.Background(), "aud"); err == nil {
		t.Error("an empty file should fail")
	}
}

func TestEnvReadsTheVariable(t *testing.T) {
	env := map[string]string{"TOK": "jwt"}
	src := Env{Name: "TOK", Getenv: func(k string) string { return env[k] }}
	if got, err := src.Token(context.Background(), "aud"); err != nil || got != "jwt" {
		t.Errorf("got %q %v", got, err)
	}
	src.Name = "MISSING"
	if _, err := src.Token(context.Background(), "aud"); err == nil || !strings.Contains(err.Error(), "MISSING") {
		t.Errorf("missing: %v", err)
	}
}

func TestGitHubRequestsTheAudience(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer req-token" || r.URL.Query().Get("audience") != "https://pm.example.com" ||
			r.URL.Query().Get("api-version") != "2.0" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"count":1,"value":"gh-jwt"}`))
	}))
	defer srv.Close()
	env := map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": srv.URL + "/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token"}
	src := GitHub{Getenv: func(k string) string { return env[k] }}
	if got, err := src.Token(context.Background(), "https://pm.example.com"); err != nil || got != "gh-jwt" {
		t.Errorf("got %q %v", got, err)
	}
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if _, err := src.Token(context.Background(), "https://pm.example.com"); err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Errorf("no permission: %v", err)
	}
}

type fakeSTS struct {
	in  *sts.GetWebIdentityTokenInput
	err error
}

func (f *fakeSTS) GetWebIdentityToken(_ context.Context, in *sts.GetWebIdentityTokenInput, _ ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	f.in = in
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetWebIdentityTokenOutput{WebIdentityToken: aws.String("aws-jwt")}, nil
}

func TestAWSAsksForAShortES384Token(t *testing.T) {
	fake := &fakeSTS{}
	src := AWS{Client: func(context.Context) (STSAPI, error) { return fake, nil }}
	if got, err := src.Token(context.Background(), "https://pm.example.com"); err != nil || got != "aws-jwt" {
		t.Fatalf("got %q %v", got, err)
	}
	if fake.in.Audience[0] != "https://pm.example.com" || aws.ToString(fake.in.SigningAlgorithm) != "ES384" || aws.ToInt32(fake.in.DurationSeconds) != 300 {
		t.Errorf("input %+v", fake.in)
	}
	fake.err = errors.New("AccessDenied")
	if _, err := src.Token(context.Background(), "aud"); err == nil || !strings.Contains(err.Error(), "sts:GetWebIdentityToken") {
		t.Errorf("denied: %v", err)
	}
}

func TestOnlyEnvSourcesAreOneShot(t *testing.T) {
	for spec, want := range map[string]bool{"aws": true, "github": true, "file:/t": true, "env:TOK": false} {
		if got := Renewable(spec); got != want {
			t.Errorf("Renewable(%q) = %v", spec, got)
		}
	}
	t.Chdir(t.TempDir())
	wd, _ := os.Getwd()
	if got, err := Absolute("file:jwt"); err != nil || got != "file:"+filepath.Join(wd, "jwt") {
		t.Errorf("relative file = %q %v", got, err)
	}
	for _, spec := range []string{"file:/abs/jwt", "env:TOK", "aws"} {
		if got, err := Absolute(spec); err != nil || got != spec {
			t.Errorf("Absolute(%q) = %q %v", spec, got, err)
		}
	}
}
