package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/ridi-oss/proxy-monster/cpgo/gobridge"
	bridgepb "github.com/ridi-oss/proxy-monster/cpgo/gobridge/pb"
)

func testPEM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

func TestRunServesTheGitHubAppToTheChildWithoutItsKey(t *testing.T) {
	t.Setenv("PM_GITHUB_APP_PRIVATE_KEY", testPEM(t))
	cfg, cancel, _ := startFront(t, func(c *config) {
		c.GitHub = githubConfig{AppID: "1", APIURL: "http://127.0.0.1:1"}
	})
	defer cancel()

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/env", cfg.HTTPPort))
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&env)
	_ = resp.Body.Close()
	if env["key"] != "" || !strings.HasPrefix(env["bridge"], "127.0.0.1:") {
		t.Fatalf("child saw %v", env)
	}

	cc, err := grpc.NewClient(env["bridge"], grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	call := func(token string) codes.Code {
		ctx := context.Background()
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, gobridge.TokenKey, token)
		}
		_, err := bridgepb.NewGitHubSourceClient(cc).CompareCommits(ctx, &bridgepb.CompareCommitsRequest{
			Repo: &bridgepb.Repo{Owner: "acme", Name: "shop"}, Base: "a", Head: "b",
		})
		return status.Code(err)
	}
	if code := call(""); code != codes.Unauthenticated {
		t.Fatalf("without the token: %v", code)
	}
	// GitHub is unreachable here, so an accepted call fails at GitHub rather than at the token check.
	if code := call(env["token"]); code != codes.Internal {
		t.Fatalf("with the child's token: %v", code)
	}
}

func TestStartBridgeRefusesAnAmbiguousOrMisplacedKey(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg config
		env map[string]string
	}{
		"a key without an App ID": {env: map[string]string{"PM_GITHUB_APP_PRIVATE_KEY": "x"}},
		"two keys":                {cfg: config{GitHub: githubConfig{AppID: "1", KMSKeyID: "alias/k"}}, env: map[string]string{"PM_GITHUB_APP_PRIVATE_KEY": "x"}},
		"no key":                  {cfg: config{GitHub: githubConfig{AppID: "1"}}},
		"attach without a port":   {cfg: config{Attach: true, GitHub: githubConfig{AppID: "1"}}, env: map[string]string{"PM_GITHUB_APP_PRIVATE_KEY": testPEM(t)}},
		"a malformed PEM":         {cfg: config{GitHub: githubConfig{AppID: "1"}}, env: map[string]string{"PM_GITHUB_APP_PRIVATE_KEY": "x"}},
		"a non-numeric App ID":    {cfg: config{GitHub: githubConfig{AppID: "app"}}, env: map[string]string{"PM_GITHUB_APP_PRIVATE_KEY": testPEM(t)}},
	} {
		t.Run(name, func(t *testing.T) {
			for _, k := range githubKeyEnv {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if s, err := startBridge(context.Background(), tc.cfg, "t", make(chan error, 1)); err == nil {
				_ = s.Close()
				t.Fatal("want an error")
			}
		})
	}
}

func TestWithoutKeysDropsOnlyTheKeySettings(t *testing.T) {
	got := withoutKeys([]string{"PM_GITHUB_APP_ID=1", "PM_GITHUB_APP_PRIVATE_KEY=k", "PM_GITHUB_APP_PRIVATE_KEY_FILE=/k", "PM_GITHUB_APP_KMS_KEY_ID=alias/k", "PM_GITHUB_API_URL=u"})
	if strings.Join(got, " ") != "PM_GITHUB_APP_ID=1 PM_GITHUB_API_URL=u" {
		t.Fatalf("got %v", got)
	}
}

// callBridge is the fake child's last call into Go after SIGTERM, reported as the call's status code.
func callBridge() string {
	cc, err := grpc.NewClient(os.Getenv("PM_CP_GO_GRPC_ADDR"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err.Error()
	}
	defer cc.Close()
	ctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(context.Background(), gobridge.TokenKey, os.Getenv("PM_CP_INTERNAL_TOKEN")), 5*time.Second)
	defer cancel()
	_, err = bridgepb.NewGitHubSourceClient(cc).CompareCommits(ctx, &bridgepb.CompareCommitsRequest{Repo: &bridgepb.Repo{Owner: "acme", Name: "shop"}})
	return status.Code(err).String()
}

func TestTheBridgeOutlastsTheChildsDrain(t *testing.T) {
	t.Setenv("PM_GITHUB_APP_PRIVATE_KEY", testPEM(t))
	result := filepath.Join(t.TempDir(), "call")
	t.Setenv("CPGO_FAKE_CHILD_CALL_ON_TERM", result)
	_, cancel, done := startFront(t, func(c *config) {
		c.GitHub = githubConfig{AppID: "1", APIURL: "http://127.0.0.1:1"}
	})
	cancel()
	select {
	case <-done:
	case <-time.After(40 * time.Second):
		t.Fatal("run did not return after shutdown")
	}
	got, err := os.ReadFile(result)
	// GitHub is unreachable in these tests, so a bridge that still answers fails the call as Internal.
	if err != nil || string(got) != codes.Internal.String() {
		t.Fatalf("the child's call during its drain: %q %v", got, err)
	}
}
