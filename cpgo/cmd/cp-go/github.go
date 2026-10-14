package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/ridi-oss/proxy-monster/cpgo/github"
)

type githubConfig struct {
	// Shared with the Kotlin child, which reads them from the environment, so they are never flags.
	AppID    string `kong:"-"`
	APIURL   string `kong:"-"`
	KMSKeyID string `env:"PM_GITHUB_APP_KMS_KEY_ID" help:"AWS KMS key (ID, ARN, or alias) holding the App's private key, used in place of a PEM."`
	CAFile   string `env:"PM_GITHUB_CA_FILE" help:"PEM CA certificates trusted for the GitHub API besides the system ones."`
}

// githubKeyEnv is read by cp-go alone and withheld from the Kotlin child.
var githubKeyEnv = []string{"PM_GITHUB_APP_PRIVATE_KEY", "PM_GITHUB_APP_PRIVATE_KEY_FILE", "PM_GITHUB_APP_KMS_KEY_ID"}

// newGitHub is the GitHubSource service when PM_GITHUB_APP_ID is set, nil otherwise.
func newGitHub(ctx context.Context, cfg githubConfig) (*github.Service, error) {
	pemText, pemFile := os.Getenv("PM_GITHUB_APP_PRIVATE_KEY"), os.Getenv("PM_GITHUB_APP_PRIVATE_KEY_FILE")
	sources := 0
	for _, v := range []string{pemText, pemFile, cfg.KMSKeyID} {
		if strings.TrimSpace(v) != "" {
			sources++
		}
	}
	if cfg.AppID == "" {
		if sources > 0 {
			return nil, errors.New("a GitHub App key is set without PM_GITHUB_APP_ID")
		}
		return nil, nil
	}
	if sources != 1 {
		return nil, errors.New("PM_GITHUB_APP_ID needs exactly one of PM_GITHUB_APP_PRIVATE_KEY, PM_GITHUB_APP_PRIVATE_KEY_FILE, and PM_GITHUB_APP_KMS_KEY_ID")
	}
	var signer github.Signer
	var err error
	switch {
	case cfg.KMSKeyID != "":
		signer, err = github.NewKMSSigner(ctx, cfg.KMSKeyID)
	case pemFile != "":
		var b []byte
		if b, err = os.ReadFile(pemFile); err == nil {
			signer, err = github.NewPEMSigner(string(b))
		}
	default:
		signer, err = github.NewPEMSigner(pemText)
	}
	if err != nil {
		return nil, fmt.Errorf("GitHub App key: %w", err)
	}
	client, err := github.New(cfg.AppID, cfg.APIURL, signer)
	if err != nil {
		return nil, err
	}
	if cfg.CAFile != "" {
		b, err := os.ReadFile(cfg.CAFile)
		if err == nil {
			err = client.TrustCAs(b)
		}
		if err != nil {
			return nil, fmt.Errorf("PM_GITHUB_CA_FILE: %w", err)
		}
	}
	return github.NewService(client), nil
}

func withoutKeys(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(githubKeyEnv, name) {
			out = append(out, kv)
		}
	}
	return out
}
