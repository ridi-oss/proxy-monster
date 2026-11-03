package workload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	awsSigningAlgorithm = "ES384"
	awsDurationSeconds  = 300
	maxTokenBytes       = 64 << 10
)

type Source interface {
	Token(ctx context.Context, audience string) (string, error)
}

var Sources = []string{"aws", "github", "file:<path>", "env:<VAR>"}

func Parse(spec string) (Source, error) {
	switch kind, arg, _ := strings.Cut(spec, ":"); {
	case spec == "aws":
		return AWS{}, nil
	case spec == "github":
		return GitHub{Getenv: os.Getenv}, nil
	case kind == "file" && arg != "":
		return File{Path: arg}, nil
	case kind == "env" && arg != "":
		return Env{Name: arg, Getenv: os.Getenv}, nil
	}
	return nil, fmt.Errorf("unknown workload token source %q: use one of %s", spec, strings.Join(Sources, ", "))
}

func Renewable(spec string) bool {
	kind, _, _ := strings.Cut(spec, ":")
	return kind != "env"
}

func Absolute(spec string) (string, error) {
	kind, path, _ := strings.Cut(spec, ":")
	if kind != "file" || path == "" {
		return spec, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("workload token file: %w", err)
	}
	return "file:" + abs, nil
}

func Audience(controlPlane string) (string, error) {
	u, err := url.Parse(controlPlane)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("cannot derive an audience from control-plane URL %q", controlPlane)
	}
	return u.Scheme + "://" + u.Host, nil
}

type File struct{ Path string }

func (f File) Token(context.Context, string) (string, error) {
	fh, err := os.Open(f.Path)
	if err != nil {
		return "", fmt.Errorf("workload token file: %w", err)
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, maxTokenBytes))
	if err != nil {
		return "", fmt.Errorf("workload token file: %w", err)
	}
	return nonEmpty(string(b), "workload token file "+f.Path)
}

type Env struct {
	Name   string
	Getenv func(string) string
}

func (e Env) Token(context.Context, string) (string, error) {
	return nonEmpty(e.Getenv(e.Name), "environment variable "+e.Name)
}

type GitHub struct {
	Getenv func(string) string
	Client *http.Client
}

func (g GitHub) Token(ctx context.Context, audience string) (string, error) {
	endpoint, bearer := g.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), g.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if endpoint == "" || bearer == "" {
		return "", errors.New("no GitHub Actions OIDC token: the job needs `permissions: id-token: write`")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GitHub Actions OIDC token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub Actions OIDC token: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenBytes)).Decode(&out); err != nil {
		return "", fmt.Errorf("GitHub Actions OIDC token: %w", err)
	}
	return nonEmpty(out.Value, "GitHub Actions OIDC token")
}

type STSAPI interface {
	GetWebIdentityToken(ctx context.Context, in *sts.GetWebIdentityTokenInput, opts ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

type AWS struct {
	Client func(ctx context.Context) (STSAPI, error)
}

func (a AWS) Token(ctx context.Context, audience string) (string, error) {
	newClient := a.Client
	if newClient == nil {
		newClient = defaultSTS
	}
	client, err := newClient(ctx)
	if err != nil {
		return "", fmt.Errorf("AWS credentials: %w", err)
	}
	out, err := client.GetWebIdentityToken(ctx, &sts.GetWebIdentityTokenInput{
		Audience:         []string{audience},
		SigningAlgorithm: aws.String(awsSigningAlgorithm),
		DurationSeconds:  aws.Int32(awsDurationSeconds),
	})
	if err != nil {
		return "", fmt.Errorf("sts:GetWebIdentityToken: %w", err)
	}
	return nonEmpty(aws.ToString(out.WebIdentityToken), "sts:GetWebIdentityToken")
}

func defaultSTS(ctx context.Context) (STSAPI, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.Region == "" {
		return nil, errors.New("no AWS region: set AWS_REGION, since STS issues these tokens only on a regional endpoint")
	}
	return sts.NewFromConfig(cfg), nil
}

func nonEmpty(token, what string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("%s is empty", what)
	}
	return token, nil
}
