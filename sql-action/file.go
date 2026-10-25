package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type sqlConn struct {
	Server   string `required:"" env:"PM_CI_SERVER_URL" help:"Control-plane base URL."`
	Audience string `env:"PM_CI_AUDIENCE" help:"OIDC audience the control plane trusts (PM_CI_OIDC_AUDIENCE); default the server's origin, as the control plane defaults it."`
}

type prRef struct {
	Repository string `required:"" help:"GitHub repository as owner/name, e.g. acme/shop."`
	PR         int    `required:"" name:"pr" help:"Pull request number."`
}

type sqlFileCmd struct {
	sqlConn    `embed:""`
	prRef      `embed:""`
	Dir        string `required:"" help:"Repository-relative directory holding the SQL files (not recursive)."`
	Datasource string `required:"" help:"Datasource the SQL runs against."`
	Schema     string `required:"" help:"Schema the SQL runs in."`
	Role       string `required:"" help:"Role the SQL runs as."`
	Scope      string `help:"Scope whose query executions happen one PR at a time (default: datasource/schema)."`
	Files      string `default:"^(?P<key>[0-9]+)_.+\\.sql$" help:"Regex a file name must match; a (?P<key>…) group is the file key, else the whole name."`
	Order      string `enum:"numeric,string" default:"numeric" help:"How file keys sort: numeric or string."`
	Instance   string `help:"The control plane's instance name (PM_INSTANCE_NAME). With it, a pull request that adds no SQL gets its <instance>/query executed check as skipped from GITHUB_TOKEN, without the control plane."`
	Base       string `required:"" help:"Base commit SHA of the pull request."`
	Head       string `required:"" help:"Head commit SHA of the pull request."`
}

type sqlEnv struct {
	getenv func(string) string
	http   *http.Client
	out    io.Writer
	gitDir string
}

func defaultSQLEnv() sqlEnv {
	return sqlEnv{getenv: os.Getenv, http: &http.Client{Timeout: 30 * time.Second}, out: os.Stdout, gitDir: "."}
}

type fileInput struct {
	Path    string `json:"path"`
	Key     string `json:"key"`
	Content string `json:"content"`
}

type fileRequestBody struct {
	Repository string      `json:"repository"`
	PR         int         `json:"pr"`
	Scope      *string     `json:"scope,omitempty"`
	Datasource string      `json:"datasource"`
	Schema     string      `json:"schema"`
	Role       string      `json:"role"`
	HeadSha    string      `json:"headSha"`
	Files      []fileInput `json:"files"`
	Order      string      `json:"order"`
}

type filedRequest struct {
	ID          int64  `json:"id"`
	Status      string `json:"status"`
	PullRequest *struct {
		Path string `json:"path"`
	} `json:"pullRequest"`
}

func (r filedRequest) path() string {
	if r.PullRequest == nil {
		return ""
	}
	return r.PullRequest.Path
}

var repositoryRe = regexp.MustCompile(`^[^/\s]+/[^/\s]+$`)

// PM_INSTANCE_NAME's grammar on the control plane.
var instanceRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)

const checkSuffix = "query executed"

func (p prRef) validate() error {
	if !repositoryRe.MatchString(p.Repository) {
		return fmt.Errorf("invalid --repository %q: want owner/name", p.Repository)
	}
	if p.PR <= 0 {
		return fmt.Errorf("invalid --pr %d: must be positive", p.PR)
	}
	return nil
}

func (c *sqlFileCmd) Run() error { return c.run(context.Background(), defaultSQLEnv()) }

func (c *sqlFileCmd) run(ctx context.Context, env sqlEnv) error {
	if err := c.validate(); err != nil {
		return err
	}
	if c.Instance != "" && !instanceRe.MatchString(c.Instance) {
		return fmt.Errorf("invalid --instance %q: want lowercase letters, digits and inner hyphens", c.Instance)
	}
	re, err := regexp.Compile(c.Files)
	if err != nil {
		return fmt.Errorf("invalid --files regex: %w", err)
	}
	files, err := addedFiles(ctx, env.gitDir, c.Dir, re, c.Base, c.Head)
	if err != nil {
		return err
	}
	headSha, err := resolveCommit(ctx, env.gitDir, c.Head)
	if err != nil {
		return err
	}
	checkName := c.Instance + "/" + checkSuffix
	if len(files) == 0 && c.Instance != "" {
		if err := postSkipped(ctx, env, c.Repository, headSha, checkName); err != nil {
			return err
		}
		fmt.Fprintf(env.out, "no new files in %s match %s; %s is skipped\n", c.Dir, c.Files, checkName)
		// The control plane drops what an earlier commit filed; while it is down, those requests end at the merge.
		if _, err := c.file(ctx, env, files, headSha, checkName); err != nil {
			fmt.Fprintf(env.out, "the control plane did not take the empty filing: %v\n", err)
		}
		return nil
	}
	res, err := c.file(ctx, env, files, headSha, checkName)
	if err != nil {
		return err
	}
	switch {
	case len(files) == 0:
		fmt.Fprintf(env.out, "no new files in %s match %s; query executed is skipped\n", c.Dir, c.Files)
	case len(res.Requests) == 0:
		fmt.Fprintln(env.out, "filed no requests; the pull request's query executed check says why")
	}
	for _, r := range res.Requests {
		fmt.Fprintf(env.out, "filed %s as request %d (%s)\n", r.path(), r.ID, r.Status)
	}
	return nil
}

type fileResponse struct {
	Requests  []filedRequest `json:"requests"`
	CheckName string         `json:"checkName"`
}

// file sends the filing to the control plane and refuses one that posts a check other than checkName.
func (c *sqlFileCmd) file(ctx context.Context, env sqlEnv, files []fileInput, headSha, checkName string) (fileResponse, error) {
	var res fileResponse
	bearer, err := authenticate(ctx, env, c.sqlConn)
	if err != nil {
		return res, err
	}
	body := fileRequestBody{
		Repository: c.Repository, PR: c.PR, Datasource: c.Datasource, Schema: c.Schema, Role: c.Role, HeadSha: headSha,
		Files: files, Order: c.Order,
	}
	if c.Scope != "" {
		body.Scope = &c.Scope
	}
	if err := postJSON(ctx, env, c.Server, "/api/github/requests", bearer, body, &res); err != nil {
		return res, err
	}
	if c.Instance != "" && res.CheckName != "" && res.CheckName != checkName {
		return res, fmt.Errorf("--instance %q posts %q, but the control plane posts %q", c.Instance, checkName, res.CheckName)
	}
	return res, nil
}

// postSkipped posts checkName on headSha as skipped, as the workflow's GITHUB_TOKEN.
func postSkipped(ctx context.Context, env sqlEnv, repository, headSha, checkName string) error {
	token := env.getenv("GITHUB_TOKEN")
	if token == "" {
		return errors.New("GITHUB_TOKEN is not set: pass it to the step, with `permissions: checks: write`")
	}
	api := env.getenv("GITHUB_API_URL")
	if api == "" {
		api = "https://api.github.com"
	}
	return postJSON(ctx, env, api, "/repos/"+repository+"/check-runs", token, map[string]any{
		"name": checkName, "head_sha": headSha, "status": "completed", "conclusion": "skipped",
		"output": map[string]string{"title": "No SQL to run", "summary": "This commit adds no SQL file for proxy-monster."},
	}, nil)
}

func authenticate(ctx context.Context, env sqlEnv, conn sqlConn) (string, error) {
	audience := conn.Audience
	if audience == "" {
		u, err := url.Parse(conn.Server)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "", fmt.Errorf("invalid --server %q", conn.Server)
		}
		audience = u.Scheme + "://" + u.Host
	}
	jwt, err := fetchOIDCToken(ctx, env, audience)
	if err != nil {
		return "", err
	}
	return exchange(ctx, env, conn.Server, jwt)
}

func fetchOIDCToken(ctx context.Context, env sqlEnv, audience string) (string, error) {
	reqURL, reqToken := env.getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), env.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqToken == "" {
		return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not set: run inside GitHub Actions with `permissions: id-token: write`")
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		return "", errors.New("invalid ACTIONS_ID_TOKEN_REQUEST_URL")
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", errors.New("invalid ACTIONS_ID_TOKEN_REQUEST_URL")
	}
	req.Header.Set("Authorization", "Bearer "+reqToken)
	resp, err := env.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request GitHub OIDC token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("request GitHub OIDC token: %s", resp.Status)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil || out.Value == "" {
		return "", fmt.Errorf("request GitHub OIDC token: %s: no token in response", resp.Status)
	}
	return out.Value, nil
}

func exchange(ctx context.Context, env sqlEnv, server, jwt string) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	if err := postJSON(ctx, env, server, "/api/workload/token", "", map[string]string{"token": jwt}, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("POST /api/workload/token: no token in response")
	}
	return out.Token, nil
}

func postJSON(ctx context.Context, env sqlEnv, server, path, bearer string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(server, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := env.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var apiErr struct {
			Code   string         `json:"code"`
			Params map[string]any `json:"params"`
		}
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Code != "" {
			if len(apiErr.Params) == 0 {
				return fmt.Errorf("POST %s: %s: %s", path, resp.Status, apiErr.Code)
			}
			return fmt.Errorf("POST %s: %s: %s %v", path, resp.Status, apiErr.Code, apiErr.Params)
		}
		snippet := strings.TrimSpace(string(data[:min(len(data), 200)]))
		if snippet == "" {
			return fmt.Errorf("POST %s: %s", path, resp.Status)
		}
		return fmt.Errorf("POST %s: %s: %s", path, resp.Status, strconv.Quote(snippet))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("POST %s: %s: %w", path, resp.Status, err)
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("POST %s: decode response: %w", path, err)
		}
	}
	return nil
}
