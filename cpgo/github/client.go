package github

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	gh "github.com/google/go-github/v88/github"
	"github.com/shurcooL/githubv4"
)

const (
	userAgent         = "proxy-monster"
	rawAccept         = "application/vnd.github.raw+json"
	commentPage       = 100
	requiredChecksTTL = 5 * time.Minute
	messageLimit      = 200
	requestTimeout    = 30 * time.Second
)

// Client is a GitHub App installed on the repositories' owners. All calls are serialized.
type Client struct {
	appID      int64
	apiURL     string
	graphqlURL string
	transport  *http.Transport
	apps       *ghinstallation.AppsTransport
	now        func() time.Time

	mu             sync.Mutex
	installationID map[string]int64
	installations  map[int64]*installation
	requiredChecks map[string]cachedChecks
	rateLimit      *RateLimit
}

// installation is one installation's clients, sharing a token ghinstallation keeps fresh.
type installation struct {
	rest *gh.Client
	gql  *githubv4.Client
}

type cachedChecks struct {
	at       time.Time
	contexts []string
}

func New(appID, apiURL string, signer Signer) (*Client, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(appID), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("GitHub App ID %q is not a number", appID)
	}
	apiURL = strings.TrimRight(apiURL, "/")
	gql := apiURL + "/graphql"
	if base, ok := strings.CutSuffix(apiURL, "/api/v3"); ok {
		gql = base + "/api/graphql"
	}
	c := &Client{
		appID:          id,
		apiURL:         apiURL,
		graphqlURL:     gql,
		transport:      githubTransport(),
		now:            time.Now,
		installationID: map[string]int64{},
		installations:  map[int64]*installation{},
		requiredChecks: map[string]cachedChecks{},
	}
	if c.apps, err = ghinstallation.NewAppsTransportWithOptions(statusTransport{c.transport, c}, id, ghinstallation.WithSigner(signer)); err != nil {
		return nil, err
	}
	c.apps.BaseURL = apiURL
	return c, nil
}

// githubTransport bounds the wait for each answer here: go-github's GetBranch round-trips without the
// http.Client, so the client's timeout alone would not cover it.
func githubTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = requestTimeout
	return t
}

// TrustCAs adds PEM CA certificates to the system roots the client verifies GitHub with, for a GitHub
// Enterprise Server behind a private CA.
func (c *Client) TrustCAs(pemCerts []byte) error {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemCerts) {
		return errors.New("no PEM certificate found")
	}
	c.transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return nil
}

// RateLimit is from the last GraphQL response that reported it; nil before the first.
func (c *Client) RateLimit() *RateLimit {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rateLimit
}

func (c *Client) restClient(tr http.RoundTripper) *gh.Client {
	base := c.apiURL + "/"
	rc, _ := gh.NewClient(
		gh.WithHTTPClient(&http.Client{Transport: tr, Timeout: requestTimeout}),
		gh.WithURLs(&base, &base),
		gh.WithUserAgent(userAgent),
	)
	return rc
}

// withRepo runs fn with the installation on repo's owner.
func (c *Client) withRepo(ctx context.Context, repo Repo, fn func(*installation) error) error {
	return c.withInstallation(repo.Owner, func(apps *gh.Client) (*gh.Installation, *gh.Response, error) {
		return apps.Apps.GetRepositoryInstallation(ctx, repo.Owner, repo.Name)
	}, fn)
}

func (c *Client) withOrg(ctx context.Context, org string, fn func(*installation) error) error {
	return c.withInstallation(org, func(apps *gh.Client) (*gh.Installation, *gh.Response, error) {
		return apps.Apps.GetOrganizationInstallation(ctx, org)
	}, fn)
}

// withInstallation looks the installation up once per owner. A 401 drops the installation's clients, and
// with them its token, and retries once with a fresh token.
func (c *Client) withInstallation(
	owner string,
	lookup func(*gh.Client) (*gh.Installation, *gh.Response, error),
	fn func(*installation) error,
) error {
	key := strings.ToLower(owner)
	id, ok := c.installationID[key]
	if !ok {
		inst, _, err := lookup(c.restClient(c.apps))
		if err != nil {
			return classify(err)
		}
		id = inst.GetID()
		c.installationID[key] = id
	}
	err := classify(fn(c.installation(id)))
	if e, ok := errors.AsType[*Error](err); ok && e.Kind == Unauthorized {
		delete(c.installations, id)
		err = classify(fn(c.installation(id)))
	}
	return err
}

func (c *Client) installation(id int64) *installation {
	if inst, ok := c.installations[id]; ok {
		return inst
	}
	tr := ghinstallation.NewFromAppsTransport(c.apps, id)
	tr.BaseURL = c.apiURL
	inst := &installation{
		rest: c.restClient(tr),
		gql:  githubv4.NewEnterpriseClient(c.graphqlURL, &http.Client{Transport: tr, Timeout: requestTimeout}),
	}
	c.installations[id] = inst
	return inst
}

// rateLimit is read in every GraphQL query.
type rateLimit struct {
	Remaining int
	ResetAt   time.Time
}

func (c *Client) noteRateLimit(r *rateLimit) {
	if r != nil {
		c.rateLimit = &RateLimit{Remaining: r.Remaining, ResetAt: r.ResetAt}
	}
}

// statusTransport turns a 4xx or 5xx response into an *Error, for every call either library makes.
type statusTransport struct {
	next http.RoundTripper
	c    *Client
}

func (t statusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)
	if err != nil || resp.StatusCode < 400 {
		return resp, err
	}
	defer resp.Body.Close()
	return nil, t.c.statusError(resp, req.Method, req.URL.EscapedPath())
}

func (c *Client) statusError(resp *http.Response, method, path string) *Error {
	status := resp.StatusCode
	msg := fmt.Sprintf("%s %s -> %d", method, path, status)
	var detail struct {
		Message string `json:"message"`
	}
	if b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16)); err == nil && json.Unmarshal(b, &detail) == nil && detail.Message != "" {
		msg += ": " + truncate(detail.Message)
	}
	limited := resp.Header.Get("X-Ratelimit-Remaining") == "0" || resp.Header.Get("Retry-After") != ""
	switch {
	case status == 401:
		return &Error{Kind: Unauthorized, Message: msg}
	case (status == 403 && limited) || status == 429:
		return &Error{Kind: RateLimited, Message: msg, ResetAt: c.resetAt(resp)}
	case status == 403:
		return &Error{Kind: Forbidden, Message: msg}
	case status == 404:
		return &Error{Kind: NotFound, Message: msg}
	case status >= 400 && status < 500:
		return &Error{Kind: Unprocessable, Message: msg}
	default:
		return &Error{Kind: Server, Message: msg, Status: status}
	}
}

func (c *Client) resetAt(resp *http.Response) *time.Time {
	if s, err := strconv.ParseInt(resp.Header.Get("X-Ratelimit-Reset"), 10, 64); err == nil {
		t := time.Unix(s, 0).UTC()
		return &t
	}
	if s, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64); err == nil {
		t := c.now().Add(time.Duration(s) * time.Second).UTC()
		return &t
	}
	return nil
}

// classify keeps an *Error the transport raised, and names go-github's pre-emptive rate-limit refusal.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if e, ok := errors.AsType[*Error](err); ok {
		return e
	}
	if e, ok := errors.AsType[*gh.RateLimitError](err); ok {
		reset := e.Rate.Reset.UTC()
		return &Error{Kind: RateLimited, Message: truncate(e.Message), ResetAt: &reset}
	}
	return err
}

// graphqlFailure is a GraphQL query that failed: at the transport, or with errors in its answer.
func (c *Client) graphqlFailure(err error) error {
	if e, ok := errors.AsType[*Error](err); ok {
		return e
	}
	u, _ := url.Parse(c.graphqlURL)
	return &Error{Kind: GraphQL, Message: fmt.Sprintf("POST %s -> GraphQL errors: %s", u.EscapedPath(), truncate(err.Error()))}
}

func truncate(s string) string {
	if r := []rune(s); len(r) > messageLimit {
		return string(r[:messageLimit])
	}
	return s
}
