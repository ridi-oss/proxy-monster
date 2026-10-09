// Package bridge asks the Kotlin control plane for Cedar decisions until Cedar moves to Go.
package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// TokenHeader carries the per-boot token cp-go hands the Kotlin child.
const TokenHeader = "X-PM-Internal-Token"

// Resource is the Cedar resource a decision is about. Principal is its owner: an audit record's, a
// grant's, or an approval request's requester.
type Resource struct {
	Type           string  `json:"type"`
	Principal      string  `json:"principal,omitempty"`
	ID             int64   `json:"id,omitempty"`
	Approver       *string `json:"approver,omitempty"`
	ExecutedBy     *string `json:"executedBy,omitempty"`
	DatasourceName *string `json:"datasourceName,omitempty"`
	RoleName       *string `json:"roleName,omitempty"`
}

var (
	AuditLog = Resource{Type: "AuditLog"}
	System   = Resource{Type: "System"}
)

func AuditRecord(owner string) Resource { return Resource{Type: "AuditRecord", Principal: owner} }

// Client calls Kotlin's /internal/authorize routes.
type Client struct {
	upstream                     *url.URL
	url, batchURL, mayConnectURL string
	token                        string
	http                         *http.Client
}

func New(upstream *url.URL, token string) *Client {
	return &Client{
		upstream:      upstream,
		url:           upstream.JoinPath("/internal/authorize").String(),
		batchURL:      upstream.JoinPath("/internal/authorize-batch").String(),
		mayConnectURL: upstream.JoinPath("/internal/may-connect").String(),
		token:         token,
		http:          &http.Client{Timeout: 10 * time.Second},
	}
}

// Authorize reports whether Cedar allows principal to take action on resource, and on a deny, Cedar's reason.
func (c *Client) Authorize(ctx context.Context, principal, action string, resource Resource, requesterIP string) (bool, string, error) {
	var out struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	}
	err := c.post(ctx, c.url, struct {
		Principal   string   `json:"principal"`
		Action      string   `json:"action"`
		Resource    Resource `json:"resource"`
		RequesterIP string   `json:"requesterIp,omitempty"`
	}{principal, action, resource, requesterIP}, &out)
	return out.Allow, out.Reason, err
}

// AuthorizeEach decides action on every resource for principal, in order, from one role resolution.
func (c *Client) AuthorizeEach(ctx context.Context, principal, action string, resources []Resource, requesterIP string) ([]bool, error) {
	if len(resources) == 0 {
		return nil, nil
	}
	var out struct {
		Allow []bool `json:"allow"`
	}
	err := c.post(ctx, c.batchURL, struct {
		Principal   string     `json:"principal"`
		Action      string     `json:"action"`
		Resources   []Resource `json:"resources"`
		RequesterIP string     `json:"requesterIp,omitempty"`
	}{principal, action, resources, requesterIP}, &out)
	if err == nil && len(out.Allow) != len(resources) {
		err = fmt.Errorf("bridge: %d decisions for %d resources", len(out.Allow), len(resources))
	}
	return out.Allow, err
}

// MayConnect is Kotlin's datasource.connect decision for each datasource, in order: context tags derived
// from the datasource first, and false for a deactivated principal or a missing datasource.
func (c *Client) MayConnect(ctx context.Context, principal string, datasourceIDs []int64, requesterIP string) ([]bool, error) {
	if len(datasourceIDs) == 0 {
		return nil, nil
	}
	var out struct {
		Allow []bool `json:"allow"`
	}
	err := c.post(ctx, c.mayConnectURL, struct {
		Principal     string  `json:"principal"`
		DatasourceIDs []int64 `json:"datasourceIds"`
		RequesterIP   string  `json:"requesterIp,omitempty"`
	}{principal, datasourceIDs, requesterIP}, &out)
	if err == nil && len(out.Allow) != len(datasourceIDs) {
		err = fmt.Errorf("bridge: %d decisions for %d datasources", len(out.Allow), len(datasourceIDs))
	}
	return out.Allow, err
}

// Validate checks a Cedar source against the authorization schema, returning the validator's errors.
func (c *Client) Validate(ctx context.Context, cedarSrc string) ([]string, error) {
	var out struct {
		Errors []string `json:"errors"`
	}
	err := c.post(ctx, c.upstream.JoinPath("/internal/cedar-validate").String(), struct {
		CedarSrc string `json:"cedarSrc"`
	}{cedarSrc}, &out)
	return out.Errors, err
}

// PoliciesChanged tells Kotlin a policy change committed, so its next decision rebuilds the policy set.
func (c *Client) PoliciesChanged(ctx context.Context) error {
	return c.post(ctx, c.upstream.JoinPath("/internal/policies-changed").String(), struct{}{}, nil)
}

func (c *Client) post(ctx context.Context, url string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(TokenHeader, c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("bridge: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && !(out == nil && resp.StatusCode == http.StatusNoContent) {
		return fmt.Errorf("bridge: %s returned %s", url, resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("bridge: %w", err)
	}
	return nil
}
