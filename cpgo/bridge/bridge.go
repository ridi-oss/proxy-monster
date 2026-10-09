// Package bridge tells the Kotlin control plane what Go changed that Kotlin caches.
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
	// ApprovalRequest: where the request came from (console, mcp, github); "" is console.
	Source string `json:"source,omitempty"`
	// ApprovalRequest: the users CC'd on it.
	CCs []string `json:"ccs,omitempty"`
	// Token: the token kind (SESSION, USER, …), "" for any kind.
	Kind string `json:"kind,omitempty"`
	// NativeResource fields.
	NativeKind     string   `json:"nativeKind,omitempty"`
	NativeID       string   `json:"nativeId,omitempty"`
	Owner          *string  `json:"owner,omitempty"`
	DatasourceTags []string `json:"datasourceTags,omitempty"`
}

var (
	AuditLog = Resource{Type: "AuditLog"}
	System   = Resource{Type: "System"}
)

func AuditRecord(owner string) Resource { return Resource{Type: "AuditRecord", Principal: owner} }

// Client calls Kotlin's /internal routes.
type Client struct {
	upstream *url.URL
	token    string
	http     *http.Client
}

func New(upstream *url.URL, token string) *Client {
	return &Client{
		upstream: upstream,
		token:    token,
		http:     &http.Client{Timeout: 10 * time.Second},
	}
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
