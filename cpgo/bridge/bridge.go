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

// Resource is the Cedar resource a decision is about.
type Resource struct {
	Type      string `json:"type"`
	Principal string `json:"principal,omitempty"`
}

var (
	AuditLog = Resource{Type: "AuditLog"}
	System   = Resource{Type: "System"}
)

func AuditRecord(owner string) Resource { return Resource{Type: "AuditRecord", Principal: owner} }

// Client calls Kotlin's POST /internal/authorize.
type Client struct {
	url   string
	token string
	http  *http.Client
}

func New(upstream *url.URL, token string) *Client {
	return &Client{
		url:   upstream.JoinPath("/internal/authorize").String(),
		token: token,
		http:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Authorize reports whether Cedar allows principal to take action on resource, and on a deny, Cedar's reason.
func (c *Client) Authorize(ctx context.Context, principal, action string, resource Resource, requesterIP string) (bool, string, error) {
	body, err := json.Marshal(struct {
		Principal   string   `json:"principal"`
		Action      string   `json:"action"`
		Resource    Resource `json:"resource"`
		RequesterIP string   `json:"requesterIp,omitempty"`
	}{principal, action, resource, requesterIP})
	if err != nil {
		return false, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(TokenHeader, c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("bridge: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("bridge: authorize returned %s", resp.Status)
	}
	var out struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, "", fmt.Errorf("bridge: %w", err)
	}
	return out.Allow, out.Reason, nil
}
