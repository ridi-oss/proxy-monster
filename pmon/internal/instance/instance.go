// Package instance reads what a proxy-monster server says about itself before anyone signs in.
package instance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Info is a server's GET /api/instance.
type Info struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	MCPURL      string `json:"mcpUrl"`
	InstallName string `json:"installName"`
}

// ErrUnsupported is a server older than /api/instance.
var ErrUnsupported = errors.New("the server does not describe itself")

// Fetch reads controlPlane's /api/instance. It does not follow redirects: an answer from elsewhere could name
// some other server.
func Fetch(ctx context.Context, controlPlane string) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(controlPlane, "/")+"/api/instance", nil)
	if err != nil {
		return Info{}, err
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return Info{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Info{}, ErrUnsupported
	}
	if resp.StatusCode != http.StatusOK {
		return Info{}, fmt.Errorf("%s/api/instance: HTTP %d", controlPlane, resp.StatusCode)
	}
	var info Info
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&info); err != nil {
		return Info{}, fmt.Errorf("%s/api/instance: %w", controlPlane, err)
	}
	return info, nil
}
