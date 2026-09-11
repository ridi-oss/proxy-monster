package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

type Datasource = driver.Endpoint

// Discovery includes only datasources the principal can connect to, not every visible datasource.
func discoverDatasources(ctx context.Context, client *http.Client, controlPlane, token string) ([]Datasource, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, controlPlane+"/api/datasources?connectable=true", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("list datasources: HTTP %d: %s", resp.StatusCode, body)
	}
	var out []Datasource
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode datasources: %w", err)
	}
	return out, nil
}
