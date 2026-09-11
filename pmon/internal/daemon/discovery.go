package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Datasource is the subset of GET /api/datasources a broker needs: the name, its engine, the default db name,
// and the advertised proxy address to dial. Extra fields in the response are ignored.
type Datasource struct {
	Name          string `json:"name"`
	Engine        string `json:"engine"` // "mysql" | "postgres" (wire name)
	DbName        string `json:"dbName"`
	AdvertiseAddr string `json:"advertiseAddr"` // client-facing proxy host:port; empty if the proxy advertised none
	// The PEM certificate chain to trust for this datasource's proxy (leaf first). Used as the root pool for
	// the upstream TLS hop, with the advertised host checked against it — ordinary verification, no pinning.
	//
	// Empty does NOT mean "no TLS" — an operator may serve a publicly-trusted cert and publish no chain, and a
	// transient cert read on the proxy publishes none either. Ask WireTLS for that; conflating the two would
	// let an attacker's plaintext greeting look like a datasource that never had TLS.
	CertChainPEM string `json:"advertiseCertChain"`
	// Whether this datasource's proxy serves TLS at all — independent of whether a chain was published. When
	// true the broker refuses a plaintext greeting instead of sending the token in the clear.
	WireTLS bool `json:"advertiseWireTls"`
}

// Brokerable reports whether this datasource has an address and a wire protocol the local broker speaks.
func (d Datasource) Brokerable() bool {
	return d.AdvertiseAddr != "" && (d.Engine == "mysql" || d.Engine == "postgres")
}

// UnbrokerableReason explains why a discovered datasource has no local listener, for a peer to show in place
// of a connection string.
func (d Datasource) UnbrokerableReason() string {
	switch {
	case d.AdvertiseAddr == "":
		return "no advertised proxy address"
	case d.Engine != "mysql" && d.Engine != "postgres":
		return fmt.Sprintf("engine %q not brokered", d.Engine)
	default:
		return ""
	}
}

// discoverDatasources lists the datasources the logged-in principal can CONNECT to, authenticating with the
// wire token as an HTTP Bearer. It passes ?connectable=true so the control plane returns only datasources this
// principal is authorized to open — the daemon must never open a broker port (and hand out the wire token)
// for a datasource the principal cannot reach.
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
