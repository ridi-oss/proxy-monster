package daemon

import (
	"encoding/json"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"strings"
	"testing"
)

// TestDiscoveryParsesTheControlPlaneChainField is the CP↔pmon CONTRACT test. The chain arrives as one JSON
// key in the datasource response, and if this struct's tag and the control plane's field name ever disagree,
// CertChainPEM silently stays empty: the upstream hop falls back to system trust (breaking every self-signed
// proxy), the plaintext-downgrade refusal becomes dead code, and the token can cross in the clear. Nothing
// errors — which is exactly why unit tests that hand a chain straight to upstreamTLSConfig cannot catch it.
//
// The literal below is the shape the control plane serializes (driver.Endpoint in Datasources.kt). Keep it a
// literal, not a constant shared with production code: the point is to fail when the two drift apart.
func TestDiscoveryParsesTheControlPlaneChainField(t *testing.T) {
	const controlPlaneResponse = `[{
      "id": 1,
      "name": "acme-mysql",
      "engine": "mysql",
      "dbName": "app",
      "advertiseAddr": "proxy.example:6033",
      "advertiseCertChain": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      "advertiseWireTls": true
    }]`

	var got []driver.Endpoint
	if err := json.Unmarshal([]byte(controlPlaneResponse), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d datasources", len(got))
	}
	if got[0].AdvertiseAddr != "proxy.example:6033" {
		t.Errorf("AdvertiseAddr = %q", got[0].AdvertiseAddr)
	}
	if !strings.Contains(got[0].CertChainPEM, "BEGIN CERTIFICATE") {
		t.Errorf(
			"CertChainPEM is empty — the control plane's chain field and this struct's json tag disagree, so "+
				"every brokered connection would silently fall back to system trust. Got %+v", got[0])
	}
	// The TLS requirement is a SEPARATE key. If this tag drifts, WireTLS decodes false for a TLS proxy and the
	// plaintext-downgrade refusal in proxyConnect goes dead — the exact hole that makes the token stealable.
	if !got[0].WireTLS {
		t.Errorf(
			"WireTLS is false for a TLS datasource — the control plane's advertiseWireTls field and this "+
				"struct's json tag disagree, so pmon would accept a plaintext downgrade. Got %+v", got[0])
	}
}

// TestATLSProxyThatPublishesNoChainStillRequiresTLS pins the distinction the two fields exist to draw. An
// operator serving a publicly-trusted certificate publishes NO chain (PM_TLS_NO_ADVERTISE), so "no chain"
// must NOT be read as "no TLS": that inference is what would let an on-path attacker answer with a plaintext
// greeting and be handed the session token. The chain is trust MATERIAL; advertiseWireTls is the REQUIREMENT.
func TestATLSProxyThatPublishesNoChainStillRequiresTLS(t *testing.T) {
	const publiclyTrustedProxy = `[{
      "name": "public-mysql",
      "engine": "mysql",
      "advertiseAddr": "proxy.example.com:6033",
      "advertiseWireTls": true
    }]`

	var got []driver.Endpoint
	if err := json.Unmarshal([]byte(publiclyTrustedProxy), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got[0].CertChainPEM != "" {
		t.Errorf("this proxy publishes no chain, so CertChainPEM must be empty; got %q", got[0].CertChainPEM)
	}
	if !got[0].WireTLS {
		t.Fatal("a proxy that publishes no chain but serves TLS must still report WireTLS true, or pmon " +
			"would hand the token to anything answering in plaintext")
	}
}

// TestAPlaintextDatasourceReportsNeitherChainNorTLS: with TLS genuinely off, both fields are absent, and only
// then may the broker speak plaintext.
func TestAPlaintextDatasourceReportsNeitherChainNorTLS(t *testing.T) {
	var got []driver.Endpoint
	if err := json.Unmarshal([]byte(`[{"name":"plain","engine":"mysql","advertiseAddr":"h:3306"}]`), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got[0].CertChainPEM != "" {
		t.Errorf("absent chain must decode to empty, got %q", got[0].CertChainPEM)
	}
	if got[0].WireTLS {
		t.Error("absent advertiseWireTls must decode false — defaulting to true would break plaintext datasources")
	}
}
