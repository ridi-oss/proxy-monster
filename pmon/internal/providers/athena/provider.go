package athena

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/internal/providers/httpapi"
)

const maxRequestBytes = 2 << 20

var regionPattern = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)

// Provider brokers a local Athena endpoint: a client signs with its local access key, pmon verifies the
// signature, drops the client's credentials and hop headers, and re-signs the request with the current
// proxy-monster token as a bearer credential over verified HTTPS to the datasource proxy. The endpoint and
// its region come from the datasource's published ConnectionInfo; the route key is the whole advertisement,
// so a changed endpoint, region, or trust chain replaces the listener.
type Provider struct{}

func (Provider) Engine() string { return "athena" }

func (Provider) SupportedFormats() []driver.Format {
	return []driver.Format{driver.CLI, driver.URL, driver.JDBC, "python", "node", "aws-config"}
}

// CLI is the default: the AWS CLI is what every Athena user already has, and the command carries the
// local access key, region, workgroup, and execution context in one paste.
func (Provider) DefaultFormat() driver.Format { return driver.CLI }

func (Provider) UnavailableReason(endpoint driver.Endpoint) string {
	if reason := httpapi.Unavailable(endpoint); reason != "" {
		return reason
	}
	if !regionPattern.MatchString(endpoint.ConnectionInfo.Properties["region"]) {
		return "Athena region required"
	}
	return ""
}

func (Provider) RouteKey(endpoint driver.Endpoint) string {
	data, _ := json.Marshal(endpoint)
	return string(data)
}

func (Provider) Serve(ctx context.Context, listener net.Listener, resolve driver.ResolveSession) error {
	handler := &broker{resolve: resolve}
	defer handler.upstream.Close()
	return httpapi.Serve(ctx, listener, handler)
}

type broker struct {
	resolve  driver.ResolveSession
	upstream httpapi.Upstream
}

func (b *broker) ServeHTTP(w http.ResponseWriter, incoming *http.Request) {
	endpoint, credentials, ok := b.resolve()
	if !ok || credentials.Principal == "" || credentials.Token == "" || credentials.LocalPassword == "" {
		writeError(w, http.StatusForbidden, "AccessDeniedException", "pmon.sessionUnavailable")
		return
	}
	if incoming.Method != http.MethodPost || incoming.URL.Path != "/" || incoming.URL.RawQuery != "" || incoming.URL.ForceQuery {
		writeError(w, http.StatusBadRequest, "InvalidRequestException", "pmon.athena.invalidRequest")
		return
	}
	if (Provider{}).UnavailableReason(endpoint) != "" {
		writeError(w, http.StatusServiceUnavailable, "InternalServerException", "pmon.athena.endpointUnavailable")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, incoming.Body, maxRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "InvalidRequestException", "pmon.athena.requestTooLarge")
		} else {
			writeError(w, http.StatusBadRequest, "InvalidRequestException", "pmon.athena.invalidRequest")
		}
		return
	}
	local := localCredentials(credentials.Principal, endpoint.Name, credentials.LocalPassword)
	if err := verifySignature(incoming, body, local, endpoint.ConnectionInfo.Properties["region"], time.Now()); err != nil {
		writeError(w, http.StatusForbidden, "UnrecognizedClientException", "pmon.athena.invalidSignature")
		return
	}
	if err := b.upstream.Forward(w, incoming, endpoint, credentials.Token, bytes.NewReader(body)); err != nil {
		writeError(w, http.StatusBadGateway, "InternalServerException", "pmon.athena.upstreamUnavailable")
	}
}

func writeError(w http.ResponseWriter, status int, kind, code string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-Errortype", kind)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": kind, "Message": code})
}
