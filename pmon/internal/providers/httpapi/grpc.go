package httpapi

import (
	"io"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

// gRPC status codes pmon answers with itself.
const (
	GRPCPermissionDenied = 7
	GRPCUnimplemented    = 12
	GRPCUnavailable      = 14
	GRPCUnauthenticated  = 16
)

// IsGRPC reports a gRPC call: HTTP/2 with a gRPC content type.
func IsGRPC(r *http.Request) bool {
	return r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
}

// WriteGRPCError answers a gRPC call with a trailers-only status.
func WriteGRPCError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", strconv.Itoa(code))
	w.Header().Set("Grpc-Message", message)
	w.WriteHeader(http.StatusOK)
}

// ForwardGRPC relays a gRPC call to the same method on the endpoint over HTTP/2, authenticated by token, and
// streams the response and its trailers back. An error means nothing was written.
func (u *Upstream) ForwardGRPC(w http.ResponseWriter, incoming *http.Request, endpoint driver.Endpoint, token string) error {
	target, err := EndpointURL(endpoint)
	if err != nil {
		return err
	}
	target.Path, target.RawPath = incoming.URL.Path, incoming.URL.RawPath
	request, err := http.NewRequestWithContext(incoming.Context(), http.MethodPost, target.String(), incoming.Body)
	if err != nil {
		return err
	}
	request.Header = UpstreamHeaders(incoming.Header)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Te", "trailers")
	_, streams, err := u.transports(endpoint.CertChainPEM)
	if err != nil {
		return err
	}
	response, err := streams.RoundTrip(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	// A result stream outlives the local server's REST deadlines.
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Time{})
	_ = controller.SetWriteDeadline(time.Time{})
	maps.Copy(w.Header(), WithoutHopHeaders(response.Header))
	w.WriteHeader(response.StatusCode)
	buffer := make([]byte, 64<<10)
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			if _, err := w.Write(buffer[:n]); err != nil {
				return nil
			}
			_ = controller.Flush()
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			w.Header().Set(http.TrailerPrefix+"Grpc-Status", strconv.Itoa(GRPCUnavailable))
			return nil
		}
	}
	for name, values := range response.Trailer {
		for _, value := range values {
			w.Header().Add(http.TrailerPrefix+name, value)
		}
	}
	return nil
}
