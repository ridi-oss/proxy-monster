package httpdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrBodyTooLarge = errors.New("httpdb: request body exceeds limit")
	ErrUnsigned     = errors.New("httpdb: upstream signing required")
)

// AuthorizeRequest must authenticate and authorize the operation and return the body to send upstream.
type AuthorizeRequest func(context.Context, *http.Request, []byte) ([]byte, error)

// SignRequest adds upstream credentials to the final request without changing its body or destination.
type SignRequest func(context.Context, *http.Request, []byte) error

// ForwardOptions fixes where a request may go and who may approve it. Endpoint is the only destination the
// signer may produce; Authorize sees every request before it leaves and may rewrite the body.
type ForwardOptions struct {
	Endpoint     string
	MaxBodyBytes int64
	Authorize    AuthorizeRequest
	Sign         SignRequest
	Transport    http.RoundTripper
	// KeepPath sends the incoming path and query under Endpoint's origin instead of to Endpoint itself.
	KeepPath bool
}

// Forwarder relays one authenticated client request to the fixed upstream endpoint: read and bound the body,
// have Authorize approve or rewrite it, drop the client's credentials and hop headers, sign with the
// proxy's upstream credentials, and refuse if the signer changed the destination. Responses are not buffered.
type Forwarder struct {
	endpoint     *url.URL
	keepPath     bool
	maxBodyBytes int64
	authorize    AuthorizeRequest
	sign         SignRequest
	client       *http.Client
}

// UpstreamEndpoint accepts only a bare HTTPS origin, the one shape the forwarder may sign requests for.
func UpstreamEndpoint(raw string) (string, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Hostname() == "" || endpoint.Scheme != "https" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return "", errors.New("httpdb: fixed HTTPS upstream endpoint required")
	}
	return endpoint.String(), nil
}

func NewForwarder(options ForwardOptions) (*Forwarder, error) {
	raw, err := UpstreamEndpoint(options.Endpoint)
	if err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if options.KeepPath && endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errors.New("httpdb: a path-keeping forwarder needs a bare origin")
	}
	if options.MaxBodyBytes <= 0 || options.MaxBodyBytes == math.MaxInt64 {
		return nil, errors.New("httpdb: positive finite request body limit required")
	}
	if options.Authorize == nil {
		return nil, ErrUnauthorized
	}
	if options.Sign == nil {
		return nil, ErrUnsigned
	}
	return &Forwarder{
		endpoint:     endpoint,
		keepPath:     options.KeepPath,
		maxBodyBytes: options.MaxBodyBytes,
		authorize:    options.Authorize,
		sign:         options.Sign,
		client: &http.Client{
			Transport: options.Transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Forward returns the upstream response without buffering it; the caller must close its body.
func (f *Forwarder) Forward(incoming *http.Request) (*http.Response, error) {
	if f == nil || f.authorize == nil {
		return nil, ErrUnauthorized
	}
	if f.sign == nil {
		return nil, ErrUnsigned
	}
	ctx := incoming.Context()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if incoming.ContentLength > f.maxBodyBytes {
		return nil, ErrBodyTooLarge
	}
	body := incoming.Body
	if body == nil {
		body = http.NoBody
	}
	data, err := io.ReadAll(io.LimitReader(body, f.maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > f.maxBodyBytes {
		return nil, ErrBodyTooLarge
	}
	approved, err := f.authorize(ctx, incoming, bytes.Clone(data))
	if err != nil {
		return nil, err
	}
	if approved == nil {
		return nil, ErrUnauthorized
	}
	if int64(len(approved)) > f.maxBodyBytes {
		return nil, ErrBodyTooLarge
	}
	if !bytes.Equal(data, approved) {
		for name := range incoming.Header {
			if isBodyChecksum(name) {
				return nil, fmt.Errorf("httpdb: cannot rewrite a request with %s", name)
			}
		}
	}
	destination := *f.endpoint
	if f.keepPath {
		destination.Path, destination.RawPath, destination.RawQuery = incoming.URL.Path, incoming.URL.RawPath, incoming.URL.RawQuery
	}
	target := destination.String()
	outgoing, err := http.NewRequestWithContext(ctx, incoming.Method, target, bytes.NewReader(approved))
	if err != nil {
		return nil, err
	}
	outgoing.GetBody = nil
	outgoing.Header = upstreamHeaders(incoming.Header)
	if err := f.sign(ctx, outgoing, bytes.Clone(approved)); err != nil {
		return nil, err
	}
	if outgoing.Header.Get("Authorization") == "" {
		return nil, ErrUnsigned
	}
	if outgoing.URL.String() != target || outgoing.Host != outgoing.URL.Host {
		return nil, errors.New("httpdb: signer changed upstream destination")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	response, err := f.client.Do(outgoing)
	if err != nil {
		return nil, fmt.Errorf("httpdb: forward request: %w", err)
	}
	return response, nil
}

// upstreamHeaders is the incoming header set with client credentials, identity, and hop headers removed.
func upstreamHeaders(incoming http.Header) http.Header {
	hopHeaders := make(map[string]bool)
	for name, values := range incoming {
		if strings.EqualFold(name, "Connection") {
			for _, value := range values {
				for _, name := range strings.Split(value, ",") {
					hopHeaders[strings.ToLower(strings.TrimSpace(name))] = true
				}
			}
		}
	}
	header := make(http.Header)
	for name, values := range incoming {
		if hopHeaders[strings.ToLower(name)] || stripRequestHeader(name) {
			continue
		}
		name = http.CanonicalHeaderKey(name)
		header[name] = append(header[name], values...)
	}
	// The server masks and refuses encoded bodies, so no response may be encoded.
	header.Set("Accept-Encoding", "identity")
	return header
}

func stripRequestHeader(name string) bool {
	name = strings.ToLower(name)
	for _, prefix := range []string{"x-pm-", "x-pmon-", "x-proxy-monster-", "x-forwarded-", "x-auth-request-", "x-amzn-oidc-", "x-amzn-mtls-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	switch name {
	case "connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade",
		"host", "content-length", "authorization", "proxy-authorization", "proxy-authenticate", "cookie", "cookie2", "set-cookie",
		"forwarded", "x-real-ip", "x-client-ip", "client-ip", "true-client-ip", "x-original-forwarded-for",
		"cf-connecting-ip", "cf-connecting-ipv6", "remote-user", "x-remote-user", "x-authenticated-user", "x-authenticated-groups",
		"x-auth-token", "x-api-key", "date", "x-amz-date", "x-amz-security-token", "x-amz-content-sha256",
		"x-amz-algorithm", "x-amz-credential", "x-amz-signedheaders", "x-amz-signature", "x-amz-expires", "x-amz-region-set", "x-amz-sso-bearer-token":
		return true
	}
	return false
}

func isBodyChecksum(name string) bool {
	name = strings.ToLower(name)
	return name == "content-md5" || name == "digest" || name == "content-digest" || name == "repr-digest" ||
		(strings.HasPrefix(name, "x-amz-checksum-") && name != "x-amz-checksum-mode")
}
