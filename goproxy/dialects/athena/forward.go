package athena

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
	ErrBodyTooLarge = errors.New("athena: request body exceeds limit")
	ErrUnauthorized = errors.New("athena: request authorization required")
	ErrUnsigned     = errors.New("athena: upstream signing required")
)

// AuthorizeRequest must authenticate and authorize the operation and any rewritten envelope.
type AuthorizeRequest func(context.Context, *http.Request, *Envelope) (*Envelope, error)

// SignRequest adds upstream credentials to the final request without changing its body or destination.
type SignRequest func(context.Context, *http.Request, []byte) error

type ForwardOptions struct {
	Endpoint     string
	MaxBodyBytes int64
	Authorize    AuthorizeRequest
	Sign         SignRequest
	Transport    http.RoundTripper
}

type Forwarder struct {
	endpoint     string
	maxBodyBytes int64
	authorize    AuthorizeRequest
	sign         SignRequest
	client       *http.Client
}

func NewForwarder(options ForwardOptions) (*Forwarder, error) {
	endpoint, err := url.Parse(options.Endpoint)
	if err != nil || endpoint.Hostname() == "" || endpoint.Scheme != "https" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return nil, errors.New("athena: fixed HTTPS upstream endpoint required")
	}
	if options.MaxBodyBytes <= 0 || options.MaxBodyBytes == math.MaxInt64 {
		return nil, errors.New("athena: positive finite request body limit required")
	}
	if options.Authorize == nil {
		return nil, ErrUnauthorized
	}
	if options.Sign == nil {
		return nil, ErrUnsigned
	}
	return &Forwarder{
		endpoint:     endpoint.String(),
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

// Forward returns the native response without buffering it; the caller must close its body.
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
	if len(incoming.Header.Values("X-Amz-Target")) > 1 {
		return nil, errors.New("athena: multiple operation headers")
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
	envelope, err := DecodeEnvelope(data)
	if err != nil {
		return nil, err
	}
	approved, err := f.authorize(ctx, incoming, envelope)
	if err != nil {
		return nil, err
	}
	if approved == nil || approved.fields == nil {
		return nil, ErrUnauthorized
	}
	if int64(len(approved.body)) > f.maxBodyBytes {
		return nil, ErrBodyTooLarge
	}
	if !bytes.Equal(data, approved.body) {
		for name := range incoming.Header {
			if isBodyChecksum(name) {
				return nil, fmt.Errorf("athena: cannot rewrite a request with %s", name)
			}
		}
	}
	outgoing, err := http.NewRequestWithContext(ctx, incoming.Method, f.endpoint, bytes.NewReader(approved.body))
	if err != nil {
		return nil, err
	}
	outgoing.GetBody = nil
	outgoing.Header = upstreamHeaders(incoming.Header)
	if err := f.sign(ctx, outgoing, approved.Bytes()); err != nil {
		return nil, err
	}
	if outgoing.Header.Get("Authorization") == "" {
		return nil, ErrUnsigned
	}
	if outgoing.URL.String() != f.endpoint || outgoing.Host != outgoing.URL.Host {
		return nil, errors.New("athena: signer changed upstream destination")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	response, err := f.client.Do(outgoing)
	if err != nil {
		return nil, fmt.Errorf("athena: forward request: %w", err)
	}
	return response, nil
}

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
	// Disable transparent decompression so native response bytes and headers stay paired.
	if header.Get("Accept-Encoding") == "" {
		header.Set("Accept-Encoding", "identity")
	}
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
