package tailnet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pires/go-proxyproto"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"

	"github.com/ridi-oss/proxy-monster/cpgo/front"
)

// Host serves the console on 443 with TLS and redirects 80 to https.
type Host struct {
	https, http *http.Server
}

// Serve listens on the Service when service is set, or else on the node itself. TLS uses cert when one is
// given, or else Tailscale's certificate for the tailnet name. served receives each server's end.
func Serve(s *tsnet.Server, st *ipnstate.Status, service string, cert *Cert, handler http.Handler, served chan<- error) (*Host, error) {
	secure, plain, err := listen(s, service, cert == nil)
	if err != nil {
		return nil, err
	}
	if cert != nil {
		secure = tls.NewListener(secure, &tls.Config{GetCertificate: cert.GetCertificate, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12})
	}
	name := func(host string) string { return cert.redirectName(host) }
	if cert == nil {
		fqdn := strings.TrimSuffix(st.Self.DNSName, ".")
		if service != "" {
			fqdn = strings.TrimPrefix(service, "svc:") + "." + st.CurrentTailnet.MagicDNSSuffix
		}
		name = func(string) string { return fqdn }
	}
	h := &Host{
		https: &http.Server{Handler: front.HTTPS(handler), ReadHeaderTimeout: 10 * time.Second},
		http: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+name(r.Host)+r.URL.RequestURI(), http.StatusMovedPermanently)
		}), ReadHeaderTimeout: 10 * time.Second},
	}
	go func() { served <- closed(h.https.Serve(secure)) }()
	go func() { served <- closed(h.http.Serve(plain)) }()
	return h, nil
}

// Shutdown stops both servers, letting in-flight requests finish until ctx ends.
func (h *Host) Shutdown(ctx context.Context) error {
	return errors.Join(h.https.Shutdown(ctx), h.http.Shutdown(ctx))
}

// Close stops both servers at once.
func (h *Host) Close() error { return errors.Join(h.https.Close(), h.http.Close()) }

// listen opens 443 and 80. With tailscaleTLS, 443 arrives with TLS already terminated by tailscaled.
func listen(s *tsnet.Server, service string, tailscaleTLS bool) (secure, plain net.Listener, err error) {
	if service == "" {
		if tailscaleTLS {
			secure, err = s.ListenTLS("tcp", ":443")
		} else {
			secure, err = s.Listen("tcp", ":443")
		}
		if err != nil {
			return nil, nil, fmt.Errorf("tailnet: listening on 443: %w", err)
		}
		if plain, err = s.Listen("tcp", ":80"); err != nil {
			_ = secure.Close()
			return nil, nil, fmt.Errorf("tailnet: listening on 80: %w", err)
		}
		return secure, plain, nil
	}
	if secure, err = listenService(s, service, 443, tailscaleTLS); err != nil {
		return nil, nil, err
	}
	if plain, err = listenService(s, service, 80, false); err != nil {
		_ = secure.Close()
		return nil, nil, err
	}
	return secure, plain, nil
}

// listenService hosts the Service on port. A Service listener is a local socket tsnet forwards to, so the
// tailnet client's address arrives only in the PROXY v2 header tsnet sends; each connection's remote
// address is that client.
func listenService(s *tsnet.Server, service string, port uint16, terminateTLS bool) (net.Listener, error) {
	ln, err := s.ListenService(service, tsnet.ServiceModeTCP{Port: port, TerminateTLS: terminateTLS, PROXYProtocolVersion: 2})
	if err != nil {
		return nil, fmt.Errorf("tailnet: hosting %s on %d: %w", service, port, err)
	}
	return &proxyproto.Listener{
		Listener:          ln,
		ConnPolicy:        func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) { return proxyproto.REQUIRE, nil },
		ReadHeaderTimeout: 5 * time.Second,
	}, nil
}

func closed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("tailnet: %w", err)
}
