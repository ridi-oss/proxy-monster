// cp-go is the control plane's front door. It owns the public HTTP and gRPC ports, runs the Kotlin
// control plane as a child on loopback, and forwards to it everything Go does not serve yet.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"google.golang.org/grpc"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/child"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/gobridge"
	bridgepb "github.com/ridi-oss/proxy-monster/cpgo/gobridge/pb"
	"github.com/ridi-oss/proxy-monster/cpgo/idp"
	"github.com/ridi-oss/proxy-monster/cpgo/routes"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/oidc"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
	"github.com/ridi-oss/proxy-monster/cpgo/store"
	"github.com/ridi-oss/proxy-monster/cpgo/tailnet"
)

type config struct {
	HTTPPort       int            `env:"PM_HTTP_PORT" default:"8080" help:"Public HTTP port."`
	GRPCPort       int            `env:"PM_GRPC_PORT" default:"9090" help:"Public gRPC port."`
	TrustedProxies []string       `env:"PM_TRUSTED_PROXIES" sep:"," help:"Peers whose X-Forwarded-* headers are honored."`
	WebURL         string         `env:"PM_WEB_URL" help:"Web console cp-go forwards non-control-plane paths to, e.g. http://web:3000. Empty serves only the control plane's paths."`
	Child          string         `env:"PM_CP_CHILD" default:"/app/bin/control-plane" help:"Kotlin control plane start script."`
	ChildHTTPPort  int            `env:"PM_CP_CHILD_HTTP_PORT" default:"18090" help:"Loopback HTTP port of the Kotlin control plane."`
	ChildGRPCPort  int            `env:"PM_CP_CHILD_GRPC_PORT" default:"18091" help:"Loopback gRPC port of the Kotlin control plane."`
	Attach         bool           `env:"PM_CP_ATTACH" help:"Forward to a Kotlin control plane already running on the child ports instead of starting one."`
	StartTimeout   time.Duration  `env:"PM_CP_START_TIMEOUT" default:"10m" help:"How long to wait for the Kotlin control plane to become healthy."`
	Tailnet        tailnet.Config `embed:"" prefix:"tailnet-"`
	GitHub         githubConfig   `embed:"" prefix:"github-"`
	BridgePort     int            `env:"PM_CP_GO_GRPC_PORT" default:"0" help:"Loopback port the Kotlin control plane calls Go on; 0 picks a free one. Set it, and the child's PM_CP_GO_GRPC_ADDR, with PM_CP_ATTACH."`
	InternalToken  string         `env:"PM_CP_INTERNAL_TOKEN" hidden:"" help:"Token cp-go and the Kotlin control plane share; generated per boot unless attaching."`

	// The Kotlin child reads these too; kotlinEnv hands it the values parsed here.
	DBURL      string `env:"PM_DB_URL" name:"db-url" default:"jdbc:postgresql://localhost:5432/proxymonster" group:"kotlin" help:"Control-plane store, as a JDBC URL."`
	DBUser     string `env:"PM_DB_USER" default:"proxymonster" group:"kotlin" help:"Control-plane store user."`
	DBPassword string `env:"PM_DB_PASSWORD" default:"proxymonster" hidden:"" group:"kotlin" help:"Control-plane store password."`

	SessionSecret       string `env:"PM_SESSION_SECRET" default:"dev-insecure-session-secret-change-me" hidden:"" group:"kotlin" help:"Signs the session cookies."`
	AuthDebug           bool   `env:"PM_AUTH_DEBUG" default:"true" negatable:"" group:"kotlin" help:"Offer POST /auth/debug, a login as any principal. Never in production."`
	MCPResource         string `env:"PM_MCP_RESOURCE" default:"http://127.0.0.1:8080/mcp" group:"kotlin" help:"Public URL of the MCP endpoint; its origin is the control plane's."`
	WebOrigin           string `env:"PM_WEB_ORIGIN" group:"kotlin" help:"Origin of the web console when it is not the control plane's."`
	ResultKey           string `env:"PM_RESULT_KEY" hidden:"" group:"kotlin" help:"Base64 AES-256 key for stored results and refresh tokens."`
	ElevatedScopeTTL    string `env:"PM_ELEVATED_SCOPE_TTL" default:"3600" group:"kotlin" help:"Seconds MCP scopes beyond read and query last after approval."`
	OAuthAccessTTL      string `env:"PM_OAUTH_ACCESS_TTL" name:"oauth-access-ttl" default:"600" group:"kotlin" help:"Seconds an MCP access token lasts."`
	SessionWindow       string `env:"PM_SESSION_WINDOW" default:"7200" group:"kotlin" help:"Wire session window: seconds, or h/m/s as in 1h30m."`
	WebAbsolute         string `env:"PM_WEB_SESSION_ABSOLUTE" default:"7200" group:"kotlin" help:"Web session lifetime."`
	WebIdle             string `env:"PM_WEB_SESSION_IDLE" default:"900" group:"kotlin" help:"Web session idle timeout."`
	WebSlide            string `env:"PM_WEB_SESSION_SLIDE" default:"120" group:"kotlin" help:"How often a web session's idle clock is renewed."`
	WebIdleWarnLead     string `env:"PM_WEB_SESSION_IDLE_WARN_LEAD" default:"60" group:"kotlin" help:"Warn this long before the idle timeout."`
	WebAbsoluteWarnLead string `env:"PM_WEB_SESSION_ABSOLUTE_WARN_LEAD" default:"300" group:"kotlin" help:"Warn this long before the session lifetime ends."`
	WebHeartbeat        string `env:"PM_WEB_SESSION_HEARTBEAT" default:"90" group:"kotlin" help:"Web session heartbeat interval."`

	OIDCIssuer         string `env:"PM_OIDC_ISSUER" group:"kotlin" help:"OIDC issuer; OIDC login is on when the issuer, client ID, client secret, and redirect URI are set."`
	OIDCClientID       string `env:"PM_OIDC_CLIENT_ID" group:"kotlin" help:"OIDC client ID."`
	OIDCClientSecret   string `env:"PM_OIDC_CLIENT_SECRET" hidden:"" group:"kotlin" help:"OIDC client secret."`
	OIDCRedirectURI    string `env:"PM_OIDC_REDIRECT_URI" group:"kotlin" help:"OIDC redirect URI, the control plane's /auth/oidc/callback."`
	OIDCScopes         string `env:"PM_OIDC_SCOPES" default:"openid profile email groups offline_access" group:"kotlin" help:"OIDC scopes requested at login."`
	OIDCGroupMap       string `env:"PM_OIDC_GROUP_MAP" group:"kotlin" help:"IdP groups mapped to local groups, e.g. idp-admins=system:admin."`
	OIDCGroupPrefix    string `env:"PM_OIDC_GROUP_PREFIX" group:"kotlin" help:"Prefix stripped from unmapped IdP groups."`
	OIDCUserAttributes string `env:"PM_OIDC_USER_ATTRIBUTES" group:"kotlin" help:"id_token claims kept as Cedar User attributes; read only with OIDC login on."`
	IdPRecheck         string `env:"PM_IDP_RECHECK_INTERVAL" name:"idp-recheck-interval" default:"300" group:"kotlin" help:"Seconds between IdP liveness rechecks of each session."`

	Session session.Settings `kong:"-"`
	// OIDC is nil unless OIDC login is on.
	OIDC *idp.Config `kong:"-"`
}

// kotlinEnv is the group:"kotlin" settings as parsed here, so the child uses the values Go uses wherever they
// came from. An empty string leaves the child's environment as it is.
func (c config) kotlinEnv() []string {
	var env []string
	var walk func(reflect.Value)
	walk = func(v reflect.Value) {
		for i := range v.NumField() {
			f, fv := v.Type().Field(i), v.Field(i)
			switch {
			case fv.Kind() == reflect.Struct:
				walk(fv)
			case f.Tag.Get("group") != "kotlin":
			case fv.Kind() == reflect.Bool:
				env = append(env, f.Tag.Get("env")+"="+strconv.FormatBool(fv.Bool()))
			case fv.String() != "":
				env = append(env, f.Tag.Get("env")+"="+fv.String())
			}
		}
	}
	walk(reflect.ValueOf(c))
	return env
}

// sessionSettings is the web-session settings as Kotlin's Config reads them, refusing a duration Kotlin refuses.
func sessionSettings(c config) (session.Settings, error) {
	s := session.Settings{
		Secret:      c.SessionSecret,
		AuthDebug:   c.AuthDebug,
		Secure:      strings.HasPrefix(c.MCPResource, "https://"),
		ResultKey:   c.ResultKey != "",
		WebOrigin:   c.WebOrigin,
		OIDCEnabled: c.oidcConfigured(),

		MCPResource:      session.CanonicalResource(c.MCPResource),
		ElevatedScopeTTL: session.ClampSeconds(c.ElevatedScopeTTL, 3600),
		MCPAccessTTL:     session.ClampSeconds(c.OAuthAccessTTL, 600),
	}
	for _, d := range []struct {
		env, raw string
		dst      *int64
	}{
		{"PM_WEB_SESSION_ABSOLUTE", c.WebAbsolute, &s.AbsoluteSeconds},
		{"PM_WEB_SESSION_IDLE", c.WebIdle, &s.IdleSeconds},
		{"PM_WEB_SESSION_SLIDE", c.WebSlide, &s.SlideSeconds},
		{"PM_WEB_SESSION_IDLE_WARN_LEAD", c.WebIdleWarnLead, &s.IdleWarnLeadSeconds},
		{"PM_WEB_SESSION_ABSOLUTE_WARN_LEAD", c.WebAbsoluteWarnLead, &s.AbsoluteWarnLeadSeconds},
		{"PM_WEB_SESSION_HEARTBEAT", c.WebHeartbeat, &s.HeartbeatSeconds},
		{"PM_SESSION_WINDOW", c.SessionWindow, &s.SessionWindowSeconds},
	} {
		v, err := session.ParseDuration(d.raw)
		if err != nil {
			return s, fmt.Errorf("%s: %w", d.env, err)
		}
		*d.dst = v
	}
	return s, nil
}

// oidcSettings is the OIDC client Kotlin's Config reads, nil when OIDC login is off.
func oidcSettings(c config) (*idp.Config, error) {
	n, err := strconv.ParseInt(c.IdPRecheck, 10, 64)
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("PM_IDP_RECHECK_INTERVAL must be a positive number of seconds: %q", c.IdPRecheck)
	}
	if !c.oidcConfigured() {
		return nil, nil
	}
	return &idp.Config{
		Issuer: c.OIDCIssuer, ClientID: c.OIDCClientID, ClientSecret: c.OIDCClientSecret, RedirectURI: c.OIDCRedirectURI,
		Scopes: c.OIDCScopes, RecheckInterval: time.Duration(n) * time.Second,
		Groups: idp.ParseGroupMapping(c.OIDCGroupMap, c.OIDCGroupPrefix),
	}, nil
}

func (c config) oidcConfigured() bool {
	return c.OIDCIssuer != "" && c.OIDCClientID != "" && c.OIDCClientSecret != "" && c.OIDCRedirectURI != ""
}

func main() {
	var cfg config
	kong.Parse(&cfg, kong.Name("cp-go"), kong.Description("proxy-monster control plane front door."),
		kong.ExplicitGroups([]kong.Group{{Key: "kotlin", Title: "Shared with the Kotlin control plane"}}))
	var err error
	if cfg.Session, err = sessionSettings(cfg); err == nil {
		cfg.OIDC, err = oidcSettings(cfg)
	}
	if err != nil {
		slog.Error("cp-go: " + err.Error())
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	code := run(ctx, cfg)
	stop()
	os.Exit(code)
}

// run serves until ctx ends or the child exits, and returns the process exit code.
func run(ctx context.Context, cfg config) int {
	if err := cfg.Tailnet.Validate(); err != nil {
		slog.Error("cp-go: " + err.Error())
		return 1
	}
	var web *url.URL
	if cfg.WebURL != "" {
		u, err := url.Parse(cfg.WebURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			slog.Error(fmt.Sprintf("cp-go: PM_WEB_URL must be an http(s) URL, got %q", cfg.WebURL))
			return 1
		}
		web = u
	}
	// Kotlin declares PM_OIDC_USER_ATTRIBUTES only with OIDC login on.
	userAttributes := ""
	if cfg.OIDC != nil {
		userAttributes = cfg.OIDCUserAttributes
	}
	attrs, err := authz.ParseUserAttributes(userAttributes)
	var schema *authz.Schema
	if err == nil {
		schema, err = authz.NewSchema(attrs)
	}
	if err != nil {
		slog.Error("cp-go: " + err.Error())
		return 1
	}
	crypto, err := idp.NewCrypto(cfg.ResultKey)
	if err != nil {
		slog.Error("cp-go: " + err.Error())
		return 1
	}
	var kt *child.Child
	var exited <-chan struct{}
	internalToken := cfg.InternalToken
	if internalToken == "" {
		if cfg.Attach {
			slog.Error("cp-go: PM_CP_ATTACH needs PM_CP_INTERNAL_TOKEN, set to the same value for the Kotlin control plane")
			return 1
		}
		internalToken = rand.Text()
	}
	// Before the child starts, so its first call into Go finds the bridge.
	served := make(chan error, 5)
	goBridge, err := startBridge(ctx, cfg, internalToken, served)
	if err != nil {
		slog.Error("cp-go: " + err.Error())
		return 1
	}
	// Closed after drain has stopped the child, which may still call Go while it drains.
	defer goBridge.Close()
	childEnv := append(append(withoutKeys(os.Environ()), cfg.kotlinEnv()...), goBridge.Env())
	if !cfg.Attach {
		if kt, err = child.Start(cfg.Child, cfg.ChildHTTPPort, cfg.ChildGRPCPort, internalToken, childEnv); err != nil {
			slog.Error("cp-go: " + err.Error())
			return 1
		}
		exited = kt.Done()
	}

	httpUpstream := &url.URL{Scheme: "http", Host: loopback(cfg.ChildHTTPPort)}
	startCtx, cancelStart := context.WithTimeout(ctx, cfg.StartTimeout)
	err = child.WaitHealthy(startCtx, httpUpstream.String()+"/health", exited)
	cancelStart()
	if err != nil {
		slog.Error("cp-go: " + err.Error())
		return shutdownChild(kt)
	}

	conn, err := front.DialUpstream(loopback(cfg.ChildGRPCPort))
	if err != nil {
		slog.Error("cp-go: " + err.Error())
		return shutdownChild(kt)
	}
	defer conn.Close()

	// Opened after the child is healthy, so its migrations have run.
	pool, err := store.Open(ctx, cfg.DBURL, cfg.DBUser, cfg.DBPassword)
	if err != nil {
		slog.Error("cp-go: " + err.Error())
		return shutdownChild(kt)
	}
	defer pool.Close()

	kotlin := bridge.New(httpUpstream, internalToken)
	resolver := session.NewResolver(pool, cfg.Session)
	login := oidc.Login{Crypto: crypto, Schema: schema}
	if cfg.OIDC != nil {
		login.Provider = idp.NewProvider(*cfg.OIDC)
		go oidc.Liveness{Pool: pool, Sessions: resolver, Kotlin: kotlin, Provider: login.Provider, Crypto: crypto, Schema: schema}.Run(ctx)
	}
	serve := func(edges front.TrustedEdges) http.Handler {
		mux := http.NewServeMux()
		routes.Register(mux, pool, api.Gate{
			Sessions:  resolver,
			Edges:     edges,
			AuthDebug: cfg.Session.AuthDebug,
			Authz:     authz.NewDecider(pool, schema),
			Kotlin:    kotlin,
		}, login)
		h := front.Route(mux, front.NewHTTP(httpUpstream, edges))
		if web != nil {
			h = front.Split(h, front.NewHTTP(web, edges))
		}
		return h
	}
	httpSrv := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.HTTPPort),
		Handler:           serve(front.ParseTrustedEdges(cfg.TrustedProxies)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	grpcSrv := front.NewGRPC(conn)

	httpLn, err := net.Listen("tcp", httpSrv.Addr)
	if err != nil {
		slog.Error("cp-go: listening for HTTP: " + err.Error())
		return shutdownChild(kt)
	}
	grpcLn, err := net.Listen("tcp", ":"+strconv.Itoa(cfg.GRPCPort))
	if err != nil {
		_ = httpLn.Close()
		slog.Error("cp-go: listening for gRPC: " + err.Error())
		return shutdownChild(kt)
	}
	go func() { served <- ignoreClosed(httpSrv.Serve(httpLn)) }()
	go func() { served <- grpcSrv.Serve(grpcLn) }()
	slog.Info("cp-go: serving", "http", cfg.HTTPPort, "grpc", cfg.GRPCPort, "upstream_http", cfg.ChildHTTPPort, "upstream_grpc", cfg.ChildGRPCPort)

	httpSrvs := []httpServer{httpSrv}
	if cfg.Tailnet.Enabled() {
		// A tailnet client is never a trusted proxy: its own address is the requester, whatever it sends.
		handler := serve(front.TrustedEdges{})
		// Bounded, and cut short if the child exits: a login can wait on approval forever.
		joinCtx, cancelJoin := context.WithTimeout(ctx, cfg.StartTimeout)
		go func() {
			select {
			case <-exited:
				cancelJoin()
			case <-joinCtx.Done():
			}
		}()
		host, closeNode, err := hostTailnet(joinCtx, ctx, cfg.Tailnet, handler, served)
		cancelJoin()
		if err != nil {
			slog.Error("cp-go: " + err.Error())
			drain(kt, grpcSrv, httpSrv)
			return 1
		}
		defer closeNode()
		httpSrvs = append(httpSrvs, host)
		slog.Info("cp-go: serving on the tailnet", "service", cfg.Tailnet.Service, "hostname", cfg.Tailnet.NodeName())
	}

	code := 0
	select {
	case <-ctx.Done():
		slog.Info("cp-go: shutting down")
	case <-exited:
		slog.Error("cp-go: control plane exited", "err", kt.Err())
		code = kt.ExitCode()
		if code == 0 {
			code = 1
		}
	case err := <-served:
		slog.Error("cp-go: server stopped", "err", err)
		code = 1
	}
	drain(kt, grpcSrv, httpSrvs...)
	return code
}

const (
	childGrace   = 30 * time.Second
	forwardGrace = 5 * time.Second
)

// drain stops accepting new work and lets the child close its own streams (Events, SSE) with the
// reconnect hints it sends on SIGTERM. Once the child is gone, forwarding gets forwardGrace to relay
// what the child already wrote before the rest is cut.
func drain(kt *child.Child, grpcSrv *grpc.Server, httpSrvs ...httpServer) {
	grpcDone := make(chan struct{})
	go func() { grpcSrv.GracefulStop(); close(grpcDone) }()
	dones := []chan struct{}{grpcDone}
	for _, srv := range httpSrvs {
		done := make(chan struct{})
		go func() { _ = srv.Shutdown(context.Background()); close(done) }()
		dones = append(dones, done)
	}
	if kt != nil {
		kt.Stop(childGrace)
	}
	grace, cancel := context.WithTimeout(context.Background(), forwardGrace)
	defer cancel()
	for _, done := range dones {
		select {
		case <-done:
		case <-grace.Done():
		}
	}
	grpcSrv.Stop()
	for _, srv := range httpSrvs {
		_ = srv.Close()
	}
}

// httpServer is what drain stops: the public HTTP server and the tailnet host.
type httpServer interface {
	Shutdown(context.Context) error
	Close() error
}

// startBridge serves the Go services the Kotlin child calls (cpgo/gobridge).
func startBridge(ctx context.Context, cfg config, token string, served chan<- error) (*gobridge.Server, error) {
	gh, err := newGitHub(ctx, cfg.GitHub)
	if err != nil {
		return nil, err
	}
	if cfg.Attach && cfg.BridgePort == 0 && gh != nil {
		return nil, errors.New("PM_CP_ATTACH with PM_GITHUB_APP_ID needs PM_CP_GO_GRPC_PORT, matching the Kotlin control plane's PM_CP_GO_GRPC_ADDR")
	}
	s, err := gobridge.Listen(cfg.BridgePort, token)
	if err != nil {
		return nil, err
	}
	if gh != nil {
		bridgepb.RegisterGitHubSourceServer(s.GRPC(), gh)
	}
	s.Serve(served)
	return s, nil
}

// hostTailnet joins the tailnet and serves the console there, with the ACM certificate when one is set,
// kept fresh daily.
func hostTailnet(startCtx, ctx context.Context, c tailnet.Config, handler http.Handler, served chan<- error) (*tailnet.Host, func(), error) {
	var cert *tailnet.Cert
	if c.CertARN != "" {
		var err error
		if cert, err = tailnet.NewCertFromACM(startCtx, c.CertARN); err != nil {
			return nil, nil, err
		}
		go cert.KeepFresh(ctx, 24*time.Hour)
	}
	ts, st, err := tailnet.Join(startCtx, c)
	if err != nil {
		return nil, nil, err
	}
	host, err := tailnet.Serve(ts, st, c.Service, cert, handler, served)
	if err != nil {
		_ = ts.Close()
		return nil, nil, err
	}
	return host, func() { _ = ts.Close() }, nil
}

func shutdownChild(kt *child.Child) int {
	if kt != nil {
		kt.Stop(childGrace)
	}
	return 1
}

func loopback(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("http: %w", err)
}
