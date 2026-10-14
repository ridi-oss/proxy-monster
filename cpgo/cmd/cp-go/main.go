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
	"strconv"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"google.golang.org/grpc"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/child"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/routes"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
	"github.com/ridi-oss/proxy-monster/cpgo/store"
	"github.com/ridi-oss/proxy-monster/cpgo/tailnet"
)

type config struct {
	HTTPPort       int            `env:"PM_HTTP_PORT" default:"8080" help:"Public HTTP port."`
	GRPCPort       int            `env:"PM_GRPC_PORT" default:"9090" help:"Public gRPC port."`
	TrustedProxies []string       `env:"PM_TRUSTED_PROXIES" sep:"," help:"Peers whose X-Forwarded-* headers are honored."`
	Child          string         `env:"PM_CP_CHILD" default:"/app/bin/control-plane" help:"Kotlin control plane start script."`
	ChildHTTPPort  int            `env:"PM_CP_CHILD_HTTP_PORT" default:"18090" help:"Loopback HTTP port of the Kotlin control plane."`
	ChildGRPCPort  int            `env:"PM_CP_CHILD_GRPC_PORT" default:"18091" help:"Loopback gRPC port of the Kotlin control plane."`
	Attach         bool           `env:"PM_CP_ATTACH" help:"Forward to a Kotlin control plane already running on the child ports instead of starting one."`
	StartTimeout   time.Duration  `env:"PM_CP_START_TIMEOUT" default:"10m" help:"How long to wait for the Kotlin control plane to become healthy."`
	Tailnet        tailnet.Config `embed:"" prefix:"tailnet-"`
	// Shared with the Kotlin child, which reads them from the environment, so they are never flags.
	DBURL         string `kong:"-"`
	DBUser        string `kong:"-"`
	DBPassword    string `kong:"-"`
	SessionSecret string `kong:"-"`
	AuthDebug     bool   `kong:"-"`
	// InternalToken authenticates cp-go to the child; generated per boot unless attaching.
	InternalToken string `kong:"-"`
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func main() {
	var cfg config
	kong.Parse(&cfg, kong.Name("cp-go"), kong.Description("proxy-monster control plane front door."))
	cfg.DBURL = envOr("PM_DB_URL", "jdbc:postgresql://localhost:5432/proxymonster")
	cfg.DBUser = envOr("PM_DB_USER", "proxymonster")
	cfg.DBPassword = envOr("PM_DB_PASSWORD", "proxymonster")
	cfg.SessionSecret = envOr("PM_SESSION_SECRET", "dev-insecure-session-secret-change-me")
	cfg.AuthDebug = envOr("PM_AUTH_DEBUG", "true") == "true"
	cfg.InternalToken = os.Getenv("PM_CP_INTERNAL_TOKEN")
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
	if !cfg.Attach {
		var err error
		if kt, err = child.Start(cfg.Child, cfg.ChildHTTPPort, cfg.ChildGRPCPort, internalToken); err != nil {
			slog.Error("cp-go: " + err.Error())
			return 1
		}
		exited = kt.Done()
	}

	httpUpstream := &url.URL{Scheme: "http", Host: loopback(cfg.ChildHTTPPort)}
	startCtx, cancelStart := context.WithTimeout(ctx, cfg.StartTimeout)
	err := child.WaitHealthy(startCtx, httpUpstream.String()+"/health", exited)
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

	serve := func(edges front.TrustedEdges) http.Handler {
		mux := http.NewServeMux()
		routes.Register(mux, pool, api.Gate{
			Sessions:      session.NewResolver(pool, cfg.SessionSecret),
			EndMismatched: api.KotlinSessionCheck(httpUpstream),
			Edges:         edges,
			AuthDebug:     cfg.AuthDebug,
		}, bridge.New(httpUpstream, internalToken))
		return front.Route(mux, front.NewHTTP(httpUpstream, edges))
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
	served := make(chan error, 4)
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
