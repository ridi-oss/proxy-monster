// cp-go is the control plane's front door. It owns the public HTTP and gRPC ports, runs the Kotlin
// control plane as a child on loopback, and forwards to it everything Go does not serve yet.
package main

import (
	"context"
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

	"github.com/ridi-oss/proxy-monster/cpgo/child"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
)

type config struct {
	HTTPPort       int           `env:"PM_HTTP_PORT" default:"8080" help:"Public HTTP port."`
	GRPCPort       int           `env:"PM_GRPC_PORT" default:"9090" help:"Public gRPC port."`
	TrustedProxies []string      `env:"PM_TRUSTED_PROXIES" sep:"," help:"Peers whose X-Forwarded-* headers are honored."`
	Child          string        `env:"PM_CP_CHILD" default:"/app/bin/control-plane" help:"Kotlin control plane start script."`
	ChildHTTPPort  int           `env:"PM_CP_CHILD_HTTP_PORT" default:"18090" help:"Loopback HTTP port of the Kotlin control plane."`
	ChildGRPCPort  int           `env:"PM_CP_CHILD_GRPC_PORT" default:"18091" help:"Loopback gRPC port of the Kotlin control plane."`
	Attach         bool          `env:"PM_CP_ATTACH" help:"Forward to a Kotlin control plane already running on the child ports instead of starting one."`
	StartTimeout   time.Duration `env:"PM_CP_START_TIMEOUT" default:"10m" help:"How long to wait for the Kotlin control plane to become healthy."`
}

func main() {
	var cfg config
	kong.Parse(&cfg, kong.Name("cp-go"), kong.Description("proxy-monster control plane front door."))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	code := run(ctx, cfg)
	stop()
	os.Exit(code)
}

// run serves until ctx ends or the child exits, and returns the process exit code.
func run(ctx context.Context, cfg config) int {
	var kt *child.Child
	var exited <-chan struct{}
	if !cfg.Attach {
		var err error
		if kt, err = child.Start(cfg.Child, cfg.ChildHTTPPort, cfg.ChildGRPCPort); err != nil {
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

	edges := front.ParseTrustedEdges(cfg.TrustedProxies)
	httpSrv := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.HTTPPort),
		Handler:           front.NewHTTP(httpUpstream, edges),
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
	served := make(chan error, 2)
	go func() { served <- ignoreClosed(httpSrv.Serve(httpLn)) }()
	go func() { served <- grpcSrv.Serve(grpcLn) }()
	slog.Info("cp-go: serving", "http", cfg.HTTPPort, "grpc", cfg.GRPCPort, "upstream_http", cfg.ChildHTTPPort, "upstream_grpc", cfg.ChildGRPCPort)

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
	drain(kt, httpSrv, grpcSrv)
	return code
}

const (
	childGrace   = 30 * time.Second
	forwardGrace = 5 * time.Second
)

// drain stops accepting new work and lets the child close its own streams (Events, SSE) with the
// reconnect hints it sends on SIGTERM. Once the child is gone, forwarding gets forwardGrace to relay
// what the child already wrote before the rest is cut.
func drain(kt *child.Child, httpSrv *http.Server, grpcSrv *grpc.Server) {
	grpcDone := make(chan struct{})
	go func() { grpcSrv.GracefulStop(); close(grpcDone) }()
	httpDone := make(chan struct{})
	go func() { _ = httpSrv.Shutdown(context.Background()); close(httpDone) }()
	if kt != nil {
		kt.Stop(childGrace)
	}
	deadline := time.After(forwardGrace)
	for _, done := range []chan struct{}{grpcDone, httpDone} {
		select {
		case <-done:
		case <-deadline:
		}
	}
	grpcSrv.Stop()
	_ = httpSrv.Close()
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
