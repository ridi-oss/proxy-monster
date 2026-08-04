package grpcsvc

import (
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// The four constants of `GrpcServer.kt`'s private companion object.
const (
	// MaxInboundMessageBytes is 64 MiB.
	//
	// 🔒 INV-A10-40 — this is a FUNCTIONAL REQUIREMENT, not tuning. A full PushCatalog (every column,
	// system schemas included) can exceed gRPC's 4 MiB default on a large database; without the raise
	// the push fails and the proxy falls into its empty-catalog fail-closed boot state. 64 MiB is
	// "generous headroom over the 4 MiB default".
	MaxInboundMessageBytes = 64 * 1024 * 1024

	// KeepaliveTime / KeepaliveTimeout / PermitKeepaliveTime are a MATCHED PAIR with the Go client's.
	//
	// 🔒 INV-A10-41 — the server pings idle connections (so a dead proxy's Events stream closes and
	// deregisters, leaving no ghost in the liveness view) and PERMITS the proxy's own 30 s keepalive
	// pings. `permit (15s) <= the client's keepAliveTime (30s)`, and without-calls must be true, or
	// the server GOAWAYs the idle stream for "too_many_pings". Verified against goproxy/cp/client.go's
	// keepaliveTime = 30s / keepaliveTimeout = 10s / PermitWithoutStream: true.
	KeepaliveTime       = 30 * time.Second
	KeepaliveTimeout    = 10 * time.Second
	PermitKeepaliveTime = 15 * time.Second

	// ShutdownGrace is `awaitTermination(5, SECONDS)`.
	ShutdownGrace = 5 * time.Second
)

// Server is `class GrpcServer(port, service, secretToken)`.
//
// It takes the pb.ControlPlaneServer INTERFACE, not the concrete *Service: "the server only needs 'a
// ControlPlane service', which lets tests bind a probe handler without opening the production class"
// (10-grpc.md §3.3). GrpcServerTest depends on exactly that.
type Server struct {
	port     int
	server   *grpc.Server
	listener net.Listener
	log      *slog.Logger

	gateConfigured bool
	done           chan struct{}
}

// NewServer builds the server. Construction mirrors the Kotlin field initializer, so a bad config
// fails at construction rather than at the first call.
func NewServer(port int, service pb.ControlPlaneServer, secretToken *string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	interceptor := NewSecretTokenInterceptor(secretToken)

	// 🔒 INV-A10-42 — ONE interceptor pair wraps the ONE service, so the gate runs on every RPC. A
	// per-handler check would be the failure mode; this is the choke point.
	s := grpc.NewServer(
		grpc.MaxRecvMsgSize(MaxInboundMessageBytes),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: KeepaliveTime, Timeout: KeepaliveTimeout}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             PermitKeepaliveTime,
			PermitWithoutStream: true,
		}),
		grpc.UnaryInterceptor(interceptor.Unary),
		grpc.StreamInterceptor(interceptor.Stream),
	)
	pb.RegisterControlPlaneServer(s, service)

	return &Server{
		port:           port,
		server:         s,
		log:            log,
		gateConfigured: interceptor.Configured(),
		done:           make(chan struct{}),
	}
}

// Start binds the port and begins serving on a background goroutine.
//
// 🔒 INV-A10-5 (= A1 INV-A1-2) — A BIND FAILURE IS FATAL. Start returns the error and main must abort
// the process: "a control-plane that can't bind its required gRPC port is misconfigured — like a bad
// DB or a taken HTTP port — and must not come up serving only HTTP while the data plane is silently
// dead." Never log-and-continue here.
//
// INV-A10-43 — Start registers NO process-level shutdown hook as a side effect. Lifecycle is the
// caller's: main installs the signal handler, tests drain via their own teardown.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("control-plane gRPC bind :%d: %w", s.port, err)
	}
	s.listener = ln
	logGatePosture(s.log, s.BoundPort(), s.gateConfigured)

	go func() {
		defer close(s.done)
		// Serve returns ErrServerStopped after Stop/GracefulStop; that is an ordinary shutdown.
		if err := s.server.Serve(ln); err != nil && err != grpc.ErrServerStopped {
			s.log.Error("control-plane gRPC serve ended", "err", err)
		}
	}()
	return nil
}

// BoundPort is the ACTUALLY-bound port, valid after Start. Equals the configured port unless it was
// 0 (ephemeral).
//
// Eight of the twelve Kotlin suites in this area bind port 0 and read this, plus two suites in other
// areas, so the ephemeral-port readback is load-bearing test infrastructure rather than a
// convenience.
func (s *Server) BoundPort() int {
	if s.listener == nil {
		return s.port
	}
	if addr, ok := s.listener.Addr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return s.port
}

// Shutdown is graceful drain then FORCE-cancel.
//
// 🔒 INV-A10-6 — the force step is mandatory, not belt-and-braces: A LONG-LIVED EVENTS STREAM NEVER
// FINISHES ON ITS OWN (its handler awaits the client forever), so a Go port using only GracefulStop()
// HANGS FOREVER and the streams never deregister. Race GracefulStop against the grace timer, then
// Stop().
func (s *Server) Shutdown() {
	stopped := make(chan struct{})
	go func() {
		s.server.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(ShutdownGrace):
		s.server.Stop()
		select {
		case <-stopped:
		case <-time.After(ShutdownGrace):
		}
	}
	<-s.done
}
