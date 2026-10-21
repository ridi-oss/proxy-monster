// Package gobridge is how the Kotlin control plane calls Go while a slice is half-moved: a gRPC server on
// loopback, serving one service per half-moved slice, each in its own file under proto/src/main/proto/. A service goes when its Kotlin
// caller moves to Go, and the server with the last one (docs/cp-go-migration.md).
package gobridge

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TokenKey carries the per-boot internal token, the same one cp-go hands the Kotlin child.
const TokenKey = "x-pm-internal-token"

// AddrEnv is where the Kotlin child finds the server.
const AddrEnv = "PM_CP_GO_GRPC_ADDR"

type Server struct {
	grpc *grpc.Server
	ln   net.Listener
}

// Listen opens the loopback listener on port, 0 for a free one; register services on GRPC before Serve.
func Listen(port int, token string) (*Server, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("gobridge: listening: %w", err)
	}
	check := func(ctx context.Context) error {
		md, _ := metadata.FromIncomingContext(ctx)
		if v := md.Get(TokenKey); len(v) != 1 || subtle.ConstantTimeCompare([]byte(v[0]), []byte(token)) != 1 {
			return status.Error(codes.Unauthenticated, "missing or wrong internal token")
		}
		return nil
	}
	return &Server{
		grpc: grpc.NewServer(
			grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
				if err := check(ctx); err != nil {
					return nil, err
				}
				return h(ctx, req)
			}),
			grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
				if err := check(ss.Context()); err != nil {
					return err
				}
				return h(srv, ss)
			}),
		),
		ln: ln,
	}, nil
}

// GRPC is where services register.
func (s *Server) GRPC() *grpc.Server { return s.grpc }

// Env is the child's environment entry naming the server.
func (s *Server) Env() string { return AddrEnv + "=" + s.ln.Addr().String() }

// Serve serves until Stop, reporting why it stopped on served.
func (s *Server) Serve(served chan<- error) {
	go func() {
		err := s.grpc.Serve(s.ln)
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		}
		served <- err
	}()
}

// Shutdown lets in-flight calls finish; Close cuts them.
func (s *Server) Shutdown(context.Context) error {
	s.grpc.GracefulStop()
	return nil
}

func (s *Server) Close() error {
	s.grpc.Stop()
	return nil
}
