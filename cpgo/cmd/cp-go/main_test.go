package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// The test binary doubles as the Kotlin child: cp-go starts it with CPGO_FAKE_CHILD set.
func TestMain(m *testing.M) {
	if os.Getenv("CPGO_FAKE_CHILD") == "1" {
		fakeChild()
		return
	}
	os.Exit(m.Run())
}

func fakeChild() {
	bind := os.Getenv("PM_BIND_HOST")
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {})
	mux.HandleFunc("/env", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"bind":    bind,
			"trusted": os.Getenv("PM_TRUSTED_PROXIES"),
			"xff":     r.Header.Get("X-Forwarded-For"),
		})
	})
	mux.HandleFunc("/exit", func(http.ResponseWriter, *http.Request) { os.Exit(3) })
	httpLn, err := net.Listen("tcp", net.JoinHostPort(bind, os.Getenv("PM_HTTP_PORT")))
	if err != nil {
		os.Exit(10)
	}
	grpcLn, err := net.Listen("tcp", net.JoinHostPort(bind, os.Getenv("PM_GRPC_PORT")))
	if err != nil {
		os.Exit(11)
	}
	gs := grpc.NewServer()
	healthpb.RegisterHealthServer(gs, health.NewServer())
	go func() { _ = gs.Serve(grpcLn) }()
	go func() { _ = http.Serve(httpLn, mux) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	<-sig
	os.Exit(0)
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func startFront(t *testing.T) (config, context.CancelFunc, <-chan int) {
	t.Helper()
	t.Setenv("CPGO_FAKE_CHILD", "1")
	t.Setenv("PM_TRUSTED_PROXIES", "10.9.9.9")
	cfg := config{
		HTTPPort: freePort(t), GRPCPort: freePort(t),
		Child: os.Args[0], ChildHTTPPort: freePort(t), ChildGRPCPort: freePort(t),
		StartTimeout: 30 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, cfg) }()
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", cfg.HTTPPort))
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("cp-go never served")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return cfg, cancel, done
}

func TestRunForwardsToChildOnLoopback(t *testing.T) {
	cfg, cancel, done := startFront(t)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/env", cfg.HTTPPort))
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&env)
	_ = resp.Body.Close()
	if env["bind"] != "127.0.0.1" || env["trusted"] != "127.0.0.1" || env["xff"] != "127.0.0.1" {
		t.Fatalf("child saw %v", env)
	}

	cc, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", cfg.GRPCPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	ctx, cancelCall := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCall()
	hr, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil || hr.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health via gRPC: %v %v", hr, err)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code %d after shutdown", code)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("run did not return after shutdown")
	}
}

func TestRunExitsWhenChildDies(t *testing.T) {
	cfg, cancel, done := startFront(t)
	defer cancel()
	_, _ = http.Get(fmt.Sprintf("http://127.0.0.1:%d/exit", cfg.HTTPPort))
	select {
	case code := <-done:
		if code != 3 {
			t.Fatalf("exit code %d, want the child's 3", code)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("run did not return after the child died")
	}
}
