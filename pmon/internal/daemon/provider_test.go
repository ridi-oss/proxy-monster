package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/providers"
)

type servingBroker struct {
	ctx     context.Context
	resolve driver.ResolveSession
}

type httpBroker struct {
	restartOnRouteChange bool
	started              chan servingBroker
}

func (httpBroker) UnavailableReason(endpoint driver.Endpoint) string {
	if endpoint.AdvertiseAddr == "" {
		return "no advertised proxy address"
	}
	return ""
}

func (b httpBroker) RouteKey(endpoint driver.Endpoint) string {
	if b.restartOnRouteChange {
		return fmt.Sprintf("%q/%q/%t", endpoint.AdvertiseAddr, endpoint.CertChainPEM, endpoint.WireTLS)
	}
	return ""
}

type httpReply struct {
	Endpoint    driver.Endpoint
	Credentials driver.Credentials
	RemoteAddr  string
}

func (b httpBroker) Serve(ctx context.Context, listener net.Listener, resolve driver.ResolveSession) error {
	b.started <- servingBroker{ctx: ctx, resolve: resolve}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint, credentials, ok := resolve()
		if !ok {
			http.Error(w, "unavailable", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(httpReply{endpoint, credentials, r.RemoteAddr})
	})}
	defer server.Close()
	err := server.Serve(listener)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func awaitBroker(t *testing.T, started <-chan servingBroker) servingBroker {
	t.Helper()
	select {
	case running := <-started:
		return running
	case <-time.After(5 * time.Second):
		t.Fatal("provider did not start")
		return servingBroker{}
	}
}

func startProviderDaemon(t *testing.T, registry *driver.Registry, endpoints []Datasource) (*Daemon, *fakeCP) {
	t.Helper()
	isolate(t)
	cp := newFakeCP(t, endpoints)
	d := New("test", registry)
	t.Cleanup(func() {
		d.closeAllListeners()
		d.closeConns()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Login(ctx, control.LoginRequest{ControlPlane: cp.URL}, func(control.LoginEvent) {}); err != nil {
		t.Fatalf("login: %v", err)
	}
	return d, cp
}

func liveConnections(d *Daemon) int {
	status := d.Status()
	return status.TotalLiveConns()
}

func providerClient(t *testing.T) *http.Client {
	t.Helper()
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func requestProvider(t *testing.T, client *http.Client, port int) httpReply {
	t.Helper()
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var reply httpReply
	if err := json.NewDecoder(response.Body).Decode(&reply); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return reply
}

func TestProviderServesHTTPWithFreshSessionOnKeepAlive(t *testing.T) {
	broker := httpBroker{started: make(chan servingBroker, 1)}
	registry := driver.NewRegistry(driver.Provider{Engine: "test-http", Broker: broker})
	d, cp := startProviderDaemon(t, registry, []Datasource{{Name: "test", Engine: "test-http", AdvertiseAddr: "first"}})
	running := awaitBroker(t, broker.started)
	if running.ctx.Err() != nil {
		t.Fatal("listener inherited the completed login request's context")
	}
	port := d.Status().Datasources[0].LocalPort
	client := providerClient(t)
	first := requestProvider(t, client, port)
	if first.Endpoint.AdvertiseAddr != "first" || first.Credentials.Token != "pmk_tok" {
		t.Fatalf("first reply = %+v", first)
	}
	cp.datasources[0].AdvertiseAddr = "second"
	d.openListeners(context.Background())
	d.mu.Lock()
	d.cfg.Principal, d.cfg.Token, d.cfg.LocalPassword = "new-principal", "new-token", "new-password"
	d.mu.Unlock()
	second := requestProvider(t, client, port)
	if second.Endpoint.AdvertiseAddr != "second" || second.Credentials != (driver.Credentials{
		Principal: "new-principal", Token: "new-token", LocalPassword: "new-password",
	}) {
		t.Fatalf("second reply = %+v", second)
	}
	if second.RemoteAddr != first.RemoteAddr {
		t.Fatal("the second request did not reuse its connection")
	}
	if got := liveConnections(d); got != 1 {
		t.Fatalf("live connections = %d, want one persistent HTTP connection", got)
	}
	if err := d.Logout(); err != nil {
		t.Fatal(err)
	}
	if got := liveConnections(d); got != 0 {
		t.Fatalf("logout left %d connections", got)
	}
	if _, _, ok := running.resolve(); ok {
		t.Fatal("logged-out listener still resolves a session")
	}
}

func TestProviderChangeReplacesListenerAndInvalidatesOldResolver(t *testing.T) {
	first := httpBroker{started: make(chan servingBroker, 2)}
	second := httpBroker{started: make(chan servingBroker, 1)}
	registry := driver.NewRegistry(
		driver.Provider{Engine: "first", Broker: first},
		driver.Provider{Engine: "second", Broker: second},
	)
	d, cp := startProviderDaemon(t, registry, []Datasource{{Name: "test", Engine: "first", AdvertiseAddr: "route"}})
	old := awaitBroker(t, first.started)
	port := d.Status().Datasources[0].LocalPort
	client := providerClient(t)
	requestProvider(t, client, port)
	cp.datasources[0].Engine = "second"
	d.openListeners(context.Background())
	awaitBroker(t, second.started)
	if old.ctx.Err() == nil {
		t.Fatal("old provider was not canceled")
	}
	if got := liveConnections(d); got != 0 {
		t.Fatalf("provider replacement left %d connections", got)
	}
	if got := d.Status().Datasources[0].LocalPort; got != port {
		t.Fatalf("replacement port = %d, want %d", got, port)
	}
	if reply := requestProvider(t, client, port); reply.Endpoint.Engine != "second" {
		t.Fatalf("replacement provider returned %+v", reply.Endpoint)
	}
	cp.datasources[0].Engine = "first"
	d.openListeners(context.Background())
	awaitBroker(t, first.started)
	if _, _, ok := old.resolve(); ok {
		t.Fatal("old resolver became valid when its engine was restored")
	}
}

func TestProviderRevocationClosesPersistentConnections(t *testing.T) {
	for _, unsupported := range []bool{false, true} {
		t.Run(fmt.Sprintf("unsupported=%t", unsupported), func(t *testing.T) {
			broker := httpBroker{started: make(chan servingBroker, 1)}
			registry := driver.NewRegistry(driver.Provider{Engine: "test-http", Broker: broker})
			d, cp := startProviderDaemon(t, registry, []Datasource{{Name: "test", Engine: "test-http", AdvertiseAddr: "route"}})
			running := awaitBroker(t, broker.started)
			port := d.Status().Datasources[0].LocalPort
			requestProvider(t, providerClient(t), port)
			if unsupported {
				cp.datasources[0].Engine = "unknown"
			} else {
				cp.datasources = nil
			}
			d.openListeners(context.Background())
			if running.ctx.Err() == nil || liveConnections(d) != 0 {
				t.Fatal("revoked provider retained its context or connections")
			}
			if _, _, ok := running.resolve(); ok {
				t.Fatal("revoked provider still resolves a session")
			}
			if unsupported {
				status := d.Status()
				if len(status.Datasources) != 1 || status.Datasources[0].Brokered || status.Datasources[0].Reason != `engine "unknown" not brokered` {
					t.Fatalf("unsupported engine status = %+v", status)
				}
			}
		})
	}
}

func TestProviderRouteKeyReplacesListener(t *testing.T) {
	broker := httpBroker{restartOnRouteChange: true, started: make(chan servingBroker, 1)}
	registry := driver.NewRegistry(driver.Provider{Engine: "test-http", Broker: broker})
	d, cp := startProviderDaemon(t, registry, []Datasource{{Name: "test", Engine: "test-http", AdvertiseAddr: "first"}})
	running := awaitBroker(t, broker.started)
	port := d.Status().Datasources[0].LocalPort
	client := providerClient(t)
	for _, change := range []func(*Datasource){
		func(ds *Datasource) { ds.AdvertiseAddr = "second" },
		func(ds *Datasource) { ds.CertChainPEM = "new-chain" },
		func(ds *Datasource) { ds.WireTLS = true },
	} {
		requestProvider(t, client, port)
		change(&cp.datasources[0])
		d.openListeners(context.Background())
		if running.ctx.Err() == nil {
			t.Fatal("route change did not cancel the provider")
		}
		if _, _, ok := running.resolve(); ok {
			t.Fatal("replaced route still resolves a session")
		}
		if got := d.Status(); got.TotalLiveConns() != 0 || got.Datasources[0].LocalPort != port {
			t.Fatalf("replacement status = %+v", got)
		}
		running = awaitBroker(t, broker.started)
	}
}

func TestMySQLRouteChangeKeepsListenerAndAcceptedConnection(t *testing.T) {
	d, cp := startProviderDaemon(t, providers.Builtins(), []Datasource{{Name: "test", Engine: "mysql", AdvertiseAddr: "first:3306"}})
	d.mu.Lock()
	listener := d.listeners["test"]
	d.mu.Unlock()
	local, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	if err := local.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mysqlwire.ReadPacket(local); err != nil {
		t.Fatalf("read MySQL greeting: %v", err)
	}
	cp.datasources[0].AdvertiseAddr = "second:3306"
	cp.datasources[0].CertChainPEM = "new-chain"
	cp.datasources[0].WireTLS = true
	d.openListeners(context.Background())
	endpoint, _, ok := d.resolveSession("test", listener)
	if !ok || endpoint != cp.datasources[0] || listener.ctx.Err() != nil {
		t.Fatalf("listener was replaced or retained stale metadata: %+v, %v", endpoint, ok)
	}
	if got := liveConnections(d); got != 1 {
		t.Fatalf("route change closed an accepted MySQL connection: %d", got)
	}
}

type failedBroker struct {
	httpBroker
	fail <-chan struct{}
}

func (b failedBroker) Serve(_ context.Context, listener net.Listener, _ driver.ResolveSession) error {
	if _, err := listener.Accept(); err != nil {
		return err
	}
	<-b.fail
	return errors.New("test provider stopped")
}

func TestProviderFailureClosesConnectionsAndIsVisible(t *testing.T) {
	fail := make(chan struct{})
	registry := driver.NewRegistry(driver.Provider{Engine: "failed", Broker: failedBroker{fail: fail}})
	d, _ := startProviderDaemon(t, registry, []Datasource{{Name: "test", Engine: "failed", AdvertiseAddr: "route"}})
	port := d.Status().Datasources[0].LocalPort
	local, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		close(fail)
		t.Fatal(err)
	}
	defer local.Close()
	waitFor(t, "accepted connection", func() bool { return liveConnections(d) == 1 })
	close(fail)
	waitFor(t, "failed provider status", func() bool {
		status := d.Status()
		return status.TotalLiveConns() == 0 && len(status.Datasources) == 1 &&
			!status.Datasources[0].Brokered && status.Datasources[0].Reason == "test provider stopped"
	})
}
