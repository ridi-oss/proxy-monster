package tailnet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"

	"github.com/ridi-oss/proxy-monster/cpgo/front"
)

const (
	serviceVIP = "100.99.99.99"
	service    = "svc:console"
	tailnetDNS = "tail-scale.ts.net"
)

// tailnet is two real nodes on an in-process control server: host serves, client dials.
type tailnet struct {
	ctx              context.Context
	host, client     *tsnet.Server
	hostSt, clientSt *ipnstate.Status
	seen             chan string
	served           chan error
	handler          http.Handler
}

func newTailnet(t *testing.T, withService bool) *tailnet {
	t.Helper()
	if testing.Short() {
		t.Skip("starts two tailnet nodes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	control := &testcontrol.Server{
		DERPMap:        integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1"),
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: tailnetDNS,
		Logf:           logger.Discard,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)

	node := func(name string) (*tsnet.Server, *ipnstate.Status) {
		t.Helper()
		s := &tsnet.Server{Dir: t.TempDir(), ControlURL: control.HTTPTestServer.URL, Hostname: name, Store: new(mem.Store),
			Ephemeral: true, Logf: logger.Discard}
		t.Cleanup(func() { _ = s.Close() })
		st, err := s.Up(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return s, st
	}
	tn := &tailnet{ctx: ctx, seen: make(chan string, 4), served: make(chan error, 2)}
	tn.host, tn.hostSt = node("console-node")
	tn.client, tn.clientSt = node("laptop")
	// The console behind cp-go's proxy, as the Kotlin control plane or web sees each request.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tn.seen <- r.Header.Get("X-Forwarded-For") + " " + r.Header.Get("X-Forwarded-Proto")
		_, _ = io.WriteString(w, "console")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	tn.handler = front.NewHTTP(u, front.TrustedEdges{})
	if !withService {
		return tn
	}

	// What the tailnet's policy grants a real Service host: the Service's VIP, a tag, and the route to it.
	mapping, _ := json.Marshal(tailcfg.ServiceIPMappings{service: {netip.MustParseAddr(serviceVIP)}})
	control.SetNodeCapMap(tn.hostSt.Self.PublicKey, tailcfg.NodeCapMap{tailcfg.NodeAttrServiceHost: {tailcfg.RawMessage(mapping)}})
	control.SetSubnetRoutes(tn.hostSt.Self.PublicKey, []netip.Prefix{netip.MustParsePrefix(serviceVIP + "/32")})
	n := control.Node(tn.hostSt.Self.PublicKey)
	n.Tags = append(n.Tags, "tag:console")
	control.UpdateNode(n)
	clientLC, _ := tn.client.LocalClient()
	if _, err := clientLC.EditPrefs(ctx, &ipn.MaskedPrefs{RouteAllSet: true, Prefs: ipn.Prefs{RouteAll: true}}); err != nil {
		t.Fatal(err)
	}
	control.AddDNSRecords(tailcfg.DNSRecord{Name: "console." + tailnetDNS, Value: serviceVIP})
	for _, s := range []*tsnet.Server{tn.host, tn.client} {
		waitForRecord(t, ctx, s)
	}
	// The status a Service host serves with is the one after its grants arrived.
	lc, _ := tn.host.LocalClient()
	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tn.hostSt = st
	return tn
}

func (tn *tailnet) serve(t *testing.T, service string, cert *Cert) {
	t.Helper()
	h, err := Serve(tn.host, tn.hostSt, service, cert, tn.handler, tn.served)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
}

// web is a client on the tailnet that trusts cert and does not follow redirects.
func (tn *tailnet) web(cert *Cert) *http.Client {
	roots := x509.NewCertPool()
	if cert != nil {
		leaf, _ := cert.GetCertificate(nil)
		roots.AddCert(leaf.Leaf)
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:     tn.client.Dial,
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "console.example.com"},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       30 * time.Second,
	}
}

// getConsole fetches https://addr/ and checks the console was told the client's own tailnet address and https.
func (tn *tailnet) getConsole(t *testing.T, web *http.Client, addr string) {
	t.Helper()
	resp, err := web.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "console" {
		t.Fatalf("served %q", body)
	}
	var got string
	select {
	case got = <-tn.seen:
	case <-tn.ctx.Done():
		t.Fatal("the console never saw the request")
	}
	if want := tn.clientSt.TailscaleIPs[0].String() + " https"; got != want {
		t.Fatalf("forwarded %q, want %q", got, want)
	}
}

func redirect(t *testing.T, web *http.Client, addr, want string) {
	t.Helper()
	resp, err := web.Get("http://" + addr + "/console?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != want {
		t.Fatalf("port 80: %d %s, want %s", resp.StatusCode, resp.Header.Get("Location"), want)
	}
}

func TestServeServiceWithACM(t *testing.T) {
	tn := newTailnet(t, true)
	cert, err := newCert(tn.ctx, "arn", &fakeACM{})
	if err != nil {
		t.Fatal(err)
	}
	tn.serve(t, service, cert)
	web := tn.web(cert)
	tn.getConsole(t, web, serviceVIP)
	redirect(t, web, serviceVIP, "https://console.example.com/console?x=1")
}

func TestServeNodeWithACM(t *testing.T) {
	tn := newTailnet(t, false)
	cert, err := newCert(tn.ctx, "arn", &fakeACM{})
	if err != nil {
		t.Fatal(err)
	}
	tn.serve(t, "", cert)
	web, addr := tn.web(cert), tn.hostSt.TailscaleIPs[0].String()
	tn.getConsole(t, web, addr)
	redirect(t, web, addr, "https://console.example.com/console?x=1")
}

// The test control server issues no certificates, so this checks what tailscaled is told to do on 443,
// and the redirect to the Service's name on 80.
func TestServeServiceWithTailscaleCert(t *testing.T) {
	tn := newTailnet(t, true)
	tn.serve(t, service, nil)
	lc, _ := tn.host.LocalClient()
	sc, err := lc.GetServeConfig(tn.ctx)
	if err != nil {
		t.Fatal(err)
	}
	svc := sc.Services[service]
	if svc == nil || svc.TCP[443] == nil || svc.TCP[80] == nil {
		t.Fatalf("serve config %+v", sc)
	}
	if h := svc.TCP[443]; h.TerminateTLS != "console."+tailnetDNS || h.ProxyProtocol != 2 {
		t.Fatalf("443: %+v", h)
	}
	if h := svc.TCP[80]; h.TerminateTLS != "" || h.ProxyProtocol != 2 {
		t.Fatalf("80: %+v", h)
	}
	redirect(t, tn.web(nil), serviceVIP, "https://console."+tailnetDNS+"/console?x=1")
}

// waitForRecord waits until s has the netmap carrying the Service's DNS record, so the setup is visible. Only the
// first message of a watch carries the netmap on every platform, so each check opens a new watch.
func waitForRecord(t *testing.T, ctx context.Context, s *tsnet.Server) {
	t.Helper()
	lc, _ := s.LocalClient()
	for {
		w, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialNetMap)
		if err != nil {
			t.Fatal(err)
		}
		n, err := w.Next()
		w.Close()
		if err != nil {
			t.Fatal(err)
		}
		if n.NetMap != nil && slices.ContainsFunc(n.NetMap.DNS.ExtraRecords, func(r tailcfg.DNSRecord) bool { return r.Value == serviceVIP }) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("the Service's DNS record never reached the node")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
