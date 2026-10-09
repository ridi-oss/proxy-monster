// Package daemon is pmon's whole runtime: it holds the credentials, discovers the datasources the principal
// can reach, opens one loopback listener per datasource, and brokers each to that datasource's proxy —
// injecting the wire token upstream so a saved client connection uses a stable local port + password.
//
// Brokers come up as soon as credentials exist: at start when the stored session is still usable, and the
// moment a login completes otherwise. There is no separate "start brokering" step.
package daemon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/internal/login"
	"github.com/ridi-oss/proxy-monster/pmon/internal/state"
)

const (
	// rediscoverInterval is how often the daemon re-lists datasources, to pick up new ones, follow a
	// re-advertised address, and — the security-relevant case — stop brokering one that is no longer
	// connectable.
	rediscoverInterval = 30 * time.Second
	// renewCheckInterval is how often the renewal loop reconsiders the wire token's expiry.
	renewCheckInterval = 1 * time.Minute
	// maxRenewLeadTime is how long before expiry a renewal is attempted for a long-lived token, leaving room for
	// a slow control plane or a transient failure to be retried before the token dies.
	maxRenewLeadTime = 30 * time.Minute
	// renewLeadFraction bounds the lead time for a SHORT token to a fraction of its own lifetime. The control
	// plane clamps TTL to a 60s floor, so a fixed 30-minute lead would put any token under that permanently past
	// its threshold — renewing on every tick for the token's whole life instead of once near the end.
	renewLeadFraction = 4
)

// Daemon is the running broker. It is the sole owner of pmon's state: peers read it through the control API
// and mutate it only by asking the daemon to act.
type Daemon struct {
	httpClient *http.Client
	startedAt  time.Time
	version    string
	providers  *driver.Registry
	ctx        context.Context

	// stop ends the daemon's run; it is what a control-API shutdown triggers.
	stop context.CancelFunc
	// rediscover carries a nudge to run discovery now instead of waiting for the next cycle.
	rediscover chan struct{}
	// loginMus serializes logins per server, so two peers asking at once cannot start two device flows for
	// one server, while a login to another server is not held up behind a pending browser step.
	loginMus sync.Map // server name -> *sync.Mutex
	// serverMus serializes the short per-server mutations — the end of a login, set, unset, logout — so none
	// lands between another's commit and its reply.
	serverMus sync.Map // server name -> *sync.Mutex
	// configMu serializes every config write with the in-memory copy it produces, so a slower writer can never
	// install an older snapshot over a newer one. Taken before d.mu, never while holding it.
	configMu sync.Mutex
	// discoveryMus serializes syncServer end to end per server. Its fine-grained d.mu sections are not enough on their
	// own: two concurrent passes (a login racing the rediscover ticker or a peer's /reload) could both observe
	// a datasource as needing a listener, and the loser's bind would fail on the winner's port and then free
	// the sticky assignment — leaving the datasource brokered but reporting LocalPort 0, so `pmon show` would
	// emit a connection string with port 0 and the sticky identity would be lost across restarts.
	discoveryMus sync.Map // server name -> *sync.Mutex

	mu            sync.Mutex
	cfg           state.Config
	localPassword string
	// listeners maps a datasource to its loopback listener; presence here means "brokered right now",
	// which is what /status reports (the sticky port map on disk keeps revoked datasources, so counting it
	// would over-report).
	listeners map[dsKey]*brokerListener
	// datasources maps a datasource name to its CURRENT discovered form, so a broker always dials the
	// freshly-advertised address rather than the one captured when its listener opened.
	datasources map[dsKey]driver.Endpoint
	// unbrokered holds discovered-but-not-fronted datasources, so a peer can explain them.
	unbrokered map[dsKey]driver.Endpoint
	// bindErrors maps a datasource name to why its listener could not open, so the reason a peer shows is the
	// real cause (a port collision) rather than a generic one.
	bindErrors map[dsKey]string
	// liveConns holds the OPEN client connections per datasource, keyed by a serial so each can be removed
	// independently. Tracking the connections (rather than only counting them) is what lets logout and
	// revocation close sessions that are already accepted — closing a listener stops new accepts but leaves an
	// established session piping until its client happens to disconnect.
	liveConns map[dsKey]map[uint64]net.Conn
	// nextConnID serializes the keys in liveConns.
	nextConnID uint64
	// lastDiscoveryErr is each server's most recent discovery failure, cleared on the next success.
	lastDiscoveryErr map[string]string
	// reauthRequired marks a server whose renewal was refused: brokering keeps working until the wire token
	// expires, but only a fresh login recovers it.
	reauthRequired map[string]bool

	subMu   sync.Mutex
	subs    map[int]chan control.Event
	nextSub int
}

// dsKey names a datasource on one server; two servers may each have a datasource of the same name.
type dsKey struct{ server, name string }

// New builds a daemon with no credentials loaded. version is what it reports over the control socket.
func New(version string, providers *driver.Registry) *Daemon {
	return &Daemon{
		version:          version,
		providers:        providers,
		ctx:              context.Background(),
		httpClient:       &http.Client{Timeout: 15 * time.Second},
		startedAt:        time.Now(),
		rediscover:       make(chan struct{}, 1),
		listeners:        map[dsKey]*brokerListener{},
		datasources:      map[dsKey]driver.Endpoint{},
		unbrokered:       map[dsKey]driver.Endpoint{},
		bindErrors:       map[dsKey]string{},
		liveConns:        map[dsKey]map[uint64]net.Conn{},
		lastDiscoveryErr: map[string]string{},
		reauthRequired:   map[string]bool{},
		subs:             map[int]chan control.Event{},
	}
}

// Run takes the single-instance pid lock, serves the control API, and brokers until ctx ends or a peer asks
// the daemon to stop.
//
// Missing credentials are NOT a startup failure: the daemon comes up idle and waits for a login, because a
// peer must be able to launch it on a fresh machine and then log in through it.
func (d *Daemon) Run(ctx context.Context) error {
	held, err := state.AcquirePidLock()
	if err != nil {
		return fmt.Errorf("pid lock: %w", err)
	}
	if !held {
		return errors.New("another pmon daemon is already running")
	}
	defer state.ReleasePidLock()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.stop = cancel
	d.ctx = ctx

	srv, err := control.Listen(d)
	if err != nil {
		return err
	}
	defer srv.Close()

	cfg, err := state.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// An unreadable config is fatal rather than silently treated as "no login": continuing would let the
		// first write overwrite state that is merely unreadable right now, losing the sticky password + ports.
		return fmt.Errorf("could not read the config (fix or remove it): %w", err)
	}
	if cfg != nil {
		d.mu.Lock()
		d.cfg = cfg.Clone()
		d.mu.Unlock()
	}
	// Ensure the sticky loopback password exists before any listener opens, so a connection string handed out
	// at any moment is already valid.
	if err := d.ensureLocalPassword(); err != nil {
		fmt.Fprintln(os.Stderr, "could not prepare the local password:", err)
	}

	// Serve the control API BEFORE the first discovery. Discovery does network I/O, and a peer that connects
	// meanwhile would sit blocked on an accepted-but-unserved socket — its readiness probe unable to reach its
	// own deadline, so `pmon start`'s timeout would not bound startup at all.
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ctx) }()

	current := d.snapshot()
	if current.LoggedIn() {
		go d.openListeners(ctx)
	} else {
		fmt.Fprintln(os.Stderr, "not logged in — the daemon is idle; run `pmon login`")
	}

	go d.rediscoverLoop(ctx)
	go d.renewLoop(ctx)

	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil {
			return err
		}
	}

	d.publish(control.Event{Kind: "shutdown", Message: "the daemon is stopping"})
	d.closeAllListeners()
	// Close established sessions too, matching logout and revocation: `pmon stop` warned the user these would be
	// dropped, so drop them deliberately rather than leaving it to process exit.
	d.closeConns()
	d.closeSubscribers()
	return nil
}

// snapshot returns a deep copy of the current config, so callers read it without holding the lock. A shallow
// copy would alias the live server and port maps, and a caller touching them outside the lock would race
// against port assignment with no compiler or race-detector warning until the timing happened to line up.
func (d *Daemon) snapshot() state.Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg.Clone()
}

// commit runs mutate under the config file lock and installs the result as the in-memory config, in one step
// serialized with every other commit.
func (d *Daemon) commit(mutate func(*state.Config) error) error {
	d.configMu.Lock()
	defer d.configMu.Unlock()
	var next *state.Config
	if err := state.Update(func(c *state.Config) error {
		next = c
		return mutate(c)
	}); err != nil {
		return err
	}
	d.mu.Lock()
	d.cfg = next.Clone()
	d.mu.Unlock()
	return nil
}

func lockOf(m *sync.Map, name string) *sync.Mutex {
	mu, _ := m.LoadOrStore(name, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// ensureLocalPassword generates the sticky loopback password once and caches it in memory.
func (d *Daemon) ensureLocalPassword() error {
	var pw string
	if err := d.commit(func(c *state.Config) error {
		p, err := c.EnsureLocalPassword()
		pw = p
		return err
	}); err != nil {
		return err
	}
	d.mu.Lock()
	d.localPassword = pw
	d.mu.Unlock()
	return nil
}

// ---- control.Backend ----------------------------------------------------------------------------

// Status reports the daemon's observable state. Brokered datasources come from the live listener map;
// discovered-but-unbrokered ones are included with a reason, so a peer never shows a silently short list.
func (d *Daemon) Status() control.Status {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := control.Status{
		LoggedIn:  d.cfg.LoggedIn(),
		StartedAt: d.startedAt.Format(time.RFC3339),
		Version:   d.version,
		// Fall back to the persisted value: the in-memory copy is only set by ensureLocalPassword, whose failure
		// at startup is tolerated, so a config that already HAS a password would otherwise report none and
		// `pmon show` would emit a connection string with an empty password.
		LocalPassword: cmp.Or(d.localPassword, d.cfg.LocalPassword),
		Servers:       make([]control.ServerInfo, 0, len(d.cfg.Servers)),
		DefaultServer: d.cfg.Default,
		Datasources:   make([]control.Datasource, 0, len(d.datasources)+len(d.unbrokered)),
	}
	for name, srv := range d.cfg.Servers {
		out.Servers = append(out.Servers, control.ServerInfo{
			Name:               name,
			Default:            name == d.cfg.Default,
			ControlPlane:       srv.ControlPlane,
			Principal:          srv.Principal,
			LoggedIn:           srv.LoggedIn(),
			ExpiresAt:          srv.ExpiresAt,
			SessionExpiresAt:   srv.SessionExpiresAt,
			Scopes:             slices.Clone(srv.Scopes),
			ElevatedUntil:      srv.ElevatedUntil,
			ReauthRequired:     d.reauthRequired[name],
			LastDiscoveryError: d.lastDiscoveryErr[name],
		})
	}
	sort.Slice(out.Servers, func(i, j int) bool { return out.Servers[i].Name < out.Servers[j].Name })

	// Every tracked connection must be accounted for, including one whose datasource has since been pruned
	// (revoked mid-session, or a broker still parked in the upstream handshake). The registry — not the listener
	// set — is the truth: stop/quit read this count to decide whether to warn before dropping live queries, so a
	// connection missing from it is a query dropped with no confirmation.
	counted := make(map[dsKey]bool, len(d.liveConns))
	for key, ds := range d.datasources {
		if _, live := d.listeners[key]; !live {
			continue
		}
		out.Datasources = append(out.Datasources, control.Datasource{
			Server:         key.server,
			Name:           ds.Name,
			Engine:         ds.Engine,
			DbName:         ds.DbName,
			ConnectionInfo: ds.ConnectionInfo.Clone(),
			LocalPort:      d.port(key),
			AdvertiseAddr:  ds.AdvertiseAddr,
			TLSVerified:    ds.CertChainPEM != "",
			WireTLS:        ds.WireTLS,
			Brokered:       true,
			LiveConns:      len(d.liveConns[key]),
		})
		counted[key] = true
	}
	for key, ds := range d.unbrokered {
		if _, live := d.listeners[key]; live {
			continue
		}
		out.Datasources = append(out.Datasources, control.Datasource{
			Server:         key.server,
			Name:           ds.Name,
			Engine:         ds.Engine,
			DbName:         ds.DbName,
			ConnectionInfo: ds.ConnectionInfo.Clone(),
			AdvertiseAddr:  ds.AdvertiseAddr,
			TLSVerified:    ds.CertChainPEM != "",
			WireTLS:        ds.WireTLS,
			Brokered:       false,
			Reason:         cmp.Or(d.bindErrors[key], d.providers.UnavailableReason(ds.Clone())),
			LiveConns:      len(d.liveConns[key]),
		})
		counted[key] = true
	}
	// Anything left in the registry has no row above — its datasource was pruned while a session was open.
	// Surface it rather than dropping it from the count.
	for key, conns := range d.liveConns {
		if counted[key] || len(conns) == 0 {
			continue
		}
		out.Datasources = append(out.Datasources, control.Datasource{
			Server:    key.server,
			Name:      key.name,
			Brokered:  false,
			Reason:    "no longer connectable; closing",
			LiveConns: len(conns),
		})
	}
	sort.Slice(out.Datasources, func(i, j int) bool {
		a, b := out.Datasources[i], out.Datasources[j]
		return cmp.Or(cmp.Compare(a.Server, b.Server), cmp.Compare(a.Name, b.Name)) < 0
	})
	return out
}

// port is a datasource's sticky loopback port, or 0. Callers hold d.mu.
func (d *Daemon) port(key dsKey) int {
	if srv := d.cfg.Servers[key.server]; srv != nil {
		return srv.Ports[key.name]
	}
	return 0
}

// LocalPassword is the sticky loopback password a peer hands out in connection strings.
func (d *Daemon) LocalPassword() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.localPassword
}

// Login runs the device-auth flow against one server, persists the result, and brings its brokers up — so a
// login is the only step needed to reach a datasource. A second concurrent login to the same server waits
// rather than starting a competing device flow.
// Login runs the device-auth flow against one server, persists the result, and brings its brokers up — so a
// login is the only step needed to reach a datasource. A second concurrent login to the same server waits
// rather than starting a competing device flow.
func (d *Daemon) Login(ctx context.Context, req control.LoginRequest, onEvent func(control.LoginEvent)) error {
	name := d.serverName(req.Server)
	if err := state.ValidServerName(name); err != nil {
		return err
	}
	loginMu := lockOf(&d.loginMus, name)
	loginMu.Lock()
	defer loginMu.Unlock()

	if req.ControlPlane != "" {
		if _, err := d.SetServer(control.SetServerRequest{Name: name, ControlPlane: req.ControlPlane}); err != nil {
			return err
		}
	}
	srv := d.snapshot().Servers[name]
	if srv == nil {
		if req.Server == "" {
			return errors.New("no default server — set one with `pmon server set --url <control-plane-url>` or `pmon login --url <control-plane-url>`, or pick one with `pmon server default <name>`")
		}
		return fmt.Errorf("unknown server %q — set it with `pmon server set %s --url <control-plane-url>`, or log in with `pmon login --url <control-plane-url> %s`", name, name, name)
	}

	res, err := login.Run(ctx, login.Options{
		ControlPlane: srv.ControlPlane,
		TTLSeconds:   req.TTLSeconds,
		Scopes:       req.Scopes,
		OnPrompt: func(p login.Prompt) {
			onEvent(control.LoginEvent{
				Kind:                    "prompt",
				VerificationURI:         p.VerificationURI,
				VerificationURIComplete: p.VerificationURIComplete,
				UserCode:                p.UserCode,
			})
		},
	})
	if err != nil {
		return err
	}

	serverMu := lockOf(&d.serverMus, name)
	serverMu.Lock()
	err = d.commit(func(c *state.Config) error {
		// The server may have been unset, recreated, or pointed elsewhere while the browser step ran; a token
		// from that control plane must not be stored under what the name means now.
		live := c.Servers[name]
		if live == nil || live.ID != srv.ID || live.ControlPlane != srv.ControlPlane {
			return fmt.Errorf("server %q changed while logging in; log in again", name)
		}
		live.Principal = res.Principal
		live.Token = res.Token
		live.ExpiresAt = res.ExpiresAt
		live.IssuedAt = time.Now().UTC().Format(time.RFC3339)
		live.SessionExpiresAt = res.SessionExpiresAt
		live.RenewalToken = res.RenewalToken
		live.Scopes = res.Scopes
		live.ElevatedUntil = res.ElevatedUntil
		return nil
	})
	if err == nil {
		d.mu.Lock()
		delete(d.reauthRequired, name)
		d.mu.Unlock()
	}
	serverMu.Unlock()
	if err != nil {
		return fmt.Errorf("could not save the login: %w", err)
	}
	// After the save, so a failed end never costs the new login.
	replacedEnded := srv.RenewalToken == "" || srv.RenewalToken == res.RenewalToken || d.endOnServer(srv, true)
	onEvent(control.LoginEvent{
		Kind: "done", Server: name, Principal: res.Principal, ExpiresAt: res.ExpiresAt,
		Scopes: res.Scopes, ElevatedUntil: res.ElevatedUntil, ReplacedNotEndedOnServer: !replacedEnded,
	})

	// Bring brokers up immediately, then announce the new state.
	d.openListeners(ctx)
	d.publishStatus()
	return nil
}

// MCPToken mints an MCP access token from a server's login, so a bridge never reads credentials itself.
func (d *Daemon) MCPToken(ctx context.Context, req control.MCPTokenRequest) (control.MCPToken, error) {
	name := d.serverName(req.Server)
	srv := d.snapshot().Servers[name]
	if srv == nil && req.Server == "" {
		return control.MCPToken{}, errors.New("no default server — pick one with `pmon server default <name>`, or name the server: `pmon mcp <server>`")
	}
	if srv == nil {
		return control.MCPToken{}, fmt.Errorf("unknown server %q — set it up with `pmon server set %s --url <control-plane-url>`, then `pmon login %s`", name, name, name)
	}
	if !srv.LoggedIn() || srv.RenewalToken == "" {
		return control.MCPToken{}, fmt.Errorf("not logged in to %q — run `pmon login %s`", name, name)
	}
	tok, err := login.ExchangeMCP(ctx, d.httpClient, srv.ControlPlane, srv.RenewalToken)
	if errors.Is(err, login.ErrMCPRefused) {
		return control.MCPToken{}, fmt.Errorf("the login to %q has ended — run `pmon login %s`", name, name)
	}
	if errors.Is(err, login.ErrMCPUnsupported) {
		return control.MCPToken{}, fmt.Errorf("%q (%s) does not support `pmon mcp` yet — its proxy-monster server needs an upgrade", name, srv.ControlPlane)
	}
	if err != nil {
		return control.MCPToken{}, fmt.Errorf("could not get an MCP token from %q: %w", name, err)
	}
	return control.MCPToken{URL: srv.ControlPlane + "/mcp", Token: tok.AccessToken, ExpiresAt: tok.ExpiresAt, Scope: tok.Scope}, nil
}

// Logout clears one server's credentials (or every server's) and closes its brokers, leaving the daemon
// running.
func (d *Daemon) Logout(req control.LogoutRequest) ([]string, error) {
	var names []string
	if req.All {
		for name := range d.snapshot().Servers {
			names = append(names, name)
		}
	} else {
		names = []string{d.serverName(req.Server)}
	}
	sort.Strings(names)
	var notEnded []string
	for _, name := range names {
		mu := lockOf(&d.serverMus, name)
		mu.Lock()
		ended, err := d.logout(name, req.All)
		mu.Unlock()
		if err != nil {
			return notEnded, err
		}
		if !ended {
			notEnded = append(notEnded, name)
		}
	}
	d.publishStatus()
	return notEnded, nil
}

// logout clears one server's login and closes its brokers. Callers hold the server's serverMus lock.
func (d *Daemon) logout(name string, missingOK bool) (ended bool, err error) {
	ended = d.endOnServer(d.snapshot().Servers[name], false)
	if err := d.commit(func(c *state.Config) error {
		srv := c.Servers[name]
		if srv == nil {
			if missingOK {
				return nil
			}
			return fmt.Errorf("unknown server %q", name)
		}
		srv.ClearLogin()
		return nil
	}); err != nil {
		return ended, err
	}
	d.forgetServer(name)
	return ended, nil
}

const endOnServerTimeout = 5 * time.Second

// endOnServer reports true when there was nothing to end or the control plane ended it.
func (d *Daemon) endOnServer(srv *state.Server, replaced bool) bool {
	if srv == nil || srv.RenewalToken == "" || srv.ControlPlane == "" {
		return true
	}
	ctx, cancel := context.WithTimeout(d.ctx, endOnServerTimeout)
	defer cancel()
	if err := login.Logout(ctx, d.httpClient, srv.ControlPlane, srv.RenewalToken, replaced); err != nil {
		fmt.Fprintf(os.Stderr, "could not end the login on %s: %v\n", srv.ControlPlane, err)
		return false
	}
	return true
}

// forgetServer closes a server's brokers and established sessions and drops what discovery knew of it.
// Closing a listener only stops NEW accepts, so without closing the sessions a logged-out server would keep
// piping live connections under the credentials just cleared.
func (d *Daemon) forgetServer(name string) {
	d.mu.Lock()
	var lns []net.Listener
	var keys []dsKey
	for key, ln := range d.listeners {
		if key.server == name {
			lns = append(lns, ln)
			delete(d.listeners, key)
		}
	}
	for _, m := range []map[dsKey]driver.Endpoint{d.datasources, d.unbrokered} {
		for key := range m {
			if key.server == name {
				delete(m, key)
			}
		}
	}
	for key := range d.bindErrors {
		if key.server == name {
			delete(d.bindErrors, key)
		}
	}
	for key := range d.liveConns {
		if key.server == name {
			keys = append(keys, key)
		}
	}
	delete(d.lastDiscoveryErr, name)
	delete(d.reauthRequired, name)
	d.mu.Unlock()
	for _, ln := range lns {
		ln.Close()
	}
	if len(keys) > 0 {
		d.closeConns(keys...)
	}
}

// SetServer creates a server or changes its URL. A token is only good against the control plane that minted
// it, so changing a logged-in server's URL logs it out.
// SetServer creates a server or changes its URL. A token is only good against the control plane that minted
// it, so changing a logged-in server's URL logs it out.
func (d *Daemon) SetServer(req control.SetServerRequest) (control.SetServerResult, error) {
	var res control.SetServerResult
	name := d.serverName(req.Name)
	if err := state.ValidServerName(name); err != nil {
		return res, err
	}
	cp, err := normalizeControlPlane(req.ControlPlane)
	if err != nil {
		return res, err
	}
	mu := lockOf(&d.serverMus, name)
	mu.Lock()
	defer mu.Unlock()
	if prev := d.snapshot().Servers[name]; prev != nil && prev.ControlPlane != cp && prev.LoggedIn() {
		res.NotEndedOnServer = !d.endOnServer(prev, false)
	}
	notEnded := res.NotEndedOnServer
	if err := d.commit(func(c *state.Config) error {
		res = control.SetServerResult{NotEndedOnServer: notEnded}
		srv := c.Servers[name]
		switch {
		case srv == nil:
			c.Servers[name] = &state.Server{ID: state.NewServerID(), ControlPlane: cp, Ports: map[string]int{}}
			res.Created = true
			if c.Servers[c.Default] == nil {
				c.Default = name
			}
		case srv.ControlPlane != cp:
			res.Changed = true
			res.LoggedOut = srv.LoggedIn()
			srv.ClearLogin()
			srv.ControlPlane = cp
		}
		return nil
	}); err != nil {
		return res, err
	}
	res.Name, res.Default = name, d.snapshot().Default == name
	if res.Changed {
		d.forgetServer(name)
	}
	if res.Created || res.Changed {
		d.publishStatus()
	}
	return res, nil
}

// UnsetServer logs a server out and deletes it, along with its sticky ports.
// UnsetServer logs a server out and deletes it, along with its sticky ports.
func (d *Daemon) UnsetServer(req control.UnsetServerRequest) ([]string, error) {
	name := d.serverName(req.Name)
	mu := lockOf(&d.serverMus, name)
	mu.Lock()
	defer mu.Unlock()
	var notEnded []string
	if srv := d.snapshot().Servers[name]; srv != nil && !d.endOnServer(srv, false) {
		notEnded = []string{name}
	}
	if err := d.commit(func(c *state.Config) error {
		if c.Servers[name] == nil {
			return fmt.Errorf("unknown server %q", name)
		}
		delete(c.Servers, name)
		return nil
	}); err != nil {
		return nil, err
	}
	d.forgetServer(name)
	d.publishStatus()
	return notEnded, nil
}

// serverName is name, or the default server when name is empty; with no default either, it is
// state.DefaultServer, the name a new server gets.
func (d *Daemon) serverName(name string) string {
	return cmp.Or(d.snapshot().Resolve(name), state.DefaultServer)
}

// SetDefault makes a configured server the one a command addresses when it names none.
func (d *Daemon) SetDefault(req control.SetDefaultRequest) error {
	if err := d.commit(func(c *state.Config) error {
		if c.Servers[req.Name] == nil {
			return fmt.Errorf("unknown server %q", req.Name)
		}
		c.Default = req.Name
		return nil
	}); err != nil {
		return err
	}
	d.publishStatus()
	return nil
}

// normalizeControlPlane checks a control-plane base URL and drops a trailing slash, so one server is not
// recorded twice under two spellings.
func normalizeControlPlane(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("invalid control-plane URL %q: want http(s)://host[:port]", raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// Reload nudges discovery to run now. Non-blocking: a nudge already pending is enough.
func (d *Daemon) Reload() {
	select {
	case d.rediscover <- struct{}{}:
	default:
	}
}

// Shutdown ends the run, which closes the listeners and the control socket.
func (d *Daemon) Shutdown() {
	if d.stop != nil {
		d.stop()
	}
}

// Subscribe opens a state-change stream. The channel is buffered and drops on overflow, so a stuck peer can
// never block the daemon — it just misses intermediate events and catches up on the next /status.
func (d *Daemon) Subscribe() (<-chan control.Event, func()) {
	d.subMu.Lock()
	defer d.subMu.Unlock()
	id := d.nextSub
	d.nextSub++
	ch := make(chan control.Event, 16)
	d.subs[id] = ch
	return ch, func() {
		d.subMu.Lock()
		defer d.subMu.Unlock()
		if c, ok := d.subs[id]; ok {
			delete(d.subs, id)
			close(c)
		}
	}
}

func (d *Daemon) publish(ev control.Event) {
	d.subMu.Lock()
	defer d.subMu.Unlock()
	for _, ch := range d.subs {
		select {
		case ch <- ev:
		default: // slow peer: drop rather than block the daemon
		}
	}
}

func (d *Daemon) publishStatus() {
	s := d.Status()
	d.publish(control.Event{Kind: "status", Status: &s})
}

func (d *Daemon) closeSubscribers() {
	d.subMu.Lock()
	defer d.subMu.Unlock()
	for id, ch := range d.subs {
		delete(d.subs, id)
		close(ch)
	}
}

// ---- brokering ----------------------------------------------------------------------------------

// openListeners runs discovery for every logged-in server.
// openListeners runs discovery for every logged-in server, concurrently, so one unreachable control plane
// does not hold up the others.
func (d *Daemon) openListeners(ctx context.Context) {
	cfg := d.snapshot()
	if !cfg.LoggedIn() {
		return
	}
	// Invariant: if a broker is listening, the sticky loopback password exists — otherwise a peer could hand
	// out a connection string with an empty password.
	if cfg.LocalPassword == "" {
		if err := d.ensureLocalPassword(); err != nil {
			fmt.Fprintln(os.Stderr, "could not prepare the local password:", err)
			return
		}
	}
	var wg sync.WaitGroup
	for name, srv := range cfg.Servers {
		if !srv.LoggedIn() {
			continue
		}
		wg.Go(func() {
			// Serialized per server: two passes (a login racing the ticker or a /reload) could both see a
			// datasource as needing a listener, and the loser's bind would fail on the winner's port.
			mu := lockOf(&d.discoveryMus, name)
			mu.Lock()
			defer mu.Unlock()
			// Re-read under the lock: the snapshot above may predate a logout or a newer login.
			if cur := d.snapshot().Servers[name]; cur.LoggedIn() {
				d.syncServer(ctx, name, cur)
			}
		})
	}
	wg.Wait()
}

// syncServer discovers one server's datasources, refreshes each one's current form (so a re-advertised address
// is picked up), assigns a sticky loopback port to any new brokerable one, and starts its listener. Discovery
// // failures are recorded and surfaced, never fatal. Callers hold the server's discoveryMus lock.
//
// Every write after the network call first checks that srv is still the server's live session (a logout, a
// URL change, or an unset-and-recreate may have landed meanwhile), so a stale catalog never pairs with a newer
// token and a forgotten server never reappears.
func (d *Daemon) syncServer(ctx context.Context, server string, srv *state.Server) {
	current := func() bool { return state.SameSession(srv, d.cfg.Servers[server]) } // callers hold d.mu
	dss, err := discoverDatasources(ctx, d.httpClient, srv.ControlPlane, srv.Token)
	if err != nil {
		// Deliberately keep the existing listeners: a failed discovery says nothing about authorization, and
		// tearing brokers down on every CP hiccup or laptop-sleep would make a saved connection unusable. The
		// enforcement boundary is not here — the proxy re-validates the token and re-decides EVERY statement
		// server-side, so a still-open broker cannot outlive the revocation of what it may read.
		d.mu.Lock()
		if current() {
			d.lastDiscoveryErr[server] = err.Error()
		}
		d.mu.Unlock()
		fmt.Fprintf(os.Stderr, "datasource discovery for %q failed: %v\n", server, err)
		d.publishStatus()
		return
	}

	brokerableNow := make(map[dsKey]bool, len(dss))
	needsListener := make([]driver.Endpoint, 0, len(dss))
	var stale []net.Listener
	var revoked []dsKey

	d.mu.Lock()
	if !current() {
		d.mu.Unlock()
		return
	}
	delete(d.lastDiscoveryErr, server)
	for key := range d.unbrokered {
		if key.server == server {
			delete(d.unbrokered, key)
		}
	}
	for key := range d.bindErrors {
		if key.server == server {
			delete(d.bindErrors, key)
		}
	}
	for _, ds := range dss {
		key := dsKey{server, ds.Name}
		if d.providers.UnavailableReason(ds.Clone()) != "" {
			d.unbrokered[key] = ds.Clone()
			continue
		}
		provider, _ := d.providers.Lookup(ds.Engine)
		if ln := d.listeners[key]; ln != nil && (ln.engine != ds.Engine || ln.routeKey != provider.RouteKey(ds.Clone())) {
			stale = append(stale, ln)
			revoked = append(revoked, key)
			delete(d.listeners, key)
		}
		brokerableNow[key] = true
		d.datasources[key] = ds.Clone()
		if _, already := d.listeners[key]; !already {
			needsListener = append(needsListener, ds)
		}
	}
	// Reconcile deletions/revocations: a datasource that dropped out of discovery — deleted, or
	// connect-revoked so it no longer appears under ?connectable=true — must stop being brokered, or the
	// daemon would keep handing the wire token to a stale/unauthorized address. The sticky port in the config
	// is kept, so a later re-grant reuses the same local port + saved connection string.
	for key, ln := range d.listeners {
		if key.server == server && !brokerableNow[key] {
			stale = append(stale, ln)
			revoked = append(revoked, key)
			delete(d.listeners, key)
			delete(d.datasources, key)
			fmt.Fprintf(os.Stderr, "broker for %s/%s closed (no longer connectable)\n", server, key.name)
		}
	}
	d.mu.Unlock()
	for _, ln := range stale {
		ln.Close()
	}
	// End sessions already established on a revoked datasource too: a closed listener stops new accepts, but an
	// open session would otherwise keep piping to an address this principal is no longer authorized for.
	if len(revoked) > 0 {
		d.closeConns(revoked...)
	}

	ports := map[string]int{}
	if len(needsListener) > 0 {
		if err := d.commit(func(c *state.Config) error {
			if live := c.Servers[server]; live == nil || live.ID != srv.ID {
				return nil
			}
			for _, ds := range needsListener {
				ports[ds.Name] = c.AssignPort(server, ds.Name)
			}
			return nil
		}); err != nil {
			fmt.Fprintln(os.Stderr, "assign ports:", err)
			return
		}
	}

	for _, ds := range needsListener {
		key := dsKey{server, ds.Name}
		port, ok := ports[ds.Name]
		if !ok {
			continue // the server was unset while discovering
		}
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// A foreign service holds this port. Keep the assignment: freeing it would just hand the SAME lowest
			// free slot back on the next pass, retrying the same occupied port forever. Instead surface the
			// datasource with the reason — otherwise it appears in no map at all and `pmon status` says "no
			// datasources yet", telling the user they have no access when a port collision is the problem.
			fmt.Fprintf(os.Stderr, "listen %s for %s/%s: %v\n", addr, server, ds.Name, err)
			d.mu.Lock()
			if current() {
				blocked := ds
				blocked.AdvertiseAddr = ""
				d.unbrokered[key] = blocked
				d.bindErrors[key] = fmt.Sprintf("local port %d is in use", port)
			}
			d.mu.Unlock()
			continue
		}
		// Re-check the login IN the same critical section that registers the listener. The discovery above did
		// network I/O, and a logout landing during it clears the credentials — binding afterwards would leave an
		// open loopback port the operator was told was closed, which no later pass reaps and which serves under
		// whatever the config holds at accept time.
		provider, _ := d.providers.Lookup(ds.Engine)
		listenerCtx, cancel := context.WithCancel(d.ctx)
		broker := &brokerListener{
			Listener: ln, ctx: listenerCtx, cancel: cancel,
			engine: ds.Engine, routeKey: provider.RouteKey(ds.Clone()),
			track: func(conn net.Conn) net.Conn { return d.trackConn(key, conn) },
		}
		d.mu.Lock()
		stillLoggedIn := current()
		if stillLoggedIn {
			d.listeners[key] = broker
		}
		d.mu.Unlock()
		if !stillLoggedIn {
			broker.Close()
			fmt.Fprintf(os.Stderr, "discarding the broker for %s/%s: logged out while discovering\n", server, ds.Name)
			continue
		}
		fmt.Printf("broker %s -> %s (%s, %s)\n", addr, ds.AdvertiseAddr, server, ds.Engine)
		go d.serve(broker, key, provider)
	}
	if len(needsListener) > 0 || len(stale) > 0 {
		d.publishStatus()
	}
}

func (d *Daemon) closeAllListeners() {
	d.mu.Lock()
	lns := make([]net.Listener, 0, len(d.listeners))
	for name, ln := range d.listeners {
		lns = append(lns, ln)
		delete(d.listeners, name)
	}
	d.mu.Unlock()
	for _, ln := range lns {
		ln.Close()
	}
}

func (d *Daemon) serve(ln *brokerListener, key dsKey, broker driver.Provider) {
	err := broker.Serve(ln.ctx, ln, func() (driver.Endpoint, driver.Credentials, bool) {
		return d.resolveSession(key, ln)
	})
	ln.Close()

	mu := lockOf(&d.discoveryMus, key.server)
	mu.Lock()
	defer mu.Unlock()
	d.mu.Lock()
	if d.listeners[key] != ln {
		d.mu.Unlock()
		return
	}
	delete(d.listeners, key)
	d.unbrokered[key] = d.datasources[key]
	d.bindErrors[key] = "broker stopped"
	if err != nil {
		d.bindErrors[key] = err.Error()
	}
	d.mu.Unlock()
	d.closeConns(key)
	d.publishStatus()
}

func (d *Daemon) resolveSession(key dsKey, ln *brokerListener) (driver.Endpoint, driver.Credentials, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ds, ok := d.datasources[key]
	srv := d.cfg.Servers[key.server]
	if !ok || !srv.LoggedIn() || d.listeners[key] != ln || ln.ctx.Err() != nil || ds.Engine != ln.engine || d.providers.UnavailableReason(ds.Clone()) != "" {
		return driver.Endpoint{}, driver.Credentials{}, false
	}
	return ds.Clone(), driver.Credentials{
		Principal: srv.Principal, Token: srv.Token, LocalPassword: d.cfg.LocalPassword,
	}, true
}

// closeConns closes established sessions for the given datasources, or all sessions when keys is empty.
func (d *Daemon) closeConns(keys ...dsKey) {
	d.mu.Lock()
	var doomed []net.Conn
	if len(keys) == 0 {
		for _, conns := range d.liveConns {
			for _, c := range conns {
				doomed = append(doomed, c)
			}
		}
	} else {
		for _, key := range keys {
			for _, c := range d.liveConns[key] {
				doomed = append(doomed, c)
			}
		}
	}
	d.mu.Unlock()
	for _, c := range doomed {
		c.Close()
	}
}

func (d *Daemon) rediscoverLoop(ctx context.Context) {
	t := time.NewTicker(rediscoverInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.openListeners(ctx)
		case <-d.rediscover:
			d.openListeners(ctx)
		}
	}
}

// renewLoop silently re-mints the wire token before it expires, so a saved connection keeps working without a
// terminal. A refusal means the session window closed: brokering continues on the current token until it
// expires, and the daemon announces that a login is required rather than failing silently.
func (d *Daemon) renewLoop(ctx context.Context) {
	t := time.NewTicker(renewCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.maybeRenew(ctx)
		}
	}
}

// renewLead is how long before expiry this token should be renewed: [maxRenewLeadTime] for a long-lived token,
// or a fraction of its own lifetime for a short one. The control plane clamps TTL to a 60s floor, so a fixed
// lead would leave any shorter token permanently past its threshold — renewing on every tick for its whole life
// rather than once near the end. Falls back to the max lead when the issue time is unknown (a config written
// before IssuedAt existed), which is the pre-existing behavior.
func renewLead(srv state.Server, expiry time.Time) time.Duration {
	issued, err := time.Parse(time.RFC3339, srv.IssuedAt)
	if err != nil {
		return maxRenewLeadTime
	}
	lifetime := expiry.Sub(issued)
	if lifetime <= 0 {
		return maxRenewLeadTime
	}
	lead := lifetime / renewLeadFraction
	// Never narrower than a couple of ticks: the loop only samples every renewCheckInterval, so a lead shorter
	// than that can fall entirely between two samples and the token expires un-renewed. Scaling the lead down
	// for short tokens must not turn "renews too often" into "never renews".
	if floor := 2 * renewCheckInterval; lead < floor {
		lead = floor
	}
	if lead > maxRenewLeadTime {
		return maxRenewLeadTime
	}
	return lead
}

// maybeRenew renews every logged-in server's token that is near expiry, concurrently, so a stalled control
// plane cannot push another server's renewal past its expiry.
func (d *Daemon) maybeRenew(ctx context.Context) {
	var wg sync.WaitGroup
	for name, srv := range d.snapshot().Servers {
		wg.Go(func() { d.maybeRenewServer(ctx, name, *srv) })
	}
	wg.Wait()
}

func (d *Daemon) maybeRenewServer(ctx context.Context, name string, srv state.Server) {
	d.mu.Lock()
	refused := d.reauthRequired[name]
	d.mu.Unlock()
	if refused || !srv.LoggedIn() || srv.RenewalToken == "" {
		return
	}
	expiry, err := time.Parse(time.RFC3339, srv.ExpiresAt)
	if err != nil || time.Until(expiry) > renewLead(srv, expiry) {
		return
	}

	// current reports whether the renewed session is still the server's live one: a login completing during the
	// round-trip installs a new token AND a new renewal token, and a logout clears them.
	current := func(s *state.Server) bool { return state.SameSession(&srv, s) }
	res, err := login.Renew(ctx, d.httpClient, srv.ControlPlane, srv.RenewalToken)
	if errors.Is(err, login.ErrRenewalRefused) {
		d.mu.Lock()
		if current(d.cfg.Servers[name]) {
			d.reauthRequired[name] = true
			d.mu.Unlock()
			fmt.Fprintf(os.Stderr, "token renewal for %q refused — a fresh `pmon login` is required\n", name)
			d.publish(control.Event{Kind: "reauth", Message: fmt.Sprintf("the session window for %q has closed; run `pmon login`", name)})
			d.publishStatus()
			return
		}
		d.mu.Unlock()
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "token renewal for %q failed (will retry): %v\n", name, err)
		return
	}
	// A renewal with no expiry would leave maybeRenew unable to parse ExpiresAt on every later tick, so it
	// would silently stop renewing forever. Treat it as a failed attempt and retry rather than persisting it.
	if res.ExpiresAt == "" {
		fmt.Fprintf(os.Stderr, "token renewal for %q returned no expiry (will retry)\n", name)
		return
	}

	issuedAt := time.Now().UTC().Format(time.RFC3339)
	if err := d.commit(func(c *state.Config) error {
		// Re-checked under the config lock: writing a token back after a logout would resurrect the session with
		// no principal and no renewal secret, and LoggedIn() would report true again.
		s := c.Servers[name]
		if !current(s) {
			return nil
		}
		s.Token = res.Token
		s.ExpiresAt = res.ExpiresAt
		s.IssuedAt = issuedAt
		return nil
	}); err != nil {
		fmt.Fprintln(os.Stderr, "could not save the renewed token:", err)
		return
	}
	d.publishStatus()
}
