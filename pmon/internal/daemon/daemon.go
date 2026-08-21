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
	"maps"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/login"
	"github.com/ridi-oss/proxy-monster/pmon/state"
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
	// dialTimeout bounds a broker's dial to a proxy. It covers refusal only — see handshakeTimeout for silence
	// after accept.
	dialTimeout = 10 * time.Second
	// localHandshakeTimeout bounds startup and local-password authentication before the client can hold a broker
	// connection indefinitely.
	localHandshakeTimeout = 20 * time.Second
	// handshakeTimeout bounds the whole upstream handshake (greeting, TLS, auth). A proxy that accepts and then
	// goes silent would otherwise park a goroutine and its two sockets forever, unreachable by logout or
	// revocation, since closing the local side does not unblock a read on the upstream one.
	handshakeTimeout = 20 * time.Second
	// acceptBackoff is the pause after a transient Accept error, so a persistent failure (e.g. fd
	// exhaustion) can't spin the CPU.
	acceptBackoff = 50 * time.Millisecond
)

// Daemon is the running broker. It is the sole owner of pmon's state: peers read it through the control API
// and mutate it only by asking the daemon to act.
type Daemon struct {
	httpClient *http.Client
	startedAt  time.Time
	version    string

	// stop ends the daemon's run; it is what a control-API shutdown triggers.
	stop context.CancelFunc
	// rediscover carries a nudge to run discovery now instead of waiting for the next cycle.
	rediscover chan struct{}
	// loginMu serializes logins, so two peers asking at once cannot start two device flows.
	loginMu sync.Mutex
	// discoveryMu serializes openListeners end to end. Its fine-grained d.mu sections are not enough on their
	// own: two concurrent passes (a login racing the rediscover ticker or a peer's /reload) could both observe
	// a datasource as needing a listener, and the loser's bind would fail on the winner's port and then free
	// the sticky assignment — leaving the datasource brokered but reporting LocalPort 0, so `pmon show` would
	// emit a connection string with port 0 and the sticky identity would be lost across restarts.
	discoveryMu sync.Mutex

	mu                     sync.Mutex
	cfg                    state.Config
	localPassword          string
	nextListenerGeneration uint64
	// listeners maps a datasource name to its loopback listener; presence here means "brokered right now",
	// which is what /status reports (the sticky port map on disk keeps revoked datasources, so counting it
	// would over-report).
	listeners           map[string]net.Listener
	listenerGenerations map[string]uint64
	// datasources maps a datasource name to its CURRENT discovered form, so a broker always dials the
	// freshly-advertised address rather than the one captured when its listener opened.
	datasources map[string]Datasource
	// unbrokered holds discovered-but-not-fronted datasources, so a peer can explain them.
	unbrokered map[string]Datasource
	// bindErrors maps a datasource name to why its listener could not open, so the reason a peer shows is the
	// real cause (a port collision) rather than a generic one.
	bindErrors map[string]string
	// liveConns holds the OPEN client connections per datasource, keyed by a serial so each can be removed
	// independently. Tracking the connections (rather than only counting them) is what lets logout and
	// revocation close sessions that are already accepted — closing a listener stops new accepts but leaves an
	// established session piping until its client happens to disconnect.
	liveConns map[string]map[uint64]net.Conn
	// nextConnID serializes the keys in liveConns.
	nextConnID uint64
	// lastDiscoveryErr is the most recent discovery failure, cleared on the next success.
	lastDiscoveryErr string
	// reauthRequired is set once renewal is refused: brokering keeps working until the wire token expires,
	// but only a fresh login recovers it.
	reauthRequired bool

	subMu   sync.Mutex
	subs    map[int]chan control.Event
	nextSub int
}

// New builds a daemon with no credentials loaded. version is what it reports over the control socket.
func New(version string) *Daemon {
	return &Daemon{
		version:             version,
		httpClient:          &http.Client{Timeout: 15 * time.Second},
		startedAt:           time.Now(),
		rediscover:          make(chan struct{}, 1),
		listeners:           map[string]net.Listener{},
		listenerGenerations: map[string]uint64{},
		datasources:         map[string]Datasource{},
		unbrokered:          map[string]Datasource{},
		bindErrors:          map[string]string{},
		liveConns:           map[string]map[uint64]net.Conn{},
		subs:                map[int]chan control.Event{},
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
		d.cfg = *cfg
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

// snapshot returns an independent copy of the current config, so callers read it without holding the lock.
//
// Ports is CLONED, not shared: a bare struct copy would alias the live map, and a caller that read or wrote it
// outside the lock would race against port assignment with no compiler or race-detector warning until the
// timing happened to line up.
func (d *Daemon) snapshot() state.Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	cfg := d.cfg
	cfg.Ports = maps.Clone(d.cfg.Ports)
	return cfg
}

// ensureLocalPassword generates the sticky loopback password once and caches it in memory.
func (d *Daemon) ensureLocalPassword() error {
	var pw string
	if err := state.Update(func(c *state.Config) error {
		p, err := c.EnsureLocalPassword()
		pw = p
		return err
	}); err != nil {
		return err
	}
	d.mu.Lock()
	d.localPassword = pw
	d.cfg.LocalPassword = pw
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
		Principal:        d.cfg.Principal,
		ControlPlane:     d.cfg.ControlPlane,
		LoggedIn:         d.cfg.LoggedIn(),
		ExpiresAt:        d.cfg.ExpiresAt,
		SessionExpiresAt: d.cfg.SessionExpiresAt,
		ReauthRequired:   d.reauthRequired,
		StartedAt:        d.startedAt.Format(time.RFC3339),
		Version:          d.version,
		// Fall back to the persisted value: the in-memory copy is only set by ensureLocalPassword, whose failure
		// at startup is tolerated, so a config that already HAS a password would otherwise report none and
		// `pmon show` would emit a connection string with an empty password.
		LocalPassword:      cmp.Or(d.localPassword, d.cfg.LocalPassword),
		LastDiscoveryError: d.lastDiscoveryErr,
		Datasources:        make([]control.Datasource, 0, len(d.datasources)+len(d.unbrokered)),
	}
	// Every tracked connection must be accounted for, including one whose datasource has since been pruned
	// (revoked mid-session, or a broker still parked in the upstream handshake). The registry — not the listener
	// set — is the truth: stop/quit read this count to decide whether to warn before dropping live queries, so a
	// connection missing from it is a query dropped with no confirmation.
	counted := make(map[string]bool, len(d.liveConns))
	for name, ds := range d.datasources {
		if _, live := d.listeners[name]; !live {
			continue
		}
		out.Datasources = append(out.Datasources, control.Datasource{
			Name:          ds.Name,
			Engine:        ds.Engine,
			DbName:        ds.DbName,
			LocalPort:     d.cfg.Ports[name],
			AdvertiseAddr: ds.AdvertiseAddr,
			TLSVerified:   ds.CertChainPEM != "",
			WireTLS:       ds.WireTLS,
			Brokered:      true,
			LiveConns:     len(d.liveConns[name]),
		})
		counted[name] = true
	}
	for name, ds := range d.unbrokered {
		if _, live := d.listeners[name]; live {
			continue
		}
		out.Datasources = append(out.Datasources, control.Datasource{
			Name:          ds.Name,
			Engine:        ds.Engine,
			DbName:        ds.DbName,
			AdvertiseAddr: ds.AdvertiseAddr,
			TLSVerified:   ds.CertChainPEM != "",
			WireTLS:       ds.WireTLS,
			Brokered:      false,
			Reason:        cmp.Or(d.bindErrors[name], ds.UnbrokerableReason()),
			LiveConns:     len(d.liveConns[name]),
		})
		counted[name] = true
	}
	// Anything left in the registry has no row above — its datasource was pruned while a session was open.
	// Surface it rather than dropping it from the count.
	for name, conns := range d.liveConns {
		if counted[name] || len(conns) == 0 {
			continue
		}
		out.Datasources = append(out.Datasources, control.Datasource{
			Name:      name,
			Brokered:  false,
			Reason:    "no longer connectable; closing",
			LiveConns: len(conns),
		})
	}
	sort.Slice(out.Datasources, func(i, j int) bool { return out.Datasources[i].Name < out.Datasources[j].Name })
	return out
}

// LocalPassword is the sticky loopback password a peer hands out in connection strings.
func (d *Daemon) LocalPassword() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.localPassword
}

// Login runs the device-auth flow, persists the result, and brings the brokers up — so a login is the only
// step needed to reach a datasource. Serialized: a second concurrent login waits rather than starting a
// competing device flow.
func (d *Daemon) Login(ctx context.Context, req control.LoginRequest, onEvent func(control.LoginEvent)) error {
	d.loginMu.Lock()
	defer d.loginMu.Unlock()

	cp := req.ControlPlane
	if cp == "" {
		cp = d.snapshot().ControlPlane
	}

	res, err := login.Run(ctx, login.Options{
		ControlPlane: cp,
		TTLSeconds:   req.TTLSeconds,
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
	if cp == "" {
		cp = login.DefaultControlPlane
	}

	if err := state.Update(func(c *state.Config) error {
		c.ControlPlane = cp
		c.Principal = res.Principal
		c.Token = res.Token
		c.ExpiresAt = res.ExpiresAt
		c.IssuedAt = time.Now().UTC().Format(time.RFC3339)
		c.SessionExpiresAt = res.SessionExpiresAt
		c.RenewalToken = res.RenewalToken
		return nil
	}); err != nil {
		return fmt.Errorf("could not save the login: %w", err)
	}
	cfg, err := state.Load()
	if err != nil {
		return fmt.Errorf("could not re-read the saved login: %w", err)
	}
	d.mu.Lock()
	d.cfg = *cfg
	d.reauthRequired = false
	d.mu.Unlock()

	onEvent(control.LoginEvent{
		Kind: "done", Principal: res.Principal, ExpiresAt: res.ExpiresAt,
	})

	// Bring brokers up immediately, then announce the new state.
	d.openListeners(ctx)
	d.publishStatus()
	return nil
}

// Logout clears the credentials and closes every broker, leaving the daemon running and idle.
func (d *Daemon) Logout() error {
	if err := state.Update(func(c *state.Config) error {
		c.Principal = ""
		c.Token = ""
		c.ExpiresAt = ""
		c.SessionExpiresAt = ""
		c.RenewalToken = ""
		return nil
	}); err != nil {
		return err
	}
	d.mu.Lock()
	d.cfg.Principal, d.cfg.Token, d.cfg.ExpiresAt, d.cfg.IssuedAt = "", "", "", ""
	d.cfg.SessionExpiresAt, d.cfg.RenewalToken = "", ""
	d.datasources = map[string]Datasource{}
	d.unbrokered = map[string]Datasource{}
	d.listenerGenerations = map[string]uint64{}
	d.reauthRequired = false
	d.mu.Unlock()
	// Clear authority first; a connection accepted just before logout may not be registered for closeConns yet.
	d.closeAllListeners()
	d.closeConns()
	d.publishStatus()
	return nil
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

// openListeners discovers datasources, refreshes each one's current form (so a re-advertised address is
// picked up), assigns a sticky loopback port to any new brokerable one, and starts its listener. Discovery
// failures are recorded and surfaced, never fatal.
func (d *Daemon) openListeners(ctx context.Context) {
	d.discoveryMu.Lock()
	defer d.discoveryMu.Unlock()

	cfg := d.snapshot()
	if !cfg.LoggedIn() {
		return
	}
	// Invariant: if a broker is listening, the sticky loopback password exists — otherwise a peer could hand
	// out a connection string with an empty password. Cheap in the steady state (the in-memory check short-
	// circuits before any config write).
	if cfg.LocalPassword == "" {
		if err := d.ensureLocalPassword(); err != nil {
			fmt.Fprintln(os.Stderr, "could not prepare the local password:", err)
			return
		}
	}
	dss, err := discoverDatasources(ctx, d.httpClient, cfg.ControlPlane, cfg.Token)
	if err != nil {
		// Deliberately keep the existing listeners: a failed discovery says nothing about authorization, and
		// tearing brokers down on every CP hiccup or laptop-sleep would make a saved connection unusable. The
		// enforcement boundary is not here — the proxy re-validates the token and re-decides EVERY statement
		// server-side, so a still-open broker cannot outlive the revocation of what it may read. What a stale
		// listener costs is a confusing error at connect time instead of a clean "not connectable", and the
		// error is surfaced on /status rather than left silent. (A prolonged outage therefore delays the
		// broker-side prune, not the actual revocation.)
		d.mu.Lock()
		d.lastDiscoveryErr = err.Error()
		d.mu.Unlock()
		fmt.Fprintln(os.Stderr, "datasource discovery failed:", err)
		d.publishStatus()
		return
	}

	brokerableNow := make(map[string]bool, len(dss))
	needsListener := make([]Datasource, 0, len(dss))
	var stale []net.Listener
	var closeSessions []string

	d.mu.Lock()
	d.lastDiscoveryErr = ""
	d.unbrokered = map[string]Datasource{}
	d.bindErrors = map[string]string{}
	for _, ds := range dss {
		if !ds.Brokerable() {
			d.unbrokered[ds.Name] = ds
			continue
		}
		brokerableNow[ds.Name] = true
		previous := d.datasources[ds.Name]
		ln, already := d.listeners[ds.Name]
		d.datasources[ds.Name] = ds
		if already && previous.Engine != ds.Engine {
			stale = append(stale, ln)
			closeSessions = append(closeSessions, ds.Name)
			delete(d.listeners, ds.Name)
			delete(d.listenerGenerations, ds.Name)
			needsListener = append(needsListener, ds)
			fmt.Fprintf(os.Stderr, "broker for %q restarting for engine %s\n", ds.Name, ds.Engine)
		} else if !already {
			needsListener = append(needsListener, ds)
		}
	}
	// Reconcile deletions/revocations: a datasource that dropped out of discovery — deleted, or
	// connect-revoked so it no longer appears under ?connectable=true — must stop being brokered, or the
	// daemon would keep handing the wire token to a stale/unauthorized address. Close its listener (its serve
	// loop exits on the closed listener) and forget its current form. The sticky port in the config is kept,
	// so a later re-grant reuses the same local port + saved connection string.
	for name, ln := range d.listeners {
		if !brokerableNow[name] {
			stale = append(stale, ln)
			closeSessions = append(closeSessions, name)
			delete(d.listeners, name)
			delete(d.listenerGenerations, name)
			delete(d.datasources, name)
			fmt.Fprintf(os.Stderr, "broker for %q closed (no longer connectable)\n", name)
		}
	}
	d.mu.Unlock()
	for _, ln := range stale {
		ln.Close()
	}
	// End sessions already established on a revoked or protocol-changed datasource too: a closed listener stops
	// new accepts, but an open session would otherwise keep piping through the old broker.
	if len(closeSessions) > 0 {
		d.closeConns(closeSessions...)
	}

	ports := map[string]int{}
	if len(needsListener) > 0 {
		if err := state.Update(func(c *state.Config) error {
			for _, ds := range needsListener {
				ports[ds.Name] = c.AssignPort(ds.Name)
			}
			return nil
		}); err != nil {
			fmt.Fprintln(os.Stderr, "assign ports:", err)
			return
		}
		d.mu.Lock()
		for name, p := range ports {
			if d.cfg.Ports == nil {
				d.cfg.Ports = map[string]int{}
			}
			d.cfg.Ports[name] = p
		}
		d.mu.Unlock()
	}

	for _, ds := range needsListener {
		addr := fmt.Sprintf("127.0.0.1:%d", ports[ds.Name])
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// A foreign service holds this port. Keep the assignment: freeing it would just hand the SAME lowest
			// free slot back on the next pass, retrying the same occupied port forever. Instead surface the
			// datasource with the reason — otherwise it appears in no map at all and `pmon status` says "no
			// datasources yet", telling the user they have no access when a port collision is the problem.
			fmt.Fprintf(os.Stderr, "listen %s for %q: %v\n", addr, ds.Name, err)
			d.mu.Lock()
			blocked := ds
			blocked.AdvertiseAddr = ""
			d.unbrokered[ds.Name] = blocked
			d.bindErrors[ds.Name] = fmt.Sprintf("local port %d is in use", ports[ds.Name])
			d.mu.Unlock()
			continue
		}
		// Re-check the login IN the same critical section that registers the listener. The discovery above did
		// network I/O, and a logout landing during it clears the credentials — binding afterwards would leave an
		// open loopback port the operator was told was closed, which no later pass reaps (every one returns
		// early on !LoggedIn) and which serves under whatever the config holds at accept time.
		d.mu.Lock()
		stillLoggedIn := d.cfg.LoggedIn()
		var generation uint64
		if stillLoggedIn {
			d.nextListenerGeneration++
			generation = d.nextListenerGeneration
			d.listeners[ds.Name] = ln
			d.listenerGenerations[ds.Name] = generation
		}
		d.mu.Unlock()
		if !stillLoggedIn {
			ln.Close()
			fmt.Fprintf(os.Stderr, "discarding the broker for %q: logged out while discovering\n", ds.Name)
			continue
		}
		fmt.Printf("broker %s -> %s (%s)\n", addr, ds.AdvertiseAddr, ds.Engine)
		go d.serve(ctx, ln, ds.Name, ds.Engine, generation)
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
		delete(d.listenerGenerations, name)
	}
	d.mu.Unlock()
	for _, ln := range lns {
		ln.Close()
	}
}

func (d *Daemon) serve(ctx context.Context, ln net.Listener, name, engine string, generation uint64) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // listener closed — shutdown, logout, or this datasource was pruned
			}
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(acceptBackoff)
				continue
			}
		}
		go d.broker(c, name, engine, generation)
	}
}

func (d *Daemon) brokerState(name, engine string, generation uint64) (Datasource, state.Config, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ds, ok := d.datasources[name]
	if generation == 0 || generation != d.listenerGenerations[name] || !d.cfg.LoggedIn() || !ok || ds.Engine != engine || ds.AdvertiseAddr == "" {
		return Datasource{}, state.Config{}, false
	}
	return ds, d.cfg, true
}

// broker uses the datasource's current advertised address and the daemon's current token.
func (d *Daemon) broker(local net.Conn, name, engine string, generation uint64) {
	defer local.Close()
	deregister := d.addConn(name, local)
	defer deregister()
	if err := local.SetDeadline(time.Now().Add(localHandshakeTimeout)); err != nil {
		return
	}

	ds, cfg, ok := d.brokerState(name, engine, generation)
	if !ok {
		if engine == "postgres" {
			_ = rejectPostgresUnavailable(local)
		} else {
			_ = mysqlwire.WritePacket(local, 2, mysqlwire.ErrPacket(1045, "proxy-monster: datasource no longer available"))
		}
		return
	}
	var err error
	switch ds.Engine {
	case "mysql":
		err = brokerMySQL(local, ds.AdvertiseAddr, ds.CertChainPEM, ds.WireTLS, cfg.Principal, cfg.Token, cfg.LocalPassword)
	case "postgres":
		err = brokerPostgres(local, ds.AdvertiseAddr, ds.CertChainPEM, ds.WireTLS, cfg.Token, cfg.LocalPassword)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "broker %q: %v\n", name, err)
	}
}

// addConn registers an open client connection and returns a function that deregisters it.
func (d *Daemon) addConn(name string, c net.Conn) func() {
	d.mu.Lock()
	id := d.nextConnID
	d.nextConnID++
	if d.liveConns[name] == nil {
		d.liveConns[name] = map[uint64]net.Conn{}
	}
	d.liveConns[name][id] = c
	d.mu.Unlock()
	return func() {
		d.mu.Lock()
		if conns := d.liveConns[name]; conns != nil {
			delete(conns, id)
			if len(conns) == 0 {
				delete(d.liveConns, name)
			}
		}
		d.mu.Unlock()
	}
}

// closeConns closes every open client connection for the named datasources (all of them when names is empty),
// so a logout or a revocation actually ends established sessions instead of only refusing new ones. Each
// broker's own defer removes its entry; this just forces the socket shut so the pipe unblocks.
func (d *Daemon) closeConns(names ...string) {
	d.mu.Lock()
	var doomed []net.Conn
	if len(names) == 0 {
		for _, conns := range d.liveConns {
			for _, c := range conns {
				doomed = append(doomed, c)
			}
		}
	} else {
		for _, name := range names {
			for _, c := range d.liveConns[name] {
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
func renewLead(cfg state.Config, expiry time.Time) time.Duration {
	issued, err := time.Parse(time.RFC3339, cfg.IssuedAt)
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

func (d *Daemon) maybeRenew(ctx context.Context) {
	cfg := d.snapshot()
	d.mu.Lock()
	refused := d.reauthRequired
	d.mu.Unlock()
	if refused || !cfg.LoggedIn() || cfg.RenewalToken == "" {
		return
	}
	expiry, err := time.Parse(time.RFC3339, cfg.ExpiresAt)
	if err != nil || time.Until(expiry) > renewLead(cfg, expiry) {
		return
	}

	res, err := login.Renew(ctx, d.httpClient, cfg.ControlPlane, cfg.RenewalToken)
	if errors.Is(err, login.ErrRenewalRefused) {
		// Only mark reauth-required if this is still the session that was refused. A login that landed during
		// the round-trip has already replaced it, and its fresh session is fine.
		d.mu.Lock()
		if d.cfg.RenewalToken == cfg.RenewalToken {
			d.reauthRequired = true
			d.mu.Unlock()
			fmt.Fprintln(os.Stderr, "token renewal refused — a fresh `pmon login` is required")
			d.publish(control.Event{Kind: "reauth", Message: "the session window has closed; run `pmon login`"})
			d.publishStatus()
			return
		}
		d.mu.Unlock()
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "token renewal failed (will retry):", err)
		return
	}
	// A renewal with no expiry would leave maybeRenew unable to parse ExpiresAt on every later tick, so it
	// would silently stop renewing forever. Treat it as a failed attempt and retry rather than persisting it.
	if res.ExpiresAt == "" {
		fmt.Fprintln(os.Stderr, "token renewal returned no expiry (will retry)")
		return
	}

	// Apply ONLY if the session that was renewed is still current: a login completing during the round-trip
	// installs a new token AND a new renewal token, and writing this stale result would pair the old token with
	// the new session's principal and renewal secret.
	d.mu.Lock()
	stale := d.cfg.RenewalToken != cfg.RenewalToken
	d.mu.Unlock()
	if stale {
		return
	}
	issuedAt := time.Now().UTC().Format(time.RFC3339)
	if err := state.Update(func(c *state.Config) error {
		// Re-checked under the config lock. An EMPTY renewal token means a logout landed and cleared the
		// credentials — writing a token back would resurrect the session with no principal and no renewal
		// secret, and LoggedIn() would report true again.
		if c.RenewalToken == "" || c.RenewalToken != cfg.RenewalToken {
			return nil
		}
		c.Token = res.Token
		c.ExpiresAt = res.ExpiresAt
		c.IssuedAt = issuedAt
		return nil
	}); err != nil {
		fmt.Fprintln(os.Stderr, "could not save the renewed token:", err)
		return
	}
	d.mu.Lock()
	if d.cfg.RenewalToken != "" && d.cfg.RenewalToken == cfg.RenewalToken {
		d.cfg.Token = res.Token
		d.cfg.ExpiresAt = res.ExpiresAt
		d.cfg.IssuedAt = issuedAt
	}
	d.mu.Unlock()
	d.publishStatus()
}
