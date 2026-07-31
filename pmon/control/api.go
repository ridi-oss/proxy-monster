// Package control is the daemon's local control API and the client both peers use to drive it. The CLI and
// the tray are SYMMETRIC peers over this API: neither is privileged, both can start and stop the daemon, and
// both work when it is down. All state and logic live in the daemon; a peer holds none.
//
// Transport is a unix socket in the state directory. Not a loopback TCP port: this API can start a login
// flow, and a localhost port is reachable from any web page in the user's browser. The socket's directory is
// created 0700, so filesystem permissions ARE the authentication — only the same OS user can connect.
package control

// Status is the daemon's whole observable state, and the only thing a peer renders. Live listener facts come
// from the daemon's own maps, never from the sticky port map on disk — a revoked datasource keeps its port
// assignment but stops being brokered, so counting the config would over-report.
type Status struct {
	Principal        string `json:"principal"`
	ControlPlane     string `json:"controlPlane"`
	LoggedIn         bool   `json:"loggedIn"`
	ExpiresAt        string `json:"expiresAt"`
	SessionExpiresAt string `json:"sessionExpiresAt"`
	// ReauthRequired is set once renewal has been refused: the session window closed, so brokering keeps
	// working only until the wire token expires and the user must log in again.
	ReauthRequired bool `json:"reauthRequired"`
	// StartedAt is the daemon's start time (RFC3339), so a peer can show an uptime.
	StartedAt string `json:"startedAt"`
	// Version is the daemon's build, which a peer compares against its own: the daemon keeps running
	// when the binary on disk is replaced.
	Version string `json:"version,omitempty"`
	// LocalPassword is the sticky loopback password a peer puts in the connection strings it hands out. It
	// travels only over the 0700 control socket, which is the same trust boundary that lets a peer start a
	// login at all.
	LocalPassword string `json:"localPassword"`
	// LastDiscoveryError is the most recent discovery failure, cleared on the next success. A peer surfaces
	// it instead of silently showing an empty datasource list.
	LastDiscoveryError string       `json:"lastDiscoveryError,omitempty"`
	Datasources        []Datasource `json:"datasources"`
}

// Datasource is one brokered datasource as the daemon currently sees it.
type Datasource struct {
	Name   string `json:"name"`
	Engine string `json:"engine"`
	DbName string `json:"dbName"`
	// LocalPort is the sticky loopback port a client connects to; 0 when this datasource has no listener.
	LocalPort int `json:"localPort"`
	// AdvertiseAddr is the proxy address the broker currently dials.
	AdvertiseAddr string `json:"advertiseAddr"`
	// TLSVerified reports whether the upstream hop verifies the proxy against a control-plane-advertised
	// certificate chain (rather than falling back to system trust, or running plaintext).
	TLSVerified bool `json:"tlsVerified"`
	// WireTLS reports whether the proxy serves TLS at all. Distinct from TLSVerified: an operator may serve a
	// publicly-trusted certificate and publish no chain, which is encrypted-and-verified against system trust.
	// Only WireTLS false is plaintext.
	WireTLS bool `json:"wireTls"`
	// Brokered is false for a datasource discovered but not fronted (no advertised address, or an engine the
	// broker does not speak yet).
	Brokered bool `json:"brokered"`
	// Reason explains a false Brokered, for a peer to show in place of a connection string.
	Reason string `json:"reason,omitempty"`
	// LiveConns is the number of client connections currently open through this broker.
	LiveConns int `json:"liveConns"`
}

// TotalLiveConns is how many client connections are open across every broker — what a stop/quit confirmation
// warns about before dropping them.
func (s *Status) TotalLiveConns() int {
	n := 0
	for _, ds := range s.Datasources {
		n += ds.LiveConns
	}
	return n
}

// LoginRequest asks the daemon to run a device-auth flow. An empty ControlPlane reuses the saved one.
type LoginRequest struct {
	ControlPlane string `json:"controlPlane,omitempty"`
	TTLSeconds   int    `json:"ttlSeconds,omitempty"`
}

// LoginEvent is one step of a login, streamed as newline-delimited JSON so a peer can show the verification
// prompt the moment it exists rather than after the flow completes.
type LoginEvent struct {
	// Kind is "prompt" (open this URL), "done" (logged in), or "error".
	Kind string `json:"kind"`
	// Prompt fields, set when Kind == "prompt".
	VerificationURI string `json:"verificationUri,omitempty"`
	// VerificationURIComplete carries the code, so an opened page prefills it. A peer opens this one
	// and prints the plain one, so a user following the printed link types the code themselves.
	VerificationURIComplete string `json:"verificationUriComplete,omitempty"`
	UserCode                string `json:"userCode,omitempty"`
	// Done fields, set when Kind == "done".
	Principal string `json:"principal,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	// Error, set when Kind == "error".
	Error string `json:"error,omitempty"`
}

// Event is a daemon state change, streamed on /events. A peer redraws on any of them; the payload is
// advisory, and /status is always the authority.
type Event struct {
	// Kind is "status" (something in Status changed), "reauth" (a login is needed), or "shutdown".
	Kind    string  `json:"kind"`
	Status  *Status `json:"status,omitempty"`
	Message string  `json:"message,omitempty"`
}

// ErrorResponse is a control-API error body.
type ErrorResponse struct {
	Error string `json:"error"`
}

// Route paths on the control socket.
const (
	PathStatus   = "/status"
	PathLogin    = "/login"
	PathLogout   = "/logout"
	PathReload   = "/reload"
	PathShutdown = "/shutdown"
	PathEvents   = "/events"
)
