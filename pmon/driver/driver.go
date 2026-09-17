// Package driver is the contract between the pmon daemon and its per-engine providers: what a discovered
// datasource looks like, how a connection string is formatted for it, how its local listener is served, and
// the registry the daemon looks providers up in.
package driver

import (
	"context"
	"maps"
	"net"
)

// Endpoint is one datasource as the control plane advertises it to pmon.
type Endpoint struct {
	Name          string `json:"name"`
	Engine        string `json:"engine"`
	DbName        string `json:"dbName"`
	AdvertiseAddr string `json:"advertiseAddr"`
	CertChainPEM  string `json:"advertiseCertChain"`
	// TLS can be required even when the proxy publishes no certificate chain.
	WireTLS bool `json:"advertiseWireTls"`
	// ConnectionInfo is what the proxy published beyond its address; nil when it published nothing.
	ConnectionInfo *ConnectionInfo `json:"connectionInfo,omitempty"`
}

// Clone deep-copies the mutable ConnectionInfo so a provider may edit its copy without touching the daemon's.
func (e Endpoint) Clone() Endpoint {
	e.ConnectionInfo = e.ConnectionInfo.Clone()
	return e
}

// ConnectionInfo is the nonsecret endpoint and engine-defined properties a proxy publishes for clients. Its
// contents belong to the provider that registered the engine; the daemon only carries and clones it.
type ConnectionInfo struct {
	Endpoint   string            `json:"endpoint"`
	Properties map[string]string `json:"properties"`
}

func (info *ConnectionInfo) Clone() *ConnectionInfo {
	if info == nil {
		return nil
	}
	return &ConnectionInfo{Endpoint: info.Endpoint, Properties: maps.Clone(info.Properties)}
}

// Credentials is the logged-in session a broker forwards with: the principal, the wire token it presents
// upstream, and the sticky local password it checks the client against.
type Credentials struct {
	Principal     string
	Token         string
	LocalPassword string
}

// ResolveSession returns the datasource's current advertisement and the current credentials, or false once
// the listener's session is gone (logout, revocation, or the listener was replaced). A broker calls it per
// connection or per request, never once at start, so a re-advertised address or a renewed token is followed.
type ResolveSession func() (Endpoint, Credentials, bool)

// Format names a connection-string flavor a Provider can produce.
type Format string

const (
	URL   Format = "url"
	JDBC  Format = "jdbc"
	GoDSN Format = "go-dsn"
	CLI   Format = "cli"
	// Host is the loopback address every local broker listens on.
	Host = "127.0.0.1"
)

// Target is what a connection string is formatted for: the local broker port plus the principal and the
// sticky local password the broker checks.
type Target struct {
	Name string
	// ConnectionInfo is the datasource's published metadata, or nil; a formatter that needs it returns "" without.
	ConnectionInfo *ConnectionInfo
	Engine         string
	DbName         string
	Port           int
	User           string
	Password       string
}

// Options adjusts formatting for clients with non-default requirements.
type Options struct {
	// JDBCTruncationDiagnostics leaves the MySQL Connector/J compatibility parameter out so the driver may issue
	// SHOW WARNINGS; the default adds it.
	JDBCTruncationDiagnostics bool
}

// Provider is one engine's contract with the daemon: its name, how its connection string is written, and
// how its local listener is served. An engine pmon cannot front yet still formats; its UnavailableReason
// says why there is no listener.
type Provider interface {
	// Engine is the name the datasource advertises and the registry keys on.
	Engine() string
	// SupportedFormats lists the connection-string flavors this engine can produce; DefaultFormat is used
	// when the user names none and must be one of them (NewRegistry panics otherwise).
	SupportedFormats() []Format
	DefaultFormat() Format
	// FormatConnectionString returns the text a client pastes, or "" when the Target lacks what that
	// format needs; the caller reports that, never a partial string.
	FormatConnectionString(Format, Target, Options) string
	// UnavailableReason says why this endpoint cannot be brokered, or "" when it can. No network I/O.
	UnavailableReason(Endpoint) string
	// RouteKey decides what happens to an existing listener when the datasource is rediscovered with a
	// changed Endpoint. The daemon compares RouteKey(old) with RouteKey(new): different keys close the
	// listener and its connections and open a fresh one; equal keys keep it. Return the fields whose change
	// must restart (e.g. address + TLS chain), or "" for "never restart, new connections just dial the new
	// address" (MySQL, which dials per connection).
	RouteKey(Endpoint) string
	// Serve runs the accept loop on the daemon's listener until it closes or ctx ends: accept a client's
	// plain connection on loopback, check the local password, relay upstream with the wire token
	// injected. It closes every connection it accepts. The daemon owns the port; Serve owns the protocol.
	Serve(context.Context, net.Listener, ResolveSession) error
}
