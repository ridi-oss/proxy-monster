// Package driver is the contract between the pmon daemon and its per-engine providers: what a discovered
// datasource looks like, how a connection string is formatted for it, and the registry the daemon looks
// providers up in.
package driver

// Endpoint is one datasource as the control plane advertises it to pmon.
type Endpoint struct {
	Name          string `json:"name"`
	Engine        string `json:"engine"`
	DbName        string `json:"dbName"`
	AdvertiseAddr string `json:"advertiseAddr"`
	CertChainPEM  string `json:"advertiseCertChain"`
	// TLS can be required even when the proxy publishes no certificate chain.
	WireTLS bool `json:"advertiseWireTls"`
}

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
	Engine   string
	DbName   string
	Port     int
	User     string
	Password string
}

// Options adjusts formatting for clients with non-default requirements.
type Options struct {
	// JDBCTruncationDiagnostics leaves the MySQL Connector/J compatibility parameter out so the driver may issue
	// SHOW WARNINGS; the default adds it.
	JDBCTruncationDiagnostics bool
}

// Provider is one engine's contract with the daemon. Today that is its name and how its connection
// string is written.
type Provider interface {
	// Engine is the name the datasource advertises and the registry keys on.
	Engine() string
	// FormatConnectionString returns the text a client pastes in the requested Format; an unknown Format
	// yields the engine's URL form.
	FormatConnectionString(Format, Target, Options) string
}
