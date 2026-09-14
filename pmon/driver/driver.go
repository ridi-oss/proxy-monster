package driver

import (
	"context"
	"maps"
	"net"
)

type Endpoint struct {
	Name          string `json:"name"`
	Engine        string `json:"engine"`
	DbName        string `json:"dbName"`
	AdvertiseAddr string `json:"advertiseAddr"`
	CertChainPEM  string `json:"advertiseCertChain"`
	// TLS can be required even when the proxy publishes no certificate chain.
	WireTLS        bool            `json:"advertiseWireTls"`
	ConnectionInfo *ConnectionInfo `json:"connectionInfo,omitempty"`
}

func (e Endpoint) Clone() Endpoint {
	e.ConnectionInfo = e.ConnectionInfo.Clone()
	return e
}

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

type Credentials struct {
	Principal     string
	Token         string
	LocalPassword string
}

// ResolveSession returns the current route and credentials, or false after removal or a listener change.
type ResolveSession func() (Endpoint, Credentials, bool)

type Broker interface {
	UnavailableReason(Endpoint) string
	// A changed key replaces the listener and closes its established connections.
	RouteKey(Endpoint) string
	Serve(context.Context, net.Listener, ResolveSession) error
}

type Format string

const (
	URL   Format = "url"
	JDBC  Format = "jdbc"
	GoDSN Format = "go-dsn"
	CLI   Format = "cli"
	Host         = "127.0.0.1"
)

type Target struct {
	Name           string
	ConnectionInfo *ConnectionInfo
	Engine         string
	DbName         string
	Port           int
	User           string
	Password       string
}

type Options struct {
	JDBCTruncationDiagnostics bool
}

type Renderer interface {
	Render(Format, Target, Options) string
}

type Provider struct {
	Engine            string
	SupportedFormats  []Format
	DefaultFormat     Format
	Renderer          Renderer
	Broker            Broker
	UnavailableReason string
}
