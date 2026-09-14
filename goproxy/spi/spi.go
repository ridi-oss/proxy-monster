// Package spi defines the dependency-free contracts between the proxy core and per-dialect leaves.
package spi

import (
	"context"
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// Identity is the authenticated wire identity retained for a client session.
type Identity struct {
	Principal    string
	Roles        []string
	ConnectionID []byte
	OnOpen       []*pb.Refetch
}

// RunOpen is the fully mapped run-session open nudge. MapErr is populated for malformed commands
// while still dispatching the session so its runner can fail it explicitly.
type RunOpen struct {
	SessionID    string
	Token        string
	ConnectionID []byte
	OnOpen       []*pb.Refetch
	MapErr       error
}

// RunStream is the subset of the proxy-dialed run stream used by the runner.
type RunStream interface {
	Send(*pb.ProxyRunMsg) error
	Recv() (*pb.ControlRunMsg, error)
	CloseSend() error
}

// TableDetailStream is the subset of the proxy-dialed table-detail stream used by the table browser.
type TableDetailStream interface {
	Send(*pb.ProxyTableDetailMsg) error
	Recv() (*pb.ControlTableDetailMsg, error)
}

// SessionClient is the control-plane capability a held target-DB session needs. The concrete gRPC client
// implements it, while tests can inject a fake without pulling that implementation into the SPI.
type SessionClient interface {
	engine.Decider
	PushSchemaFragment(*pb.SchemaFragmentPush) (uint64, error)
}

// EnforcementClient is the complete control-plane capability used by a native-wire server. It adds the
// post-relay completion report (engine.CompletionReporter) that only the native-wire path emits — the
// editor path streams to the control plane, which records its own completion, so SessionClient omits it.
type RequestAuthorizer interface {
	AuthorizeRequest(context.Context, *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error)
}

type EnforcementClient interface {
	RequestAuthorizer
	SessionClient
	engine.CompletionReporter
	ValidateToken(token, clientAddr string) (Identity, error)
	CloseConnection(connectionID []byte) error
}

// RunClient is the control-plane capability used by the dialect-neutral runner.
type RunClient interface {
	SessionClient
	OpenRunStream(context.Context) (RunStream, error)
	CloseConnection(connectionID []byte) error
}

// TableDetailClient is the control-plane capability used by the dialect-neutral table-detail runner.
type TableDetailClient interface {
	OpenTableDetailStream(context.Context) (TableDetailStream, error)
}

// WireServer is the enforcing native-wire broker's boot contract: Start blocks serving connections until
// the process is asked to stop; Shutdown closes the listener; Drain closes the listener and then gracefully
// winds down live client connections — in-flight statements finish, idle connections get a protocol-level
// shutdown notice and close — bounded by ctx, force-closing any that outlast it.
type WireServer interface {
	Start() error
	Shutdown()
	Drain(ctx context.Context)
}

// TargetDbSession is one dedicated run target-DB session.
type TargetDbSession interface {
	ServeStatement(sql string, maxRows int) (engine.StatementResult, error)
	// OnOpen runs the on-open catalog fetch. ctx is the target-DB open context: if the control-plane closes the
	// run (or the proxy drains) while the fetch is in flight, ctx is cancelled and the in-flight target-DB read
	// unwinds at once (a catalog push RPC to the control-plane still runs to its own deadline).
	OnOpen(ctx context.Context, cmds []*pb.Refetch) error
	Cancel() error
	Close() error
}

// TableDetail is the canonical metadata-only table-browser response shared with the control plane.
type TableDetail struct {
	Catalog      *string             `json:"catalog"`
	Schema       string              `json:"schema"`
	Table        string              `json:"table"`
	Columns      []TableDetailColumn `json:"columns"`
	Indexes      []TableIndex        `json:"indexes"`
	ForeignKeys  []TableRelation     `json:"foreignKeys"`
	ReferencedBy []TableRelation     `json:"referencedBy"`
	Metadata     TableMetadata       `json:"metadata"`
}

// TableDetailColumn describes one live target column. Classification is always nil at the proxy;
// the control plane owns that overlay.
type TableDetailColumn struct {
	Name                   string          `json:"name"`
	DataType               string          `json:"dataType"`
	Ordinal                int             `json:"ordinal"`
	Nullable               bool            `json:"nullable"`
	DefaultValue           *string         `json:"defaultValue"`
	CharacterMaximumLength *int64          `json:"characterMaximumLength"`
	NumericPrecision       *int            `json:"numericPrecision"`
	NumericScale           *int            `json:"numericScale"`
	PartOfIndex            bool            `json:"partOfIndex"`
	AutoIncrement          bool            `json:"autoIncrement"`
	Comment                *string         `json:"comment"`
	Charset                *string         `json:"charset"`
	Collation              *string         `json:"collation"`
	Classification         *Classification `json:"classification"`
}

// TableIndexColumn describes one column or expression in an index.
type TableIndexColumn struct {
	Name      string  `json:"name"`
	Position  int     `json:"position"`
	Direction *string `json:"direction"`
}

// TableIndex describes one live target index.
type TableIndex struct {
	Name    string             `json:"name"`
	Columns []TableIndexColumn `json:"columns"`
	Unique  bool               `json:"unique"`
	Type    string             `json:"type"`
}

// TableRelation describes one foreign-key relation.
type TableRelation struct {
	SourceCatalog *string  `json:"sourceCatalog"`
	TargetCatalog *string  `json:"targetCatalog"`
	Name          string   `json:"name"`
	SourceSchema  string   `json:"sourceSchema"`
	SourceTable   string   `json:"sourceTable"`
	SourceColumns []string `json:"sourceColumns"`
	TargetSchema  string   `json:"targetSchema"`
	TargetTable   string   `json:"targetTable"`
	TargetColumns []string `json:"targetColumns"`
	OnUpdate      *string  `json:"onUpdate"`
	OnDelete      *string  `json:"onDelete"`
}

// TableMetadata contains engine-specific storage metadata for one table.
type TableMetadata struct {
	Engine        string  `json:"engine"`
	EstimatedRows *int64  `json:"estimatedRows"`
	RowFormat     *string `json:"rowFormat"`
	OnDiskBytes   *int64  `json:"onDiskBytes"`
	Collation     *string `json:"collation"`
	Comment       *string `json:"comment"`
}

// Classification is the persisted control-plane overlay shape. The proxy never populates it.
type Classification struct {
	Schema     string   `json:"schema"`
	Table      string   `json:"table"`
	Column     string   `json:"column"`
	Tags       []string `json:"tags"`
	MaskFnId   *int64   `json:"maskFnId"`
	MaskFnName *string  `json:"maskFnName"`
}

type Definition struct {
	Name             string
	Engine           enginepb.Engine
	DefaultProxyPort int
}

type LookupEnv func(string) (string, bool)

// TargetInfo contains only advisory, nonsecret target metadata.
type TargetInfo struct {
	Host     string
	Port     int
	Database string
}

type NativeServerOptions struct {
	Port        int
	Client      EnforcementClient
	TLSProvider func() (*tls.Config, error)
}

type RunSessionOptions struct {
	Client       SessionClient
	Token        string
	ConnectionID []byte
	Guard        engine.ExecGuard
	ReadTimeout  time.Duration
}

type Provider interface {
	Definition() Definition
	Configure(LookupEnv) (Target, error)
}

// Target owns its configured resources; consumers request operations, not SQL connections.
type Target interface {
	ReadCatalog(context.Context) (*pb.CatalogRequest, error)
	ReadTableDetail(context.Context, *enginepb.TableRef) (*TableDetail, error)
	TargetInfo() TargetInfo
	ConnectionInfo() *pb.ConnectionInfo
	NewNativeServer(NativeServerOptions) WireServer
	NewRunSession(context.Context, RunSessionOptions) (TargetDbSession, error)
	Close() error
}

type Registry interface {
	For(string) (Provider, error)
	Names() []string
}

type registry struct {
	providers map[string]Provider
	names     []string
}

func NewRegistry(providers ...Provider) (Registry, error) {
	registered := make(map[string]Provider, len(providers))
	names := make([]string, 0, len(providers))
	for i, provider := range providers {
		if provider == nil {
			return nil, fmt.Errorf("spi: provider row %d is nil", i)
		}
		definition := provider.Definition()
		name := definition.Name
		if name == "" || name != strings.ToLower(strings.TrimSpace(name)) || definition.Engine == enginepb.Engine_ENGINE_UNSPECIFIED {
			return nil, fmt.Errorf("spi: provider row %d has an invalid definition", i)
		}
		if _, exists := registered[name]; exists {
			return nil, fmt.Errorf("spi: duplicate provider for engine %q", name)
		}
		registered[name] = provider
		names = append(names, name)
	}
	sort.Strings(names)
	return &registry{providers: registered, names: names}, nil
}

func MustRegistry(providers ...Provider) Registry {
	registry, err := NewRegistry(providers...)
	if err != nil {
		panic(err)
	}
	return registry
}

func (r *registry) For(name string) (Provider, error) {
	provider, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("unsupported engine %q (registered: %s)", name, strings.Join(r.names, ", "))
	}
	return provider, nil
}

func (r *registry) Names() []string { return append([]string(nil), r.names...) }
