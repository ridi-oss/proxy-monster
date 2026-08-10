// Package spi defines the dependency-free contracts between the proxy core and per-dialect leaves.
package spi

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// TargetDb is the per-datasource target-DB connection details (the service-account broker target).
type TargetDb struct {
	Host     string
	Port     int
	Db       string
	User     string
	Password string
}

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
type EnforcementClient interface {
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

// Provider bundles the per-dialect capabilities (target-DB connection, wire server, run session,
// introspection) used by dialect-neutral consumers. The pure per-dialect facts (registration engine,
// default ports, placeholder, schema resolution) live on engine.Dialect; a new dialect is one Provider
// implementation plus one registry row.
type Provider interface {
	Dialect() engine.Dialect
	NewDb() engine.Db
	OpenTarget(target TargetDb) (*sql.DB, error)
	ProbeNamespace(conn *sql.Conn, targetDb string) (defaultSchemas []string, mysqlLowerCaseTableNames *int32, err error)
	ReadTableDetail(conn *sql.Conn, schema, table string) (*TableDetail, error)
	NewWireServer(port int, targetDb TargetDb, client EnforcementClient, db engine.Db, tlsProvider func() (*tls.Config, error)) WireServer
	// NewRunSession dials and authenticates the target DB. ctx is the target-DB open context: cancelling it aborts
	// an in-flight dial/auth so a run the control-plane already closed does not finish a target-DB handshake.
	NewRunSession(ctx context.Context, target TargetDb, db engine.Db, client SessionClient, token string, connectionID []byte, guard engine.ExecGuard, readTimeout time.Duration) (TargetDbSession, error)
}

// Registry resolves the canonical PM_ENGINE name to its Provider. Consumers depend on this interface and
// receive it from the executable composition root; they never import the concrete dialect wiring package.
type Registry interface {
	For(engine.Dialect) (Provider, error)
	Names() []string
}

type registry struct {
	providers map[engine.Dialect]Provider
	names     []string
}

// NewRegistry constructs an immutable provider registry. Duplicate or invalid dialect rows are rejected.
func NewRegistry(providers ...Provider) (Registry, error) {
	registered := make(map[engine.Dialect]Provider, len(providers))
	names := make([]string, 0, len(providers))
	for i, provider := range providers {
		if provider == nil {
			return nil, fmt.Errorf("spi: provider row %d is nil", i)
		}
		dialect := provider.Dialect()
		if !dialect.Valid() {
			return nil, fmt.Errorf("spi: provider row %d has an invalid dialect", i)
		}
		if _, exists := registered[dialect]; exists {
			return nil, fmt.Errorf("spi: duplicate provider for engine %q", dialect.WireName())
		}
		registered[dialect] = provider
		names = append(names, dialect.WireName())
	}
	sort.Strings(names)
	return &registry{providers: registered, names: names}, nil
}

// MustRegistry is NewRegistry for static executable wiring; invalid rows panic during process startup.
func MustRegistry(providers ...Provider) Registry {
	registry, err := NewRegistry(providers...)
	if err != nil {
		panic(err)
	}
	return registry
}

func (r *registry) For(dialect engine.Dialect) (Provider, error) {
	provider, ok := r.providers[dialect]
	if !ok {
		return nil, fmt.Errorf("unsupported engine %q (registered: %s)", dialect.WireName(), strings.Join(r.names, ", "))
	}
	return provider, nil
}

func (r *registry) Names() []string { return append([]string(nil), r.names...) }
