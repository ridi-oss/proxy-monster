// Package engine is the proxy's single stateless enforcement relay. It makes NO enforcement
// decisions — every allow / deny / mask is the control plane's call via the Decide RPC (Cedar). The
// engine only: gathers the context the control plane needs (the connection's namespace + session-temp
// columns), calls Decide, and reduces the control plane's verdict to an instruction a dumb protocol
// applies (deny / relay / mask). It fails closed ONLY on mechanical impossibility (the control plane
// is unreachable, or a returned mask cannot be bound to the result columns). Databases and protocols
// are dumb adapters around this engine.
package engine

import (
	"errors"
	"fmt"
	"strconv"

	// The shared proxymonster.v1.Engine enum (engine.proto) is generated once, into analyzer/probe/pb —
	// goproxy links analyzer/probe into this same binary in-process (introspect.go, db.go), and two
	// independently-generated copies of the same .proto file panic the protobuf runtime's global file
	// registry at init. controlplane.proto's own generated code (goproxy/internal/pb) already resolves
	// its Engine field to this same package (see goproxy/buf.gen.yaml's Mengine.proto= mapping); this
	// import is the same resolution for this file's hand-written Dialect.Proto().
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// Dialect is the typed datasource engine — the target-DB SQL dialect and the registration identity are the
// same fact. It is the single home for every "is this MySQL or Postgres?" decision, so nothing else
// compares an engine string literal. MySQL is the priority engine (iota 0, listed first everywhere).
type Dialect int

const (
	MySQL Dialect = iota
	Postgres
	// invalidDialect is the fail-closed value ParseDialect returns for an unrecognized engine; both
	// IsMySQL and IsPostgres report false for it.
	invalidDialect Dialect = -1
)

// ParseDialect maps a canonical registration/wire engine string to its Dialect, fail-closed. Callers pass
// the already-lowercased wire string ("mysql" | "postgres"); the match is case-sensitive to mirror the
// config boundary (config.Load lowercases PM_ENGINE) — an unrecognized value is an error, never a silent
// default.
func ParseDialect(raw string) (Dialect, error) {
	switch raw {
	case "mysql":
		return MySQL, nil
	case "postgres":
		return Postgres, nil
	default:
		return invalidDialect, fmt.Errorf("unsupported engine %q (expected mysql or postgres)", raw)
	}
}

// WireName is the canonical registration/wire string for the dialect ("mysql" | "postgres").
func (d Dialect) WireName() string {
	switch d {
	case MySQL:
		return "mysql"
	case Postgres:
		return "postgres"
	default:
		return fmt.Sprintf("Dialect(%d)", int(d))
	}
}

// IsMySQL reports whether this is the MySQL dialect.
//
// Calling this to branch behavior at a call site is almost always wrong: per-dialect behavior belongs in
// a method on Dialect (Proto, Placeholder, DefaultProxyPort, …), so adding a future engine means
// implementing the type's methods, not hunting down scattered call-site branches.
// Kept only for a genuinely local one-off.
func (d Dialect) IsMySQL() bool { return d == MySQL }

// IsPostgres reports whether this is the Postgres dialect. See IsMySQL: prefer a method on Dialect over
// branching on this at a call site.
func (d Dialect) IsPostgres() bool { return d == Postgres }

// Valid reports whether this is a recognized engine dialect — false only for the fail-closed sentinel
// ParseDialect returns for unknown input. Config validation uses it so the raw PM_ENGINE string is parsed
// to a Dialect exactly once (at the config boundary), never re-parsed downstream.
func (d Dialect) Valid() bool { return d != invalidDialect }

// Proto maps the dialect to its protobuf Engine for the registration RPC, fail-closed: an unrecognized
// dialect maps to ENGINE_UNSPECIFIED so the control plane rejects it rather than defaulting to a real
// engine.
func (d Dialect) Proto() enginepb.Engine {
	switch d {
	case MySQL:
		return enginepb.Engine_MYSQL
	case Postgres:
		return enginepb.Engine_POSTGRES
	default:
		return enginepb.Engine_ENGINE_UNSPECIFIED
	}
}

// Placeholder renders the bind-parameter placeholder for the nth (1-based) parameter in this dialect's
// SQL: MySQL uses positional "?", Postgres uses "$n". It is the single home for the "? vs $n" difference,
// so no query builder branches on the dialect itself.
func (d Dialect) Placeholder(n int) string {
	switch d {
	case MySQL:
		return "?"
	case Postgres:
		return fmt.Sprintf("$%d", n)
	default:
		return "?"
	}
}

// ResolveSchema resolves a per-request schema to the concrete schema a table lives under. The cross-engine
// "public" default selector maps to this dialect's default schema (MySQL's database, since a MySQL
// "database" is the ANSI schema; Postgres's "public"); any other value is an explicit schema/database and
// is used as-is, so MySQL addresses every database, not only the connection's default. Mirrors
// Engine.resolveSchema in the control plane.
func (d Dialect) ResolveSchema(requestedSchema, dbName string) string {
	if requestedSchema != "public" {
		return requestedSchema
	}
	switch d {
	case MySQL:
		return dbName
	default:
		return "public"
	}
}

// DefaultProxyPort is the proxy's default client-facing listen port for this dialect when PM_PROXY_PORT is
// unset — MySQL 6033, Postgres 6432 (an unrecognized dialect falls back to the MySQL default; boot rejects
// it before the port is used).
func (d Dialect) DefaultProxyPort() int {
	switch d {
	case MySQL:
		return 6033
	case Postgres:
		return 6432
	default:
		return 6033
	}
}

// DefaultTargetPort is the proxy's default target DB port for this dialect when PM_TARGET_PORT is unset —
// MySQL 3307, Postgres 5433 (an unrecognized dialect falls back to the MySQL default; boot rejects it
// before the port is used).
func (d Dialect) DefaultTargetPort() int {
	switch d {
	case MySQL:
		return 3307
	case Postgres:
		return 5433
	default:
		return 3307
	}
}

// ---- Mechanical masking: render the control plane's chosen masks onto result rows ----

// ErrMaskUnbound reports that a control-plane-selected mask cannot be applied to the live result shape.
var ErrMaskUnbound = errors.New("required mask could not be bound to a result column")

// MaskBinding is masks keyed by result-column index plus any that could not bind (out of range or an
// absent proto ordinal). The mask type is the proto ColumnMask (pb.ColumnMask) used AS the data class.
type MaskBinding struct {
	ByIndex map[int]string
	Unbound []*pb.ColumnMask
}

// AllBound reports whether every mask bound to a live result column.
func (b MaskBinding) AllBound() bool { return len(b.Unbound) == 0 }

// RowMasker renders the control plane's masks onto decoded result rows. It is mechanical, not a
// decision: the control plane chose the columns and kinds; the proxy only renders them.
type RowMasker struct {
	byIndex map[int]string
}

// NewRowMasker binds masks to a result set of columnCount columns. It returns nil when any mask is
// out of range — the caller MUST then fail closed, because a mask the proxy cannot bind means the
// intended column would otherwise reach the client unmasked.
func NewRowMasker(masks []*pb.ColumnMask, columnCount int) *RowMasker {
	binding := BindMasks(masks, columnCount)
	if !binding.AllBound() {
		return nil
	}
	return &RowMasker{byIndex: binding.ByIndex}
}

// Apply returns a copy of values with the bound columns masked.
func (m *RowMasker) Apply(values []*string) []*string {
	masked := append([]*string(nil), values...)
	for index, kind := range m.byIndex {
		if index >= 0 && index < len(masked) {
			masked[index] = applyMaskKind(masked[index], kind)
		}
	}
	return masked
}

// ---- Control-plane decision (the Decider maps the wire enum to a string Action + fail-closes) ----

// Decision is the control plane's enforcement verdict for one statement. Mirrors WireDecision in
// controlplane.proto. Masks and AfterStatement are the proto types (pb.ColumnMask / pb.Refetch) used AS
// the data classes; a pb.Refetch mechanically requests a conditional refresh of one connection-local
// schema fragment.
type Decision struct {
	Action              string // "ALLOW" | "MASK" | "DENY" (mapped by NAME; unknown -> DENY, fail closed)
	DecisionID          int64
	DenyReason          string
	Masks               []*pb.ColumnMask
	EffectiveRoles      []string
	RewrittenSQL        *string // nil == relay the client's original SQL verbatim (no * expansion)
	UnmaskablePermitted bool
	AfterStatement      []*pb.Refetch
	Generation          uint64
	// SanitizeDiagnostics is the control plane's per-decision diagnostic-redaction flag. When set,
	// the proxy strips this statement's target-DB error/notice messages down to code + severity. See
	// docs/diagnostic-redaction.md.
	SanitizeDiagnostics bool
	// ResultFingerprint is the decision's authorization requirements (the analyzer's result-read grants). The
	// proxy does not interpret them; it only echoes them back on a RunDecision so an execute-under-R run can
	// freeze them with the stored result (the control plane's result-view drift gate).
	ResultFingerprint []*enginepb.RequireResultReadGrant
}

// RedactedDiagnosticMessage is the single generic string that replaces every target-DB diagnostic message on
// a diagnostic-redacted connection. It carries no stored value; the proxy keeps only the
// machine-readable code + severity beside it. See docs/diagnostic-redaction.md.
const RedactedDiagnosticMessage = "target-DB diagnostic details are redacted on this connection (proxy-monster)"

// EnfActionName reduces a proto EnfAction to Decision.Action's string vocabulary, fail-closed: any
// value that is not ALLOW or MASK — including ENF_ACTION_UNSPECIFIED and the generated UNRECOGNIZED —
// becomes "DENY", so an unknown verdict never falls open.
func EnfActionName(a pb.EnfAction) string {
	switch a {
	case pb.EnfAction_ALLOW:
		return "ALLOW"
	case pb.EnfAction_MASK:
		return "MASK"
	default:
		return "DENY"
	}
}

// ParseEnfActionName is the inverse of EnfActionName, fail-closed to DENY on any string that is not
// "ALLOW" or "MASK".
func ParseEnfActionName(s string) pb.EnfAction {
	switch s {
	case "ALLOW":
		return pb.EnfAction_ALLOW
	case "MASK":
		return pb.EnfAction_MASK
	default:
		return pb.EnfAction_DENY
	}
}

// DecisionOutcome is the result of a Decide call: Ok(decision) or an Err message (fail closed).
type DecisionOutcome struct {
	Decision *Decision
	Err      string // non-empty == the control-plane call failed / was unreachable; caller fails closed
}

// IsErr reports whether the Decide call failed.
func (o DecisionOutcome) IsErr() bool { return o.Decision == nil }

// TempColumn is one column of a session-temp table on the connection — context the proxy sends so the
// control plane resolves a bare name to the connection's temp. Mirrors proto TempColumn.
type TempColumn struct {
	Schema  string
	Table   string
	Column  string
	SqlType string
	Ordinal int
}

// DecideRequest is the complete per-query control-plane request plus the callback used to satisfy
// before_decide commands on the held target-DB connection.
type DecideRequest struct {
	Token      string
	SQL        string
	ClientAddr string
	Namespace  []string
	// MysqlAnsiQuotes reports that the connection's live MySQL session runs under sql_mode=ANSI_QUOTES, so
	// `"x"` is a quoted identifier rather than a string literal. The control plane forwards it to the
	// analyzer's EngineConfig (mysql_ansi_quotes) so a masked column quoted with `"` is still masked.
	// Always false for Postgres and for MySQL's default mode.
	MysqlAnsiQuotes                   bool
	PostgresShadowedFunctions         []string
	PostgresFunctionShadowingObserved bool
	PostgresSystemXIDVisible          bool
	PostgresTypeVisibilityObserved    bool
	TempColumns                       []TempColumn
	ConnectionID                      []byte
	RunCommands                       func([]*pb.Refetch) error
}

// Decider performs the per-query control-plane decision. It is injected so the engine is unit-testable;
// the real implementation is the gRPC client, tests supply a fake. The implementation maps the proto
// verdict by name (unknown / unspecified -> DENY) so the engine never sees an ambiguous Action.
type Decider interface {
	Decide(req DecideRequest) DecisionOutcome
}

// Db is the DUMB per-database adapter: the few facts the relay needs to gather context and mechanically
// refresh a connection-local schema fragment. No enforcement logic, no state machine.
type Db interface {
	// NamespaceProbeSQL is the query whose result yields the connection's effective namespace
	// (PG: current_schemas(true) list; MySQL: SELECT DATABASE()).
	NamespaceProbeSQL() string
	// SupportsTempOverlay reports whether the connection can carry a session-temp overlay (PG only).
	SupportsTempOverlay() bool
	// TempColumnsProbeSQL is the temp-column overlay probe (PG only; "" when unsupported).
	TempColumnsProbeSQL() string
	// HashSetupProbeSQL locates optional engine-specific hash support (PG pgcrypto); empty means none.
	HashSetupProbeSQL() string
	HashSetupColumns() int
	// SchemaHashSQL returns the DB-side hash query and its expected result width.
	SchemaHashSQL(schema string, setupRows [][]*string) (sql string, columns int, err error)
	// SchemaHashFromRows validates and decodes the hash query result.
	SchemaHashFromRows(rows [][]*string) (hash []byte, trusted bool, err error)
	// SchemaColumnsSQL returns six fragment columns ordered by binary (table, ordinal, column).
	SchemaColumnsSQL(schema string) string
	// LowerCaseTableNamesProbeSQL is the query whose single-row single-column result is MySQL's live
	// lower_case_table_names mode ("" for a dialect with no such concept, e.g. Postgres — NormalizeColumns
	// ignores the mode argument in that case).
	LowerCaseTableNamesProbeSQL() string
	// NormalizeColumns folds columns to their canonical spelling per the dialect's own rules — the
	// analyzer's normalization (analyzer/probe.NormalizeRelation), gated by lowerCaseTableNames for
	// MySQL, an identity function for Postgres. The refetch path calls this so the schema-fragment pool
	// pushed to the control plane matches the same canonical spelling introspect's bulk catalog push
	// uses — no caller decides whether/how to fold.
	NormalizeColumns(lowerCaseTableNames int, columns []*pb.Column) []*pb.Column
}

// FragmentColumnsFromRows strictly maps six-column information_schema rows into a canonical schema
// fragment. Rows are folded via db.NormalizeColumns(lowerCaseTableNames, ...) — the SAME rule
// introspect's bulk catalog push uses — and every row's canonical schema must then equal the requested
// schema's own canonical form. This is a self-consistency check (every row came back for the schema
// that was actually asked for), not an authorization boundary, but its strictness now follows the
// connection's actual dialect/mode instead of a blanket case-fold: MySQL lower_case_table_names=2 is
// the only configuration where canonical spelling can legitimately diverge in case from live storage
// (case-insensitive lookup, case-preserving storage), so it's the only one where this tolerates a case
// difference — Postgres and MySQL modes 0/1 require an exact match, same as before this normalized the
// comparison at all. The column is the proto Column (pb.Column) used AS the data class.
func FragmentColumnsFromRows(db Db, lowerCaseTableNames int, schema string, rows [][]*string) ([]*pb.Column, error) {
	raw := make([]*pb.Column, 0, len(rows))
	for i, row := range rows {
		if len(row) != 6 {
			return nil, fmt.Errorf("fragment row %d has %d columns, want 6", i, len(row))
		}
		for j, field := range row {
			if field == nil {
				return nil, fmt.Errorf("fragment row %d field %d is NULL", i, j)
			}
		}
		ordinal, err := strconv.ParseInt(*row[4], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("fragment row %d ordinal %q: %w", i, *row[4], err)
		}
		var nullable bool
		switch *row[5] {
		case "YES":
			nullable = true
		case "NO":
			nullable = false
		default:
			return nil, fmt.Errorf("fragment row %d nullable %q is not YES or NO", i, *row[5])
		}
		raw = append(raw, &pb.Column{
			Schema:   *row[0],
			Table:    *row[1],
			Column:   *row[2],
			DataType: *row[3],
			Ordinal:  int32(ordinal),
			Nullable: nullable,
		})
	}

	canonicalSchema := db.NormalizeColumns(lowerCaseTableNames, []*pb.Column{{Schema: schema, Table: "_", Column: "_"}})[0].GetSchema()
	columns := db.NormalizeColumns(lowerCaseTableNames, raw)
	for i, column := range columns {
		if column.GetSchema() != canonicalSchema {
			return nil, fmt.Errorf("fragment row %d schema %q does not match requested schema %q (canonical %q vs %q)",
				i, raw[i].GetSchema(), schema, column.GetSchema(), canonicalSchema)
		}
	}
	return columns, nil
}

// ---- The verdict the engine hands back to the protocol ----

// Verdict is the control plane's decision reduced to what the dumb protocol must do.
type Verdict interface{ isVerdict() }

// Deny: send a wire error (Decision.DenyReason); the statement is not forwarded.
type Deny struct{ Decision *Decision }

// Proceed: forward SQL (RewrittenSQL if non-nil, else the client's original). When Masks is non-empty
// the protocol MUST mask those result columns via NewRowMasker; a mask that fails to bind is a
// mechanical failure and the protocol fails closed.
type Proceed struct {
	Decision     *Decision
	RewrittenSQL *string
	Masks        []*pb.ColumnMask
}

// Fail: a mechanical impossibility (control plane unreachable, a probe failed, ...) — fail closed.
type Fail struct{ Message string }

func (Deny) isVerdict()    {}
func (Proceed) isVerdict() {}
func (Fail) isVerdict()    {}

// ---- The engine ----

// QueryEngine runs one connection's relay. It holds ONLY a namespace cache (invalidated by protocol
// signals via MarkNamespaceDirty, never by inspecting SQL). It is created with a dumb Db and an
// injected Decider and never touches sockets — the protocol supplies probe I/O via callbacks.
type QueryEngine struct {
	db                                Db
	decider                           Decider
	namespace                         []string
	mysqlAnsiQuotes                   bool
	postgresShadowedFunctions         []string
	postgresFunctionShadowingObserved bool
	postgresSystemXIDVisible          bool
	postgresTypeVisibilityObserved    bool
	nsDirty                           bool
	sanitizeDiag                      bool
}

// NewQueryEngine creates the per-connection engine. The namespace starts dirty so the first query
// probes it.
func NewQueryEngine(db Db, decider Decider) *QueryEngine {
	return &QueryEngine{db: db, decider: decider, nsDirty: true}
}

// MarkNamespaceDirty invalidates the cached namespace. The protocol calls this when an authoritative
// target DB signal says the namespace may have changed but does not include its new value, never by
// classifying SQL text.
func (e *QueryEngine) MarkNamespaceDirty() { e.nsDirty = true }

// SanitizeDiagnostics reports whether the CURRENT statement's target-DB diagnostics must be redacted
// — the value from the most recent decision, so the protocol can gate each target-DB error/notice forward on
// it. Per-decision, not latched (the control plane decides it fresh each Decide). See
// docs/diagnostic-redaction.md.
func (e *QueryEngine) SanitizeDiagnostics() bool { return e.sanitizeDiag }

// SetNamespace replaces the cached namespace from an authoritative target DB protocol signal. It copies
// namespace so a caller cannot mutate the authorization context after the signal is consumed.
func (e *QueryEngine) SetNamespace(namespace []string) {
	e.namespace = append([]string{}, namespace...)
	e.nsDirty = false
}

// NamespaceProbe is the pre-statement session observation the protocol returns to the engine: the
// connection's effective namespace plus engine-specific lookup state: MySQL ANSI_QUOTES and PostgreSQL
// function/type visibility. The engine caches the observation atomically with the namespace.
type NamespaceProbe struct {
	Namespace                         []string
	MySQLAnsiQuotes                   bool
	PostgresShadowedFunctions         []string
	PostgresFunctionShadowingObserved bool
	PostgresSystemXIDVisible          bool
	PostgresTypeVisibilityObserved    bool
}

// AuthzInput is one statement to authorize plus the probe callbacks the protocol wires up. The Db
// supplies the probe SQL; the protocol runs it on the target DB and parses the result. The engine calls
// ProbeNamespace only when its cache is dirty, and ProbeTempColumns only when the Db supports the overlay.
type AuthzInput struct {
	SQL              string
	Token            string
	ClientAddr       string
	ConnectionID     []byte
	ProbeNamespace   func() (NamespaceProbe, error)
	ProbeTempColumns func() ([]TempColumn, error)
	RunCommands      func([]*pb.Refetch) error
}

// Authorize gathers namespace context (cached unless dirty), gathers session-temp columns when the Db
// supports the overlay, calls the control plane's Decide, and returns the verdict for the protocol to
// apply. It makes no enforcement decision of its own; the only local outcomes are fail-closed (Fail) on
// a mechanical impossibility and the reduction of the control plane's Action to Deny/Proceed.
func (e *QueryEngine) Authorize(in AuthzInput) Verdict {
	if e.nsDirty || e.namespace == nil {
		probe, err := in.ProbeNamespace()
		if err != nil {
			return Fail{Message: "namespace probe failed: " + err.Error()}
		}
		e.namespace = append([]string{}, probe.Namespace...)
		e.mysqlAnsiQuotes = probe.MySQLAnsiQuotes
		e.postgresShadowedFunctions = append([]string{}, probe.PostgresShadowedFunctions...)
		e.postgresFunctionShadowingObserved = probe.PostgresFunctionShadowingObserved
		e.postgresSystemXIDVisible = probe.PostgresSystemXIDVisible
		e.postgresTypeVisibilityObserved = probe.PostgresTypeVisibilityObserved
		e.nsDirty = false
	}

	var temps []TempColumn
	if e.db.SupportsTempOverlay() && in.ProbeTempColumns != nil {
		// Best-effort: on failure none are overlaid, so a temp read resolves fail-closed at the CP.
		if t, err := in.ProbeTempColumns(); err == nil {
			temps = t
		}
	}

	out := e.decider.Decide(DecideRequest{
		Token:                             in.Token,
		SQL:                               in.SQL,
		ClientAddr:                        in.ClientAddr,
		Namespace:                         e.namespace,
		MysqlAnsiQuotes:                   e.mysqlAnsiQuotes,
		PostgresShadowedFunctions:         e.postgresShadowedFunctions,
		PostgresFunctionShadowingObserved: e.postgresFunctionShadowingObserved,
		PostgresSystemXIDVisible:          e.postgresSystemXIDVisible,
		PostgresTypeVisibilityObserved:    e.postgresTypeVisibilityObserved,
		TempColumns:                       temps,
		ConnectionID:                      in.ConnectionID,
		RunCommands:                       in.RunCommands,
	})
	if out.IsErr() {
		return Fail{Message: out.Err}
	}
	// Per-decision, NOT latched: an ALLOW whose leak set is fully readable relays raw even right after a
	// MASK (docs/diagnostic-redaction.md).
	e.sanitizeDiag = out.Decision.SanitizeDiagnostics
	switch out.Decision.Action {
	case "ALLOW":
		return Proceed{Decision: out.Decision, RewrittenSQL: out.Decision.RewrittenSQL}
	case "MASK":
		return Proceed{Decision: out.Decision, RewrittenSQL: out.Decision.RewrittenSQL, Masks: out.Decision.Masks}
	default:
		// DENY and any unexpected Action: fail closed with an error the protocol renders.
		return Deny{Decision: out.Decision}
	}
}
