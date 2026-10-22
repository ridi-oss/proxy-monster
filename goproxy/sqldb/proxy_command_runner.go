package sqldb

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// ProxyCommandRunner executes connection-local catalog commands through callback-injected held-target DB I/O.
type ProxyCommandRunner struct {
	Catalog           string
	Queries           Queries
	Session           *engines.Session
	ConnectionID      []byte
	BackendGeneration uint64
	Probe             func(sql string, expectedColumns int) ([][]*string, error)
	Push              func(*pb.SchemaFragmentPush) (uint64, error)
}

func NewProxyCommandRunner(queries Queries, session *engines.Session, connectionID []byte, generation uint64, probe func(string, int) ([][]*string, error), push func(*pb.SchemaFragmentPush) (uint64, error)) *ProxyCommandRunner {
	return &ProxyCommandRunner{Queries: queries, Session: session, ConnectionID: connectionID, BackendGeneration: generation, Probe: probe, Push: push}
}

// Refetch executes one refetch. A failed hash probe degrades to a full fetch; a failed read, a failed push,
// or a schema that changed under the read is an error, and the schema stays pending until it is re-asked.
func (r *ProxyCommandRunner) Refetch(cmd *pb.Refetch) error {
	if cmd.GetSchema() == "" {
		return errors.New("refetch command has blank schema")
	}
	if r.Queries.SchemaColumns == nil {
		return errors.New("command runner has no queries")
	}
	if r.Probe == nil {
		return errors.New("command runner has no probe callback")
	}
	if r.Push == nil {
		return errors.New("command runner has no push callback")
	}

	if r.Catalog == "" {
		return errors.New("command runner has no catalog")
	}
	if cmd.GetCatalog() != r.Catalog {
		return fmt.Errorf("refetch catalog %q does not match target catalog %q", cmd.GetCatalog(), r.Catalog)
	}

	var setupRows [][]*string
	if setupSQL := r.Queries.HashSetupProbe; setupSQL != "" {
		rows, err := r.Probe(setupSQL, r.Queries.HashSetupColumns)
		if err == nil {
			setupRows = rows
		}
	}

	hashSQL, hashColumns, hashSQLErr := r.Queries.SchemaHash(cmd.GetSchema(), setupRows)
	h1, trusted1 := r.measureHash(hashSQL, hashColumns, hashSQLErr)
	if trusted1 && len(cmd.GetIfHashDiffers()) > 0 && bytes.Equal(h1, cmd.GetIfHashDiffers()) {
		_, err := r.Push(&pb.SchemaFragmentPush{
			ConnectionId:      append([]byte(nil), r.ConnectionID...),
			Schema:            cmd.GetSchema(),
			Catalog:           r.Catalog,
			ContentHash:       append([]byte(nil), h1...),
			Unchanged:         true,
			BackendGeneration: r.BackendGeneration,
		})
		return err
	}

	rows, err := r.Probe(r.Queries.SchemaColumns(cmd.GetSchema()), 7)
	if err != nil {
		return fmt.Errorf("introspecting schema %q: %w", cmd.GetSchema(), err)
	}
	columns, err := FragmentColumnsFromRows(r.Session, cmd.GetSchema(), rows)
	if err != nil {
		return fmt.Errorf("mapping schema %q fragment: %w", cmd.GetSchema(), err)
	}
	routineRows, err := r.Probe(r.Queries.SchemaRoutines(cmd.GetSchema()), 1)
	if err != nil {
		return fmt.Errorf("introspecting schema %q routines: %w", cmd.GetSchema(), err)
	}
	routines := make([]string, 0, len(routineRows))
	for _, row := range routineRows {
		if len(row) == 1 && row[0] != nil {
			routines = append(routines, *row[0])
		}
	}

	// h1 != h2: DDL landed between the two probes, so columns and routines may not belong together.
	h2, trusted2 := r.measureHash(hashSQL, hashColumns, hashSQLErr)
	if trusted1 && trusted2 && !bytes.Equal(h1, h2) {
		return fmt.Errorf("schema %q changed during introspection", cmd.GetSchema())
	}
	contentHash := make([]byte, 32)
	if _, err := rand.Read(contentHash); err != nil {
		return fmt.Errorf("generating untrusted fragment nonce: %w", err)
	}
	if trusted1 && trusted2 {
		contentHash = append(contentHash[:0], h2...)
	}

	var routineNames []string
	for _, functionName := range r.Session.FunctionNames(routines) {
		routineNames = append(routineNames, functionName.String())
	}
	_, err = r.Push(&pb.SchemaFragmentPush{
		ConnectionId:      append([]byte(nil), r.ConnectionID...),
		Schema:            cmd.GetSchema(),
		Catalog:           r.Catalog,
		ContentHash:       contentHash,
		Columns:           columns,
		Routines:          routineNames,
		BackendGeneration: r.BackendGeneration,
	})
	return err
}

func (r *ProxyCommandRunner) measureHash(sql string, expectedColumns int, sqlErr error) ([]byte, bool) {
	if sqlErr != nil {
		return nil, false
	}
	rows, err := r.Probe(sql, expectedColumns)
	if err != nil {
		return nil, false
	}
	hash, trusted, err := r.Queries.SchemaHashFromRows(rows)
	if err != nil {
		return nil, false
	}
	return hash, trusted
}

// RunAll executes commands in order and stops at the first failure.
// RunAll executes a command list on the held connection. The SQL engines answer only the Refetch arm; any
// other command is unknown here and fails closed. session is unused: nothing a refetch fetches changes the
// per-statement session facts.
func (r *ProxyCommandRunner) RunAll(cmds []*pb.ProxyCommand, _ *spi.SessionSnapshot) error {
	for i, cmd := range cmds {
		refetch := cmd.GetRefetch()
		if refetch == nil {
			return fmt.Errorf("command %d is not a refetch", i)
		}
		if err := r.Refetch(refetch); err != nil {
			return fmt.Errorf("refetch command %d: %w", i, err)
		}
	}
	return nil
}

// FragmentColumnsFromRows strictly maps information_schema rows into a fragment of the requested canonical schema.
func FragmentColumnsFromRows(session *engines.Session, schema string, rows [][]*string) ([]*enginepb.Column, error) {
	raw := make([]*enginepb.Column, 0, len(rows))
	for i, row := range rows {
		if len(row) != 7 {
			return nil, fmt.Errorf("fragment row %d has %d columns, want 7", i, len(row))
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
		raw = append(raw, &enginepb.Column{
			Catalog:  *row[6],
			Schema:   *row[0],
			Table:    *row[1],
			Column:   *row[2],
			DataType: *row[3],
			Ordinal:  int32(ordinal),
			Nullable: nullable,
		})
	}

	canonicalSchema := session.CanonicalSchemas([]string{schema})[0].String()
	columns := session.CanonicalColumns(raw)
	for i, column := range columns {
		if column.GetSchema() != canonicalSchema {
			return nil, fmt.Errorf("fragment row %d schema %q does not match requested schema %q (canonical %q vs %q)",
				i, raw[i].GetSchema(), schema, column.GetSchema(), canonicalSchema)
		}
	}
	return columns, nil
}

// NewSession builds the engine session of the connection being opened from one target settings probe.
func NewSession(queries Queries, probe func(sql string, columns int) ([][]*string, error)) (*engines.Session, error) {
	rows, err := probe(queries.TargetSettingsProbe, queries.TargetSettingsColumns)
	if err != nil {
		return nil, fmt.Errorf("reading target settings: %w", err)
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("reading target settings: %d rows, want 1", len(rows))
	}
	targetSettings, err := queries.TargetSettings(rows[0])
	if err != nil {
		return nil, err
	}
	return queries.Engine.NewSession(targetSettings)
}
