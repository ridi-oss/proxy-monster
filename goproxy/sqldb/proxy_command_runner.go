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
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// Inspector inspects a schema over the held target connection through probe.
type Inspector struct {
	Queries Queries
	Session *engines.Session
	Probe   func(sql string, expectedColumns int) ([][]*string, error)
}

func NewProxyCommandRunner(queries Queries, session *engines.Session, connectionID []byte, generation uint64, probe func(string, int) ([][]*string, error), push func(*pb.SchemaFragmentPush) (uint64, error)) *relay.ProxyCommandRunner {
	return &relay.ProxyCommandRunner{
		ConnectionID:      connectionID,
		BackendGeneration: generation,
		Inspector:         &Inspector{Queries: queries, Session: session, Probe: probe},
		Push:              push,
	}
}

// InspectSchema reads one schema. A failed hash probe degrades to a full fetch; a failed read, or a schema
// that changed under the read, is an error.
func (m *Inspector) InspectSchema(schema string, ifHashDiffers []byte) (*pb.SchemaFragmentPush, error) {
	if m.Queries.SchemaColumns == nil {
		return nil, errors.New("command runner has no queries")
	}
	if m.Probe == nil {
		return nil, errors.New("command runner has no probe callback")
	}

	var setupRows [][]*string
	if setupSQL := m.Queries.HashSetupProbe; setupSQL != "" {
		rows, err := m.Probe(setupSQL, m.Queries.HashSetupColumns)
		if err == nil {
			setupRows = rows
		}
	}

	hashSQL, hashColumns, hashSQLErr := m.Queries.SchemaHash(schema, setupRows)
	h1, trusted1 := m.inspectHash(hashSQL, hashColumns, hashSQLErr)
	if trusted1 && len(ifHashDiffers) > 0 && bytes.Equal(h1, ifHashDiffers) {
		return &pb.SchemaFragmentPush{ContentHash: append([]byte(nil), h1...), Unchanged: true}, nil
	}

	rows, err := m.Probe(m.Queries.SchemaColumns(schema), 7)
	if err != nil {
		return nil, fmt.Errorf("introspecting schema %q: %w", schema, err)
	}
	columns, err := FragmentColumnsFromRows(m.Session, schema, rows)
	if err != nil {
		return nil, fmt.Errorf("mapping schema %q fragment: %w", schema, err)
	}
	routineRows, err := m.Probe(m.Queries.SchemaRoutines(schema), 1)
	if err != nil {
		return nil, fmt.Errorf("introspecting schema %q routines: %w", schema, err)
	}
	routines := make([]string, 0, len(routineRows))
	for _, row := range routineRows {
		if len(row) == 1 && row[0] != nil {
			routines = append(routines, *row[0])
		}
	}

	// h1 != h2: DDL landed between the two probes, so columns and routines may not belong together.
	h2, trusted2 := m.inspectHash(hashSQL, hashColumns, hashSQLErr)
	if trusted1 && trusted2 && !bytes.Equal(h1, h2) {
		return nil, fmt.Errorf("schema %q changed during introspection", schema)
	}
	contentHash := make([]byte, 32)
	if _, err := rand.Read(contentHash); err != nil {
		return nil, fmt.Errorf("generating untrusted fragment nonce: %w", err)
	}
	if trusted1 && trusted2 {
		contentHash = append(contentHash[:0], h2...)
	}

	var routineNames []string
	for _, functionName := range m.Session.FunctionNames(routines) {
		routineNames = append(routineNames, functionName.String())
	}
	return &pb.SchemaFragmentPush{ContentHash: contentHash, Columns: columns, Routines: routineNames}, nil
}

func (m *Inspector) inspectHash(sql string, expectedColumns int, sqlErr error) ([]byte, bool) {
	if sqlErr != nil {
		return nil, false
	}
	rows, err := m.Probe(sql, expectedColumns)
	if err != nil {
		return nil, false
	}
	hash, trusted, err := m.Queries.SchemaHashFromRows(rows)
	if err != nil {
		return nil, false
	}
	return hash, trusted
}

// RunCommand refuses every arm but Refetch, which the runner handles.
func (*Inspector) RunCommand(*pb.ProxyCommand, *spi.SessionSnapshot) error {
	return relay.ErrUnknownCommand
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
