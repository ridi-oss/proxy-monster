package sqldb

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// Refetcher executes connection-local catalog commands through callback-injected held-target DB I/O.
type Refetcher struct {
	Catalog           string
	Db                relay.Db
	ConnectionID      []byte
	BackendGeneration uint64
	Probe             func(sql string, expectedColumns int) ([][]*string, error)
	Push              func(*pb.SchemaFragmentPush) (uint64, error)
}

func NewRefetcher(queries relay.Db, connectionID []byte, generation uint64, probe func(string, int) ([][]*string, error), push func(*pb.SchemaFragmentPush) (uint64, error)) *Refetcher {
	return &Refetcher{Db: queries, ConnectionID: connectionID, BackendGeneration: generation, Probe: probe, Push: push}
}

// Run executes one refetch. A failed hash probe degrades to a full fetch; a failed read, a failed push,
// or a schema that changed under the read is an error, and the schema stays pending until it is re-asked.
func (r *Refetcher) Run(cmd *pb.Refetch) error {
	if cmd.GetSchema() == "" {
		return errors.New("refetch command has blank schema")
	}
	if r.Db == nil {
		return errors.New("refetcher has no database adapter")
	}
	if r.Probe == nil {
		return errors.New("refetcher has no probe callback")
	}
	if r.Push == nil {
		return errors.New("refetcher has no push callback")
	}

	if r.Catalog == "" {
		return errors.New("refetcher has no catalog")
	}
	if cmd.GetCatalog() != r.Catalog {
		return fmt.Errorf("refetch catalog %q does not match target catalog %q", cmd.GetCatalog(), r.Catalog)
	}

	var setupRows [][]*string
	if setupSQL := r.Db.HashSetupProbeSQL(); setupSQL != "" {
		rows, err := r.Probe(setupSQL, r.Db.HashSetupColumns())
		if err == nil {
			setupRows = rows
		}
	}

	hashSQL, hashColumns, hashSQLErr := r.Db.SchemaHashSQL(cmd.GetSchema(), setupRows)
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

	rows, err := r.Probe(r.Db.SchemaColumnsSQL(cmd.GetSchema()), 7)
	if err != nil {
		return fmt.Errorf("introspecting schema %q: %w", cmd.GetSchema(), err)
	}
	columns, err := FragmentColumnsFromRows(r.Db, r.lowerCaseTableNames(), cmd.GetSchema(), rows)
	if err != nil {
		return fmt.Errorf("mapping schema %q fragment: %w", cmd.GetSchema(), err)
	}
	routineRows, err := r.Probe(r.Db.SchemaRoutinesSQL(cmd.GetSchema()), 1)
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

	_, err = r.Push(&pb.SchemaFragmentPush{
		ConnectionId:      append([]byte(nil), r.ConnectionID...),
		Schema:            cmd.GetSchema(),
		Catalog:           r.Catalog,
		ContentHash:       contentHash,
		Columns:           columns,
		Routines:          FoldFunctionNames(r.Db, routines),
		BackendGeneration: r.BackendGeneration,
	})
	return err
}

// lowerCaseTableNames probes the connection's live mode fresh (no cached state on Refetcher/Db —
// mirrors mysqlSchemaFilter's own live @@lower_case_table_names check in goproxy/db). "" from
// LowerCaseTableNamesProbeSQL (non-MySQL, or a probe failure) returns 0, which NormalizeColumns
// ignores for any dialect that doesn't fold at all.
func (r *Refetcher) lowerCaseTableNames() int {
	probeSQL := r.Db.LowerCaseTableNamesProbeSQL()
	if probeSQL == "" {
		return 0
	}
	rows, err := r.Probe(probeSQL, 1)
	if err != nil || len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] == nil {
		return 0
	}
	mode, err := strconv.Atoi(*rows[0][0])
	if err != nil {
		return 0
	}
	return mode
}

func (r *Refetcher) measureHash(sql string, expectedColumns int, sqlErr error) ([]byte, bool) {
	if sqlErr != nil {
		return nil, false
	}
	rows, err := r.Probe(sql, expectedColumns)
	if err != nil {
		return nil, false
	}
	hash, trusted, err := r.Db.SchemaHashFromRows(rows)
	if err != nil {
		return nil, false
	}
	return hash, trusted
}

// RunAll executes commands in order and stops at the first failure.
// RunAll executes a command list on the held connection. The SQL engines answer only the Refetch arm; any
// other command is unknown here and fails closed. session is unused: nothing a refetch fetches changes the
// per-statement session facts.
func (r *Refetcher) RunAll(cmds []*pb.ProxyCommand, _ *spi.SessionObservation) error {
	for i, cmd := range cmds {
		refetch := cmd.GetRefetch()
		if refetch == nil {
			return fmt.Errorf("command %d is not a refetch", i)
		}
		if err := r.Run(refetch); err != nil {
			return fmt.Errorf("refetch command %d: %w", i, err)
		}
	}
	return nil
}

// FragmentColumnsFromRows strictly maps seven-column information_schema rows into a canonical schema
// fragment. Rows are folded via db.NormalizeColumns(lowerCaseTableNames, ...) — the SAME rule
// introspect's bulk catalog push uses — and every row's canonical schema must then equal the requested
// schema's own canonical form. This is a self-consistency check (every row came back for the schema
// that was actually asked for), not an authorization boundary, but its strictness now follows the
// connection's actual dialect/mode instead of a blanket case-fold: MySQL lower_case_table_names=2 is
// the only configuration where canonical spelling can legitimately diverge in case from live storage
// (case-insensitive lookup, case-preserving storage), so it's the only one where this tolerates a case
// difference — Postgres and MySQL modes 0/1 require an exact match, same as before this normalized the
// comparison at all. The column is the proto Column (enginepb.Column) used AS the data class.
func FragmentColumnsFromRows(queries relay.Db, lowerCaseTableNames int, schema string, rows [][]*string) ([]*enginepb.Column, error) {
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

	canonicalSchema := queries.NormalizeColumns(lowerCaseTableNames, []*enginepb.Column{{Schema: schema, Table: "_", Column: "_"}})[0].GetSchema()
	columns := queries.NormalizeColumns(lowerCaseTableNames, raw)
	for i, column := range columns {
		if column.GetSchema() != canonicalSchema {
			return nil, fmt.Errorf("fragment row %d schema %q does not match requested schema %q (canonical %q vs %q)",
				i, raw[i].GetSchema(), schema, column.GetSchema(), canonicalSchema)
		}
	}
	return columns, nil
}
