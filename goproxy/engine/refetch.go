package engine

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// Refetcher executes connection-local catalog commands through callback-injected held-target DB I/O.
type Refetcher struct {
	Catalog           string
	Db                Db
	ConnectionID      []byte
	BackendGeneration uint64
	Probe             func(sql string, expectedColumns int) ([][]*string, error)
	Push              func(*pb.SchemaFragmentPush) (uint64, error)
}

func NewRefetcher(db Db, connectionID []byte, generation uint64, probe func(string, int) ([][]*string, error), push func(*pb.SchemaFragmentPush) (uint64, error)) *Refetcher {
	return &Refetcher{Db: db, ConnectionID: connectionID, BackendGeneration: generation, Probe: probe, Push: push}
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
	ds, err := r.datasource()
	if err != nil {
		return err
	}
	columns, err := FragmentColumnsFromRows(r.Db, ds, cmd.GetSchema(), rows)
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

// datasource is the engine with the connection's live lower_case_table_names, probed fresh where the engine has
// one. A failed probe fails the refetch: guessing 0 would leave a lower_case_table_names=2 `Goods` unfolded.
func (r *Refetcher) datasource() (engines.Datasource, error) {
	probeSQL := r.Db.LowerCaseTableNamesProbeSQL()
	if probeSQL == "" {
		return r.Db.Engine().Datasource(nil)
	}
	rows, err := r.Probe(probeSQL, 1)
	if err != nil {
		return engines.Datasource{}, fmt.Errorf("reading lower_case_table_names: %w", err)
	}
	if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] == nil {
		return engines.Datasource{}, errors.New("reading lower_case_table_names: no value")
	}
	n, err := strconv.ParseInt(*rows[0][0], 10, 32)
	if err != nil {
		return engines.Datasource{}, fmt.Errorf("reading lower_case_table_names: invalid value %q", *rows[0][0])
	}
	lctn := int32(n)
	return r.Db.Engine().Datasource(&enginepb.EngineDatasource{MysqlLowerCaseTableNames: &lctn})
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
func (r *Refetcher) RunAll(cmds []*pb.ProxyCommand, _ *SessionObservation) error {
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
