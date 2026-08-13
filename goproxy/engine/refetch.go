package engine

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// Refetcher executes connection-local catalog commands through callback-injected held-target DB I/O.
type Refetcher struct {
	Db                Db
	ConnectionID      []byte
	BackendGeneration uint64
	Probe             func(sql string, expectedColumns int) ([][]*string, error)
	Push              func(*pb.SchemaFragmentPush) (uint64, error)
}

func NewRefetcher(db Db, connectionID []byte, generation uint64, probe func(string, int) ([][]*string, error), push func(*pb.SchemaFragmentPush) (uint64, error)) *Refetcher {
	return &Refetcher{Db: db, ConnectionID: connectionID, BackendGeneration: generation, Probe: probe, Push: push}
}

// Run executes one refetch command. Hash failures degrade to a full fetch; introspection and push failures
// are terminal because the control plane must never decide against stale connection-local structure.
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
			ContentHash:       append([]byte(nil), h1...),
			Unchanged:         true,
			BackendGeneration: r.BackendGeneration,
		})
		return err
	}

	rows, err := r.Probe(r.Db.SchemaColumnsSQL(cmd.GetSchema()), 6)
	if err != nil {
		return fmt.Errorf("introspecting schema %q: %w", cmd.GetSchema(), err)
	}
	columns, err := FragmentColumnsFromRows(r.Db, r.lowerCaseTableNames(), cmd.GetSchema(), rows)
	if err != nil {
		return fmt.Errorf("mapping schema %q fragment: %w", cmd.GetSchema(), err)
	}

	h2, trusted2 := r.measureHash(hashSQL, hashColumns, hashSQLErr)
	contentHash := make([]byte, 32)
	if _, err := rand.Read(contentHash); err != nil {
		return fmt.Errorf("generating untrusted fragment nonce: %w", err)
	}
	if trusted1 && trusted2 && bytes.Equal(h1, h2) {
		contentHash = append(contentHash[:0], h2...)
	}

	_, err = r.Push(&pb.SchemaFragmentPush{
		ConnectionId:      append([]byte(nil), r.ConnectionID...),
		Schema:            cmd.GetSchema(),
		ContentHash:       contentHash,
		Columns:           columns,
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
func (r *Refetcher) RunAll(cmds []*pb.Refetch) error {
	for i, cmd := range cmds {
		if err := r.Run(cmd); err != nil {
			return fmt.Errorf("refetch command %d: %w", i, err)
		}
	}
	return nil
}
