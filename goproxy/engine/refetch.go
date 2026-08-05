package engine

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// Refetcher executes connection-local catalog commands through callback-injected held-backend I/O.
type Refetcher struct {
	Db                Db
	ConnectionID      []byte
	BackendGeneration uint64
	Probe             func(sql string, expectedColumns int) ([][]*string, error)
	Push              func(*pb.SchemaFragmentPush) (uint64, error)
	// InTransaction reports whether the held backend connection had a transaction open, read at each
	// measurement rather than captured once — the status changes under the statements being bracketed.
	// nil means "no latch to read, and none needed": the MySQL paths qualify by construction (on_open
	// precedes the first client statement, and after_statement follows DDL, which implicitly commits),
	// so they stamp clean. PostgreSQL supplies a closure over the live ReadyForQuery status.
	InTransaction func() bool
}

func NewRefetcher(db Db, connectionID []byte, generation uint64, probe func(string, int) ([][]*string, error), push func(*pb.SchemaFragmentPush) (uint64, error), inTransaction func() bool) *Refetcher {
	return &Refetcher{
		Db: db, ConnectionID: connectionID, BackendGeneration: generation,
		Probe: probe, Push: push, InTransaction: inTransaction,
	}
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
	obs1, ok1 := r.measureHash(hashSQL, hashColumns, hashSQLErr)
	tx1 := r.inTx()
	if ok1 && obs1.Trusted && len(cmd.GetIfHashDiffers()) > 0 && bytes.Equal(obs1.Hash, cmd.GetIfHashDiffers()) {
		_, err := r.Push(&pb.SchemaFragmentPush{
			ConnectionId:          append([]byte(nil), r.ConnectionID...),
			Schema:                cmd.GetSchema(),
			ContentHash:           append([]byte(nil), obs1.Hash...),
			Unchanged:             true,
			BackendGeneration:     r.BackendGeneration,
			DbClockMicros:         obs1.DbClockMicros,
			MeasuredInTransaction: tx1,
			BackendId:             obs1.BackendID,
			HashTrusted:           true,
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

	obs2, ok2 := r.measureHash(hashSQL, hashColumns, hashSQLErr)
	tx2 := r.inTx()
	// Coherent = the columns just read are provably the state both measurements saw. Backend identity
	// must match too: equal hashes from two different servers bracket nothing.
	coherent := ok1 && ok2 && obs1.Trusted && obs2.Trusted &&
		bytes.Equal(obs1.Hash, obs2.Hash) && obs1.BackendID == obs2.BackendID
	// content_hash carries a genuine measurement or nothing — never a fabricated value. When the
	// bracket fails, hash_trusted=false already tells the manager to keep the observation
	// connection-only, so the honest measured bytes are strictly more useful than a nonce.
	contentHash := obs2.Hash
	if len(contentHash) == 0 {
		contentHash = obs1.Hash
	}
	backendID := obs1.BackendID
	if backendID == "" {
		backendID = obs2.BackendID
	}

	_, err = r.Push(&pb.SchemaFragmentPush{
		ConnectionId:          append([]byte(nil), r.ConnectionID...),
		Schema:                cmd.GetSchema(),
		ContentHash:           append([]byte(nil), contentHash...),
		Columns:               columns,
		BackendGeneration:     r.BackendGeneration,
		DbClockMicros:         obs1.DbClockMicros,
		MeasuredInTransaction: tx1 || tx2,
		BackendId:             backendID,
		HashTrusted:           coherent,
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

func (r *Refetcher) inTx() bool {
	return r.InTransaction != nil && r.InTransaction()
}

func (r *Refetcher) measureHash(sql string, expectedColumns int, sqlErr error) (HashObservation, bool) {
	if sqlErr != nil {
		return HashObservation{}, false
	}
	rows, err := r.Probe(sql, expectedColumns)
	if err != nil {
		return HashObservation{}, false
	}
	observation, err := r.Db.SchemaHashFromRows(rows)
	if err != nil {
		return observation, false
	}
	return observation, true
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
