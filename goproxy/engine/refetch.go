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
	// nil means the dialect exposes no such latch, and then only the refetch POSITION can establish the
	// fact: see RunAll and RunAllSettled. PostgreSQL supplies a closure over the live ReadyForQuery
	// status and answers for every position from it.
	InTransaction func() bool

	// settledByConstruction is set for the duration of one RunAllSettled call, naming a position where no
	// transaction can be open regardless of what any latch would say. Not a field a caller sets: the
	// position is a property of the call site, and letting it be configured once per Refetcher would make
	// a single mis-set value silently vouch for every later measurement on that connection.
	settledByConstruction bool
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

// inTx reports the transaction status to stamp on a measurement taken now.
//
// With a latch, that is simply what the latch says. Without one the answer is decided by the refetch
// POSITION, which the caller declares by choosing RunAll or RunAllSettled, and the unproven default is
// "in a transaction" — the fail-closed reading. A measurement that cannot prove it is settled must not
// be shared, because a client that runs BEGIN, works past the staleness bound, then issues a SELECT gets
// a before_decide probe measured inside its own open transaction, where the catalog it reads may include
// its uncommitted DDL or miss committed DDL from elsewhere. Calling that clean would let another
// connection adopt a view that never existed for anyone but this one.
func (r *Refetcher) inTx() bool {
	if r.InTransaction != nil {
		return r.InTransaction()
	}
	return !r.settledByConstruction
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

// RunAll executes commands in order and stops at the first failure. Without a transaction-status latch
// these measurements stamp themselves in-transaction, since nothing about this position rules it out.
func (r *Refetcher) RunAll(cmds []*pb.Refetch) error {
	for i, cmd := range cmds {
		if err := r.Run(cmd); err != nil {
			return fmt.Errorf("refetch command %d: %w", i, err)
		}
	}
	return nil
}

// RunAllSettled is RunAll at a position where no transaction can be open, which a dialect with no
// transaction-status latch can establish no other way.
//
// Exactly two positions qualify, both by construction rather than by observation:
//
//   - on_open, which runs before the proxy serves the connection's first client statement, on a backend
//     connection the proxy itself just dialed — no client statement has run, so no transaction exists.
//   - after_statement, which fires only on a catalog-changing statement, i.e. after DDL, and MySQL DDL
//     commits implicitly.
//
// before_decide is deliberately NOT among them: freshnessGate runs on every statement, so a probe can
// land in the middle of a client's own open transaction. Use RunAll there.
//
// A dialect that supplies InTransaction ignores this entirely — a measured fact beats a positional
// argument, and on PostgreSQL the two disagree exactly when the argument is wrong (a COMMIT refetch
// issued while a failed transaction is still open).
func (r *Refetcher) RunAllSettled(cmds []*pb.Refetch) error {
	r.settledByConstruction = true
	defer func() { r.settledByConstruction = false }()
	return r.RunAll(cmds)
}
