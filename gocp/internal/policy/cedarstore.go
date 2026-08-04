package policy

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// CedarPolicyStore is Kotlin's `class CedarPolicyStore(dataSource, auditStore = AuditStore(dataSource))`.
//
// It arrived in two increments and the split is still visible in the files: THIS one is the READ half
// [authz.PolicyStore] declares (EnabledSources / StateVersion / Bump), and cedarwrite.go is the CRUD
// half — the origin guards under a row lock (INV-A2-20), enable-revalidates (INV-A2-21) and the
// SYSTEM-toggle sentinel audit row (INV-A2-22).
//
// internal/authz/engine.go:26-29 carries the TODO the read half discharges. It is the production
// replacement for internal/dbtest's DBPolicyStore, which takes a testing.TB and calls t.Fatalf and
// therefore cannot be used off a test goroutine.
//
// 🔒 INV-A1-1 — this object is constructed ONCE, in ControlPlaneCore, and shared by the HTTP and
// gRPC surfaces. [CedarPolicyStore.StateVersion] is an in-memory counter; a second store instance
// keeps a second counter, so a policy edited over HTTP would never invalidate the gRPC engine's
// cached PolicySet and the data plane would serve permanently stale decisions.
//
// 🔒 INV-A2-19 — every mutation calls [CedarPolicyStore.Bump] AFTER its transaction commits, never
// before: the version moves only once the new row is visible to another connection.
type CedarPolicyStore struct {
	db store.DB

	// audit is the `auditStore = AuditStore(dataSource)` default argument — INV-A2-22's appender. Nil
	// means "not yet resolved"; see auditStore() in cedarwrite.go.
	audit AuditAppender

	// version is Kotlin's `AtomicLong stateVersion`. It starts at 0 and only ever increases.
	version atomic.Int64

	// onError receives a read failure. Kotlin's enabledSources() throws an SQLException, which
	// propagates out of CedarEngine's rebuild and out of the handler; the Go PolicyStore interface
	// returns no error, so a failure has to go somewhere. It must NOT be swallowed into an empty
	// source list: an empty policy set is a total deny-by-default outage that looks exactly like a
	// correctly-configured install with no policies. Panicking reproduces the throw's control flow
	// (the RPC fails; grpc-go recovers the goroutine), and the seam exists so a test can observe it.
	onError func(error)
}

var _ authz.PolicyStore = (*CedarPolicyStore)(nil)

// NewCedarPolicyStore builds the store over the shared pool.
func NewCedarPolicyStore(db store.DB) *CedarPolicyStore {
	return &CedarPolicyStore{db: db}
}

// SetErrorHandler replaces the read-failure handler. A nil handler restores the default (panic).
func (s *CedarPolicyStore) SetErrorHandler(f func(error)) { s.onError = f }

// EnabledSources returns `(id, cedar_src)` for `enabled = TRUE`, `ORDER BY id`.
//
// 🔒 The ORDER BY is not cosmetic: [authz.CedarEngine] builds its PolicySet by iterating this slice
// and names each policy by position, so an unordered read would rename policies between rebuilds and
// make a diagnostic's "policy N" reference meaningless.
func (s *CedarPolicyStore) EnabledSources() []authz.PolicySource {
	ctx := context.Background()
	rows, err := s.db.Query(ctx, `SELECT id, cedar_src FROM policy WHERE enabled = TRUE ORDER BY id`)
	if err != nil {
		s.fail(fmt.Errorf("read enabled policies: %w", err))
		return nil
	}
	defer rows.Close()

	out := []authz.PolicySource{}
	for rows.Next() {
		var src authz.PolicySource
		if err := rows.Scan(&src.ID, &src.Src); err != nil {
			s.fail(fmt.Errorf("read enabled policies: %w", err))
			return nil
		}
		out = append(out, src)
	}
	if err := rows.Err(); err != nil {
		s.fail(fmt.Errorf("read enabled policies: %w", err))
		return nil
	}
	return out
}

// StateVersion is the in-memory invalidation counter (INV-A2-19).
func (s *CedarPolicyStore) StateVersion() int64 { return s.version.Load() }

// Bump advances the state version, invalidating the shared engine's cached PolicySet. Call it AFTER
// the mutation's transaction commits.
func (s *CedarPolicyStore) Bump() { s.version.Add(1) }

func (s *CedarPolicyStore) fail(err error) {
	if s.onError != nil {
		s.onError(err)
		return
	}
	panic(err)
}
