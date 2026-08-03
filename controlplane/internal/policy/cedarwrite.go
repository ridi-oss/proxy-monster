package policy

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/audit"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/instant"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The WRITE half of CedarPolicyStore — 02-authz.md §8. The read half (EnabledSources /
// StateVersion / Bump) is in cedarstore.go and predates this file.
// ---------------------------------------------------------------------------------------------

// SystemPolicyOrigin and UserPolicyOrigin are the two values `policy.origin` may take
// (V3__policy.sql:32). SYSTEM rows are migration-owned, carry a `system_key` and a NEGATIVE id;
// USER rows carry neither and a positive one.
const (
	SystemPolicyOrigin = "SYSTEM"
	UserPolicyOrigin   = "USER"
)

// ReservedPolicyNamePrefix is the namespace only a migration may write. V3__policy.sql:37-40 enforces
// the same rule as a CHECK constraint, so the guard here is a better error, not the only defence.
const ReservedPolicyNamePrefix = "system:"

// ErrSystemPolicyImmutable is `SystemPolicyImmutableException` (02-authz.md §8 "Exceptions") ⇒ 409.
//
// 🔒 INV-A2-20 — this is raised by the STORE, under a row lock, not by the route. Two reasons, and
// both are load-bearing: (a) a non-HTTP caller (the MCP management tool, a future job) cannot rewrite
// migration-owned source by going around the route, and (b) `SELECT … FOR UPDATE` means a concurrent
// transaction cannot swap the checked row between the guard and the UPDATE.
var ErrSystemPolicyImmutable = errors.New("policy: system policies are immutable")

// ReservedPolicyNameError is `ReservedPolicyNameException` ⇒ `policy.reserved_name`.
//
// It carries the offending name because the caller asked for it by name and the message the console
// shows interpolates it.
type ReservedPolicyNameError struct{ Name string }

func (e ReservedPolicyNameError) Error() string {
	return fmt.Sprintf("policy: %q is in the reserved %q namespace", e.Name, ReservedPolicyNamePrefix)
}

// InvalidCedarPolicyError is `InvalidCedarPolicyException(errors: List<String>)` ⇒ 400.
//
// The list is Cedar's own compiler output, preserved verbatim — it is what the editor renders, one
// line per message, and it is why the 400 body is a bare `{errors: […]}` map rather than an ApiError
// (see [CedarPolicyErrors]).
type InvalidCedarPolicyError struct{ Errors []string }

func (e InvalidCedarPolicyError) Error() string {
	return fmt.Sprintf("policy: cedar source failed validation (%d error(s))", len(e.Errors))
}

// AuditAppender is the one method [CedarPolicyStore] needs from `AuditStore`: an insert that runs on
// the CALLER's connection.
//
// 🔒 INV-A2-22 depends on exactly that narrowness. The sentinel row for a SYSTEM toggle must go in on
// the SAME connection as the UPDATE, so an audit failure rolls the toggle back with it —
// `CedarPolicyOriginTest` case 3 is "audit failure rolls back the system toggle in the same
// transaction". An interface with an `Insert` (own-transaction) method on it would make the wrong
// call the easy one to write; there is deliberately no way to reach that method from here.
type AuditAppender interface {
	InsertOn(ctx context.Context, c store.Queryer, rec types.AuditEvent) (int64, error)
}

// SetAuditStore replaces the audit appender. Its only intended callers are the wiring in A1 and the
// INV-A2-22 rollback test, which needs an appender that fails on demand.
func (s *CedarPolicyStore) SetAuditStore(a AuditAppender) { s.audit = a }

// auditStore is the `auditStore = AuditStore(dataSource)` default argument, resolved lazily so
// NewCedarPolicyStore stays a two-line constructor and so a nil handed to SetAuditStore restores it.
func (s *CedarPolicyStore) auditStore() AuditAppender {
	if s.audit == nil {
		s.audit = audit.New(s.db)
	}
	return s.audit
}

// ---- Reads ------------------------------------------------------------------------------------

const cedarPolicyColumns = `id, origin, system_key, name, cedar_src, enabled, updated_by, updated_at`

// List is `list()` — all rows `ORDER BY id`.
//
// 🔒 The order is id, NOT name and NOT updated_at. SYSTEM rows carry negative ids
// (V3__policy.sql:34), so ordering by id puts every migration-owned row FIRST, ascending toward the
// most recently created user policy — which is the order the console's policy list renders and the
// order `CedarPolicyRoutesTest` case 1 reads provenance in.
func (s *CedarPolicyStore) List(ctx context.Context) ([]CedarPolicy, error) {
	return s.ListOn(ctx, s.db)
}

// ListOn is `list(c)`.
func (s *CedarPolicyStore) ListOn(ctx context.Context, c store.Queryer) ([]CedarPolicy, error) {
	return query(ctx, c, `SELECT `+cedarPolicyColumns+` FROM policy ORDER BY id`, scanCedarPolicy)
}

// Get is `get(id)`; nil, nil ⇒ no such row.
func (s *CedarPolicyStore) Get(ctx context.Context, id int64) (*CedarPolicy, error) {
	return s.GetOn(ctx, s.db, id)
}

// GetOn is `get(id, conn)`.
func (s *CedarPolicyStore) GetOn(ctx context.Context, c store.Queryer, id int64) (*CedarPolicy, error) {
	return queryOne(ctx, c, `SELECT `+cedarPolicyColumns+` FROM policy WHERE id=$1`, id, scanCedarPolicy)
}

// GetByName is `getByName(name)`.
func (s *CedarPolicyStore) GetByName(ctx context.Context, name string) (*CedarPolicy, error) {
	return s.GetByNameOn(ctx, s.db, name)
}

// GetByNameOn is `getByName(name, conn)` — the MCP surface's name-keyed lookup.
func (s *CedarPolicyStore) GetByNameOn(ctx context.Context, c store.Queryer, name string) (*CedarPolicy, error) {
	rows, err := c.Query(ctx, `SELECT `+cedarPolicyColumns+` FROM policy WHERE name=$1`, name)
	if err != nil {
		return nil, err
	}
	return firstRow(rows, scanCedarPolicy)
}

// ---- Mutations --------------------------------------------------------------------------------
//
// 🔒 INV-A2-19 — THE VERSION BUMPS ONLY AFTER COMMIT. Every wrapper below is `inTx { … }` followed by
// [CedarPolicyStore.Bump]; the `…On` overloads never bump, because their caller owns the transaction
// and must call Bump itself once the OUTER transaction commits. Bumping inside the transaction would
// publish a cache invalidation for a rollback that never happened — the shared CedarEngine would
// rebuild its PolicySet from rows that no longer exist and then never rebuild again, because the
// version it cached is the version the store reports.

// Create is `create(input, updatedBy)`.
func (s *CedarPolicyStore) Create(ctx context.Context, input CedarPolicyInput, updatedBy *string) (CedarPolicy, error) {
	created, err := store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (CedarPolicy, error) {
		return s.CreateOn(ctx, tx, input, updatedBy)
	})
	if err != nil {
		return CedarPolicy{}, err
	}
	s.Bump()
	return created, nil
}

// CreateOn is `create(input, updatedBy, conn)`, in the Kotlin's three steps:
//
//  1. `name.startsWith("system:")` ⇒ [ReservedPolicyNameError]
//  2. validate ⇒ [InvalidCedarPolicyError]
//  3. `INSERT … origin='USER' RETURNING id`, then re-read
//
// 🔒 Step 1 BEFORE step 2 is observable: a request that is both reserved-named and syntactically
// invalid answers `policy.reserved_name`, not the compiler's error list.
// `CedarPolicyOriginTest` case 1 is "store rejects system mutation and reserved user names BEFORE
// touching state".
//
// 🔒 Step 2 is INV-A2-21's other half — validate-on-WRITE. A row can only become malformed after
// this point by a migration inserting it or by the schema changing underneath it, which is exactly
// the case revalidate-on-enable covers.
//
// `origin` is hardcoded to 'USER' and NOT taken from the input, which is why [CedarPolicyInput] has
// no origin field: `CedarPolicyRoutesTest` case 1 is "list exposes system provenance without
// accepting it in input".
func (s *CedarPolicyStore) CreateOn(
	ctx context.Context, c store.Queryer, input CedarPolicyInput, updatedBy *string,
) (CedarPolicy, error) {
	if err := guardReservedName(input.Name); err != nil {
		return CedarPolicy{}, err
	}
	if err := guardValidCedar(input.CedarSrc); err != nil {
		return CedarPolicy{}, err
	}
	id, err := insertReturningID(ctx, c,
		`INSERT INTO policy (name, cedar_src, enabled, origin, updated_by)
		 VALUES ($1, $2, $3, '`+UserPolicyOrigin+`', $4) RETURNING id`,
		input.Name, input.CedarSrc, input.Enabled, updatedBy)
	if err != nil {
		return CedarPolicy{}, err
	}
	row, err := s.GetOn(ctx, c, id)
	if err != nil {
		return CedarPolicy{}, err
	}
	if row == nil {
		return CedarPolicy{}, fmt.Errorf("policy: policy %d disappeared between INSERT and re-read", id)
	}
	return *row, nil
}

// Update is `update(id, input, updatedBy)`; nil, nil ⇒ no such row.
func (s *CedarPolicyStore) Update(
	ctx context.Context, id int64, input CedarPolicyInput, updatedBy *string,
) (*CedarPolicy, error) {
	updated, err := store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (*CedarPolicy, error) {
		return s.UpdateOn(ctx, tx, id, input, updatedBy)
	})
	if err != nil {
		return nil, err
	}
	// Bump even when the row was absent. The Kotlin's `inTx { … }.also { markCommittedMutation() }`
	// does the same, and a spurious invalidation costs one PolicySet rebuild — whereas a MISSING one
	// serves stale decisions until the next real write. Only Delete gets the conditional treatment,
	// because INV-A11-31 names it specifically.
	s.Bump()
	return updated, nil
}

// UpdateOn is `update(id, input, updatedBy, conn)`, in the Kotlin's five steps:
//
//  1. `SELECT origin … FOR UPDATE` — absent ⇒ nil (which the management layer turns into 404)
//  2. `origin == 'SYSTEM'` ⇒ [ErrSystemPolicyImmutable]
//  3. reserved-name check on the NEW name
//  4. validate the NEW source
//  5. `UPDATE … updated_at = now()`, then re-read
//
// 🔒 INV-A2-20 — step 1 takes the ROW LOCK, and steps 2-5 run under it. Without `FOR UPDATE` a
// concurrent transaction could flip `origin` (or delete the row) between the guard and the UPDATE,
// and the immutability check would have been performed on a row that no longer exists.
//
// 🔒 Step 3 covers RENAMING a user policy into the reserved namespace, not just creating one there —
// `CedarPolicyRoutesTest` case 2 is "POST and USER RENAME reject the reserved `system:` namespace".
func (s *CedarPolicyStore) UpdateOn(
	ctx context.Context, c store.Queryer, id int64, input CedarPolicyInput, updatedBy *string,
) (*CedarPolicy, error) {
	origin, found, err := lockPolicyOrigin(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	if origin == SystemPolicyOrigin {
		return nil, ErrSystemPolicyImmutable
	}
	if err := guardReservedName(input.Name); err != nil {
		return nil, err
	}
	if err := guardValidCedar(input.CedarSrc); err != nil {
		return nil, err
	}
	if err := exec(ctx, c,
		`UPDATE policy SET name=$1, cedar_src=$2, enabled=$3, updated_by=$4, updated_at=now() WHERE id=$5`,
		input.Name, input.CedarSrc, input.Enabled, updatedBy, id); err != nil {
		return nil, err
	}
	return s.GetOn(ctx, c, id)
}

// SetEnabled is `setEnabled(id, enabled, updatedBy)`; nil, nil ⇒ no such row.
func (s *CedarPolicyStore) SetEnabled(
	ctx context.Context, id int64, enabled bool, updatedBy *string,
) (*CedarPolicy, error) {
	toggled, err := store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (*CedarPolicy, error) {
		return s.SetEnabledOn(ctx, tx, id, enabled, updatedBy)
	})
	if err != nil {
		return nil, err
	}
	s.Bump()
	return toggled, nil
}

// SetEnabledOn is `setEnabled(id, enabled, updatedBy, conn)`, in the Kotlin's four steps:
//
//  1. `SELECT … FOR UPDATE` — absent ⇒ nil
//  2. ONLY WHEN ENABLING, `validate(existing.cedarSrc)`
//  3. `UPDATE`
//  4. if `origin == 'SYSTEM'` AND the state ACTUALLY CHANGED, insert the sentinel audit row
//
// 🔒 INV-A2-21 — ENABLING REVALIDATES; DISABLING NEVER DOES. A row that became malformed while
// disabled (or that a migration inserted against an older schema) is rejected on enable and STAYS
// disabled. The asymmetry is the point: refusing to disable a malformed policy would leave a
// deployment unable to turn off the very row breaking it, and disabling is always the safe direction.
// `CedarPolicyStoreTest` case 6 pins it — "enabling a stored-malformed row is rejected and leaves it
// disabled".
//
// 🔒 INV-A2-22 — a SYSTEM toggle writes a VISIBLE SENTINEL AUDIT RECORD, on THIS connection. It is
// the only mutation a SYSTEM policy admits, so it is the only chance to record that a
// migration-owned security rule was turned off; and because the insert shares the transaction, an
// audit failure ROLLS THE TOGGLE BACK. Do not "improve" this by moving the insert after the commit or
// onto the pool — that turns the atomic pair into a toggle that silently succeeds unlogged.
//
// Note step 4's second condition: a no-op toggle (enable an enabled row) writes NO audit row, so the
// trail records state CHANGES rather than requests.
func (s *CedarPolicyStore) SetEnabledOn(
	ctx context.Context, c store.Queryer, id int64, enabled bool, updatedBy *string,
) (*CedarPolicy, error) {
	existing, err := lockPolicyRow(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, nil
	}
	if enabled {
		if err := guardValidCedar(existing.CedarSrc); err != nil {
			return nil, err
		}
	}
	if err := exec(ctx, c,
		`UPDATE policy SET enabled=$1, updated_by=$2, updated_at=now() WHERE id=$3`,
		enabled, updatedBy, id); err != nil {
		return nil, err
	}
	if existing.Origin == SystemPolicyOrigin && existing.Enabled != enabled {
		if _, err := s.auditStore().InsertOn(ctx, c, systemToggleAuditEvent(*existing, enabled, updatedBy)); err != nil {
			return nil, err
		}
	}
	return s.GetOn(ctx, c, id)
}

// Delete is `delete(id)`; false ⇒ no row matched.
func (s *CedarPolicyStore) Delete(ctx context.Context, id int64) (bool, error) {
	deleted, err := store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (bool, error) {
		return s.DeleteOn(ctx, tx, id)
	})
	if err != nil {
		return false, err
	}
	// 🔒 INV-A11-31 — "deletePolicy calls markCommittedMutation() ONLY WHEN A ROW WAS ACTUALLY
	// DELETED." The other three mutations bump unconditionally; this one does not, and the difference
	// is cited per-method in 11-mcp-oauth-management.md:459-460.
	if deleted {
		s.Bump()
	}
	return deleted, nil
}

// DeleteOn is `delete(id, conn)`: `SELECT origin … FOR UPDATE`, SYSTEM ⇒ immutable, then DELETE.
//
// ⚠️ Unlike update and setEnabled, the Kotlin's step 1 here has NO "(null ⇒ return null)" arm
// (02-authz.md:475). An absent row therefore falls through the SYSTEM guard, runs a DELETE that
// matches nothing and answers false — the same answer as "deleted nothing", which is what the
// management layer turns into a 404. Reproduced rather than tidied: adding an early return would be
// indistinguishable here but would change which lock the transaction is holding when it commits.
func (s *CedarPolicyStore) DeleteOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	origin, found, err := lockPolicyOrigin(ctx, c, id)
	if err != nil {
		return false, err
	}
	if found && origin == SystemPolicyOrigin {
		return false, ErrSystemPolicyImmutable
	}
	rows, err := execUpdate(ctx, c, `DELETE FROM policy WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// ---- Guards and helpers ------------------------------------------------------------------------

// guardReservedName is `if (input.name.startsWith("system:")) throw ReservedPolicyNameException(...)`.
//
// ⚠️ CASE-SENSITIVE, and that matches the CHECK constraint it shadows: V3__policy.sql:38 is
// `name NOT LIKE 'system:%'`, which is also case-sensitive in Postgres. So `System:foo` passes both.
// REPRODUCE — a case-insensitive guard here would reject names the database accepts, which is a
// different API.
func guardReservedName(name string) error {
	if strings.HasPrefix(name, ReservedPolicyNamePrefix) {
		return ReservedPolicyNameError{Name: name}
	}
	return nil
}

// guardValidCedar is `CedarSchema.validate(src).takeIf { it.isNotEmpty() }?.let { throw
// InvalidCedarPolicyException(it) }`.
//
// It goes through [authz.DefaultSchema] — the STATELESS validator over the bundled schema — and NOT
// through the live CedarEngine. 02-authz.md §7 is explicit that the two are independent on purpose:
// the store rejects invalid Cedar at WRITE time, before a bad row could ever become enabled, while
// the engine's copy fails fast at construction. Validating against the live enabled set instead would
// make a write's acceptance depend on what else is currently enabled.
//
// 🔒 `validate` NEVER THROWS for policy-shaped input (02-authz.md:399) — it returns a list, empty
// meaning valid — so there is no error path here beyond the list itself.
func guardValidCedar(cedarSrc string) error {
	if errs := authz.DefaultSchema.Validate(cedarSrc); len(errs) > 0 {
		return InvalidCedarPolicyError{Errors: errs}
	}
	return nil
}

// lockPolicyOrigin is `SELECT origin FROM policy WHERE id = ? FOR UPDATE` — the INV-A2-20 guard read.
// found=false means no such row.
func lockPolicyOrigin(ctx context.Context, c store.Queryer, id int64) (origin string, found bool, err error) {
	err = c.QueryRow(ctx, `SELECT origin FROM policy WHERE id=$1 FOR UPDATE`, id).Scan(&origin)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return origin, true, nil
}

// lockPolicyRow is setEnabled's wider guard read: the whole row under `FOR UPDATE`, because step 2
// needs `cedar_src` and step 4 needs `origin`, `system_key` and the OLD `enabled`.
func lockPolicyRow(ctx context.Context, c store.Queryer, id int64) (*CedarPolicy, error) {
	rows, err := c.Query(ctx, `SELECT `+cedarPolicyColumns+` FROM policy WHERE id=$1 FOR UPDATE`, id)
	if err != nil {
		return nil, err
	}
	return firstRow(rows, scanCedarPolicy)
}

// SystemPolicyToggleDetail is the sentinel row's `detail`, the string an audit query filters on to
// find "who turned off a shipped security rule".
const SystemPolicyToggleDetail = "SYSTEM_POLICY_TOGGLE"

// SystemPolicyToggleDatasource is the sentinel row's `datasource`. The control plane is not a
// datasource, but `audit_event.datasource` is NOT NULL, so management decisions record themselves
// against this pseudo-name.
const SystemPolicyToggleDatasource = "control-plane"

// UnknownPolicyPrincipal is `updatedBy ?: "unknown"` — what the sentinel row records when the toggle
// arrived without an identity (PM_AUTH_DEBUG, or a non-HTTP caller).
const UnknownPolicyPrincipal = "unknown"

// systemToggleAuditEvent builds INV-A2-22's row, field for field:
//
//	statement  = "[ADMIN policy.toggle] policy <id> (<systemKey>) enabled <old>-><new>"
//	principal  = updatedBy ?: "unknown"
//	datasource = "control-plane"
//	decision   = ALLOW
//	detail     = "SYSTEM_POLICY_TOGGLE"
//
// ⚠️ `<systemKey>` interpolates a Kotlin `String?` directly, so a NULL system_key renders the four
// characters `null`. A SYSTEM row cannot have one (V3__policy.sql:34's CHECK), but the rendering is
// reproduced rather than guarded, because the statement text is hashed into the audit chain and a
// divergence there is a verification failure that reads as tampering.
//
// `decision = ALLOW` is not a claim that the toggle was authorized — the route's requireAdmin already
// settled that — it is the audit schema's only value for "this happened".
func systemToggleAuditEvent(existing CedarPolicy, enabled bool, updatedBy *string) types.AuditEvent {
	systemKey := "null"
	if existing.SystemKey != nil {
		systemKey = *existing.SystemKey
	}
	statement := fmt.Sprintf("[ADMIN policy.toggle] policy %d (%s) enabled %s->%s",
		existing.ID, systemKey, strconv.FormatBool(existing.Enabled), strconv.FormatBool(enabled))

	principal := UnknownPolicyPrincipal
	if updatedBy != nil {
		principal = *updatedBy
	}

	event := types.NewAuditEvent(principal, SystemPolicyToggleDatasource, statement, types.DecisionAllow)
	event.Detail = types.Ptr(SystemPolicyToggleDetail)
	return event
}

// scanCedarPolicy maps one `policy` row. `updated_at` is read as a time.Time and rendered through
// [instant.Format] — Java's variable-precision `Instant.toString()`, the same wire-visible formatting
// internal/audit uses for `ts` (02-authz.md:450, Q3).
func scanCedarPolicy(row pgx.Row) (CedarPolicy, error) {
	var p CedarPolicy
	var updatedAt time.Time
	err := row.Scan(&p.ID, &p.Origin, &p.SystemKey, &p.Name, &p.CedarSrc, &p.Enabled, &p.UpdatedBy, &updatedAt)
	if err != nil {
		return CedarPolicy{}, err
	}
	p.UpdatedAt = instant.Format(updatedAt)
	return p, nil
}
