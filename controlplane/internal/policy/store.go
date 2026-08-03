package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// PolicyStore is the port of `class PolicyStore(internal val dataSource: DataSource)`
// (Policies.kt:29-147).
//
// The Kotlin's `dataSource` is `internal`, not private, because `policyRoutes`' default `management`
// parameter reads it to build `CedarPolicyStore(store.dataSource)` (Policies.kt:153). DB() below is
// that accessor; A11's wiring is its only intended caller.
//
// 🔒 Port this store EARLY and EXACTLY. ~36 Kotlin suites use it as a fixture, so a behaviour change
// here breaks them in ways that look like THOSE areas failing (09-policies.md §4.4).
type PolicyStore struct {
	db store.DB
}

// NewPolicyStore builds the store over the shared control-plane handle. There is no second pool: A1
// wires ONE ControlPlaneCore and every area's store takes a handle from it (INV-A1-1).
func NewPolicyStore(db store.DB) *PolicyStore { return &PolicyStore{db: db} }

// DB exposes the underlying handle, reproducing `internal val dataSource`.
//
// TODO(A11): the only intended caller is the `PolicyManagementService(CedarPolicyStore(store.dataSource), store)`
// default at Policies.kt:153. Nothing else should reach through the store for a connection.
func (s *PolicyStore) DB() store.DB { return s.db }

// ---- Roles — `app_role` --------------------------------------------------------------------

// ListRoles is `listRoles()`.
func (s *PolicyStore) ListRoles(ctx context.Context) ([]Role, error) {
	return s.ListRolesOn(ctx, s.db)
}

// ListRolesOn is `listRoles(c)`. INV-A3-14's ordering rule applies here too: `ORDER BY name` is not
// cosmetic — web/ renders this list directly.
func (s *PolicyStore) ListRolesOn(ctx context.Context, c store.Queryer) ([]Role, error) {
	return query(ctx, c, `SELECT id, name, description FROM app_role ORDER BY name`, scanRole)
}

// GetRole is `getRole(id)`.
func (s *PolicyStore) GetRole(ctx context.Context, id int64) (*Role, error) {
	return s.GetRoleOn(ctx, s.db, id)
}

// GetRoleOn is `getRole(id, c)`. nil, nil ⇒ no such row (the Kotlin's `Role?`).
func (s *PolicyStore) GetRoleOn(ctx context.Context, c store.Queryer, id int64) (*Role, error) {
	return queryOne(ctx, c, `SELECT id, name, description FROM app_role WHERE id=$1`, id, scanRole)
}

// GetRoleByName is `getRoleByName(name)`.
func (s *PolicyStore) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	return s.GetRoleByNameOn(ctx, s.db, name)
}

// GetRoleByNameOn is `getRoleByName(name, c)`.
//
// The Kotlin writes this one out longhand instead of going through its own `queryOne` helper,
// because that helper binds exactly one Long (Policies.kt:137). The same split is kept here: the
// id-keyed reads use queryOne, the name-keyed ones do not. Duplication is REPRODUCE
// (09-policies.md:95-98), and unifying them is a post-cutover refactor.
func (s *PolicyStore) GetRoleByNameOn(ctx context.Context, c store.Queryer, name string) (*Role, error) {
	rows, err := c.Query(ctx, `SELECT id, name, description FROM app_role WHERE name=$1`, name)
	if err != nil {
		return nil, err
	}
	return firstRow(rows, scanRole)
}

// CreateRole is `createRole(input)`.
func (s *PolicyStore) CreateRole(ctx context.Context, input RoleInput) (Role, error) {
	return s.CreateRoleOn(ctx, s.db, input)
}

// CreateRoleOn is `createRole(input, c)`: INSERT … RETURNING id, then re-read the row.
//
// The Kotlin's re-read is `getRole(id, c)!!` — a non-null assertion that throws
// NullPointerException if the row vanished between the two statements (possible on the pool's
// autocommit path, where the INSERT has already committed). Go has no `!!`, so the same
// can't-happen state becomes a returned error rather than a panic; it stays just as loud.
func (s *PolicyStore) CreateRoleOn(ctx context.Context, c store.Queryer, input RoleInput) (Role, error) {
	id, err := insertReturningID(ctx, c,
		`INSERT INTO app_role (name, description) VALUES ($1, $2) RETURNING id`,
		input.Name, input.Description)
	if err != nil {
		return Role{}, err
	}
	role, err := s.GetRoleOn(ctx, c, id)
	if err != nil {
		return Role{}, err
	}
	if role == nil {
		return Role{}, fmt.Errorf("policy: app_role %d disappeared between INSERT and re-read", id)
	}
	return *role, nil
}

// UpdateRole is `updateRole(id, input)`.
func (s *PolicyStore) UpdateRole(ctx context.Context, id int64, input RoleInput) (*Role, error) {
	return s.UpdateRoleOn(ctx, s.db, id, input)
}

// UpdateRoleOn is `updateRole(id, input, c)`: existence check first, so an absent id is nil (which
// A11 turns into 404) rather than a silent zero-row UPDATE.
//
// ⚠️ Nothing here checks IsSystemRole. The `role.system_immutable` guard lives in A11
// (`ManagementServices.kt:362,370`), and it is untested there (F19). REPRODUCE — do not add the
// check to the store, or A11's tests would pass for the wrong reason.
func (s *PolicyStore) UpdateRoleOn(ctx context.Context, c store.Queryer, id int64, input RoleInput) (*Role, error) {
	existing, err := s.GetRoleOn(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, nil
	}
	if err := exec(ctx, c, `UPDATE app_role SET name=$1, description=$2 WHERE id=$3`,
		input.Name, input.Description, id); err != nil {
		return nil, err
	}
	return s.GetRoleOn(ctx, c, id)
}

// DeleteRole is `deleteRole(id)`.
func (s *PolicyStore) DeleteRole(ctx context.Context, id int64) (bool, error) {
	return s.DeleteRoleOn(ctx, s.db, id)
}

// DeleteRoleOn is `deleteRole(id, c)`; false ⇒ no row matched.
//
// V1__identity.sql declares `group_role.role_id` and `principal_role.role_id` ON DELETE CASCADE, so
// deleting a role silently drops its group mappings and every direct assignment. That is the
// migration's behaviour, carried as-is.
func (s *PolicyStore) DeleteRoleOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	n, err := execUpdate(ctx, c, `DELETE FROM app_role WHERE id=$1`, id)
	return n > 0, err
}

// IsSystemRole is `isSystemRole(id)`.
func (s *PolicyStore) IsSystemRole(ctx context.Context, id int64) (bool, error) {
	return s.IsSystemRoleOn(ctx, s.db, id)
}

// IsSystemRoleOn is `isSystemRole(id, c)`.
//
// 🔒 INV-A9-1 — "system role" is DERIVED, not a column. A role is a system role iff at least one
// group with `source = 'SYSTEM'` grants it. There is NO `app_role.is_system` flag, and a Go port
// that adds one changes the semantics: under this query a role becomes — or stops being — a system
// role as `group_role` mappings change.
//
// ⚠️ F34: `V8__seed.sql:48-58` installs SEVEN `source=SYSTEM` groups, not one. The predicate keys on
// the COLUMN, so all seven behave identically; a port that special-cases the string `"system:admin"`
// would leave the other six production-capability groups' roles freely mutable. The name is also not
// the test: `system:auditor` is seeded, is `system:`-prefixed, and is granted by NO group — so it is
// NOT a system role. store_db_test.go pins both halves.
func (s *PolicyStore) IsSystemRoleOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	var out bool
	err := c.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM group_role gr JOIN app_group g ON g.id = gr.group_id
           WHERE gr.role_id = $1 AND g.source = 'SYSTEM')`, id).Scan(&out)
	if err != nil {
		return false, err
	}
	return out, nil
}

// ---- Assignments — `principal_role` ---------------------------------------------------------

// assignmentSelect is the shared projection. Every read joins `app_role` because RoleAssignment
// carries the denormalized `roleName` (09-policies.md §1).
const assignmentSelect = `SELECT pr.id, pr.principal, pr.role_id, r.name AS role_name
               FROM principal_role pr JOIN app_role r ON r.id = pr.role_id`

// ListAssignments is `listAssignments(principal, roleId)`. Both filters are optional; nil means
// "no filter", which is Kotlin's `String?` / `Long?`.
func (s *PolicyStore) ListAssignments(ctx context.Context, principal *string, roleID *int64) ([]RoleAssignment, error) {
	return s.ListAssignmentsOn(ctx, s.db, principal, roleID)
}

// ListAssignmentsOn is `listAssignments(principal, roleId, c)`.
//
// ⚠️ The `WHERE 1=1` + conditional-append idiom is carried over verbatim, and with it the port's
// single most dangerous mechanical hazard: JDBC's positional `?` is order-only, so the Kotlin can
// append clauses freely and bind with a running index. pgx placeholders are NUMBERED, so the number
// has to be derived from the same running count — when `principal` is nil, `roleId` binds to `$1`,
// not `$2`. A mis-numbered argument here is a silent wrong-value bug, not a compile error, so the
// index is taken from len(args) at the moment each clause is appended and never written literally.
func (s *PolicyStore) ListAssignmentsOn(
	ctx context.Context, c store.Queryer, principal *string, roleID *int64,
) ([]RoleAssignment, error) {
	sql := assignmentSelect + ` WHERE 1=1`
	var args []any
	if principal != nil {
		args = append(args, *principal)
		sql += fmt.Sprintf(" AND pr.principal = $%d", len(args))
	}
	if roleID != nil {
		args = append(args, *roleID)
		sql += fmt.Sprintf(" AND pr.role_id = $%d", len(args))
	}
	sql += ` ORDER BY pr.principal, r.name`
	return query(ctx, c, sql, scanAssignment, args...)
}

// GetAssignment is `getAssignment(id)`.
func (s *PolicyStore) GetAssignment(ctx context.Context, id int64) (*RoleAssignment, error) {
	return s.GetAssignmentOn(ctx, s.db, id)
}

// GetAssignmentOn is `getAssignment(id, c)`. Exact, single-row, and — per F8 — deliberately NOT what
// CreateAssignmentOn uses.
func (s *PolicyStore) GetAssignmentOn(ctx context.Context, c store.Queryer, id int64) (*RoleAssignment, error) {
	rows, err := c.Query(ctx, assignmentSelect+` WHERE pr.id = $1`, id)
	if err != nil {
		return nil, err
	}
	return firstRow(rows, scanAssignment)
}

// CreateAssignment is `createAssignment(input)`.
func (s *PolicyStore) CreateAssignment(ctx context.Context, input RoleAssignmentInput) (RoleAssignment, error) {
	return s.CreateAssignmentOn(ctx, s.db, input)
}

// CreateAssignmentOn is `createAssignment(input, c)`.
//
// 🔒 INV-A9-2 — the upsert is an IDEMPOTENCY IDIOM, not a real update.
// `ON CONFLICT (principal, role_id) DO UPDATE SET principal=EXCLUDED.principal` is a deliberate
// no-op write: setting principal to the value it already has. Its only purpose is to make
// `RETURNING id` fire on conflict, because a plain `DO NOTHING` returns NO ROW — the insert would
// yield nothing to return, and the caller has no id to look up. So re-assigning an existing
// (principal, role) pair returns the EXISTING id instead of failing. Do not "simplify" this.
//
// ⚠️ F8 — REPRODUCED, deliberately. The row is located with a FULL TABLE READ
// (`listAssignments(null, null, c).first { it.id == id }`, Policies.kt:98) even though
// GetAssignmentOn(id) is exact and one line away. 00-INDEX.md:375 dispositions this REPRODUCE:
// inefficiency is named in the port policy as *not* grounds for OMIT, and the two paths are not
// identical either — `.first {}` throws on a miss where GetAssignmentOn returns null. Swapping them
// is a behaviour change, however small, and belongs in a separate PR against the working Go service.
func (s *PolicyStore) CreateAssignmentOn(
	ctx context.Context, c store.Queryer, input RoleAssignmentInput,
) (RoleAssignment, error) {
	id, err := insertReturningID(ctx, c,
		`INSERT INTO principal_role (principal, role_id) VALUES ($1, $2) `+
			`ON CONFLICT (principal, role_id) DO UPDATE SET principal=EXCLUDED.principal RETURNING id`,
		input.Principal, input.RoleID)
	if err != nil {
		return RoleAssignment{}, err
	}
	// F8: every assignment row in the table, to find the one we just wrote.
	all, err := s.ListAssignmentsOn(ctx, c, nil, nil)
	if err != nil {
		return RoleAssignment{}, err
	}
	for _, a := range all {
		if a.ID == id {
			return a, nil
		}
	}
	// Kotlin's `.first {}` throws NoSuchElementException here; Go returns it.
	return RoleAssignment{}, fmt.Errorf("policy: principal_role %d not found in listAssignments after upsert", id)
}

// DeleteAssignment is `deleteAssignment(id)`.
func (s *PolicyStore) DeleteAssignment(ctx context.Context, id int64) (bool, error) {
	return s.DeleteAssignmentOn(ctx, s.db, id)
}

// DeleteAssignmentOn is `deleteAssignment(id, c)`.
func (s *PolicyStore) DeleteAssignmentOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	n, err := execUpdate(ctx, c, `DELETE FROM principal_role WHERE id=$1`, id)
	return n > 0, err
}

// DeleteAssignmentByPrincipalRoleOn is `deleteAssignment(principal, roleId, c)`.
//
// ⚠️ It has NO own-handle twin, in the Kotlin or here. The only caller is A11's `replaceDirectRoles`,
// which runs it inside the transaction holding the per-principal advisory lock (INV-A11-30) — the
// whole point is that it composes into someone else's transaction. Adding a `dataSource.connection`
// form would be a new API, and one whose safe use is not obvious.
func (s *PolicyStore) DeleteAssignmentByPrincipalRoleOn(
	ctx context.Context, c store.Queryer, principal string, roleID int64,
) (bool, error) {
	n, err := execUpdate(ctx, c, `DELETE FROM principal_role WHERE principal=$1 AND role_id=$2`, principal, roleID)
	return n > 0, err
}

// ---- Mask functions — `mask_fn` --------------------------------------------------------------

// ListMaskFns is `listMaskFns()`.
func (s *PolicyStore) ListMaskFns(ctx context.Context) ([]MaskFn, error) {
	return s.ListMaskFnsOn(ctx, s.db)
}

// ListMaskFnsOn is `listMaskFns(c)`.
func (s *PolicyStore) ListMaskFnsOn(ctx context.Context, c store.Queryer) ([]MaskFn, error) {
	return query(ctx, c, `SELECT id, name, kind FROM mask_fn ORDER BY name`, scanMaskFn)
}

// GetMaskFn is `getMaskFn(id)`.
func (s *PolicyStore) GetMaskFn(ctx context.Context, id int64) (*MaskFn, error) {
	return s.GetMaskFnOn(ctx, s.db, id)
}

// GetMaskFnOn is `getMaskFn(id, c)`.
func (s *PolicyStore) GetMaskFnOn(ctx context.Context, c store.Queryer, id int64) (*MaskFn, error) {
	return queryOne(ctx, c, `SELECT id, name, kind FROM mask_fn WHERE id=$1`, id, scanMaskFn)
}

// GetMaskFnByName is `getMaskFnByName(name)`.
func (s *PolicyStore) GetMaskFnByName(ctx context.Context, name string) (*MaskFn, error) {
	return s.GetMaskFnByNameOn(ctx, s.db, name)
}

// GetMaskFnByNameOn is `getMaskFnByName(name, c)`. Longhand for the same reason GetRoleByNameOn is.
func (s *PolicyStore) GetMaskFnByNameOn(ctx context.Context, c store.Queryer, name string) (*MaskFn, error) {
	rows, err := c.Query(ctx, `SELECT id, name, kind FROM mask_fn WHERE name=$1`, name)
	if err != nil {
		return nil, err
	}
	return firstRow(rows, scanMaskFn)
}

// CreateMaskFn is `createMaskFn(input)`.
func (s *PolicyStore) CreateMaskFn(ctx context.Context, input MaskFnInput) (MaskFn, error) {
	return s.CreateMaskFnOn(ctx, s.db, input)
}

// CreateMaskFnOn is `createMaskFn(input, c)`. Same `!!`-becomes-error note as CreateRoleOn.
func (s *PolicyStore) CreateMaskFnOn(ctx context.Context, c store.Queryer, input MaskFnInput) (MaskFn, error) {
	id, err := insertReturningID(ctx, c,
		`INSERT INTO mask_fn (name, kind) VALUES ($1, $2) RETURNING id`, input.Name, input.Kind)
	if err != nil {
		return MaskFn{}, err
	}
	fn, err := s.GetMaskFnOn(ctx, c, id)
	if err != nil {
		return MaskFn{}, err
	}
	if fn == nil {
		return MaskFn{}, fmt.Errorf("policy: mask_fn %d disappeared between INSERT and re-read", id)
	}
	return *fn, nil
}

// UpdateMaskFn is `updateMaskFn(id, input)`.
func (s *PolicyStore) UpdateMaskFn(ctx context.Context, id int64, input MaskFnInput) (*MaskFn, error) {
	return s.UpdateMaskFnOn(ctx, s.db, id, input)
}

// UpdateMaskFnOn is `updateMaskFn(id, input, c)`; nil for an absent id.
func (s *PolicyStore) UpdateMaskFnOn(ctx context.Context, c store.Queryer, id int64, input MaskFnInput) (*MaskFn, error) {
	existing, err := s.GetMaskFnOn(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, nil
	}
	if err := exec(ctx, c, `UPDATE mask_fn SET name=$1, kind=$2 WHERE id=$3`, input.Name, input.Kind, id); err != nil {
		return nil, err
	}
	return s.GetMaskFnOn(ctx, c, id)
}

// DeleteMaskFn is `deleteMaskFn(id)`.
func (s *PolicyStore) DeleteMaskFn(ctx context.Context, id int64) (bool, error) {
	return s.DeleteMaskFnOn(ctx, s.db, id)
}

// DeleteMaskFnOn is `deleteMaskFn(id, c)`.
//
// ⚠️ `column_classification.mask_fn_id` is a plain REFERENCES with no ON DELETE clause
// (V2__catalog.sql:85), so deleting a mask fn a classification still points at raises SQLSTATE
// 23503. store.IsUniqueViolation deliberately does NOT match 23503 (F29), so this surfaces as a raw
// error — which is exactly what the Kotlin does with it.
func (s *PolicyStore) DeleteMaskFnOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	n, err := execUpdate(ctx, c, `DELETE FROM mask_fn WHERE id=$1`, id)
	return n > 0, err
}

// ---- Row mappers + the private query helpers -------------------------------------------------
//
// The Kotlin's `ResultSet.toRole()` / `toMaskFn()` and its five `Connection.*` extensions
// (Policies.kt:132-146). REPRODUCE, including the fact that `CedarPolicyStore` and `Users.kt` carry
// their own copies — 09-policies.md:95-98 dispositions all three, and collapsing them is a
// post-cutover refactor, not part of the port.

// scanRole is `ResultSet.toRole()`.
func scanRole(row pgx.Row) (Role, error) {
	var r Role
	err := row.Scan(&r.ID, &r.Name, &r.Description)
	return r, err
}

// scanMaskFn is `ResultSet.toMaskFn()`.
func scanMaskFn(row pgx.Row) (MaskFn, error) {
	var m MaskFn
	err := row.Scan(&m.ID, &m.Name, &m.Kind)
	return m, err
}

// scanAssignment maps the assignment join. The Kotlin builds RoleAssignment inline at both read
// sites (Policies.kt:78,90) rather than through a `toAssignment()` extension; one mapper here is the
// same behaviour and keeps the column order defined once.
func scanAssignment(row pgx.Row) (RoleAssignment, error) {
	var a RoleAssignment
	err := row.Scan(&a.ID, &a.Principal, &a.RoleID, &a.RoleName)
	return a, err
}

// query is `private fun <T> Connection.query(sql, map): List<T>`.
//
// It returns a nil slice for an empty result, matching Kotlin's `buildList {}` producing an empty
// list: both are len 0, and nil marshals to `[]` only through internal/types' normalisation, which
// is A11's concern at the route boundary, not the store's.
func query[T any](ctx context.Context, c store.Queryer, sql string, scan func(pgx.Row) (T, error), args ...any) ([]T, error) {
	rows, err := c.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// queryOne is `private fun <T> Connection.queryOne(sql, id, map): T?` — note it binds exactly ONE
// Long, which is why the name-keyed reads above go longhand instead.
func queryOne[T any](ctx context.Context, c store.Queryer, sql string, id int64, scan func(pgx.Row) (T, error)) (*T, error) {
	rows, err := c.Query(ctx, sql, id)
	if err != nil {
		return nil, err
	}
	return firstRow(rows, scan)
}

// firstRow drains at most one row, then closes — the Go shape of
// `executeQuery().use { rs -> if (rs.next()) map(rs) else null }`.
//
// pgx defers most execution errors to Next/Close rather than reporting them from Query, so the
// error check has to come from rows.Err() after the loop, not from the Query call.
func firstRow[T any](rows pgx.Rows, scan func(pgx.Row) (T, error)) (*T, error) {
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	v, err := scan(rows)
	if err != nil {
		return nil, err
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &v, nil
}

// insertReturningID is `private fun Connection.insertReturningId(sql, bind): Long`.
//
// ⚠️ Name-collision note carried from 09-policies.md: THIS one is live. `CedarPolicyStore`'s
// identically-named private helper is dead (F2) and `Users.kt:878`'s is dead (F80). Three copies,
// three dispositions.
//
// The Kotlin is `executeQuery().use { rs -> rs.next(); rs.getLong(1) }` — it advances and IGNORES
// the boolean, so a statement that returned nothing throws from `getLong` ("no current row"). pgx's
// QueryRow().Scan() returns pgx.ErrNoRows for the same state; both are errors, neither is silent.
func insertReturningID(ctx context.Context, c store.Queryer, sql string, args ...any) (int64, error) {
	var id int64
	if err := c.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("policy: INSERT … RETURNING id produced no row: %w", err)
		}
		return 0, err
	}
	return id, nil
}

// exec is `private fun Connection.exec(sql, bind)` — the update whose row count is discarded.
func exec(ctx context.Context, c store.Queryer, sql string, args ...any) error {
	_, err := c.Exec(ctx, sql, args...)
	return err
}

// execUpdate is `private fun Connection.execUpdate(sql, bind): Int` — the update whose row count is
// the answer (`> 0` at every call site).
func execUpdate(ctx context.Context, c store.Queryer, sql string, args ...any) (int64, error) {
	tag, err := c.Exec(ctx, sql, args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
