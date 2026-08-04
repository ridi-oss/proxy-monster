package dbtest

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// Seed writes control-plane rows so a suite can state its intent — "this column is pii and masked
// last-4", "this group grants that role" — instead of spelling out SQL. It is the vocabulary
// EnforcementFixture's seedPolicy is written in (EnforcementFixture.kt:193-308).
//
// ⚠️ TODO(A5)/TODO(A9)/TODO(A2): every method here writes SQL DIRECTLY, because the production stores
// it should be calling — DatasourceStore, PolicyStore, CedarPolicyStore — are not ported yet. The
// Kotlin fixture calls those stores (`s.policyStore.createRole(...)`, `s.cedarPolicyStore.create(...)`),
// which is what keeps its fixtures and its production writes on one code path. Re-point these methods
// at the production stores as each area lands, and delete the SQL: a fixture that keeps its own INSERT
// statements is a second, silently diverging definition of what a valid row looks like. Until then,
// treat a constraint violation from one of these statements as a signal that the fixture drifted, not
// that the migration is wrong.
//
// Every method fails the test on error rather than returning one: a fixture that half-succeeds
// produces a test failure somewhere else entirely, which is the most expensive kind to diagnose.
type Seed struct {
	t    testing.TB
	ctx  context.Context
	pool *pgxpool.Pool
}

// NewSeed builds a seeder over a migrated control-plane store.
func NewSeed(t testing.TB, db *store.Db) *Seed {
	t.Helper()
	return &Seed{t: t, ctx: context.Background(), pool: db.Pool}
}

// DatasourceSpec is the subset of `datasource` a fixture sets. The remaining columns keep their
// migration defaults (V2__catalog.sql), which is what a datasource created through the admin API and
// never yet introspected looks like.
type DatasourceSpec struct {
	Name   string
	Engine string // EnginePostgres | EngineMySQL
	Host   string
	Port   int
	DBName string
	// Tags are the datasource posture/free-form tags Authz marshals onto the Datasource Cedar entity.
	// nil seeds the migration default `[]`.
	Tags []string
}

// Datasource inserts a datasource row and returns its id.
func (s *Seed) Datasource(spec DatasourceSpec) int64 {
	s.t.Helper()
	tags := spec.Tags
	if tags == nil {
		tags = []string{}
	}
	var id int64
	err := s.pool.QueryRow(s.ctx,
		`INSERT INTO datasource (name, engine, host, port, db_name, tags)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb) RETURNING id`,
		spec.Name, spec.Engine, spec.Host, spec.Port, spec.DBName, mustJSON(s.t, tags),
	).Scan(&id)
	if err != nil {
		s.t.Fatalf("seed datasource %s: %v", spec.Name, err)
	}
	return id
}

// CatalogColumn is one row of the introspected catalog (V2__catalog.sql `catalog_column`).
type CatalogColumn struct {
	Schema   string
	Table    string
	Column   string
	DataType string // the raw engine type, e.g. "character varying"
	SQLType  string // the normalized name the analyzer binds against; blank derives it from DataType
	Ordinal  int
	Nullable bool
}

// CatalogColumns inserts catalog rows for a datasource.
//
// COPY rather than one INSERT per row: a full information_schema scan of a PostgreSQL target is a few
// thousand columns (see IntrospectTargetInto on why the scan is not narrowed), and a per-row round
// trip there is the difference between a fixture that costs milliseconds and one that costs seconds
// on every DB-backed test.
func (s *Seed) CatalogColumns(datasourceID int64, cols ...CatalogColumn) {
	s.t.Helper()
	if len(cols) == 0 {
		return
	}
	rows := make([][]any, 0, len(cols))
	for _, c := range cols {
		sqlType := c.SQLType
		if sqlType == "" {
			sqlType = SQLTypeFor(c.DataType)
		}
		rows = append(rows, []any{
			datasourceID, c.Schema, c.Table, c.Column, c.DataType, sqlType, c.Ordinal, c.Nullable,
		})
	}
	_, err := s.pool.CopyFrom(s.ctx,
		pgx.Identifier{"catalog_column"},
		[]string{"datasource_id", "schema_name", "table_name", "column_name", "data_type", "sql_type", "ordinal", "nullable"},
		pgx.CopyFromRows(rows))
	if err != nil {
		s.t.Fatalf("seed %d catalog columns for datasource %d: %v", len(cols), datasourceID, err)
	}
}

// Namespace records the static namespace metadata a proxy captures alongside a catalog push: the
// ordered default schemas bare names resolve against, MySQL's @@lower_case_table_names, and the live
// server version the system-classification manifest is keyed off.
func (s *Seed) Namespace(datasourceID int64, defaultSchemas []string, mysqlLowerCaseTableNames *int, engineVersion string) {
	s.t.Helper()
	_, err := s.pool.Exec(s.ctx,
		`UPDATE datasource
		    SET default_schemas = $2::jsonb,
		        mysql_lower_case_table_names = $3,
		        engine_version = $4,
		        catalog_synced_at = now()
		  WHERE id = $1`,
		datasourceID, mustJSON(s.t, defaultSchemas), mysqlLowerCaseTableNames, engineVersion)
	if err != nil {
		s.t.Fatalf("seed namespace for datasource %d: %v", datasourceID, err)
	}
}

// EngineVersion overwrites JUST `datasource.engine_version`, leaving the rest of the namespace
// metadata alone — the Go form of the gate suites' `setEngineVersion(v)`
// (SystemClassificationEnforcementDbTest.kt:38-46, UtilityGateDbTest.kt:40, and
// BaselineDangerousFunctionEnforcementDbTest.kt's `configure`). nil clears it.
//
// 🔒 The version is what selects the governing system-classification manifest, so clearing it is not
// cosmetic: it is the "uncertified / unreported version" posture in which system schemas stay
// deny-by-default and A6's step-13 utility gate hard-denies. Several gate cases turn exactly on the
// difference, which is why this is a NARROW setter and not a call to [Seed.Namespace] — rewriting
// default_schemas or lower_case_table_names alongside it would silently change what the analyzer
// resolves as well as what the classifier answers.
func (s *Seed) EngineVersion(datasourceID int64, version *string) {
	s.t.Helper()
	if _, err := s.pool.Exec(s.ctx,
		`UPDATE datasource SET engine_version = $2 WHERE id = $1`, datasourceID, version,
	); err != nil {
		s.t.Fatalf("set engine_version on datasource %d: %v", datasourceID, err)
	}
}

// DatasourceTags overwrites `datasource.tags` — the Go form of the gate suites' `setTags(tagsJson)`.
//
// The posture tags (`system:development` / `system:production`) are what the shipped preset policies
// key off: -200 permits unmasked reads on dev, and the -110/-120 activity/data-leak forbids carry an
// `unless { resource in Tag::"system:development" }` relaxation while -130 (critical) does not. A
// suite flipping these is flipping the Cedar outcome, not a label.
func (s *Seed) DatasourceTags(datasourceID int64, tags []string) {
	s.t.Helper()
	if _, err := s.pool.Exec(s.ctx,
		`UPDATE datasource SET tags = $2::jsonb WHERE id = $1`, datasourceID, mustJSON(s.t, tags),
	); err != nil {
		s.t.Fatalf("set tags on datasource %d: %v", datasourceID, err)
	}
}

// SetUserActive flips `app_user.active` — the Go form of
// `userGroupStore.setUserActive(principal, false)` (the SCIM active=false / IdP-liveness-failure
// path). The row must already exist; [Seed.User] creates it.
//
// ⚠️ TODO(A3): the production home is `UserGroupStore.setUserActive`, which internal/identity has not
// ported (it has IsDeactivated and RolesForPrincipal only). Re-point this at the production method
// when it lands rather than growing this one — deprovisioning has side effects the real method owns
// (token/session/grant revocation) and a fixture that keeps its own UPDATE will drift from them.
func (s *Seed) SetUserActive(principal string, active bool) {
	s.t.Helper()
	tag, err := s.pool.Exec(s.ctx, `UPDATE app_user SET active = $2 WHERE principal = $1`, principal, active)
	if err != nil {
		s.t.Fatalf("set active=%v on %s: %v", active, principal, err)
	}
	if tag.RowsAffected() != 1 {
		s.t.Fatalf("set active=%v on %s: %d rows matched, want 1 (seed the app_user row first)",
			active, principal, tag.RowsAffected())
	}
}

// MaskFn inserts a mask function and returns its id. kind is one of FIXED | LAST_N |
// FORMAT_PRESERVING | NULL — masking selects the transform by kind alone (V2__catalog.sql).
func (s *Seed) MaskFn(name, kind string) int64 {
	s.t.Helper()
	var id int64
	if err := s.pool.QueryRow(s.ctx,
		`INSERT INTO mask_fn (name, kind) VALUES ($1, $2) RETURNING id`, name, kind,
	).Scan(&id); err != nil {
		s.t.Fatalf("seed mask_fn %s: %v", name, err)
	}
	return id
}

// Classify overlays tags (and optionally a mask function) on a catalog column. maskFnID may be nil.
//
// This is catalog DATA, not authorization: WHO may read or mask the column is Cedar policy text, and
// a touched column with no matching grant is denied rather than returned cleartext (V2__catalog.sql).
func (s *Seed) Classify(datasourceID int64, schema, table, column string, tags []string, maskFnID *int64) {
	s.t.Helper()
	_, err := s.pool.Exec(s.ctx,
		`INSERT INTO column_classification
		   (datasource_id, schema_name, table_name, column_name, tags, mask_fn_id)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6)
		 ON CONFLICT (datasource_id, schema_name, table_name, column_name)
		 DO UPDATE SET tags = EXCLUDED.tags, mask_fn_id = EXCLUDED.mask_fn_id, updated_at = now()`,
		datasourceID, schema, table, column, mustJSON(s.t, tags), maskFnID)
	if err != nil {
		s.t.Fatalf("seed classification %s.%s.%s: %v", schema, table, column, err)
	}
}

// Role inserts an app_role and returns its id.
func (s *Seed) Role(name string) int64 {
	s.t.Helper()
	var id int64
	if err := s.pool.QueryRow(s.ctx,
		`INSERT INTO app_role (name) VALUES ($1) RETURNING id`, name,
	).Scan(&id); err != nil {
		s.t.Fatalf("seed role %s: %v", name, err)
	}
	return id
}

// AssignRole gives a principal a DIRECT principal_role assignment — the assignment RoleResolver's
// directRoles() reads. Role resolution is entirely server-side: no caller may assert a role list
// (RoleResolver.kt:6-12), so this is how a fixture gives its principal roles.
func (s *Seed) AssignRole(principal string, roleID int64) {
	s.t.Helper()
	if _, err := s.pool.Exec(s.ctx,
		`INSERT INTO principal_role (principal, role_id) VALUES ($1, $2)`, principal, roleID,
	); err != nil {
		s.t.Fatalf("seed principal_role %s -> %d: %v", principal, roleID, err)
	}
}

// Group inserts an app_group and returns its id.
func (s *Seed) Group(name string) int64 {
	s.t.Helper()
	var id int64
	if err := s.pool.QueryRow(s.ctx,
		`INSERT INTO app_group (name) VALUES ($1) RETURNING id`, name,
	).Scan(&id); err != nil {
		s.t.Fatalf("seed group %s: %v", name, err)
	}
	return id
}

// GroupRole maps a local group to a role. The IdP never mints a role: its group claim provisions
// local app_group membership, and THIS map is what turns a group into roles (V1__identity.sql).
func (s *Seed) GroupRole(groupID, roleID int64) {
	s.t.Helper()
	if _, err := s.pool.Exec(s.ctx,
		`INSERT INTO group_role (group_id, role_id) VALUES ($1, $2)`, groupID, roleID,
	); err != nil {
		s.t.Fatalf("seed group_role %d -> %d: %v", groupID, roleID, err)
	}
}

// User inserts an app_user and returns its id. active defaults to TRUE, per V1__identity.sql.
func (s *Seed) User(principal string) int64 {
	s.t.Helper()
	var id int64
	if err := s.pool.QueryRow(s.ctx,
		`INSERT INTO app_user (principal) VALUES ($1) RETURNING id`, principal,
	).Scan(&id); err != nil {
		s.t.Fatalf("seed user %s: %v", principal, err)
	}
	return id
}

// GroupMember puts a user in a group.
func (s *Seed) GroupMember(groupID, userID int64) {
	s.t.Helper()
	if _, err := s.pool.Exec(s.ctx,
		`INSERT INTO group_member (group_id, user_id) VALUES ($1, $2)`, groupID, userID,
	); err != nil {
		s.t.Fatalf("seed group_member %d/%d: %v", groupID, userID, err)
	}
}

// CedarPolicy inserts an enabled USER-origin Cedar policy and returns its id.
//
// USER origin is not a default worth hiding: V3__policy.sql's three CHECK constraints tie origin to
// the id's sign, to the `system:` name prefix and to system_key together, so a fixture cannot seed a
// SYSTEM policy through this method even by accident. Seeding one means writing a NEGATIVE id
// explicitly, which is exactly the visibility that constraint set exists to force.
func (s *Seed) CedarPolicy(name, cedarSrc string) int64 {
	s.t.Helper()
	if strings.HasPrefix(name, "system:") {
		s.t.Fatalf("seed cedar policy %q: `system:` names are migration-owned (V3__policy.sql); "+
			"a fixture may not create one", name)
	}
	var id int64
	if err := s.pool.QueryRow(s.ctx,
		`INSERT INTO policy (name, cedar_src, updated_by) VALUES ($1, $2, 'test-fixture') RETURNING id`,
		name, cedarSrc,
	).Scan(&id); err != nil {
		s.t.Fatalf("seed cedar policy %s: %v", name, err)
	}
	return id
}

// IntrospectTargetInto scans a live target's information_schema and stores the result as this
// datasource's catalog, plus the static namespace metadata.
//
// It is the port of EnforcementFixture.kt:35-107's `pushTestCatalog`, and it mirrors what the proxy
// pushes over gRPC without asking the control plane to dial the target — the control plane never
// dials a target and holds no credential to one (V2__catalog.sql). The TEST owns this connection.
func (s *Seed) IntrospectTargetInto(datasourceID int64, engine string, target *sql.DB, dbName string) {
	s.t.Helper()

	var (
		defaultSchemas []string
		lowerCase      *int
		engineVersion  string
	)
	switch engine {
	case EngineMySQL:
		var currentDB string
		var lct int
		var matches bool
		err := target.QueryRow(
			`SELECT DATABASE(), @@lower_case_table_names, DATABASE() = ?, VERSION()`, dbName,
		).Scan(&currentDB, &lct, &matches, &engineVersion)
		if err != nil {
			s.t.Fatalf("MySQL namespace probe: %v", err)
		}
		if lct < 0 || lct > 2 {
			s.t.Fatalf("MySQL returned invalid lower_case_table_names: %d", lct)
		}
		if !matches {
			s.t.Fatalf("MySQL current database %q does not match bound database %q", currentDB, dbName)
		}
		defaultSchemas, lowerCase = []string{currentDB}, &lct
	case EnginePostgres:
		if err := target.QueryRow(`SELECT version()`).Scan(&engineVersion); err != nil {
			s.t.Fatalf("PostgreSQL version probe: %v", err)
		}
		rows, err := target.Query(`SELECT unnest(current_schemas(true))`)
		if err != nil {
			s.t.Fatalf("PostgreSQL search_path probe: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var schema string
			if err := rows.Scan(&schema); err != nil {
				s.t.Fatalf("PostgreSQL search_path probe: %v", err)
			}
			defaultSchemas = append(defaultSchemas, schema)
		}
		if err := rows.Err(); err != nil {
			s.t.Fatalf("PostgreSQL search_path probe: %v", err)
		}
	default:
		s.t.Fatalf("unknown engine %q", engine)
	}

	// The same statement for both engines, and the same ORDER BY, as the Kotlin's columnSql.
	rows, err := target.Query(
		`SELECT table_schema, table_name, column_name, data_type, ordinal_position, is_nullable
		   FROM information_schema.columns
		  ORDER BY table_schema, table_name, ordinal_position`)
	if err != nil {
		s.t.Fatalf("introspect target columns: %v", err)
	}
	defer rows.Close()

	var cols []CatalogColumn
	for rows.Next() {
		var c CatalogColumn
		var nullable string
		if err := rows.Scan(&c.Schema, &c.Table, &c.Column, &c.DataType, &c.Ordinal, &nullable); err != nil {
			s.t.Fatalf("introspect target columns: %v", err)
		}
		c.Nullable = nullable == "YES"
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		s.t.Fatalf("introspect target columns: %v", err)
	}

	// ⚠️ The scan is NOT narrowed to the datasource's own schemas, and that is deliberate: the Kotlin's
	// pushTestCatalog stores every row information_schema.columns returns, which on PostgreSQL means
	// pg_catalog and information_schema itself — a few thousand columns. Filtering here would be
	// tidier and would be a behaviour change: the system-classification path (A13) is precisely about
	// what happens when a query touches a system catalog, and a fixture that omits those rows makes
	// the test that covers it vacuous while still passing.
	s.CatalogColumns(datasourceID, cols...)
	s.Namespace(datasourceID, defaultSchemas, lowerCase, engineVersion)
}

// SQLTypeFor maps a raw engine `data_type` to the SQL type name the sqlglot schema understands.
//
// ⚠️ TODO(A5): this is a copy of Datasources.kt:138-147, read this session. It lives here only because
// A5 is not ported; DELETE it and call the production function the moment DatasourceStore lands. Two
// copies of a type mapping is exactly the divergence a fixture must not introduce — a catalog seeded
// with a different sql_type than production writes makes every lineage assertion vacuous.
func SQLTypeFor(dataType string) string {
	switch strings.ToLower(strings.TrimSpace(dataType)) {
	case "integer", "int", "int4", "smallint", "int2", "serial", "tinyint", "mediumint":
		return "INTEGER"
	case "bigint", "int8", "bigserial":
		return "BIGINT"
	case "numeric", "decimal", "real", "double precision", "double", "float", "float4", "float8", "money":
		return "DECIMAL"
	case "boolean", "bool":
		return "BOOLEAN"
	case "date", "year":
		return "DATE"
	case "timestamp", "timestamp without time zone", "timestamp with time zone", "timestamptz", "datetime":
		return "TIMESTAMP"
	case "time", "time without time zone", "time with time zone":
		return "TIME"
	default:
		return "VARCHAR" // varchar, text, char, uuid, json, jsonb, bytea, blob, enum, set, ...
	}
}

// mustJSON renders a string slice as a JSON array. A nil slice marshals to `null`, which the
// `jsonb_typeof(tags) = 'array'` CHECK constraints reject (V2__catalog.sql), so nil is normalized to
// `[]` — the same value the column's own DEFAULT carries.
func mustJSON(t testing.TB, v []string) string {
	t.Helper()
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fixture JSON: %v", err)
	}
	return string(b)
}
