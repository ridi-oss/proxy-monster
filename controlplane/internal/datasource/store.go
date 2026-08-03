package datasource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// ---- DatasourceStore (05-datasources-catalog.md §4) ------------------------------------------
//
// A5 owns what a datasource is and what its schema looks like. The headline design constraint,
// restated in four separate source comments and load-bearing for the whole area: THE CONTROL PLANE
// NEVER DIALS A TARGET DATABASE. It holds no target credential, so host/port/db_name are advisory
// display fields, "test connection" is a liveness report rather than a dial, and every byte of schema
// knowledge arrives because a proxy pushed it.

// ReservedTagPrefix is the `system:` tag namespace, owned by the shipped classification manifests —
// user column tags may not use it.
//
// 🔒 This is the WRITE side of A2 INV-A2-7's type-scoping; A2 enforces the read side at
// Cedar-marshalling time. BOTH are required.
const ReservedTagPrefix = "system:"

// datasourceProjection is the ONE shared 15-column projection every read maps through.
//
// ⚠️ INV-A5-10's contradiction is reproduced here: advertise_cert_chain IS in this projection (the
// DTO carries it and Datasources.kt:59-63 argues for that), while WireCertChain's own kdoc says the
// chain is read separately "so a certificate body never rides along in the datasource poll every
// client makes". The two comments contradict each other; the BEHAVIOUR ported is "the chain rides on
// the list", which makes WireCertChain a redundant query — kept redundant. §10 Q5.
const datasourceProjection = `SELECT id, name, engine, host, port, db_name, tags, default_schemas,
	mysql_lower_case_table_names, catalog_synced_at, last_seen_at, engine_version, advertise_addr,
	advertise_cert_chain, advertise_wire_tls FROM datasource`

// DatasourceStore is the `datasource` / `catalog_column` / `column_classification` store.
//
// TODO(A1): ControlPlaneCore holds ONE of these, shared by the HTTP and gRPC surfaces (INV-A1-1).
type DatasourceStore struct{ db *store.Db }

// NewDatasourceStore builds the store over the migrated control-plane handle.
func NewDatasourceStore(db *store.Db) *DatasourceStore { return &DatasourceStore{db: db} }

// scanDatasource is the single private ResultSet.toDatasource() every read maps through.
func scanDatasource(row pgx.Row) (Datasource, error) {
	var (
		ds             Datasource
		engineRaw      string
		tagsRaw        []byte
		defaultRaw     []byte
		lowerCase      *int32
		catalogSynced  *time.Time
		lastSeen       *time.Time
		engineVersion  *string
		advertiseAddr  *string
		advertiseChain *string
	)
	err := row.Scan(
		&ds.ID, &ds.Name, &engineRaw, &ds.Host, &ds.Port, &ds.DBName, &tagsRaw, &defaultRaw,
		&lowerCase, &catalogSynced, &lastSeen, &engineVersion, &advertiseAddr, &advertiseChain,
		&ds.AdvertiseWireTls,
	)
	if err != nil {
		return Datasource{}, err
	}
	// engineFromWire, not a lenient parse: a stored non-canonical engine is a hard error here exactly
	// as it is in the Kotlin (INV-A5-7).
	engine, err := EngineFromWire(engineRaw)
	if err != nil {
		return Datasource{}, err
	}
	ds.Engine = engine
	if err := json.Unmarshal(tagsRaw, &ds.Tags); err != nil {
		return Datasource{}, fmt.Errorf("datasource %d tags: %w", ds.ID, err)
	}
	if err := json.Unmarshal(defaultRaw, &ds.DefaultSchemas); err != nil {
		return Datasource{}, fmt.Errorf("datasource %d default_schemas: %w", ds.ID, err)
	}
	ds.MysqlLowerCaseTableNames = lowerCase
	if catalogSynced != nil {
		s := javaInstantString(*catalogSynced)
		ds.CatalogSyncedAt = &s
	}
	if lastSeen != nil {
		s := javaInstantString(*lastSeen)
		ds.LastSeenAt = &s
	}
	ds.EngineVersion = engineVersion
	ds.AdvertiseAddr = advertiseAddr
	ds.AdvertiseCertChain = advertiseChain
	return ds, nil
}

// List returns every datasource, ORDER BY id.
func (s *DatasourceStore) List(ctx context.Context) ([]Datasource, error) {
	rows, err := s.db.Pool.Query(ctx, datasourceProjection+" ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Datasource{}
	for rows.Next() {
		ds, err := scanDatasource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ds)
	}
	return out, rows.Err()
}

// Get returns the datasource with id, ok=false when absent.
func (s *DatasourceStore) Get(ctx context.Context, id int64) (Datasource, bool, error) {
	return s.GetOn(ctx, s.db.Pool, id)
}

// GetOn is Get composed into a caller's transaction (Kotlin's `get(id, c)` overload).
func (s *DatasourceStore) GetOn(ctx context.Context, c store.Queryer, id int64) (Datasource, bool, error) {
	ds, err := scanDatasource(c.QueryRow(ctx, datasourceProjection+" WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Datasource{}, false, nil
	}
	if err != nil {
		return Datasource{}, false, err
	}
	return ds, true, nil
}

// GetByName looks a datasource up by its stable name — the wire identity the proxy presents over
// gRPC (the proxy sends datasource_name, NEVER a numeric id). `name` is UNIQUE, so this returns at
// most one row.
func (s *DatasourceStore) GetByName(ctx context.Context, name string) (Datasource, bool, error) {
	return s.GetByNameOn(ctx, s.db.Pool, name)
}

// GetByNameOn is GetByName composed into a caller's transaction.
func (s *DatasourceStore) GetByNameOn(ctx context.Context, c store.Queryer, name string) (Datasource, bool, error) {
	ds, err := scanDatasource(c.QueryRow(ctx, datasourceProjection+" WHERE name = $1", name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Datasource{}, false, nil
	}
	if err != nil {
		return Datasource{}, false, err
	}
	return ds, true, nil
}

// Register is the gRPC Register upsert-by-name. The proxy is the source of truth for its own
// identity, so a brand-new name self-creates a row. No target credential is ever stored.
//
// advertiseCertChain: nil = "no opinion, keep the stored chain" (a transient cert read on the proxy);
// a PRESENT blank clears it, so an operator who stops publishing does not strand clients on roots the
// proxy dropped.
//
// 🔒 INV-A5-11 — the engine guard is the WHERE clause, not the pre-read. "If a row for this name raced
// in after the prior read, `WHERE datasource.engine = EXCLUDED.engine` refuses to flip its engine: the
// update touches 0 rows and RETURNING is empty. That is the only way upsertedId comes back null (a
// fresh insert and a same-engine update both RETURN the id), so it unambiguously means 'engine
// conflict'." Moving the guard to application code reintroduces the TOCTOU the advisory lock
// explicitly does not cover.
//
// 🔒 INV-A5-12 — a db_name retarget invalidates the catalog ATOMICALLY, decided from OLD vs NEW inside
// the UPDATE. catalog() builds the analyzer catalog name from db_name, so leaving it would authorize
// the new target against the wrong schema — a fail-OPEN. A host/port-only move DELIBERATELY keeps it.
//
// 🔒 INV-A5-13 — advertise_wire_tls = false CLEARS the chain; a blank chain PRESERVES it.
//
// INV-A5-14 — an EMPTY tags list PRESERVES admin-set tags rather than clobbering them.
func (s *DatasourceStore) Register(
	ctx context.Context,
	name string, engine Engine, host string, port int32, dbName string, tags []string,
	advertiseAddr string, advertiseCertChain *string, advertiseWireTls bool,
) (Datasource, error) {
	wire, err := WireName(engine)
	if err != nil {
		return Datasource{}, err
	}
	if tags == nil {
		tags = []string{}
	}
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return Datasource{}, err
	}
	// Blank → NULL so the COALESCE upsert preserves any previously-advertised address rather than
	// wiping it (e.g. a bare admin pre-provision that carries no reachable address).
	var addrParam *string
	if strings.TrimSpace(advertiseAddr) != "" {
		addrParam = &advertiseAddr
	}

	err = store.InTxDo(ctx, s.db.Pool, func(ctx context.Context, tx pgx.Tx) error {
		// Serialize registrations for this NAME so two concurrent registers of the same name do not
		// pile up on the `name` UNIQUE index. This is ONLY a serialization nicety: it does NOT carry
		// the engine-immutability guarantee, because the admin create/update (rename) surfaces do NOT
		// take this lock. store.AdvisoryLockPrincipal issues exactly
		// `SELECT pg_advisory_xact_lock(hashtext($1))`, which is the same statement the Kotlin runs —
		// reused rather than duplicated so a rolling cutover still serializes against a live Kotlin.
		if err := store.AdvisoryLockPrincipal(ctx, tx, "datasource:register:"+name); err != nil {
			return err
		}
		// Lock the row (if it exists) so a concurrent register/push cannot interleave with the
		// identity-change → catalog-invalidate below, and capture the PRIOR load-bearing identity.
		var priorEngine, priorDBName string
		hasPrior := true
		err := tx.QueryRow(ctx,
			"SELECT id, engine, db_name FROM datasource WHERE name = $1 FOR UPDATE", name,
		).Scan(new(int64), &priorEngine, &priorDBName)
		if errors.Is(err, pgx.ErrNoRows) {
			hasPrior = false
		} else if err != nil {
			return err
		}
		// Fast path: reject a mismatched re-register up front with a precise message (nothing is
		// written yet). The atomic WHERE guard below is the race-proof backstop.
		if hasPrior && priorEngine != wire {
			return &EngineConflictError{Name: name, ExistingEngine: priorEngine, RequestedEngine: wire}
		}

		var upsertedID int64
		var catalogCleared bool
		err = tx.QueryRow(ctx, `INSERT INTO datasource (name, engine, host, port, db_name, tags, advertise_addr, advertise_cert_chain, advertise_wire_tls)
			VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
			ON CONFLICT (name) DO UPDATE SET
				engine  = EXCLUDED.engine,
				host    = EXCLUDED.host,
				port    = EXCLUDED.port,
				db_name = EXCLUDED.db_name,
				tags    = CASE WHEN EXCLUDED.tags = '[]'::jsonb THEN datasource.tags ELSE EXCLUDED.tags END,
				advertise_addr = COALESCE(EXCLUDED.advertise_addr, datasource.advertise_addr),
				-- Blank preserves the prior chain (a transient cert read sends none), EXCEPT when the
				-- proxy reports TLS is off: that is an intentional clear, and keeping a stale chain
				-- would have clients verify a rotated or absent cert against dead roots.
				advertise_cert_chain = CASE
					WHEN NOT EXCLUDED.advertise_wire_tls THEN NULL
					WHEN EXCLUDED.advertise_cert_chain IS NULL THEN datasource.advertise_cert_chain
					ELSE NULLIF(EXCLUDED.advertise_cert_chain, '')
				END,
				-- Authoritative every register, so TLS-on -> TLS-off is observable rather than sticky.
				advertise_wire_tls = EXCLUDED.advertise_wire_tls,
				catalog_synced_at = CASE WHEN datasource.db_name IS DISTINCT FROM EXCLUDED.db_name THEN NULL ELSE datasource.catalog_synced_at END,
				default_schemas   = CASE WHEN datasource.db_name IS DISTINCT FROM EXCLUDED.db_name THEN '[]'::jsonb ELSE datasource.default_schemas END,
				mysql_lower_case_table_names = CASE WHEN datasource.db_name IS DISTINCT FROM EXCLUDED.db_name THEN NULL ELSE datasource.mysql_lower_case_table_names END
			WHERE datasource.engine = EXCLUDED.engine
			RETURNING id, (catalog_synced_at IS NULL) AS catalog_cleared`,
			name, wire, host, port, dbName, string(tagsJSON), addrParam,
			// Distinct from advertiseAddr above: this is a NULLABLE parameter carrying PRESENCE, so an
			// ABSENT chain (nil) preserves the stored one while a PRESENT blank overwrites it. Do not
			// collapse blank to nil here — that would make "stop publishing" unexpressible.
			advertiseCertChain, advertiseWireTls,
		).Scan(&upsertedID, &catalogCleared)
		if errors.Is(err, pgx.ErrNoRows) {
			// The conflict arm's engine guard refused the flip: a row under this name exists with a
			// DIFFERENT engine (it raced in after the prior read saw none). Nothing was written;
			// re-read the now-committed engine for a precise message and reject fail-closed.
			existing := wire
			if scanErr := tx.QueryRow(ctx, "SELECT engine FROM datasource WHERE name = $1", name).Scan(&existing); scanErr != nil {
				existing = wire
			}
			return &EngineConflictError{Name: name, ExistingEngine: existing, RequestedEngine: wire}
		}
		if err != nil {
			return err
		}
		// The upsert already cleared the datasource-row catalog stamp atomically iff db_name changed.
		// Now drop the orphaned catalog_column rows for exactly that case. catalogCleared reflects the
		// ATOMIC old→new transition, not the pre-read, so it is race-free.
		//
		// Minor, and deliberately kept: catalogCleared is `catalog_synced_at IS NULL` AFTER the upsert,
		// so it is also true for a fresh insert and for an existing row that was simply never synced.
		// The DELETE is idempotent, which is what makes that harmless — KEEP IT IDEMPOTENT.
		if catalogCleared {
			if _, err := tx.Exec(ctx, "DELETE FROM catalog_column WHERE datasource_id = $1", upsertedID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Datasource{}, err
	}
	// Kotlin's `return getByName(name)!!` — a fresh read on a NEW connection after the commit.
	ds, ok, err := s.GetByName(ctx, name)
	if err != nil {
		return Datasource{}, err
	}
	if !ok {
		return Datasource{}, fmt.Errorf("datasource %q disappeared immediately after register", name)
	}
	return ds, nil
}

// MarkSeen stamps last_seen_at = now() — called when a proxy's Events stream opens (liveness).
func (s *DatasourceStore) MarkSeen(ctx context.Context, id int64) error {
	_, err := s.db.Pool.Exec(ctx, "UPDATE datasource SET last_seen_at = now() WHERE id = $1", id)
	return err
}

// PushedColumn is a column the proxy introspected and pushed over gRPC PushCatalog.
type PushedColumn struct {
	Schema   string
	Table    string
	Column   string
	DataType string
	Ordinal  int32
	Nullable bool
}

// StorePushedCatalog replaces datasource id's catalog with the columns the PROXY introspected and
// pushed — the control plane never connects to the target itself. Returns the number of columns.
//
// 🔒 INV-A5-15 — the row lock serializes concurrent pushes; without it the UNIQUE trips. "Lock the
// datasource row so concurrent pushes (multiple proxy replicas fronting one name) serialize instead
// of interleaving their DELETE/INSERT — otherwise the second push's insert races the first's delete
// and trips the (datasource, schema, table, column) UNIQUE. Also doubles as the
// disappeared-datasource check."
//
// INV-A5-16 — REPLACE, NEVER MERGE. Delete-then-insert in one transaction is what makes a dropped
// table disappear from the catalog. Upserts would leave removed columns behind forever, and a
// dropped-then-recreated table would keep stale classifications resolving.
func (s *DatasourceStore) StorePushedCatalog(
	ctx context.Context, id int64, defaultSchemas []string, mysqlLowerCaseTableNames *int32,
	engineVersion string, columns []PushedColumn,
) (int, error) {
	if defaultSchemas == nil {
		defaultSchemas = []string{}
	}
	schemasJSON, err := json.Marshal(defaultSchemas)
	if err != nil {
		return 0, err
	}
	var versionParam *string
	if strings.TrimSpace(engineVersion) != "" {
		versionParam = &engineVersion
	}

	err = store.InTxDo(ctx, s.db.Pool, func(ctx context.Context, tx pgx.Tx) error {
		var locked int64
		if err := tx.QueryRow(ctx, "SELECT id FROM datasource WHERE id = $1 FOR UPDATE", id).Scan(&locked); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("datasource %d disappeared before catalog push", id)
			}
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM catalog_column WHERE datasource_id = $1", id); err != nil {
			return err
		}
		if len(columns) > 0 {
			// pgx.Batch is JDBC's addBatch/executeBatch: ONE round trip for N inserts. A per-row Exec
			// loop would be slower than the Kotlin, which the port policy does not license either.
			batch := &pgx.Batch{}
			for _, col := range columns {
				batch.Queue(`INSERT INTO catalog_column
					(datasource_id, schema_name, table_name, column_name, data_type, sql_type, ordinal, nullable)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
					id, col.Schema, col.Table, col.Column, col.DataType, SQLTypeFor(col.DataType),
					col.Ordinal, col.Nullable)
			}
			results := tx.SendBatch(ctx, batch)
			for range columns {
				if _, err := results.Exec(); err != nil {
					results.Close()
					return err
				}
			}
			if err := results.Close(); err != nil {
				return err
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE datasource
			SET default_schemas = $1::jsonb, mysql_lower_case_table_names = $2, engine_version = $3,
				catalog_synced_at = now()
			WHERE id = $4`, string(schemasJSON), mysqlLowerCaseTableNames, versionParam, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("datasource %d disappeared during catalog push", id)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(columns), nil
}

// Create inserts an admin-provisioned row.
//
// ⚠️ There is NO engine validation here — THE ROUTE validates (EngineFromWireOrNull) before calling.
// A caller other than the route loses that, exactly as in the Kotlin.
//
// ⚠️ REPRODUCED DEFECT (§10 Q12): there is no uniqueness pre-check, so a duplicate `name` surfaces as
// the raw `datasource_name_key` UNIQUE violation. In the Kotlin it reaches App.kt:452's
// `exception<Throwable>` and answers 500 common.fallback rather than a 409 the console can localize.
// TODO(A1): the route must keep that shape, or Q12 must be decided deliberately — not silently.
func (s *DatasourceStore) Create(ctx context.Context, input DatasourceInput) (Datasource, error) {
	var id int64
	err := s.db.Pool.QueryRow(ctx,
		`INSERT INTO datasource (name, engine, host, port, db_name) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		input.Name, input.Engine, input.Host, input.Port, input.DBName,
	).Scan(&id)
	if err != nil {
		return Datasource{}, err
	}
	ds, ok, err := s.Get(ctx, id)
	if err != nil {
		return Datasource{}, err
	}
	if !ok {
		return Datasource{}, fmt.Errorf("datasource %d disappeared immediately after create", id)
	}
	return ds, nil
}

// invalidateCatalog drops id's stored catalog and clears its sync stamps so decisions fail closed
// until a fresh PushCatalog lands. Shared by Register's db_name retarget (inline, not via this
// helper — same as the Kotlin) and Update's admin db_name change.
func invalidateCatalog(ctx context.Context, tx pgx.Tx, id int64) error {
	if _, err := tx.Exec(ctx, "DELETE FROM catalog_column WHERE datasource_id = $1", id); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		"UPDATE datasource SET catalog_synced_at = NULL, default_schemas = '[]'::jsonb, mysql_lower_case_table_names = NULL WHERE id = $1",
		id)
	return err
}

// Update is the admin edit of a datasource's advisory fields (name/host/port/db_name).
//
// ENGINE IS IMMUTABLE: a PUT that changes engine is rejected with [EngineConflictError] — the SAME
// fail-closed invariant the proxy Register path enforces. The admin update surface is not a bypass:
// the web edit form seeds engine from the current value, so a normal edit carries the unchanged
// engine and never trips this. TODO(A1): the route's EngineFromWireOrNull canonicalization exists for
// exactly this — otherwise a PUT carrying "Postgres", "postgresql" or the DatasourceInput default
// "postgres" would be compared verbatim against the stored canonical engine and spuriously trip it.
//
// ⚠️ Minor inconsistency REPRODUCED: the error is constructed with input.Name (the NEW name), while
// Register uses the stored name. The 409 body carries no name, so this only affects logs.
//
// 🔴 F21 — REPRODUCED GAP. This clears the PERSISTED catalog on a db_name change and never touches the
// in-memory ConnectionCatalogRegistry, not even on a RENAME, which frees a name whose authoritative
// entries stay live. Only gRPC Register calls InvalidateDatasource, and only under
// `priorDbName != null && priorDbName != ds.dbName`. See ConnectionCatalogRegistry.InvalidateDatasource
// for the full mechanism. Wiring it in here would hide a possible live defect; §10 Q1 is open.
func (s *DatasourceStore) Update(ctx context.Context, id int64, input DatasourceInput) (Datasource, bool, error) {
	existed, err := store.InTx(ctx, s.db.Pool, func(ctx context.Context, tx pgx.Tx) (bool, error) {
		var priorEngine, priorDBName string
		err := tx.QueryRow(ctx, "SELECT engine, db_name FROM datasource WHERE id = $1 FOR UPDATE", id).
			Scan(&priorEngine, &priorDBName)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if priorEngine != input.Engine {
			return false, &EngineConflictError{
				Name: input.Name, ExistingEngine: priorEngine, RequestedEngine: input.Engine,
			}
		}
		if _, err := tx.Exec(ctx,
			"UPDATE datasource SET name=$1, engine=$2, host=$3, port=$4, db_name=$5 WHERE id=$6",
			input.Name, input.Engine, input.Host, input.Port, input.DBName, id,
		); err != nil {
			return false, err
		}
		if priorDBName != input.DBName {
			if err := invalidateCatalog(ctx, tx, id); err != nil {
				return false, err
			}
		}
		return true, nil
	})
	if err != nil {
		return Datasource{}, false, err
	}
	if !existed {
		return Datasource{}, false, nil
	}
	return s.Get(ctx, id)
}

// Delete removes a datasource. catalog_column and column_classification CASCADE (V2).
//
// 🔴 F21 — same reproduced gap as [DatasourceStore.Update]: this frees the datasource NAME while its
// in-memory authoritative entries and pooled fragments stay live.
func (s *DatasourceStore) Delete(ctx context.Context, id int64) (bool, error) {
	tag, err := s.db.Pool.Exec(ctx, "DELETE FROM datasource WHERE id = $1", id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// Test is a CREDS-FREE LIVENESS REPORT, not a dial: the control plane does not dial the target, so
// "test" reports whether a proxy is currently attached (an open Events stream for this datasource)
// plus the catalog/last-seen state. proxyAttached is resolved by the caller from ProxyEventsHub.
//
// ⚠️ The message is English prose on the wire — see [TestResult] for the reproduced l10n gap.
func (s *DatasourceStore) Test(ds Datasource, proxyAttached bool) TestResult {
	catalogState := "catalog not synced"
	if ds.CatalogSyncedAt != nil {
		catalogState = "catalog synced " + *ds.CatalogSyncedAt
	}
	seenState := "never seen"
	if ds.LastSeenAt != nil {
		seenState = "last seen " + *ds.LastSeenAt
	}
	if proxyAttached {
		return TestResult{OK: true, Message: "proxy attached; " + catalogState + "; " + seenState}
	}
	return TestResult{OK: false, Message: "no proxy attached; " + catalogState + "; " + seenState}
}

// Catalog is the persisted config catalog for one datasource, with each column's classification
// overlaid.
//
// 🔒 INV-A5-17 — `ORDER BY … ordinal` is a MASKING GUARANTEE, not cosmetics. Column order is what
// fixes mask ordinals for the proxy's inline result rewriting. ConnectionCatalogRegistry.StructuralRows
// re-sorts for the same reason (INV-A5-40).
//
// The `catalog` segment is COMPUTED IN SQL, not stored, and the lower() is part of the rule.
func (s *DatasourceStore) Catalog(ctx context.Context, id int64) ([]CatalogColumn, error) {
	return s.CatalogOn(ctx, s.db.Pool, id)
}

// CatalogOn is Catalog composed into a caller's transaction.
func (s *DatasourceStore) CatalogOn(ctx context.Context, c store.Queryer, id int64) ([]CatalogColumn, error) {
	rows, err := c.Query(ctx, `SELECT CASE WHEN lower(d.engine) = 'mysql' THEN 'def' ELSE d.db_name END AS catalog_name,
			   c.schema_name, c.table_name, c.column_name, c.data_type, c.sql_type, c.ordinal, c.nullable,
			   cl.tags, cl.mask_fn_id, m.name AS mask_fn_name
		FROM catalog_column c
		JOIN datasource d ON d.id = c.datasource_id
		LEFT JOIN column_classification cl
		  ON cl.datasource_id = c.datasource_id AND cl.schema_name = c.schema_name
		 AND cl.table_name = c.table_name AND cl.column_name = c.column_name
		LEFT JOIN mask_fn m ON m.id = cl.mask_fn_id
		WHERE c.datasource_id = $1
		ORDER BY c.schema_name, c.table_name, c.ordinal`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []CatalogColumn{}
	for rows.Next() {
		var (
			col        CatalogColumn
			tagsRaw    []byte
			maskFnID   *int64
			maskFnName *string
		)
		if err := rows.Scan(
			&col.Catalog, &col.Schema, &col.Table, &col.Column, &col.DataType, &col.SQLType,
			&col.Ordinal, &col.Nullable, &tagsRaw, &maskFnID, &maskFnName,
		); err != nil {
			return nil, err
		}
		// classification is non-null IFF cl.tags is non-null (i.e. a column_classification row
		// exists) — a column with a row but EMPTY tags still gets a Classification with tags = [].
		if tagsRaw != nil {
			var tags []string
			if err := json.Unmarshal(tagsRaw, &tags); err != nil {
				return nil, err
			}
			col.Classification = &Classification{
				Schema: col.Schema, Table: col.Table, Column: col.Column,
				Tags: tags, MaskFnID: maskFnID, MaskFnName: maskFnName,
			}
		}
		// 🔒 INV-A5-1: IsTemp is left false. A5 never sets it.
		out = append(out, col)
	}
	return out, rows.Err()
}

// WireCertChain is the stored certificate chain for one datasource.
//
// ⚠️ Kept even though the same bytes ride on the list/get projection — see INV-A5-10's contradiction
// on [datasourceProjection]. The redundancy is the ported behaviour.
func (s *DatasourceStore) WireCertChain(ctx context.Context, id int64) (*string, error) {
	var chain *string
	err := s.db.Pool.QueryRow(ctx, "SELECT advertise_cert_chain FROM datasource WHERE id = $1", id).Scan(&chain)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return chain, nil
}

// ColumnKey is the (schema, table, column) triple ClassificationsFor is keyed by — Kotlin's
// `Triple<String, String, String>`.
type ColumnKey struct {
	Schema string
	Table  string
	Column string
}

// ClassificationsFor is live classification metadata keyed INDEPENDENTLY of catalog_column.
//
// 🔒 INV-A5-18 — structure and classification are independently sourced. Structure comes from the
// connection's fragment; classification from Postgres. A newly-tagged PII column therefore takes
// effect on the NEXT STATEMENT, with no proxy round-trip. Joining them (as Catalog does) on the
// enforcement path would make a classification change wait for a catalog push.
func (s *DatasourceStore) ClassificationsFor(ctx context.Context, id int64) (map[ColumnKey]Classification, error) {
	rows, err := s.db.Pool.Query(ctx, `SELECT cl.schema_name, cl.table_name, cl.column_name, cl.tags,
			   cl.mask_fn_id, m.name AS mask_fn_name
		FROM column_classification cl
		LEFT JOIN mask_fn m ON m.id = cl.mask_fn_id
		WHERE cl.datasource_id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[ColumnKey]Classification{}
	for rows.Next() {
		var (
			key        ColumnKey
			tagsRaw    []byte
			maskFnID   *int64
			maskFnName *string
		)
		if err := rows.Scan(&key.Schema, &key.Table, &key.Column, &tagsRaw, &maskFnID, &maskFnName); err != nil {
			return nil, err
		}
		var tags []string
		if err := json.Unmarshal(tagsRaw, &tags); err != nil {
			return nil, err
		}
		out[key] = Classification{
			Schema: key.Schema, Table: key.Table, Column: key.Column,
			Tags: tags, MaskFnID: maskFnID, MaskFnName: maskFnName,
		}
	}
	return out, rows.Err()
}

// DefaultSchema is the first NON-SYSTEM entry of the ordered default-schema list. ok=false when the
// list is empty (never introspected) or ALL-SYSTEM.
func (s *DatasourceStore) DefaultSchema(ctx context.Context, id int64) (string, bool, error) {
	return s.DefaultSchemaOn(ctx, s.db.Pool, id)
}

// DefaultSchemaOn is DefaultSchema composed into a caller's transaction.
func (s *DatasourceStore) DefaultSchemaOn(ctx context.Context, c store.Queryer, id int64) (string, bool, error) {
	ds, ok, err := s.GetOn(ctx, c, id)
	if err != nil || !ok {
		return "", false, err
	}
	for _, schema := range ds.DefaultSchemas {
		if !MustIsSystemSchema(ds.Engine, schema) {
			return schema, true, nil
		}
	}
	return "", false, nil
}

// ErrReservedTag is the store-layer reserved-prefix refusal.
//
// 🔒 INV-A5-19 — the guard exists at BOTH layers, DELIBERATELY. TODO(A11): DatasourceManagementService
// checks it FIRST and raises ManagementException(ApiError("datasource.reserved_tag")); this store copy
// is the backstop for a non-HTTP caller.
//
// ⚠️ REPRODUCED CONSEQUENCE: the store's error is NOT a ManagementException, so it has no
// respondManagementError mapping and would fall through to App.kt:452's `exception<Throwable>` as 500
// common.fallback — losing both the status and the {tag} param. Currently unreachable via HTTP because
// the management layer always checks first. The same fall-through applies to [ErrSchemaRequired],
// whose HTTP-visible counterpart is datasource.schema_required (400).
var ErrReservedTag = errors.New("reserved tag")

// ErrSchemaRequired is the store-layer "no schema and no captured default" refusal. See
// [ErrReservedTag] for the reproduced 500-fall-through consequence.
var ErrSchemaRequired = errors.New("schema is required until datasource introspection captures a default schema")

// UpsertClassification overlays tags (and optionally a mask function) on a catalog column.
func (s *DatasourceStore) UpsertClassification(ctx context.Context, id int64, input ClassificationInput) (Classification, error) {
	return s.UpsertClassificationOn(ctx, s.db.Pool, id, input)
}

// UpsertClassificationOn is UpsertClassification composed into a caller's transaction.
func (s *DatasourceStore) UpsertClassificationOn(
	ctx context.Context, c store.Queryer, id int64, input ClassificationInput,
) (Classification, error) {
	for _, tag := range input.Tags {
		if strings.HasPrefix(tag, ReservedTagPrefix) {
			return Classification{}, fmt.Errorf(
				"%w: tag '%s' is reserved: the '%s' namespace is owned by system classification",
				ErrReservedTag, tag, ReservedTagPrefix)
		}
	}
	var schema string
	if input.Schema != nil {
		schema = *input.Schema
	} else {
		resolved, ok, err := s.DefaultSchemaOn(ctx, c, id)
		if err != nil {
			return Classification{}, err
		}
		if !ok {
			return Classification{}, ErrSchemaRequired
		}
		schema = resolved
	}
	tags := input.Tags
	if tags == nil {
		tags = []string{}
	}
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return Classification{}, err
	}
	if _, err := c.Exec(ctx, `INSERT INTO column_classification
		(datasource_id, schema_name, table_name, column_name, tags, mask_fn_id, updated_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, now())
		ON CONFLICT (datasource_id, schema_name, table_name, column_name)
		DO UPDATE SET tags = EXCLUDED.tags, mask_fn_id = EXCLUDED.mask_fn_id, updated_at = now()`,
		id, schema, input.Table, input.Column, string(tagsJSON), input.MaskFnID,
	); err != nil {
		return Classification{}, err
	}
	name, err := maskFnName(ctx, c, input.MaskFnID)
	if err != nil {
		return Classification{}, err
	}
	return Classification{
		Schema: schema, Table: input.Table, Column: input.Column,
		Tags: input.Tags, MaskFnID: input.MaskFnID, MaskFnName: name,
	}, nil
}

// maskFnName resolves a mask function's name; nil for a nil id OR A MISSING ROW — so a dangling
// maskFnId yields maskFnName = nil rather than an error.
func maskFnName(ctx context.Context, c store.Queryer, id *int64) (*string, error) {
	if id == nil {
		return nil, nil
	}
	var name string
	err := c.QueryRow(ctx, "SELECT name FROM mask_fn WHERE id = $1", *id).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &name, nil
}

// DeleteClassification removes one column classification. It requires an EXPLICIT schema — the
// management layer (A11) resolves the default.
func (s *DatasourceStore) DeleteClassification(ctx context.Context, id int64, schema, table, column string) (bool, error) {
	return s.DeleteClassificationOn(ctx, s.db.Pool, id, schema, table, column)
}

// DeleteClassificationOn is DeleteClassification composed into a caller's transaction.
//
// ⚠️ TODO(A1)/§10 Q13: the route DISCARDS this boolean, so deleting a classification that does not
// exist is 204, NEVER 404. A port that 404s on zero rows changes an idempotent surface into a failing
// one. The information is available here and deliberately dropped at the route.
func (s *DatasourceStore) DeleteClassificationOn(
	ctx context.Context, c store.Queryer, id int64, schema, table, column string,
) (bool, error) {
	tag, err := c.Exec(ctx,
		"DELETE FROM column_classification WHERE datasource_id=$1 AND schema_name=$2 AND table_name=$3 AND column_name=$4",
		id, schema, table, column)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
