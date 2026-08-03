package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.authorizeDatasourceAction
import com.ridi.oss.proxymonster.controlplane.authz.requireAdmin
import com.ridi.oss.proxymonster.controlplane.authz.resolveContextTags
import com.ridi.oss.proxymonster.controlplane.management.DatasourceManagementService
import com.ridi.oss.proxymonster.controlplane.grpc.inspectTrustChain
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.probe.Classification
import com.ridi.oss.proxymonster.probe.TableDetail
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import javax.sql.DataSource

// ---- DTOs — the wire contract for /api/datasources** -------------------------------------

@Serializable
data class Datasource(
    val id: Long,
    val name: String,
    @Serializable(with = EngineWireSerializer::class) val engine: Engine,
    // host/port/db_name are advisory (admin UI / triage): the proxy is authoritative and overwrites them
    // on Register. The control-plane holds NO target credential — it never dials a
    // target (the proxy executes everything), so there is literally zero target secret at rest here.
    val host: String,
    val port: Int,
    val dbName: String,
    val tags: List<String> = emptyList(),
    val defaultSchemas: List<String> = emptyList(),
    val mysqlLowerCaseTableNames: Int? = null,
    val catalogSyncedAt: String? = null,
    // When a proxy was last observed attached (Events stream open). Null = never attached.
    val lastSeenAt: String? = null,
    // The target's live server version, proxy-detected + pushed; drives system-classification's
    // manifest resolution. Null until a catalog is pushed.
    val engineVersion: String? = null,
    // The client-facing host:port a wire client (pmon) dials to reach this datasource's proxy — set by the
    // proxy at Register (distinct from host/port, the advisory upstream). Null until a proxy advertises one.
    val advertiseAddr: String? = null,
    // The PEM certificate chain to trust for this datasource's proxy, leaf first, as the proxy advertised it
    // at registration. pmon uses it as the root pool for its upstream hop, with advertiseAddr checked against
    // it; the browser downloads the same bytes from {id}/wire-cert for psql/mysql/DataGrip. Null when the
    // proxy has no wire TLS. Public material — this is what the proxy already presents to every TLS client —
    // and a few KB on a poll no client makes hot, which is cheaper than a second round trip per datasource.
    val advertiseCertChain: String? = null,
    // Whether this datasource's proxy serves client-facing TLS — a separate fact from the chain above, since a
    // proxy may serve a publicly-trusted certificate and publish nothing. A client reads this to know a
    // plaintext greeting must be refused; false means plaintext.
    val advertiseWireTls: Boolean = false,
)

// Admin create/update payload. This is OPTIONAL pre-provisioning only — a way to seed a row
// (name + advisory connection fields) before its proxy first attaches; the proxy's Register is the
// authoritative path and overwrites host/port/db_name. No credential fields exist: the control-plane never
// dials a target. host/port/dbName default to empty/0 so the form can create a name-only placeholder.
@Serializable
data class DatasourceInput(
    val name: String,
    val engine: String = "postgres",
    val host: String = "",
    val port: Int = 0,
    val dbName: String = "",
)

@Serializable
data class CatalogColumn(
    val catalog: String,
    val schema: String,
    val table: String,
    val column: String,
    val dataType: String,
    val sqlType: String,
    val ordinal: Int,
    val nullable: Boolean,
    val classification: Classification? = null,
    // True for a per-connection session/temp column overlaid onto the base catalog. A temp the
    // user created on their own session connection is theirs to read (it can only hold data they were
    // entitled to — CREATE TEMP AS SELECT is a write, so the write-references-masked deny blocks copying
    // masked/denied source into it), so decideQuery reads it UNMASKED without a Cedar grant. Base catalog
    // columns are always false.
    val isTemp: Boolean = false,
)

@Serializable
data class ClassificationInput(
    val schema: String? = null,
    val table: String,
    val column: String,
    val tags: List<String> = emptyList(),
    val maskFnId: Long? = null,
)

@Serializable
data class ClassificationDelete(val schema: String? = null, val table: String, val column: String)

@Serializable
data class TestResult(val ok: Boolean, val message: String)

/** Result of an admin refresh push: how many attached proxy Events streams were notified. */
@Serializable
data class RefreshResult(val notified: Int)

/**
 * Thrown by [DatasourceStore.register] when a caller tries to re-register an EXISTING [name] under a
 * different [requestedEngine] than its stored [existingEngine] (docs/datasource-registration.md).
 * Engine is immutable at register: silently flipping it would repoint every FK keyed off `datasource_id`
 * (catalog_column, column_classification, query_history, access_request) at a schema from a different
 * dialect, and the analyzer/system-classification manifest resolution keyed off engine would go stale —
 * all fail-open. Thrown BEFORE any write, so the row/catalog are left untouched; the gRPC layer maps this
 * to `FAILED_PRECONDITION`.
 */
class DatasourceEngineConflictException(name: String, existingEngine: String, requestedEngine: String) :
    IllegalStateException(
        "datasource '$name' is registered as $existingEngine; refusing re-register as $requestedEngine — " +
            "engine is immutable at register (delete and re-create to change it)",
    )

/** Map a raw DB type name (Postgres or MySQL `data_type`) to a SQL type name the sqlglot schema understands. */
fun sqlTypeFor(dataType: String): String = when (dataType.lowercase().trim()) {
    "integer", "int", "int4", "smallint", "int2", "serial", "tinyint", "mediumint" -> "INTEGER"
    "bigint", "int8", "bigserial" -> "BIGINT"
    "numeric", "decimal", "real", "double precision", "double", "float", "float4", "float8", "money" -> "DECIMAL"
    "boolean", "bool" -> "BOOLEAN"
    "date", "year" -> "DATE"
    "timestamp", "timestamp without time zone", "timestamp with time zone", "timestamptz", "datetime" -> "TIMESTAMP"
    "time", "time without time zone", "time with time zone" -> "TIME"
    else -> "VARCHAR" // varchar, text, char, uuid, json, jsonb, bytea, blob, enum, set, ...
}

// ---- Store -------------------------------------------------------------------------------

class DatasourceStore(internal val dataSource: DataSource) {
    private val json = Json
    private val stringList = ListSerializer(String.serializer())

    companion object {
        /** The `system:` tag namespace is owned by the shipped classification manifests — user column tags may not use it. */
        const val RESERVED_TAG_PREFIX = "system:"
    }

    fun list(): List<Datasource> = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT id, name, engine, host, port, db_name, tags, default_schemas, mysql_lower_case_table_names, catalog_synced_at, last_seen_at, engine_version, advertise_addr, advertise_cert_chain, advertise_wire_tls FROM datasource ORDER BY id",
        ).use { ps ->
            ps.executeQuery().use { rs ->
                val out = ArrayList<Datasource>()
                while (rs.next()) out += rs.toDatasource()
                out
            }
        }
    }

    fun get(id: Long): Datasource? = dataSource.connection.use { c -> get(id, c) }

    fun get(id: Long, c: java.sql.Connection): Datasource? = c.prepareStatement(
        "SELECT id, name, engine, host, port, db_name, tags, default_schemas, mysql_lower_case_table_names, catalog_synced_at, last_seen_at, engine_version, advertise_addr, advertise_cert_chain, advertise_wire_tls FROM datasource WHERE id = ?",
    ).use { ps ->
        ps.setLong(1, id)
        ps.executeQuery().use { rs -> if (rs.next()) rs.toDatasource() else null }
    }

    /**
     * Look a datasource up by its stable [name] — the wire identity the proxy presents over gRPC
     * (docs/datasource-registration.md: the proxy sends `datasource_name`, never a numeric id). `name`
     * is unique in the schema, so this returns at most one row.
     */
    fun getByName(name: String): Datasource? = dataSource.connection.use { c -> getByName(name, c) }

    fun getByName(name: String, c: java.sql.Connection): Datasource? = c.prepareStatement(
        "SELECT id, name, engine, host, port, db_name, tags, default_schemas, mysql_lower_case_table_names, catalog_synced_at, last_seen_at, engine_version, advertise_addr, advertise_cert_chain, advertise_wire_tls FROM datasource WHERE name = ?",
    ).use { ps ->
        ps.setString(1, name)
        ps.executeQuery().use { rs -> if (rs.next()) rs.toDatasource() else null }
    }

    /**
     * gRPC Register (docs/datasource-registration.md): upsert a datasource by its stable [name].
     * The proxy is the source of truth for its own identity, so a brand-new name self-creates a row.
     * No target credential is ever stored — the control-plane never dials the target.
     * host/port/db_name are advisory (admin UI / triage). [tags] are a free-form bag; the posture ones
     * (`system:development` / `system:production`) drive the preset policies, everything else is inert;
     * an EMPTY list PRESERVES any admin-set tags on an existing row rather than clobbering them (a fresh
     * row defaults to '[]'). Idempotent: a restart / redeploy / scaled replica re-registering converges.
     * ENGINE IS IMMUTABLE: re-registering an existing [name] with a different [engine] than its
     * stored value throws [DatasourceEngineConflictException] instead of upserting — see that class's
     * kdoc for why. host/port/db_name stay mutable.
     */
    fun register(
        name: String,
        engine: Engine,
        host: String,
        port: Int,
        dbName: String,
        tags: List<String>,
        advertiseAddr: String,
        // NULL = "no opinion, keep the stored chain" (a transient cert read on the proxy); a PRESENT blank
        // clears it, so an operator who stops publishing does not strand clients on roots the proxy dropped.
        advertiseCertChain: String?,
        advertiseWireTls: Boolean,
    ): Datasource {
        dataSource.connection.use { c ->
            c.autoCommit = false
            try {
                // Serialize registrations for this NAME to keep two concurrent registers of the same name from
                // piling up on the `name` UNIQUE index (the same tx-advisory-lock idiom Deprovision.kt uses
                // per-principal, released at commit/rollback). This is ONLY a serialization nicety: it does NOT
                // carry the engine-immutability guarantee, because the admin `create`/`update` (rename) surfaces do NOT take this
                // lock. The fail-closed engine guard is the `WHERE datasource.engine = EXCLUDED.engine` clause on
                // the upsert below — enforced atomically at row-conflict time, so a row that races into this name
                // (via create/rename) after the prior read can never have its engine silently flipped.
                c.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))").use { ps ->
                    ps.setString(1, "datasource:register:$name")
                    ps.executeQuery().use { it.next() }
                }
                // Lock the row (if it exists) so a concurrent register/push can't interleave with the
                // identity-change → catalog-invalidate below, and capture the PRIOR load-bearing identity.
                data class Prior(val id: Long, val engine: String, val dbName: String)
                val prior = c.prepareStatement(
                    "SELECT id, engine, db_name FROM datasource WHERE name = ? FOR UPDATE",
                ).use { ps ->
                    ps.setString(1, name)
                    ps.executeQuery().use { rs ->
                        if (rs.next()) Prior(rs.getLong(1), rs.getString(2), rs.getString(3)) else null
                    }
                }
                // Fast path: engine is immutable at register — reject a mismatched re-register up front with
                // a precise message (nothing is written yet). The atomic WHERE guard on the upsert below is the
                // race-proof backstop for the case where `prior` read null but a row races into this name (via
                // create/rename) before the upsert lands.
                if (prior != null && prior.engine != engine.wireName) {
                    throw DatasourceEngineConflictException(name, prior.engine, engine.wireName)
                }
                // Atomic upsert with the fail-closed engine guard IN the conflict arm. If a row for this name
                // raced in after the prior read, `WHERE datasource.engine = EXCLUDED.engine` refuses to flip its
                // engine: the update touches 0 rows and RETURNING is empty. That is the only way `upsertedId`
                // comes back null (a fresh insert and a same-engine update both RETURN the id), so it
                // unambiguously means "engine conflict" and we reject fail-closed below.
                // The db_name-retarget catalog invalidation is folded INTO the conflict arm: comparing the OLD
                // row (`datasource.db_name`) to the NEW (`EXCLUDED.db_name`) inside the atomic UPDATE removes the
                // TOCTOU of deciding from the pre-read `prior` — correct regardless of the advisory lock's
                // coverage (an admin create/rename that doesn't take it can't interleave a stale decision). The
                // datasource-row catalog fields clear here; the RETURNING flag drives the orphaned catalog_column
                // delete below (delete can't live in the INSERT). A fresh insert leaves catalog_synced_at NULL.
                val (upsertedId, catalogCleared) = c.prepareStatement(
                    """INSERT INTO datasource (name, engine, host, port, db_name, tags, advertise_addr, advertise_cert_chain, advertise_wire_tls)
                       VALUES (?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?)
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
                       RETURNING id, (catalog_synced_at IS NULL) AS catalog_cleared""",
                ).use { ps ->
                    ps.setString(1, name)
                    ps.setString(2, engine.wireName)
                    ps.setString(3, host)
                    ps.setInt(4, port)
                    ps.setString(5, dbName)
                    ps.setString(6, json.encodeToString(stringList, tags))
                    // Blank → NULL so the COALESCE upsert preserves any previously-advertised address rather
                    // than wiping it (e.g. a bare admin pre-provision that carries no reachable address).
                    ps.setString(7, advertiseAddr.ifBlank { null })
                    // Distinct from advertiseAddr above: this is a NULLABLE parameter carrying presence, so an
                    // ABSENT chain (null) preserves the stored one via COALESCE, while a PRESENT blank becomes
                    // the empty string and overwrites it. Do not collapse blank to null here — that would make
                    // "stop publishing" unexpressible.
                    ps.setString(8, advertiseCertChain)
                    ps.setBoolean(9, advertiseWireTls)
                    ps.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) to rs.getBoolean(2) else null to false }
                }
                if (upsertedId == null) {
                    // The conflict arm's engine guard refused the flip: a row under this name exists with a
                    // DIFFERENT engine (it raced in after the prior read saw null). Nothing was written; re-read
                    // the now-committed engine for a precise message and reject fail-closed — the engine-immutability
                    // invariant holds without relying on the advisory lock.
                    val existingEngine = c.prepareStatement("SELECT engine FROM datasource WHERE name = ?").use { ps ->
                        ps.setString(1, name)
                        ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else engine.wireName }
                    }
                    throw DatasourceEngineConflictException(name, existingEngine, engine.wireName)
                }
                // The upsert already cleared the datasource-row catalog stamp atomically iff db_name changed
                // (a retarget makes the retained catalog describe a DIFFERENT schema — `catalog()` builds the
                // analyzer catalog name from db_name — so leaving it would authorize the new target against the
                // wrong schema, a fail-OPEN). Now drop the orphaned catalog_column rows for exactly that case.
                // `catalogCleared` reflects the ATOMIC old→new transition (RETURNING catalog_synced_at IS NULL),
                // not the pre-read `prior`, so it's race-free; the delete is idempotent (a fresh insert or a
                // same-db_name re-register has no rows to drop). A host/port-only move keeps the catalog.
                if (catalogCleared) {
                    c.prepareStatement("DELETE FROM catalog_column WHERE datasource_id = ?").use { ps ->
                        ps.setLong(1, upsertedId); ps.executeUpdate()
                    }
                }
                c.commit()
            } catch (e: Exception) {
                c.rollback(); throw e
            } finally {
                c.autoCommit = true
            }
        }
        return getByName(name)!!
    }

    /** Stamp `last_seen_at = now()` — called when a proxy's Events stream opens (liveness). */
    fun markSeen(id: Long) = dataSource.connection.use { c ->
        c.prepareStatement("UPDATE datasource SET last_seen_at = now() WHERE id = ?").use { ps ->
            ps.setLong(1, id); ps.executeUpdate()
        }
    }

    /** A column the proxy introspected and pushed over gRPC PushCatalog. */
    data class PushedColumn(
        val schema: String,
        val table: String,
        val column: String,
        val dataType: String,
        val ordinal: Int,
        val nullable: Boolean,
    )

    /**
     * gRPC PushCatalog: replace datasource [id]'s catalog with the columns the PROXY introspected and
     * pushed — the control-plane never connects to the target itself (that's the headline of this design).
     * Transactionally delete-then-batch-insert `catalog_column` (deriving each `sql_type` from the raw
     * `data_type` via [sqlTypeFor]), then stamp the connection's live `default_schemas` /
     * `mysql_lower_case_table_names` / `catalog_synced_at`. Returns the number of columns stored.
     */
    fun storePushedCatalog(
        id: Long,
        defaultSchemas: List<String>,
        mysqlLowerCaseTableNames: Int?,
        engineVersion: String,
        columns: List<PushedColumn>,
    ): Int {
        dataSource.connection.use { c ->
            c.autoCommit = false
            try {
                // Lock the datasource row so concurrent pushes (multiple proxy replicas fronting one name)
                // serialize instead of interleaving their DELETE/INSERT — otherwise the second push's insert
                // races the first's delete and trips the (datasource, schema, table, column) UNIQUE. Also
                // doubles as the disappeared-datasource check.
                c.prepareStatement("SELECT id FROM datasource WHERE id = ? FOR UPDATE").use { ps ->
                    ps.setLong(1, id)
                    ps.executeQuery().use { rs -> check(rs.next()) { "datasource $id disappeared before catalog push" } }
                }
                c.prepareStatement("DELETE FROM catalog_column WHERE datasource_id = ?").use { ps ->
                    ps.setLong(1, id); ps.executeUpdate()
                }
                c.prepareStatement(
                    """INSERT INTO catalog_column
                       (datasource_id, schema_name, table_name, column_name, data_type, sql_type, ordinal, nullable)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                ).use { ps ->
                    for (col in columns) {
                        ps.setLong(1, id)
                        ps.setString(2, col.schema)
                        ps.setString(3, col.table)
                        ps.setString(4, col.column)
                        ps.setString(5, col.dataType)
                        ps.setString(6, sqlTypeFor(col.dataType))
                        ps.setInt(7, col.ordinal)
                        ps.setBoolean(8, col.nullable)
                        ps.addBatch()
                    }
                    ps.executeBatch()
                }
                c.prepareStatement(
                    """UPDATE datasource
                       SET default_schemas = ?::jsonb, mysql_lower_case_table_names = ?, engine_version = ?,
                           catalog_synced_at = now()
                       WHERE id = ?""",
                ).use { ps ->
                    ps.setString(1, json.encodeToString(stringList, defaultSchemas))
                    setNullableInt(ps, 2, mysqlLowerCaseTableNames)
                    ps.setString(3, engineVersion.ifBlank { null })
                    ps.setLong(4, id)
                    check(ps.executeUpdate() == 1) { "datasource $id disappeared during catalog push" }
                }
                c.commit()
            } catch (e: Exception) {
                c.rollback(); throw e
            } finally {
                c.autoCommit = true
            }
        }
        return columns.size
    }

    fun create(input: DatasourceInput): Datasource {
        val id = dataSource.connection.use { c ->
            c.prepareStatement(
                """INSERT INTO datasource (name, engine, host, port, db_name)
                   VALUES (?, ?, ?, ?, ?) RETURNING id""",
            ).use { ps ->
                ps.setString(1, input.name)
                ps.setString(2, input.engine)
                ps.setString(3, input.host)
                ps.setInt(4, input.port)
                ps.setString(5, input.dbName)
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
        }
        return get(id)!!
    }

    /** Drop [id]'s stored catalog and clear its sync stamps so decisions fail closed until a fresh
     *  PushCatalog lands. Shared by [register]'s db_name retarget and [update]'s admin db_name change —
     *  both leave a catalog that now describes a DIFFERENT schema, a fail-OPEN unless invalidated. */
    private fun invalidateCatalog(c: java.sql.Connection, id: Long) {
        c.prepareStatement("DELETE FROM catalog_column WHERE datasource_id = ?").use { ps ->
            ps.setLong(1, id); ps.executeUpdate()
        }
        c.prepareStatement(
            "UPDATE datasource SET catalog_synced_at = NULL, default_schemas = '[]'::jsonb, mysql_lower_case_table_names = NULL WHERE id = ?",
        ).use { ps -> ps.setLong(1, id); ps.executeUpdate() }
    }

    /**
     * Admin edit of a datasource's advisory fields (name/host/port/db_name). ENGINE IS IMMUTABLE: a PUT
     * that changes engine is rejected with [DatasourceEngineConflictException] — the SAME fail-closed invariant
     * the proxy Register path enforces, so a stored catalog can never be reinterpreted under a different dialect
     * (repointing every `datasource_id` FK + the analyzer/system-classification manifest resolution). The admin
     * update surface is not a bypass: the web edit form seeds engine from the current value, so a normal edit
     * carries the unchanged engine and never trips this. A db_name change invalidates the stale catalog exactly
     * as a Register retarget does. Returns null if [id] doesn't exist.
     */
    fun update(id: Long, input: DatasourceInput): Datasource? {
        val existed = dataSource.connection.use { c ->
            c.autoCommit = false
            try {
                data class Prior(val engine: String, val dbName: String)
                val prior = c.prepareStatement("SELECT engine, db_name FROM datasource WHERE id = ? FOR UPDATE").use { ps ->
                    ps.setLong(1, id)
                    ps.executeQuery().use { rs -> if (rs.next()) Prior(rs.getString(1), rs.getString(2)) else null }
                }
                if (prior == null) {
                    c.rollback()
                    return@use false
                }
                if (prior.engine != input.engine) {
                    throw DatasourceEngineConflictException(input.name, prior.engine, input.engine)
                }
                c.prepareStatement(
                    "UPDATE datasource SET name=?, engine=?, host=?, port=?, db_name=? WHERE id=?",
                ).use { ps ->
                    ps.setString(1, input.name)
                    ps.setString(2, input.engine)
                    ps.setString(3, input.host)
                    ps.setInt(4, input.port)
                    ps.setString(5, input.dbName)
                    ps.setLong(6, id)
                    ps.executeUpdate()
                }
                if (prior.dbName != input.dbName) invalidateCatalog(c, id)
                c.commit()
                true
            } catch (e: Exception) {
                c.rollback(); throw e
            } finally {
                c.autoCommit = true
            }
        }
        return if (existed) get(id) else null
    }

    fun delete(id: Long): Boolean = dataSource.connection.use { c ->
        c.prepareStatement("DELETE FROM datasource WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeUpdate() > 0
        }
    }

    /**
     * A creds-free liveness result: the control-plane does not dial the target, so "test" reports whether
     * a proxy is currently attached (an open Events stream for this datasource) plus the catalog/last-seen
     * state. [proxyAttached] is resolved by the caller from [ProxyEventsHub.attached].
     */
    fun test(datasource: Datasource, proxyAttached: Boolean): TestResult {
        val catalogState = datasource.catalogSyncedAt?.let { "catalog synced $it" } ?: "catalog not synced"
        val seenState = datasource.lastSeenAt?.let { "last seen $it" } ?: "never seen"
        return if (proxyAttached) {
            TestResult(true, "proxy attached; $catalogState; $seenState")
        } else {
            TestResult(false, "no proxy attached; $catalogState; $seenState")
        }
    }

    fun catalog(id: Long): List<CatalogColumn> = dataSource.connection.use { c -> catalog(id, c) }

    /**
     * The stored certificate chain for one datasource. Read on its own rather than joined into the list/get
     * projection, so a certificate body never rides along in the datasource poll every client makes; the
     * download route is the only caller.
     */
    fun wireCertChain(id: Long): String? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT advertise_cert_chain FROM datasource WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }
    }


    fun catalog(id: Long, c: java.sql.Connection): List<CatalogColumn> {
        val classifications = classificationsFor(id, c)
        return c.prepareStatement(
            """SELECT CASE WHEN lower(d.engine) = 'mysql' THEN 'def' ELSE d.db_name END AS catalog_name,
                      c.schema_name, c.table_name, c.column_name, c.data_type, c.sql_type, c.ordinal, c.nullable
               FROM catalog_column c
               JOIN datasource d ON d.id = c.datasource_id
               WHERE c.datasource_id = ?
               ORDER BY c.schema_name, c.table_name, c.ordinal""",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                val out = ArrayList<CatalogColumn>()
                while (rs.next()) {
                    val schema = rs.getString("schema_name")
                    val table = rs.getString("table_name")
                    val column = rs.getString("column_name")
                    out += CatalogColumn(
                        rs.getString("catalog_name"), schema, table, column,
                        rs.getString("data_type"), rs.getString("sql_type"),
                        rs.getInt("ordinal"), rs.getBoolean("nullable"),
                        classifications[Triple(schema, table, column)],
                    )
                }
                out
            }
        }
    }

    /**
     * Live classification metadata keyed independently of catalog_column, with every attached
     * classification profile resolved in. Enforcement fragments provide the structural rows;
     * classifications remain CP-owned and can change without a connection re-introspection.
     *
     * This is the ONLY resolution of profile inheritance — every read path routes through it, so a
     * caller cannot see a column's own row without the profile rules that also cover it.
     *
     * Tags are the union across the datasource's own row and every attached profile: a per-datasource
     * override adds tags and can never drop one a profile applied, so an override that omits `pii`
     * cannot turn a masked column into cleartext. The mask function resolves by precedence instead —
     * the datasource's own row first (precedence -1), then the lowest-precedence attachment that
     * carries one.
     *
     * Ordering is applied here rather than in SQL: sorting the union server-side costs ~35x the
     * unordered scan on a realistic catalog, and this read is on the per-statement decision path.
     */
    fun classificationsFor(id: Long): Map<Triple<String, String, String>, Classification> =
        dataSource.connection.use { c -> classificationsFor(id, c) }

    fun classificationsFor(id: Long, c: java.sql.Connection): Map<Triple<String, String, String>, Classification> {
        val accumulators = LinkedHashMap<Triple<String, String, String>, ClassificationAccumulator>()
        c.prepareStatement(
            """SELECT cl.schema_name, cl.table_name, cl.column_name, cl.tags, cl.mask_fn_id,
                      m.name AS mask_fn_name, -1 AS precedence, '' AS profile_name
               FROM column_classification cl
               LEFT JOIN mask_fn m ON m.id = cl.mask_fn_id
               WHERE cl.datasource_id = ?
               UNION ALL
               SELECT r.schema_name, r.table_name, r.column_name, r.tags, r.mask_fn_id,
                      m.name AS mask_fn_name, dcp.precedence, p.name AS profile_name
               FROM datasource_classification_profile dcp
               JOIN classification_profile_rule r ON r.profile_id = dcp.profile_id
               JOIN classification_profile p ON p.id = dcp.profile_id
               LEFT JOIN mask_fn m ON m.id = r.mask_fn_id
               WHERE dcp.datasource_id = ?""",
        ).use { ps ->
            ps.setLong(1, id)
            ps.setLong(2, id)
            ps.executeQuery().use { rs ->
                while (rs.next()) {
                    val schema = rs.getString("schema_name")
                    val table = rs.getString("table_name")
                    val column = rs.getString("column_name")
                    accumulators.getOrPut(Triple(schema, table, column)) {
                        ClassificationAccumulator(schema, table, column)
                    }.add(
                        precedence = rs.getInt("precedence"),
                        profileName = rs.getString("profile_name"),
                        tags = json.decodeFromString(stringList, rs.getString("tags")),
                        maskFnId = rs.longOrNull("mask_fn_id"),
                        maskFnName = rs.getString("mask_fn_name"),
                    )
                }
            }
        }
        return accumulators.mapValues { (_, accumulator) -> accumulator.resolve() }
    }

    /**
     * Merges one column's contributing rows — the datasource's own classification and every attached
     * profile's rule for it — into the single [Classification] the enforcement path sees.
     */
    private class ClassificationAccumulator(
        private val schema: String,
        private val table: String,
        private val column: String,
    ) {
        private class Contribution(
            val precedence: Int,
            val profileName: String,
            val tags: List<String>,
            val maskFnId: Long?,
            val maskFnName: String?,
        )

        private val contributions = ArrayList<Contribution>()

        fun add(precedence: Int, profileName: String, tags: List<String>, maskFnId: Long?, maskFnName: String?) {
            contributions += Contribution(precedence, profileName, tags, maskFnId, maskFnName)
        }

        /**
         * Union in resolution order — the datasource's own contribution first, then each profile's.
         *
         * Ordering the CONTRIBUTIONS rather than the tag names keeps a datasource-only column's tags in
         * their stored order, which every existing caller already observes. Profile name breaks a
         * precedence tie so two attachments sharing a precedence cannot resolve to different masks run
         * to run: without it the winner is whichever row the planner happened to emit first, and a plan
         * change could swap a strong mask for a weak one on a column that is masked either way.
         */
        fun resolve(): Classification {
            val ordered = contributions.sortedWith(
                compareBy(Contribution::precedence, Contribution::profileName),
            )
            val tags = LinkedHashSet<String>()
            for (contribution in ordered) tags += contribution.tags
            val mask = ordered.firstOrNull { it.maskFnId != null }
            return Classification(schema, table, column, tags.toList(), mask?.maskFnId, mask?.maskFnName)
        }
    }

    fun defaultSchema(id: Long): String? = dataSource.connection.use { c -> defaultSchema(id, c) }

    fun defaultSchema(id: Long, c: java.sql.Connection): String? = get(id, c)?.let { datasource ->
        datasource.defaultSchemas.firstOrNull { !datasource.engine.isSystemSchema(it) }
    }

    fun upsertClassification(id: Long, input: ClassificationInput): Classification =
        dataSource.connection.use { c -> upsertClassification(id, input, c) }

    fun upsertClassification(id: Long, input: ClassificationInput, c: java.sql.Connection): Classification {
        input.tags.firstOrNull { it.startsWith(RESERVED_TAG_PREFIX) }?.let {
            throw IllegalArgumentException("tag '$it' is reserved: the '$RESERVED_TAG_PREFIX' namespace is owned by system classification")
        }
        // A blank schema is absent, not a name. Taking it literally writes a row keyed on "" that no
        // enforcement lookup can ever match (decide joins classifications by exact schema/table/column),
        // so the caller sees a tagged column while the real one stays untagged and reads cleartext.
        val schema = input.schema?.takeIf(String::isNotBlank) ?: defaultSchema(id, c)
            ?: throw IllegalArgumentException("schema is required until datasource introspection captures a default schema")
        c.prepareStatement(
            """INSERT INTO column_classification
               (datasource_id, schema_name, table_name, column_name, tags, mask_fn_id, updated_at)
               VALUES (?, ?, ?, ?, ?::jsonb, ?, now())
               ON CONFLICT (datasource_id, schema_name, table_name, column_name)
               DO UPDATE SET tags = EXCLUDED.tags, mask_fn_id = EXCLUDED.mask_fn_id, updated_at = now()""",
        ).use { ps ->
            ps.setLong(1, id)
            ps.setString(2, schema)
            ps.setString(3, input.table)
            ps.setString(4, input.column)
            ps.setString(5, json.encodeToString(stringList, input.tags))
            setNullableLong(ps, 6, input.maskFnId)
            ps.executeUpdate()
        }
        return Classification(schema, input.table, input.column, input.tags, input.maskFnId, maskFnName(input.maskFnId, c))
    }

    private fun maskFnName(id: Long?, c: java.sql.Connection): String? {
        if (id == null) return null
        return c.prepareStatement("SELECT name FROM mask_fn WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }
    }

    private fun setNullableLong(ps: java.sql.PreparedStatement, idx: Int, v: Long?) {
        if (v == null) ps.setNull(idx, java.sql.Types.BIGINT) else ps.setLong(idx, v)
    }

    private fun setNullableInt(ps: java.sql.PreparedStatement, idx: Int, v: Int?) {
        if (v == null) ps.setNull(idx, java.sql.Types.INTEGER) else ps.setInt(idx, v)
    }

    private fun java.sql.ResultSet.longOrNull(col: String): Long? = getLong(col).let { if (wasNull()) null else it }

    private fun java.sql.ResultSet.intOrNull(col: String): Int? = getInt(col).let { if (wasNull()) null else it }

    fun deleteClassification(id: Long, schema: String, table: String, column: String): Boolean =
        dataSource.connection.use { c -> deleteClassification(id, schema, table, column, c) }

    fun deleteClassification(id: Long, schema: String, table: String, column: String, c: java.sql.Connection): Boolean =
        c.prepareStatement(
            "DELETE FROM column_classification WHERE datasource_id=? AND schema_name=? AND table_name=? AND column_name=?",
        ).use { ps ->
            ps.setLong(1, id); ps.setString(2, schema); ps.setString(3, table); ps.setString(4, column)
            ps.executeUpdate() > 0
        }

    private fun java.sql.ResultSet.toDatasource() = Datasource(
        id = getLong("id"),
        name = getString("name"),
        engine = engineFromWire(getString("engine")),
        host = getString("host"),
        port = getInt("port"),
        dbName = getString("db_name"),
        tags = json.decodeFromString(stringList, getString("tags")),
        defaultSchemas = json.decodeFromString(stringList, getString("default_schemas")),
        mysqlLowerCaseTableNames = getInt("mysql_lower_case_table_names").let { if (wasNull()) null else it },
        catalogSyncedAt = getTimestamp("catalog_synced_at")?.toInstant()?.toString(),
        lastSeenAt = getTimestamp("last_seen_at")?.toInstant()?.toString(),
        engineVersion = getString("engine_version"),
        advertiseAddr = getString("advertise_addr"),
        advertiseCertChain = getString("advertise_cert_chain"),
        advertiseWireTls = getBoolean("advertise_wire_tls"),
    )
}

// ---- Routes ------------------------------------------------------------------------------

/** Reject if no session and not in auth-debug mode (mirrors the /api/audit guard). */
suspend fun ApplicationCall.requireApi(config: Config): Boolean {
    if (!config.authDebug && userSession() == null) {
        respond(HttpStatusCode.Unauthorized, ApiError("common.unauthenticated"))
        return false
    }
    return true
}

suspend fun ApplicationCall.idParam(): Long? = parameters["id"]?.toLongOrNull()

internal suspend fun ApplicationCall.respondManagementError(exception: ManagementException) {
    val status = when (exception.error.code) {
        "common.not_found" -> HttpStatusCode.NotFound
        "datasource.table_introspection_failed" -> HttpStatusCode.BadGateway
        "group.system_immutable", "role.system_immutable", "policy.system_immutable",
        "classification_profile.attached",
        -> HttpStatusCode.Conflict
        else -> HttpStatusCode.BadRequest
    }
    respond(status, exception.error)
}

/**
 * The `pmon` CLI is an authenticated OAuth client after `pmon login`, but the
 * device-auth flow hands the browser the web-session cookie, not the CLI — so the CLI presents its own wire
 * token as an HTTP `Authorization: Bearer` to reach read-only datasource discovery. Only native-wire kinds
 * (SESSION/USER) count, and this is wired ONLY into the read-only datasource GET routes — never mutations or
 * token mint — so a leaked wire token cannot bootstrap more credentials through the API. Roles are still
 * resolved server-side per principal, so this is a new authentication surface, not a privilege grant. The
 * broader question — the CLI authenticating the whole API as a first-class OAuth bearer client, or reusing
 * the web session like a browser — is backlogged (docs/backlog.md "pmon HTTP API auth").
 */
private fun ApplicationCall.bearerWirePrincipal(tokenStore: TokenStore, userGroupStore: UserGroupStore): String? {
    val header = request.headers[HttpHeaders.Authorization] ?: return null
    if (!header.startsWith("Bearer ", ignoreCase = true)) return null
    val token = header.substring(7).trim().ifBlank { return null }
    val id = tokenStore.resolve(token) ?: return null
    val kind = TokenKind.fromWire(id.kind)
    if (kind != TokenKind.SESSION && kind != TokenKind.USER) return null
    // Fail closed for a deactivated principal even if a token row survived — matches the gRPC decide path
    // (a SCIM active=false push or a failed IdP liveness recheck can mark the app_user inactive without the
    // credential revoke having raced in yet).
    if (userGroupStore.isDeactivated(id.principal)) return null
    return id.principal
}

/**
 * Authenticate a read-only API call by web session, else (interim option a) a native-wire Bearer token, else
 * authDebug. Returns the caller principal, or responds 401 and returns null. Mirrors [requireApi] but adds
 * the Bearer path so the `pmon` daemon can discover datasources without a browser cookie. PRIVATE by design:
 * the Bearer path is discovery-only, so no other route file can reach it (compiler-enforced scope).
 */
private suspend fun ApplicationCall.requireApiOrBearer(config: Config, tokenStore: TokenStore, userGroupStore: UserGroupStore): String? {
    userSession()?.principal?.let { return it }
    bearerWirePrincipal(tokenStore, userGroupStore)?.let { return it }
    if (config.authDebug) return "debug-user"
    respond(HttpStatusCode.Unauthorized, ApiError("common.unauthenticated"))
    return null
}

private val datasourceLog = org.slf4j.LoggerFactory.getLogger("com.ridi.oss.proxymonster.controlplane.Datasources")

fun Route.datasourceRoutes(
    config: Config,
    authz: Authz,
    roleResolver: RoleResolver,
    store: DatasourceStore,
    eventsHub: ProxyEventsHub,
    tableDetailService: TableDetailService,
    tokenStore: TokenStore,
    userGroupStore: UserGroupStore,
    management: DatasourceManagementService = DatasourceManagementService(store, eventsHub, tableDetailService),
) {
    // A caller may connect to (and so browse the catalog of) a datasource iff Cedar grants
    // datasource.connect on it — the same name-keyed decision, with derived context tags, the proxy runs on
    // connect. authDebug sees everything, matching every other route.
    fun mayConnect(call: ApplicationCall, principal: String, ds: Datasource): Boolean {
        if (config.authDebug) return true
        val roles = roleResolver.resolve(principal)
        val raw = call.httpAuthzContext(config)
        val tags = authz.resolveContextTags(principal, roles, ds.name, raw, ds.tags)
        return authz.authorizeDatasourceAction(
            principal, roles, AuthzAction.DATASOURCE_CONNECT, ds.name, raw.copy(tags = tags), ds.tags,
        ) !is AuthzDecision.Deny
    }

    // The datasource list + detail stay open to every authenticated principal: the SQL editor's picker,
    // JIT-request compose (which must show datasources you CANNOT yet connect to, precisely so they can be
    // requested), and token generation all need it — not an admin action. `?connectable=true` narrows the
    // list to datasources the caller can connect to (for the query picker); the CATALOG itself is
    // connect-gated below. Only mutation/config routes require admin.datasources.
    get("/api/datasources") {
        // Discovery route: the pmon daemon reads this (with a Bearer wire token) to learn each datasource's
        // engine + advertised proxy address, so it can open a local broker port per datasource.
        val principal = call.requireApiOrBearer(config, tokenStore, userGroupStore) ?: return@get
        val all = management.listDatasources()
        val connectableOnly = call.request.queryParameters["connectable"].equals("true", ignoreCase = true)
        call.respond(if (connectableOnly) all.filter { mayConnect(call, principal, it) } else all)
    }
    // Which datasources currently have a proxy attached (an open Events stream) — the admin liveness
    // view. Read-only; returns the set of attached datasource names.
    get("/api/datasources/live") {
        if (!call.requireApi(config)) return@get
        call.respond(eventsHub.attached())
    }
    // Admin "re-introspect now": push a RefreshCatalog down the datasource's open Events stream(s).
    // The response reports how many proxy streams were notified (0 == no proxy currently attached).
    post("/api/datasources/{id}/refresh") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val ds = store.get(id) ?: return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
        call.respond(RefreshResult(eventsHub.requestRefresh(ds.name)))
    }
    post("/api/datasources") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@post
        val input = call.receive<DatasourceInput>()
        // Only `name` is required: this is optional pre-provisioning (the proxy's Register fills in the
        // advisory host/port/db_name and is authoritative). No credential fields exist.
        if (input.name.isBlank()) {
            call.respond(HttpStatusCode.BadRequest, ApiError("common.field_required", mapOf("fields" to "name")))
            return@post
        }
        // Canonicalize + validate the engine at admin-create: a non-canonical value (e.g. "Postgres", "psql")
        // would be stored verbatim and then LOCKED by the engine-immutability guard, so the datasource can
        // never be adopted by its proxy (which registers "postgres"/"mysql") — unusable until deletion. Only the
        // two canonical engines are accepted, normalized to the canonical wire string (the proxy's Register uses
        // the same set).
        val engine = engineFromWireOrNull(input.engine)
            ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("datasource.invalid_engine", mapOf("engine" to input.engine)))
        call.respond(HttpStatusCode.Created, store.create(input.copy(engine = engine.wireName)))
    }
    get("/api/datasources/{id}") {
        if (!call.requireApi(config)) return@get
        val id = call.idParam() ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        store.get(id)?.let { call.respond(it) } ?: call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
    }
    put("/api/datasources/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@put
        val id = call.idParam() ?: return@put call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<DatasourceInput>()
        // Canonicalize + validate the engine exactly as create does — otherwise a PUT carrying "Postgres",
        // "postgresql", or the DatasourceInput default "postgres" would be compared verbatim against the
        // stored canonical engine and spuriously trip the immutability guard below.
        val engine = engineFromWireOrNull(input.engine)
            ?: return@put call.respond(HttpStatusCode.BadRequest, ApiError("datasource.invalid_engine", mapOf("engine" to input.engine)))
        // Engine is immutable — a PUT that changes it is a fail-closed 409 (delete + re-create to change
        // engine), mirroring the proxy Register path's FAILED_PRECONDITION.
        val updated = try {
            store.update(id, input.copy(engine = engine.wireName))
        } catch (e: DatasourceEngineConflictException) {
            return@put call.respond(HttpStatusCode.Conflict, ApiError("datasource.engine_immutable"))
        }
        updated?.let { call.respond(it) } ?: call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
    }
    delete("/api/datasources/{id}") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@delete
        val id = call.idParam() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        if (store.delete(id)) call.respond(HttpStatusCode.NoContent) else call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
    }
    post("/api/datasources/{id}/test") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@post
        val id = call.idParam() ?: return@post call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val ds = store.get(id) ?: return@post call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
        call.respond(store.test(ds, management.getDatasourceLiveness(ds.name).attached))
    }
    get("/api/datasources/{id}/catalog") {
        // requireApiOrBearer, and the principal it RETURNS: a wire-token caller has no session, so resolving
        // the principal from the session alone would fall through to the literal "debug-user" and run the
        // Cedar check against a synthetic identity. The helper hands back whichever identity authenticated,
        // and only answers "debug-user" when PM_AUTH_DEBUG actually says so.
        val principal = call.requireApiOrBearer(config, tokenStore, userGroupStore) ?: return@get
        val id = call.idParam() ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val datasource = store.get(id)
            ?: return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
        // Schema visibility tracks connect access: browsing the catalog needs the same datasource.connect
        // authority as opening a session to the datasource.
        if (!mayConnect(call, principal, datasource)) {
            return@get call.respond(HttpStatusCode.Forbidden, ApiError("datasource.not_connectable"))
        }
        call.respond(management.browseCatalog(datasource.name))
    }
    /**
     * The certificate chain to trust for this datasource's proxy, PEM, leaf first — the same bytes the
     * datasource list carries, offered as a downloadable file for psql/mysql/DataGrip to use as
     * `sslrootcert` / `--ssl-ca` with `verify-full`. A self-signed proxy cert is the one-element case.
     * pmon does not need this route: it reads the chain from the datasource list it already polls.
     *
     * Not a secret — these are the certificates the proxy already presents to every client that opens a TLS
     * connection to it — so the gate is `datasource.connect`, the same authority `{id}/catalog` needs:
     * whoever may open a session may fetch what they need to open it safely.
     *
     * Re-validated before serving. Registration already refuses a chain that does not chain, so a failure
     * here means the row changed underneath the control plane — exactly when serving trust material would be
     * worst. 409 rather than 500: the row is readable, the chain is not usable, and re-registering fixes it.
     */
    get("/api/datasources/{id}/wire-cert") {
        // Same gate and the same principal resolution as {id}/catalog: a browser session or a wire-token
        // Bearer. The console is today's only caller, since the chain also rides on the datasource list pmon
        // already polls — but a Bearer client asking for the certificate directly is a reasonable thing to do,
        // and the alternative was a 401 for it plus a "debug-user" fallback in the authorization check.
        val principal = call.requireApiOrBearer(config, tokenStore, userGroupStore) ?: return@get
        val id = call.idParam() ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val datasource = store.get(id)
            ?: return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
        if (!mayConnect(call, principal, datasource)) {
            return@get call.respond(HttpStatusCode.Forbidden, ApiError("datasource.not_connectable"))
        }
        val chain = store.wireCertChain(id)
        if (chain.isNullOrBlank()) {
            // Distinct from "not found" so the console can say "this proxy has no wire TLS" rather than
            // "no such datasource".
            return@get call.respond(HttpStatusCode.NotFound, ApiError("datasource.no_wire_cert"))
        }
        // Served whatever it looks like. The client verifies, and it is the only party that can report a
        // meaningful error about its own trust store — withholding the file just leaves the operator with
        // nothing to install and no way to see why.
        inspectTrustChain(chain)?.let { reason ->
            datasourceLog.warn("serving datasource '{}' wire cert chain that may not verify: {}", datasource.name, reason)
        }
        // Filename from the id, not the name: a datasource name is barely constrained, and a quote or CRLF in
        // one would be header injection here.
        call.response.header(
            HttpHeaders.ContentDisposition,
            "attachment; filename=\"datasource-${datasource.id}-wire-cert.pem\"",
        )
        call.respondText(chain, ContentType.parse("application/x-pem-file"))
    }
    get("/api/datasources/{id}/table-detail") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@get
        val id = call.idParam()?.takeIf { it > 0 }
            ?: return@get call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val schema = call.request.queryParameters["schema"]
        val table = call.request.queryParameters["table"]
        if (schema.isNullOrBlank() || table.isNullOrBlank()) {
            call.respond(HttpStatusCode.BadRequest, ApiError("common.field_required", mapOf("fields" to "schema, table")))
            return@get
        }
        val datasource = store.get(id)
            ?: return@get call.respond(HttpStatusCode.NotFound, ApiError("common.not_found", mapOf("resource" to "datasource")))
        try {
            call.respond(management.getTableDetail(datasource.name, schema, table))
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    put("/api/datasources/{id}/classification") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@put
        val id = call.idParam() ?: return@put call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val input = call.receive<ClassificationInput>()
        try {
            call.respond(
                management.setColumnClassification(
                    id, input.schema, input.table, input.column, input.tags, input.maskFnId,
                ),
            )
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
    delete("/api/datasources/{id}/classification") {
        if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@delete
        val id = call.idParam() ?: return@delete call.respond(HttpStatusCode.BadRequest, ApiError("common.bad_id"))
        val body = call.receive<ClassificationDelete>()
        try {
            management.clearColumnClassification(id, body.schema, body.table, body.column)
            call.respond(HttpStatusCode.NoContent)
        } catch (e: ManagementException) {
            call.respondManagementError(e)
        }
    }
}
