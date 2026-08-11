package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.AccessStore
import com.ridi.oss.proxymonster.controlplane.AuditStore
import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.ClassificationInput
import com.ridi.oss.proxymonster.controlplane.DecisionContext
import com.ridi.oss.proxymonster.controlplane.decideQuery
import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceInput
import com.ridi.oss.proxymonster.controlplane.DatasourceStore
import com.ridi.oss.proxymonster.controlplane.MaskFnInput
import com.ridi.oss.proxymonster.controlplane.catalogName
import com.ridi.oss.proxymonster.controlplane.defaultSchema
import com.ridi.oss.proxymonster.controlplane.isMySql
import com.ridi.oss.proxymonster.controlplane.PolicyStore
import com.ridi.oss.proxymonster.controlplane.QueryResponse
import com.ridi.oss.proxymonster.controlplane.RoleAssignmentInput
import com.ridi.oss.proxymonster.controlplane.RoleInput
import com.ridi.oss.proxymonster.controlplane.RoleResolver
import com.ridi.oss.proxymonster.controlplane.TokenStore
import com.ridi.oss.proxymonster.controlplane.UserGroupStore
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import org.flywaydb.core.Flyway
import java.sql.DriverManager
import javax.sql.DataSource

/**
 * Populate the metadata catalog through the proxy-push store path while tests own the target connection.
 * Mirrors the proxy's namespace probe + information_schema scan without asking the control-plane store to
 * dial the target (the control-plane does not dial targets).
 */
internal fun DatasourceStore.pushTestCatalog(
    datasource: Datasource,
    jdbcUrl: String,
    user: String,
    password: String,
) {
    data class Namespace(
        val defaultSchemas: List<String>,
        val mysqlLowerCaseTableNames: Int?,
        val engineVersion: String,
    )

    val columns = ArrayList<DatasourceStore.PushedColumn>()
    val isMysql = datasource.engine.isMySql
    val columnSql =
        """SELECT table_schema, table_name, column_name, data_type, ordinal_position, is_nullable
           FROM information_schema.columns
           ORDER BY table_schema, table_name, ordinal_position"""
    val namespace = DriverManager.getConnection(jdbcUrl, user, password).use { target ->
        val captured = if (isMysql) {
            target.prepareStatement("SELECT DATABASE(), @@lower_case_table_names, DATABASE() = ?, VERSION()").use { ps ->
                ps.setString(1, datasource.dbName)
                ps.executeQuery().use { rs ->
                    check(rs.next()) { "MySQL namespace probe returned no row" }
                    val currentDb = rs.getString(1) ?: error("MySQL connection has no current database")
                    val lowerCaseTableNames = rs.getInt(2)
                    check(!rs.wasNull() && lowerCaseTableNames in 0..2) {
                        "MySQL returned invalid lower_case_table_names: $lowerCaseTableNames"
                    }
                    check(rs.getBoolean(3)) {
                        "MySQL current database '$currentDb' does not match bound database '${datasource.dbName}'"
                    }
                    val engineVersion = rs.getString(4) ?: error("MySQL returned no server version")
                    Namespace(listOf(currentDb), lowerCaseTableNames, engineVersion)
                }
            }
        } else {
            val schemas = ArrayList<String>()
            val engineVersion = target.prepareStatement("SELECT version()").use { ps ->
                ps.executeQuery().use { rs ->
                    check(rs.next()) { "PostgreSQL version probe returned no row" }
                    rs.getString(1) ?: error("PostgreSQL returned no server version")
                }
            }
            target.prepareStatement("SELECT unnest(current_schemas(true))").use { ps ->
                ps.executeQuery().use { rs -> while (rs.next()) schemas += rs.getString(1) }
            }
            Namespace(schemas, null, engineVersion)
        }
        target.prepareStatement(columnSql).use { ps ->
            ps.executeQuery().use { rs ->
                while (rs.next()) {
                    columns += DatasourceStore.PushedColumn(
                        schema = rs.getString(1),
                        table = rs.getString(2),
                        column = rs.getString(3),
                        dataType = rs.getString(4),
                        ordinal = rs.getInt(5),
                        nullable = rs.getString(6) == "YES",
                    )
                }
            }
        }
        captured
    }
    storePushedCatalog(
        id = datasource.id,
        defaultSchemas = namespace.defaultSchemas,
        mysqlLowerCaseTableNames = namespace.mysqlLowerCaseTableNames,
        engineVersion = namespace.engineVersion,
        columns = columns,
    )
}

/**
 * A fully wired enforcement stack against real databases: a Flyway-migrated Postgres control-plane
 * store plus a seeded target database (Postgres or MySQL) whose `users.ssn` is tagged pii and
 * carries a last4 mask, with Cedar policies granting the `analyst` role cleartext on `users` EXCEPT
 * pii (masked instead) — the "read table except pii" pattern (docs/authz-model.md). The target also
 * has an UNGRANTED `orders` table (no Cedar grant covers it) so deny-by-default is provable
 * end-to-end: a query touching it must DENY, never fall through to cleartext. Lets DB-backed tests
 * exercise [runEnforcedForTest] end-to-end — decide, broker to the real target, and mask/deny result
 * values — over a shared, reused container.
 */
class EnforcementFixture(
    val datasourceStore: DatasourceStore,
    val policyStore: PolicyStore,
    val auditStore: AuditStore,
    val accessStore: AccessStore,
    val userGroupStore: UserGroupStore,
    val tokenStore: TokenStore,
    val daemonSessionStore: PrincipalSessionStore,
    val datasource: Datasource,
    val role: String,
    val cleartextSsn: List<String>,
    val roleResolver: RoleResolver,
    val authz: Authz,
    val dataSource: DataSource,
    val cedarPolicyStore: com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore,
    // The target connection the TEST owns (Testcontainers creds). The control-plane does not store or
    // dial these (it holds no service credentials); the harness executes ALLOW'd queries here itself.
    val targetJdbcUrl: String,
    val targetUser: String,
    val targetPassword: String,
) {
    // principal defaults to the principal seedPolicy() grants ROLE to via a direct principal_role
    // assignment — role resolution is entirely server-side, never a client-asserted list.
    fun run(sql: String, principal: String = "analyst@example.com"): QueryResponse = runEnforcedForTest(
        principal = principal,
        ds = datasource,
        sql = sql,
        maxRows = 100,
        clientAddr = "127.0.0.1",
        datasourceStore = datasourceStore,
        policyStore = policyStore,
        auditStore = auditStore,
        accessStore = accessStore,
        userGroupStore = userGroupStore,
        roleResolver = roleResolver,
        authz = authz,
        execute = { sql, maxRows -> execOnTarget(targetJdbcUrl, targetUser, targetPassword, sql, maxRows) },
    )

    /**
     * The real analyzer → [decideQuery] decision for [sql] (no execution), so a test can assert on the
     * DecisionContext itself — e.g. the analyzer-emitted `rewrittenSql` — through the production seam rather
     * than injecting synthetic facts.
     */
    fun decide(
        sql: String,
        principal: String = "analyst@example.com",
        channel: Channel = Channel.WIRE,
        // A task's frozen execute_as snapshot: when set it REPLACES server role resolution (the approval
        // execute + stored-result view path), exercising the decision's own live-role re-filter.
        providedRoles: Set<String>? = null,
    ): DecisionContext =
        decideQuery(
            principal, datasource, sql, channel, datasourceStore.catalog(datasource.id),
            policyStore, accessStore, userGroupStore, roleResolver, authz,
            providedRoles = providedRoles,
        )

    /** Run raw SQL directly against the target (test setup/teardown; no enforcement gate). */
    fun execOnTarget(sql: String): QueryRows = execOnTarget(targetJdbcUrl, targetUser, targetPassword, sql, 1000)

    companion object {
        private const val ROLE = "analyst"
        private val CLEARTEXT = listOf("987-65-4320", "987-65-4321")

        /** Build a control-plane store on a fresh migrated Postgres metadata database. */
        private fun metadataStores(): MetaStores {
            val metaDb = SharedPostgres.freshDatabase("pm_meta")
            val meta = SharedPostgres.hikari(metaDb)
            Flyway.configure().dataSource(meta).load().migrate()
            return MetaStores(
                meta, DatasourceStore(meta), PolicyStore(meta), AuditStore(meta), AccessStore(meta),
                UserGroupStore(meta), CedarPolicyStore(meta), TokenStore(meta), PrincipalSessionStore(meta, null),
            )
        }

        /**
         * Classifies `users.ssn` as pii + last4-masked, grants `analyst` a direct role assignment,
         * then seeds the Cedar "read table except pii" pair (docs/authz-model.md worked example):
         * cleartext on every `users` column NOT tagged pii, masked on the ones that are. Deny-by-
         * default covers everything else (a column with no matching grant at all -> DENIED, never
         * cleartext) — that's what `non-sensitive query is allowed` (EnforcementDbTest) actually
         * proves: `region`/`id` are ungranted-by-name but covered by the table-level permit.
         *
         * Also seeds the once-per-query `datasource.connect` / statement-category gates: `analyst` gets
         * `datasource.connect` + `stmt.cat.read` (plus `stmt.cat.metadata`/`stmt.cat.session` for benign
         * passthrough), so all the existing SELECT-based EnforcementDbTest cases stay green once the gates
         * are live, plus two more roles/principals that prove the gates' ordering and composition:
         * `no-connect-reader` (stmt.cat.read + result.read.unmasked, but NO datasource.connect — proves
         * connect is checked first) and `ddl-writer` (datasource.connect + stmt.cat.ddl + the same users
         * unmasked/masked-pii pair `analyst` has — proves a CTAS that reads a masked column still gets
         * caught by PolicyEvaluator's write-payload rule even though stmt.cat.ddl itself is granted).
         */
        private fun seedPolicy(s: MetaStores, ds: Datasource): Datasource {
            val catalog = ds.engine.catalogName(ds.dbName)
            val schema = ds.engine.defaultSchema(ds.dbName)
            val usersTableEuid = "${ds.name}/$catalog/$schema/users"
            val maskFn = s.policyStore.createMaskFn(MaskFnInput("last4", "LAST_N"))
            s.datasourceStore.upsertClassification(
                ds.id,
                ClassificationInput(schema = schema, table = "users", column = "ssn", tags = listOf("pii"), maskFnId = maskFn.id),
            )
            val role = s.policyStore.createRole(RoleInput(ROLE))
            // Direct principal_role assignment so RoleResolver.resolve("analyst@example.com") — the
            // default principal in run() — actually resolves to {ROLE} server-side.
            s.policyStore.createAssignment(RoleAssignmentInput("analyst@example.com", role.id))
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "analyst-users-unmasked",
                    cedarSrc = """permit(principal in Role::"$ROLE", action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid") unless { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "analyst-users-masked-pii",
                    // Table-scoped, NOT a blanket `resource in Tag::"pii"`: the masked grant only
                    // covers pii columns OF THE users table (docs/authz-model.md:55-56's canonical
                    // "read table except pii" pair). A pii column in a table analyst has no grant on
                    // (e.g. the ungranted `orders` below) must therefore be DENIED, not blanket-masked.
                    cedarSrc = """permit(principal in Role::"$ROLE", action == Action::"result.read.masked", resource in Table::"$usersTableEuid") when { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "analyst-connect-select",
                    // Plus stmt.cat.metadata / stmt.cat.session so a plain reader's benign SHOW/DESCRIBE and
                    // SET/BEGIN passthrough still clears the kind gate (this bespoke datasource carries no
                    // system:development preset that would grant those categories).
                    cedarSrc = """permit(principal in Role::"$ROLE", action in [Action::"datasource.connect", Action::"stmt.cat.read", Action::"stmt.cat.metadata", Action::"stmt.cat.session"], resource in Datasource::"${ds.name}");""",
                ),
                updatedBy = "test-fixture",
            )

            // `no-connect-reader` — sql.select + result.read.unmasked on users, but deliberately NO
            // datasource.connect — proves the connect gate runs (and denies) before sql.<kind>/columns.
            val noConnectRole = s.policyStore.createRole(RoleInput("no-connect-reader"))
            s.policyStore.createAssignment(RoleAssignmentInput("reader@example.com", noConnectRole.id))
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "no-connect-reader-select",
                    cedarSrc = """permit(principal in Role::"no-connect-reader", action in [Action::"stmt.cat.read"], resource in Datasource::"${ds.name}");""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "no-connect-reader-unmasked",
                    cedarSrc = """permit(principal in Role::"no-connect-reader", action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid") unless { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )

            // `ddl-writer` — datasource.connect + sql.ddl, plus the same users unmasked/masked-pii pair
            // `analyst` has, so a CTAS reading `ssn` resolves it to MASKED and the write-payload rule in
            // PolicyEvaluator.evaluate fires even though sql.ddl itself is granted.
            val ddlRole = s.policyStore.createRole(RoleInput("ddl-writer"))
            s.policyStore.createAssignment(RoleAssignmentInput("writer@example.com", ddlRole.id))
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "ddl-writer-connect-ddl",
                    cedarSrc = """permit(principal in Role::"ddl-writer", action in [Action::"datasource.connect", Action::"stmt.cat.ddl"], resource in Datasource::"${ds.name}");""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "ddl-writer-users-unmasked",
                    cedarSrc = """permit(principal in Role::"ddl-writer", action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid") unless { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "ddl-writer-users-masked-pii",
                    cedarSrc = """permit(principal in Role::"ddl-writer", action == Action::"result.read.masked", resource in Table::"$usersTableEuid") when { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )

            // `insert-writer` — datasource.connect + sql.insert (deliberately NO sql.update) + the same
            // users unmasked/masked-pii pair — proves an upsert (ON CONFLICT DO UPDATE / ON DUPLICATE KEY
            // UPDATE) is denied for an insert-only principal: its kind insert_on_dup is a member of
            // write.update, not write.insert, since an upsert can modify an EXISTING row.
            val insertRole = s.policyStore.createRole(RoleInput("insert-writer"))
            s.policyStore.createAssignment(RoleAssignmentInput("inserter@example.com", insertRole.id))
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "insert-writer-connect-insert",
                    cedarSrc = """permit(principal in Role::"insert-writer", action in [Action::"datasource.connect", Action::"stmt.cat.write.insert"], resource in Datasource::"${ds.name}");""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "insert-writer-users-unmasked",
                    cedarSrc = """permit(principal in Role::"insert-writer", action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid") unless { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "insert-writer-users-masked-pii",
                    cedarSrc = """permit(principal in Role::"insert-writer", action == Action::"result.read.masked", resource in Table::"$usersTableEuid") when { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )

            // `update-writer` — datasource.connect + stmt.cat.write.update + the same users read grants. An
            // upsert's kind is insert_on_dup (a member of write.update), so this update-only principal can run
            // one and INSERT a new row. That is the ACCEPTED tradeoff of one-kind-one-category — Cedar
            // membership is OR, not AND — where the forward hole (insert-only cannot update via upsert) is
            // closed but the reverse is by design (see EnforcementDbTest).
            val updateRole = s.policyStore.createRole(RoleInput("update-writer"))
            s.policyStore.createAssignment(RoleAssignmentInput("updater@example.com", updateRole.id))
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "update-writer-connect-update",
                    cedarSrc = """permit(principal in Role::"update-writer", action in [Action::"datasource.connect", Action::"stmt.cat.write.update"], resource in Datasource::"${ds.name}");""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "update-writer-users-unmasked",
                    cedarSrc = """permit(principal in Role::"update-writer", action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid") unless { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "update-writer-users-masked-pii",
                    cedarSrc = """permit(principal in Role::"update-writer", action == Action::"result.read.masked", resource in Table::"$usersTableEuid") when { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )

            // `file-writer` — datasource.connect + stmt.cat.admin.file (the server-side FILE-write kind
            // category) + the same users unmasked/masked-pii pair. A `SELECT ssn ... INTO OUTFILE` clears the
            // kind gate (its kind select_into_outfile is a member of admin.file), reaches column authorization
            // where ssn resolves to MASKED, and must then be denied by the write-payload rule — the OUTFILE
            // analog of the CTAS write-payload check. (A principal without admin.file kind-denies first.)
            val fileRole = s.policyStore.createRole(RoleInput("file-writer"))
            s.policyStore.createAssignment(RoleAssignmentInput("filewriter@example.com", fileRole.id))
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "file-writer-connect-file",
                    cedarSrc = """permit(principal in Role::"file-writer", action in [Action::"datasource.connect", Action::"stmt.cat.admin.file"], resource in Datasource::"${ds.name}");""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "file-writer-users-unmasked",
                    cedarSrc = """permit(principal in Role::"file-writer", action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid") unless { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "file-writer-users-masked-pii",
                    cedarSrc = """permit(principal in Role::"file-writer", action == Action::"result.read.masked", resource in Table::"$usersTableEuid") when { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )
            // `explainer` — the same reads as `analyst` (connect + cat.read, non-pii unmasked, pii masked)
            // PLUS a plan-only-EXPLAIN unmask: result.read.unmasked on the users table, but ONLY when
            // context.stmt_kind == "explain". A masked column in a predicate — denied for a row-returning
            // SELECT, since its selectivity would leak — is then readable under a plan-only EXPLAIN, which
            // returns no rows. Proves the stmt_kind context threading; the shipped -262 preset applies this
            // shape to system:production-pii-accessor.
            val explainRole = s.policyStore.createRole(RoleInput("explainer"))
            s.policyStore.createAssignment(RoleAssignmentInput("explainer@example.com", explainRole.id))
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "explainer-connect-read-write",
                    cedarSrc = """permit(principal in Role::"explainer", action in [Action::"datasource.connect", Action::"stmt.cat.read", Action::"stmt.cat.write.insert", Action::"stmt.cat.ddl"], resource in Datasource::"${ds.name}");""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "explainer-users-unmasked",
                    cedarSrc = """permit(principal in Role::"explainer", action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid") unless { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "explainer-users-masked-pii",
                    cedarSrc = """permit(principal in Role::"explainer", action == Action::"result.read.masked", resource in Table::"$usersTableEuid") when { resource in Tag::"pii" };""",
                ),
                updatedBy = "test-fixture",
            )
            s.cedarPolicyStore.create(
                CedarPolicyInput(
                    name = "explainer-explain-unmasked",
                    cedarSrc = """permit(principal in Role::"explainer", action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid") when { context has stmt_kind && context.stmt_kind == "explain" };""",
                ),
                updatedBy = "test-fixture",
            )
            // pushTestCatalog() captures static namespace/case metadata on the datasource row. Always hand
            // decideQuery the refreshed row rather than the pre-catalog create() result.
            return s.datasourceStore.get(ds.id)!!
        }

        fun postgres(): EnforcementFixture {
            val s = metadataStores()
            val targetDb = SharedPostgres.freshDatabase("pm_target")
            DriverManager.getConnection(SharedPostgres.jdbcUrlFor(targetDb), SharedPostgres.username(), SharedPostgres.password()).use { c ->
                c.createStatement().use { st ->
                    st.execute("CREATE TABLE users (id BIGINT PRIMARY KEY, email VARCHAR(64), ssn VARCHAR(32), region VARCHAR(8))")
                    st.execute("INSERT INTO users VALUES (1,'a@x','${CLEARTEXT[0]}','KR'),(2,'b@x','${CLEARTEXT[1]}','KR')")
                    // An ungranted table (no Cedar grant covers it) — deny-by-default regression: a
                    // touched column here must resolve to DENIED, never fall through to cleartext.
                    st.execute("CREATE TABLE orders (id BIGINT PRIMARY KEY, amount BIGINT)")
                    st.execute("INSERT INTO orders VALUES (1,100),(2,200)")
                }
            }
            val ds = s.datasourceStore.create(
                DatasourceInput(
                    name = "target-pg", engine = "postgres",
                    host = SharedPostgres.host(), port = SharedPostgres.port(),
                    dbName = targetDb,
                ),
            )
            s.datasourceStore.pushTestCatalog(ds, SharedPostgres.jdbcUrlFor(targetDb), SharedPostgres.username(), SharedPostgres.password())
            val refreshed = seedPolicy(s, ds)
            return s.fixture(refreshed, SharedPostgres.jdbcUrlFor(targetDb), SharedPostgres.username(), SharedPostgres.password())
        }

        fun mysql(): EnforcementFixture {
            val s = metadataStores()
            val targetDb = SharedMySql.defaultDatabase()
            DriverManager.getConnection(SharedMySql.jdbcUrlFor(targetDb), SharedMySql.username(), SharedMySql.password()).use { c ->
                c.createStatement().use { st ->
                    st.execute("DROP TABLE IF EXISTS users")
                    st.execute("CREATE TABLE users (id BIGINT PRIMARY KEY, email VARCHAR(64), ssn VARCHAR(32), region VARCHAR(8))")
                    st.execute("INSERT INTO users VALUES (1,'a@x','${CLEARTEXT[0]}','KR'),(2,'b@x','${CLEARTEXT[1]}','KR')")
                    // An ungranted table (no Cedar grant covers it) — see postgres() for the rationale.
                    st.execute("DROP TABLE IF EXISTS orders")
                    st.execute("CREATE TABLE orders (id BIGINT PRIMARY KEY, amount BIGINT)")
                    st.execute("INSERT INTO orders VALUES (1,100),(2,200)")
                }
            }
            val ds = s.datasourceStore.create(
                DatasourceInput(
                    name = "target-mysql", engine = "mysql",
                    host = SharedMySql.host(), port = SharedMySql.port(),
                    dbName = targetDb,
                ),
            )
            s.datasourceStore.pushTestCatalog(ds, SharedMySql.jdbcUrlFor(targetDb), SharedMySql.username(), SharedMySql.password())
            val refreshed = seedPolicy(s, ds)
            return s.fixture(refreshed, SharedMySql.jdbcUrlFor(targetDb), SharedMySql.username(), SharedMySql.password())
        }

        private data class MetaStores(
            val meta: DataSource,
            val datasourceStore: DatasourceStore,
            val policyStore: PolicyStore,
            val auditStore: AuditStore,
            val accessStore: AccessStore,
            val userGroupStore: UserGroupStore,
            val cedarPolicyStore: CedarPolicyStore,
            val tokenStore: TokenStore,
            val daemonSessionStore: PrincipalSessionStore,
        ) {
            // Built AFTER seedPolicy() has run (see postgres()/mysql() — seed happens before this is
            // called), so correctness never depends on CedarEngine cache invalidation: the engine's
            // first isAuthorized() builds its cached PolicySet from the already-seeded enabledSources()
            // (at the post-seed stateVersion), and no Cedar mutation happens during run(), so that
            // cache stays valid for the fixture's lifetime.
            fun fixture(ds: Datasource, targetJdbcUrl: String, targetUser: String, targetPassword: String): EnforcementFixture {
                val roleResolver = RoleResolver(meta, userGroupStore, accessStore)
                val engine = CedarEngine(cedarPolicyStore)
                val authz = Authz(engine, cedarPolicyStore, RoleSource { p -> roleResolver.resolve(p) })
                return EnforcementFixture(
                    datasourceStore, policyStore, auditStore, accessStore, userGroupStore, tokenStore, daemonSessionStore,
                    ds, ROLE, CLEARTEXT, roleResolver, authz, meta, cedarPolicyStore,
                    targetJdbcUrl, targetUser, targetPassword,
                )
            }
        }
    }
}
