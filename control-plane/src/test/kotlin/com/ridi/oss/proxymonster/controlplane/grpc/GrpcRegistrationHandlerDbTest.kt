package com.ridi.oss.proxymonster.controlplane.grpc

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.controlplane.Binding
import com.ridi.oss.proxymonster.controlplane.CatalogMutationResult
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceEngineConflictException
import com.ridi.oss.proxymonster.controlplane.DatasourceInput
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.catalogRequest
import com.ridi.oss.proxymonster.grpc.column
import com.ridi.oss.proxymonster.grpc.registerRequest
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * DB-backed coverage for the registration gRPC handlers (docs/datasource-registration.md): Register (upsert
 * by name, self-create, tag preservation, fail-closed engine) and PushCatalog (proxy-pushed catalog write,
 * NOT_FOUND on an unregistered name, transactional replace). The control-plane never dials a target here —
 * the "catalog" arrives as gRPC messages, exactly as the proxy sends it.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GrpcRegistrationHandlerDbTest {
    private companion object {
        // Throwaway certificates: a self-signed leaf (its own anchor, the ordinary proxy case) and a
        // CA-issued leaf with its issuer deliberately withheld (anchors nothing).
        val SELF_SIGNED_CHAIN =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDPTCCAiWgAwIBAgIUJeAynTaX/TJdfCHpPYqljxv5BJ0wDQYJKoZIhvcNAQEL\n" +
        "BQAwHzEdMBsGA1UEAwwUcG0tcHJveHkuZXhhbXBsZS5jb20wHhcNMjYwNzI3MTIy\n" +
        "MDIzWhcNMjcwNzI3MTIyMDIzWjAfMR0wGwYDVQQDDBRwbS1wcm94eS5leGFtcGxl\n" +
        "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALAPb/6x5fTqssbH\n" +
        "0jKzOI90/MnENRaAfb4As4e5yse0Xrir2Kz/10O6GSH49lhdRa/csLqeH122m9gj\n" +
        "C4vCIvDJRTqz81s3yaLN7/4PnTbS1WOwp+PTwRajHXC8Xp5MPBEyZVNj+WjzCYE4\n" +
        "inlXuSJSFaTUB1Md1F91UaD/q+eOt/Rocg5Erq65Z6tWnAs03t3Sp8ZfBs/YlA5u\n" +
        "TP5BPgE3NQq6uwU1kBfQQpPiem+B/9NATbY094YH3cJwOFMF1Z69t80LO2ZvZ7u8\n" +
        "fQs0GHPpIE8n7mkGjleOwFypoDM9N+ZDtSeAQBGAk5ulV59lni2/xV1pQ0YDx8H6\n" +
        "t1ekfI8CAwEAAaNxMG8wHQYDVR0OBBYEFCUm5743U+xa/Rqr4rlRqDt/qJ8SMB8G\n" +
        "A1UdIwQYMBaAFCUm5743U+xa/Rqr4rlRqDt/qJ8SMAwGA1UdEwEB/wQCMAAwHwYD\n" +
        "VR0RBBgwFoIUcG0tcHJveHkuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\n" +
        "AKbyz1Vu4MhL49dXoCQPdyXj+m332HIAMtQDDRJubbFTm+x0KQLOCgb3ZBvi6x1k\n" +
        "WertFs3Mqs4g/72BvfU96aCmCYJ4iZi0XT3ZC/1j36dJjxpk1EDM75pW5KLnfDDo\n" +
        "qWF7gtahB3uGqKM4uRpkodGE7OIelf/Hs/m/iSnnX6VEGCQIe9Ew87B2xtj4u891\n" +
        "ghWojgBCelZxEmN31Og6VFRYTZYLk/Xb4ya2Xq6g8jjwGKKYHZCs1gQ1vvZm4eof\n" +
        "GrFvts/fga0akW6kpc3vBLP1gMZFirHQ6WZnemsdEcXG1GKyM40O4KkPBYcnypT0\n" +
        "3lp9W8du2aYfDic7uDfw0Gg=\n" +
        "-----END CERTIFICATE-----\n"
        val CA_ISSUED_LEAF_ALONE =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDODCCAiCgAwIBAgIUCMlJHsWQYF9aDuby/9E5L6bOjrUwDQYJKoZIhvcNAQEL\n" +
        "BQAwGjEYMBYGA1UEAwwPVGVzdCBQcml2YXRlIENBMB4XDTI2MDcyNzA5MDUwOFoX\n" +
        "DTI3MDcyNzA5MDUwOFowHzEdMBsGA1UEAwwUcG0tcHJveHkuZXhhbXBsZS5jb20w\n" +
        "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDc265GclVN6fROXzi+yxYz\n" +
        "PyWp/0DuoV6VZBIxjoPAYZE5iMpLqz4COlr/y+0sRZ8fy3/3v3VF+AkR+Nreeznd\n" +
        "WNNBdnDkYg48vgy6Og4V7riU2uFL6SEGqCsM3Thcj3TffNmfRd2+OebD8CMg91Hs\n" +
        "Hn6ddmCVT0yUrJstLasuS4yNd0JVrX8FrxxaljQjlVX7H+kSLVn+x/qLLga1wWRd\n" +
        "wEHd7LObrk06WvPsMP+qbyQTA9CP7GJtbv7vEloECE3sS2l3QjWUQGp4YFrnMWl5\n" +
        "wdZSuThXz9sub/y0c51vLvzDJVVbNYdshMBrpZWbp6cALVS+qzCt35drj6WOnkUt\n" +
        "AgMBAAGjcTBvMAwGA1UdEwEB/wQCMAAwHwYDVR0RBBgwFoIUcG0tcHJveHkuZXhh\n" +
        "bXBsZS5jb20wHQYDVR0OBBYEFBj09SNWr+0aRPR3d2yu+D71Ne9QMB8GA1UdIwQY\n" +
        "MBaAFPLbxOH+O1GK8v0GeivzFC4vXMp+MA0GCSqGSIb3DQEBCwUAA4IBAQBVsgMq\n" +
        "MBK2K1hwcDWlMDxRAnXjxlBlTFOAYUqHPj3Ldxqwma753kPcXaikfS4NJ9+ykHkh\n" +
        "0tr+UhYe7GzW28pEz2qzkh1uBqYi2gQHgFMyIkjCECFSE8YVFXaVWFdVI9NEeRdp\n" +
        "KzWxd4PrudQ1Rz9AN2OTD1O/HXlvZ5McWltira59nLZKmKt27Z10qq3vBrjHapoX\n" +
        "0m9jVxpnAquar42WJTlKcs7xp8Z6uKVqCURu4csrWDalAWprdHHKaxLazVjh1L2w\n" +
        "qAv8gJuOTmYouD/hcFK0SCNtT3Rq4f9HFQlo7mYjXs02LK/IIYTxUwmJzW2W06vF\n" +
        "TBtfh2tHAcUTxjLG\n" +
        "-----END CERTIFICATE-----\n"
    }

    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var server: GrpcServer
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var rawChannel: io.grpc.ManagedChannel

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_grpc_register"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        server = GrpcServer(0, ControlPlaneGrpcService(core), secretToken = null).also { it.start() }
        rawChannel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(rawChannel)
    }

    @AfterAll
    fun teardown() {
        rawChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        server.shutdown()
    }

    private fun statusOf(block: suspend () -> Unit): Status.Code =
        assertFailsWith<StatusException> { runBlocking { block() } }.status.code

    @Test
    fun `register self-creates a datasource by name with no service credential`() = runBlocking {
        val resp = stub.register(
            registerRequest {
                name = "reg-new"
                engine = Engine.POSTGRES
                host = "db.internal"
                port = 5432
                dbName = "app"
                tags.add("system:development")
            },
        )
        assertEquals("reg-new", resp.name)
        val ds = core.datasourceStore.getByName("reg-new")!!
        assertEquals(Engine.POSTGRES, ds.engine)
        assertEquals("db.internal", ds.host)
        assertEquals(5432, ds.port)
        assertEquals("app", ds.dbName)
        assertEquals(listOf("system:development"), ds.tags)
    }

    @Test
    fun `register persists the advertised proxy address and cert chain and preserves them on a blank re-register`() = runBlocking {
        stub.register(
            registerRequest {
                name = "reg-adv"
                engine = Engine.MYSQL
                host = "db.internal"
                port = 3306
                dbName = "app"
                advertiseAddr = "proxy.example.ts.net:6033"
                advertiseCertChain = SELF_SIGNED_CHAIN
                advertiseWireTls = true
            },
        )
        val ds = core.datasourceStore.getByName("reg-adv")!!
        assertEquals("proxy.example.ts.net:6033", ds.advertiseAddr)
        assertTrue(ds.advertiseWireTls, "the TLS requirement must persist; pmon refuses a plaintext downgrade on it")
        // The chain must reach the DATASOURCE RESPONSE, not just the row: pmon reads it from this JSON, so a
        // field that exists in the database and not in the response is a silent TLS downgrade for every
        // brokered connection. This is the CP/pmon contract, and it is the one seam unit tests kept missing.
        assertEquals(SELF_SIGNED_CHAIN, ds.advertiseCertChain)
        assertEquals(SELF_SIGNED_CHAIN, core.datasourceStore.wireCertChain(ds.id))
        val json = kotlinx.serialization.json.Json.encodeToString(Datasource.serializer(), ds)
        assertTrue(
            json.contains("\"advertiseCertChain\""),
            "the response must carry advertiseCertChain — pmon's discovery struct reads exactly that key: $json",
        )

        // A re-register carrying no address/chain (a bare admin re-seed, or a transient read on the proxy)
        // must not wipe what a proxy previously advertised — the COALESCE upsert keeps the prior values.
        stub.register(
            registerRequest {
                name = "reg-adv"; engine = Engine.MYSQL; host = "db2"; port = 3307; dbName = "app"
                advertiseWireTls = true
            },
        )
        val ds2 = core.datasourceStore.getByName("reg-adv")!!
        assertEquals("proxy.example.ts.net:6033", ds2.advertiseAddr)
        assertEquals(SELF_SIGNED_CHAIN, ds2.advertiseCertChain)
        assertEquals(SELF_SIGNED_CHAIN, core.datasourceStore.wireCertChain(ds2.id))
    }

    @Test
    fun `turning wire TLS off clears a previously advertised chain`() = runBlocking {
        // The state transition an operator actually performs: a proxy advertising a private chain is
        // reconfigured (TLS disabled, or rotated onto a publicly-trusted certificate that publishes nothing).
        // If the stored chain survived that, clients would keep verifying the new certificate against dead
        // roots and every connection would fail -- and the console would keep offering a stale download.
        stub.register(
            registerRequest {
                name = "reg-tls-off"; engine = Engine.MYSQL; host = "h"; port = 3306; dbName = "d"
                advertiseCertChain = SELF_SIGNED_CHAIN
                advertiseWireTls = true
            },
        )
        assertEquals(SELF_SIGNED_CHAIN, core.datasourceStore.getByName("reg-tls-off")!!.advertiseCertChain)

        stub.register(
            registerRequest {
                name = "reg-tls-off"; engine = Engine.MYSQL; host = "h"; port = 3306; dbName = "d"
                advertiseWireTls = false
            },
        )
        val off = core.datasourceStore.getByName("reg-tls-off")!!
        assertFalse(off.advertiseWireTls, "the proxy said TLS is off, so the row must say so")
        assertNull(
            off.advertiseCertChain,
            "a datasource with TLS off must not keep advertising a chain -- clients would verify against roots " +
                "the proxy no longer serves, and the console would offer a certificate that is gone",
        )
        assertNull(core.datasourceStore.wireCertChain(off.id), "the download route must have nothing to serve")
    }

    @Test
    fun `a proxy serving TLS without publishing a chain still reports the TLS requirement`() = runBlocking {
        // PM_TLS_NO_ADVERTISE: a publicly-trusted certificate, so there is nothing worth distributing and
        // clients verify against their own trust store. The REQUIREMENT must still reach pmon, or its
        // plaintext-downgrade refusal goes dead for exactly this deployment and an attacker answering the
        // greeting without CLIENT_SSL collects a live session token.
        stub.register(
            registerRequest {
                name = "reg-public-tls"; engine = Engine.MYSQL; host = "h"; port = 3306; dbName = "d"
                advertiseAddr = "proxy.example.com:6033"
                advertiseWireTls = true
            },
        )
        val ds = core.datasourceStore.getByName("reg-public-tls")!!
        assertNull(ds.advertiseCertChain, "nothing was published, so there is no chain to store")
        assertTrue(ds.advertiseWireTls, "TLS is served; a client must learn that even with no chain")
        val json = kotlinx.serialization.json.Json.encodeToString(Datasource.serializer(), ds)
        assertTrue(
            json.contains("\"advertiseWireTls\":true"),
            "the response must carry advertiseWireTls -- pmon reads exactly that key to refuse a plaintext " +
                "downgrade, and a chain-only response would silently permit one: $json",
        )
    }

    @Test
    fun `register stores a questionable chain rather than refusing the datasource`() = runBlocking {
        // A chain the control plane cannot vouch for is still stored and served. Refusing would mean the
        // datasource is never created — no catalog, every decision failing closed — which is a far worse
        // outcome than one client reporting its own TLS error. The client verifies; it is the only party that
        // can. A warning is logged for the operator.
        stub.register(
            registerRequest {
                name = "reg-odd-chain"; engine = Engine.MYSQL; host = "h"; port = 3306; dbName = "d"
                advertiseCertChain = CA_ISSUED_LEAF_ALONE
                advertiseWireTls = true
            },
        )
        val ds = core.datasourceStore.getByName("reg-odd-chain")
        assertNotNull(ds, "the datasource must exist — refusing registration is the outage this avoids")
        assertEquals(CA_ISSUED_LEAF_ALONE, ds.advertiseCertChain)
    }

    @Test
    fun `register is idempotent by name and updates advisory fields`() = runBlocking {
        stub.register(registerRequest { name = "reg-idem"; engine = Engine.POSTGRES; host = "old"; port = 1; dbName = "d" })
        stub.register(registerRequest { name = "reg-idem"; engine = Engine.POSTGRES; host = "new"; port = 3306; dbName = "d2"; tags.add("system:production") })
        val ds = core.datasourceStore.getByName("reg-idem")!!
        assertEquals(Engine.POSTGRES, ds.engine, "engine is immutable at register — the same-engine re-register keeps it")
        assertEquals("new", ds.host)
        assertEquals(3306, ds.port)
        assertEquals("d2", ds.dbName)
        assertEquals(listOf("system:production"), ds.tags)
        assertEquals(1, core.datasourceStore.list().count { it.name == "reg-idem" }, "upsert, not a second row")
    }

    @Test
    fun `register refuses an engine change FAILED_PRECONDITION and leaves the row untouched`() = runBlocking {
        stub.register(registerRequest { name = "reg-engine-lock"; engine = Engine.POSTGRES; host = "h"; port = 5432; dbName = "d" })
        stub.pushCatalog(
            catalogRequest {
                datasourceName = "reg-engine-lock"
                defaultSchemas.add("public")
                columns.add(column { schema = "public"; table = "t"; this.column = "c"; dataType = "text"; ordinal = 1; nullable = true })
            },
        )
        val before = core.datasourceStore.getByName("reg-engine-lock")!!
        assertTrue(before.catalogSyncedAt != null)

        val code = statusOf {
            stub.register(registerRequest { name = "reg-engine-lock"; engine = Engine.MYSQL; host = "h2"; port = 3306; dbName = "d2" })
        }
        assertEquals(Status.Code.FAILED_PRECONDITION, code)

        val after = core.datasourceStore.getByName("reg-engine-lock")!!
        assertEquals(Engine.POSTGRES, after.engine, "a rejected engine change must not mutate the row")
        assertEquals("h", after.host, "no field is touched by a rejected register, not just engine")
        assertEquals(5432, after.port)
        assertEquals("d", after.dbName)
        assertTrue(core.datasourceStore.catalog(before.id).isNotEmpty(), "a rejected engine change must not invalidate the catalog")
        assertEquals(before.catalogSyncedAt, after.catalogSyncedAt, "catalog_synced_at is retained on a rejected register")
    }

    @Test
    fun `concurrent first registrations with different engines cannot bypass the engine guard`() = runBlocking {
        val name = "reg-race"
        // Fire a POSTGRES and a MYSQL Register for the SAME previously-unseen name at once. `SELECT ... FOR
        // UPDATE` can't lock a row that doesn't exist yet, so both transactions may read prior==null and race
        // the upsert. Exactly one self-creates; the loser's ON CONFLICT DO UPDATE hits the conflict-arm
        // `WHERE datasource.engine = EXCLUDED.engine` guard, which refuses to flip the committed engine — 0
        // rows updated, rejected FAILED_PRECONDITION. (The name advisory lock only serializes them to avoid
        // piling up on the UNIQUE index; the atomic WHERE is what makes the flip impossible.)
        val outcomes = listOf(Engine.POSTGRES, Engine.MYSQL).map { eng ->
            async(Dispatchers.IO) {
                runCatching { stub.register(registerRequest { this.name = name; engine = eng; host = "h"; port = 1; dbName = "d" }) }
            }
        }.awaitAll()

        val winners = outcomes.filter { it.isSuccess }
        val rejected = outcomes.mapNotNull { it.exceptionOrNull() as? StatusException }
        assertEquals(1, winners.size, "exactly one concurrent first-registration may win")
        assertEquals(1, rejected.size, "the losing engine must be rejected, not silently upserted")
        assertEquals(Status.Code.FAILED_PRECONDITION, rejected.single().status.code)
        assertEquals(1, core.datasourceStore.list().count { it.name == name }, "still a single row, never a silent flip")
        val stored = core.datasourceStore.getByName(name)!!.engine
        assertTrue(stored == Engine.POSTGRES || stored == Engine.MYSQL, "the surviving engine is the winner's, intact")
    }

    @Test
    fun `a row racing into an in-flight register cannot bypass the engine guard (cross-writer)`() = runBlocking {
        val name = "reg-cross-writer-race"
        // Deterministic interleaving of the REAL register() against a writer that does NOT enter register (a
        // direct INSERT, modeling an admin create/rename that never takes register's name lock — the exact
        // cross-writer bypass the async Register-vs-Register test above cannot reach). The barrier is a DB
        // lock, not a sleep: `writerConn` stages a POSTGRES row for `name` but leaves it UNCOMMITTED — invisible
        // to register's prior read (MVCC), yet its uncommitted UNIQUE row blocks register's ON CONFLICT upsert.
        // We wait (via pg_stat_activity) until register is PROVABLY parked on that upsert, which means its prior
        // read already ran and saw null (writerConn is still uncommitted) — i.e. the vulnerable window
        // (prior==null while the row exists) is reached. Only THEN do we commit the POSTGRES row: the upsert
        // unblocks, hits the conflict, and the atomic engine guard must reject the MYSQL flip.
        val writerConn = dataSource.connection
        try {
            writerConn.autoCommit = false
            writerConn.prepareStatement(
                "INSERT INTO datasource (name, engine, host, port, db_name, tags) VALUES (?, 'postgres', 'h', 5432, 'app', '[]'::jsonb)",
            ).use { ps -> ps.setString(1, name); ps.executeUpdate() } // staged, uncommitted

            val outcome = async(Dispatchers.IO) {
                runCatching { core.datasourceStore.register(name, Engine.MYSQL, "h2", 3306, "app", emptyList(), "127.0.0.1:3306", null, false) }
            }
            awaitRegisterParkedOnUpsert()

            // register is parked on the upsert with prior==null already observed; releasing the racing row now
            // drives it straight into the conflict-arm engine guard.
            writerConn.commit()

            val result = outcome.await()
            assertTrue(result.isFailure, "a raced-in row must not let register silently flip the engine")
            assertTrue(
                result.exceptionOrNull() is DatasourceEngineConflictException,
                "the cross-writer race must be rejected by the atomic engine guard, got ${result.exceptionOrNull()}",
            )
            val stored = core.datasourceStore.getByName(name)!!
            assertEquals(Engine.POSTGRES, stored.engine, "the raced-in engine survives intact — no silent flip")
            assertEquals(1, core.datasourceStore.list().count { it.name == name }, "still a single row")
        } finally {
            runCatching { writerConn.rollback() }
            writerConn.close()
        }
    }

    /**
     * Block until an in-flight `register` is parked on its ON CONFLICT upsert, waiting on the racing row's
     * lock — proof its prior read already ran (and saw null). Polls `pg_stat_activity` for a backend in THIS
     * database blocked on a Lock while executing the upsert; the DB-level block (not the poll interval) is the
     * real barrier, so this is deterministic rather than timing-dependent.
     */
    private fun awaitRegisterParkedOnUpsert() {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        while (System.nanoTime() < deadline) {
            val parked = dataSource.connection.use { c ->
                c.prepareStatement(
                    """SELECT count(*) FROM pg_stat_activity
                       WHERE datname = current_database()
                         AND wait_event_type = 'Lock'
                         AND query ILIKE '%insert into datasource%on conflict%'""",
                ).use { ps -> ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) } }
            }
            if (parked > 0) return
            Thread.sleep(20)
        }
        error("register never parked on its upsert INSERT — the deterministic interleaving barrier was not reached")
    }

    @Test
    fun `admin update refuses an engine change and invalidates the catalog on a db_name retarget`() = runBlocking {
        val ds = core.datasourceStore.create(
            DatasourceInput(name = "upd-engine-lock", engine = "postgres", host = "h", port = 5432, dbName = "app"),
        )
        stub.pushCatalog(
            catalogRequest {
                datasourceName = "upd-engine-lock"
                defaultSchemas.add("public")
                columns.add(column { schema = "public"; table = "t"; this.column = "c"; dataType = "text"; ordinal = 1; nullable = true })
            },
        )
        // A PUT that flips engine is rejected fail-closed (the admin surface is not a bypass of engine immutability) — the row
        // and its catalog are left untouched, so a stored catalog can never be reinterpreted under a new dialect.
        assertFailsWith<DatasourceEngineConflictException> {
            core.datasourceStore.update(ds.id, DatasourceInput(name = "upd-engine-lock", engine = "mysql", host = "h", port = 5432, dbName = "app"))
        }
        val afterReject = core.datasourceStore.get(ds.id)!!
        assertEquals(Engine.POSTGRES, afterReject.engine, "a rejected admin engine change must not mutate the row")
        assertTrue(core.datasourceStore.catalog(ds.id).isNotEmpty(), "a rejected engine change must not touch the catalog")

        // A same-engine edit that retargets db_name invalidates the stale catalog (fail-closed), exactly as a
        // Register retarget does — the retained catalog now describes a DIFFERENT schema.
        val edited = core.datasourceStore.update(
            ds.id, DatasourceInput(name = "upd-engine-lock", engine = "postgres", host = "h2", port = 5432, dbName = "app2"),
        )!!
        assertEquals("h2", edited.host)
        assertEquals("app2", edited.dbName)
        assertTrue(core.datasourceStore.catalog(ds.id).isEmpty(), "a db_name retarget via admin PUT must invalidate the stale catalog")
        assertEquals(null, edited.catalogSyncedAt, "catalog_synced_at is cleared on invalidation")
    }

    @Test
    fun `re-register with empty tags preserves the existing tags`() = runBlocking {
        stub.register(registerRequest { name = "reg-tags"; engine = Engine.POSTGRES; host = "h"; port = 1; dbName = "d"; tags.add("system:development") })
        stub.register(registerRequest { name = "reg-tags"; engine = Engine.POSTGRES; host = "h2"; port = 1; dbName = "d" }) // no tags
        assertEquals(listOf("system:development"), core.datasourceStore.getByName("reg-tags")!!.tags)
    }

    @Test
    fun `register accepts a free-form tag bag including both postures and custom tags`() = runBlocking {
        // Datasource tags are free-form: there is no exact-one-posture validation. Whatever the proxy sends is
        // stored verbatim (the marshaller later honors only the recognized posture tags; everything else is inert).
        stub.register(
            registerRequest {
                name = "reg-freeform"; engine = Engine.POSTGRES; host = "h"; port = 1; dbName = "d"
                tags.addAll(listOf("system:development", "system:production", "team-x"))
            },
        )
        assertEquals(
            listOf("system:development", "system:production", "team-x"),
            core.datasourceStore.getByName("reg-freeform")!!.tags,
            "a free-form tag bag is stored verbatim, both postures and custom tags alike",
        )
    }

    @Test
    fun `register rejects an unspecified engine INVALID_ARGUMENT`() {
        assertEquals(Status.Code.INVALID_ARGUMENT, statusOf { stub.register(registerRequest { name = "reg-bad"; host = "h"; port = 1; dbName = "d" }) })
        assertNull(core.datasourceStore.getByName("reg-bad"), "a rejected register must not create a row")
    }

    @Test
    fun `register rejects a blank name INVALID_ARGUMENT`() {
        assertEquals(Status.Code.INVALID_ARGUMENT, statusOf { stub.register(registerRequest { name = ""; engine = Engine.POSTGRES; host = "h"; port = 1; dbName = "d" }) })
    }

    @Test
    fun `pushCatalog for an unknown datasource is NOT_FOUND`() {
        assertEquals(
            Status.Code.NOT_FOUND,
            statusOf { stub.pushCatalog(catalogRequest { datasourceName = "never-registered" }) },
        )
    }

    @Test
    fun `pushCatalog stores the proxy-pushed columns and default schemas`() = runBlocking {
        stub.register(registerRequest { name = "reg-cat"; engine = Engine.POSTGRES; host = "h"; port = 1; dbName = "d" })
        val ack = stub.pushCatalog(
            catalogRequest {
                datasourceName = "reg-cat"
                defaultSchemas.addAll(listOf("pg_catalog", "public"))
                engineVersion = "PostgreSQL 16.3 (aurora 16.3)"
                columns.add(column { schema = "public"; table = "users"; this.column = "id"; dataType = "integer"; ordinal = 1; nullable = false })
                columns.add(column { schema = "public"; table = "users"; this.column = "rrn"; dataType = "text"; ordinal = 2; nullable = true })
            },
        )
        assertEquals(2, ack.columns)
        val ds = core.datasourceStore.getByName("reg-cat")!!
        assertEquals(listOf("pg_catalog", "public"), ds.defaultSchemas)
        assertEquals("PostgreSQL 16.3 (aurora 16.3)", ds.engineVersion, "the proxy-pushed engine version is stored for system-classification")
        assertTrue(ds.catalogSyncedAt != null, "catalog_synced_at is stamped on push")
        val cols = core.datasourceStore.catalog(ds.id)
        val rrn = cols.single { it.table == "users" && it.column == "rrn" }
        assertEquals("text", rrn.dataType)
        assertEquals("VARCHAR", rrn.sqlType, "the control-plane derives sql_type from the raw data_type")
    }

    @Test
    fun `pushCatalog re-measures the enforcement catalog, not only the stored one`() = runBlocking {
        // The staleness ceiling is set above the ambient refresh interval on the premise that the refresh
        // keeps enforcement content verified. That premise is a single call in this handler: exercise it
        // through the RPC, because a registry-level test would stay green if the wiring were removed and
        // the refresh went back to feeding only the stored catalog.
        stub.register(registerRequest { name = "reg-ambient"; engine = Engine.MYSQL; host = "h"; port = 1; dbName = "app" })
        val ds = core.datasourceStore.getByName("reg-ambient")!!

        // A connection measures `app` itself, so the control plane holds enforcement content for it.
        val opened = core.connectionCatalog.open(Binding(ds.name, "p", "USER"), listOf("app"))
        val applied = core.connectionCatalog.applyPush(
            schemaFragmentPush {
                connectionId = opened.connectionId
                datasourceName = ds.name
                schema = "app"
                contentHash = ByteString.copyFromUtf8("h1")
                backendGeneration = 1
                columns.add(
                    column { schema = "app"; table = "users"; this.column = "id"; dataType = "bigint"; ordinal = 1; nullable = false },
                )
            },
            ds,
        )
        assertIs<CatalogMutationResult.Applied>(applied)
        val measuredBefore = core.connectionCatalog.measuredNanosFor(ds.name, "app")!!

        // The ambient refresh reports the same content for that schema.
        stub.pushCatalog(
            catalogRequest {
                datasourceName = ds.name
                defaultSchemas.add("app")
                columns.add(
                    column { schema = "app"; table = "users"; this.column = "id"; dataType = "bigint"; ordinal = 1; nullable = false },
                )
            },
        )

        // The recorded measurement time must have MOVED. Asserting that instead of "the adopter looks
        // fresh" is deliberate: the adopter would look fresh anyway from the original measurement seconds
        // earlier, so a freshness assertion holds even with this handler unwired and proves nothing.
        val afterAmbient = core.connectionCatalog.measuredNanosFor(ds.name, "app")
        assertNotNull(afterAmbient, "the enforcement entry must survive the push")
        assertTrue(
            afterAmbient > measuredBefore,
            "pushCatalog must record its read against the enforcement catalog " +
                "(before=$measuredBefore after=$afterAmbient)",
        )

        // The push confirms content; it never installs it.
        val adopter = core.connectionCatalog.open(
            Binding(ds.name, "later", "USER"), listOf("app"), adoptHeldContent = true,
        )
        assertTrue(adopter.onOpen.isEmpty(), "the ambient push must leave the adopter with nothing to fetch")
        assertEquals(
            listOf("id"),
            core.connectionCatalog.structuralRows(
                core.connectionCatalog.find(adopter.connectionId)!!,
            ).map { it.column },
        )
    }

    @Test
    fun `re-register with the same target preserves the catalog and updates advisory fields`() = runBlocking {
        // A row pre-provisioned via the admin form (name + advisory connection fields only — no creds
        // exist anymore), plus a catalog.
        val ds = core.datasourceStore.create(
            DatasourceInput(name = "reg-preserve", engine = "postgres", host = "h", port = 5432, dbName = "app"),
        )
        stub.pushCatalog(
            catalogRequest {
                datasourceName = "reg-preserve"
                defaultSchemas.add("public")
                columns.add(column { schema = "public"; table = "keep"; this.column = "c"; dataType = "text"; ordinal = 1; nullable = true })
            },
        )
        // A proxy self-registers by the same name, same engine+db, host moved. The catalog survives because
        // engine+db_name are unchanged (only advisory host moved); the advisory host is refreshed.
        stub.register(registerRequest { name = "reg-preserve"; engine = Engine.POSTGRES; host = "h2"; port = 5432; dbName = "app" })
        val after = core.datasourceStore.getByName("reg-preserve")!!
        assertEquals("h2", after.host, "advisory host is still updated")
        assertTrue(core.datasourceStore.catalog(ds.id).any { it.table == "keep" }, "same-target re-register must not wipe the catalog")
        assertTrue(after.catalogSyncedAt != null, "catalog_synced_at is retained on a same-target re-register")
    }

    @Test
    fun `re-register to a different schema invalidates the stale catalog (fail-closed)`() = runBlocking {
        stub.register(registerRequest { name = "reg-retarget"; engine = Engine.POSTGRES; host = "h"; port = 5432; dbName = "db_a" })
        stub.pushCatalog(
            catalogRequest {
                datasourceName = "reg-retarget"
                defaultSchemas.add("public")
                columns.add(column { schema = "public"; table = "old_table"; this.column = "c"; dataType = "text"; ordinal = 1; nullable = true })
            },
        )
        val ds = core.datasourceStore.getByName("reg-retarget")!!
        assertTrue(core.datasourceStore.catalog(ds.id).isNotEmpty())

        // Reuse the name for a DIFFERENT database — the old catalog describes the wrong schema now, so it must
        // be dropped and catalog_synced_at cleared until a fresh push lands (decisions fail closed meanwhile).
        stub.register(registerRequest { name = "reg-retarget"; engine = Engine.POSTGRES; host = "h"; port = 5432; dbName = "db_b" })
        val after = core.datasourceStore.getByName("reg-retarget")!!
        assertEquals("db_b", after.dbName)
        assertTrue(core.datasourceStore.catalog(ds.id).isEmpty(), "a retarget must invalidate the stale catalog")
        assertEquals(null, after.catalogSyncedAt, "catalog_synced_at is cleared on invalidation")
        assertTrue(after.defaultSchemas.isEmpty(), "default_schemas is cleared on invalidation")
    }

    @Test
    fun `pushCatalog rolls back a mid-batch failure and keeps the prior catalog`() = runBlocking {
        stub.register(registerRequest { name = "reg-rollback"; engine = Engine.POSTGRES; host = "h"; port = 1; dbName = "d" })
        stub.pushCatalog(
            catalogRequest {
                datasourceName = "reg-rollback"
                defaultSchemas.add("public")
                columns.add(column { schema = "public"; table = "orig"; this.column = "c"; dataType = "text"; ordinal = 1; nullable = true })
            },
        )
        val ds = core.datasourceStore.getByName("reg-rollback")!!
        // Two columns with the same (schema, table, column) trip the UNIQUE constraint on the second insert —
        // AFTER the DELETE — so the whole push must roll back, leaving the prior catalog intact.
        val code = statusOf {
            stub.pushCatalog(
                catalogRequest {
                    datasourceName = "reg-rollback"
                    defaultSchemas.add("public")
                    columns.add(column { schema = "public"; table = "dup"; this.column = "x"; dataType = "text"; ordinal = 1; nullable = true })
                    columns.add(column { schema = "public"; table = "dup"; this.column = "x"; dataType = "text"; ordinal = 2; nullable = true })
                },
            )
        }
        assertTrue(code != Status.Code.OK, "a duplicate-column push must fail, not silently succeed")
        val cols = core.datasourceStore.catalog(ds.id)
        assertTrue(cols.any { it.table == "orig" }, "the prior catalog must survive a rolled-back push")
        assertTrue(cols.none { it.table == "dup" }, "no partial rows from the failed push may remain")
    }

    @Test
    fun `pushCatalog replaces the prior catalog (delete-then-insert)`() = runBlocking {
        stub.register(registerRequest { name = "reg-replace"; engine = Engine.POSTGRES; host = "h"; port = 1; dbName = "d" })
        stub.pushCatalog(
            catalogRequest {
                datasourceName = "reg-replace"
                defaultSchemas.add("public")
                columns.add(column { schema = "public"; table = "a"; this.column = "x"; dataType = "integer"; ordinal = 1; nullable = true })
                columns.add(column { schema = "public"; table = "b"; this.column = "y"; dataType = "integer"; ordinal = 1; nullable = true })
            },
        )
        val ack = stub.pushCatalog(
            catalogRequest {
                datasourceName = "reg-replace"
                defaultSchemas.add("public")
                columns.add(column { schema = "public"; table = "a"; this.column = "x"; dataType = "integer"; ordinal = 1; nullable = true })
            },
        )
        assertEquals(1, ack.columns)
        val ds = core.datasourceStore.getByName("reg-replace")!!
        val cols = core.datasourceStore.catalog(ds.id)
        assertTrue(cols.none { it.table == "b" }, "the replaced catalog must not retain table b")
        assertEquals(1, cols.count { it.table == "a" })
    }

    @Test
    fun `pushCatalog replacement preserves classification for a surviving column identity`() = runBlocking {
        stub.register(registerRequest { name = "reg-replace-classified"; engine = Engine.POSTGRES; host = "h"; port = 1; dbName = "d" })
        stub.pushCatalog(
            catalogRequest {
                datasourceName = "reg-replace-classified"
                defaultSchemas.add("public")
                columns.add(column { schema = "public"; table = "users"; this.column = "rrn"; dataType = "text"; ordinal = 1; nullable = false })
                columns.add(column { schema = "public"; table = "users"; this.column = "display_name"; dataType = "text"; ordinal = 2; nullable = true })
            },
        )
        val ds = core.datasourceStore.getByName("reg-replace-classified")!!
        dataSource.connection.use { c ->
            c.prepareStatement(
                """INSERT INTO column_classification
                   (datasource_id, schema_name, table_name, column_name, tags)
                   VALUES (?, 'public', 'users', 'rrn', '["pii","government-id"]'::jsonb)""",
            ).use { ps ->
                ps.setLong(1, ds.id)
                ps.executeUpdate()
            }
        }

        stub.pushCatalog(
            catalogRequest {
                datasourceName = "reg-replace-classified"
                defaultSchemas.add("public")
                columns.add(column { schema = "public"; table = "users"; this.column = "rrn"; dataType = "text"; ordinal = 1; nullable = false })
                columns.add(column { schema = "public"; table = "users"; this.column = "display_name"; dataType = "character varying"; ordinal = 2; nullable = false })
                columns.add(column { schema = "public"; table = "users"; this.column = "created_at"; dataType = "timestamp"; ordinal = 3; nullable = false })
            },
        )

        val rrn = core.datasourceStore.catalog(ds.id).single { it.schema == "public" && it.table == "users" && it.column == "rrn" }
        val classification = assertNotNull(rrn.classification, "the surviving rrn identity must stay attached to its classification")
        assertEquals(listOf("pii", "government-id"), classification.tags)
    }
}
