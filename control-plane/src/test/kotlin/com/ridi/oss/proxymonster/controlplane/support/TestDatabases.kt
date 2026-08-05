package com.ridi.oss.proxymonster.controlplane.support

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.MySQLContainer
import org.testcontainers.containers.PostgreSQLContainer
import java.sql.DriverManager
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/**
 * Gate DB-backed tests on Docker. Normally these skip when Docker is unavailable (so the suite stays
 * runnable on machines without it), but a CI that MUST run them can set `PM_REQUIRE_DB_TESTS=true` to
 * turn "Docker not available" into a hard failure — the security regression tests can't silently pass
 * by skipping.
 */
fun requireDockerOrSkip() {
    val available = DockerClientFactory.instance().isDockerAvailable
    if (System.getenv("PM_REQUIRE_DB_TESTS") == "true") {
        assertTrue(available, "PM_REQUIRE_DB_TESTS=true but no Docker environment was found for the DB-backed tests")
    } else {
        assumeTrue(available, "Docker not available — skipping DB-backed tests")
    }
}

/** Hard gate for the DB-backed security tests: missing Docker is a test failure, never a skip. */
fun requireDocker() {
    assertTrue(
        DockerClientFactory.instance().isDockerAvailable,
        "Docker is required for the per-connection-catalog DB-backed security tests",
    )
}

/**
 * The container image a shared test database runs. Defaults to the newest supported series so a plain
 * `gradlew test` covers the version most installs will be on; `PM_TEST_POSTGRES_IMAGE` /
 * `PM_TEST_MYSQL_IMAGE` override it, which is how one CI matrix leg pins one version. The supported set
 * itself lives in `db-support.json` at the repo root — see [DbSupportMatrixTest].
 */
private fun imageFor(envVar: String, default: String): String =
    System.getenv(envVar)?.takeIf { it.isNotBlank() } ?: default

/**
 * The version series an image tag names (`mysql:8.0` → `8.0`, `postgres:16-alpine` → `16`), or null
 * when the tag pins no version (`latest`, or no tag at all). The tag is what follows the last colon
 * only if that colon comes after the last slash — otherwise the colon belongs to a registry port, so
 * `localhost:5000/postgres` has no tag. A variant suffix (`16-alpine`) is dropped so the series
 * compares against what the server reports.
 */
internal fun imageSeries(image: String): String? {
    val colon = image.lastIndexOf(':')
    if (colon <= image.lastIndexOf('/')) return null
    val tag = image.substring(colon + 1).substringBefore('-')
    return tag.takeIf { it.isNotEmpty() && it.first().isDigit() }
}

/**
 * Fail the test if [actual], the version string the live server reported, is not in the series
 * [expected] names. A matrix leg that silently fell back to another version would otherwise report a
 * pass for a version it never ran, which is indistinguishable from real coverage.
 */
internal fun assertServerSeries(image: String, expected: String?, actual: String) {
    // Nothing to check when the image pins no version; the declaration guard is what refuses to let a
    // supported version be declared with such an image in the first place.
    val want = expected ?: return
    assertTrue(
        actual == want || actual.startsWith("$want."),
        "image $image should serve a $want.x server but it reported $actual — the matrix leg is not testing the version it claims",
    )
}

/**
 * Let a finished test class's pool give its connections back to the shared container.
 *
 * Every DB-backed test class opens a pool in `@BeforeAll` and never closes it, so without this a class
 * keeps [HikariConfig.getMinimumIdle] connections (defaulted to the max) for the rest of the JVM's life
 * and the suite's peak is the sum over *all* classes, not the ones actually running. Classes execute
 * sequentially in one JVM, so holding them idle buys nothing while the sum climbs toward the server's
 * `max_connections` — which surfaces in whichever class happens to start next as
 * "FATAL: sorry, too many clients already", not in the one that leaked.
 */
private fun HikariConfig.applyTestPoolReclaim() {
    minimumIdle = 0
    idleTimeout = 10_000
}

/**
 * Shared Testcontainers-backed databases for DB-backed unit tests.
 *
 * Each engine's container is started **once, lazily, and reused across every test in the module**
 * (a singleton object that never calls stop() — the Testcontainers/Ryuk reaper tears it down at JVM
 * exit). Starting a database container is the expensive part (~seconds); reusing it keeps the whole
 * DB-backed suite fast. Per-test isolation comes from a fresh logical database, not a fresh container.
 */
object SharedPostgres {
    val IMAGE: String = imageFor("PM_TEST_POSTGRES_IMAGE", "postgres:17")
    private val counter = AtomicInteger()

    private val container: PostgreSQLContainer<*> by lazy {
        // Generous max_connections: every DB-backed test class opens its own pool against this ONE shared
        // container, and no pool is ever closed, so the suite's ceiling scales with the number of DB test
        // classes rather than with how many run at once. This is test-infra headroom only.
        PostgreSQLContainer(IMAGE).apply { withCommand("postgres", "-c", "max_connections=500"); start() }
    }

    /** Create a fresh, uniquely-named database in the shared container and return its name. */
    fun freshDatabase(prefix: String): String {
        val name = "${prefix}_${counter.incrementAndGet()}"
        adminConnection().use { c ->
            c.createStatement().use { it.executeUpdate("CREATE DATABASE \"$name\"") }
        }
        return name
    }

    fun hikari(dbName: String): DataSource = HikariDataSource(
        HikariConfig().apply {
            jdbcUrl = jdbcUrlFor(dbName)
            username = container.username
            password = container.password
            driverClassName = "org.postgresql.Driver"
            maximumPoolSize = 4
            applyTestPoolReclaim()
        },
    )

    fun jdbcUrlFor(dbName: String): String = "jdbc:postgresql://${container.host}:${container.getMappedPort(5432)}/$dbName"

    /** `server_version` as the major series alone ("17"), for asserting which version a run covered. */
    fun serverSeries(): String = adminConnection().use { c ->
        c.createStatement().use { st ->
            st.executeQuery("SHOW server_version").use { rs ->
                check(rs.next()) { "Postgres server_version probe returned no row" }
                rs.getString(1).trim().substringBefore('.').substringBefore(' ')
            }
        }
    }

    fun host(): String = container.host
    fun port(): Int = container.getMappedPort(5432)
    fun username(): String = container.username
    fun password(): String = container.password

    private fun adminConnection() =
        DriverManager.getConnection(container.jdbcUrl, container.username, container.password)
}

object SharedMySql {
    val IMAGE: String = imageFor("PM_TEST_MYSQL_IMAGE", "mysql:8.4")
    private val counter = AtomicInteger()

    /**
     * MySQL 8.4 ships `mysql_native_password` DISABLED, so `IDENTIFIED WITH mysql_native_password`
     * is a hard error (1524) there while it still works on 8.0. Tests that need a service account with
     * a known auth plugin ask for this instead of naming a plugin, so one test body covers both series.
     */
    val defaultAuthPlugin: String
        get() = if (nativePasswordAvailable) "mysql_native_password" else "caching_sha2_password"

    private val nativePasswordAvailable: Boolean by lazy {
        adminConnection().use { c ->
            c.createStatement().use { st ->
                st.executeQuery(
                    "SELECT plugin_status FROM information_schema.plugins WHERE plugin_name = 'mysql_native_password'",
                ).use { rs -> rs.next() && rs.getString(1).equals("ACTIVE", ignoreCase = true) }
            }
        }
    }

    /** `VERSION()` as the major.minor series alone ("8.4"), for asserting which version a run covered. */
    fun serverSeries(): String = adminConnection().use { c ->
        c.createStatement().use { st ->
            st.executeQuery("SELECT VERSION()").use { rs ->
                check(rs.next()) { "MySQL VERSION() probe returned no row" }
                rs.getString(1).split('.').take(2).joinToString(".")
            }
        }
    }

    private val container: MySQLContainer<*> by lazy {
        MySQLContainer(IMAGE).apply { start() }
    }

    /** The container's original database, retained for the older single-schema fixtures. */
    fun defaultDatabase(): String = container.databaseName

    /**
     * Create a fresh database and grant the container's normal test user access to it. The root
     * connection is deliberately confined to this Testcontainers helper; production datasource
     * credentials remain the non-root service user returned by [username].
     */
    fun freshDatabase(prefix: String): String {
        require(prefix.matches(Regex("[a-zA-Z][a-zA-Z0-9_]*"))) { "unsafe MySQL database prefix: $prefix" }
        val name = "${prefix}_${counter.incrementAndGet()}"
        adminConnection().use { c ->
            c.createStatement().use { st ->
                st.executeUpdate("CREATE DATABASE `$name`")
                st.executeUpdate("GRANT ALL PRIVILEGES ON `$name`.* TO '${container.username}'@'%'")
            }
        }
        return name
    }

    fun jdbcUrlFor(dbName: String): String =
        "jdbc:mysql://${container.host}:${container.getMappedPort(3306)}/$dbName?allowPublicKeyRetrieval=true&sslMode=DISABLED"

    fun hikari(dbName: String): DataSource = HikariDataSource(
        HikariConfig().apply {
            jdbcUrl = jdbcUrlFor(dbName)
            username = container.username
            password = container.password
            driverClassName = "com.mysql.cj.jdbc.Driver"
            maximumPoolSize = 4
            applyTestPoolReclaim()
        },
    )

    fun host(): String = container.host
    fun port(): Int = container.getMappedPort(3306)
    fun username(): String = container.username
    fun password(): String = container.password

    /** MySQLContainer configures root with the same generated test password. */
    private fun adminConnection() = DriverManager.getConnection(jdbcUrlFor("mysql"), "root", container.password)
}
