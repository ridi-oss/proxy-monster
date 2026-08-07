package com.ridi.oss.proxymonster.controlplane

import java.nio.file.Path
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.name
import kotlin.io.path.readLines
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * An applied migration is immutable, and Flyway enforces that by checksumming the whole file —
 * comments included. So a comment that names something outside the file is a tripwire: renaming that
 * thing is a routine edit everywhere else in the tree, but here it changes the checksum of an
 * already-applied migration, `validateOnMigrate` refuses, and control-plane startup aborts before it
 * opens a port. Every existing install stops booting until an operator repairs `flyway_schema_history`
 * by hand.
 *
 * That is not hypothetical. A tree-wide doc-path rewrite once edited the comment headers of seven
 * shipped migrations, and every control plane already carrying them refused to boot on its next
 * start — over nine lines that no code reads and that Flyway only sees as bytes.
 *
 * The reference is a liability with no upside: nothing resolves it at migration time, and a reader
 * already has the schema in front of them. So a migration comment must stand alone — describe what the
 * schema is, not where to read about it. Context that lives elsewhere belongs in `docs/` or in a new
 * migration.
 *
 * This is a unit test rather than a CI-only shell check so it fails on the machine of whoever makes the
 * edit, before it can reach main. The migrations are inside this module's own resources, so Gradle
 * already tracks them as task inputs and cannot report a stale pass when one changes.
 */
class MigrationSelfContainmentTest {
    private val migrationDir: Path =
        Path.of("src/main/resources/db/migration").toAbsolutePath().normalize()

    /**
     * A path, doc, or URL in a migration. Deliberately broad — every form is equally a checksum
     * liability, and a narrow pattern would just move the tripwire rather than remove it.
     */
    private val forbidden = listOf(
        Regex("""\.md\b""") to "a doc filename",
        Regex("""https?://""") to "a URL",
        Regex("""(?<![A-Za-z])(?:tasks|docs)/""") to "a repository path",
        Regex("""\.(?:kts?|go|tsx?)\b""") to "a source filename",
    )

    // The version is the digits after the leading V, before the "__" description.
    private val versionOf = Regex("""^V(\d+)__""")

    private fun sqlFiles(): List<Path> =
        migrationDir.listDirectoryEntries("V*.sql").sortedBy { it.name }

    @Test
    fun `every migration is self-contained`() {
        val files = sqlFiles()
        // A directory that resolved to the wrong place, or a glob that matched nothing, would make an
        // empty result read exactly like a clean tree. Assert we actually looked at the migrations.
        assertTrue(
            files.size >= 8,
            "expected the shipped migrations under $migrationDir, found ${files.size}",
        )

        val violations = files.flatMap { file ->
            file.readLines().withIndex().flatMap { (i, line) ->
                forbidden.mapNotNull { (pattern, what) ->
                    pattern.find(line)?.let {
                        "${file.name}:${i + 1} contains $what (\"${it.value}\"): ${line.trim()}"
                    }
                }
            }
        }

        assertTrue(
            violations.isEmpty(),
            buildString {
                append("A migration must not reference anything outside itself, because Flyway ")
                append("checksums the whole file and a later rename of the referenced path then stops ")
                append("every existing database from booting.\n\n")
                violations.forEach { appendLine("  $it") }
                append("\nWrite the comment so it stands alone: say what the schema is, not where to ")
                append("read about it. See docs/migrations.md.")
            },
        )
    }

    @Test
    fun `the guard rejects the reference forms that break a database`() {
        // Without this, the test above passes whether or not its patterns work — a clean tree and a
        // broken matcher are indistinguishable. These include the form that has broken a control
        // plane, plus the other forms someone would reach for next.
        val mustFail = listOf(
            "-- The Cedar policy store (docs/policy-store.md, docs/authz-model.md).",
            "-- The audit trail (docs/audit-trail-hardening.md).",
            "-- See migrations.md for the rule.",
            "-- https://docs.cedarpolicy.com",
            "-- Mirrors Db.kt behaviour.",
        )
        mustFail.forEach { line ->
            assertTrue(
                forbidden.any { (pattern, _) -> pattern.containsMatchIn(line) },
                "the guard would have allowed a known-bad comment: $line",
            )
        }

        // And it must not fire on ordinary prose, or it would be switched off rather than obeyed.
        val mustPass = listOf(
            "-- The Cedar policy store.",
            "-- One row per audited event, keyed by decision_id.",
            "-- Deny-by-default: a clean install has no usable admin until seeded.",
            "-- 3. the derived context.tags the request earned.",
        )
        mustPass.forEach { line ->
            assertTrue(
                forbidden.none { (pattern, _) -> pattern.containsMatchIn(line) },
                "the guard fires on an ordinary comment: $line",
            )
        }
    }

    @Test
    fun `no two migrations share a version`() {
        val files = sqlFiles()
        assertTrue(
            files.size >= 8,
            "expected the shipped migrations under $migrationDir, found ${files.size}",
        )
        // Flyway refuses to migrate when two files carry the same version ("Found more than one migration
        // with version N"), aborting control-plane startup — but only at migrate() time, in the
        // Docker-backed tests or against a real database. Two branches each adding a V<n> merge cleanly and
        // slip past the append-only CI guard (both are adds), so catch a collision here: fast, no container,
        // on the author's machine before merge.
        val byVersion = files.groupBy { file ->
            versionOf.find(file.name)?.groupValues?.get(1)
                ?: error("migration ${file.name} is not named V<n>__<description>.sql")
        }
        val collisions = byVersion.filterValues { it.size > 1 }
        assertTrue(
            collisions.isEmpty(),
            buildString {
                append("Two or more migrations share a version. Flyway will refuse to migrate, stopping every ")
                append("database from booting; renumber one to the next free version.\n")
                collisions.toSortedMap().forEach { (v, fs) -> appendLine("  V$v: ${fs.map { it.name }.sorted()}") }
            },
        )
    }

    @Test
    fun `the version guard detects a collision`() {
        // Without this, the check above passes whether or not its version parsing works — a unique tree and a
        // broken matcher look identical. This also pins that V1 and V10 are distinct (not substring-confused).
        val names = listOf("V1__a.sql", "V2__b.sql", "V2__c.sql", "V10__d.sql")
        val byVersion = names.groupBy { versionOf.find(it)?.groupValues?.get(1) }
        assertEquals(
            setOf("2"),
            byVersion.filterValues { it.size > 1 }.keys,
            "the guard should flag exactly the shared version (2), and not confuse V1 with V10",
        )
    }
}
