package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.tempColumn
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Trust gates on the proxy-supplied temp overlay ([editorTempOverlay]). A temp overlay column is
 * read UNMASKED and skips the uncovered-scan gate, so BOTH gates that keep a hostile/buggy proxy from turning
 * that into an exfiltration primitive are load-bearing and must be pinned: the EDITOR-channel gate and the
 * `pg_temp*` schema filter. (Pure — no DB/gRPC server needed, so it runs everywhere.)
 */
class GrpcTempOverlayTest {
    private fun temp(schema: String, table: String = "scratch", column: String = "secret", catalog: String = "appdb") = tempColumn {
        this.catalog = catalog
        this.schema = schema
        this.table = table
        this.column = column
        this.sqlType = "text"
        this.ordinal = 1
    }

    @Test
    fun `an editor pg_temp column is overlaid under the pg database catalog as a temp`() {
        val out = editorTempOverlay(Channel.EDITOR, Engine.POSTGRES, listOf(temp("pg_temp_3")))
        assertEquals(1, out.size)
        val c = out.single()
        assertTrue(c.isTemp, "an overlaid session temp must be flagged isTemp (reads unmasked)")
        assertEquals("appdb", c.catalog, "the overlay keeps the catalog the proxy inspected")
        assertEquals("pg_temp_3", c.schema)
        assertEquals("scratch", c.table)
    }

    @Test
    fun `a non-pg_temp overlay entry is DROPPED — a proxy cannot mislabel a real table as a temp`() {
        // The whole point of the filter: a compromised/buggy proxy claiming public.users (or a system schema)
        // is a temp would otherwise read a real, masked table UNMASKED. It must be dropped.
        val out = editorTempOverlay(
            Channel.EDITOR,
            Engine.POSTGRES,
            listOf(temp("public", table = "users"), temp("pg_catalog"), temp("information_schema")),
        )
        assertTrue(out.isEmpty(), "only pg_temp* schemas may be overlaid unmasked; got $out")
    }

    @Test
    fun `a mixed batch keeps only the pg_temp entries`() {
        val out = editorTempOverlay(
            Channel.EDITOR,
            Engine.POSTGRES,
            listOf(temp("public", table = "real"), temp("pg_temp_5", table = "mine")),
        )
        assertEquals(listOf("mine"), out.map { it.table }, "the real-schema entry must be dropped, the temp kept")
    }

    @Test
    fun `temps are dropped on every non-editor channel`() {
        // Only a persistent editor session legitimately carries session temps. A wire/workflow decision with
        // temp_columns is a buggy/compromised proxy — the overlay must be empty regardless of the schema.
        for (ch in listOf(Channel.WIRE, Channel.WORKFLOW_EXECUTOR, Channel.WORKFLOW_VIEWER)) {
            val out = editorTempOverlay(ch, Engine.POSTGRES, listOf(temp("pg_temp_3")))
            assertTrue(out.isEmpty(), "a session-temp overlay must never apply on the $ch channel; got $out")
        }
    }

    @Test
    fun `only the engine's exact temp schema is overlaid`() {
        // A MySQL database may be named pg_temp_1, and a quoted Postgres "PG_TEMP_1" is a user schema.
        assertTrue(editorTempOverlay(Channel.EDITOR, Engine.MYSQL, listOf(temp("pg_temp_1", catalog = "def"))).isEmpty())
        assertTrue(editorTempOverlay(Channel.EDITOR, Engine.POSTGRES, listOf(temp("PG_TEMP_1"), temp("pg_tempx"))).isEmpty())
        assertEquals(1, editorTempOverlay(Channel.EDITOR, Engine.POSTGRES, listOf(temp("pg_temp"))).size)
    }
}
