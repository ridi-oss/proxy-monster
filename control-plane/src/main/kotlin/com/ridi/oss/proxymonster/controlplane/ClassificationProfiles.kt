package com.ridi.oss.proxymonster.controlplane

import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.sql.Connection
import javax.sql.DataSource

/**
 * A named, reusable set of column classification rules several datasources share.
 *
 * Resolution against a datasource happens in [DatasourceStore.classificationsFor], which unions a
 * profile's rules with the datasource's own `column_classification` rows.
 */
@Serializable
data class ClassificationProfile(
    val id: Long,
    val name: String,
    val description: String? = null,
    val ruleCount: Int = 0,
    val attachedDatasources: List<String> = emptyList(),
)

@Serializable
data class ClassificationProfileInput(
    val name: String,
    val description: String? = null,
)

@Serializable
data class ClassificationProfileRule(
    val id: Long,
    val schema: String,
    val table: String,
    val column: String,
    val tags: List<String> = emptyList(),
    val maskFnId: Long? = null,
    val maskFnName: String? = null,
)

/**
 * A rule write. Unlike a datasource classification, `schema` is required: a profile belongs to no one
 * datasource, so there is no introspected default schema to resolve a null against.
 */
@Serializable
data class ClassificationProfileRuleInput(
    val schema: String,
    val table: String,
    val column: String,
    val tags: List<String> = emptyList(),
    val maskFnId: Long? = null,
)

@Serializable
data class ClassificationProfileRuleDelete(
    val schema: String,
    val table: String,
    val column: String,
)

@Serializable
data class ProfileAttachment(
    val datasource: String,
    val profile: String,
    val precedence: Int,
)

@Serializable
data class ProfileAttachmentInput(
    val profile: String,
    val precedence: Int = 0,
)

class ClassificationProfileStore(internal val dataSource: DataSource) {
    private val json = Json
    private val stringList = ListSerializer(String.serializer())

    fun list(): List<ClassificationProfile> = dataSource.connection.use { c -> list(c) }

    fun list(c: Connection): List<ClassificationProfile> = c.prepareStatement(
        """SELECT p.id, p.name, p.description,
                  (SELECT count(*) FROM classification_profile_rule r WHERE r.profile_id = p.id) AS rule_count,
                  COALESCE(
                      (SELECT array_agg(d.name ORDER BY d.name)
                       FROM datasource_classification_profile dcp
                       JOIN datasource d ON d.id = dcp.datasource_id
                       WHERE dcp.profile_id = p.id),
                      '{}'
                  ) AS attached
           FROM classification_profile p
           ORDER BY p.name""",
    ).use { ps ->
        ps.executeQuery().use { rs ->
            val out = ArrayList<ClassificationProfile>()
            while (rs.next()) out += rs.toProfile()
            out
        }
    }

    fun getByName(name: String): ClassificationProfile? = dataSource.connection.use { c -> getByName(name, c) }

    fun getByName(name: String, c: Connection): ClassificationProfile? = c.prepareStatement(
        """SELECT p.id, p.name, p.description,
                  (SELECT count(*) FROM classification_profile_rule r WHERE r.profile_id = p.id) AS rule_count,
                  COALESCE(
                      (SELECT array_agg(d.name ORDER BY d.name)
                       FROM datasource_classification_profile dcp
                       JOIN datasource d ON d.id = dcp.datasource_id
                       WHERE dcp.profile_id = p.id),
                      '{}'
                  ) AS attached
           FROM classification_profile p
           WHERE p.name = ?""",
    ).use { ps ->
        ps.setString(1, name)
        ps.executeQuery().use { rs -> if (rs.next()) rs.toProfile() else null }
    }

    fun create(input: ClassificationProfileInput, c: Connection): ClassificationProfile = c.prepareStatement(
        "INSERT INTO classification_profile (name, description) VALUES (?, ?) RETURNING id",
    ).use { ps ->
        ps.setString(1, input.name)
        ps.setString(2, input.description)
        ps.executeQuery().use { rs ->
            rs.next()
            ClassificationProfile(rs.getLong("id"), input.name, input.description)
        }
    }

    fun update(id: Long, input: ClassificationProfileInput, c: Connection): Boolean = c.prepareStatement(
        "UPDATE classification_profile SET name = ?, description = ?, updated_at = now() WHERE id = ?",
    ).use { ps ->
        ps.setString(1, input.name)
        ps.setString(2, input.description)
        ps.setLong(3, id)
        ps.executeUpdate() > 0
    }

    /**
     * Take the profile row's write lock so an attachment cannot commit between a caller's
     * attached-check and its delete. Under READ COMMITTED the check alone sees a snapshot that a
     * concurrent attach invalidates; an INSERT on the attachment takes FOR KEY SHARE on this row, so
     * this blocks until that transaction resolves and the re-read then observes it.
     */
    fun lockForDelete(id: Long, c: Connection) {
        c.prepareStatement("SELECT id FROM classification_profile WHERE id = ? FOR UPDATE").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { it.next() }
        }
    }

    fun delete(id: Long, c: Connection): Boolean =
        c.prepareStatement("DELETE FROM classification_profile WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeUpdate() > 0
        }

    fun listRules(profileId: Long, c: Connection): List<ClassificationProfileRule> = c.prepareStatement(
        """SELECT r.id, r.schema_name, r.table_name, r.column_name, r.tags, r.mask_fn_id,
                  m.name AS mask_fn_name
           FROM classification_profile_rule r
           LEFT JOIN mask_fn m ON m.id = r.mask_fn_id
           WHERE r.profile_id = ?
           ORDER BY r.schema_name, r.table_name, r.column_name""",
    ).use { ps ->
        ps.setLong(1, profileId)
        ps.executeQuery().use { rs ->
            val out = ArrayList<ClassificationProfileRule>()
            while (rs.next()) {
                out += ClassificationProfileRule(
                    id = rs.getLong("id"),
                    schema = rs.getString("schema_name"),
                    table = rs.getString("table_name"),
                    column = rs.getString("column_name"),
                    tags = json.decodeFromString(stringList, rs.getString("tags")),
                    maskFnId = rs.getLong("mask_fn_id").let { if (rs.wasNull()) null else it },
                    maskFnName = rs.getString("mask_fn_name"),
                )
            }
            out
        }
    }

    fun upsertRule(profileId: Long, input: ClassificationProfileRuleInput, c: Connection): ClassificationProfileRule {
        // Backstop the service-layer check, matching DatasourceStore.upsertClassification: a profile rule
        // is a third write path into the same tag field, and the `system:` namespace belongs to the
        // shipped classification manifests on every one of them.
        input.tags.firstOrNull { it.startsWith(DatasourceStore.RESERVED_TAG_PREFIX) }?.let {
            throw IllegalArgumentException(
                "tag '$it' is reserved: the '${DatasourceStore.RESERVED_TAG_PREFIX}' namespace is owned by system classification",
            )
        }
        val id = c.prepareStatement(
            """INSERT INTO classification_profile_rule
               (profile_id, schema_name, table_name, column_name, tags, mask_fn_id, updated_at)
               VALUES (?, ?, ?, ?, ?::jsonb, ?, now())
               ON CONFLICT (profile_id, schema_name, table_name, column_name)
               DO UPDATE SET tags = EXCLUDED.tags, mask_fn_id = EXCLUDED.mask_fn_id, updated_at = now()
               RETURNING id""",
        ).use { ps ->
            ps.setLong(1, profileId)
            ps.setString(2, input.schema)
            ps.setString(3, input.table)
            ps.setString(4, input.column)
            ps.setString(5, json.encodeToString(stringList, input.tags))
            if (input.maskFnId == null) ps.setNull(6, java.sql.Types.BIGINT) else ps.setLong(6, input.maskFnId)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong("id") }
        }
        return ClassificationProfileRule(
            id, input.schema, input.table, input.column, input.tags, input.maskFnId,
            maskFnName(input.maskFnId, c),
        )
    }

    fun deleteRule(profileId: Long, schema: String, table: String, column: String, c: Connection): Boolean =
        c.prepareStatement(
            """DELETE FROM classification_profile_rule
               WHERE profile_id = ? AND schema_name = ? AND table_name = ? AND column_name = ?""",
        ).use { ps ->
            ps.setLong(1, profileId)
            ps.setString(2, schema)
            ps.setString(3, table)
            ps.setString(4, column)
            ps.executeUpdate() > 0
        }

    fun attach(datasourceId: Long, profileId: Long, precedence: Int, c: Connection): Boolean = c.prepareStatement(
        """INSERT INTO datasource_classification_profile (datasource_id, profile_id, precedence)
           VALUES (?, ?, ?)
           ON CONFLICT (datasource_id, profile_id) DO UPDATE SET precedence = EXCLUDED.precedence""",
    ).use { ps ->
        ps.setLong(1, datasourceId)
        ps.setLong(2, profileId)
        ps.setInt(3, precedence)
        ps.executeUpdate() > 0
    }

    fun detach(datasourceId: Long, profileId: Long, c: Connection): Boolean = c.prepareStatement(
        "DELETE FROM datasource_classification_profile WHERE datasource_id = ? AND profile_id = ?",
    ).use { ps ->
        ps.setLong(1, datasourceId)
        ps.setLong(2, profileId)
        ps.executeUpdate() > 0
    }

    fun listAttachments(datasourceId: Long, c: Connection): List<ProfileAttachment> = c.prepareStatement(
        """SELECT d.name AS datasource, p.name AS profile, dcp.precedence
           FROM datasource_classification_profile dcp
           JOIN datasource d ON d.id = dcp.datasource_id
           JOIN classification_profile p ON p.id = dcp.profile_id
           WHERE dcp.datasource_id = ?
           ORDER BY dcp.precedence, p.name""",
    ).use { ps ->
        ps.setLong(1, datasourceId)
        ps.executeQuery().use { rs ->
            val out = ArrayList<ProfileAttachment>()
            while (rs.next()) {
                out += ProfileAttachment(
                    rs.getString("datasource"), rs.getString("profile"), rs.getInt("precedence"),
                )
            }
            out
        }
    }

    private fun maskFnName(id: Long?, c: Connection): String? {
        if (id == null) return null
        return c.prepareStatement("SELECT name FROM mask_fn WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }
    }

    private fun java.sql.ResultSet.toProfile(): ClassificationProfile {
        val attached = getArray("attached")?.let { array ->
            @Suppress("UNCHECKED_CAST")
            (array.array as Array<String?>).filterNotNull()
        } ?: emptyList()
        return ClassificationProfile(
            id = getLong("id"),
            name = getString("name"),
            description = getString("description"),
            ruleCount = getInt("rule_count"),
            attachedDatasources = attached,
        )
    }
}
