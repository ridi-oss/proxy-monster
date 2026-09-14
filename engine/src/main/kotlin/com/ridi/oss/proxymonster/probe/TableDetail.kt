package com.ridi.oss.proxymonster.probe

import kotlinx.serialization.Serializable

/** Persisted column classification overlaid by the control plane onto live proxy introspection. */
@Serializable
data class Classification(
    val schema: String,
    val table: String,
    val column: String,
    val tags: List<String> = emptyList(),
    val maskFnId: Long? = null,
    val maskFnName: String? = null,
    val catalog: String = "",
)

/** Live table-browser metadata. The proxy serializes this shape and the control plane serves it unchanged. */
@Serializable
data class TableDetail(
    val schema: String,
    val table: String,
    val columns: List<TableDetailColumn>,
    val indexes: List<TableIndex>,
    val foreignKeys: List<TableRelation>,
    val referencedBy: List<TableRelation>,
    val metadata: TableMetadata,
    val catalog: String? = null,
)

@Serializable
data class TableDetailColumn(
    val name: String,
    val dataType: String,
    val ordinal: Int,
    val nullable: Boolean,
    val defaultValue: String?,
    val characterMaximumLength: Long?,
    val numericPrecision: Int?,
    val numericScale: Int?,
    val partOfIndex: Boolean,
    val autoIncrement: Boolean,
    val comment: String?,
    val charset: String?,
    val collation: String?,
    val classification: Classification?,
)

@Serializable
data class TableIndexColumn(
    val name: String,
    val position: Int,
    val direction: String?,
)

@Serializable
data class TableIndex(
    val name: String,
    val columns: List<TableIndexColumn>,
    val unique: Boolean,
    val type: String,
)

@Serializable
data class TableRelation(
    val name: String,
    val sourceSchema: String,
    val sourceTable: String,
    val sourceColumns: List<String>,
    val targetSchema: String,
    val targetTable: String,
    val targetColumns: List<String>,
    val onUpdate: String?,
    val onDelete: String?,
    val sourceCatalog: String? = null,
    val targetCatalog: String? = null,
)

@Serializable
data class TableMetadata(
    val engine: String,
    val estimatedRows: Long?,
    val rowFormat: String?,
    val onDiskBytes: Long?,
    val collation: String?,
    val comment: String?,
)
