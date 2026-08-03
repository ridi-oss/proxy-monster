// Catalog → CodeMirror SQL `schema` map + a grouped table/column tree, derived
// once from a datasource's CatalogColumn[]. The same source drives both
// schema-aware autocomplete (the `schema` map) and the explorer tree (the
// grouped view) — one shape, no parallel derivation.
import type { CatalogColumn } from '@/lib/api/types'

/** A column row in the tree, carrying its qualified name + PII flag for the explorer. */
export interface TreeColumn {
  name: string
  dataType: string
  /** Classification tags (e.g. `pii`, `financial`) — empty when unclassified. */
  tags: string[]
  nullable: boolean
}

/** One table group: its catalog identity, qualified label, and columns in catalog order. */
export interface TreeTable {
  schema: string
  /** Bare table name within `schema`. */
  name: string
  /** `schema.table` (or bare `table` when schema is "public"). */
  qualified: string
  /** Identifier inserted into the editor when the table node is clicked. */
  insert: string
  columns: TreeColumn[]
  /** Count of PII columns — surfaced as a badge on the table node. */
  piiCount: number
}

/** Drop the redundant "public." prefix so names read like the user would type them. */
function qualify(schema: string, table: string): string {
  return schema && schema !== 'public' ? `${schema}.${table}` : table
}

/** Group catalog columns into table nodes, preserving catalog (ordinal) order. */
export function buildTree(cols: CatalogColumn[]): TreeTable[] {
  const bySchema = new Map<string, Map<string, TreeTable>>()
  const tree: TreeTable[] = []
  for (const c of cols) {
    let byTable = bySchema.get(c.schema)
    if (!byTable) {
      byTable = new Map()
      bySchema.set(c.schema, byTable)
    }

    let node = byTable.get(c.table)
    if (!node) {
      const qualified = qualify(c.schema, c.table)
      node = {
        schema: c.schema,
        name: c.table,
        qualified,
        insert: qualified,
        columns: [],
        piiCount: 0,
      }
      byTable.set(c.table, node)
      tree.push(node)
    }
    const tags = c.classification?.tags ?? []
    node.columns.push({ name: c.column, dataType: c.dataType, tags, nullable: c.nullable })
    // The badge counts classified columns, whatever the tag is named.
    if (tags.length > 0) node.piiCount += 1
  }
  return tree
}

/**
 * The `schema` map @codemirror/lang-sql consumes for table + column completion:
 * `{ "<table>": ["<col>", ...] }`. Keyed by both the qualified name and the bare
 * table name so completion fires whether the user types `orders` or `public.orders`.
 */
export function buildSchemaMap(tree: TreeTable[]): Record<string, string[]> {
  const map: Record<string, string[]> = {}
  for (const t of tree) {
    const colNames = t.columns.map((c) => c.name)
    map[t.qualified] = colNames
    const bare = t.qualified.includes('.') ? t.qualified.split('.').pop()! : t.qualified
    if (!(bare in map)) map[bare] = colNames
  }
  return map
}
