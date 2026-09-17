import { MySQL, PostgreSQL, type SQLNamespace } from '@codemirror/lang-sql'
import type { CatalogColumn, Datasource } from '@/lib/api/types'
import { currentCatalog, groupCatalogTables } from '@/lib/catalog'

export interface TreeColumn {
  name: string
  dataType: string
  tags: string[]
  nullable: boolean
}

export interface TreeTable {
  key: string
  catalog: string
  schema: string
  name: string
  qualified: string
  insert: string | null
  columns: TreeColumn[]
  piiCount: number
}

export function sqlDialect(engine?: string) {
  return engine === 'mysql' ? MySQL : PostgreSQL
}

function identifierLabel(name: string, engine?: string): string {
  const quote = engine === 'mysql' ? '`' : '"'
  return name.replaceAll(quote, quote + quote)
}

function identifier(name: string, engine?: string): string {
  const quote = engine === 'mysql' ? '`' : '"'
  return quote + identifierLabel(name, engine) + quote
}

export function buildTree(cols: CatalogColumn[], datasource?: Datasource): TreeTable[] {
  const catalog = currentCatalog(datasource)
  const engine = datasource?.engine
  return groupCatalogTables(cols).map((group) => {
    const canQuery = (engine === 'mysql' || engine === 'postgres') &&
      catalog != null && catalog.trim() !== '' && group.catalog === catalog
    const parts = group.schema ? [group.schema, group.table] : [group.table]
    return {
      key: group.key,
      catalog: group.catalog,
      schema: group.schema,
      name: group.table,
      qualified: group.label,
      insert: canQuery ? parts.map((part) => identifier(part, engine)).join('.') : null,
      columns: group.columns.map((column) => ({
        name: column.column,
        dataType: column.dataType,
        tags: column.classification?.tags ?? [],
        nullable: column.nullable,
      })),
      piiCount: group.piiCount,
    }
  })
}

// CodeMirror keeps doubled quotes in identifier lookups and splits unescaped dots.
function completionKey(name: string, engine?: string): string {
  return identifierLabel(name, engine).replaceAll('.', '\\.')
}

export function buildSchemaMap(tree: TreeTable[], engine?: string): SQLNamespace {
  const schemas = new Map<string, TreeTable[]>()
  const aliases = new Map<string, TreeTable | null>()
  for (const table of tree) {
    if (table.insert == null) continue
    const tables = schemas.get(table.schema) ?? []
    tables.push(table)
    schemas.set(table.schema, tables)
    aliases.set(table.name, aliases.has(table.name) ? null : table)
  }
  const tableNamespace = (table: TreeTable, apply: string): SQLNamespace => ({
    self: { label: identifierLabel(table.name, engine), type: 'type', apply },
    children: table.columns.map((column) => ({
      label: identifierLabel(column.name, engine), type: 'property', apply: identifier(column.name, engine),
    })),
  })
  return Object.fromEntries([
    ...[...schemas].filter(([schema]) => schema !== '').map(([schema, tables]) => [
      completionKey(schema, engine), {
        self: { label: identifierLabel(schema, engine), type: 'type', apply: identifier(schema, engine) },
        children: Object.fromEntries(tables.map((table) => [
          completionKey(table.name, engine), tableNamespace(table, identifier(table.name, engine)),
        ])),
      },
    ]),
    ...[...aliases].flatMap(([name, table]) => table && !schemas.has(name)
      ? [[completionKey(name, engine), tableNamespace(table, table.insert!)]] : []),
  ])
}
