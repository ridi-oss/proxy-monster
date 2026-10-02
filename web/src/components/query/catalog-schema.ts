import { MySQL, PostgreSQL, type SQLDialect, type SQLNamespace } from '@codemirror/lang-sql'
import type { CatalogColumn, Datasource } from '@/lib/api/types'
import { currentCatalog, groupCatalogTables } from '@/lib/catalog'
import { MYSQL_RESERVED, POSTGRES_RESERVED } from './sql-reserved'

export interface TreeColumn {
  name: string
  /** The name as written in SQL: quoted only when it is not a plain identifier or is a reserved word. */
  ref: string
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
  /** `schema.table` and `schema` as written in SQL, quoted only where needed. */
  ref: string
  schemaRef: string
  columns: TreeColumn[]
  piiCount: number
  system: boolean
}

interface EngineSql {
  dialect: SQLDialect
  quote: string
  /** Whether a name can be written without quotes: a plain identifier the engine neither folds nor reserves. */
  bare: (name: string) => boolean
}

const ENGINE_SQL: Record<string, EngineSql> = {
  mysql: {
    dialect: MySQL,
    quote: '`',
    bare: (name) => /^[A-Za-z_][A-Za-z0-9_$]*$/.test(name) && !MYSQL_RESERVED.has(name.toLowerCase()),
  },
  postgres: {
    dialect: PostgreSQL,
    quote: '"',
    // Unquoted names fold to lower case, so a name with an upper-case letter needs quotes.
    bare: (name) => /^[a-z_][a-z0-9_$]*$/.test(name) && !POSTGRES_RESERVED.has(name),
  },
}
// Any other engine (Athena) quotes every name: there is no reserved-word list for it here.
const OTHER_ENGINE: EngineSql = { dialect: PostgreSQL, quote: '"', bare: () => false }

const engineSql = (engine?: string): EngineSql => ENGINE_SQL[engine ?? ''] ?? OTHER_ENGINE

export function sqlDialect(engine?: string) {
  return engineSql(engine).dialect
}

function identifierLabel(name: string, engine?: string): string {
  const { quote } = engineSql(engine)
  return name.replaceAll(quote, quote + quote)
}

function identifier(name: string, engine?: string): string {
  const { quote } = engineSql(engine)
  return quote + identifierLabel(name, engine) + quote
}

// e.g. users -> users, select -> "select", Order Items -> "Order Items" (backticks on MySQL).
function sqlName(name: string, engine?: string): string {
  return engineSql(engine).bare(name) ? name : identifier(name, engine)
}

export function buildTree(cols: CatalogColumn[], datasource?: Datasource): TreeTable[] {
  const catalog = currentCatalog(datasource)
  const engine = datasource?.engine
  return groupCatalogTables(cols).map((group) => {
    const canQuery = catalog != null && catalog.trim() !== '' && group.catalog === catalog
    const parts = group.schema ? [group.schema, group.table] : [group.table]
    return {
      key: group.key,
      catalog: group.catalog,
      schema: group.schema,
      name: group.table,
      qualified: group.label,
      insert: canQuery ? parts.map((part) => identifier(part, engine)).join('.') : null,
      ref: parts.map((part) => sqlName(part, engine)).join('.'),
      schemaRef: sqlName(group.schema, engine),
      columns: group.columns.map((column) => ({
        name: column.column,
        ref: sqlName(column.column, engine),
        dataType: column.dataType,
        tags: column.classification?.tags ?? [],
        nullable: column.nullable,
      })),
      piiCount: group.piiCount,
      system: group.columns.some((column) => column.system === true),
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
