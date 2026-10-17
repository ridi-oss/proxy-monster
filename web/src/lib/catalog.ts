import type { CatalogColumn, Datasource } from './api/types'

export interface TableIdentity {
  catalog: string
  schema: string
  table: string
}

export function tableKey({ catalog, schema, table }: TableIdentity): string {
  return JSON.stringify([catalog, schema, table])
}

export function schemaKey(catalog: string, schema: string): string {
  return JSON.stringify([catalog, schema])
}

/** A browsed name as SQL identifier text, so the server keeps its exact spelling: Users -> "Users". */
export function quoteIdentifier(datasource: Pick<Datasource, 'identifierQuote'>, name: string): string {
  const q = datasource.identifierQuote
  return q + name.split(q).join(q + q) + q
}

/** A browsed column as the classification API's identifier text. */
export function classificationTarget(
  datasource: Pick<Datasource, 'identifierQuote'>,
  column: { catalog: string; schema?: string; table: string; column: string },
) {
  const quote = (name: string) => quoteIdentifier(datasource, name)
  return {
    catalog: quote(column.catalog),
    schema: column.schema ? quote(column.schema) : undefined,
    table: quote(column.table),
    column: quote(column.column),
  }
}

export function currentCatalog(datasource: Datasource | undefined): string | null {
  if (!datasource) return null
  if (datasource.currentCatalog != null) return datasource.currentCatalog
  switch (datasource.engine) {
    case 'mysql': return 'def'
    case 'postgres': return datasource.dbName || null
    default: return null
  }
}

/** What the console shows as the datasource endpoint: the published metadata when a proxy sent it, else host:port/db. */
export function connectionEndpoint(datasource: Datasource): string | null {
  if (datasource.connectionInfo) return datasource.connectionInfo.endpoint
  if (datasource.engine !== 'mysql' && datasource.engine !== 'postgres') return null
  return `${datasource.host}:${datasource.port}/${datasource.dbName}`
}

export function groupCatalogTables(columns: CatalogColumn[]) {
  const multipleCatalogs = new Set(columns.map((column) => column.catalog)).size > 1
  const groups = new Map<string, TableIdentity & {
    key: string
    label: string
    columns: CatalogColumn[]
    piiCount: number
  }>()
  for (const column of columns) {
    const key = tableKey(column)
    let group = groups.get(key)
    if (!group) {
      const name = column.schema && column.schema !== 'public'
        ? `${column.schema}.${column.table}` : column.table
      group = {
        key,
        catalog: column.catalog,
        schema: column.schema,
        table: column.table,
        label: multipleCatalogs ? `${name} (${column.catalog})` : name,
        columns: [],
        piiCount: 0,
      }
      groups.set(key, group)
    }
    group.columns.push(column)
    if ((column.classification?.tags.length ?? 0) > 0) group.piiCount++
  }
  return [...groups.values()]
}
