import { describe, expect, it } from 'vitest'
import type { CatalogColumn, Datasource } from './api/types'
import { connectionEndpoint, currentCatalog, groupCatalogTables, schemaKey, tableKey } from './catalog'

const datasource: Datasource = {
  id: 1, name: 'test', engine: 'mysql', host: 'db.example.test', port: 3306,
  dbName: 'app', tags: [], defaultSchemas: ['app'],
}

function column(catalog: string, schema: string, table: string): CatalogColumn {
  return { catalog, schema, table, column: 'id', dataType: 'int', sqlType: 'int', ordinal: 1, nullable: false }
}

describe('catalog identity', () => {
  it('keeps equal schema and table names in different catalogs separate', () => {
    const groups = groupCatalogTables([column('one', 'app', 'users'), column('two', 'app', 'users')])
    expect(groups).toHaveLength(2)
    expect(groups.map((group) => group.columns.length)).toEqual([1, 1])
    expect(new Set(groups.map((group) => group.key)).size).toBe(2)
    expect(new Set(groups.map((group) => group.label)).size).toBe(2)
    expect(schemaKey('one', 'app')).not.toBe(schemaKey('two', 'app'))
  })

  it('does not use dotted identifiers as keys', () => {
    const columns = [column('a.b', 'c', 'd'), column('a', 'b.c', 'd'), column('a', 'b', 'c.d')]
    expect(new Set(columns.map(tableKey)).size).toBe(3)
    expect(groupCatalogTables(columns)).toHaveLength(3)
    expect(schemaKey('a.b', 'c')).not.toBe(schemaKey('a', 'b.c'))
  })

  it('preserves ordinal order and single-catalog labels', () => {
    const id = column('def', 'app', 'users')
    const groups = groupCatalogTables([id, { ...id, column: 'email', ordinal: 2, classification: {
      schema: 'app', table: 'users', column: 'email', tags: ['pii'],
    } }])
    expect(groups[0].columns.map((col) => col.column)).toEqual(['id', 'email'])
    expect(groups[0].label).toBe('app.users')
    expect(groups[0].piiCount).toBe(1)
  })
})

describe('legacy datasource metadata', () => {
  it('derives a current catalog only for known engines', () => {
    expect(currentCatalog(datasource)).toBe('def')
    expect(currentCatalog({ ...datasource, engine: 'postgres' })).toBe('app')
    expect(currentCatalog({ ...datasource, engine: 'other' })).toBeNull()
    expect(currentCatalog(undefined)).toBeNull()
  })

  it('does not replace explicit catalog values, including blank', () => {
    expect(currentCatalog({ ...datasource, currentCatalog: 'other' })).toBe('other')
    expect(currentCatalog({ ...datasource, currentCatalog: '' })).toBe('')
  })

  it('prefers nonsecret connection metadata without serializing properties', () => {
    expect(connectionEndpoint({ ...datasource, connectionInfo: {
      endpoint: 'db.example.test:3306/app', properties: { note: '<script>text</script>' },
    } })).toBe('db.example.test:3306/app')
    expect(connectionEndpoint(datasource)).toBe('db.example.test:3306/app')
    expect(connectionEndpoint({ ...datasource, engine: 'other' })).toBeNull()
    expect(connectionEndpoint({ ...datasource, connectionInfo: { endpoint: '', properties: {} } })).toBe('')
  })
})
