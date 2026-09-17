import { CompletionContext } from '@codemirror/autocomplete'
import { schemaCompletionSource, sql } from '@codemirror/lang-sql'
import { EditorState } from '@codemirror/state'
import { syntaxTree } from '@codemirror/language'
import { describe, expect, it } from 'vitest'
import type { CatalogColumn, Datasource } from '@/lib/api/types'
import { buildSchemaMap, buildTree, sqlDialect } from './catalog-schema'

const mysql: Datasource = {
  id: 1, name: 'test', engine: 'mysql', host: 'db.example.test', port: 3306,
  dbName: 'app', tags: [], defaultSchemas: ['app'],
}
const postgres: Datasource = { ...mysql, engine: 'postgres', port: 5432, defaultSchemas: ['public'] }

function column(catalog: string, schema = 'public', table = 'users', name = 'id'): CatalogColumn {
  return { catalog, schema, table, column: name, dataType: 'int', sqlType: 'int', ordinal: 1, nullable: false }
}

async function complete(columns: CatalogColumn[], datasource: Datasource, text: string) {
  const pos = text.indexOf('|')
  const doc = text.replace('|', '')
  const config = {
    dialect: sqlDialect(datasource.engine),
    schema: buildSchemaMap(buildTree(columns, datasource), datasource.engine),
  }
  const state = EditorState.create({ doc, extensions: [sql(config)] })
  const result = await schemaCompletionSource(config)(new CompletionContext(state, pos, true))
  return {
    options: result?.options ?? [],
    apply(name: string) {
      const option = result?.options.find((option) => option.label === name)
      expect(option, JSON.stringify({ result, tree: syntaxTree(state).toString(), schema: config.schema })).toBeDefined()
      const insert = option!.apply ?? option!.label
      expect(typeof insert).toBe('string')
      return state.update({ changes: { from: result!.from, to: result!.to ?? pos, insert: insert as string } }).state.doc.toString()
    },
  }
}

describe('query catalog tree', () => {
  it('keeps catalogs distinct while limiting SQL to the current catalog', async () => {
    const columns = [column('app'), column('other', 'public', 'users', 'email')]
    const tree = buildTree(columns, postgres)
    expect(tree).toHaveLength(2)
    expect(tree[0].key).not.toBe(tree[1].key)
    expect(tree.map((table) => table.columns.map((col) => col.name))).toEqual([['id'], ['email']])
    expect(tree.map((table) => table.insert)).toEqual(['"public"."users"', null])
    expect((await complete(columns, postgres, 'SELECT "public"."users".|')).options.map((item) => item.label)).toEqual(['id'])
  })

  it('qualifies public as explicitly as a shadow schema, without catalog qualifiers', () => {
    expect(buildTree([column('def', 'app')], mysql)[0].insert).toBe('`app`.`users`')
    const tree = buildTree([column('app'), column('app', 'shadow')], { ...postgres, defaultSchemas: ['shadow', 'public'] })
    expect(tree.map((table) => table.insert)).toEqual(['"public"."users"', '"shadow"."users"'])
  })

  it.each([
    [mysql, 'def', 'public', 'order', '`public`.`order`'],
    [postgres, 'app', 'public', 'order', '"public"."order"'],
    [mysql, 'def', 'app.data', 'user.records', '`app.data`.`user.records`'],
    [postgres, 'app', 'a"b', 'c.d', '"a""b"."c.d"'],
    [mysql, 'def', 'a`b', 'c`d', '`a``b`.`c``d`'],
  ])('quotes every identifier component for %j', (datasource, catalog, schema, table, expected) => {
    expect(buildTree([column(catalog, schema, table)], datasource)[0].insert).toBe(expected)
  })

  it('does not pick the first catalog for an unknown engine or missing datasource', () => {
    expect(buildTree([column('app')], { ...postgres, engine: 'other' })[0].insert).toBeNull()
    expect(buildTree([column('app')])[0].insert).toBeNull()
    expect(buildTree([column('app')], { ...postgres, currentCatalog: '' })[0].insert).toBeNull()
    expect(buildTree([column(' ')], { ...postgres, currentCatalog: ' ' })[0].insert).toBeNull()
    expect(buildSchemaMap(buildTree([column('app')]))).toEqual({})
  })

  it('honors the explicit current catalog instead of legacy dbName', () => {
    const tree = buildTree([column('app'), column('other')], { ...postgres, currentCatalog: 'other' })
    expect(tree.map((table) => table.insert)).toEqual([null, '"public"."users"'])
  })
})

describe('CodeMirror catalog completion', () => {
  it('keeps public and shadow schema columns distinct and omits an ambiguous bare alias', async () => {
    const columns = [column('app', 'public', 'users', 'id'), column('app', 'shadow', 'users', 'email')]
    const top = await complete(columns, postgres, 'SELECT * FROM |')
    expect(top.options.map((option) => option.label)).toEqual(['public', 'shadow'])
    expect((await complete(columns, postgres, 'SELECT "public"."users".|')).options.map((option) => option.label)).toEqual(['id'])
    expect((await complete(columns, postgres, 'SELECT "shadow"."users".|')).options.map((option) => option.label)).toEqual(['email'])
  })

  it('inserts a qualified bare alias and quoted reserved table and column names', async () => {
    const columns = [column('app', 'public', 'order', 'select')]
    expect((await complete(columns, postgres, 'SELECT * FROM ord|')).apply('order')).toBe('SELECT * FROM "public"."order"')
    expect((await complete(columns, postgres, 'SELECT * FROM public.ord|')).apply('order')).toBe('SELECT * FROM public."order"')
    expect((await complete(columns, postgres, 'SELECT p.| FROM "public"."order" p')).apply('select')).toBe('SELECT p."select" FROM "public"."order" p')
  })

  it.each([
    [postgres, 'app', 'app.data', 'user.records', 'odd"name', '"app.data"."user.records"', '"odd""name"'],
    [mysql, 'def', 'app.data', 'user.records', 'odd`name', '`app.data`.`user.records`', '`odd``name`'],
  ])('resolves dotted names with the engine dialect for %j', async (datasource, catalog, schema, table, name, qualified, quotedColumn) => {
    const columns = [column(catalog, schema, table, name)]
    expect((await complete(columns, datasource, 'SELECT * FROM |')).apply(table)).toBe(`SELECT * FROM ${qualified}`)
    expect((await complete(columns, datasource, `SELECT ${qualified}.|`)).apply(quotedColumn.slice(1, -1))).toBe(`SELECT ${qualified}.${quotedColumn}`)
  })

  it('escapes embedded identifier quotes when completing table names', async () => {
    const columns = [column('app', 'public', 'c"d')]
    expect((await complete(columns, postgres, 'SELECT * FROM "public".|')).apply('c""d')).toBe('SELECT * FROM "public"."c""d"')
    expect((await complete(columns, postgres, 'SELECT * FROM "public"."c|')).apply('"c""d"')).toBe('SELECT * FROM "public"."c""d"')
  })

  it('documents CodeMirror’s doubled-quote namespace limitation', async () => {
    const columns = [column('app', 'a"b', 'c"d')]
    expect((await complete(columns, postgres, 'SELECT * FROM |')).apply('c""d')).toBe('SELECT * FROM "a""b"."c""d"')
    expect((await complete(columns, postgres, 'SELECT * FROM "a""b".|')).options).toEqual([])
  })
})
