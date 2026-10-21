import { renderToStaticMarkup } from 'react-dom/server'
import { NextIntlClientProvider } from 'next-intl'
import { expect, it } from 'vitest'
import en from '../../../messages/en/query.json'
import type { TreeTable } from './catalog-schema'
import { Highlight, SchemaTree } from './schema-tree'

function table(schema: string, name: string, system = false): TreeTable {
  return {
    key: JSON.stringify(['app', schema, name]), catalog: 'app', schema, name, qualified: `${schema}.${name}`,
    insert: null, ref: `${schema}.${name}`, schemaRef: schema,
    columns: [{ name: 'id', ref: 'id', dataType: 'int', tags: [], nullable: false }], piiCount: 0, system,
  }
}

function render(tables: TreeTable[]): string {
  return renderToStaticMarkup(
    <NextIntlClientProvider locale="en" messages={{ Query: en }}>
      <SchemaTree datasourceId={1} tables={tables} onInsert={() => {}} onOpenTable={() => {}} />
    </NextIntlClientProvider>,
  )
}

it('marks every case-insensitive match', () => {
  const html = renderToStaticMarkup(<Highlight text="User_users" query="user" />)
  expect(html.match(/<mark[^>]*>/g)).toHaveLength(2)
  expect(html).toContain('>User</mark>_<mark')
  expect(renderToStaticMarkup(<Highlight text="orders" query="user" />)).toBe('orders')
})

it('hides system schemas by default and says how many', () => {
  const html = render([
    table('public', 'users'),
    table('pg_catalog', 'pg_class', true),
    table('information_schema', 'tables', true),
  ])
  expect(html).toContain('data-schema="public"')
  expect(html).not.toContain('data-schema="pg_catalog"')
  expect(html).not.toContain('data-schema="information_schema"')
  expect(html).toContain('2 system schemas hidden.')
})
