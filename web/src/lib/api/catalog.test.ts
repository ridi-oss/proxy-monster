import { afterEach, describe, expect, it, vi } from 'vitest'
import { deleteClassification, getTableDetail, putClassification } from './client'

vi.mock('@/lib/i18n/errors', () => ({ translateApiError: (code: string) => code }))

afterEach(() => vi.unstubAllGlobals())

function mockFetch() {
  const fetch = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', fetch)
  return fetch
}

describe('catalog selectors', () => {
  it.each(['one', 'two', '', 'a.b/&?'])('sends table-detail catalog %j without normalization', async (catalog) => {
    const fetch = mockFetch()
    await getTableDetail(7, 'schema.name', 'table/name', catalog)
    const url = new URL(fetch.mock.calls[0][0], 'https://example.test')
    expect(url.pathname).toBe('/api/datasources/7/table-detail')
    expect(url.searchParams.get('catalog')).toBe(catalog)
    expect(url.searchParams.get('schema')).toBe('schema.name')
    expect(url.searchParams.get('table')).toBe('table/name')
  })

  it('omits the selector only when it is absent', async () => {
    const fetch = mockFetch()
    await getTableDetail(7, 'public', 'users')
    expect(new URL(fetch.mock.calls[0][0], 'https://example.test').searchParams.has('catalog')).toBe(false)
  })

  it.each(['one', 'two', ''])('preserves catalog %j in classification writes and deletes', async (catalog) => {
    const fetch = mockFetch()
    const identity = { catalog, schema: 'app.data', table: 'user.records', column: 'email' }
    await putClassification(7, { ...identity, tags: ['pii'] })
    expect(fetch.mock.calls[0][1].method).toBe('PUT')
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ ...identity, tags: ['pii'] })
    fetch.mockResolvedValueOnce(new Response(null, { status: 204 }))
    await deleteClassification(7, identity)
    expect(fetch.mock.calls[1][1].method).toBe('DELETE')
    expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual(identity)
  })
})
