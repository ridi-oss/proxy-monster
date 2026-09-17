import { expect, it, vi } from 'vitest'
import { swrKeys } from './hooks'

vi.mock('./auth', () => ({ useAuth: vi.fn() }))
vi.mock('./api/client', () => ({}))

it('keeps table-detail caches separate by catalog and identifier component', () => {
  const keys = [
    swrKeys.tableDetail(1, 'one', 'app', 'users'),
    swrKeys.tableDetail(1, 'two', 'app', 'users'),
    swrKeys.tableDetail(1, 'one', 'a.b', 'c'),
    swrKeys.tableDetail(1, 'one', 'a', 'b.c'),
    swrKeys.tableDetail(1, 'one.a', 'b', 'c'),
  ]
  expect(new Set(keys.map((key) => JSON.stringify(key))).size).toBe(keys.length)
})
