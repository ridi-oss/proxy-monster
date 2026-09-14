import { expect, it, vi } from 'vitest'
import { swrKeys } from './hooks'

vi.mock('./auth', () => ({ useAuth: vi.fn() }))
vi.mock('./api/client', () => ({}))

it('keeps table-detail caches separate by catalog and identifier component', () => {
  const keys = [
    swrKeys.tableDetail(1, 'app', 'users', 'one'),
    swrKeys.tableDetail(1, 'app', 'users', 'two'),
    swrKeys.tableDetail(1, 'app', 'users', ''),
    swrKeys.tableDetail(1, 'app', 'users'),
    swrKeys.tableDetail(1, 'a.b', 'c', 'one'),
    swrKeys.tableDetail(1, 'a', 'b.c', 'one'),
  ]
  expect(new Set(keys.map((key) => JSON.stringify(key))).size).toBe(keys.length)
})
