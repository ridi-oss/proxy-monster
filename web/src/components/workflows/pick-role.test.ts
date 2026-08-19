import { describe, expect, it } from 'vitest'
import { pickRole } from './pick-role'
import type { RoleOption } from '@/lib/api/types'

// pickRole is the pure selection rule the composer applies each render with the CURRENT options and the
// user's persisted `userChoice`. The composer's async discovery state machine (debounce / seq-guarded
// `discovering` / retry) lives in the component; the repo has no jsdom + testing-library env, so it is
// exercised through this pure helper plus review, not a full component render.

const opt = (roleId: number, roleName: string): RoleOption => ({
  roleId,
  roleName,
  decision: 'ALLOW',
  maskedColumns: [],
})

describe('pickRole', () => {
  const analyst = opt(1, 'analyst')
  const piiReader = opt(2, 'pii-reader')
  const auditor = opt(3, 'auditor')

  it('selects the first offered role when nothing was picked', () => {
    expect(pickRole([analyst, piiReader], null)).toBe('1')
  })

  it('keeps the user pick while it is still offered', () => {
    expect(pickRole([analyst, piiReader, auditor], '2')).toBe('2')
  })

  it('recovers the pick across a query change that drops then re-offers it', () => {
    // The component holds `userChoice` = '2' throughout; only the options list changes as the query is
    // re-discovered. pickRole must keep '2' while offered, fall back to the first when it is dropped, and
    // recover '2' when it is offered again — without the caller ever forgetting the pick.
    const choice = '2'
    expect(pickRole([analyst, piiReader, auditor], choice)).toBe('2') // offered → kept
    expect(pickRole([analyst, auditor], choice)).toBe('1') // dropped → first
    expect(pickRole([analyst, piiReader, auditor], choice)).toBe('2') // re-offered → recovered
  })

  it('returns null when no role is offered', () => {
    expect(pickRole([], '2')).toBeNull()
    expect(pickRole([], null)).toBeNull()
  })
})
