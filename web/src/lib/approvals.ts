import type { AccessRequest } from '@/lib/api/types'

/** A GitHub request runs when its pull request merges, so the console only approves it. */
export function runsOnMerge(r: Pick<AccessRequest, 'source'> | null | undefined): boolean {
  return r?.source === 'github'
}

export function approveLabelKey(
  r: Pick<AccessRequest, 'source'> | null | undefined,
): 'actions.approve' | 'actions.approveAndRun' {
  return runsOnMerge(r) ? 'actions.approve' : 'actions.approveAndRun'
}
