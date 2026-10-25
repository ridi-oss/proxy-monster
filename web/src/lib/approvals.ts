import type { AccessRequest } from '@/lib/api/types';

/** A GitHub request runs when its pull request merges, so the console only approves it. */
export function runsOnMerge(r: Pick<AccessRequest, 'source'> | null | undefined): boolean {
  return r?.source === 'github';
}
