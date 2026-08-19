import type { RoleOption } from '@/lib/api/types'

/**
 * The role to select from a discovery: the user's explicit pick while it is still offered — recovered when it
 * reappears after a query change had dropped it — else the first offered role; null when nothing is offered.
 * Pure so the recover/fallback behavior is unit-tested without the component.
 */
export function pickRole(options: RoleOption[], userChoice: string | null): string | null {
  if (options.length === 0) return null
  if (userChoice != null && options.some((o) => String(o.roleId) === userChoice)) return userChoice
  return String(options[0].roleId)
}
