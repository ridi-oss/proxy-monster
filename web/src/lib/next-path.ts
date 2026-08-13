/**
 * Post-login return-path safety.
 *
 * A `next` destination is attacker-influenceable (it rides a URL), so it must be an internal path and nothing
 * else — never an absolute URL, a protocol-relative `//host`, or a backslash trick a browser normalizes to
 * one. Anything that is not a single-slash-rooted path is dropped, and the caller falls back to the default
 * landing. This is the one gate every producer and consumer of `next` shares, so the rule cannot drift
 * between them.
 */
export function safeInternalPath(candidate: string | null | undefined): string | null {
  if (!candidate) return null
  // Must start with exactly one '/', and not '//' or '/\' (both resolve to an off-site host in a browser).
  if (!candidate.startsWith('/') || candidate.startsWith('//') || candidate.startsWith('/\\')) return null
  // A control character or whitespace has no place in a path and is a common normalization-bypass vector.
  if (/[\x00-\x1f\x7f\s]/.test(candidate)) return null
  return candidate
}

/** Session-storage key carrying the intended path across the OIDC full-page round-trip. */
export const NEXT_STORAGE_KEY = 'pm.login.next'
