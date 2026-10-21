// Local, self-contained format helpers for the audit page (no shared formatting dependency).

/** Collapse whitespace and truncate SQL to a single dense line for the feed row. */
export function oneLineSql(sql: string, max = 160): string {
  const flat = sql.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/**
 * Buckets a timestamp into a relative-time shape ("just now" / N seconds/minutes/hours/days ago)
 * without picking any locale's words for it — this file has no next-intl dependency on purpose
 * (kept pure/testable), so the caller resolves `bucket.kind` through `useTranslations('Audit')`'s
 * `relativeTime.*` keys (decision-row.tsx). `null` for a missing/invalid timestamp; the caller
 * renders its own localized "—" for that case.
 */
export type RelativeTimeBucket =
  { kind: 'justNow' } | { kind: 'secondsAgo' | 'minutesAgo' | 'hoursAgo' | 'daysAgo'; count: number };

export function relativeTimeBucket(iso: string | null | undefined, nowMs = Date.now()): RelativeTimeBucket | null {
  if (!iso) return null;
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return null;
  const sec = Math.floor((nowMs - then) / 1000);
  if (sec < 10) return { kind: 'justNow' };
  if (sec < 60) return { kind: 'secondsAgo', count: sec };
  const min = Math.floor(sec / 60);
  if (min < 60) return { kind: 'minutesAgo', count: min };
  const hr = Math.floor(min / 60);
  if (hr < 24) return { kind: 'hoursAgo', count: hr };
  return { kind: 'daysAgo', count: Math.floor(hr / 24) };
}

/** Full ISO-8601 timestamp for the detail panel and hover titles. */
export function formatFullTimestamp(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace('T', ' ').replace('Z', ' UTC');
}
