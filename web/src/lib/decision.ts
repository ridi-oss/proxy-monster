// The load-bearing token (docs/web-console.md), expressed as Tailwind utility classes.
// One shared map used by every badge, banner left-bar, and counter so a DENY
// reads identically everywhere: deny = red (always loudest), mask = amber,
// allow = emerald, error = zinc. Fail-closed posture made visual.

import type { Decision } from './api/types';

export interface DecisionTone {
  /** Solid accent text (e.g. for the verdict label). */
  text: string;
  /** Tinted surface for callouts. */
  surface: string;
  /** Hairline border for callouts. */
  border: string;
  /** Solid bar/dot — the loud accent (banner inset bar, status dot). */
  solid: string;
  /** Badge classes — DENY is filled (loudest); others are subtle tints. */
  badge: string;
}

export const decisionTone: Record<Decision, DecisionTone> = {
  DENY: {
    text: 'text-red-500',
    surface: 'bg-red-500/10',
    border: 'border-red-500/30',
    solid: 'bg-red-500',
    badge: 'bg-red-500 text-white border-transparent',
  },
  MASK: {
    text: 'text-amber-500',
    surface: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    solid: 'bg-amber-500',
    badge: 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/25',
  },
  ALLOW: {
    text: 'text-emerald-500',
    surface: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    solid: 'bg-emerald-500',
    badge: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/25',
  },
  ERROR: {
    text: 'text-zinc-400',
    surface: 'bg-zinc-500/10',
    border: 'border-zinc-500/30',
    solid: 'bg-zinc-500',
    badge: 'bg-zinc-500/15 text-zinc-500 dark:text-zinc-400 border-zinc-500/25',
  },
};

/** Known tag → badge classes for catalog/column chips. Unknown tags fall back to neutral zinc. */
export const tagTone: Record<string, string> = {
  pii: 'bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/25',
  financial: 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/25',
};

const neutralTone = 'bg-zinc-500/15 text-zinc-500 dark:text-zinc-400 border-zinc-500/25';

/** Tone for a column's tag set: loudest signal (`pii` → red) wins, else neutral zinc. */
export function toneForTags(tags: string[]): string {
  if (tags.includes('pii')) return tagTone.pii;
  for (const t of tags) {
    if (tagTone[t]) return tagTone[t];
  }
  return neutralTone;
}
