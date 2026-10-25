'use client';

// One dense row per AuditEvent in the audit feed. The left accent bar (3 px
// wide) is the loudest visual signal — DENY is red-filled so it pops even when
// the list scrolls fast. Everything else is sized for density: monospace
// timestamps, truncated SQL, small chips for PII/masked counts.
import { memo } from 'react';
import { useTranslations } from 'next-intl';
import type { AuditEvent } from '@/lib/api/types';
import { decisionTone } from '@/lib/decision';
import { cn } from '@/lib/utils';
import { Skeleton } from '@/components/ui/skeleton';
import { relativeTimeBucket, formatFullTimestamp, oneLineSql } from './format';

interface DecisionRowProps {
  record: AuditEvent;
  selected: boolean;
  onSelect: () => void;
}

export const DecisionRow = memo(function DecisionRow({ record, selected, onSelect }: DecisionRowProps) {
  const t = useTranslations('Audit');
  const tone = decisionTone[record.decision];
  const isDeny = record.decision === 'DENY';
  const bucket = relativeTimeBucket(record.ts);
  const relative =
    bucket == null
      ? '—'
      : bucket.kind === 'justNow'
        ? t('relativeTime.justNow')
        : t(`relativeTime.${bucket.kind}`, { count: bucket.count });

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect();
        }
      }}
      className={cn(
        'relative flex cursor-pointer items-center gap-3 border-b px-4 py-2.5 text-sm transition-colors',
        'hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset',
        selected && 'bg-muted/60',
        // DENY rows get a faint red wash so they stand out even when unselected.
        isDeny && !selected && 'bg-red-500/[0.03]',
      )}
    >
      {/* Left accent bar — the load-bearing visual signal (decisionTone.solid). */}
      <span className={cn('absolute inset-y-0 left-0 w-[3px]', tone.solid)} />

      {/* Timestamp — relative text, full ISO on hover via title. */}
      <span
        className="text-muted-foreground w-[72px] shrink-0 font-mono text-[11px] tabular-nums"
        title={formatFullTimestamp(record.ts)}
      >
        {relative}
      </span>

      {/* Verdict badge */}
      <span
        className={cn(
          'inline-flex w-[52px] shrink-0 items-center justify-center rounded border px-1 py-px font-mono text-[10px] font-semibold',
          tone.badge,
        )}
      >
        {record.decision}
      </span>

      {/* Principal — mono, truncated */}
      <span className="text-foreground/90 w-[140px] shrink-0 truncate font-mono text-xs">{record.principal}</span>

      {/* Datasource — dimmed, truncated */}
      <span className="text-muted-foreground w-[100px] shrink-0 truncate font-mono text-xs">{record.datasource}</span>

      {/* SQL — one-line, mono, expands to fill remaining space */}
      <span
        className={cn('min-w-0 flex-1 truncate font-mono text-xs', isDeny ? 'text-red-500/80' : 'text-foreground/70')}
      >
        {oneLineSql(record.statement)}
      </span>

      {/* Right-side chips: PII, masked columns, latency */}
      <div className="flex shrink-0 items-center gap-1.5">
        {record.piiTouched.length > 0 && (
          <span className="rounded border border-red-500/25 bg-red-500/10 px-1 py-px font-mono text-[10px] text-red-500">
            {t('row.pii', { count: record.piiTouched.length })}
          </span>
        )}
        {record.maskedColumns.length > 0 && (
          <span className="rounded border border-amber-500/25 bg-amber-500/10 px-1 py-px font-mono text-[10px] text-amber-600 dark:text-amber-400">
            {t('row.masked', { count: record.maskedColumns.length })}
          </span>
        )}
        <span className="text-muted-foreground font-mono text-[10px] tabular-nums">{record.latencyMs}ms</span>
      </div>
    </div>
  );
});

/** Skeleton placeholder rows rendered while the first load is in flight. */
export function DecisionRowSkeleton() {
  return (
    <div className="relative flex items-center gap-3 border-b px-4 py-2.5">
      <span className="absolute inset-y-0 left-0 w-[3px] bg-muted" />
      <Skeleton className="h-3 w-[72px]" />
      <Skeleton className="h-4 w-[52px]" />
      <Skeleton className="h-3 w-[140px]" />
      <Skeleton className="h-3 w-[100px]" />
      <Skeleton className="h-3 flex-1" />
      <Skeleton className="h-3 w-[48px]" />
    </div>
  );
}
