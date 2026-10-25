'use client';

// Right-sheet detail panel for a single AuditEvent. Answers the binary question
// above the fold (loud verdict + datasource + timestamp), then traces identity,
// raw SQL, PII/masking summary, and timing. Ported and redesigned from
import type { ReactNode } from 'react';
import { useTranslations } from 'next-intl';
import type { AuditEvent } from '@/lib/api/types';
import { decisionTone } from '@/lib/decision';
import { cn } from '@/lib/utils';
import { Separator } from '@/components/ui/separator';
import { formatFullTimestamp } from './format';

interface Props {
  record: AuditEvent;
}

export function DecisionDetail({ record }: Props) {
  const t = useTranslations('Audit');
  const tone = decisionTone[record.decision];

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Above-the-fold verdict header */}
      <div className={cn('relative flex items-start gap-3 border-b px-5 py-4', tone.surface, tone.border)}>
        {/* Accent bar */}
        <span className={cn('absolute inset-y-0 left-0 w-[3px]', tone.solid)} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                'inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-xs font-semibold',
                tone.badge,
              )}
            >
              {record.decision}
            </span>
            <span className="font-mono text-sm font-medium">{record.datasource}</span>
          </div>
          <p className="text-muted-foreground mt-1 font-mono text-xs">{formatFullTimestamp(record.ts)}</p>
          {record.detail && <p className={cn('mt-2 text-sm', tone.text)}>{record.detail}</p>}
        </div>
      </div>

      {/* Scrollable body */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="space-y-5 px-5 py-5">
          {/* Failed stage — only shown when present */}
          {record.failedStage && (
            <Field label={t('detail.failedStage')}>
              <span className="inline-flex items-center rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 font-mono text-xs text-red-500">
                {record.failedStage}
              </span>
            </Field>
          )}

          <Separator />

          {/* Identity */}
          <div className="grid grid-cols-2 gap-x-4 gap-y-4">
            <Field label={t('detail.principal')}>
              <MonoValue>{record.principal}</MonoValue>
            </Field>
            <Field label={t('detail.clientAddress')}>
              <MonoValue>{record.clientAddr ?? '—'}</MonoValue>
            </Field>
            <Field label={t('detail.roles')} className="col-span-2">
              {record.roles.length === 0 ? (
                <EmptyDash />
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {record.roles.map((r) => (
                    <span
                      key={r}
                      className="border-border text-muted-foreground rounded border px-1.5 py-0.5 font-mono text-[11px]"
                    >
                      {r}
                    </span>
                  ))}
                </div>
              )}
            </Field>
          </div>

          <Separator />

          {/* SQL block */}
          <Field label={t('detail.sql')}>
            <pre className="border-border bg-muted/40 text-foreground/90 mt-1 overflow-x-auto rounded-lg border p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words">
              {record.statement}
            </pre>
          </Field>

          <Separator />

          {/* PII + masking */}
          <div className="space-y-4">
            <Field label={t('detail.piiTouched')}>
              <ColumnChips columns={record.piiTouched} variant="pii" />
            </Field>
            <Field label={t('detail.maskedColumns')}>
              <ColumnChips columns={record.maskedColumns} variant="masked" />
            </Field>
          </div>

          <Separator />

          {/* Timing */}
          <Field label={t('detail.latency')}>
            <MonoValue>{record.latencyMs} ms</MonoValue>
          </Field>
        </div>
      </div>
    </div>
  );
}

// ---- Small sub-components ---------------------------------------------------

function Field({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn('space-y-1', className)}>
      <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">{label}</p>
      <div>{children}</div>
    </div>
  );
}

function MonoValue({ children }: { children: ReactNode }) {
  return <span className="font-mono text-sm break-all">{children}</span>;
}

function EmptyDash() {
  return <span className="text-muted-foreground text-sm">—</span>;
}

function ColumnChips({ columns, variant }: { columns: string[]; variant: 'pii' | 'masked' }) {
  if (columns.length === 0) return <EmptyDash />;
  const chipClass =
    variant === 'pii'
      ? 'border-red-500/25 bg-red-500/10 text-red-600 dark:text-red-400'
      : 'border-amber-500/25 bg-amber-500/10 text-amber-600 dark:text-amber-400';
  return (
    <div className="flex flex-wrap gap-1.5">
      {columns.map((col) => (
        <span key={col} className={cn('rounded border px-1.5 py-0.5 font-mono text-[11px]', chipClass)}>
          {col}
        </span>
      ))}
    </div>
  );
}
