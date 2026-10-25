'use client';

// Plain console-style output for the session's query history — DataGrip's "Output" panel,
// not a formatted results view: one monospace line per event, no badges or cards.
import { useTranslations } from 'next-intl';
import { Button } from '@/components/ui/button';
import { useDatasources } from '@/lib/hooks';
import type { QueryLogEntry } from './use-result-tabs';

function formatLogTimestamp(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// DENY/ERROR read as errors, MASK as a warning — ALLOW stays the default text color so the
// common case doesn't compete for attention with the lines that actually need it.
function outcomeTone(decision: QueryLogEntry['decision']): string {
  if (decision === 'DENY' || decision === 'ERROR') return 'text-red-500 font-medium';
  if (decision === 'MASK') return 'text-amber-500 font-medium';
  return '';
}

export function QueryLogs({ logs, clearLogs }: { logs: QueryLogEntry[]; clearLogs: () => void }) {
  const t = useTranslations('Query');
  const { data: datasources } = useDatasources();

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 items-center justify-between gap-3 border-b px-4 py-1.5">
        <p className="text-muted-foreground text-xs">{t('logs.countThisSession', { count: logs.length })}</p>
        <Button
          type="button"
          variant="outline"
          size="xs"
          onClick={clearLogs}
          disabled={logs.length === 0}
          data-testid="clear-editor-logs"
        >
          {t('logs.clear')}
        </Button>
      </div>

      {logs.length === 0 ? (
        <div className="flex min-h-0 flex-1 items-center justify-center p-6 text-center">
          <p className="text-muted-foreground text-xs">{t('logs.emptyTitle')}</p>
        </div>
      ) : (
        <div className="min-h-0 flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap">
          {logs.map((entry) => {
            const ts = formatLogTimestamp(entry.timestamp);
            const dsName = datasources?.find((d) => d.id === entry.datasourceId)?.name ?? entry.datasourceId;
            const outcome =
              entry.decision === 'DENY'
                ? t('logs.deniedLine', { reason: entry.denyReason ?? '', ms: entry.latencyMs })
                : entry.decision === 'ERROR'
                  ? t('logs.errorLine', { message: entry.error ?? '', ms: entry.latencyMs })
                  : entry.decision === 'MASK'
                    ? t('logs.maskedRowsLine', { count: entry.rowsReturned, ms: entry.latencyMs })
                    : t('logs.rowsLine', { count: entry.rowsReturned, ms: entry.latencyMs });
            return (
              <div key={entry.id} data-testid="editor-log-entry">
                <div className="text-foreground/80">{`[${ts}] ${dsName}> ${entry.statement}`}</div>
                <div className={outcomeTone(entry.decision)}>{`[${ts}] ${outcome}`}</div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
