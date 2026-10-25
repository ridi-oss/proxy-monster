'use client';

// /audit — live audit log merging Feed + Audit history (docs/web-console.md).
// Polls GET /api/audit every 5 s by default; the pause toggle flips the interval
// to 0 so SWR stops re-fetching. Filters are all client-side against the
// 200-event window returned by the API.
import Link from 'next/link';
import { useMemo, useState } from 'react';
import { useTranslations } from 'next-intl';
import type { AuditEvent, Decision } from '@/lib/api/types';
import { useAuditEvents, useMePermissions } from '@/lib/hooks';
import { decisionTone } from '@/lib/decision';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/page-scaffold';
import { EmptyState, ErrorState } from '@/components/page-scaffold';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet';
import { DecisionRow, DecisionRowSkeleton } from '@/components/audit/decision-row';
import { DecisionDetail } from '@/components/audit/decision-detail';

// Decisions we can filter to (ALL means no filter applied).
type FilterDecision = Decision | 'ALL';

/** Stable row key: server id when present, else ts + principal + statement length + index. */
function rowKey(r: AuditEvent, i: number): string {
  return r.id != null ? String(r.id) : `${r.ts ?? 'na'}|${r.principal}|${r.statement.length}|${i}`;
}

export default function AuditPage() {
  const t = useTranslations('Audit');
  const [live, setLive] = useState(true);
  const [decisionFilter, setDecisionFilter] = useState<FilterDecision>('ALL');
  const [search, setSearch] = useState('');
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  // refreshInterval=0 stops SWR polling; 5000 gives a 5-second live feed.
  const { data, error, isLoading } = useAuditEvents(200, {
    refreshInterval: live ? 5000 : 0,
  });
  const { data: permissions } = useMePermissions();

  const records = useMemo(() => data ?? [], [data]);

  // Client-side filter: decision type + text search (principal OR statement).
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return records.filter((d) => {
      if (decisionFilter !== 'ALL' && d.decision !== decisionFilter) return false;
      if (q && !d.principal.toLowerCase().includes(q) && !d.statement.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [records, decisionFilter, search]);

  // Per-decision count summary over the current filtered set.
  const counts = useMemo(() => {
    const c: Record<Decision, number> = { ALLOW: 0, MASK: 0, DENY: 0, ERROR: 0 };
    for (const d of filtered) c[d.decision] += 1;
    return c;
  }, [filtered]);

  const rows = useMemo(() => filtered.map((r, i) => ({ key: rowKey(r, i), record: r })), [filtered]);

  const selectedRecord = rows.find((r) => r.key === selectedKey)?.record ?? null;

  return (
    // Full-height flex column so the list scrolls inside the shell's overflow area.
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader
        title={t('log.title')}
        subtitle={permissions?.canReadAllAudit === false ? t('log.subtitleMine') : t('log.subtitleAll')}
        actions={
          // Live indicator: pulsing green dot + pause toggle.
          <div className="flex items-center gap-2.5">
            <span
              className={cn('relative flex size-2 shrink-0', live ? 'text-emerald-500' : 'text-zinc-500')}
              aria-label={live ? t('live.live') : t('live.paused')}
            >
              {/* Ping animation when live */}
              {live && (
                <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              )}
              <span
                className={cn('relative inline-flex size-2 rounded-full', live ? 'bg-emerald-500' : 'bg-zinc-500')}
              />
            </span>
            <span className="text-muted-foreground text-xs">{live ? t('live.live') : t('live.paused')}</span>
            <Switch size="sm" checked={live} onCheckedChange={setLive} aria-label={t('live.toggle')} />
          </div>
        }
      />

      {/* Toolbar: decision filter + text search */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b px-6 py-3">
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Decision filter */}
          <Select
            value={decisionFilter}
            onValueChange={(v: string | null) => setDecisionFilter((v ?? 'ALL') as FilterDecision)}
          >
            <SelectTrigger size="sm" className="w-[120px]">
              <SelectValue placeholder={t('filter.allDecisions')}>
                {(v: string | null) => (v === 'ALL' || v == null ? t('filter.all') : v)}
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ALL">{t('filter.allDecisions')}</SelectItem>
              <SelectItem value="ALLOW">ALLOW</SelectItem>
              <SelectItem value="MASK">MASK</SelectItem>
              <SelectItem value="DENY">DENY</SelectItem>
              <SelectItem value="ERROR">ERROR</SelectItem>
            </SelectContent>
          </Select>

          {/* Text search */}
          <Input
            className="h-7 w-[240px] text-xs"
            placeholder={t('filter.searchPlaceholder')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Decision count chips */}
        <div className="flex items-center gap-1.5">
          <span className="text-muted-foreground text-xs tabular-nums">
            {filtered.length} / {records.length}
          </span>
          {(
            [
              ['ALLOW', counts.ALLOW],
              ['MASK', counts.MASK],
              ['DENY', counts.DENY],
              ...(counts.ERROR > 0 ? [['ERROR', counts.ERROR]] : []),
            ] as [Decision, number][]
          ).map(([d, n]) => (
            <span
              key={d}
              className={cn('rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold', decisionTone[d].badge)}
            >
              {n} {d}
            </span>
          ))}
        </div>
      </div>

      {/* Decision list — flex-1 + overflow so it fills and scrolls independently */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {isLoading && records.length === 0 ? (
          // Skeleton rows while the first fetch is in flight.
          <>
            {Array.from({ length: 12 }).map((_, i) => (
              <DecisionRowSkeleton key={i} />
            ))}
          </>
        ) : error ? (
          <div className="px-6 py-6">
            <ErrorState error={error} />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            title={records.length > 0 ? t('empty.noMatchTitle') : t('empty.noneTitle')}
            hint={records.length > 0 ? t('empty.noMatchHint') : t('empty.noneHint')}
          />
        ) : (
          rows.map(({ key, record }) => (
            <DecisionRow
              key={key}
              record={record}
              selected={key === selectedKey}
              onSelect={() => setSelectedKey(selectedKey === key ? null : key)}
            />
          ))
        )}
      </div>

      {/* Right detail sheet — opens on row click, closes on overlay or X. */}
      <Sheet
        open={selectedRecord !== null}
        onOpenChange={(open) => {
          if (!open) setSelectedKey(null);
        }}
      >
        <SheetContent
          side="right"
          // Wider than the shadcn default sm:max-w-sm to fit the SQL block comfortably.
          className="sm:max-w-xl w-full gap-0 p-0"
          showCloseButton
        >
          <SheetHeader className="sr-only">
            <SheetTitle>{t('sheet.title')}</SheetTitle>
            <SheetDescription>{t('sheet.description')}</SheetDescription>
          </SheetHeader>
          {selectedRecord && (
            <div className="flex h-full min-h-0 flex-col">
              {selectedRecord.id != null && (
                <div className="flex flex-wrap items-center gap-3 border-b px-5 py-2 text-xs">
                  <Link href={`/audit/${selectedRecord.id}`} className="text-primary underline underline-offset-4">
                    {t('sheet.permalink')}
                  </Link>
                  {selectedRecord.decision === 'DENY' && (
                    <Link
                      href={`/workflows/new?from=${selectedRecord.id}`}
                      className="text-primary underline underline-offset-4"
                    >
                      {t('sheet.requestApproval')}
                    </Link>
                  )}
                </div>
              )}
              <DecisionDetail record={selectedRecord} />
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
