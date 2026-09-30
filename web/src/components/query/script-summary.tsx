'use client'

import { useTranslations } from 'next-intl'
import { CheckCircle2, CircleSlash, Loader2, XCircle } from 'lucide-react'
import type { QueryResultMeta } from '@/lib/api/types'
import { translateApiError } from '@/lib/i18n/errors'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { leavesTransactionOpen } from './statement'
import type { SummaryTab } from './use-result-tabs'

interface Props {
  tab: SummaryTab
  canceling: boolean
  onOpen: (ordinal: number) => void
  onCancel?: () => void
}

type Outcome = 'running' | 'committed' | 'endedOpen' | 'stopped'

function outcomeOf(tab: SummaryTab): Outcome {
  const status = tab.batch?.status
  if (status == null || status === 'APPROVED' || status === 'EXECUTING') return 'running'
  if (status !== 'EXECUTED') return 'stopped'
  return leavesTransactionOpen(tab.statements) ? 'endedOpen' : 'committed'
}

const OUTCOME_TONE: Record<Outcome, string> = {
  running: 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-400',
  committed: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400',
  endedOpen: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400',
  stopped: 'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400',
}

function StatusIcon({ status }: { status: QueryResultMeta['status'] }) {
  if (status === 'DONE') return <CheckCircle2 className="size-3.5 text-emerald-600" />
  if (status === 'FAILED' || status === 'CANCELLED') return <XCircle className="size-3.5 text-red-500" />
  if (status === 'SKIPPED') return <CircleSlash className="text-muted-foreground size-3.5" />
  return <Loader2 className="text-muted-foreground size-3.5 animate-spin" />
}

export function ScriptSummary({ tab, canceling, onOpen, onCancel }: Props) {
  const t = useTranslations('Query')
  if (tab.res.error) {
    return <p className="p-4 text-sm text-red-500">{tab.res.error}</p>
  }
  const outcome = outcomeOf(tab)
  const metas = new Map((tab.batch?.statements ?? []).map((meta) => [meta.ordinal, meta]))

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className={cn('flex items-center justify-between gap-2 border-b px-4 py-2 text-sm', OUTCOME_TONE[outcome])}>
        <span>{t(`runAll.outcome.${outcome}`)}</span>
        {outcome === 'running' && onCancel && (
          <Button size="sm" variant="outline" onClick={onCancel} disabled={canceling}>
            {canceling ? t('results.canceling') : t('results.cancel')}
          </Button>
        )}
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-xs">
          <thead className="bg-muted/50 sticky top-0">
            <tr className="text-muted-foreground text-left">
              <th className="w-10 border-b px-3 py-1.5 font-normal">#</th>
              <th className="border-b px-3 py-1.5 font-normal">{t('runAll.columns.statement')}</th>
              <th className="w-48 border-b px-3 py-1.5 font-normal">{t('runAll.columns.status')}</th>
              <th className="w-32 border-b px-3 py-1.5 text-right font-normal">{t('runAll.columns.rows')}</th>
            </tr>
          </thead>
          <tbody>
            {tab.statements.map((sql, ordinal) => {
              const meta = metas.get(ordinal)
              const rows =
                meta?.status !== 'DONE' || meta.rowCount == null
                  ? ''
                  : meta.columns.length === 0
                    ? t('runAll.rowsAffected', { count: meta.rowCount })
                    : t('runAll.rowsReturned', { count: meta.rowCount })
              return (
                <tr
                  key={ordinal}
                  data-script-statement={ordinal}
                  onClick={() => onOpen(ordinal)}
                  className="hover:bg-muted/50 cursor-pointer border-b"
                >
                  <td className="text-muted-foreground px-3 py-1.5 font-mono">{ordinal + 1}</td>
                  <td className="max-w-0 truncate px-3 py-1.5 font-mono" title={sql}>
                    {sql}
                  </td>
                  <td className="px-3 py-1.5">
                    <span className="flex items-center gap-1.5">
                      <StatusIcon status={meta?.status ?? null} />
                      <span className="truncate">
                        {meta?.errorCode ? translateApiError(meta.errorCode) : t(`runAll.status.${meta?.status ?? 'PENDING'}`)}
                      </span>
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{rows}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
