'use client'

// The approval page's result workspace, matching the editor's: a permanent Logs tab first, then one tab
// per statement that ran. The editor builds its tabs by RUNNING queries; a decided request already has its
// results stored, so these tabs read them instead — the presentation (ResultsPanel, QueryLogs) is shared.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslations } from 'next-intl'
import useSWR from 'swr'
import { ScrollText } from 'lucide-react'
import { ApiError, getApprovalResult } from '@/lib/api/client'
import type { QueryResponse, QueryResultMeta, QueryResultView } from '@/lib/api/types'
import { translateApiError } from '@/lib/i18n/errors'
import { cn } from '@/lib/utils'
import { QueryLogs } from '@/components/query/query-logs'
import { ResultsPanel } from '@/components/query/results-panel'
import type { QueryLogEntry } from '@/components/query/use-result-tabs'

/** A stored result rendered through the editor's panel, which speaks QueryResponse. */
function asQueryResponse(view: QueryResultView, meta: QueryResultMeta): QueryResponse {
  return {
    decision: view.decision ?? 'ALLOW',
    decisionId: meta.decisionId ?? null,
    denyReason: meta.denyReason ?? null,
    maskedColumns: view.maskedColumns ?? [],
    piiTouched: [],
    effectiveRoles: [],
    columns: view.columns ?? [],
    rows: view.rows ?? [],
    rowsAffected: meta.rowCount ?? null,
    latencyMs: 0,
  }
}

function StatementTab({
  taskId,
  statement,
  datasourceId,
  onLog,
}: {
  taskId: number
  statement: QueryResultMeta
  datasourceId: number | null
  onLog: (entry: QueryLogEntry) => void
}) {
  const canViewRows = statement.status === 'DONE'
  // FAILED is fetched too: the view carries this statement's target-DB errorDetail, released per viewer.
  // Only an expected absence (404 can't-assume, 409 not-ready) becomes null; a 5xx re-throws so SWR retries.
  const { data: view, error } = useSWR(
    canViewRows || statement.status === 'FAILED'
      ? (['approval-result', taskId, statement.ordinal] as const)
      : null,
    () =>
      getApprovalResult(taskId, statement.ordinal).catch((e) => {
        if (e instanceof ApiError && (e.status === 404 || e.status === 409)) return null
        throw e
      }),
  )

  const failure =
    statement.status === 'FAILED'
      ? [statement.errorCode ? translateApiError(statement.errorCode) : null, view?.errorDetail]
          .filter(Boolean)
          .join('\n')
      : null

  // Feed the Logs tab one line per statement, the way a run does in the editor.
  const entry = useMemo<QueryLogEntry>(
    () => ({
      id: `${taskId}:${statement.ordinal}`,
      datasourceId: datasourceId ?? 0,
      statement: statement.sql ?? '',
      // ERROR, not DENY: a FAILED statement was authorized and then failed on the target DB. A DENY here
      // would read as "policy refused it", which is a different outcome entirely.
      decision: statement.status === 'FAILED' ? 'ERROR' : (view?.decision ?? 'ALLOW'),
      denyReason: failure,
      rowsReturned: statement.rowCount ?? 0,
      latencyMs: 0,
      error: failure,
      timestamp: statement.executedAt ?? '',
    }),
    [taskId, datasourceId, statement, view, failure],
  )
  useEffect(() => {
    onLog(entry)
  }, [entry, onLog])

  return (
    <ResultsPanel
      result={view && canViewRows ? asQueryResponse(view, statement) : null}
      running={false}
      error={failure ?? (error ? String(error) : null)}
      onRequestAccess={() => {}}
    />
  )
}

export function ApprovalResultTabs({
  taskId,
  datasourceId,
  statements,
}: {
  taskId: number
  datasourceId: number | null
  statements: QueryResultMeta[]
}) {
  const t = useTranslations('Query')
  const tq = useTranslations('Workflows')
  // Only statements that RAN have a result to show; a skipped one is visible in the script above.
  const ran = statements.filter((s) => s.status === 'DONE' || s.status === 'FAILED')
  const [activeOrdinal, setActiveOrdinal] = useState<number | null>(ran[0]?.ordinal ?? null)
  const [viewingLogs, setViewingLogs] = useState(false)
  const [logs, setLogs] = useState<Record<string, QueryLogEntry>>({})

  // Compared by VALUE and stable across renders: the effect below rebuilds its entry object every render,
  // so an identity check would set state forever.
  const addLog = useCallback((entry: QueryLogEntry) => {
    setLogs((prev) => {
      const seen = prev[entry.id]
      if (seen && JSON.stringify(seen) === JSON.stringify(entry)) return prev
      return { ...prev, [entry.id]: entry }
    })
  }, [])

  if (ran.length === 0) return null
  const active = ran.find((s) => s.ordinal === activeOrdinal) ?? ran[0]

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <div className="flex shrink-0 items-stretch overflow-x-auto border-b">
        <div
          role="tab"
          aria-selected={viewingLogs}
          onClick={() => setViewingLogs(true)}
          className={cn(
            'flex shrink-0 cursor-pointer items-center gap-1.5 border-r px-3 py-1.5 text-xs',
            viewingLogs ? 'bg-background text-foreground' : 'text-muted-foreground hover:bg-muted/50',
          )}
        >
          <ScrollText className="size-3.5 shrink-0" />
          <span>{t('tabs.logs')}</span>
        </div>
        {ran.map((statement) => {
          const selected = !viewingLogs && statement.ordinal === active.ordinal
          return (
            <div
              key={statement.ordinal}
              role="tab"
              aria-selected={selected}
              onClick={() => {
                setViewingLogs(false)
                setActiveOrdinal(statement.ordinal)
              }}
              className={cn(
                'flex shrink-0 cursor-pointer items-center gap-1.5 border-r px-3 py-1.5 text-xs',
                selected ? 'bg-background text-foreground' : 'text-muted-foreground hover:bg-muted/50',
                statement.status === 'FAILED' && !selected && 'text-red-500/80',
              )}
              title={statement.sql ?? undefined}
            >
              <span className={cn(statement.status === 'FAILED' && 'text-red-500')}>
                {tq('approvalDetail.statementTab', { n: statement.ordinal + 1 })}
              </span>
            </div>
          )
        })}
      </div>

      <div className="flex min-h-0 flex-1 flex-col">
        {viewingLogs ? (
          <QueryLogs logs={ran.map((s) => logs[`${taskId}:${s.ordinal}`]).filter(Boolean)} clearLogs={() => setLogs({})} />
        ) : (
          <StatementTab
            key={active.ordinal}
            taskId={taskId}
            statement={active}
            datasourceId={datasourceId}
            onLog={addLog}
          />
        )}
        {/* Every statement mounts so the Logs tab is complete without visiting each one; only the
            active one is visible. */}
        <div className="hidden">
          {ran
            .filter((s) => s.ordinal !== active.ordinal)
            .map((s) => (
              <StatementTab
                key={s.ordinal}
                taskId={taskId}
                statement={s}
                datasourceId={datasourceId}
                onLog={addLog}
              />
            ))}
        </div>
      </div>
    </div>
  )
}
