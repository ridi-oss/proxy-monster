'use client'

import Link from 'next/link'
import { useTranslations } from 'next-intl'
import type { WorkflowRequestEntry } from '@/lib/workflow-requests'
import { cn } from '@/lib/utils'

type Translator = ReturnType<typeof useTranslations>

const STATUS_STYLE: Record<string, string> = {
  PENDING: 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  APPROVED: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  REJECTED: 'border-red-500/30 bg-red-500/10 text-red-500',
}

const KIND_STYLE: Record<WorkflowRequestEntry['request']['kind'], string> = {
  ROLE: 'border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400',
  QUERY: 'border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400',
}

function formatRelative(iso: string, t: Translator): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (seconds < 60) return t('relativeTime.justNow')
  if (seconds < 3600) return t('relativeTime.minutesAgo', { count: Math.floor(seconds / 60) })
  if (seconds < 86_400) return t('relativeTime.hoursAgo', { count: Math.floor(seconds / 3600) })
  return t('relativeTime.daysAgo', { count: Math.floor(seconds / 86_400) })
}

function oneLine(value: string | null | undefined, t: Translator): string {
  return value?.replace(/\s+/g, ' ').trim() || t('values.noSqlAttached')
}

function requestTitle(entry: WorkflowRequestEntry, t: Translator): string {
  const { request } = entry
  const role =
    request.roleName ?? (request.roleId != null ? `#${request.roleId}` : t('values.unknownRole'))
  return request.kind === 'ROLE'
    ? t('requestList.roleAccessTitle', { role })
    : request.title || t('requestList.queryApprovalTitle', { id: request.id })
}

function requestContext(entry: WorkflowRequestEntry, t: Translator): string {
  const { request } = entry
  const datasource = request.datasourceName
    ?? (request.datasourceId != null
      ? t('values.datasourceNumbered', { id: request.datasourceId })
      : t('values.anyDatasourceLower'))
  return `${request.principal} · ${datasource}`
}

function requestPreview(entry: WorkflowRequestEntry, t: Translator): string {
  const { request } = entry
  if (request.kind !== 'QUERY') return request.reason ?? ''
  const preview = oneLine(request.sql, t)
  // A batch collapses to one line, so say how many statements it holds — otherwise the preview reads as a
  // single statement that happens to be long.
  const count = request.statementCount ?? 1
  return count > 1 ? `${preview} (${t('queryComposer.statementCount', { count })})` : preview
}

export function WorkflowRequestList({
  entries,
  selectedId,
}: {
  entries: WorkflowRequestEntry[]
  selectedId?: number | null
}) {
  const t = useTranslations('Workflows')
  return (
    <div data-testid="workflow-request-list" className="divide-y">
      {entries.map((entry) => {
        const { request } = entry
        const selected = selectedId === request.id

        return (
          <Link
            key={`${request.kind}-${request.id}`}
            href={`/workflows/${request.id}`}
            data-testid="workflow-request-row"
            data-kind={request.kind}
            data-status={request.status}
            data-request-id={request.id}
            aria-current={selected ? 'page' : undefined}
            className={cn(
              'group relative block px-4 py-3 text-sm transition-colors',
              'hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset',
              selected && 'bg-muted/60',
            )}
          >
            <span
              className={cn(
                'absolute inset-y-0 left-0 w-[3px]',
                request.kind === 'ROLE' ? 'bg-violet-500' : 'bg-sky-500',
                !selected && 'opacity-60 group-hover:opacity-100',
              )}
            />

            <div className="flex min-w-0 items-start gap-3">
              <div className="min-w-0 flex-1 space-y-1.5">
                <div className="flex min-w-0 items-center gap-1.5">
                  <span
                    className={cn(
                      'inline-flex shrink-0 rounded border px-1.5 py-px font-mono text-[10px] font-semibold',
                      KIND_STYLE[request.kind],
                    )}
                  >
                    {request.kind}
                  </span>
                  <span
                    className={cn(
                      'inline-flex shrink-0 rounded border px-1.5 py-px text-[10px] font-medium',
                      STATUS_STYLE[request.status] ?? 'border-border text-muted-foreground',
                    )}
                  >
                    {request.status}
                  </span>
                  <span className="min-w-0 flex-1 truncate font-medium">
                    {requestTitle(entry, t)}
                  </span>
                </div>

                <p className="text-muted-foreground truncate font-mono text-[11px]">
                  {requestContext(entry, t)}
                </p>
                <p
                  className={cn(
                    'text-foreground/70 truncate text-xs',
                    request.kind === 'QUERY' && 'font-mono',
                  )}
                >
                  {requestPreview(entry, t)}
                </p>
              </div>

              <div className="flex shrink-0 flex-col items-end gap-1.5">
                <time
                  dateTime={request.createdAt}
                  title={new Date(request.createdAt).toLocaleString()}
                  className="text-muted-foreground font-mono text-[10px] tabular-nums"
                >
                  {formatRelative(request.createdAt, t)}
                </time>
                <div className="flex max-w-24 flex-wrap justify-end gap-1">
                  {entry.incoming && (
                    <span className="rounded bg-red-500/10 px-1.5 py-px text-[9px] font-medium text-red-500">
                      {t('requestList.incoming')}
                    </span>
                  )}
                  {entry.outgoing && (
                    <span className="bg-muted text-muted-foreground rounded px-1.5 py-px text-[9px] font-medium">
                      {t('requestList.outgoing')}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </Link>
        )
      })}
    </div>
  )
}
