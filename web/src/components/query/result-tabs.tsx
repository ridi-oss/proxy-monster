'use client'

// The result workspace: an outer strip of tabs (a permanent, non-closable Logs tab first, then
// one per query / opened table with pin + close) and the active tab's content (the plain console
// log, a query result, or a table's Schema/Data view).
import { Fragment, useEffect, useRef, useState } from 'react'
import { useTranslations } from 'next-intl'
import { ChevronDown, ChevronRight, ListChecks, Pin, Table2, SquareTerminal, ScrollText, X, Loader2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import { QueryLogs } from './query-logs'
import { ResultsPanel } from './results-panel'
import { TableView } from './table-view'
import { ScriptSummary } from './script-summary'
import type { ResultTab, ResultTabsApi } from './use-result-tabs'

export function ResultTabs({
  api,
  onRequestAccess,
  onRequestRateReset,
}: {
  api: ResultTabsApi
  onRequestAccess: (denyReason?: string | null) => void
  onRequestRateReset?: (denyReason?: string | null) => void
}) {
  const t = useTranslations('Query')
  const { tabs, activeId, active, logs, clearLogs } = api
  const [viewingLogs, setViewingLogs] = useState(false)

  // Running a query or opening a table appends a new tab — bring that result forward, the way
  // DataGrip switches out of its Output panel when a statement finishes. Re-running an existing
  // (unpinned) tab, or closing some other tab, doesn't touch the tab count, so it leaves the
  // user's current view (including Logs) alone.
  const prevTabCount = useRef(tabs.length)
  useEffect(() => {
    if (tabs.length > prevTabCount.current) setViewingLogs(false)
    prevTabCount.current = tabs.length
  }, [tabs.length])

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Tab strip */}
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
        {tabs.map((tab, index) => {
          const group = tab.groupId
          const startsGroup = group != null && tabs[index - 1]?.groupId !== group
          const collapsed = group != null && api.collapsedGroups.has(group)
          return (
            <Fragment key={tab.id}>
              {startsGroup && (
                <GroupChip
                  count={tabs.filter((other) => other.groupId === group).length}
                  collapsed={collapsed}
                  onToggle={() => api.toggleGroup(group)}
                  onClose={() => api.closeGroup(group)}
                />
              )}
              {(!collapsed || tab.kind === 'summary') && (
                <TabChip
                  tab={tab}
                  active={!viewingLogs && tab.id === activeId}
                  onSelect={() => {
                    setViewingLogs(false)
                    api.setActive(tab.id)
                  }}
                  onPin={() => api.pin(tab.id)}
                  onClose={() => api.close(tab.id)}
                />
              )}
            </Fragment>
          )
        })}
      </div>

      {/* Active content */}
      <div className="flex min-h-0 flex-1 flex-col">
        {viewingLogs ? (
          <QueryLogs logs={logs} clearLogs={clearLogs} />
        ) : active?.kind === 'summary' ? (
          <ScriptSummary
            tab={active}
            canceling={active.res.canceling}
            onOpen={(ordinal) => active.groupId != null && api.openStatement(active.groupId, ordinal)}
            onCancel={active.taskId != null ? () => api.cancel(active.id) : undefined}
          />
        ) : active?.kind === 'table' ? (
          <TableView tab={active} onRequestAccess={onRequestAccess} onRequestRateReset={onRequestRateReset} />
        ) : active ? (
          <ResultsPanel
            result={active.res.result}
            running={active.res.loading}
            canceling={active.res.canceling}
            canceled={active.res.canceled}
            error={active.res.error}
            onCancel={active.res.loading && active.taskId != null ? () => api.cancel(active.id) : undefined}
            onRequestAccess={() => onRequestAccess(active.res.result?.denyReason)}
            onRequestRateReset={onRequestRateReset && (() => onRequestRateReset(active.res.result?.denyReason))}
          />
        ) : (
          <ResultsPanel
            result={null}
            running={false}
            error={null}
            onRequestAccess={() => onRequestAccess(null)}
          />
        )}
      </div>
    </div>
  )
}

function TabChip({
  tab,
  active,
  onSelect,
  onPin,
  onClose,
}: {
  tab: ResultTab
  active: boolean
  onSelect: () => void
  onPin: () => void
  onClose: () => void
}) {
  const t = useTranslations('Query')
  const Icon = tab.kind === 'table' ? Table2 : tab.kind === 'summary' ? ListChecks : SquareTerminal
  return (
    <div
      data-result-tab=""
      role="tab"
      aria-selected={active}
      onClick={onSelect}
      data-group-tab={tab.groupId != null ? '' : undefined}
      title={tab.kind === 'query' ? tab.sql : tab.kind === 'table' ? tab.table.qualified : tab.title}
      className={cn(
        'group flex max-w-56 shrink-0 cursor-pointer items-center gap-1.5 border-r px-3 py-1.5 text-xs',
        tab.groupId != null && 'bg-muted/30',
        active ? 'bg-background text-foreground' : 'text-muted-foreground hover:bg-muted/50',
      )}
    >
      {tab.res.loading ? (
        <Loader2 className="size-3.5 shrink-0 animate-spin" />
      ) : (
        <Icon className="size-3.5 shrink-0" />
      )}
      <span className={cn('truncate', tab.kind === 'query' && 'font-mono')}>{tab.title}</span>
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); onPin() }}
        aria-label={tab.pinned ? t('tabs.unpin') : t('tabs.pin')}
        className={cn(
          'ml-0.5 shrink-0 rounded p-0.5',
          tab.pinned ? 'text-foreground' : 'text-muted-foreground opacity-0 group-hover:opacity-100 hover:text-foreground',
        )}
      >
        <Pin className={cn('size-3', tab.pinned && 'fill-current')} />
      </button>
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); onClose() }}
        aria-label={t('tabs.close')}
        className="text-muted-foreground hover:text-foreground shrink-0 rounded p-0.5 opacity-0 group-hover:opacity-100"
      >
        <X className="size-3" />
      </button>
    </div>
  )
}

function GroupChip({
  count,
  collapsed,
  onToggle,
  onClose,
}: {
  count: number
  collapsed: boolean
  onToggle: () => void
  onClose: () => void
}) {
  const t = useTranslations('Query')
  const Chevron = collapsed ? ChevronRight : ChevronDown
  return (
    <div className="bg-muted/60 text-muted-foreground flex shrink-0 items-center gap-1 border-r px-2 py-1.5 text-xs">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={!collapsed}
        aria-label={collapsed ? t('runAll.expandGroup') : t('runAll.collapseGroup')}
        className="hover:text-foreground flex items-center gap-1 rounded"
      >
        <Chevron className="size-3.5" />
        <span className="font-medium">{t('runAll.groupLabel', { count })}</span>
      </button>
      <button
        type="button"
        onClick={onClose}
        aria-label={t('runAll.closeGroup')}
        className="hover:text-foreground ml-0.5 rounded p-0.5"
      >
        <X className="size-3" />
      </button>
    </div>
  )
}
