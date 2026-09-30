'use client'

// The SQL editor workbench (GCP BigQuery-console layout, Vercel polish).
// Left rail: datasource picker + searchable schema/table/column explorer.
// Right: a resizable editor-over-results split — CodeMirror with a toolbar
// (Run, row limit, shortcut hint) on top, the enforcing results panel below.
// Every query is policy-enforced server-side: ALLOW / MASK / DENY; a DENY opens
// the JIT request dialog.
import { useMemo, useRef, useState } from 'react'
import { useTranslations } from 'next-intl'
import { ListChecks, Loader2, Play, TriangleAlert, Unplug } from 'lucide-react'
import { useCatalog, useDatasources } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from '@/components/ui/resizable'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { LoadingState } from '@/components/page-scaffold'
import { DatasourceSelect } from '@/components/datasource-select'
import { buildSchemaMap, buildTree } from './catalog-schema'
import { usePersistedDatasource } from './use-persisted-datasource'
import { usePersistedSql } from './use-persisted-sql'
import { useResultTabs } from './use-result-tabs'
import { SchemaTree } from './schema-tree'
import { SqlEditor, type SqlEditorHandle } from './sql-editor'
import { ResultTabs } from './result-tabs'
import { QueryHistoryMenu } from './query-history-menu'
import { RequestAccessDialog } from './request-access-dialog'
import { RateResetRequestDialog } from './rate-reset-request-dialog'
import { CloseSessionDialog } from './close-session-dialog'
import { RunAllConfirmDialog } from './run-all-confirm-dialog'
import { opensTransaction } from './statement'

const ROW_LIMITS = [100, 200, 500, 1000, 5000]
const SCRIPT_TIMEOUTS = ['30', '60', '300', '600']

// The proxy's shipped default row cap (docs/result-caps.md): a page size above it can only produce a capped run.
const DEFAULT_CAP_ROWS = 5000

export function Workbench() {
  const t = useTranslations('Query')
  const [datasourceId, setDatasourceId] = usePersistedDatasource()
  const [sql, setSql] = usePersistedSql()
  const [maxRows, setMaxRows] = useState('200')
  const [requestOpen, setRequestOpen] = useState(false)
  const [denyReason, setDenyReason] = useState<string | null>(null)
  const [rateResetOpen, setRateResetOpen] = useState(false)
  const [rateDenyReason, setRateDenyReason] = useState<string | null>(null)
  const [closeSessionOpen, setCloseSessionOpen] = useState(false)
  const [scriptTimeout, setScriptTimeout] = useState('300')
  const [notice, setNotice] = useState<'selectOne' | 'useRunAll' | 'selectAll' | null>(null)
  const [pendingScript, setPendingScript] = useState<string | null>(null)
  const editorRef = useRef<SqlEditorHandle>(null)

  const { data: catalog, isLoading: catalogLoading, error: catalogError } = useCatalog(datasourceId)
  const { data: datasources, isLoading: datasourcesLoading, error: datasourcesError } = useDatasources(true)
  const datasource = datasources?.find((item) => item.id === datasourceId)
  const tree = useMemo(() => buildTree(catalog ?? [], datasource), [catalog, datasource])
  const schemaMap = useMemo(() => buildSchemaMap(tree, datasource?.engine), [tree, datasource?.engine])

  const rowLimits = useMemo(() => ROW_LIMITS.filter((n) => n <= DEFAULT_CAP_ROWS).map(String), [])
  const effectiveMaxRows = rowLimits.includes(maxRows) ? maxRows : rowLimits[rowLimits.length - 1]

  const resultTabs = useResultTabs(datasourceId, Number(effectiveMaxRows))
  const running = resultTabs.active?.res.loading ?? false
  const canRun = datasourceId != null && sql.trim().length > 0

  const handleSqlChange = (value: string) => {
    setNotice(null)
    setSql(value)
  }

  const handleRun = () => {
    if (datasourceId == null) return
    const target = editorRef.current?.runTarget()
    if (!target || target.kind === 'empty') return
    if (target.kind !== 'run') {
      setNotice(target.kind)
      return
    }
    setNotice(null)
    resultTabs.run(target.sql)
  }

  const handleRunAll = () => {
    if (datasourceId == null) return
    const target = editorRef.current?.runAllTarget()
    if (!target || target.kind === 'empty') return
    if (target.kind === 'selectAll') {
      setNotice('selectAll')
      return
    }
    setNotice(null)
    if (opensTransaction(target.sql)) resultTabs.runAll(target.sql, Number(scriptTimeout))
    else setPendingScript(target.sql)
  }

  const handleRequestAccess = (reason?: string | null) => {
    setDenyReason(reason ?? null)
    setRequestOpen(true)
  }
  const handleRequestRateReset = (reason?: string | null) => {
    setRateDenyReason(reason ?? null)
    setRateResetOpen(true)
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex min-h-0 flex-1">
        {/* Explorer rail (fixed-width sidebar) */}
        <aside className="flex w-72 shrink-0 flex-col border-r">
            <div className="space-y-2 border-b p-2">
              <p className="text-muted-foreground px-1 text-[11px] font-medium tracking-wider uppercase">
                {t('workbench.explorer')}
              </p>
              <DatasourceSelect
                value={datasourceId}
                onChange={setDatasourceId}
                className="w-full"
                connectableOnly
              />
            </div>
            {datasourceId == null ? (
              <p className="text-muted-foreground p-3 text-xs">{t('workbench.selectDatasource')}</p>
            ) : (catalogLoading && !catalog) || datasourcesLoading ? (
              <div className="p-2">
                <LoadingState label={t('workbench.loadingSchema')} />
              </div>
            ) : catalogError || datasourcesError ? (
              <p className="p-3 text-xs text-red-500">{t('workbench.catalogError')}</p>
            ) : tree.length === 0 ? (
              <p className="text-muted-foreground p-3 text-xs">
                {t('workbench.noCatalog')}
              </p>
            ) : (
              <SchemaTree
                datasourceId={datasourceId}
                tables={tree}
                onInsert={(text) => editorRef.current?.insertAtCursor(text)}
                onOpenTable={resultTabs.openTable}
              />
            )}
        </aside>

        {/* Editor + results */}
        <div className="flex min-w-0 flex-1 flex-col">
          <ResizablePanelGroup orientation="vertical" className="min-h-0 flex-1">
            <ResizablePanel defaultSize={52} minSize={20}>
              <div className="flex h-full min-h-0 flex-col">
                {/* Toolbar */}
                <div className="flex items-center justify-between gap-2 border-b px-3 py-2">
                  <div className="flex items-center gap-1.5">
                    <Button size="sm" onClick={handleRun} disabled={!canRun}>
                      {running ? (
                        <Loader2 className="size-3.5 animate-spin" />
                      ) : (
                        <Play className="size-3.5" />
                      )}
                      {t('workbench.run')}
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={handleRunAll}
                      disabled={!canRun}
                      title={t('runAll.shortcut')}
                    >
                      <ListChecks className="size-3.5" />
                      {t('runAll.button')}
                    </Button>
                    <Select value={scriptTimeout} onValueChange={(v: string | null) => setScriptTimeout(v ?? '300')}>
                      <SelectTrigger size="sm" className="w-24" aria-label={t('runAll.timeout')}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SCRIPT_TIMEOUTS.map((seconds) => (
                          <SelectItem key={seconds} value={seconds}>
                            {t('runAll.timeoutOption', { seconds: Number(seconds) })}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <QueryHistoryMenu onPick={handleSqlChange} />
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setCloseSessionOpen(true)}
                      disabled={!resultTabs.sessionOpen}
                    >
                      <Unplug className="size-3.5" />
                      {t('session.close')}
                    </Button>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground hidden text-xs sm:inline">
                      <kbd className="bg-muted rounded border px-1 py-0.5 font-mono text-[10px]">
                        ⌘
                      </kbd>
                      /
                      <kbd className="bg-muted rounded border px-1 py-0.5 font-mono text-[10px]">
                        Ctrl
                      </kbd>{' '}
                      + Enter
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span className="text-muted-foreground text-xs">{t('workbench.limit')}</span>
                      <Select
                        value={effectiveMaxRows}
                        onValueChange={(v: string | null) => setMaxRows(v ?? '200')}
                      >
                        <SelectTrigger size="sm" className="w-20">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {rowLimits.map((n) => (
                            <SelectItem key={n} value={n}>
                              {n}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </div>
                {notice && (
                  <div
                    role="status"
                    className="flex items-center gap-2 border-b border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-700 dark:text-amber-400"
                  >
                    <TriangleAlert className="size-3.5 shrink-0" />
                    {t(`runRules.${notice}`)}
                  </div>
                )}
                {/* Editor */}
                <div className={cn('min-h-0 flex-1 overflow-hidden')}>
                  <SqlEditor
                    ref={editorRef}
                    value={sql}
                    onChange={handleSqlChange}
                    schema={schemaMap}
                    engine={datasource?.engine}
                    onRun={handleRun}
                    onRunAll={handleRunAll}
                    linkedQuery={resultTabs.active?.kind === 'query' ? resultTabs.active.sql : null}
                  />
                </div>
              </div>
            </ResizablePanel>

            <ResizableHandle />

            <ResizablePanel defaultSize={48} minSize={15}>
              <ResultTabs api={resultTabs} onRequestAccess={handleRequestAccess} onRequestRateReset={handleRequestRateReset} />
            </ResizablePanel>
          </ResizablePanelGroup>
        </div>
      </div>

      <RunAllConfirmDialog
        open={pendingScript != null}
        onOpenChange={(open) => !open && setPendingScript(null)}
        onConfirm={() => {
          if (pendingScript != null) resultTabs.runAll(pendingScript, Number(scriptTimeout))
          setPendingScript(null)
        }}
      />
      <CloseSessionDialog
        open={closeSessionOpen}
        onOpenChange={setCloseSessionOpen}
        onConfirm={resultTabs.closeSession}
      />
      <RateResetRequestDialog open={rateResetOpen} onOpenChange={setRateResetOpen} denyReason={rateDenyReason} />
      {datasourceId != null && (
        <RequestAccessDialog
          open={requestOpen}
          onOpenChange={setRequestOpen}
          datasourceId={datasourceId}
          denyReason={denyReason}
        />
      )}
    </div>
  )
}
