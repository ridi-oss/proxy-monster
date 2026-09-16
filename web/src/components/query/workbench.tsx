'use client'

// The SQL editor workbench (GCP BigQuery-console layout, Vercel polish).
// Left rail: datasource picker + searchable schema/table/column explorer.
// Right: a resizable editor-over-results split — CodeMirror with a toolbar
// (Run, row limit, shortcut hint) on top, the enforcing results panel below.
// Every query is policy-enforced server-side: ALLOW / MASK / DENY; a DENY opens
// the JIT request dialog.
import { useMemo, useRef, useState } from 'react'
import { useTranslations } from 'next-intl'
import { Loader2, Play } from 'lucide-react'
import { useCatalog } from '@/lib/hooks'
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

const ROW_LIMITS = ['100', '200', '500', '1000', '5000']

export function Workbench() {
  const t = useTranslations('Query')
  const [datasourceId, setDatasourceId] = usePersistedDatasource()
  const [sql, setSql] = usePersistedSql()
  const [maxRows, setMaxRows] = useState('200')
  const [requestOpen, setRequestOpen] = useState(false)
  const [denyReason, setDenyReason] = useState<string | null>(null)
  const editorRef = useRef<SqlEditorHandle>(null)

  const { data: catalog, isLoading: catalogLoading, error: catalogError } = useCatalog(datasourceId)
  const tree = useMemo(() => buildTree(catalog ?? []), [catalog])
  const schemaMap = useMemo(() => buildSchemaMap(tree), [tree])

  const resultTabs = useResultTabs(datasourceId, Number(maxRows))
  const running = resultTabs.active?.res.loading ?? false
  const canRun = datasourceId != null && sql.trim().length > 0

  const handleRun = () => {
    if (datasourceId == null) return
    const query = editorRef.current?.currentQuery()?.trim()
    if (query) resultTabs.run(query)
  }

  const handleRequestAccess = (reason?: string | null) => {
    setDenyReason(reason ?? null)
    setRequestOpen(true)
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
            ) : catalogLoading && !catalog ? (
              <div className="p-2">
                <LoadingState label={t('workbench.loadingSchema')} />
              </div>
            ) : catalogError ? (
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
                    <QueryHistoryMenu onPick={setSql} />
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
                      <Select value={maxRows} onValueChange={(v: string | null) => setMaxRows(v ?? '200')}>
                        <SelectTrigger size="sm" className="w-20">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {ROW_LIMITS.map((n) => (
                            <SelectItem key={n} value={n}>
                              {n}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </div>
                {/* Editor */}
                <div className={cn('min-h-0 flex-1 overflow-hidden')}>
                  <SqlEditor
                    ref={editorRef}
                    value={sql}
                    onChange={setSql}
                    schema={schemaMap}
                    onRun={handleRun}
                    linkedQuery={resultTabs.active?.kind === 'query' ? resultTabs.active.sql : null}
                  />
                </div>
              </div>
            </ResizablePanel>

            <ResizableHandle />

            <ResizablePanel defaultSize={48} minSize={15}>
              <ResultTabs api={resultTabs} onRequestAccess={handleRequestAccess} />
            </ResizablePanel>
          </ResizablePanelGroup>
        </div>
      </div>

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
