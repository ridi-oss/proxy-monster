'use client'

// Full-page catalog browser for one datasource (replaces the cramped side-sheet). Master/detail:
// tables on the left, the selected table's columns on the right with inline classification.
// Export/Import lets the PII tagging be managed as a JSON text file (classification-as-code).
import { useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { useTranslations } from 'next-intl'
import {
  ArrowLeft,
  Database,
  Download,
  KeyRound,
  RefreshCw,
  Search,
  Table2,
  Upload,
} from 'lucide-react'
import { toast } from 'sonner'
import { mutate } from 'swr'
import { refreshDatasource, putClassification } from '@/lib/api/client'
import { useCatalog, useDatasources, swrKeys } from '@/lib/hooks'
import type { CatalogColumn } from '@/lib/api/types'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { LoadingState, ErrorState, EmptyState } from '@/components/page-scaffold'
import { ClassifyPopover } from './classify-popover'

interface TableGroup {
  key: string
  label: string
  columns: CatalogColumn[]
  piiCount: number
}

function groupByTable(cols: CatalogColumn[]): TableGroup[] {
  const m = new Map<string, TableGroup>()
  for (const c of cols) {
    const key = `${c.schema}.${c.table}`
    const label = c.schema && c.schema !== 'public' ? `${c.schema}.${c.table}` : c.table
    let g = m.get(key)
    if (!g) m.set(key, (g = { key, label, columns: [], piiCount: 0 }))
    g.columns.push(c)
    // The badge counts classified columns, whatever the tag is named.
    if ((c.classification?.tags?.length ?? 0) > 0) g.piiCount += 1
  }
  return [...m.values()]
}

export function DatasourceCatalog({ id }: { id: number }) {
  const t = useTranslations('Datasources')
  const { data: datasources } = useDatasources()
  const { data: catalog, isLoading, error } = useCatalog(id)
  const ds = datasources?.find((d) => d.id === id)

  const tables = useMemo(() => groupByTable(catalog ?? []), [catalog])
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [filter, setFilter] = useState('')
  const [importing, setImporting] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const selected = tables.find((t) => t.key === selectedKey) ?? tables[0] ?? null
  const filteredTables = useMemo(() => {
    const q = filter.trim().toLowerCase()
    return q ? tables.filter((t) => t.label.toLowerCase().includes(q)) : tables
  }, [tables, filter])

  const classifiedCount = (catalog ?? []).filter((c) => c.classification).length

  const handleExport = () => {
    const classifications = (catalog ?? [])
      .filter((c) => c.classification)
      .map((c) => ({
        schema: c.schema,
        table: c.table,
        column: c.column,
        tags: c.classification!.tags,
        maskFnId: c.classification!.maskFnId ?? null,
      }))
    const body = JSON.stringify({ datasource: ds?.name ?? `datasource-${id}`, classifications }, null, 2)
    const url = URL.createObjectURL(new Blob([body], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `${ds?.name ?? `datasource-${id}`}-classifications.json`
    a.click()
    URL.revokeObjectURL(url)
    toast.success(t('catalog.toastExported', { count: classifications.length }))
  }

  const handleImport = async (file: File) => {
    setImporting(true)
    try {
      const data = JSON.parse(await file.text())
      const list: Array<{
        schema?: string
        table: string
        column: string
        tags?: string[]
        maskFnId?: number | null
      }> = Array.isArray(data) ? data : (data.classifications ?? [])
      let n = 0
      for (const c of list) {
        if (!c.table || !c.column) continue
        await putClassification(id, {
          schema: c.schema,
          table: c.table,
          column: c.column,
          tags: c.tags ?? [],
          maskFnId: c.maskFnId ?? null,
        })
        n++
      }
      await mutate(swrKeys.catalog(id))
      toast.success(t('catalog.toastImported', { count: n }))
    } catch (err) {
      toast.error(t('catalog.toastImportFailed'), {
        description: err instanceof Error ? err.message : t('catalog.toastImportInvalid'),
      })
    } finally {
      setImporting(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  const handleRefresh = async () => {
    try {
      const r = await refreshDatasource(id)
      await mutate(swrKeys.catalog(id))
      await mutate(swrKeys.datasources)
      if (r.notified > 0) {
        toast.success(t('catalog.toastRefreshRequested'), {
          description: t('catalog.toastRefreshNotified', { notified: r.notified }),
        })
      } else {
        toast.warning(t('catalog.toastRefreshRequested'), {
          description: t('catalog.toastRefreshNoProxy'),
        })
      }
    } catch (err) {
      toast.error(t('catalog.toastRefreshFailed'), {
        description: err instanceof Error ? err.message : t('catalog.toastRefreshError'),
      })
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3 border-b px-6 py-4">
        <Link href="/admin/datasources" className="text-muted-foreground hover:text-foreground">
          <ArrowLeft className="size-4" />
        </Link>
        <Database className="text-muted-foreground size-4" />
        <h1 className="font-mono text-base font-semibold">
          {ds?.name ?? t('catalog.titleFallback', { id })}
        </h1>
        {ds && (
          <span className="text-muted-foreground font-mono text-xs">
            {ds.host}:{ds.port}/{ds.dbName}
          </span>
        )}
        {ds && ds.tags.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {ds.tags.map((tag) => (
              <Badge key={tag} variant="secondary" className="font-mono text-[10px]">
                {tag}
              </Badge>
            ))}
          </div>
        )}
        <span className="text-muted-foreground ml-auto text-xs">
          {t('catalog.headerSummary', {
            tables: tables.length,
            columns: catalog?.length ?? 0,
            classified: classifiedCount,
          })}
        </span>
        <input
          ref={fileRef}
          type="file"
          accept="application/json,.json"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0]
            if (f) handleImport(f)
          }}
        />
        <Button size="sm" variant="outline" onClick={() => fileRef.current?.click()} disabled={importing}>
          <Upload className="size-3.5" />
          {t('catalog.import')}
        </Button>
        <Button size="sm" variant="outline" onClick={handleExport} disabled={!classifiedCount}>
          <Download className="size-3.5" />
          {t('catalog.export')}
        </Button>
        <Button size="sm" variant="outline" onClick={handleRefresh}>
          <RefreshCw className="size-3.5" />
          {t('catalog.refresh')}
        </Button>
      </div>

      {isLoading && !catalog ? (
        <div className="p-6">
          <LoadingState label={t('catalog.loading')} />
        </div>
      ) : error ? (
        <div className="p-6">
          <ErrorState error={error} />
        </div>
      ) : tables.length === 0 ? (
        <EmptyState
          title={t('catalog.emptyTitle')}
          hint={t('catalog.emptyHint')}
          icon={<Table2 className="size-8" />}
          action={
            <Button size="sm" onClick={handleRefresh}>
              <RefreshCw className="size-3.5" />
              {t('catalog.refresh')}
            </Button>
          }
        />
      ) : (
        <div className="flex min-h-0 flex-1">
          {/* Tables (LHS) */}
          <aside className="flex w-72 shrink-0 flex-col border-r">
            <div className="relative p-2">
              <Search className="text-muted-foreground absolute top-1/2 left-4 size-3.5 -translate-y-1/2" />
              <Input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder={t('catalog.filterPlaceholder')}
                className="h-7 pl-7 text-xs"
              />
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto px-1 pb-2">
              {filteredTables.map((t) => (
                <button
                  key={t.key}
                  onClick={() => setSelectedKey(t.key)}
                  className={cn(
                    'flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left',
                    selected?.key === t.key ? 'bg-accent' : 'hover:bg-muted/50',
                  )}
                >
                  <Table2 className="text-muted-foreground size-3.5 shrink-0" />
                  <span className="min-w-0 flex-1 truncate font-mono text-xs">{t.label}</span>
                  <span className="text-muted-foreground text-[10px]">{t.columns.length}</span>
                  {t.piiCount > 0 && (
                    <span className="rounded border border-red-500/25 bg-red-500/10 px-1 font-mono text-[10px] text-red-500">
                      {t.piiCount}
                    </span>
                  )}
                </button>
              ))}
            </div>
          </aside>

          {/* Columns (RHS) */}
          <div className="min-h-0 flex-1 overflow-auto">
            {selected && (
              <table className="w-full border-collapse text-sm">
                <thead className="bg-muted/50 text-muted-foreground sticky top-0">
                  <tr>
                    <th className="border-b px-4 py-2 text-left font-medium">{t('catalog.colColumn')}</th>
                    <th className="border-b px-4 py-2 text-left font-medium">{t('catalog.colType')}</th>
                    <th className="border-b px-4 py-2 text-left font-medium">{t('catalog.colNullable')}</th>
                    <th className="w-40 border-b px-4 py-2 text-left font-medium">{t('catalog.colClassification')}</th>
                  </tr>
                </thead>
                <tbody>
                  {selected.columns.map((c) => {
                    const pii = c.classification?.tags?.includes('pii') ?? false
                    return (
                      <tr key={`${c.table}.${c.column}`} className="hover:bg-muted/40">
                        <td className="border-b px-4 py-1.5">
                          <span className="flex items-center gap-1.5">
                            {pii && <KeyRound className="size-3 text-red-500" />}
                            <code className={cn('font-mono text-xs', pii && 'text-red-500')}>{c.column}</code>
                          </span>
                        </td>
                        <td className="text-muted-foreground border-b px-4 py-1.5 font-mono text-xs lowercase">
                          {c.dataType}
                        </td>
                        <td className="text-muted-foreground border-b px-4 py-1.5 text-xs">
                          {c.nullable ? t('catalog.nullableYes') : t('catalog.nullableNo')}
                        </td>
                        <td className="border-b px-4 py-1.5">
                          {/* ClassifyPopover's trigger is the tags/mask badge (or "+ classify"). */}
                          <ClassifyPopover datasourceId={id} col={c} />
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
