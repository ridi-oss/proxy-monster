'use client'

// A table tab's content: live physical metadata/classification tabs plus a live, enforced Data
// preview (SELECT * through the policy engine, so PII is masked/denied just like a query).
import { useTranslations } from 'next-intl'
import { KeyRound } from 'lucide-react'
import type { TableRelation } from '@/lib/api/types'
import { toneForTags } from '@/lib/decision'
import { useTableDetail } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ResultsPanel } from './results-panel'
import type { TableTab } from './use-result-tabs'

const EM_DASH = '—'

function formatColumnType(column: {
  dataType: string
  characterMaximumLength: number | null
  numericPrecision: number | null
  numericScale: number | null
}) {
  if (column.characterMaximumLength != null) {
    return `${column.dataType}(${column.characterMaximumLength})`
  }
  // Only exact-numeric types (decimal/numeric) carry a meaningful (precision, scale). Integers report
  // a numeric_precision with numeric_scale=0 in information_schema on both engines, so appending it
  // unconditionally would render misleading pseudo-types like `bigint(20, 0)` / `integer(32, 0)`.
  const isExactNumeric = /^(decimal|numeric|dec|fixed)$/i.test(column.dataType)
  if (isExactNumeric && column.numericPrecision != null) {
    return column.numericScale == null || column.numericScale === 0
      ? `${column.dataType}(${column.numericPrecision})`
      : `${column.dataType}(${column.numericPrecision}, ${column.numericScale})`
  }
  return column.dataType
}

function formatBytes(bytes: number) {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value = bytes / 1024 ** exponent
  return `${value >= 10 || exponent === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[exponent]}`
}

function LiveState({ loading, error }: { loading: boolean; error: unknown }) {
  const t = useTranslations('Query')
  if (error) {
    const message = error instanceof Error ? error.message : t('table.loadErrorFallback')
    return (
      <div className="flex min-h-40 items-center justify-center p-6 text-center">
        <div>
          <p className="font-medium text-destructive">{t('table.loadErrorTitle')}</p>
          <p className="text-muted-foreground mt-1 max-w-xl text-xs">{message}</p>
        </div>
      </div>
    )
  }
  if (loading) {
    return (
      <div className="text-muted-foreground flex min-h-40 items-center justify-center p-6 text-xs">
        {t('table.loading')}
      </div>
    )
  }
  return null
}

export function TableView({
  tab,
  onRequestAccess,
}: {
  tab: TableTab
  onRequestAccess: (denyReason?: string | null) => void
}) {
  const t = useTranslations('Query')
  const unavailable = t('table.unavailable')
  const { data: detail, error } = useTableDetail(
    tab.datasourceId,
    tab.table.schema,
    tab.table.name,
  )
  // First-load only: keep the rendered detail visible during SWR background revalidation
  // (useTableDetail runs revalidateOnFocus), instead of flashing "Loading…" over all four tabs
  // on every tab refocus while the ~8 live target queries re-run.
  const loadingDetail = !detail && !error
  const showDetail = detail && !error

  return (
    <Tabs
      defaultValue="columns"
      data-testid="table-detail-tabs"
      className="flex min-h-0 min-w-0 flex-1 flex-col gap-0"
    >
      <div className="overflow-x-auto border-b">
        <div className="flex min-w-max items-center gap-2 px-3 py-2">
          <TabsList className="shrink-0">
            <TabsTrigger value="columns">{t('table.tabColumns')}</TabsTrigger>
            <TabsTrigger value="indexes">{t('table.tabIndexes')}</TabsTrigger>
            <TabsTrigger value="relations">{t('table.tabRelations')}</TabsTrigger>
            <TabsTrigger value="metadata">{t('table.tabMetadata')}</TabsTrigger>
            <TabsTrigger value="data">{t('table.tabData')}</TabsTrigger>
          </TabsList>
          <span className="text-muted-foreground ml-1 font-mono text-xs">{tab.table.qualified}</span>
          {showDetail && (
            <span className="text-muted-foreground ml-auto text-xs">
              {t('table.columnCount', { count: detail.columns.length })}
            </span>
          )}
        </div>
      </div>

      <TabsContent
        value="columns"
        data-testid="table-columns-panel"
        className="min-h-0 min-w-0 flex-1 overflow-auto"
      >
        {!showDetail ? (
          <LiveState loading={loadingDetail} error={error} />
        ) : detail.columns.length === 0 ? (
          <div className="text-muted-foreground flex min-h-40 items-center justify-center p-6 text-xs">
            {t('table.noColumns')}
          </div>
        ) : (
          <table className="w-full min-w-max border-collapse text-xs">
            <thead className="bg-muted/50 text-muted-foreground sticky top-0 z-10">
              <tr>
                <th className="border-b px-3 py-1.5 text-right font-medium">#</th>
                <th className="border-b px-3 py-1.5 text-left font-medium">{t('table.colHeaderColumn')}</th>
                <th className="border-b px-3 py-1.5 text-left font-medium">{t('table.colHeaderType')}</th>
                <th className="border-b px-3 py-1.5 text-left font-medium">{t('table.colHeaderNullable')}</th>
                <th className="border-b px-3 py-1.5 text-left font-medium">{t('table.colHeaderDefault')}</th>
                <th className="border-b px-3 py-1.5 text-left font-medium">{t('table.colHeaderIndexed')}</th>
                <th className="border-b px-3 py-1.5 text-left font-medium">{t('table.colHeaderAutoIncrement')}</th>
                <th className="border-b px-3 py-1.5 text-left font-medium">{t('table.colHeaderComment')}</th>
                <th className="border-b px-3 py-1.5 text-left font-medium">{t('table.colHeaderCharset')}</th>
                <th className="border-b px-3 py-1.5 text-left font-medium">{t('table.colHeaderCollation')}</th>
                <th className="border-b px-3 py-1.5 text-left font-medium">{t('table.colHeaderClassification')}</th>
                <th className="border-b px-3 py-1.5 text-left font-medium">{t('table.colHeaderMaskFunction')}</th>
              </tr>
            </thead>
            <tbody>
              {[...detail.columns]
                .sort((a, b) => a.ordinal - b.ordinal)
                .map((column) => {
                  const tags = column.classification?.tags ?? []
                  const pii = tags.includes('pii')
                  return (
                    <tr key={column.name} className="hover:bg-muted/40">
                      <td className="text-muted-foreground border-b px-3 py-1.5 text-right tabular-nums">
                        {column.ordinal}
                      </td>
                      <td className="border-b px-3 py-1.5">
                        <span className="flex items-center gap-1.5">
                          {pii && <KeyRound className="size-3 text-red-500" />}
                          <code className={cn('font-mono', pii && 'text-red-500')}>{column.name}</code>
                        </span>
                      </td>
                      <td className="text-muted-foreground border-b px-3 py-1.5 font-mono lowercase">
                        {formatColumnType(column)}
                      </td>
                      <td className="text-muted-foreground border-b px-3 py-1.5">
                        {column.nullable ? t('table.yes') : t('table.no')}
                      </td>
                      <td className="text-muted-foreground border-b px-3 py-1.5 font-mono">
                        {column.defaultValue ?? EM_DASH}
                      </td>
                      <td className="text-muted-foreground border-b px-3 py-1.5">
                        {column.partOfIndex ? t('table.yes') : t('table.no')}
                      </td>
                      <td className="text-muted-foreground border-b px-3 py-1.5">
                        {column.autoIncrement ? t('table.yes') : t('table.no')}
                      </td>
                      <td className="text-muted-foreground max-w-64 border-b px-3 py-1.5">
                        {column.comment ?? EM_DASH}
                      </td>
                      <td className="text-muted-foreground border-b px-3 py-1.5 font-mono">
                        {column.charset ?? EM_DASH}
                      </td>
                      <td className="text-muted-foreground border-b px-3 py-1.5 font-mono">
                        {column.collation ?? EM_DASH}
                      </td>
                      <td className="border-b px-3 py-1.5">
                        {tags.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {tags.map((tag) => (
                              <span
                                key={tag}
                                className={cn(
                                  'rounded border px-1.5 py-0.5 text-[10px] font-medium',
                                  toneForTags([tag]),
                                )}
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-muted-foreground/50">{EM_DASH}</span>
                        )}
                      </td>
                      <td className="text-muted-foreground border-b px-3 py-1.5 font-mono">
                        {column.classification?.maskFnName ?? EM_DASH}
                      </td>
                    </tr>
                  )
                })}
            </tbody>
          </table>
        )}
      </TabsContent>

      <TabsContent
        value="indexes"
        data-testid="table-indexes-panel"
        className="min-h-0 min-w-0 flex-1 overflow-auto p-3"
      >
        {!showDetail ? (
          <LiveState loading={loadingDetail} error={error} />
        ) : detail.indexes.length === 0 ? (
          <div className="text-muted-foreground flex min-h-40 items-center justify-center p-6 text-xs">
            {t('table.noIndexes')}
          </div>
        ) : (
          <div className="min-w-max space-y-2">
            {detail.indexes.map((index) => (
              <div key={index.name} className="rounded-md border p-3 text-xs">
                <div className="flex items-start gap-4">
                  <div className="min-w-48">
                    <p className="font-mono font-medium">{index.name}</p>
                    <div className="text-muted-foreground mt-1 flex flex-wrap gap-x-3 gap-y-1">
                      <span>{index.unique ? t('table.unique') : t('table.nonUnique')}</span>
                      <span>{t('table.indexType', { type: index.type || unavailable })}</span>
                    </div>
                  </div>
                  <ol className="min-w-80 space-y-1 font-mono">
                    {[...index.columns]
                      .sort((a, b) => a.position - b.position)
                      .map((column) => (
                        <li key={`${column.position}:${column.name}`}>
                          <span className="text-muted-foreground mr-2 tabular-nums">{column.position}.</span>
                          {column.name || EM_DASH}
                          {column.direction ? (
                            <span className="text-muted-foreground ml-2">{column.direction}</span>
                          ) : null}
                        </li>
                      ))}
                  </ol>
                </div>
              </div>
            ))}
          </div>
        )}
      </TabsContent>

      <TabsContent
        value="relations"
        data-testid="table-relations-panel"
        className="min-h-0 min-w-0 flex-1 overflow-auto p-3"
      >
        {!showDetail ? (
          <LiveState loading={loadingDetail} error={error} />
        ) : (
          <div className="min-w-max space-y-6 text-xs">
            <section aria-labelledby="outbound-relations-heading">
              <h3 id="outbound-relations-heading" className="mb-2 font-medium">
                {t('table.foreignKeys')}
              </h3>
              {detail.foreignKeys.length === 0 ? (
                <div className="text-muted-foreground rounded-md border border-dashed p-4">
                  {t('table.noForeignKeys')}
                </div>
              ) : (
                <div className="space-y-2">
                  {detail.foreignKeys.map((relation) => (
                    <RelationCard key={relation.name} relation={relation} />
                  ))}
                </div>
              )}
            </section>

            <section aria-labelledby="inbound-relations-heading">
              <h3 id="inbound-relations-heading" className="mb-2 font-medium">
                {t('table.referencedBy')}
              </h3>
              {detail.referencedBy.length === 0 ? (
                <div className="text-muted-foreground rounded-md border border-dashed p-4">
                  {t('table.noReferencedBy')}
                </div>
              ) : (
                <div className="space-y-2">
                  {detail.referencedBy.map((relation) => (
                    <RelationCard key={relation.name} relation={relation} />
                  ))}
                </div>
              )}
            </section>
          </div>
        )}
      </TabsContent>

      <TabsContent
        value="metadata"
        data-testid="table-metadata-panel"
        className="min-h-0 min-w-0 flex-1 overflow-auto p-3"
      >
        {!showDetail ? (
          <LiveState loading={loadingDetail} error={error} />
        ) : (
          <dl className="grid min-w-96 grid-cols-[max-content_minmax(12rem,1fr)] overflow-hidden rounded-md border text-xs">
            <MetadataRow label={t('table.metaEngine')} value={detail.metadata.engine ?? unavailable} mono />
            <MetadataRow
              label={t('table.metaEstimatedRows')}
              value={detail.metadata.estimatedRows?.toLocaleString() ?? unavailable}
            />
            <MetadataRow label={t('table.metaRowFormat')} value={detail.metadata.rowFormat ?? unavailable} />
            <MetadataRow
              label={t('table.metaOnDiskSize')}
              value={
                detail.metadata.onDiskBytes == null ? (
                  unavailable
                ) : (
                  <span title={`${detail.metadata.onDiskBytes.toLocaleString()} bytes`}>
                    {formatBytes(detail.metadata.onDiskBytes)} ({detail.metadata.onDiskBytes.toLocaleString()} bytes)
                  </span>
                )
              }
            />
            <MetadataRow label={t('table.metaCollation')} value={detail.metadata.collation ?? unavailable} mono />
            <MetadataRow label={t('table.metaTableComment')} value={detail.metadata.comment ?? unavailable} />
          </dl>
        )}
      </TabsContent>

      <TabsContent value="data" className="min-h-0 flex-1 overflow-hidden">
        <ResultsPanel
          result={tab.res.result}
          running={tab.res.loading}
          error={tab.res.error}
          onRequestAccess={() => onRequestAccess(tab.res.result?.denyReason)}
        />
      </TabsContent>
    </Tabs>
  )
}

function RelationCard({ relation }: { relation: TableRelation }) {
  const t = useTranslations('Query')
  return (
    <div className="rounded-md border p-3">
      <p className="font-mono font-medium">{relation.name}</p>
      <p className="mt-1 font-mono">
        {relation.sourceSchema}.{relation.sourceTable}
        <span className="text-muted-foreground mx-2">→</span>
        {relation.targetSchema}.{relation.targetTable}
      </p>
      <ol className="mt-2 space-y-1 font-mono">
        {relation.sourceColumns.map((sourceColumn, index) => (
          <li key={`${index}:${sourceColumn}:${relation.targetColumns[index] ?? ''}`}>
            <span className="text-muted-foreground mr-2 tabular-nums">{index + 1}.</span>
            {sourceColumn}
            <span className="text-muted-foreground mx-2">→</span>
            {relation.targetColumns[index] ?? EM_DASH}
          </li>
        ))}
      </ol>
      {(relation.onUpdate || relation.onDelete) && (
        <div className="text-muted-foreground mt-2 flex gap-4">
          {relation.onUpdate && <span>{t('table.onUpdate', { action: relation.onUpdate })}</span>}
          {relation.onDelete && <span>{t('table.onDelete', { action: relation.onDelete })}</span>}
        </div>
      )}
    </div>
  )
}

function MetadataRow({
  label,
  value,
  mono = false,
}: {
  label: string
  value: React.ReactNode
  mono?: boolean
}) {
  return (
    <div className="contents">
      <dt className="bg-muted/40 text-muted-foreground border-b px-3 py-2 font-medium">{label}</dt>
      <dd className={cn('border-b px-3 py-2', mono && 'font-mono')}>{value}</dd>
    </div>
  )
}
