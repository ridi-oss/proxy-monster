'use client'

// /admin/datasources — register and manage target databases
// (docs/datasource-registration.md). The list is the primary surface; each row lets the user test the
// connection, nudge a connected proxy to refresh its catalog, and open the
// full catalog browser with inline classification.

import { useCallback, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useTranslations } from 'next-intl'
import {
  Database,
  FlaskConical,
  MoreHorizontal,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
} from 'lucide-react'
import { toast } from 'sonner'
import { mutate } from 'swr'
import { refreshDatasource, testDatasource } from '@/lib/api/client'
import { connectionEndpoint } from '@/lib/catalog'
import { useDatasources, useDatasourcesLive, swrKeys } from '@/lib/hooks'
import type { Datasource, RefreshResult, TestResult } from '@/lib/api/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  PageHeader,
  PageContainer,
  LoadingState,
  ErrorState,
  EmptyState,
} from '@/components/page-scaffold'
import { DatasourceFormDialog } from '@/components/datasources/datasource-form-dialog'
import { DeleteConfirmDialog } from '@/components/datasources/delete-confirm-dialog'
import { cn } from '@/lib/utils'

// Per-row probe state: idle | testing | refreshing | test result | refresh result | error.
type ProbeState =
  | { kind: 'idle' }
  | { kind: 'testing' }
  | { kind: 'refreshing' }
  | { kind: 'test'; result: TestResult }
  | { kind: 'refresh'; result: RefreshResult }
  | { kind: 'error'; message: string }

type RelativeLabel =
  | { kind: 'justNow' }
  | { kind: 'minutes'; mins: number }
  | { kind: 'hours'; hrs: number }
  | { kind: 'days'; days: number }
  | { kind: 'absolute'; text: string }

/** Bucket an ISO-8601 instant into a relative-time descriptor; the component maps it to a locale string. */
function relativeLabel(iso: string): RelativeLabel {
  const ms = Date.now() - new Date(iso).getTime()
  const secs = Math.floor(ms / 1000)
  if (secs < 60) return { kind: 'justNow' }
  const mins = Math.floor(secs / 60)
  if (mins < 60) return { kind: 'minutes', mins }
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return { kind: 'hours', hrs }
  const days = Math.floor(hrs / 24)
  if (days < 30) return { kind: 'days', days }
  return { kind: 'absolute', text: new Date(iso).toLocaleDateString() }
}

/** Engine → short display label. */
function engineLabel(engine: string): string {
  if (engine === 'postgres') return 'PG'
  if (engine === 'mysql') return 'MySQL'
  return engine
}

export default function DatasourcesPage() {
  const t = useTranslations('Datasources')
  const { data: datasources, isLoading, error } = useDatasources()
  const { data: liveNames } = useDatasourcesLive()
  const router = useRouter()

  // Map the relative-time descriptor to a locale string.
  const formatRelative = (iso: string): string => {
    const r = relativeLabel(iso)
    switch (r.kind) {
      case 'justNow':
        return t('relative.justNow')
      case 'minutes':
        return t('relative.minutes', { mins: r.mins })
      case 'hours':
        return t('relative.hours', { hrs: r.hrs })
      case 'days':
        return t('relative.days', { days: r.days })
      case 'absolute':
        return r.text
    }
  }

  // Form dialog state.
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<Datasource | null>(null)

  // Delete confirm state.
  const [deleting, setDeleting] = useState<Datasource | null>(null)

  // Per-row probe states.
  const [probes, setProbes] = useState<Record<number, ProbeState>>({})
  const setProbe = useCallback((id: number, state: ProbeState) => {
    setProbes((prev) => ({ ...prev, [id]: state }))
  }, [])

  const handleTest = async (ds: Datasource) => {
    setProbe(ds.id, { kind: 'testing' })
    try {
      const result = await testDatasource(ds.id)
      setProbe(ds.id, { kind: 'test', result })
      if (result.ok) {
        toast.success(t('list.toast.connected', { name: ds.name }), { description: result.message })
      } else {
        toast.error(t('list.toast.connectionFailed', { name: ds.name }), { description: result.message })
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : t('list.toast.testFailed')
      setProbe(ds.id, { kind: 'error', message })
      toast.error(t('list.toast.testError', { name: ds.name }), { description: message })
    }
  }

  const handleRefresh = async (ds: Datasource) => {
    setProbe(ds.id, { kind: 'refreshing' })
    try {
      const result = await refreshDatasource(ds.id)
      setProbe(ds.id, { kind: 'refresh', result })
      // The catalog itself lands later, async, once the nudged proxy pushes its schema — these
      // just pick up any change to catalogSyncedAt that's already landed by the time this resolves.
      await mutate(swrKeys.datasources)
      await mutate(swrKeys.catalog(ds.id))
      if (result.notified > 0) {
        toast.success(t('list.toast.refreshRequested', { name: ds.name }), {
          description: t('list.toast.refreshNotified', { notified: result.notified }),
        })
      } else {
        toast.warning(t('list.toast.refreshRequested', { name: ds.name }), {
          description: t('list.toast.refreshNoProxy'),
        })
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : t('list.toast.refreshFailed')
      setProbe(ds.id, { kind: 'error', message })
      toast.error(t('list.toast.refreshError', { name: ds.name }), { description: message })
    }
  }

  const openCreate = () => {
    setEditing(null)
    setFormOpen(true)
  }
  const openEdit = (ds: Datasource) => {
    setEditing(ds)
    setFormOpen(true)
  }

  return (
    <>
      <PageHeader
        title={t('list.title')}
        subtitle={t('list.subtitle')}
        actions={
          <Button size="sm" onClick={openCreate}>
            <Plus className="size-3.5" />
            {t('list.addDatasource')}
          </Button>
        }
      />

      <PageContainer>
        {isLoading && !datasources ? (
          <LoadingState label={t('list.loading')} />
        ) : error ? (
          <ErrorState error={error} />
        ) : !datasources || datasources.length === 0 ? (
          <EmptyState
            title={t('list.emptyTitle')}
            hint={t('list.emptyHint')}
            icon={<Database className="size-8" />}
            action={
              <Button size="sm" onClick={openCreate}>
                <Plus className="size-3.5" />
                {t('list.addDatasource')}
              </Button>
            }
          />
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('list.colName')}</TableHead>
                  <TableHead>{t('list.colEngine')}</TableHead>
                  <TableHead>{t('list.colConnection')}</TableHead>
                  <TableHead>{t('list.colTags')}</TableHead>
                  <TableHead>{t('list.colCatalog')}</TableHead>
                  <TableHead>{t('list.colStatus')}</TableHead>
                  <TableHead className="text-right">{t('list.colActions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {datasources.map((ds) => {
                  const probe = probes[ds.id] ?? { kind: 'idle' }
                  const isBusy = probe.kind === 'testing' || probe.kind === 'refreshing'
                  return (
                    <TableRow
                      key={ds.id}
                      className="cursor-pointer"
                      onClick={() => router.push(`/admin/datasources/${ds.id}`)}
                    >
                      {/* Name */}
                      <TableCell>
                        <span className="font-mono text-sm font-semibold">{ds.name}</span>
                      </TableCell>

                      {/* Engine badge */}
                      <TableCell>
                        <Badge variant="outline" className="font-mono text-xs">
                          {engineLabel(ds.engine)}
                        </Badge>
                      </TableCell>

                      {/* Connection string */}
                      <TableCell>
                        <span className="text-muted-foreground font-mono text-xs">
                          {connectionEndpoint(ds)}
                        </span>
                      </TableCell>

                      {/* Datasource-level tags (policy posture, e.g. preset:*) */}
                      <TableCell>
                        {ds.tags.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {ds.tags.map((tag) => (
                              <Badge key={tag} variant="secondary" className="font-mono text-[10px]">
                                {tag}
                              </Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-muted-foreground text-xs">{t('list.noTags')}</span>
                        )}
                      </TableCell>

                      {/* Catalog synced-at */}
                      <TableCell>
                        {ds.catalogSyncedAt ? (
                          <span className="text-muted-foreground text-xs">
                            {t('list.catalogSynced', { relative: formatRelative(ds.catalogSyncedAt) })}
                          </span>
                        ) : (
                          <span className="text-amber-500/80 text-xs">{t('list.noCatalogYet')}</span>
                        )}
                      </TableCell>

                      {/* Per-row probe feedback — falls back to the polled live-attachment set (whether a
                          proxy currently has an open Events stream) when no manual test/refresh has run yet. */}
                      <TableCell>
                        <ProbeCell probe={probe} isLive={liveNames?.includes(ds.name) ?? null} />
                      </TableCell>

                      {/* Row actions — stop propagation so clicks don't open the sheet */}
                      <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1">
                          <Tooltip>
                            <TooltipTrigger
                              render={
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  disabled={isBusy}
                                  onClick={() => handleTest(ds)}
                                />
                              }
                            >
                              <FlaskConical className="size-3.5" />
                              <span className="sr-only">{t('list.testConnection')}</span>
                            </TooltipTrigger>
                            <TooltipContent>{t('list.testConnection')}</TooltipContent>
                          </Tooltip>

                          <Tooltip>
                            <TooltipTrigger
                              render={
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  disabled={isBusy}
                                  onClick={() => handleRefresh(ds)}
                                />
                              }
                            >
                              <RefreshCw className="size-3.5" />
                              <span className="sr-only">{t('catalog.refresh')}</span>
                            </TooltipTrigger>
                            <TooltipContent>{t('list.refreshCatalog')}</TooltipContent>
                          </Tooltip>

                          <DropdownMenu>
                            <DropdownMenuTrigger
                              render={
                                <Button variant="ghost" size="icon-xs" aria-label={t('list.moreActions')} />
                              }
                            >
                              <MoreHorizontal className="size-3.5" />
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" side="bottom">
                              <DropdownMenuItem onClick={() => openEdit(ds)}>
                                <Pencil className="size-3.5" />
                                {t('list.edit')}
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                variant="destructive"
                                onClick={() => setDeleting(ds)}
                              >
                                <Trash2 className="size-3.5" />
                                {t('list.delete')}
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </PageContainer>

      {/* Add / edit dialog */}
      <DatasourceFormDialog
        open={formOpen}
        onOpenChange={setFormOpen}
        editing={editing}
      />

      {/* Delete confirm dialog */}
      <DeleteConfirmDialog
        datasource={deleting}
        onClose={() => setDeleting(null)}
      />
    </>
  )
}

/**
 * Inline per-row probe result cell. Before a manual test/refresh has run this row (`probe.kind ===
 * 'idle'`), falls back to [isLive] — the polled `/api/datasources/live` attachment set — so the
 * column shows real proxy-connection state by default rather than a bare dash. `isLive === null`
 * means the live set hasn't loaded yet.
 */
function ProbeCell({ probe, isLive }: { probe: ProbeState; isLive: boolean | null }) {
  const t = useTranslations('Datasources')
  switch (probe.kind) {
    case 'testing':
      return <span className="text-muted-foreground text-xs">{t('probe.testing')}</span>
    case 'refreshing':
      return <span className="text-muted-foreground text-xs">{t('probe.refreshing')}</span>
    case 'test':
      return (
        <div className="space-y-0.5">
          <span
            className={cn(
              'text-xs font-medium',
              probe.result.ok ? 'text-emerald-500' : 'text-red-500',
            )}
          >
            {probe.result.ok ? t('probe.connected') : t('probe.failed')}
          </span>
          {probe.result.message && (
            <p className="text-muted-foreground max-w-[180px] truncate text-[10px]">
              {probe.result.message}
            </p>
          )}
        </div>
      )
    case 'refresh':
      return (
        <span className={cn('text-xs', probe.result.notified > 0 ? 'text-emerald-500' : 'text-muted-foreground')}>
          {t('probe.refreshNotified', { notified: probe.result.notified })}
        </span>
      )
    case 'error':
      return (
        <p className="max-w-[180px] truncate text-xs text-red-500">{probe.message}</p>
      )
    default:
      if (isLive == null) return <span className="text-muted-foreground text-xs">—</span>
      return isLive ? (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-500">
          <span className="size-1.5 rounded-full bg-emerald-500" />
          {t('list.liveConnected')}
        </span>
      ) : (
        <span className="text-muted-foreground inline-flex items-center gap-1.5 text-xs">
          <span className="bg-muted-foreground/40 size-1.5 rounded-full" />
          {t('list.liveNotConnected')}
        </span>
      )
  }
}
