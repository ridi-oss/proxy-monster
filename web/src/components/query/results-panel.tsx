'use client'

// Results panel for the editor (docs/web-console.md decisionColor as the load-bearing
// token). A decision banner colored by ALLOW/MASK/DENY (effective roles +
// latency always; masked columns on MASK; deny reason + a Request-access button
// on DENY), then Results / Details tabs. DENY returns no rows, so its Results
// tab shows the deny callout instead of a grid.
import Link from 'next/link'
import { useTranslations } from 'next-intl'
import { AlertTriangle, ShieldAlert } from 'lucide-react'
import type { QueryResponse } from '@/lib/api/types'
import { decisionTone } from '@/lib/decision'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Loader2 } from 'lucide-react'

interface Props {
  result: QueryResponse | null
  running: boolean
  canceling?: boolean
  canceled?: boolean
  error: string | null
  onCancel?: () => void
  onRequestAccess: () => void
}

export function ResultsPanel({
  result,
  running,
  canceling = false,
  canceled = false,
  error,
  onCancel,
  onRequestAccess,
}: Props) {
  const t = useTranslations('Query')
  const tone = result ? decisionTone[result.decision] : null

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Decision banner */}
      {result && tone && (
        <div className="relative flex flex-wrap items-center justify-between gap-2 border-b py-2 pr-4 pl-4">
          <span className={cn('absolute inset-y-0 left-0 w-[3px]', tone.solid)} />
          <div className="flex flex-wrap items-center gap-2.5">
            <span
              className={cn(
                'inline-flex items-center rounded-md border px-1.5 py-0.5 text-xs font-semibold',
                tone.badge,
              )}
            >
              {result.decision}
            </span>
            {result.decision === 'MASK' && result.maskedColumns.length > 0 && (
              <span className="text-muted-foreground text-xs">
                {t('results.masked')}{' '}
                {result.maskedColumns.map((c) => (
                  <code key={c} className="text-foreground/80 mr-1 font-mono">
                    {c}
                  </code>
                ))}
              </span>
            )}
            {result.effectiveRoles.length > 0 && (
              <span className="flex items-center gap-1">
                {result.effectiveRoles.map((r) => (
                  <span
                    key={r}
                    className="border-border text-muted-foreground rounded border px-1 py-px font-mono text-[10px]"
                  >
                    {r}
                  </span>
                ))}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            {result.decision !== 'DENY' && (
              <span className="text-muted-foreground font-mono text-xs">
                {t('results.rowCount', { count: result.rows.length })}
                {result.rowsAffected != null
                  ? t('results.rowsAffectedSuffix', { count: result.rowsAffected })
                  : ''}
              </span>
            )}
            <span className="text-muted-foreground font-mono text-xs">{result.latencyMs} ms</span>
            {result.decision === 'DENY' && (
              <div className="flex items-center gap-2">
                {result.decisionId != null && (
                  <Button size="xs" asChild>
                    <Link href={`/workflows/new?from=${result.decisionId}`}>{t('results.requestApproval')}</Link>
                  </Button>
                )}
                <Button size="xs" variant="destructive" onClick={onRequestAccess}>
                  {t('results.requestAccess')}
                </Button>
              </div>
            )}
          </div>
        </div>
      )}

      <Tabs defaultValue="results" className="flex min-h-0 flex-1 flex-col gap-0">
        <TabsList className="h-8 shrink-0 rounded-none border-b bg-transparent px-3">
          <TabsTrigger value="results" className="text-xs">
            {t('results.tabResults')}
          </TabsTrigger>
          <TabsTrigger value="details" className="text-xs">
            {t('results.tabDetails')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="results" className="min-h-0 flex-1 overflow-hidden">
          {error ? (
            <Centered>
              <div className="flex max-w-md items-start gap-2.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2.5 text-sm text-red-500">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" />
                <div>
                  <p className="font-medium">{t('results.queryFailed')}</p>
                  <p className="mt-0.5 break-words opacity-90">{error}</p>
                </div>
              </div>
            </Centered>
          ) : running && !result ? (
            <Centered>
              <div className="flex flex-col items-center gap-3">
                <span className="text-muted-foreground flex items-center gap-2 text-sm">
                  <Loader2 className="size-4 animate-spin" /> {t('results.running')}
                </span>
                {onCancel && (
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={onCancel}
                    disabled={canceling}
                    data-testid="cancel-editor-task"
                  >
                    {canceling ? t('results.canceling') : t('results.cancel')}
                  </Button>
                )}
              </div>
            </Centered>
          ) : canceled ? (
            <Centered>
              <div className="text-center">
                <p className="text-sm font-medium">{t('results.canceledTitle')}</p>
                <p className="text-muted-foreground mt-1 text-xs">
                  {t('results.canceledDescription')}
                </p>
              </div>
            </Centered>
          ) : !result ? (
            <Centered>
              <div className="text-center">
                <p className="text-sm font-medium">{t('results.noResultsTitle')}</p>
                <p className="text-muted-foreground mt-1 text-xs">
                  {t('results.noResultsDescription')}
                </p>
              </div>
            </Centered>
          ) : result.decision === 'DENY' ? (
            <DenyCallout result={result} onRequestAccess={onRequestAccess} />
          ) : (
            <ResultGrid result={result} />
          )}
        </TabsContent>

        <TabsContent value="details" className="min-h-0 flex-1 overflow-y-auto p-4">
          {result ? (
            <Details result={result} />
          ) : (
            <Centered>
              <p className="text-muted-foreground text-sm">{t('results.noExecutionDetails')}</p>
            </Centered>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="flex min-h-0 flex-1 items-center justify-center p-6">{children}</div>
}

function DenyCallout({
  result,
  onRequestAccess,
}: {
  result: QueryResponse
  onRequestAccess: () => void
}) {
  const t = useTranslations('Query')
  return (
    <div className="flex min-h-0 flex-1 items-start justify-center overflow-y-auto p-6">
      <div className="max-w-lg rounded-xl border border-red-500/30 bg-red-500/10 p-4">
        <div className="flex items-center gap-2">
          <ShieldAlert className="size-4 text-red-500" />
          <p className="font-semibold text-red-500">{t('results.denyTitle')}</p>
        </div>
        <p className="mt-2 text-sm">
          {result.denyReason || t('results.denyFallback')}
        </p>
        {result.piiTouched.length > 0 && (
          <p className="text-muted-foreground mt-2 text-xs">
            {t('results.piiTouched')}{' '}
            {result.piiTouched.map((c) => (
              <code key={c} className="text-foreground/80 mr-1 font-mono">
                {c}
              </code>
            ))}
          </p>
        )}
        <p className="text-muted-foreground mt-3 text-xs">
          {t('results.denyHelp')}
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {result.decisionId != null && (
            <Button size="sm" asChild>
              <Link href={`/workflows/new?from=${result.decisionId}`}>{t('results.requestApproval')}</Link>
            </Button>
          )}
          <Button size="sm" variant="destructive" onClick={onRequestAccess}>
            {t('results.requestAccess')}
          </Button>
          {result.decisionId != null && (
            <Link
              href={`/audit/${result.decisionId}`}
              className="text-muted-foreground hover:text-foreground text-xs underline underline-offset-4"
            >
              {t('results.viewAudit')}
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}

function ResultGrid({ result }: { result: QueryResponse }) {
  const t = useTranslations('Query')
  const masked = new Set(result.maskedColumns)

  if (result.columns.length === 0) {
    return (
      <Centered>
        <div className="text-center">
          <p className="text-sm font-medium">{t('results.statementNoColumns')}</p>
          {result.rowsAffected != null && (
            <p className="text-muted-foreground mt-1 text-xs">
              {t('results.rowsAffectedLine', { count: result.rowsAffected })}
            </p>
          )}
        </div>
      </Centered>
    )
  }

  return (
    <div className="h-full overflow-auto">
      <table className="w-full border-collapse text-xs">
        <thead className="bg-muted/50 sticky top-0 z-10 backdrop-blur">
          <tr>
            <th className="text-muted-foreground border-b border-r px-2 py-1.5 text-right font-mono font-normal">
              #
            </th>
            {result.columns.map((col, i) => {
              const isMasked = masked.has(col)
              return (
                <th
                  key={`${col}-${i}`}
                  className="border-b border-r px-3 py-1.5 text-left font-medium whitespace-nowrap"
                >
                  <span className="flex items-center gap-1.5">
                    <code className="font-mono">{col}</code>
                    {isMasked && (
                      <span className="rounded border border-amber-500/25 bg-amber-500/15 px-1 py-px font-mono text-[10px] text-amber-600 dark:text-amber-400">
                        {t('results.masked')}
                      </span>
                    )}
                  </span>
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {result.rows.length === 0 ? (
            <tr>
              <td
                colSpan={result.columns.length + 1}
                className="text-muted-foreground px-3 py-8 text-center"
              >
                {t('results.noRows')}
              </td>
            </tr>
          ) : (
            result.rows.map((row, ri) => (
              <tr key={ri} className="hover:bg-muted/40">
                <td className="text-muted-foreground/60 border-b border-r px-2 py-1 text-right font-mono tabular-nums">
                  {ri + 1}
                </td>
                {result.columns.map((col, ci) => {
                  const value = row[ci]
                  const isMasked = masked.has(col)
                  return (
                    <td
                      key={ci}
                      className="border-b border-r px-3 py-1 align-top font-mono"
                    >
                      {value == null ? (
                        <span className="text-muted-foreground/50 italic">NULL</span>
                      ) : (
                        <span
                          className={cn(
                            'break-words whitespace-pre-wrap',
                            isMasked && 'text-amber-600 dark:text-amber-400',
                          )}
                        >
                          {value}
                        </span>
                      )}
                    </td>
                  )
                })}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}

function Details({ result }: { result: QueryResponse }) {
  const t = useTranslations('Query')
  const rows: [string, React.ReactNode][] = [
    [t('results.detailDecision'), result.decision],
    [t('results.detailLatency'), `${result.latencyMs} ms`],
    [t('results.detailEffectiveRoles'), result.effectiveRoles.join(', ') || '—'],
    [t('results.detailMaskedColumns'), result.maskedColumns.join(', ') || '—'],
    [t('results.detailPiiTouched'), result.piiTouched.join(', ') || '—'],
    [t('results.detailRowsReturned'), result.decision === 'DENY' ? t('results.rowsDenied') : String(result.rows.length)],
    [t('results.detailRowsAffected'), result.rowsAffected != null ? String(result.rowsAffected) : '—'],
  ]
  if (result.denyReason) rows.push([t('results.detailDenyReason'), result.denyReason])

  return (
    <dl className="grid max-w-2xl grid-cols-[160px_1fr] gap-x-4 gap-y-2 text-sm">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="font-mono break-words">{v}</dd>
        </div>
      ))}
    </dl>
  )
}
