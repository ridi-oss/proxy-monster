'use client'

import { useEffect, useState, type ReactNode } from 'react'
import { useTranslations } from 'next-intl'
import useSWR, { mutate as globalMutate } from 'swr'
import { toast } from 'sonner'
import { cancelApproval, executeApproval, getApprovalResult, rejectApproval } from '@/lib/api/client'
import { onTaskEvent, subscribeTaskEvents } from '@/lib/api/task-events'
import { translateApiError } from '@/lib/i18n/errors'
import { swrKeys, useApproval } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { ErrorState, LoadingState } from '@/components/page-scaffold'
import { ApproveQueryDialog } from './approve-query-dialog'

const STATUS_STYLE: Record<string, string> = {
  DRAFT: 'border-border text-muted-foreground',
  PENDING: 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  APPROVED: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  REJECTED: 'border-red-500/30 bg-red-500/10 text-red-500',
  EXECUTING: 'border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-400',
  EXECUTED: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  FAILED: 'border-red-500/30 bg-red-500/10 text-red-500',
  CANCELLED: 'border-border text-muted-foreground',
  DELETED: 'border-border text-muted-foreground',
}

const DECISION_STYLE: Record<string, string> = {
  ALLOW: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  MASK: 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  DENY: 'border-red-500/30 bg-red-500/10 text-red-500',
}

function formatTimestamp(iso?: string | null): string {
  return iso ? new Date(iso).toLocaleString() : '—'
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
        {label}
      </p>
      <div className="text-sm">{children}</div>
    </div>
  )
}

function ResultGrid({ columns, rows }: { columns: string[]; rows: (string | null)[][] }) {
  const t = useTranslations('Workflows')
  return (
    <div className="border-border overflow-x-auto rounded-lg border">
      <table className="w-full text-left text-xs">
        <thead className="bg-muted/50 text-muted-foreground">
          <tr>
            {columns.map((c) => (
              <th key={c} className="px-3 py-2 font-mono font-medium whitespace-nowrap">{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={Math.max(columns.length, 1)} className="text-muted-foreground px-3 py-3">
                {t('approvalDetail.noRows')}
              </td>
            </tr>
          ) : (
            rows.map((row, i) => (
              <tr key={i} className="border-border/60 border-t">
                {row.map((v, j) => (
                  <td key={j} className="text-foreground/90 px-3 py-1.5 font-mono whitespace-pre">
                    {v ?? <span className="text-muted-foreground">NULL</span>}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}

function Pill({ value, styles }: { value?: string | null; styles: Record<string, string> }) {
  if (!value) return <span className="text-muted-foreground">—</span>
  return (
    <span
      className={cn(
        'inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium',
        styles[value] ?? 'border-border text-muted-foreground',
      )}
    >
      {value}
    </span>
  )
}

export function ApprovalDetail({ id }: { id: number }) {
  const t = useTranslations('Workflows')
  const { data, error, isLoading } = useApproval(id, { refreshInterval: 15000 })
  const [busy, setBusy] = useState<'reject' | 'run' | 'cancel' | null>(null)
  const [approveOpen, setApproveOpen] = useState(false)
  const [rejectOpen, setRejectOpen] = useState(false)
  const [rejectReason, setRejectReason] = useState('')
  const [rejectError, setRejectError] = useState<string | null>(null)

  const result = data?.result ?? null
  // The statement child is pre-created at task creation with a null status ("not started yet"), so
  // `result` is truthy before any run. A run has actually started only once the child carries a status
  // (RUNNING → DONE | FAILED). Gating on `runStarted` — not on `result` — keeps the Run button visible
  // while APPROVED-not-yet-run, and keeps progress/rows/error visible once the parent leaves APPROVED.
  const runStarted = result != null && result.status != null
  const canViewRows = result?.status === 'DONE'

  const { data: resultView } = useSWR(
    canViewRows ? (['approval-result', id] as const) : null,
    () => getApprovalResult(id),
  )

  // Task-event push: revalidate the moment this task terminalizes (execute done, cancel) instead of waiting
  // for the 15s poll. Best-effort accelerator — the refreshInterval above remains the fallback on stream absence.
  useEffect(() => {
    const unsubscribe = subscribeTaskEvents()
    const off = onTaskEvent(id, () => {
      void globalMutate(swrKeys.approval(id))
      void globalMutate(['approval-result', id])
    })
    return () => {
      off()
      unsubscribe()
    }
  }, [id])

  if (isLoading && !data) return <LoadingState label={t('approvalDetail.loading')} />
  if (error) return <ErrorState error={error} />
  if (!data) return null

  const { request, canDecide } = data

  const refresh = () => {
    globalMutate(swrKeys.approval(id))
    globalMutate(swrKeys.myApprovals(undefined))
    globalMutate(swrKeys.approvalInbox)
    globalMutate(['approval-result', id])
  }

  const handleRun = async () => {
    setBusy('run')
    try {
      await executeApproval(id)
      toast.success(t('approvalDetail.submittedToast'))
      refresh()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('approvalDetail.runFailed'))
    } finally {
      setBusy(null)
    }
  }

  const handleCancel = async () => {
    setBusy('cancel')
    try {
      await cancelApproval(id)
      toast.success(t('approvalDetail.canceledToast'))
      refresh()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('approvalDetail.cancelFailed'))
    } finally {
      setBusy(null)
    }
  }

  const handleReject = async () => {
    if (!rejectReason.trim()) return
    setBusy('reject')
    setRejectError(null)
    try {
      await rejectApproval(id, rejectReason.trim())
      toast.success(t('approvalDetail.rejectedToast'))
      setRejectReason('')
      setRejectOpen(false)
      refresh()
    } catch (err) {
      setRejectError(err instanceof Error ? err.message : t('approvalDetail.rejectFailed'))
    } finally {
      setBusy(null)
    }
  }

  const approvedCopy = t('approvalDetail.approvedExecuteUnderR')

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="space-y-2">
              <CardTitle>{request.title || t('approvalDetail.queryApprovalFallbackTitle', { id: request.id })}</CardTitle>
              <div className="flex flex-wrap items-center gap-2">
                <Pill value={request.status} styles={STATUS_STYLE} />
                <Pill value={request.evaluatedDecision} styles={DECISION_STYLE} />
              </div>
            </div>
            {canDecide && (
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  onClick={() => setRejectOpen(true)}
                  disabled={busy !== null}
                  className="border-red-500/30 text-red-500 hover:bg-red-500/10 hover:text-red-500"
                >
                  {t('actions.reject')}
                </Button>
                <Button
                  onClick={() => setApproveOpen(true)}
                  disabled={busy !== null}
                  className="bg-emerald-600 text-white hover:bg-emerald-700"
                >
                  {t('actions.approveAndRun')}
                </Button>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label={t('fields.requester')}>
              <code className="font-mono">{request.principal}</code>
            </Field>
            <Field label={t('fields.datasource')}>
              <code className="font-mono">
                {request.datasourceName
                  ?? (request.datasourceId != null ? `#${request.datasourceId}` : '—')}
              </code>
            </Field>
            <Field label={t('fields.created')}>
              <code className="font-mono">{formatTimestamp(request.createdAt)}</code>
            </Field>
            <Field label={t('fields.decided')}>
              <code className="font-mono">{formatTimestamp(request.decidedAt)}</code>
            </Field>
            <Field label={t('fields.decidedBy')}>
              <code className="font-mono">{request.decidedBy ?? '—'}</code>
            </Field>
            <Field label={t('fields.sourceDecision')}>
              <code className="font-mono">
                {request.sourceDecisionId != null ? `#${request.sourceDecisionId}` : t('values.proactive')}
              </code>
            </Field>
          </div>

          <Field label={t('fields.sql')}>
            <pre className="border-border bg-muted/40 text-foreground/90 mt-1 overflow-x-auto rounded-lg border p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words">
              {request.sql ?? '—'}
            </pre>
          </Field>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t('fields.denyReason')}>{request.denyReason ?? '—'}</Field>
            <Field label={t('fields.requesterReason')}>{request.reason ?? '—'}</Field>
          </div>

          {request.status === 'REJECTED' && request.rejectionReason && (
            <Field label={t('fields.rejectionReason')}>
              <span className="text-red-500">{request.rejectionReason}</span>
            </Field>
          )}

          {request.status === 'APPROVED' && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400">
              {approvedCopy}
            </div>
          )}

          {(request.status === 'APPROVED' || runStarted) && (
            <div className="space-y-3 border-t pt-4">
              <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
                {t('approvalDetail.approverExecution')}
              </p>

              {data.canExecute && !runStarted && (
                <div className="space-y-2">
                  <p className="text-muted-foreground text-sm">
                    {t('approvalDetail.runUnderRole', { principal: request.principal })}
                  </p>
                  <Button
                    onClick={handleRun}
                    disabled={busy !== null}
                    className="bg-emerald-600 text-white hover:bg-emerald-700"
                  >
                    {busy === 'run' ? t('actions.running') : t('actions.runQuery')}
                  </Button>
                </div>
              )}

              {runStarted && result && (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-muted-foreground text-sm">
                      {t('approvalDetail.runStatus', {
                        status: result.status ?? request.status,
                        rows: result.rowCount ?? 0,
                        expires: formatTimestamp(result.expiresAt),
                      })}
                    </p>
                    {request.status === 'EXECUTING' && data.canCancel !== false && (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={handleCancel}
                        disabled={busy !== null}
                        data-testid="cancel-approval-execution"
                      >
                        {busy === 'cancel' ? t('actions.cancelingExecution') : t('actions.cancelExecution')}
                      </Button>
                    )}
                  </div>

                  {result.status === 'FAILED' && result.errorCode && (
                    <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                      {t('approvalDetail.failedCode', { code: translateApiError(result.errorCode) })}
                    </div>
                  )}

                  {canViewRows && resultView && (
                    <ResultGrid columns={resultView.columns} rows={resultView.rows} />
                  )}
                </div>
              )}

              {!runStarted && !data.canExecute && request.status === 'APPROVED' && (
                <p className="text-muted-foreground text-sm">
                  {t('approvalDetail.awaitingApprover')}
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <ApproveQueryDialog
        key={approveOpen ? request.id : 'closed'}
        request={approveOpen ? request : null}
        onClose={() => setApproveOpen(false)}
        onApproved={refresh}
      />

      <Dialog open={rejectOpen} onOpenChange={setRejectOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('approvalDetail.rejectTitle')}</DialogTitle>
            <DialogDescription>
              {t('approvalDetail.rejectDescription', { principal: request.principal })}
            </DialogDescription>
          </DialogHeader>

          {rejectError && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
              {rejectError}
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="query-approval-reject-reason">{t('fields.reasonRequired')}</Label>
            <Textarea
              id="query-approval-reject-reason"
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              placeholder={t('approvalDetail.rejectPlaceholder')}
              rows={3}
              autoFocus
            />
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setRejectOpen(false)} disabled={busy === 'reject'}>
              {t('actions.cancel')}
            </Button>
            <Button variant="destructive" onClick={handleReject} disabled={!rejectReason.trim() || busy === 'reject'}>
              {busy === 'reject' ? t('actions.rejecting') : t('actions.reject')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
