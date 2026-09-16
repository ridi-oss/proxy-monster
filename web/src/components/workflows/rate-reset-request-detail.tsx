'use client'

// A RATE_RESET request (docs/result-caps.md): approving writes the requester's reset marker, so relayed
// volume before the approval stops counting toward every rate window. Decided like a ROLE request.
import { useState, type ReactNode } from 'react'
import { useTranslations } from 'next-intl'
import { mutate } from 'swr'
import { toast } from 'sonner'
import { approveAccessRequest } from '@/lib/api/client'
import type { AccessRequest } from '@/lib/api/types'
import { swrKeys } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { RejectDialog } from '@/components/access/reject-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

const STATUS_STYLE: Record<string, string> = {
  PENDING: 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  APPROVED: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  REJECTED: 'border-red-500/30 bg-red-500/10 text-red-500',
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">{label}</p>
      <div className="text-sm">{children}</div>
    </div>
  )
}

function refresh() {
  void mutate(swrKeys.accessRequests('PENDING'))
  void mutate(swrKeys.accessRequests(undefined))
}

export function RateResetRequestDetail({ request }: { request: AccessRequest }) {
  const t = useTranslations('Workflows')
  const [approving, setApproving] = useState(false)
  const [rejecting, setRejecting] = useState<AccessRequest | null>(null)

  const handleApprove = async () => {
    setApproving(true)
    try {
      await approveAccessRequest(request.id)
      toast.success(t('rateResetDetail.approvedToast', { principal: request.principal }))
      refresh()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t('roleDetail.approveFailed'))
    } finally {
      setApproving(false)
    }
  }

  return (
    <div data-workflow-detail-kind="RATE_RESET">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="space-y-2">
              <CardTitle>{t('rateResetDetail.title', { id: request.id })}</CardTitle>
              <span
                className={cn(
                  'inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium',
                  STATUS_STYLE[request.status] ?? 'border-border text-muted-foreground',
                )}
              >
                {request.status}
              </span>
            </div>
            {request.status === 'PENDING' && (
              <div className="flex flex-wrap items-end justify-end gap-2">
                <Button
                  variant="outline"
                  onClick={() => setRejecting(request)}
                  disabled={approving}
                  className="border-red-500/30 text-red-500 hover:bg-red-500/10 hover:text-red-500"
                >
                  {t('actions.reject')}
                </Button>
                <Button onClick={handleApprove} disabled={approving}>
                  {approving ? t('actions.approving') : t('actions.approve')}
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
            <Field label={t('rateResetDetail.spentRate')}>
              <code className="font-mono">{request.denyReason ?? '—'}</code>
            </Field>
            <Field label={t('fields.created')}>
              <code className="font-mono">{new Date(request.createdAt).toLocaleString()}</code>
            </Field>
            <Field label={t('fields.decided')}>
              <code className="font-mono">{request.decidedAt ? new Date(request.decidedAt).toLocaleString() : '—'}</code>
            </Field>
            <Field label={t('fields.decidedBy')}>
              <code className="font-mono">{request.decidedBy ?? '—'}</code>
            </Field>
          </div>
          <Field label={t('fields.reason')}>{request.reason ?? '—'}</Field>
          {request.rejectionReason && (
            <Field label={t('fields.rejectionReason')}>
              <span className="text-red-500">{request.rejectionReason}</span>
            </Field>
          )}
          <p className="text-muted-foreground text-xs">{t('rateResetDetail.note', { principal: request.principal })}</p>
        </CardContent>
      </Card>
      <RejectDialog request={rejecting} onClose={() => setRejecting(null)} onRejected={refresh} />
    </div>
  )
}
