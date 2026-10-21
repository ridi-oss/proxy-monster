'use client'

import { useState, type ReactNode } from 'react'
import { useTranslations } from 'next-intl'
import { mutate } from 'swr'
import { Clock } from 'lucide-react'
import { toast } from 'sonner'
import { approveAccessRequest } from '@/lib/api/client'
import type { AccessRequest } from '@/lib/api/types'
import { swrKeys, useRequestThread } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { RejectDialog } from '@/components/access/reject-dialog'
import { CloseRequestButton, RequestTimeline } from '@/components/approvals/request-timeline'
import { useAuth } from '@/lib/auth'
import { ErrorState } from '@/components/page-scaffold'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

type Translator = ReturnType<typeof useTranslations>

const DURATION_OVERRIDE_OPTIONS: { value: string; key: string }[] = [
  { value: '__requested__', key: 'asRequested' },
  { value: '1800', key: 'm30' },
  { value: '3600', key: 'h1' },
  { value: '7200', key: 'h2' },
  { value: '14400', key: 'h4' },
  { value: '28800', key: 'h8' },
  { value: '43200', key: 'h12' },
]

const STATUS_STYLE: Record<string, string> = {
  PENDING: 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  APPROVED: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  REJECTED: 'border-red-500/30 bg-red-500/10 text-red-500',
  CANCELLED: 'border-border text-muted-foreground',
}

function formatDuration(seconds: number, t: Translator): string {
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (hours > 0 && minutes > 0) return t('durationFormat.hoursMinutes', { hours, minutes })
  if (hours > 0) return t('durationFormat.hours', { hours })
  return t('durationFormat.minutes', { minutes })
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

function refreshRoleWorkflow(id: number) {
  void mutate(swrKeys.requestThread(id))
  void mutate(swrKeys.involvedApprovals)
  void mutate(swrKeys.accessRequests('PENDING'))
  void mutate(swrKeys.accessRequests(undefined))
  void mutate(swrKeys.accessGrants(true))
}

export function RoleRequestDetail({ request }: { request: AccessRequest }) {
  const t = useTranslations('Workflows')
  const [durationSelection, setDurationSelection] = useState({
    requestId: request.id,
    value: '__requested__',
  })
  const [approving, setApproving] = useState(false)
  const [rejectingId, setRejectingId] = useState<number | null>(null)
  const { identity } = useAuth()
  const canDecide = useRequestThread(request.id).data?.canDecide ?? false

  if (request.kind !== 'ROLE') {
    return (
      <div data-workflow-detail-kind="ROLE">
        <ErrorState error={new Error(t('roleDetail.notRoleError'))} />
      </div>
    )
  }

  const durationOverrides = DURATION_OVERRIDE_OPTIONS.map((option) => ({
    value: option.value,
    label: t(`durations.${option.key}`),
  }))
  const datasource =
    request.datasourceId == null
      ? t('values.anyDatasource')
      : (request.datasourceName ?? `#${request.datasourceId}`)
  const role = request.roleName ?? (request.roleId != null ? `#${request.roleId}` : '—')
  const durationOverride =
    durationSelection.requestId === request.id ? durationSelection.value : '__requested__'
  const durationLabel =
    durationOverrides.find((option) => option.value === durationOverride)?.label
      ?? t('durations.asRequested')

  const handleApprove = async () => {
    setApproving(true)
    const durationSec =
      durationOverride === '__requested__' ? undefined : Number(durationOverride)
    try {
      await approveAccessRequest(request.id, durationSec)
      toast.success(t('roleDetail.approvedToast', { principal: request.principal, role }))
      refreshRoleWorkflow(request.id)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t('roleDetail.approveFailed'))
    } finally {
      setApproving(false)
    }
  }

  return (
    <div data-workflow-detail-kind="ROLE">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="space-y-2">
              <CardTitle>{t('roleDetail.title', { id: request.id })}</CardTitle>
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
                <CloseRequestButton request={request} onClosed={() => refreshRoleWorkflow(request.id)} />
                {canDecide && (
                  <>
                  <div className="space-y-1.5">
                    <Label htmlFor={`role-request-duration-override-${request.id}`}>
                      {t('fields.grantDuration')}
                    </Label>
                    <Select
                      value={durationOverride}
                      onValueChange={(value: string | null) =>
                        setDurationSelection({
                          requestId: request.id,
                          value: value ?? '__requested__',
                        })
                      }
                    >
                      <SelectTrigger
                        id={`role-request-duration-override-${request.id}`}
                        size="sm"
                        className="w-36"
                      >
                        <Clock className="text-muted-foreground size-3.5" />
                        <SelectValue>{durationLabel}</SelectValue>
                      </SelectTrigger>
                      <SelectContent>
                        {durationOverrides.map((option) => (
                          <SelectItem key={option.value} value={option.value}>
                            {option.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <Button
                    variant="outline"
                    onClick={() => setRejectingId(request.id)}
                    disabled={approving}
                    className="border-red-500/30 text-red-500 hover:bg-red-500/10 hover:text-red-500"
                  >
                    {t('actions.reject')}
                  </Button>
                  <Button onClick={handleApprove} disabled={approving}>
                    {approving ? t('actions.approving') : t('actions.approve')}
                  </Button>
                  </>
                )}
              </div>
            )}
          </div>
        </CardHeader>

        <CardContent className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label={t('fields.requester')}>
              <code className="font-mono">{request.principal}</code>
            </Field>
            <Field label={t('fields.role')}>
              <code className="font-mono">{role}</code>
            </Field>
            <Field label={t('fields.datasource')}>
              <code className="font-mono">{datasource}</code>
            </Field>
            <Field label={t('fields.requestedDuration')}>
              <code className="font-mono">{formatDuration(request.requestedDurationSec, t)}</code>
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
          </div>


          <Field label={t('fields.reason')}>{request.reason ?? '—'}</Field>

          {request.rejectionReason && (
            <Field label={t('fields.rejectionReason')}>
              <span className="text-red-500">{request.rejectionReason}</span>
            </Field>
          )}

          <RequestTimeline request={request} principal={identity?.principal} onChanged={() => refreshRoleWorkflow(request.id)} />
        </CardContent>
      </Card>

      {request.status === 'PENDING' && (
        <RejectDialog
          request={rejectingId === request.id ? request : null}
          onClose={() => setRejectingId(null)}
          onRejected={() => {
            toast.success(t('roleDetail.rejectedToast', { principal: request.principal }))
            refreshRoleWorkflow(request.id)
          }}
        />
      )}
    </div>
  )
}
