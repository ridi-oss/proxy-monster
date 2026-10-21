'use client'

// Deny → "Request access" dialog (docs/web-console.md "Workflows").
// Opened from a DENY decision banner: pick a role, write a reason, choose a
// capped duration → POST /api/access-requests, pre-scoped to the datasource the
// query ran against. On success an inline confirmation explains the next step
// (an approver grants it on /workflows, then re-run just works — grants auto-apply).
import { useEffect, useState } from 'react'
import { useTranslations } from 'next-intl'
import { CheckCircle2 } from 'lucide-react'
import { createAccessRequest } from '@/lib/api/client'
import { useRoles } from '@/lib/hooks'
import type { AccessRequestInput } from '@/lib/api/types'
import { Button } from '@/components/ui/button'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

const DURATIONS = [
  { value: '1800', key: 'duration30m' },
  { value: '3600', key: 'duration1h' },
  { value: '7200', key: 'duration2h' },
  { value: '14400', key: 'duration4h' },
  { value: '28800', key: 'duration8h' },
  { value: '43200', key: 'duration12h' },
] as const

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  datasourceId: number
  datasourceName?: string
  denyReason?: string | null
  /** Role to preselect on open when the roles list has it. */
  roleName?: string
}

export function RequestAccessDialog({
  open,
  onOpenChange,
  datasourceId,
  datasourceName,
  denyReason,
  roleName: preselectRoleName,
}: Props) {
  const t = useTranslations('Query')
  const { data: roles, isLoading } = useRoles()
  const [roleId, setRoleId] = useState<string | null>(null)
  const [reason, setReason] = useState('')
  const [durationSec, setDurationSec] = useState('3600')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [submitted, setSubmitted] = useState(false)

  // Seed defaults each time the dialog opens.
  useEffect(() => {
    if (!open) return
    setSubmitted(false)
    setError(null)
    const preselected = preselectRoleName ? roles?.find((r) => r.name === preselectRoleName) : undefined
    if (preselected) setRoleId(String(preselected.id))
    else if (roleId == null && roles && roles.length > 0) setRoleId(String(roles[0].id))
    if (!reason && denyReason) setReason(t('requestAccess.prefilledReason', { reason: denyReason }))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, roles, preselectRoleName])

  const valid = !!roleId && reason.trim().length > 0

  const handleSubmit = async () => {
    if (!valid || !roleId) return
    setBusy(true)
    setError(null)
    const input: AccessRequestInput = {
      roleId: Number(roleId),
      datasourceId,
      reason: reason.trim(),
      requestedDurationSec: Number(durationSec),
    }
    try {
      await createAccessRequest(input)
      setSubmitted(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('requestAccess.submitError'))
    } finally {
      setBusy(false)
    }
  }

  const roleName = (v: string | null) =>
    v ? (roles?.find((r) => String(r.id) === v)?.name ?? '') : t('requestAccess.rolePlaceholder')
  const durLabel = (v: string | null) => {
    const d = DURATIONS.find((d) => d.value === v)
    return d ? t(`requestAccess.${d.key}`) : ''
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('requestAccess.title')}</DialogTitle>
          <DialogDescription>
            {datasourceName
              ? t('requestAccess.descriptionWithDatasource', { name: datasourceName })
              : t('requestAccess.description')}
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        {submitted ? (
          <div className="flex items-start gap-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-3 text-sm">
            <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-500" />
            <div>
              <p className="font-medium text-emerald-600 dark:text-emerald-400">
                {t('requestAccess.successTitle')}
              </p>
              <p className="text-muted-foreground mt-0.5 text-xs">
                {t('requestAccess.successDescription')}
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-4 py-1">
            <div className="space-y-1.5">
              <Label>{t('requestAccess.roleLabel')}</Label>
              <Select value={roleId} onValueChange={(v: string | null) => setRoleId(v)} disabled={isLoading}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder={t('requestAccess.rolePlaceholder')}>
                    {(v: string | null) => roleName(v)}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {(roles ?? []).map((r) => (
                    <SelectItem key={r.id} value={String(r.id)}>
                      {r.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="reason">{t('requestAccess.reasonLabel')}</Label>
              <Textarea
                id="reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder={t('requestAccess.reasonPlaceholder')}
                rows={3}
              />
            </div>

            <div className="space-y-1.5">
              <Label>{t('requestAccess.durationLabel')}</Label>
              <Select value={durationSec} onValueChange={(v: string | null) => setDurationSec(v ?? '3600')}>
                <SelectTrigger className="w-full">
                  <SelectValue>{(v: string | null) => durLabel(v)}</SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {DURATIONS.map((d) => (
                    <SelectItem key={d.value} value={d.value}>
                      {t(`requestAccess.${d.key}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        )}

        <DialogFooter>
          {submitted ? (
            <Button onClick={() => onOpenChange(false)}>{t('requestAccess.close')}</Button>
          ) : (
            <>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                {t('requestAccess.cancel')}
              </Button>
              <Button onClick={handleSubmit} disabled={!valid || busy}>
                {busy ? t('requestAccess.submitting') : t('requestAccess.submit')}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
