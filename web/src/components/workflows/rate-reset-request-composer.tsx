'use client'

// Files a RATE_RESET request from the Workflows page, for a spent `@cap` rate hit over the wire (the editor's
// deny callout files the same request with the deny reason attached; here the reason is typed).
import { useState, type FormEvent } from 'react'
import { useTranslations } from 'next-intl'
import { mutate } from 'swr'
import { toast } from 'sonner'
import { createRateResetRequest } from '@/lib/api/client'
import type { AccessRequest } from '@/lib/api/types'
import { swrKeys } from '@/lib/hooks'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'

export function RateResetRequestComposer({
  onCreated,
  onCancel,
}: {
  onCreated: (request: AccessRequest) => void
  onCancel: () => void
}) {
  const t = useTranslations('Workflows')
  const [reason, setReason] = useState('')
  const [denyReason, setDenyReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const valid = reason.trim().length > 0

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!valid) return
    setBusy(true)
    setError(null)
    try {
      const created = await createRateResetRequest({
        reason: reason.trim(),
        denyReason: denyReason.trim() || null,
      })
      const upsertCreated = (requests: AccessRequest[] | undefined) => [
        created,
        ...(requests ?? []).filter((request) => request.id !== created.id),
      ]
      toast.success(t('rateResetComposer.submittedToast'))
      void mutate(swrKeys.accessRequests('PENDING'), upsertCreated, { revalidate: true })
      void mutate(swrKeys.accessRequests(undefined), upsertCreated, { revalidate: true })
      onCreated(created)
    } catch (submissionError) {
      setError(
        submissionError instanceof Error ? submissionError.message : t('rateResetComposer.submitFailed'),
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <form data-workflow-composer-kind="RATE_RESET" onSubmit={handleSubmit}>
      <Card>
        <CardHeader>
          <CardTitle>{t('rateResetComposer.title')}</CardTitle>
          <CardDescription>{t('rateResetComposer.description')}</CardDescription>
        </CardHeader>

        <CardContent className="space-y-4">
          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
              {error}
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="rate-reset-request-deny-reason">{t('rateResetComposer.denyReasonLabel')}</Label>
            <Input
              id="rate-reset-request-deny-reason"
              value={denyReason}
              onChange={(event) => setDenyReason(event.target.value)}
              placeholder={t('rateResetComposer.denyReasonPlaceholder')}
              className="font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="rate-reset-request-reason">{t('fields.reason')}</Label>
            <Textarea
              id="rate-reset-request-reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder={t('rateResetComposer.reasonPlaceholder')}
              rows={3}
              required
            />
          </div>
        </CardContent>

        <CardFooter className="justify-end gap-2">
          <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>
            {t('actions.cancel')}
          </Button>
          <Button type="submit" disabled={!valid || busy}>
            {busy ? t('actions.submitting') : t('actions.submitRequest')}
          </Button>
        </CardFooter>
      </Card>
    </form>
  )
}
