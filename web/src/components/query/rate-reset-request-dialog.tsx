'use client'

// A spent `@cap` rate denies the query (docs/result-caps.md). The reset is a marker an approver grants: this
// dialog files the RATE_RESET request with the deny reason attached, and the Workflows page decides it.
import { useEffect, useState } from 'react'
import { useTranslations } from 'next-intl'
import { CheckCircle2 } from 'lucide-react'
import { createRateResetRequest } from '@/lib/api/client'
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

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  denyReason: string | null
}

export function RateResetRequestDialog({ open, onOpenChange, denyReason }: Props) {
  const t = useTranslations('Query')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [submitted, setSubmitted] = useState(false)

  useEffect(() => {
    if (!open) return
    setSubmitted(false)
    setError(null)
    setReason('')
  }, [open])

  const handleSubmit = async () => {
    if (!reason.trim()) return
    setBusy(true)
    setError(null)
    try {
      await createRateResetRequest({ reason: reason.trim(), denyReason })
      setSubmitted(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('rateReset.submitError'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('rateReset.title')}</DialogTitle>
          <DialogDescription>{t('rateReset.description')}</DialogDescription>
        </DialogHeader>

        {denyReason && (
          <p className="text-muted-foreground rounded-lg border px-3 py-2 font-mono text-xs">{denyReason}</p>
        )}
        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        {submitted ? (
          <div className="flex items-start gap-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-3 text-sm">
            <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-500" />
            <div>
              <p className="font-medium text-emerald-600 dark:text-emerald-400">{t('rateReset.successTitle')}</p>
              <p className="text-muted-foreground mt-0.5 text-xs">{t('rateReset.successDescription')}</p>
            </div>
          </div>
        ) : (
          <div className="space-y-1.5">
            <Label htmlFor="rate-reset-reason">{t('rateReset.reasonLabel')}</Label>
            <Textarea
              id="rate-reset-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder={t('rateReset.reasonPlaceholder')}
              rows={3}
              autoFocus
            />
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {submitted ? t('rateReset.close') : t('rateReset.cancel')}
          </Button>
          {!submitted && (
            <Button onClick={handleSubmit} disabled={!reason.trim() || busy}>
              {busy ? t('rateReset.submitting') : t('rateReset.submit')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
