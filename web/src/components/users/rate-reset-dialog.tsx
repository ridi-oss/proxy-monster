'use client'

// An admin resets a principal's spent `@cap` rates directly (docs/result-caps.md). The reset is a marker, not
// a deletion — relayed volume before it stops counting — and the reason is recorded with it.
import { useEffect, useState } from 'react'
import { useTranslations } from 'next-intl'
import { toast } from 'sonner'
import { getPrincipalRateReset, resetPrincipalRate } from '@/lib/api/client'
import type { RateReset } from '@/lib/api/types'
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
  principal: string | null
  onClose: () => void
}

export function RateResetDialog({ principal, onClose }: Props) {
  const t = useTranslations('Users')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [last, setLast] = useState<RateReset | null | undefined>(undefined)

  useEffect(() => {
    if (!principal) return
    setReason('')
    setError(null)
    setLast(undefined)
    getPrincipalRateReset(principal)
      .then(setLast)
      .catch(() => setLast(null))
  }, [principal])

  const handleReset = async () => {
    if (!principal || !reason.trim()) return
    setBusy(true)
    setError(null)
    try {
      await resetPrincipalRate(principal, reason.trim())
      toast.success(t('rateReset.toast', { principal }))
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('rateReset.failed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={principal !== null} onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('rateReset.title')}</DialogTitle>
          <DialogDescription>
            {principal ? t('rateReset.description', { principal }) : ''}
          </DialogDescription>
        </DialogHeader>

        <p className="text-muted-foreground text-xs" data-testid="rate-reset-last">
          {last === undefined
            ? t('rateReset.lastLoading')
            : last === null
              ? t('rateReset.lastNone')
              : t('rateReset.last', { at: new Date(last.resetAt).toLocaleString(), by: last.resetBy })}
        </p>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        <div className="space-y-1.5">
          <Label htmlFor="admin-rate-reset-reason">{t('rateReset.reasonLabel')}</Label>
          <Textarea
            id="admin-rate-reset-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder={t('rateReset.reasonPlaceholder')}
            rows={3}
            autoFocus
          />
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('rateReset.cancel')}
          </Button>
          <Button onClick={handleReset} disabled={!reason.trim() || busy}>
            {busy ? t('rateReset.submitting') : t('rateReset.submit')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
