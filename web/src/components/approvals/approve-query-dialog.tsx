'use client'

import { useState } from 'react'
import { useTranslations } from 'next-intl'
import { mutate } from 'swr'
import { toast } from 'sonner'
import { approveApproval, executeApproval, ApiError } from '@/lib/api/client'
import type { AccessRequest } from '@/lib/api/types'
import { swrKeys } from '@/lib/hooks'
import { approveLabelKey, runsOnMerge } from '@/lib/approvals'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

type Translator = ReturnType<typeof useTranslations>

function errorMessage(err: unknown, t: Translator): string {
  if (err instanceof ApiError) {
    try {
      const parsed = JSON.parse(err.message) as { error?: string }
      return parsed.error ?? err.message
    } catch {
      return err.message
    }
  }
  return err instanceof Error ? err.message : t('approveDialog.approveFailed')
}

export function ApproveQueryDialog({
  request,
  onClose,
  onApproved,
}: {
  request: AccessRequest | null
  onClose: () => void
  onApproved?: () => void
}) {
  const t = useTranslations('Workflows')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const approveOnly = runsOnMerge(request)

  const handleOpenChange = (open: boolean) => {
    if (!open && !busy) onClose()
  }

  // Approval commits first; a console request then runs at once, a GitHub one waits for its merge.
  const handleApprove = async () => {
    if (!request) return
    setBusy(true)
    setError(null)
    try {
      await approveApproval(request.id, request.revision)
    } catch (err) {
      setError(errorMessage(err, t))
      setBusy(false)
      return
    }
    try {
      if (approveOnly) {
        toast.success(t('approveDialog.approvedToast', { principal: request.principal }))
      } else {
        await executeApproval(request.id)
        toast.success(t('approveDialog.approveAndRunToast', { principal: request.principal }))
      }
    } catch (err) {
      // Approval already committed; surface the run's REAL localized error (e.g. no result store, deleted
      // datasource) rather than a blanket "retry" line that may not be actionable. The detail refresh below
      // reflects the true state — the Run button appears only when a retry is actually available.
      toast.error(err instanceof ApiError ? errorMessage(err, t) : t('approveDialog.approvedRunFailed'))
    }
    mutate(swrKeys.approvalInbox)
    mutate(swrKeys.approval(request.id))
    mutate(['approval-result', request.id])
    onApproved?.()
    onClose()
    setBusy(false)
  }

  return (
    <Dialog open={request !== null} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t(approveOnly ? 'approveDialog.titleGithub' : 'approveDialog.title')}</DialogTitle>
          <DialogDescription>
            {approveOnly
              ? t('approvalDetail.approvedGithub')
              : request
                ? t('approveDialog.descriptionWithPrincipal', { principal: request.principal })
                : t('approveDialog.descriptionFallback')}
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        {!approveOnly && (
          <p className="text-muted-foreground text-sm">{t('approveDialog.executeUnderRNote')}</p>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('actions.cancel')}
          </Button>
          <Button
            onClick={handleApprove}
            disabled={busy}
            className="bg-emerald-600 text-white hover:bg-emerald-700"
          >
            {busy
              ? t(approveOnly ? 'actions.approving' : 'actions.approvingAndRunning')
              : t(approveLabelKey(request))}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
