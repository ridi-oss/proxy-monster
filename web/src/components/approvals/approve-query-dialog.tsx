'use client'

import { useState } from 'react'
import { useTranslations } from 'next-intl'
import { mutate } from 'swr'
import { toast } from 'sonner'
import { approveApproval, executeApproval, ApiError } from '@/lib/api/client'
import type { AccessRequest } from '@/lib/api/types'
import { swrKeys } from '@/lib/hooks'
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

  const handleOpenChange = (open: boolean) => {
    if (!open && !busy) onClose()
  }

  // Approve and run are one action here, mirroring the Slack "Approve and run" button: the approver is
  // always the executor (the query runs under the requested role, execute-under-R), so approving without
  // running would just strand the task waiting for a second click. Approval is committed first; if only the
  // run fails, the request stays APPROVED and the detail's Run button lets the approver retry.
  const handleApproveAndRun = async () => {
    if (!request) return
    setBusy(true)
    setError(null)
    try {
      await approveApproval(request.id)
    } catch (err) {
      setError(errorMessage(err, t))
      setBusy(false)
      return
    }
    try {
      await executeApproval(request.id)
      toast.success(t('approveDialog.approveAndRunToast', { principal: request.principal }))
    } catch {
      toast.error(t('approveDialog.approvedRunFailed'))
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
          <DialogTitle>{t('approveDialog.title')}</DialogTitle>
          <DialogDescription>
            {request
              ? t('approveDialog.descriptionWithPrincipal', { principal: request.principal })
              : t('approveDialog.descriptionFallback')}
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        <p className="text-muted-foreground text-sm">{t('approveDialog.executeUnderRNote')}</p>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('actions.cancel')}
          </Button>
          <Button
            onClick={handleApproveAndRun}
            disabled={busy}
            className="bg-emerald-600 text-white hover:bg-emerald-700"
          >
            {busy ? t('actions.approvingAndRunning') : t('actions.approveAndRun')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
