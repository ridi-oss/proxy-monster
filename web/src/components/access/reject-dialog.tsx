'use client';

// Reject reason dialog — opened when an approver clicks "Reject" on a pending
// request. Requires a non-empty reason before the API call goes out.
import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { rejectAccessRequest } from '@/lib/api/client';
import type { AccessRequest } from '@/lib/api/types';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';

interface Props {
  request: AccessRequest | null;
  onClose: () => void;
  onRejected: () => void;
}

export function RejectDialog({ request, onClose, onRejected }: Props) {
  const t = useTranslations('Access');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleReject = async () => {
    if (!request || !reason.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await rejectAccessRequest(request.id, reason.trim());
      setReason('');
      onRejected();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('reject.failed'));
    } finally {
      setBusy(false);
    }
  };

  const handleOpenChange = (open: boolean) => {
    if (!open) {
      setReason('');
      setError(null);
      onClose();
    }
  };

  return (
    <Dialog open={request !== null} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('reject.title')}</DialogTitle>
          <DialogDescription>
            {request
              ? request.kind === 'QUERY'
                ? t('reject.descriptionQuery', { principal: request.principal })
                : t('reject.descriptionAccess', {
                    principal: request.principal,
                    role: request.roleName ?? '—',
                  })
              : t('reject.descriptionFallback')}
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        <div className="space-y-1.5">
          <Label htmlFor="reject-reason">{t('reject.reasonLabel')}</Label>
          <Textarea
            id="reject-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder={t('reject.reasonPlaceholder')}
            rows={3}
            autoFocus
          />
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('reject.cancel')}
          </Button>
          <Button variant="destructive" onClick={handleReject} disabled={!reason.trim() || busy}>
            {busy ? t('reject.submitting') : t('reject.submit')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
