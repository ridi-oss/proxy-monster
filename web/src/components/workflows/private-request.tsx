'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { toast } from 'sonner';
import { Lock } from 'lucide-react';
import { makeRequestPrivate } from '@/lib/api/client';
import type { AccessRequest } from '@/lib/api/types';
import { useAuth } from '@/lib/auth';
import { useMePermissions } from '@/lib/hooks';
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
import { Switch } from '@/components/ui/switch';

export function PrivateField({
  id,
  checked,
  onCheckedChange,
}: {
  id: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  const t = useTranslations('Workflows');
  return (
    <div className="flex items-start gap-3">
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} className="mt-0.5" />
      <div className="space-y-0.5">
        <Label htmlFor={id}>{t('private.label')}</Label>
        <p className="text-muted-foreground text-xs">{t('private.hint')}</p>
      </div>
    </div>
  );
}

export function PrivateBadge({ request }: { request: AccessRequest }) {
  const t = useTranslations('Workflows');
  if (!request.private) return null;
  return (
    <span className="border-border text-muted-foreground inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium">
      <Lock className="size-3" />
      {t('private.badge')}
    </span>
  );
}

export function MakePrivateButton({ request, onDone }: { request: AccessRequest; onDone?: () => void }) {
  const t = useTranslations('Workflows');
  const { identity } = useAuth();
  const isAdmin = useMePermissions().data?.isAdmin ?? false;
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  if (request.private || (identity?.principal !== request.principal && !isAdmin)) return null;

  const confirm = async () => {
    setBusy(true);
    try {
      await makeRequestPrivate(request.id);
      toast.success(t('private.madeToast'));
      setOpen(false);
      onDone?.();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('private.failed'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}>
        <Lock className="size-3.5" />
        {t('private.make')}
      </Button>
      <Dialog open={open} onOpenChange={(next) => !busy && setOpen(next)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('private.dialogTitle')}</DialogTitle>
            <DialogDescription>{t('private.dialogBody')}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
              {t('actions.cancel')}
            </Button>
            <Button onClick={confirm} disabled={busy}>
              {busy ? t('private.making') : t('private.confirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
