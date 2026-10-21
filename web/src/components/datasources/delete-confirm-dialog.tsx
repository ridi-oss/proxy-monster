'use client';

// Confirm-gated delete dialog for a datasource. Warns that policies scoped to
// the datasource will stop resolving — matches the warning copy from the old
// DatasourcesPage.tsx.

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Loader2 } from 'lucide-react';
import { deleteDatasource } from '@/lib/api/client';
import { mutate } from 'swr';
import { swrKeys } from '@/lib/hooks';
import type { Datasource } from '@/lib/api/types';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

interface Props {
  datasource: Datasource | null;
  onClose: () => void;
}

export function DeleteConfirmDialog({ datasource, onClose }: Props) {
  const t = useTranslations('Datasources');
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleConfirm = async () => {
    if (!datasource) return;
    setDeleting(true);
    setError(null);
    try {
      await deleteDatasource(datasource.id);
      await mutate(swrKeys.datasources);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('deleteDialog.deleteFailed'));
    } finally {
      setDeleting(false);
    }
  };

  return (
    <Dialog open={datasource !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('deleteDialog.title')}</DialogTitle>
          <DialogDescription>
            {t.rich('deleteDialog.description', {
              name: datasource?.name ?? '',
              b: (chunks) => <span className="text-foreground font-medium">{chunks}</span>,
            })}
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={deleting}>
            {t('deleteDialog.cancel')}
          </Button>
          <Button variant="destructive" onClick={handleConfirm} disabled={deleting}>
            {deleting && <Loader2 className="size-3.5 animate-spin" />}
            {t('deleteDialog.delete')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
