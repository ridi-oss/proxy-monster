'use client';

// Add / edit a local app_group row. Source/externalId stay server-owned.

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { mutate } from 'swr';
import { createGroup, updateGroup } from '@/lib/api/client';
import { swrKeys } from '@/lib/hooks';
import type { AppGroup, AppGroupInput } from '@/lib/api/types';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: AppGroup | null;
}

export function GroupFormDialog({ open, onOpenChange, editing }: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        {open && (
          <GroupForm
            key={editing ? `edit-${editing.id}` : 'create'}
            editing={editing}
            onClose={() => onOpenChange(false)}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function GroupForm({ editing, onClose }: { editing: AppGroup | null; onClose: () => void }) {
  const t = useTranslations('Groups');
  const [name, setName] = useState(editing?.name ?? '');
  const [description, setDescription] = useState(editing?.description ?? '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid = name.trim() !== '';

  const handleSubmit = async () => {
    if (!valid) return;
    setSaving(true);
    setError(null);
    const input: AppGroupInput = {
      name: name.trim(),
      description: description.trim() || null,
    };
    try {
      if (editing) {
        await updateGroup(editing.id, input);
        toast.success(t('form.toastUpdated', { name: input.name }));
      } else {
        await createGroup(input);
        toast.success(t('form.toastCreated', { name: input.name }));
      }
      await mutate(swrKeys.groups);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('form.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <DialogHeader>
        <DialogTitle>{editing ? t('form.editTitle', { name: editing.name }) : t('form.addTitle')}</DialogTitle>
        <DialogDescription>{editing ? t('form.editDescription') : t('form.addDescription')}</DialogDescription>
      </DialogHeader>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">{error}</div>
      )}

      <div className="space-y-3 py-1">
        <div className="space-y-1.5">
          <Label htmlFor="group-name">{t('form.labelName')}</Label>
          <Input
            id="group-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="pii-readers"
            autoFocus
            required
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="group-description">{t('form.labelDescription')}</Label>
          <Input
            id="group-description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder={t('form.descriptionPlaceholder')}
          />
        </div>
      </div>

      <DialogFooter>
        <Button variant="outline" onClick={onClose} disabled={saving}>
          {t('form.cancel')}
        </Button>
        <Button onClick={handleSubmit} disabled={!valid || saving}>
          {saving && <Loader2 className="size-3.5 animate-spin" />}
          {editing ? t('form.submitEdit') : t('form.submitCreate')}
        </Button>
      </DialogFooter>
    </>
  );
}
