'use client';

// Add / edit a local app_user row. Source/externalId are server-owned so SCIM
// provenance cannot be forged through this local admin API.

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { mutate } from 'swr';
import { createUser, updateUser } from '@/lib/api/client';
import { swrKeys } from '@/lib/hooks';
import type { AppUser, AppUserInput } from '@/lib/api/types';
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
import { Switch } from '@/components/ui/switch';

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: AppUser | null;
}

export function UserFormDialog({ open, onOpenChange, editing }: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        {open && (
          <UserForm
            key={editing ? `edit-${editing.id}` : 'create'}
            editing={editing}
            onClose={() => onOpenChange(false)}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function UserForm({ editing, onClose }: { editing: AppUser | null; onClose: () => void }) {
  const t = useTranslations('Users');
  const [principal, setPrincipal] = useState(editing?.principal ?? '');
  const [displayName, setDisplayName] = useState(editing?.displayName ?? '');
  const [email, setEmail] = useState(editing?.email ?? '');
  const [active, setActive] = useState(editing?.active ?? true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid = principal.trim() !== '';

  const handleSubmit = async () => {
    if (!valid) return;
    setSaving(true);
    setError(null);
    const input: AppUserInput = {
      principal: principal.trim(),
      displayName: displayName.trim() || null,
      email: email.trim() || null,
      active,
    };
    try {
      if (editing) {
        await updateUser(editing.id, input);
        toast.success(t('form.toastUpdated', { principal: input.principal }));
      } else {
        await createUser(input);
        toast.success(t('form.toastCreated', { principal: input.principal }));
      }
      await mutate(swrKeys.users);
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
        <DialogTitle>
          {editing ? t('form.editTitle', { principal: editing.principal }) : t('form.addTitle')}
        </DialogTitle>
        <DialogDescription>{editing ? t('form.editDescription') : t('form.addDescription')}</DialogDescription>
      </DialogHeader>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">{error}</div>
      )}

      <div className="space-y-3 py-1">
        <div className="space-y-1.5">
          <Label htmlFor="user-principal">{t('form.labelPrincipal')}</Label>
          <Input
            id="user-principal"
            value={principal}
            onChange={(e) => setPrincipal(e.target.value)}
            placeholder="bob@example.com"
            autoFocus
            required
          />
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="user-display-name">{t('form.labelDisplayName')}</Label>
          <Input
            id="user-display-name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Bob"
          />
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="user-email">{t('form.labelEmail')}</Label>
          <Input
            id="user-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="bob@example.com"
          />
        </div>

        <div className="flex items-center justify-between rounded-lg border px-3 py-2">
          <div className="space-y-0.5">
            <Label htmlFor="user-active">{t('form.labelActive')}</Label>
            <p className="text-muted-foreground text-xs">{t('form.activeHint')}</p>
          </div>
          <Switch id="user-active" checked={active} onCheckedChange={setActive} />
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
