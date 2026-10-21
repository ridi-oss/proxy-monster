'use client';

// Manage one user's group memberships from the flat Users page.

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Loader2, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { mutate } from 'swr';
import { addGroupMember, removeGroupMember } from '@/lib/api/client';
import { swrKeys, useGroups, useUsers } from '@/lib/hooks';
import type { AppUser, GroupRef } from '@/lib/api/types';
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

interface Props {
  user: AppUser | null;
  onClose: () => void;
}

export function UserGroupsDialog({ user, onClose }: Props) {
  const t = useTranslations('Users');
  const { data: users } = useUsers();
  const { data: groups, isLoading, error } = useGroups();
  const currentUser = user ? (users?.find((u) => u.id === user.id) ?? user) : null;
  const currentGroups = currentUser?.groups ?? [];
  const joinedIds = new Set(currentGroups.map((g) => g.id));
  const available = (groups ?? []).filter((g) => !joinedIds.has(g.id));

  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [addBusy, setAddBusy] = useState(false);
  const [busyGroupId, setBusyGroupId] = useState<number | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const selectedGroup = selectedGroupId ? available.find((g) => String(g.id) === selectedGroupId) : null;

  const refreshAfterWrite = async (groupId: number) => {
    await mutate(swrKeys.users);
    await mutate(swrKeys.groups);
    await mutate(swrKeys.groupMembers(groupId));
  };

  const handleAdd = async () => {
    if (!currentUser || !selectedGroup) return;
    setAddBusy(true);
    setErrorMessage(null);
    try {
      await addGroupMember(selectedGroup.id, currentUser.id);
      await refreshAfterWrite(selectedGroup.id);
      toast.success(
        t('groupsDialog.toastAdded', {
          principal: currentUser.principal,
          group: selectedGroup.name,
        }),
      );
      setSelectedGroupId(null);
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : t('groupsDialog.addFailed'));
    } finally {
      setAddBusy(false);
    }
  };

  const handleRemove = async (group: GroupRef) => {
    if (!currentUser) return;
    setBusyGroupId(group.id);
    setErrorMessage(null);
    try {
      await removeGroupMember(group.id, currentUser.id);
      await refreshAfterWrite(group.id);
      toast.success(t('groupsDialog.toastRemoved', { principal: currentUser.principal, group: group.name }));
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : t('groupsDialog.removeFailed'));
    } finally {
      setBusyGroupId(null);
    }
  };

  const groupLabel = (v: string | null) => {
    if (!v) return t('groupsDialog.selectGroup');
    return available.find((g) => String(g.id) === v)?.name ?? t('groupsDialog.selectGroup');
  };

  return (
    <Dialog open={user !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('groupsDialog.title')}</DialogTitle>
          <DialogDescription>
            {t.rich('groupsDialog.description', {
              principal: currentUser?.principal ?? '',
              code: (chunks) => <code className="text-foreground font-mono">{chunks}</code>,
            })}
          </DialogDescription>
        </DialogHeader>

        {errorMessage && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {errorMessage}
          </div>
        )}
        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error instanceof Error ? error.message : String(error)}
          </div>
        )}

        <div className="space-y-4 py-1">
          <div className="space-y-2">
            <Label>{t('groupsDialog.labelCurrentGroups')}</Label>
            {isLoading && !groups ? (
              <p className="text-muted-foreground text-sm">{t('groupsDialog.loadingGroups')}</p>
            ) : currentGroups.length === 0 ? (
              <p className="text-muted-foreground rounded-lg border border-dashed px-3 py-4 text-sm">
                {t('groupsDialog.noGroups')}
              </p>
            ) : (
              <div className="divide-y rounded-lg border">
                {currentGroups.map((g) => (
                  <div key={g.id} className="flex items-center justify-between gap-3 px-3 py-2">
                    <span className="font-mono text-sm">{g.name}</span>
                    <Button
                      size="icon-xs"
                      variant="ghost"
                      className="text-destructive hover:text-destructive"
                      onClick={() => handleRemove(g)}
                      disabled={busyGroupId === g.id}
                      aria-label={t('groupsDialog.removeGroup')}
                    >
                      {busyGroupId === g.id ? (
                        <Loader2 className="size-3.5 animate-spin" />
                      ) : (
                        <Trash2 className="size-3.5" />
                      )}
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="space-y-2">
            <Label>{t('groupsDialog.labelAddGroup')}</Label>
            <div className="flex gap-2">
              <Select value={selectedGroupId} onValueChange={(v: string | null) => setSelectedGroupId(v)}>
                <SelectTrigger className="min-w-0 flex-1">
                  <SelectValue placeholder={t('groupsDialog.selectGroup')}>
                    {(v: string | null) => groupLabel(v)}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {available.map((g) => (
                    <SelectItem key={g.id} value={String(g.id)}>
                      {g.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button onClick={handleAdd} disabled={!selectedGroup || addBusy}>
                {addBusy ? <Loader2 className="size-3.5 animate-spin" /> : <Plus className="size-3.5" />}
                {t('groupsDialog.add')}
              </Button>
            </div>
            {available.length === 0 && (
              <p className="text-muted-foreground text-xs">{t('groupsDialog.noMoreGroups')}</p>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('groupsDialog.close')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
