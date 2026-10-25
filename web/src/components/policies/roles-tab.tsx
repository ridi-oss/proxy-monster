'use client';

// Roles tab — CRUD for app roles. Each role is the unit that policies and JIT
// grants attach to. Name is the stable identifier; description is optional prose.
import { Fragment, useState } from 'react';
import { useTranslations } from 'next-intl';
import { Loader2, Pencil, Plus, Trash2 } from 'lucide-react';
import { mutate } from 'swr';
import { createRole, deleteRole, updateRole } from '@/lib/api/client';
import { useRoles, swrKeys } from '@/lib/hooks';
import type { Role, RoleInput } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, ErrorState, LoadingState } from '@/components/page-scaffold';
import { toast } from 'sonner';

export function RolesTab() {
  const t = useTranslations('Policies');
  const { data, error, isLoading } = useRoles();
  const [editing, setEditing] = useState<Role | null>(null);
  const [creating, setCreating] = useState(false);
  // Role pending deletion — show inline confirm row
  const [deleting, setDeleting] = useState<Role | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const handleDelete = async (role: Role) => {
    setDeleteBusy(true);
    setDeleteError(null);
    try {
      await deleteRole(role.id);
      await mutate(swrKeys.roles);
      setDeleting(null);
      toast.success(t('roles.toastDeleted', { name: role.name }));
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : t('roles.deleteFailed'));
    } finally {
      setDeleteBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <p className="text-muted-foreground text-sm">{t('roles.blurb')}</p>
        <Button size="sm" onClick={() => setCreating(true)}>
          <Plus className="size-3.5" />
          {t('roles.add')}
        </Button>
      </div>

      {isLoading && !data ? (
        <LoadingState label={t('roles.loading')} />
      ) : error ? (
        <ErrorState error={error} />
      ) : !data || data.length === 0 ? (
        <EmptyState
          title={t('roles.emptyTitle')}
          hint={t('roles.emptyHint')}
          action={
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus className="size-3.5" />
              {t('roles.add')}
            </Button>
          }
        />
      ) : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('common.name')}</TableHead>
                <TableHead>{t('roles.colDescription')}</TableHead>
                <TableHead className="w-[120px] text-right">{t('common.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((role) => (
                <Fragment key={role.id}>
                  <TableRow>
                    <TableCell>
                      <code className="font-mono text-sm font-semibold">{role.name}</code>
                    </TableCell>
                    <TableCell>
                      <span className={cn('text-sm', !role.description && 'text-muted-foreground italic')}>
                        {role.description || '—'}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          size="icon-xs"
                          variant="ghost"
                          onClick={() => {
                            setDeleting(null);
                            setEditing(role);
                          }}
                          aria-label={t('common.edit')}
                        >
                          <Pencil className="size-3.5" />
                        </Button>
                        <Button
                          size="icon-xs"
                          variant="ghost"
                          className="text-destructive hover:text-destructive"
                          onClick={() => {
                            setEditing(null);
                            setDeleteError(null);
                            setDeleting((prev) => (prev?.id === role.id ? null : role));
                          }}
                          aria-label={t('common.delete')}
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                  {/* Inline delete confirm row */}
                  {deleting?.id === role.id && (
                    <TableRow key={`${role.id}-confirm`} className="bg-red-500/5">
                      <TableCell colSpan={3}>
                        <div className="flex flex-wrap items-center justify-between gap-2 py-0.5">
                          <div>
                            <p className="text-sm font-medium text-red-500">
                              {t('roles.deleteConfirm', { name: role.name })}
                            </p>
                            <p className="text-muted-foreground text-xs">{t('roles.deleteConsequence')}</p>
                            {deleteError && <p className="mt-1 text-xs text-red-500">{deleteError}</p>}
                          </div>
                          <div className="flex items-center gap-2">
                            <Button size="xs" variant="outline" onClick={() => setDeleting(null)} disabled={deleteBusy}>
                              {t('common.cancel')}
                            </Button>
                            <Button
                              size="xs"
                              variant="destructive"
                              onClick={() => handleDelete(role)}
                              disabled={deleteBusy}
                            >
                              {deleteBusy ? <Loader2 className="size-3 animate-spin" /> : null}
                              {t('common.delete')}
                            </Button>
                          </div>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Create / edit dialog */}
      {(creating || editing !== null) && (
        <RoleDialog
          editing={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
          onSaved={() => mutate(swrKeys.roles)}
        />
      )}
    </div>
  );
}

// ---- Role dialog ------------------------------------------------------------

function RoleDialog({ editing, onClose, onSaved }: { editing: Role | null; onClose: () => void; onSaved: () => void }) {
  const t = useTranslations('Policies');
  const [name, setName] = useState(editing?.name ?? '');
  const [description, setDescription] = useState(editing?.description ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid = name.trim().length > 0;

  const handleSave = async () => {
    if (!valid) return;
    setBusy(true);
    setError(null);
    const input: RoleInput = {
      name: name.trim(),
      description: description.trim() || null,
    };
    try {
      if (editing) {
        await updateRole(editing.id, input);
        toast.success(t('roles.toastUpdated', { name: input.name }));
      } else {
        await createRole(input);
        toast.success(t('roles.toastCreated', { name: input.name }));
      }
      onSaved();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('roles.saveFailed'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{editing ? t('roles.dialogEditTitle', { name: editing.name }) : t('roles.add')}</DialogTitle>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        <div className="space-y-4 py-1">
          <div className="space-y-1.5">
            <Label htmlFor="role-name">{t('roles.fieldName')}</Label>
            <Input
              id="role-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="analyst-pii"
              autoFocus
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="role-desc">{t('roles.fieldDescription')}</Label>
            <Textarea
              id="role-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder={t('roles.descriptionPlaceholder')}
              rows={2}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button onClick={handleSave} disabled={!valid || busy}>
            {busy ? <Loader2 className="size-3.5 animate-spin" /> : null}
            {editing ? t('common.save') : t('roles.add')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
