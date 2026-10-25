'use client';

// Assignments tab — maps a principal (email / IdP group) to a base role.
// IdP groups resolve server-side; this is the explicit principal-level override.
import { Fragment, useState } from 'react';
import { useTranslations } from 'next-intl';
import { Loader2, Plus, Trash2 } from 'lucide-react';
import { mutate } from 'swr';
import { createRoleAssignment, deleteRoleAssignment } from '@/lib/api/client';
import { useRoleAssignments, useRoles, swrKeys } from '@/lib/hooks';
import type { Role, RoleAssignment } from '@/lib/api/types';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, ErrorState, LoadingState } from '@/components/page-scaffold';
import { toast } from 'sonner';

export function AssignmentsTab() {
  const t = useTranslations('Policies');
  const { data: assignments, error, isLoading } = useRoleAssignments();
  const { data: roles } = useRoles();
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<RoleAssignment | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const handleDelete = async (a: RoleAssignment) => {
    setDeleteBusy(true);
    setDeleteError(null);
    try {
      await deleteRoleAssignment(a.id);
      await mutate(swrKeys.roleAssignments);
      setDeleting(null);
      toast.success(t('assignments.toastRemoved', { roleName: a.roleName, principal: a.principal }));
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : t('assignments.removeFailed'));
    } finally {
      setDeleteBusy(false);
    }
  };

  const noRoles = (roles?.length ?? 0) === 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-muted-foreground text-sm">{t('assignments.blurb')}</p>
        <Button size="sm" onClick={() => setAdding(true)} disabled={noRoles}>
          <Plus className="size-3.5" />
          {t('assignments.assign')}
        </Button>
      </div>

      {isLoading && !assignments ? (
        <LoadingState label={t('assignments.loading')} />
      ) : error ? (
        <ErrorState error={error} />
      ) : !assignments || assignments.length === 0 ? (
        <EmptyState
          title={t('assignments.emptyTitle')}
          hint={t('assignments.emptyHint')}
          action={
            <Button size="sm" onClick={() => setAdding(true)} disabled={noRoles}>
              <Plus className="size-3.5" />
              {t('assignments.assign')}
            </Button>
          }
        />
      ) : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('assignments.colPrincipal')}</TableHead>
                <TableHead>{t('assignments.colRole')}</TableHead>
                <TableHead className="w-[80px] text-right">{t('common.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {assignments.map((a) => (
                <Fragment key={a.id}>
                  <TableRow>
                    <TableCell>
                      <code className="text-muted-foreground font-mono text-sm">{a.principal}</code>
                    </TableCell>
                    <TableCell>
                      <span className="border-border text-foreground/80 rounded border px-1.5 py-0.5 font-mono text-xs">
                        {a.roleName}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="icon-xs"
                        variant="ghost"
                        className="text-destructive hover:text-destructive"
                        onClick={() => {
                          setDeleteError(null);
                          setDeleting((prev) => (prev?.id === a.id ? null : a));
                        }}
                        aria-label={t('assignments.remove')}
                      >
                        <Trash2 className="size-3.5" />
                      </Button>
                    </TableCell>
                  </TableRow>
                  {deleting?.id === a.id && (
                    <TableRow key={`${a.id}-confirm`} className="bg-red-500/5">
                      <TableCell colSpan={3}>
                        <div className="flex flex-wrap items-center justify-between gap-2 py-0.5">
                          <div>
                            <p className="text-sm font-medium text-red-500">
                              {t.rich('assignments.deleteConfirm', {
                                roleName: a.roleName,
                                principal: a.principal,
                                code: (chunks) => <code className="font-mono">{chunks}</code>,
                              })}
                            </p>
                            {deleteError && <p className="mt-1 text-xs text-red-500">{deleteError}</p>}
                          </div>
                          <div className="flex items-center gap-2">
                            <Button size="xs" variant="outline" onClick={() => setDeleting(null)} disabled={deleteBusy}>
                              {t('common.cancel')}
                            </Button>
                            <Button
                              size="xs"
                              variant="destructive"
                              onClick={() => handleDelete(a)}
                              disabled={deleteBusy}
                            >
                              {deleteBusy ? <Loader2 className="size-3 animate-spin" /> : null}
                              {t('assignments.remove')}
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

      {adding && (
        <AssignDialog
          roles={roles ?? []}
          onClose={() => setAdding(false)}
          onSaved={() => mutate(swrKeys.roleAssignments)}
        />
      )}
    </div>
  );
}

// ---- Assign dialog ----------------------------------------------------------

function AssignDialog({ roles, onClose, onSaved }: { roles: Role[]; onClose: () => void; onSaved: () => void }) {
  const t = useTranslations('Policies');
  const [principal, setPrincipal] = useState('');
  const [roleId, setRoleId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid = principal.trim().length > 0 && roleId != null;

  const handleSave = async () => {
    if (!valid || !roleId) return;
    setBusy(true);
    setError(null);
    try {
      await createRoleAssignment({ principal: principal.trim(), roleId: Number(roleId) });
      toast.success(
        t('assignments.toastAssigned', {
          roleName: roles.find((r) => String(r.id) === roleId)?.name ?? '',
          principal: principal.trim(),
        }),
      );
      onSaved();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('assignments.assignFailed'));
    } finally {
      setBusy(false);
    }
  };

  const roleLabel = (v: string | null) =>
    v ? (roles.find((r) => String(r.id) === v)?.name ?? '') : t('assignments.selectRole');

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('assignments.assign')}</DialogTitle>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        <div className="space-y-4 py-1">
          <div className="space-y-1.5">
            <Label htmlFor="assign-principal">{t('assignments.colPrincipal')}</Label>
            <Input
              id="assign-principal"
              value={principal}
              onChange={(e) => setPrincipal(e.target.value)}
              placeholder="bob@example.com"
              autoFocus
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label>{t('assignments.colRole')}</Label>
            <Select value={roleId} onValueChange={(v: string | null) => setRoleId(v)}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder={t('assignments.selectRole')}>
                  {(v: string | null) => roleLabel(v)}
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                {roles.map((r) => (
                  <SelectItem key={r.id} value={String(r.id)}>
                    {r.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button onClick={handleSave} disabled={!valid || busy}>
            {busy ? <Loader2 className="size-3.5 animate-spin" /> : null}
            {t('assignments.assignButton')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
