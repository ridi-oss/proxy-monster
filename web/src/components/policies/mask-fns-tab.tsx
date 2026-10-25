'use client';

// Mask functions tab — CRUD for the deterministic transform library that column
// policies reference when action=MASK. The transform is fully specified by its
// kind (FIXED / LAST_N / FORMAT_PRESERVING / NULL).
import { Fragment, useState } from 'react';
import { useTranslations } from 'next-intl';
import { Loader2, Pencil, Plus, Trash2 } from 'lucide-react';
import { mutate } from 'swr';
import { createMaskFn, deleteMaskFn, updateMaskFn } from '@/lib/api/client';
import { useMaskFns, swrKeys } from '@/lib/hooks';
import type { MaskFn, MaskFnInput, MaskFnKind } from '@/lib/api/types';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, ErrorState, LoadingState } from '@/components/page-scaffold';
import { toast } from 'sonner';

const KINDS: MaskFnKind[] = ['FIXED', 'LAST_N', 'FORMAT_PRESERVING', 'NULL'];

export function MaskFnsTab() {
  const t = useTranslations('Policies');
  const { data, error, isLoading } = useMaskFns();

  const [editing, setEditing] = useState<MaskFn | null>(null);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<MaskFn | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const handleDelete = async (fn: MaskFn) => {
    setDeleteBusy(true);
    setDeleteError(null);
    try {
      await deleteMaskFn(fn.id);
      await mutate(swrKeys.maskFns);
      setDeleting(null);
      toast.success(t('maskFns.toastDeleted', { name: fn.name }));
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : t('maskFns.deleteFailed'));
    } finally {
      setDeleteBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-muted-foreground text-sm">{t('maskFns.blurb')}</p>
        <Button size="sm" onClick={() => setCreating(true)}>
          <Plus className="size-3.5" />
          {t('maskFns.add')}
        </Button>
      </div>

      {isLoading && !data ? (
        <LoadingState label={t('maskFns.loading')} />
      ) : error ? (
        <ErrorState error={error} />
      ) : !data || data.length === 0 ? (
        <EmptyState
          title={t('maskFns.emptyTitle')}
          hint={t('maskFns.emptyHint')}
          action={
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus className="size-3.5" />
              {t('maskFns.add')}
            </Button>
          }
        />
      ) : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('common.name')}</TableHead>
                <TableHead>{t('maskFns.colKind')}</TableHead>
                <TableHead className="w-[120px] text-right">{t('common.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((fn) => (
                <Fragment key={fn.id}>
                  <TableRow>
                    <TableCell>
                      <code className="font-mono text-sm font-semibold">{fn.name}</code>
                    </TableCell>
                    <TableCell>
                      <span className="border-border text-foreground/80 rounded border px-1.5 py-0.5 font-mono text-xs">
                        {fn.kind}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          size="icon-xs"
                          variant="ghost"
                          onClick={() => {
                            setDeleting(null);
                            setEditing(fn);
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
                            setDeleting((prev) => (prev?.id === fn.id ? null : fn));
                          }}
                          aria-label={t('common.delete')}
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                  {deleting?.id === fn.id && (
                    <TableRow key={`${fn.id}-confirm`} className="bg-red-500/5">
                      <TableCell colSpan={3}>
                        <div className="flex flex-wrap items-center justify-between gap-2 py-0.5">
                          <div>
                            <p className="text-sm font-medium text-red-500">
                              {t('maskFns.deleteConfirm', { name: fn.name })}
                            </p>
                            <p className="text-muted-foreground text-xs">{t('maskFns.deleteConsequence')}</p>
                            {deleteError && <p className="mt-1 text-xs text-red-500">{deleteError}</p>}
                          </div>
                          <div className="flex items-center gap-2">
                            <Button size="xs" variant="outline" onClick={() => setDeleting(null)} disabled={deleteBusy}>
                              {t('common.cancel')}
                            </Button>
                            <Button
                              size="xs"
                              variant="destructive"
                              onClick={() => handleDelete(fn)}
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

      {(creating || editing !== null) && (
        <MaskFnDialog
          editing={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
          onSaved={() => mutate(swrKeys.maskFns)}
        />
      )}
    </div>
  );
}

// ---- Mask function dialog ---------------------------------------------------

function MaskFnDialog({
  editing,
  onClose,
  onSaved,
}: {
  editing: MaskFn | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const t = useTranslations('Policies');
  const KIND_LABEL: Record<MaskFnKind, string> = {
    FIXED: t('maskFns.kinds.FIXED'),
    LAST_N: t('maskFns.kinds.LAST_N'),
    FORMAT_PRESERVING: t('maskFns.kinds.FORMAT_PRESERVING'),
    NULL: t('maskFns.kinds.NULL'),
  };
  const [name, setName] = useState(editing?.name ?? '');
  const [kind, setKind] = useState<MaskFnKind>((editing?.kind as MaskFnKind) ?? 'FIXED');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid = name.trim().length > 0;

  const handleSave = async () => {
    if (!valid) return;
    setBusy(true);
    setError(null);
    const input: MaskFnInput = { name: name.trim(), kind };
    try {
      if (editing) {
        await updateMaskFn(editing.id, input);
        toast.success(t('maskFns.toastUpdated', { name: input.name }));
      } else {
        await createMaskFn(input);
        toast.success(t('maskFns.toastCreated', { name: input.name }));
      }
      onSaved();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('maskFns.saveFailed'));
    } finally {
      setBusy(false);
    }
  };

  const kindLabel = (v: string | null) => (v ? (KIND_LABEL[v as MaskFnKind] ?? v) : t('maskFns.selectKind'));

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{editing ? t('maskFns.dialogEditTitle', { name: editing.name }) : t('maskFns.add')}</DialogTitle>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        <div className="space-y-4 py-1">
          <div className="space-y-1.5">
            <Label htmlFor="mf-name">{t('common.name')}</Label>
            <Input
              id="mf-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="email-last-domain"
              autoFocus
              required
            />
          </div>

          <div className="space-y-1.5">
            <Label>{t('maskFns.colKind')}</Label>
            <Select value={kind} onValueChange={(v: string | null) => setKind((v as MaskFnKind) ?? 'FIXED')}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder={t('maskFns.selectKind')}>{(v: string | null) => kindLabel(v)}</SelectValue>
              </SelectTrigger>
              <SelectContent>
                {KINDS.map((k) => (
                  <SelectItem key={k} value={k}>
                    {KIND_LABEL[k]}
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
            {editing ? t('common.save') : t('maskFns.addShort')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
