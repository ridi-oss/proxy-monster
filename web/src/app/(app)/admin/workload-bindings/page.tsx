'use client';

import { Fragment, useState } from 'react';
import { useTranslations } from 'next-intl';
import { KeyRound, Loader2, MoreHorizontal, Pencil, Plus, Power, PowerOff, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { mutate } from 'swr';
import { deleteWorkloadBinding, updateWorkloadBinding } from '@/lib/api/client';
import { swrKeys, useWorkloadBindings, useWorkloadIssuers } from '@/lib/hooks';
import type { WorkloadBinding } from '@/lib/api/types';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, ErrorState, LoadingState, PageContainer, PageHeader } from '@/components/page-scaffold';
import { BindingFormDialog } from '@/components/workload-bindings/binding-form-dialog';

const COLUMNS = 9;

export default function WorkloadBindingsPage() {
  const t = useTranslations('WorkloadBindings');
  const { data: bindings, isLoading, error } = useWorkloadBindings();
  const { data: issuers } = useWorkloadIssuers();
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<WorkloadBinding | null>(null);
  const [deleting, setDeleting] = useState<WorkloadBinding | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const noIssuers = issuers != null && issuers.length === 0;
  const kindOf = (issuer: string) => issuers?.find((i) => i.name === issuer)?.kind;

  const openCreate = () => {
    setEditing(null);
    setFormOpen(true);
  };

  const openEdit = (binding: WorkloadBinding) => {
    setEditing(binding);
    setFormOpen(true);
  };

  const setEnabled = async (binding: WorkloadBinding, enabled: boolean) => {
    try {
      await updateWorkloadBinding(binding.id, {
        name: binding.name,
        description: binding.description ?? null,
        issuer: binding.issuer,
        subject: binding.subject,
        conditions: binding.conditions,
        principal: binding.principal,
        purposes: binding.purposes,
        mcpScopes: binding.mcpScopes,
        ttlSeconds: binding.ttlSeconds,
        enabled,
      });
      await mutate(swrKeys.workloadBindings);
      toast.success(t(enabled ? 'list.toastEnabled' : 'list.toastDisabled', { name: binding.name }));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('list.toggleFailed'));
    }
  };

  const confirmDelete = async (binding: WorkloadBinding) => {
    setDeleteBusy(true);
    setDeleteError(null);
    try {
      await deleteWorkloadBinding(binding.id);
      await mutate(swrKeys.workloadBindings);
      setDeleting(null);
      toast.success(t('list.toastDeleted', { name: binding.name }));
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : t('list.deleteFailed'));
    } finally {
      setDeleteBusy(false);
    }
  };

  const addButton = (
    <Button size="sm" onClick={openCreate} disabled={noIssuers}>
      <Plus className="size-3.5" />
      {t('list.addBinding')}
    </Button>
  );

  return (
    <>
      <PageHeader title={t('list.title')} subtitle={t('list.subtitle')} actions={addButton} />

      <PageContainer>
        {noIssuers && (
          <div className="mb-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm">
            {t('list.noIssuers')}
          </div>
        )}
        {isLoading && !bindings ? (
          <LoadingState label={t('list.loading')} />
        ) : error ? (
          <ErrorState error={error} />
        ) : !bindings || bindings.length === 0 ? (
          <EmptyState
            title={t('list.emptyTitle')}
            hint={t('list.emptyHint')}
            icon={<KeyRound className="size-8" />}
            action={addButton}
          />
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('list.colName')}</TableHead>
                  <TableHead>{t('list.colIssuer')}</TableHead>
                  <TableHead>{t('list.colSubject')}</TableHead>
                  <TableHead>{t('list.colConditions')}</TableHead>
                  <TableHead>{t('list.colPrincipal')}</TableHead>
                  <TableHead>{t('list.colPurposes')}</TableHead>
                  <TableHead>{t('list.colTtl')}</TableHead>
                  <TableHead>{t('list.colEnabled')}</TableHead>
                  <TableHead className="text-right">{t('list.colActions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {bindings.map((binding) => {
                  const kind = kindOf(binding.issuer);
                  const conditions = Object.entries(binding.conditions);
                  return (
                    <Fragment key={binding.id}>
                      <TableRow>
                        <TableCell>
                          <code className="font-mono text-sm font-semibold">{binding.name}</code>
                          {binding.description && (
                            <p className="text-muted-foreground mt-0.5 text-xs">{binding.description}</p>
                          )}
                        </TableCell>
                        <TableCell>
                          <span className="font-mono text-xs">{binding.issuer}</span>
                          {kind && (
                            <Badge variant="outline" className="ml-1.5 text-xs">
                              {t(`kind.${kind}`)}
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          <code className="block max-w-[280px] font-mono text-xs break-all">{binding.subject}</code>
                        </TableCell>
                        <TableCell>
                          {conditions.length === 0 ? (
                            <span className="text-muted-foreground">—</span>
                          ) : (
                            <div className="flex max-w-[260px] flex-col gap-0.5">
                              {conditions.map(([claim, values]) => (
                                <code key={claim} className="font-mono text-xs break-all">
                                  {claim}={values.join(',')}
                                </code>
                              ))}
                            </div>
                          )}
                        </TableCell>
                        <TableCell>
                          <code className="font-mono text-xs">{binding.principal}</code>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {binding.purposes.map((p) => (
                              <Badge key={p} variant="secondary" className="font-mono text-xs">
                                {p}
                              </Badge>
                            ))}
                          </div>
                          {binding.mcpScopes.length > 0 && (
                            <p className="text-muted-foreground mt-1 font-mono text-xs">
                              {t('list.scopes', { scopes: binding.mcpScopes.join(' ') })}
                            </p>
                          )}
                        </TableCell>
                        <TableCell className="text-xs">
                          {t('list.ttlSeconds', { seconds: binding.ttlSeconds })}
                        </TableCell>
                        <TableCell>
                          {binding.enabled ? (
                            <Badge variant="secondary">{t('list.statusEnabled')}</Badge>
                          ) : (
                            <span className="text-muted-foreground text-xs">{t('list.statusDisabled')}</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger
                              render={<Button variant="ghost" size="icon-xs" aria-label={t('list.moreActions')} />}
                            >
                              <MoreHorizontal className="size-3.5" />
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" side="bottom">
                              <DropdownMenuItem onClick={() => openEdit(binding)}>
                                <Pencil className="size-3.5" />
                                {t('list.edit')}
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => setEnabled(binding, !binding.enabled)}>
                                {binding.enabled ? <PowerOff className="size-3.5" /> : <Power className="size-3.5" />}
                                {binding.enabled ? t('list.disable') : t('list.enable')}
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                variant="destructive"
                                onClick={() => {
                                  setDeleteError(null);
                                  setDeleting((prev) => (prev?.id === binding.id ? null : binding));
                                }}
                              >
                                <Trash2 className="size-3.5" />
                                {t('list.delete')}
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                      {deleting?.id === binding.id && (
                        <TableRow className="bg-red-500/5">
                          <TableCell colSpan={COLUMNS}>
                            <div className="flex flex-wrap items-center justify-between gap-2 py-0.5">
                              <div>
                                <p className="text-sm font-medium text-red-500">
                                  {t.rich('list.deleteConfirm', {
                                    name: binding.name,
                                    code: (chunks) => <code className="font-mono">{chunks}</code>,
                                  })}
                                </p>
                                {deleteError && <p className="mt-1 text-xs text-red-500">{deleteError}</p>}
                              </div>
                              <div className="flex items-center gap-2">
                                <Button
                                  size="xs"
                                  variant="outline"
                                  onClick={() => setDeleting(null)}
                                  disabled={deleteBusy}
                                >
                                  {t('list.cancel')}
                                </Button>
                                <Button
                                  size="xs"
                                  variant="destructive"
                                  onClick={() => confirmDelete(binding)}
                                  disabled={deleteBusy}
                                >
                                  {deleteBusy ? <Loader2 className="size-3 animate-spin" /> : null}
                                  {t('list.delete')}
                                </Button>
                              </div>
                            </div>
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </PageContainer>

      <BindingFormDialog open={formOpen} onOpenChange={setFormOpen} editing={editing} issuers={issuers ?? []} />
    </>
  );
}
