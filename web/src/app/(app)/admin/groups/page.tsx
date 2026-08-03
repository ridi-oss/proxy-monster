'use client'

// /admin/groups — local groups, member counts, and mapped roles. Row click
// opens the detail page for membership and role management.

import { Fragment, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useTranslations } from 'next-intl'
import { Loader2, MoreHorizontal, Pencil, Plus, ShieldCheck, Trash2, Users } from 'lucide-react'
import { toast } from 'sonner'
import { mutate } from 'swr'
import { deleteGroup } from '@/lib/api/client'
import { swrKeys, useGroups } from '@/lib/hooks'
import type { AppGroup } from '@/lib/api/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageContainer,
  PageHeader,
} from '@/components/page-scaffold'
import { GroupFormDialog } from '@/components/groups/group-form-dialog'

export default function GroupsPage() {
  const t = useTranslations('Groups')
  const router = useRouter()
  const { data: groups, isLoading, error } = useGroups()
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<AppGroup | null>(null)
  const [deleting, setDeleting] = useState<AppGroup | null>(null)
  const [deleteBusy, setDeleteBusy] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  const openCreate = () => {
    setEditing(null)
    setFormOpen(true)
  }

  const openEdit = (group: AppGroup) => {
    setEditing(group)
    setFormOpen(true)
  }

  const confirmDelete = async (group: AppGroup) => {
    setDeleteBusy(true)
    setDeleteError(null)
    try {
      await deleteGroup(group.id)
      await mutate(swrKeys.groups)
      await mutate(swrKeys.users)
      await mutate(swrKeys.groupMembers(group.id))
      await mutate(swrKeys.groupRoles(group.id))
      setDeleting(null)
      toast.success(t('list.toastDeleted', { name: group.name }))
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : t('list.deleteFailed'))
    } finally {
      setDeleteBusy(false)
    }
  }

  return (
    <>
      <PageHeader
        title={t('list.title')}
        subtitle={t('list.subtitle')}
        actions={
          <Button size="sm" onClick={openCreate}>
            <Plus className="size-3.5" />
            {t('list.addGroup')}
          </Button>
        }
      />

      <PageContainer>
        {isLoading && !groups ? (
          <LoadingState label={t('list.loading')} />
        ) : error ? (
          <ErrorState error={error} />
        ) : !groups || groups.length === 0 ? (
          <EmptyState
            title={t('list.emptyTitle')}
            hint={t('list.emptyHint')}
            icon={<Users className="size-8" />}
            action={
              <Button size="sm" onClick={openCreate}>
                <Plus className="size-3.5" />
                {t('list.addGroup')}
              </Button>
            }
          />
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('list.colName')}</TableHead>
                  <TableHead>{t('list.colDescription')}</TableHead>
                  <TableHead>{t('list.colMembers')}</TableHead>
                  <TableHead>{t('list.colRoles')}</TableHead>
                  <TableHead>{t('list.colSource')}</TableHead>
                  <TableHead className="text-right">{t('list.colActions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {groups.map((group) => (
                  <Fragment key={group.id}>
                    <TableRow className="cursor-pointer" onClick={() => router.push(`/admin/groups/${group.id}`)}>
                      <TableCell>
                        <span className="font-mono text-sm font-semibold">{group.name}</span>
                      </TableCell>
                      <TableCell>
                        {group.description || <span className="text-muted-foreground">—</span>}
                      </TableCell>
                      <TableCell>
                        <span className="text-muted-foreground text-sm">{group.memberCount}</span>
                      </TableCell>
                      <TableCell>
                        {group.roles.length === 0 ? (
                          <span className="text-muted-foreground">—</span>
                        ) : (
                          <div className="flex max-w-[280px] flex-wrap gap-1">
                            {group.roles.map((r) => (
                              <Badge key={r.id} variant="outline" className="font-mono text-xs">
                                {r.name}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="font-mono text-xs">
                          {group.source}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                        <DropdownMenu>
                          <DropdownMenuTrigger
                            render={<Button variant="ghost" size="icon-xs" aria-label={t('list.moreActions')} />}
                          >
                            <MoreHorizontal className="size-3.5" />
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" side="bottom">
                            {/* The server rejects both on a SYSTEM group; disabling explains why
                                instead of failing the call. */}
                            <DropdownMenuItem
                              disabled={group.source === 'SYSTEM'}
                              onClick={() => openEdit(group)}
                            >
                              <Pencil className="size-3.5" />
                              {t('list.edit')}
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => router.push(`/admin/groups/${group.id}`)}>
                              <ShieldCheck className="size-3.5" />
                              {t('list.manageMembersRoles')}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              variant="destructive"
                              disabled={group.source === 'SYSTEM'}
                              onClick={() => {
                                setDeleteError(null)
                                setDeleting((prev) => (prev?.id === group.id ? null : group))
                              }}
                            >
                              <Trash2 className="size-3.5" />
                              {t('list.delete')}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                    {deleting?.id === group.id && (
                      <TableRow className="bg-red-500/5">
                        <TableCell colSpan={6}>
                          <div className="flex flex-wrap items-center justify-between gap-2 py-0.5">
                            <div>
                              <p className="text-sm font-medium text-red-500">
                                {t.rich('list.deleteConfirm', {
                                  name: group.name,
                                  code: (chunks) => <code className="font-mono">{chunks}</code>,
                                })}
                              </p>
                              {group.source === 'OIDC' && (
                                <p className="text-muted-foreground mt-1 text-xs">
                                  {t('detail.deleteOidcWarning')}
                                </p>
                              )}
                              {deleteError && <p className="mt-1 text-xs text-red-500">{deleteError}</p>}
                            </div>
                            <div className="flex items-center gap-2">
                              <Button size="xs" variant="outline" onClick={() => setDeleting(null)} disabled={deleteBusy}>
                                {t('list.cancel')}
                              </Button>
                              <Button size="xs" variant="destructive" onClick={() => confirmDelete(group)} disabled={deleteBusy}>
                                {deleteBusy ? <Loader2 className="size-3 animate-spin" /> : null}
                                {t('list.delete')}
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
      </PageContainer>

      <GroupFormDialog open={formOpen} onOpenChange={setFormOpen} editing={editing} />
    </>
  )
}
