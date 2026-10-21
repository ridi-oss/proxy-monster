'use client'

// /admin/users — local users plus their group memberships. Group-derived roles
// are resolved at query time by the control-plane.

import { Fragment, useState } from 'react'
import { useTranslations } from 'next-intl'
import { Loader2, MoreHorizontal, Pencil, Plus, Trash2, UserRoundCog, Users } from 'lucide-react'
import { toast } from 'sonner'
import { mutate } from 'swr'
import { deleteUser } from '@/lib/api/client'
import { swrKeys, useUsers } from '@/lib/hooks'
import type { AppUser } from '@/lib/api/types'
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
import { UserFormDialog } from '@/components/users/user-form-dialog'
import { UserGroupsDialog } from '@/components/users/user-groups-dialog'

export default function UsersPage() {
  const t = useTranslations('Users')
  const { data: users, isLoading, error } = useUsers()
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<AppUser | null>(null)
  const [managingGroups, setManagingGroups] = useState<AppUser | null>(null)
  const [deleting, setDeleting] = useState<AppUser | null>(null)
  const [deleteBusy, setDeleteBusy] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  const openCreate = () => {
    setEditing(null)
    setFormOpen(true)
  }

  const openEdit = (user: AppUser) => {
    setEditing(user)
    setFormOpen(true)
  }

  const confirmDelete = async (user: AppUser) => {
    setDeleteBusy(true)
    setDeleteError(null)
    try {
      await deleteUser(user.id)
      await mutate(swrKeys.users)
      await mutate(swrKeys.groups)
      for (const g of user.groups) await mutate(swrKeys.groupMembers(g.id))
      setDeleting(null)
      toast.success(t('list.toastDeleted', { principal: user.principal }))
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
            {t('list.addUser')}
          </Button>
        }
      />

      <PageContainer>
        {isLoading && !users ? (
          <LoadingState label={t('list.loading')} />
        ) : error ? (
          <ErrorState error={error} />
        ) : !users || users.length === 0 ? (
          <EmptyState
            title={t('list.emptyTitle')}
            hint={t('list.emptyHint')}
            icon={<Users className="size-8" />}
            action={
              <Button size="sm" onClick={openCreate}>
                <Plus className="size-3.5" />
                {t('list.addUser')}
              </Button>
            }
          />
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('list.colPrincipal')}</TableHead>
                  <TableHead>{t('list.colDisplayName')}</TableHead>
                  <TableHead>{t('list.colEmail')}</TableHead>
                  <TableHead>{t('list.colGroups')}</TableHead>
                  <TableHead>{t('list.colActive')}</TableHead>
                  <TableHead>{t('list.colSource')}</TableHead>
                  <TableHead className="text-right">{t('list.colActions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => (
                  <Fragment key={user.id}>
                    <TableRow>
                      <TableCell>
                        <code className="font-mono text-sm font-semibold">{user.principal}</code>
                      </TableCell>
                      <TableCell>{user.displayName || <span className="text-muted-foreground">—</span>}</TableCell>
                      <TableCell>
                        {user.email ? (
                          <span className="text-muted-foreground font-mono text-xs">{user.email}</span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {user.groups.length === 0 ? (
                          <span className="text-muted-foreground">—</span>
                        ) : (
                          <div className="flex max-w-[280px] flex-wrap gap-1">
                            {user.groups.map((g) => (
                              <Badge key={g.id} variant="outline" className="font-mono text-xs">
                                {g.name}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        {user.active ? (
                          <Badge variant="secondary">{t('list.active')}</Badge>
                        ) : (
                          <span className="text-muted-foreground text-xs">{t('list.inactive')}</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="font-mono text-xs">
                          {user.source}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger
                            render={<Button variant="ghost" size="icon-xs" aria-label={t('list.moreActions')} />}
                          >
                            <MoreHorizontal className="size-3.5" />
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" side="bottom">
                            <DropdownMenuItem onClick={() => openEdit(user)}>
                              <Pencil className="size-3.5" />
                              {t('list.edit')}
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setManagingGroups(user)}>
                              <UserRoundCog className="size-3.5" />
                              {t('list.manageGroups')}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              variant="destructive"
                              onClick={() => {
                                setDeleteError(null)
                                setDeleting((prev) => (prev?.id === user.id ? null : user))
                              }}
                            >
                              <Trash2 className="size-3.5" />
                              {t('list.delete')}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                    {deleting?.id === user.id && (
                      <TableRow className="bg-red-500/5">
                        <TableCell colSpan={7}>
                          <div className="flex flex-wrap items-center justify-between gap-2 py-0.5">
                            <div>
                              <p className="text-sm font-medium text-red-500">
                                {t.rich('list.deleteConfirm', {
                                  principal: user.principal,
                                  code: (chunks) => <code className="font-mono">{chunks}</code>,
                                })}
                              </p>
                              {deleteError && <p className="mt-1 text-xs text-red-500">{deleteError}</p>}
                            </div>
                            <div className="flex items-center gap-2">
                              <Button size="xs" variant="outline" onClick={() => setDeleting(null)} disabled={deleteBusy}>
                                {t('list.cancel')}
                              </Button>
                              <Button size="xs" variant="destructive" onClick={() => confirmDelete(user)} disabled={deleteBusy}>
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

      <UserFormDialog open={formOpen} onOpenChange={setFormOpen} editing={editing} />
      <UserGroupsDialog user={managingGroups} onClose={() => setManagingGroups(null)} />
    </>
  )
}
