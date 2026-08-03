'use client'

// Detail surface for one group: members and mapped roles. Mapped roles are
// resolved into effectiveRoles at query time (most-permissive-wins downstream).

import { Fragment, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useTranslations } from 'next-intl'
import { ArrowLeft, Loader2, Pencil, Plus, ShieldCheck, Trash2, Users } from 'lucide-react'
import { toast } from 'sonner'
import { mutate } from 'swr'
import {
  addGroupMember,
  addGroupRole,
  deleteGroup,
  removeGroupMember,
  removeGroupRole,
} from '@/lib/api/client'
import {
  swrKeys,
  useGroupMembers,
  useGroupRoles,
  useGroups,
  useRoles,
  useUsers,
} from '@/lib/hooks'
import type { AppUser, GroupMember, GroupRoleMapping, Role } from '@/lib/api/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { EmptyState, ErrorState, LoadingState } from '@/components/page-scaffold'
import { GroupFormDialog } from '@/components/groups/group-form-dialog'

export function GroupDetail({ id }: { id: number }) {
  const t = useTranslations('Groups')
  const router = useRouter()
  const { data: groups } = useGroups()
  const { data: users } = useUsers()
  const { data: roles } = useRoles()
  const { data: members, isLoading: membersLoading, error: membersError } = useGroupMembers(id)
  const { data: groupRoles, isLoading: rolesLoading, error: rolesError } = useGroupRoles(id)
  const group = groups?.find((g) => g.id === id)
  const groupName = group?.name ?? t('detail.groupFallback', { id })

  const [addingMember, setAddingMember] = useState(false)
  const [mappingRole, setMappingRole] = useState(false)
  const [removingMember, setRemovingMember] = useState<GroupMember | null>(null)
  const [removingRole, setRemovingRole] = useState<GroupRoleMapping | null>(null)
  const [removeMemberBusy, setRemoveMemberBusy] = useState(false)
  const [removeRoleBusy, setRemoveRoleBusy] = useState(false)
  const [removeMemberError, setRemoveMemberError] = useState<string | null>(null)
  const [removeRoleError, setRemoveRoleError] = useState<string | null>(null)
  const [renaming, setRenaming] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [deleteBusy, setDeleteBusy] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  // The server rejects both on a SYSTEM group; disabling here explains why instead of failing the call.
  const immutable = group?.source === 'SYSTEM'

  const handleDelete = async () => {
    if (!group) return
    setDeleteBusy(true)
    setDeleteError(null)
    try {
      await deleteGroup(group.id)
      await mutate(swrKeys.groups)
      await mutate(swrKeys.users)
      await mutate(swrKeys.groupMembers(group.id))
      await mutate(swrKeys.groupRoles(group.id))
      toast.success(t('list.toastDeleted', { name: group.name }))
      router.push('/admin/groups')
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : t('list.deleteFailed'))
      setDeleteBusy(false)
    }
  }

  const handleRemoveMember = async (member: GroupMember) => {
    setRemoveMemberBusy(true)
    setRemoveMemberError(null)
    try {
      await removeGroupMember(id, member.userId)
      await mutate(swrKeys.groupMembers(id))
      await mutate(swrKeys.users)
      await mutate(swrKeys.groups)
      setRemovingMember(null)
      toast.success(t('detail.toastMemberRemoved', { principal: member.principal, group: groupName }))
    } catch (err) {
      setRemoveMemberError(err instanceof Error ? err.message : t('detail.removeMemberFailed'))
    } finally {
      setRemoveMemberBusy(false)
    }
  }

  const handleRemoveRole = async (role: GroupRoleMapping) => {
    setRemoveRoleBusy(true)
    setRemoveRoleError(null)
    try {
      await removeGroupRole(id, role.roleId)
      await mutate(swrKeys.groupRoles(id))
      await mutate(swrKeys.groups)
      setRemovingRole(null)
      toast.success(t('detail.toastRoleRemoved', { roleName: role.roleName, group: groupName }))
    } catch (err) {
      setRemoveRoleError(err instanceof Error ? err.message : t('detail.removeRoleFailed'))
    } finally {
      setRemoveRoleBusy(false)
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b px-6 py-4">
        <Link href="/admin/groups" className="text-muted-foreground hover:text-foreground">
          <ArrowLeft className="size-4" />
        </Link>
        <Users className="text-muted-foreground size-4" />
        <h1 className="font-mono text-base font-semibold">{groupName}</h1>
        {group?.description && (
          <span className="text-muted-foreground text-sm">{group.description}</span>
        )}
        {group && (
          <>
            <Badge variant="outline" className="ml-auto font-mono text-xs">
              {group.source}
            </Badge>
            <div className="flex items-center gap-2" title={immutable ? t('detail.systemImmutable') : undefined}>
              <Button size="xs" variant="outline" disabled={immutable} onClick={() => setRenaming(true)}>
                <Pencil className="size-3" />
                {t('detail.rename')}
              </Button>
              <Button
                size="xs"
                variant="outline"
                disabled={immutable}
                onClick={() => {
                  setDeleteError(null)
                  setDeleting((prev) => !prev)
                }}
              >
                <Trash2 className="size-3" />
                {t('detail.deleteGroup')}
              </Button>
            </div>
          </>
        )}
      </div>

      {group && deleting && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b bg-red-500/5 px-6 py-3">
          <div>
            <p className="text-sm font-medium text-red-500">
              {t.rich('detail.deleteConfirm', {
                name: group.name,
                code: (chunks) => <code className="font-mono">{chunks}</code>,
              })}
            </p>
            {group.source === 'OIDC' && (
              <p className="text-muted-foreground mt-1 text-xs">{t('detail.deleteOidcWarning')}</p>
            )}
            {deleteError && <p className="mt-1 text-xs text-red-500">{deleteError}</p>}
          </div>
          <div className="flex items-center gap-2">
            <Button size="xs" variant="outline" onClick={() => setDeleting(false)} disabled={deleteBusy}>
              {t('list.cancel')}
            </Button>
            <Button size="xs" variant="destructive" onClick={handleDelete} disabled={deleteBusy}>
              {deleteBusy ? <Loader2 className="size-3 animate-spin" /> : null}
              {t('detail.deleteGroup')}
            </Button>
          </div>
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-6xl space-y-6 px-6 py-6">
          <p className="text-muted-foreground text-sm">{t('detail.intro')}</p>

          <section className="space-y-3">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold">{t('detail.membersHeading')}</h2>
                <p className="text-muted-foreground text-xs">{t('detail.membersSubtitle')}</p>
              </div>
              <Button size="sm" onClick={() => setAddingMember(true)}>
                <Plus className="size-3.5" />
                {t('detail.addMember')}
              </Button>
            </div>

            {membersLoading && !members ? (
              <LoadingState label={t('detail.membersLoading')} />
            ) : membersError ? (
              <ErrorState error={membersError} />
            ) : !members || members.length === 0 ? (
              <EmptyState
                title={t('detail.membersEmptyTitle')}
                hint={t('detail.membersEmptyHint')}
                icon={<Users className="size-8" />}
                action={
                  <Button size="sm" onClick={() => setAddingMember(true)}>
                    <Plus className="size-3.5" />
                    {t('detail.addMember')}
                  </Button>
                }
              />
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('detail.colPrincipal')}</TableHead>
                      <TableHead>{t('detail.colDisplayName')}</TableHead>
                      <TableHead className="w-[80px] text-right">{t('detail.colActions')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {members.map((member) => (
                      <Fragment key={member.userId}>
                        <TableRow>
                          <TableCell>
                            <code className="font-mono text-sm">{member.principal}</code>
                          </TableCell>
                          <TableCell>
                            {member.displayName || <span className="text-muted-foreground">—</span>}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              size="icon-xs"
                              variant="ghost"
                              className="text-destructive hover:text-destructive"
                              onClick={() => {
                                setRemoveMemberError(null)
                                setRemovingMember((prev) => (prev?.userId === member.userId ? null : member))
                              }}
                              aria-label={t('detail.removeMember')}
                            >
                              <Trash2 className="size-3.5" />
                            </Button>
                          </TableCell>
                        </TableRow>
                        {removingMember?.userId === member.userId && (
                          <TableRow className="bg-red-500/5">
                            <TableCell colSpan={3}>
                              <div className="flex flex-wrap items-center justify-between gap-2 py-0.5">
                                <div>
                                  <p className="text-sm font-medium text-red-500">
                                    {t.rich('detail.removeMemberConfirm', {
                                      principal: member.principal,
                                      code: (chunks) => <code className="font-mono">{chunks}</code>,
                                    })}
                                  </p>
                                  {removeMemberError && <p className="mt-1 text-xs text-red-500">{removeMemberError}</p>}
                                </div>
                                <div className="flex items-center gap-2">
                                  <Button size="xs" variant="outline" onClick={() => setRemovingMember(null)} disabled={removeMemberBusy}>
                                    {t('detail.cancel')}
                                  </Button>
                                  <Button size="xs" variant="destructive" onClick={() => handleRemoveMember(member)} disabled={removeMemberBusy}>
                                    {removeMemberBusy ? <Loader2 className="size-3 animate-spin" /> : null}
                                    {t('detail.remove')}
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
          </section>

          <section className="space-y-3">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold">{t('detail.rolesHeading')}</h2>
                <p className="text-muted-foreground text-xs">{t('detail.rolesSubtitle')}</p>
              </div>
              <Button size="sm" onClick={() => setMappingRole(true)}>
                <Plus className="size-3.5" />
                {t('detail.mapRole')}
              </Button>
            </div>

            {rolesLoading && !groupRoles ? (
              <LoadingState label={t('detail.rolesLoading')} />
            ) : rolesError ? (
              <ErrorState error={rolesError} />
            ) : !groupRoles || groupRoles.length === 0 ? (
              <EmptyState
                title={t('detail.rolesEmptyTitle')}
                hint={t('detail.rolesEmptyHint')}
                icon={<ShieldCheck className="size-8" />}
                action={
                  <Button size="sm" onClick={() => setMappingRole(true)}>
                    <Plus className="size-3.5" />
                    {t('detail.mapRole')}
                  </Button>
                }
              />
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('detail.colRole')}</TableHead>
                      <TableHead className="w-[80px] text-right">{t('detail.colActions')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {groupRoles.map((role) => (
                      <Fragment key={role.roleId}>
                        <TableRow>
                          <TableCell>
                            <Badge variant="outline" className="font-mono text-xs">
                              {role.roleName}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              size="icon-xs"
                              variant="ghost"
                              className="text-destructive hover:text-destructive"
                              onClick={() => {
                                setRemoveRoleError(null)
                                setRemovingRole((prev) => (prev?.roleId === role.roleId ? null : role))
                              }}
                              aria-label={t('detail.removeRole')}
                            >
                              <Trash2 className="size-3.5" />
                            </Button>
                          </TableCell>
                        </TableRow>
                        {removingRole?.roleId === role.roleId && (
                          <TableRow className="bg-red-500/5">
                            <TableCell colSpan={2}>
                              <div className="flex flex-wrap items-center justify-between gap-2 py-0.5">
                                <div>
                                  <p className="text-sm font-medium text-red-500">
                                    {t.rich('detail.removeRoleConfirm', {
                                      roleName: role.roleName,
                                      code: (chunks) => <code className="font-mono">{chunks}</code>,
                                    })}
                                  </p>
                                  {removeRoleError && <p className="mt-1 text-xs text-red-500">{removeRoleError}</p>}
                                </div>
                                <div className="flex items-center gap-2">
                                  <Button size="xs" variant="outline" onClick={() => setRemovingRole(null)} disabled={removeRoleBusy}>
                                    {t('detail.cancel')}
                                  </Button>
                                  <Button size="xs" variant="destructive" onClick={() => handleRemoveRole(role)} disabled={removeRoleBusy}>
                                    {removeRoleBusy ? <Loader2 className="size-3 animate-spin" /> : null}
                                    {t('detail.remove')}
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
          </section>
        </div>
      </div>

      {addingMember && (
        <AddMemberDialog
          groupId={id}
          groupName={groupName}
          users={users ?? []}
          members={members ?? []}
          onClose={() => setAddingMember(false)}
        />
      )}
      {mappingRole && (
        <MapRoleDialog
          groupId={id}
          groupName={groupName}
          roles={roles ?? []}
          groupRoles={groupRoles ?? []}
          onClose={() => setMappingRole(false)}
        />
      )}
      <GroupFormDialog open={renaming} onOpenChange={setRenaming} editing={group ?? null} />
    </div>
  )
}

function AddMemberDialog({
  groupId,
  groupName,
  users,
  members,
  onClose,
}: {
  groupId: number
  groupName: string
  users: AppUser[]
  members: GroupMember[]
  onClose: () => void
}) {
  const t = useTranslations('Groups')
  const memberIds = new Set(members.map((m) => m.userId))
  const available = users.filter((u) => !memberIds.has(u.id))
  const [userId, setUserId] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const selected = userId ? available.find((u) => String(u.id) === userId) : null

  const userLabel = (v: string | null) => {
    if (!v) return t('addMember.selectUser')
    const u = available.find((candidate) => String(candidate.id) === v)
    return u ? u.principal : t('addMember.selectUser')
  }

  const handleAdd = async () => {
    if (!selected) return
    setBusy(true)
    setError(null)
    try {
      await addGroupMember(groupId, selected.id)
      await mutate(swrKeys.groupMembers(groupId))
      await mutate(swrKeys.users)
      await mutate(swrKeys.groups)
      toast.success(t('addMember.toastAdded', { principal: selected.principal, group: groupName }))
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('addMember.addFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('addMember.title')}</DialogTitle>
          <DialogDescription>{t('addMember.description', { group: groupName })}</DialogDescription>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        <div className="space-y-2 py-1">
          <Label>{t('addMember.labelUser')}</Label>
          <Select value={userId} onValueChange={(v: string | null) => setUserId(v)}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder={t('addMember.selectUser')}>{(v: string | null) => userLabel(v)}</SelectValue>
            </SelectTrigger>
            <SelectContent>
              {available.map((u) => (
                <SelectItem key={u.id} value={String(u.id)}>
                  {u.principal}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {available.length === 0 && <p className="text-muted-foreground text-xs">{t('addMember.noUsers')}</p>}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('addMember.cancel')}
          </Button>
          <Button onClick={handleAdd} disabled={!selected || busy}>
            {busy ? <Loader2 className="size-3.5 animate-spin" /> : null}
            {t('addMember.submit')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function MapRoleDialog({
  groupId,
  groupName,
  roles,
  groupRoles,
  onClose,
}: {
  groupId: number
  groupName: string
  roles: Role[]
  groupRoles: GroupRoleMapping[]
  onClose: () => void
}) {
  const t = useTranslations('Groups')
  const mappedIds = new Set(groupRoles.map((r) => r.roleId))
  const available = roles.filter((r) => !mappedIds.has(r.id))
  const [roleId, setRoleId] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const selected = roleId ? available.find((r) => String(r.id) === roleId) : null

  const roleLabel = (v: string | null) => {
    if (!v) return t('mapRole.selectRole')
    return available.find((r) => String(r.id) === v)?.name ?? t('mapRole.selectRole')
  }

  const handleMap = async () => {
    if (!selected) return
    setBusy(true)
    setError(null)
    try {
      await addGroupRole(groupId, selected.id)
      await mutate(swrKeys.groupRoles(groupId))
      await mutate(swrKeys.groups)
      toast.success(t('mapRole.toastMapped', { roleName: selected.name, group: groupName }))
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('mapRole.mapFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('mapRole.title')}</DialogTitle>
          <DialogDescription>{t('mapRole.description', { group: groupName })}</DialogDescription>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        <div className="space-y-2 py-1">
          <Label>{t('mapRole.labelRole')}</Label>
          <Select value={roleId} onValueChange={(v: string | null) => setRoleId(v)}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder={t('mapRole.selectRole')}>{(v: string | null) => roleLabel(v)}</SelectValue>
            </SelectTrigger>
            <SelectContent>
              {available.map((r) => (
                <SelectItem key={r.id} value={String(r.id)}>
                  {r.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {available.length === 0 && <p className="text-muted-foreground text-xs">{t('mapRole.noRoles')}</p>}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('mapRole.cancel')}
          </Button>
          <Button onClick={handleMap} disabled={!selected || busy}>
            {busy ? <Loader2 className="size-3.5 animate-spin" /> : null}
            {t('mapRole.submit')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
