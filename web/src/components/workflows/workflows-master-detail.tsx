'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { useTranslations } from 'next-intl'
import { ChevronDown, Inbox, Plus, ShieldCheck } from 'lucide-react'
import type { AccessRequest } from '@/lib/api/types'
import {
  type WorkflowTab,
  useWorkflowRequests,
} from '@/lib/workflow-requests'
import { ApprovalDetail } from '@/components/approvals/approval-detail'
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
} from '@/components/page-scaffold'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ActiveRoleGrants } from './active-role-grants'
import { QueryRequestComposer } from './query-request-composer'
import { RoleRequestComposer } from './role-request-composer'
import { RoleRequestDetail } from './role-request-detail'
import { WorkflowRequestList } from './workflow-request-list'

export type WorkflowComposeDraft =
  | { kind: 'ROLE' }
  | {
      kind: 'QUERY'
      sourceDecisionId: number | null
      sourceDecisionError?: string | null
    }

/** The scroll + centered padding every detail view but the query one (which owns its full height) uses. */
function DetailScroll({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto w-full max-w-5xl p-6">{children}</div>
    </div>
  )
}

function DetailPanel({
  selectedId,
  compose,
  auxiliary,
  lists,
  roleRequestsById,
  roleLookupLoading,
  roleLookupError,
  onCreated,
  onCancel,
}: {
  selectedId?: number | null
  compose?: WorkflowComposeDraft | null
  auxiliary?: 'ACTIVE_GRANTS' | null
  lists: ReturnType<typeof useWorkflowRequests>['lists']
  roleRequestsById: ReturnType<typeof useWorkflowRequests>['roleRequestsById']
  roleLookupLoading: boolean
  roleLookupError: unknown
  onCreated: (request: AccessRequest) => void
  onCancel: () => void
}) {
  const t = useTranslations('Workflows')
  const invalidSelectedId = selectedId != null && (!Number.isFinite(selectedId) || selectedId <= 0)
  const composeError = compose?.kind === 'QUERY' ? compose.sourceDecisionError : null

  if (invalidSelectedId) {
    return <DetailScroll><ErrorState error={t('masterDetail.invalidRequestId')} /></DetailScroll>
  }
  if (composeError) {
    return <DetailScroll><ErrorState error={composeError} /></DetailScroll>
  }
  if (auxiliary === 'ACTIVE_GRANTS') {
    return <DetailScroll><ActiveRoleGrants /></DetailScroll>
  }
  if (compose?.kind === 'ROLE') {
    return <DetailScroll><RoleRequestComposer onCreated={onCreated} onCancel={onCancel} /></DetailScroll>
  }
  if (compose?.kind === 'QUERY') {
    return (
      <DetailScroll>
        <QueryRequestComposer
          sourceDecisionId={compose.sourceDecisionId}
          onCreated={onCreated}
          onCancel={onCancel}
        />
      </DetailScroll>
    )
  }

  if (selectedId != null) {
    const selectedEntry = lists.all.find((entry) => entry.request.id === selectedId)
    const selectedRoleRequest = roleRequestsById.get(selectedId)
      ?? (selectedEntry?.request.kind === 'ROLE' ? selectedEntry.request : null)

    if (selectedRoleRequest) {
      return <DetailScroll><RoleRequestDetail request={selectedRoleRequest} /></DetailScroll>
    }
    if (selectedEntry?.request.kind === 'QUERY') {
      // Full height, no wrapper scroll: this one docks its results panel at the bottom and scrolls its
      // own details pane, the way the editor does.
      return (
        <div data-workflow-detail-kind="QUERY" className="flex min-h-0 flex-1 flex-col">
          <ApprovalDetail id={selectedId} />
        </div>
      )
    }
    if (roleLookupLoading) {
      return <DetailScroll><LoadingState label={t('masterDetail.lookingUpType')} /></DetailScroll>
    }
    if (roleLookupError) {
      return <DetailScroll><ErrorState error={roleLookupError} /></DetailScroll>
    }

    return (
      <div data-workflow-detail-kind="QUERY">
        <ApprovalDetail id={selectedId} />
      </div>
    )
  }

  return (
    <DetailScroll>
      <EmptyState
        icon={<Inbox className="size-9" />}
        title={t('masterDetail.selectRequestTitle')}
        hint={t('masterDetail.selectRequestHint')}
      />
    </DetailScroll>
  )
}

export function WorkflowsMasterDetail({
  selectedId,
  compose,
  auxiliary,
}: {
  selectedId?: number | null
  compose?: WorkflowComposeDraft | null
  auxiliary?: 'ACTIVE_GRANTS' | null
}) {
  const t = useTranslations('Workflows')
  const router = useRouter()
  const [tab, setTab] = useState<WorkflowTab>('all')
  const {
    lists,
    incomingCount,
    roleRequestsById,
    isLoading,
    error,
    roleLookupLoading,
    roleLookupError,
  } = useWorkflowRequests()
  const entries = lists[tab]
  const tabs: { value: WorkflowTab; label: string }[] = [
    { value: 'all', label: t('masterDetail.tabs.all') },
    { value: 'incoming', label: t('masterDetail.tabs.incoming') },
    { value: 'outgoing', label: t('masterDetail.tabs.outgoing') },
  ]
  const emptyCopy =
    tab === 'incoming'
      ? { title: t('masterDetail.empty.incomingTitle'), hint: t('masterDetail.empty.incomingHint') }
      : tab === 'outgoing'
        ? { title: t('masterDetail.empty.outgoingTitle'), hint: t('masterDetail.empty.outgoingHint') }
        : { title: t('masterDetail.empty.allTitle'), hint: t('masterDetail.empty.allHint') }

  const handleCreated = (request: AccessRequest) => {
    router.push(`/workflows/${request.id}`)
  }

  return (
    <div data-testid="workflows-master-detail" className="flex min-h-0 flex-1 flex-col">
      <PageHeader
        title={t('masterDetail.pageTitle')}
        subtitle={t('masterDetail.pageSubtitle')}
        className="shrink-0 py-4"
        actions={
          <>
            <Button size="sm" variant="outline" asChild>
              <Link href="/workflows/grants">
                <ShieldCheck className="size-3.5" />
                {t('masterDetail.activeGrants')}
              </Link>
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger
                render={
                  <Button size="sm">
                    <Plus className="size-3.5" />
                    {t('masterDetail.newRequest')}
                    <ChevronDown className="size-3.5" />
                  </Button>
                }
              />
              <DropdownMenuContent align="end" className="w-52">
                <DropdownMenuItem render={<Link href="/workflows/new?kind=role" />}>
                  {t('masterDetail.roleAccessRequest')}
                </DropdownMenuItem>
                <DropdownMenuItem render={<Link href="/workflows/new?kind=query" />}>
                  {t('masterDetail.queryApprovalRequest')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        }
      />

      <div className="flex min-h-0 flex-1">
        <div className="flex h-full w-80 shrink-0 min-h-0 flex-col border-r">
          <Tabs
            value={tab}
            onValueChange={(value) => setTab(value as WorkflowTab)}
            className="shrink-0 gap-0 border-b"
          >
            <TabsList variant="line" className="h-10 w-full justify-start gap-3 px-4">
              {tabs.map((item) => (
                <TabsTrigger key={item.value} value={item.value} className="flex-none px-1">
                  {item.label}
                  {item.value === 'incoming' && (
                    <span
                      data-testid="workflows-incoming-count"
                      className="bg-red-500 text-[10px] font-semibold leading-none text-white inline-flex h-4 min-w-4 items-center justify-center rounded-full px-1"
                    >
                      {incomingCount}
                    </span>
                  )}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>

          <div className="min-h-0 flex-1 overflow-y-auto">
            <WorkflowRequestList
              entries={(isLoading && lists.all.length === 0) || error ? [] : entries}
              selectedId={selectedId}
            />
            {isLoading && lists.all.length === 0 ? (
              <div className="px-4">
                <LoadingState label={t('masterDetail.loadingRequests')} />
              </div>
            ) : error ? (
              <div className="p-4">
                <ErrorState error={error} />
              </div>
            ) : entries.length === 0 ? (
              <EmptyState title={emptyCopy.title} hint={emptyCopy.hint} />
            ) : null}
          </div>
        </div>

        <div data-testid="workflow-detail-panel" className="flex min-h-0 min-w-0 flex-1 flex-col">
          <DetailPanel
            selectedId={selectedId}
            compose={compose}
            auxiliary={auxiliary}
            lists={lists}
            roleRequestsById={roleRequestsById}
            roleLookupLoading={roleLookupLoading}
            roleLookupError={roleLookupError}
            onCreated={handleCreated}
            onCancel={() => router.push('/workflows')}
          />
        </div>
      </div>
    </div>
  )
}
