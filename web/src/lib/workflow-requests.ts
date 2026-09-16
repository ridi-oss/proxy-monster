'use client'

import { useMemo } from 'react'
import { useAuth } from '@/lib/auth'
import type { AccessRequest } from '@/lib/api/types'
import { useAccessRequests, useApprovalInbox, useMyApprovals } from '@/lib/hooks'

export type WorkflowTab = 'all' | 'incoming' | 'outgoing'

export interface WorkflowRequestEntry {
  request: AccessRequest
  incoming: boolean
  outgoing: boolean
}

const POLL_OPTIONS = { refreshInterval: 15_000 }

function firstError(...errors: unknown[]): unknown {
  return errors.find((error) => error != null)
}

function newestFirst(a: AccessRequest, b: AccessRequest): number {
  const createdAtDifference = Date.parse(b.createdAt) - Date.parse(a.createdAt)
  return createdAtDifference || b.id - a.id
}

function sortedRequests(requests: AccessRequest[]): AccessRequest[] {
  return [...requests].sort(newestFirst)
}

function sortedEntries(entries: WorkflowRequestEntry[]): WorkflowRequestEntry[] {
  return [...entries].sort((a, b) => newestFirst(a.request, b.request))
}

export function useWorkflowIncomingRequests(): {
  requests: AccessRequest[]
  count: number
  isLoading: boolean
  error: unknown
} {
  // ROLE requests intentionally remain unscoped: canApprove is only the admin bit,
  // while each ROLE decision endpoint authorizes the acting principal per request.
  const roleRequests = useAccessRequests('PENDING', POLL_OPTIONS)
  const queryRequests = useApprovalInbox(POLL_OPTIONS)

  const requests = useMemo(() => {
    const byId = new Map<number, AccessRequest>()
    for (const request of roleRequests.data ?? []) {
      if (request.kind === 'ROLE') byId.set(request.id, request)
    }
    for (const request of queryRequests.data ?? []) {
      if (request.kind === 'QUERY') byId.set(request.id, request)
    }
    return sortedRequests([...byId.values()])
  }, [queryRequests.data, roleRequests.data])

  return {
    requests,
    count: requests.length,
    isLoading: roleRequests.isLoading || queryRequests.isLoading,
    error: firstError(roleRequests.error, queryRequests.error),
  }
}

export function useWorkflowRequests(): {
  lists: Record<WorkflowTab, WorkflowRequestEntry[]>
  incomingCount: number
  roleRequestsById: ReadonlyMap<number, AccessRequest>
  isLoading: boolean
  error: unknown
  roleLookupLoading: boolean
  roleLookupError: unknown
} {
  const { identity } = useAuth()
  const incoming = useWorkflowIncomingRequests()
  const roleLookup = useAccessRequests(undefined, POLL_OPTIONS)
  const queryOutgoing = useMyApprovals(undefined, POLL_OPTIONS)

  const outgoingRequests = useMemo(() => {
    const principal = identity?.principal
    return [
      ...(roleLookup.data ?? []).filter(
        (request) => request.kind === 'ROLE' && request.principal === principal,
      ),
      ...(queryOutgoing.data ?? []).filter((request) => request.kind === 'QUERY'),
    ]
  }, [identity?.principal, queryOutgoing.data, roleLookup.data])

  const lists = useMemo<Record<WorkflowTab, WorkflowRequestEntry[]>>(() => {
    const byId = new Map<number, WorkflowRequestEntry>()

    for (const request of incoming.requests) {
      byId.set(request.id, { request, incoming: true, outgoing: false })
    }
    for (const request of outgoingRequests) {
      const existing = byId.get(request.id)
      byId.set(request.id, existing
        ? { ...existing, outgoing: true }
        : { request, incoming: false, outgoing: true })
    }

    const all = sortedEntries([...byId.values()])
    return {
      all,
      incoming: all.filter((entry) => entry.incoming),
      outgoing: all.filter((entry) => entry.outgoing),
    }
  }, [incoming.requests, outgoingRequests])

  const roleRequestsById = useMemo<ReadonlyMap<number, AccessRequest>>(
    () => new Map(
      (roleLookup.data ?? [])
        .filter((request) => request.kind === 'ROLE')
        .map((request) => [request.id, request]),
    ),
    [roleLookup.data],
  )

  return {
    lists,
    incomingCount: incoming.count,
    roleRequestsById,
    isLoading: incoming.isLoading || roleLookup.isLoading || queryOutgoing.isLoading,
    error: firstError(incoming.error, roleLookup.error, queryOutgoing.error),
    roleLookupLoading: roleLookup.isLoading,
    roleLookupError: roleLookup.error,
  }
}
