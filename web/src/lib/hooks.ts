'use client'

// Typed SWR read hooks over the API client. SWR gives us caching, focus
// revalidation, and clean loading/error states for the polished feel. Writes
// go through the client functions directly; call `mutate(key)` after to refresh.

import useSWR, { type SWRConfiguration } from 'swr'
import { useAuth } from './auth'
import {
  getAccessGrants,
  getAccessRequests,
  getApproval,
  getApprovalInbox,
  getAuthConfig,
  getCatalog,
  getCedarPolicies,
  getCedarSchema,
  getDatasources,
  getDatasourcesLive,
  getAuditEvent,
  getAuditEvents,
  getGroupMembers,
  getGroupRoles,
  getGroups,
  getMaskFns,
  getMePermissions,
  getMyApprovals,
  getQueryHistory,
  getRoleAssignments,
  getRoles,
  getTableDetail,
  getTokens,
  getUsers,
} from './api/client'

const KEYS = {
  authConfig: 'auth-config',
  mePermissions: (principal: string) => ['me-permissions', principal] as const,
  datasources: 'datasources',
  datasourcesLive: 'datasources-live',
  catalog: (id: number) => ['catalog', id] as const,
  tableDetail: (id: number, schema: string, table: string) =>
    ['table-detail', id, schema, table] as const,
  auditEvents: (limit: number) => ['audit-events', limit] as const,
  auditEvent: (id: number) => ['audit-event', id] as const,
  approval: (id: number) => ['approval', id] as const,
  approvalInbox: 'approval-inbox',
  myApprovals: (status?: string) => ['my-approvals', status ?? null] as const,
  roles: 'roles',
  users: 'users',
  groups: 'groups',
  groupMembers: (id: number) => ['group-members', id] as const,
  groupRoles: (id: number) => ['group-roles', id] as const,
  maskFns: 'mask-fns',
  queryHistory: 'query-history',
  tokens: 'tokens',
  roleAssignments: 'role-assignments',
  cedarPolicies: 'cedar-policies',
  cedarSchema: 'cedar-schema',
  accessRequests: (status?: string) => ['access-requests', status ?? null] as const,
  accessGrants: (active?: boolean) => ['access-grants', active ?? null] as const,
}

export { KEYS as swrKeys }

export function useAuthConfig() {
  return useSWR(KEYS.authConfig, getAuthConfig)
}

export function useMePermissions() {
  const { identity, status } = useAuth()
  const key = status === 'authenticated' && identity
    ? KEYS.mePermissions(identity.principal)
    : null
  return useSWR(key, getMePermissions)
}

export function useDatasources(connectableOnly = false) {
  return useSWR(
    connectableOnly ? `${KEYS.datasources}:connectable` : KEYS.datasources,
    () => getDatasources(connectableOnly),
  )
}

/** Names of datasources with a proxy CURRENTLY attached — polled, since a proxy can disconnect
 *  between renders without the client otherwise finding out. */
export function useDatasourcesLive() {
  return useSWR(KEYS.datasourcesLive, getDatasourcesLive, { refreshInterval: 10_000 })
}

export function useCatalog(id: number | null) {
  return useSWR(id == null ? null : KEYS.catalog(id), () => getCatalog(id!))
}

export function useTableDetail(
  datasourceId: number | null,
  schema: string | null,
  table: string | null,
) {
  const key = datasourceId == null || schema == null || table == null
    ? null
    : KEYS.tableDetail(datasourceId, schema, table)
  return useSWR(key, () => getTableDetail(datasourceId!, schema!, table!), {
    revalidateOnMount: true,
    revalidateOnFocus: true,
    dedupingInterval: 0,
  })
}

export function useAuditEvents(limit = 100, opts?: SWRConfiguration) {
  return useSWR(KEYS.auditEvents(limit), () => getAuditEvents(limit), opts)
}

export function useAuditEvent(id: number | null) {
  return useSWR(id == null ? null : KEYS.auditEvent(id), () => getAuditEvent(id!))
}

export function useApproval(id: number | null, opts?: SWRConfiguration) {
  return useSWR(id == null ? null : KEYS.approval(id), () => getApproval(id!), opts)
}

export function useApprovalInbox(opts?: SWRConfiguration) {
  return useSWR(KEYS.approvalInbox, getApprovalInbox, opts)
}

export function useMyApprovals(status?: string, opts?: SWRConfiguration) {
  return useSWR(KEYS.myApprovals(status), () => getMyApprovals(status), opts)
}

export function useRoles() {
  return useSWR(KEYS.roles, getRoles)
}

export function useUsers() {
  return useSWR(KEYS.users, getUsers)
}

export function useGroups() {
  return useSWR(KEYS.groups, getGroups)
}

export function useGroupMembers(id: number | null) {
  return useSWR(id == null ? null : KEYS.groupMembers(id), () => getGroupMembers(id!))
}

export function useGroupRoles(id: number | null) {
  return useSWR(id == null ? null : KEYS.groupRoles(id), () => getGroupRoles(id!))
}

export function useMaskFns() {
  return useSWR(KEYS.maskFns, getMaskFns)
}

export function useQueryHistory() {
  return useSWR(KEYS.queryHistory, () => getQueryHistory(50))
}

export function useTokens(opts?: SWRConfiguration) {
  return useSWR(KEYS.tokens, getTokens, opts)
}

export function useRoleAssignments() {
  return useSWR(KEYS.roleAssignments, () => getRoleAssignments())
}

export function useCedarPolicies() {
  return useSWR(KEYS.cedarPolicies, getCedarPolicies)
}

/** The authz Cedar schema text, for the policy editor's schema-aware lint/completion. Carries the
 *  context.tag actions derived from stored policies, so it changes when policies do. */
export function useCedarSchema() {
  return useSWR(KEYS.cedarSchema, getCedarSchema, { revalidateOnFocus: false })
}

export function useAccessRequests(status?: string, opts?: SWRConfiguration) {
  return useSWR(KEYS.accessRequests(status), () => getAccessRequests(status), opts)
}

export function useAccessGrants(active?: boolean, opts?: SWRConfiguration) {
  return useSWR(KEYS.accessGrants(active), () => getAccessGrants({ active }), opts)
}
