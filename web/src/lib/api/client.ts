// Thin fetch wrapper. All calls send the session cookie (credentials: include)
// so the control-plane can authenticate via its httpOnly session cookie.
//
// API base is NEXT_PUBLIC_API_URL (default ""), which means same-origin — Next's
// rewrites (next.config.ts) forward /api and /auth to the control-plane on :41390.

import { translateApiError } from '@/lib/i18n/errors'
import type {
  AccessGrant,
  AccessRequest,
  AccessRequestInput,
  ApprovalDetail,
  AppGroup,
  AppGroupInput,
  AppUser,
  AppUserInput,
  AuthConfig,
  CatalogColumn,
  CedarPolicy,
  CedarPolicyInput,
  Classification,
  ClassificationDelete,
  ClassificationInput,
  CreateApprovalInput,
  CreateApprovalResponse,
  CreateTokenInput,
  DiscoverRolesRequest,
  DiscoverRolesResponse,
  ExecuteApprovalResponse,
  QueryResultView,
  Datasource,
  DatasourceInput,
  AuditEvent,
  GroupMember,
  GroupRoleMapping,
  Identity,
  IssuedToken,
  EditorResultView,
  EditorSubmitResponse,
  EditorTaskStatus,
  MaskFn,
  MaskFnInput,
  MePermissions,
  QueryHistoryEntry,
  QueryRequest,
  QueryResponse,
  RefreshResult,
  Role,
  RoleAssignment,
  RoleAssignmentInput,
  RoleInput,
  SessionStatus,
  TableDetail,
  TestResult,
  WireTokenInfo,
} from './types'

/** API base; "" means same-origin so requests go through Next's rewrites. */
export const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? ''
const BASE = API_BASE

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

/**
 * Raised for any non-2xx response; `status` lets callers branch on 401, etc. `message` is already
 * the fully localized, param-interpolated string (docs/l10n.md) — computed once here from the
 * server's `{code, params}` body, so every existing `err.message`/`toast.error(err.message)` call
 * site across the app renders correctly localized text with no changes of its own. `code`/`params`
 * are exposed too, for the rare caller that wants to branch on the error kind itself.
 */
export class ApiError extends Error {
  readonly status: number
  readonly code?: string
  readonly params?: Record<string, string>
  readonly reason?: string
  constructor(
    status: number,
    message: string,
    code?: string,
    params?: Record<string, string>,
    reason?: string,
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.params = params
    this.reason = reason
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  })
  if (!res.ok) {
    const bodyText = await res.text().catch(() => '')
    const parsed = bodyText ? safeJsonParse(bodyText) : null
    if (parsed && typeof parsed === 'object' && typeof (parsed as { code?: unknown }).code === 'string') {
      const { code, params } = parsed as { code: string; params?: Record<string, string> }
      throw new ApiError(res.status, translateApiError(code, params ?? {}), code, params)
    }
    if (parsed && typeof parsed === 'object' && typeof (parsed as { reason?: unknown }).reason === 'string') {
      throw new ApiError(
        res.status,
        bodyText || res.statusText,
        undefined,
        undefined,
        (parsed as { reason: string }).reason,
      )
    }
    throw new ApiError(res.status, bodyText || res.statusText)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

/** GET /auth/config — which login methods this control-plane offers (OIDC/SSO / debug). */
export function getAuthConfig(): Promise<AuthConfig> {
  return request<AuthConfig>('/auth/config')
}

/** GET /auth/me — resolves the current principal, or throws ApiError(401) if unauthenticated. */
export function getMe(): Promise<Identity> {
  return request<Identity>('/auth/me')
}

/** GET /auth/session/status — observes authoritative session deadlines without extending idle activity. */
export function getSessionStatus(): Promise<SessionStatus> {
  return request<SessionStatus>('/auth/session/status')
}

/** POST /auth/session/heartbeat — records visible activity and returns authoritative session deadlines. */
export function touchSession(): Promise<SessionStatus> {
  return request<SessionStatus>('/auth/session/heartbeat', { method: 'POST' })
}

/** GET /api/me/permissions — resolves coarse Cedar-backed capabilities for the current principal. */
export function getMePermissions(): Promise<MePermissions> {
  return request<MePermissions>('/api/me/permissions')
}

/**
 * POST /auth/debug — dev-only login bypass; sets the session cookie. `requesterIp` simulates the source
 * address the session's decisions authorize under, so a network-conditioned policy can be exercised from a
 * dev box where every request arrives from loopback.
 */
export function debugLogin(
  principal: string,
  roles: string[],
  requesterIp?: string,
): Promise<Identity> {
  return request<Identity>('/auth/debug', {
    method: 'POST',
    body: JSON.stringify({ principal, roles, requesterIp: requesterIp || null }),
  })
}

/** POST /auth/logout — conditionally ends a specific session, or unconditionally ends the current one. */
export function logout(sessionId?: number): Promise<{ ended: boolean }> {
  return request<{ ended: boolean }>('/auth/logout', {
    method: 'POST',
    body: JSON.stringify(sessionId === undefined ? {} : { sessionId }),
  })
}

/** GET /api/audit?limit=N — newest-first audit events. */
export function getAuditEvents(limit = 100): Promise<AuditEvent[]> {
  return request<AuditEvent[]>(`/api/audit?limit=${limit}`)
}

export function getAuditEvent(id: number): Promise<AuditEvent> {
  return request<AuditEvent>(`/api/audit/${id}`)
}

// ---- Datasources -----------------------------------------------------------

export function getDatasources(connectable = false): Promise<Datasource[]> {
  return request<Datasource[]>(`/api/datasources${connectable ? '?connectable=true' : ''}`)
}

/** GET /api/datasources/live — names of datasources with a proxy CURRENTLY attached (an open gRPC
 *  Events stream), not just "seen at some point" (`lastSeenAt`). */
export function getDatasourcesLive(): Promise<string[]> {
  return request<string[]>('/api/datasources/live')
}

export function createDatasource(input: DatasourceInput): Promise<Datasource> {
  return request<Datasource>('/api/datasources', {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

export function updateDatasource(id: number, input: DatasourceInput): Promise<Datasource> {
  return request<Datasource>(`/api/datasources/${id}`, {
    method: 'PUT',
    body: JSON.stringify(input),
  })
}

export function deleteDatasource(id: number): Promise<void> {
  return request<void>(`/api/datasources/${id}`, { method: 'DELETE' })
}

export function testDatasource(id: number): Promise<TestResult> {
  return request<TestResult>(`/api/datasources/${id}/test`, { method: 'POST' })
}

/** POST /api/datasources/{id}/refresh — nudge any connected proxy stream(s) to re-introspect and push a fresh catalog. */
export function refreshDatasource(id: number): Promise<RefreshResult> {
  return request<RefreshResult>(`/api/datasources/${id}/refresh`, { method: 'POST' })
}

// ---- Catalog + classification ----------------------------------------------

export function getCatalog(datasourceId: number): Promise<CatalogColumn[]> {
  return request<CatalogColumn[]>(`/api/datasources/${datasourceId}/catalog`)
}

export function getTableDetail(
  datasourceId: number,
  schema: string,
  table: string,
): Promise<TableDetail> {
  const query = new URLSearchParams({ schema, table })
  return request<TableDetail>(`/api/datasources/${datasourceId}/table-detail?${query}`)
}

// ---- Web SQL query ---------------------------------------------------------

/**
 * POST /api/datasources/{id}/query — run SQL through the enforcement pipeline.
 * Returns the decision (ALLOW/MASK/DENY) plus columns/rows (already masked on
 * MASK, empty on DENY). A blocked DENY is still a 200 — branch on `decision`.
 */
export function runQuery(datasourceId: number, input: QueryRequest): Promise<QueryResponse> {
  return request<QueryResponse>(`/api/datasources/${datasourceId}/query`, {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

// ---- Persistent editor sessions -----------------------------------
// One held backend connection per editor session, so SET/USE/temp/BEGIN persist across queries.

/** POST /api/editor/sessions — open a persistent editor session for a datasource. */
export function openEditorSession(datasourceId: number): Promise<{ sessionId: string }> {
  return request<{ sessionId: string }>(`/api/editor/sessions`, {
    method: 'POST',
    body: JSON.stringify({ datasourceId }),
  })
}

/**
 * POST /api/editor/sessions/{id}/query — SUBMIT SQL to run ASYNC on a held session as an auto-approved
 * task. Returns 202 with the task to poll (no rows inline); the enforced result is saved server-side.
 * SET/USE/temp still persist across submits (they run on the same held connection, one at a time).
 */
export function submitEditorQuery(sessionId: string, input: QueryRequest): Promise<EditorSubmitResponse> {
  return request<EditorSubmitResponse>(`/api/editor/sessions/${encodeURIComponent(sessionId)}/query`, {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

/** GET /api/editor/tasks/{taskId} — poll an editor task's status + its result metadata. */
export function getEditorTask(taskId: number): Promise<EditorTaskStatus> {
  return request<EditorTaskStatus>(`/api/editor/tasks/${taskId}`)
}

/** GET /api/editor/tasks/{taskId}/result — the saved, re-decided rows once the task is DONE. */
export function getEditorResult(taskId: number): Promise<EditorResultView> {
  return request<EditorResultView>(`/api/editor/tasks/${taskId}/result`)
}

/** POST /api/editor/tasks/{taskId}/cancel — cancel a running editor task. */
export function cancelEditorTask(taskId: number): Promise<EditorTaskStatus> {
  return request<EditorTaskStatus>(`/api/editor/tasks/${taskId}/cancel`, { method: 'POST' })
}

/** DELETE /api/editor/tasks/{taskId} — drop a task's saved rows (close-tab / re-run supersede). Idempotent. */
export function deleteEditorTask(taskId: number): Promise<void> {
  return request<void>(`/api/editor/tasks/${taskId}`, { method: 'DELETE' })
}

/** DELETE /api/editor/sessions/{id} — close the session, freeing its backend connection. */
export function closeEditorSession(sessionId: string): Promise<void> {
  return request<void>(`/api/editor/sessions/${encodeURIComponent(sessionId)}`, { method: 'DELETE' })
}

/** GET /api/query-history — the current principal's recent distinct queries (newest first). */
export function getQueryHistory(limit = 50): Promise<QueryHistoryEntry[]> {
  return request<QueryHistoryEntry[]>(`/api/query-history?limit=${limit}`)
}

export function putClassification(
  datasourceId: number,
  input: ClassificationInput,
): Promise<Classification> {
  return request<Classification>(`/api/datasources/${datasourceId}/classification`, {
    method: 'PUT',
    body: JSON.stringify(input),
  })
}

export function deleteClassification(
  datasourceId: number,
  body: ClassificationDelete,
): Promise<void> {
  return request<void>(`/api/datasources/${datasourceId}/classification`, {
    method: 'DELETE',
    body: JSON.stringify(body),
  })
}

// ---- Roles & principal mapping ---------------------------------------------

export function getRoles(): Promise<Role[]> {
  return request<Role[]>('/api/roles')
}

export function createRole(input: RoleInput): Promise<Role> {
  return request<Role>('/api/roles', { method: 'POST', body: JSON.stringify(input) })
}

export function updateRole(id: number, input: RoleInput): Promise<Role> {
  return request<Role>(`/api/roles/${id}`, { method: 'PUT', body: JSON.stringify(input) })
}

export function deleteRole(id: number): Promise<void> {
  return request<void>(`/api/roles/${id}`, { method: 'DELETE' })
}

export function getRoleAssignments(params?: {
  principal?: string
  roleId?: number
}): Promise<RoleAssignment[]> {
  const q = new URLSearchParams()
  if (params?.principal) q.set('principal', params.principal)
  if (params?.roleId != null) q.set('roleId', String(params.roleId))
  const qs = q.toString()
  return request<RoleAssignment[]>(`/api/role-assignments${qs ? `?${qs}` : ''}`)
}

export function createRoleAssignment(input: RoleAssignmentInput): Promise<RoleAssignment> {
  return request<RoleAssignment>('/api/role-assignments', {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

export function deleteRoleAssignment(id: number): Promise<void> {
  return request<void>(`/api/role-assignments/${id}`, { method: 'DELETE' })
}

// ---- Cedar policies ----------------------------------------------------------

export function getCedarPolicies(): Promise<CedarPolicy[]> {
  return request<CedarPolicy[]>('/api/policies')
}

export function createCedarPolicy(input: CedarPolicyInput): Promise<CedarPolicy> {
  return request<CedarPolicy>('/api/policies', { method: 'POST', body: JSON.stringify(input) })
}

export function updateCedarPolicy(id: number, input: CedarPolicyInput): Promise<CedarPolicy> {
  return request<CedarPolicy>(`/api/policies/${id}`, {
    method: 'PUT',
    body: JSON.stringify(input),
  })
}

export function setCedarPolicyEnabled(id: number, enabled: boolean): Promise<CedarPolicy> {
  return request<CedarPolicy>(`/api/policies/${id}/${enabled ? 'enable' : 'disable'}`, {
    method: 'POST',
  })
}

export function deleteCedarPolicy(id: number): Promise<void> {
  return request<void>(`/api/policies/${id}`, { method: 'DELETE' })
}

/** POST /api/policies/validate — Cedar-syntax-check without saving; `errors` is empty when valid. */
export function validateCedarPolicy(cedarSrc: string): Promise<{ errors: string[] }> {
  return request<{ errors: string[] }>('/api/policies/validate', {
    method: 'POST',
    body: JSON.stringify({ cedarSrc }),
  })
}

/** GET /api/policies/schema — the authz Cedar schema text, for in-editor schema-aware lint/completion. */
export function getCedarSchema(): Promise<{ schema: string }> {
  return request<{ schema: string }>('/api/policies/schema')
}

// ---- Users & groups --------------------------------------------------------

export function getUsers(): Promise<AppUser[]> {
  return request<AppUser[]>('/api/users')
}

export function createUser(input: AppUserInput): Promise<AppUser> {
  return request<AppUser>('/api/users', { method: 'POST', body: JSON.stringify(input) })
}

export function updateUser(id: number, input: AppUserInput): Promise<AppUser> {
  return request<AppUser>(`/api/users/${id}`, { method: 'PUT', body: JSON.stringify(input) })
}

export function deleteUser(id: number): Promise<void> {
  return request<void>(`/api/users/${id}`, { method: 'DELETE' })
}

export function getGroups(): Promise<AppGroup[]> {
  return request<AppGroup[]>('/api/groups')
}

export function createGroup(input: AppGroupInput): Promise<AppGroup> {
  return request<AppGroup>('/api/groups', { method: 'POST', body: JSON.stringify(input) })
}

export function updateGroup(id: number, input: AppGroupInput): Promise<AppGroup> {
  return request<AppGroup>(`/api/groups/${id}`, { method: 'PUT', body: JSON.stringify(input) })
}

export function deleteGroup(id: number): Promise<void> {
  return request<void>(`/api/groups/${id}`, { method: 'DELETE' })
}

export function getGroupMembers(groupId: number): Promise<GroupMember[]> {
  return request<GroupMember[]>(`/api/groups/${groupId}/members`)
}

export function addGroupMember(groupId: number, userId: number): Promise<GroupMember> {
  return request<GroupMember>(`/api/groups/${groupId}/members`, {
    method: 'POST',
    body: JSON.stringify({ userId }),
  })
}

export function removeGroupMember(groupId: number, userId: number): Promise<void> {
  return request<void>(`/api/groups/${groupId}/members/${userId}`, { method: 'DELETE' })
}

export function getGroupRoles(groupId: number): Promise<GroupRoleMapping[]> {
  return request<GroupRoleMapping[]>(`/api/groups/${groupId}/roles`)
}

export function addGroupRole(groupId: number, roleId: number): Promise<GroupRoleMapping> {
  return request<GroupRoleMapping>(`/api/groups/${groupId}/roles`, {
    method: 'POST',
    body: JSON.stringify({ roleId }),
  })
}

export function removeGroupRole(groupId: number, roleId: number): Promise<void> {
  return request<void>(`/api/groups/${groupId}/roles/${roleId}`, { method: 'DELETE' })
}

// ---- Mask functions --------------------------------------------------------

export function getMaskFns(): Promise<MaskFn[]> {
  return request<MaskFn[]>('/api/mask-fns')
}

export function createMaskFn(input: MaskFnInput): Promise<MaskFn> {
  return request<MaskFn>('/api/mask-fns', { method: 'POST', body: JSON.stringify(input) })
}

export function updateMaskFn(id: number, input: MaskFnInput): Promise<MaskFn> {
  return request<MaskFn>(`/api/mask-fns/${id}`, { method: 'PUT', body: JSON.stringify(input) })
}

export function deleteMaskFn(id: number): Promise<void> {
  return request<void>(`/api/mask-fns/${id}`, { method: 'DELETE' })
}

// ---- JIT access ------------------------------------------------------------

export function getAccessRequests(status?: string): Promise<AccessRequest[]> {
  const qs = status ? `?status=${encodeURIComponent(status)}` : ''
  return request<AccessRequest[]>(`/api/access-requests${qs}`)
}

export function createAccessRequest(input: AccessRequestInput): Promise<AccessRequest> {
  return request<AccessRequest>('/api/access-requests', {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

export function approveAccessRequest(id: number, durationSec?: number): Promise<AccessRequest> {
  return request<AccessRequest>(`/api/access-requests/${id}/approve`, {
    method: 'POST',
    body: JSON.stringify(durationSec != null ? { durationSec } : {}),
  })
}

export function rejectAccessRequest(id: number, reason: string): Promise<AccessRequest> {
  return request<AccessRequest>(`/api/access-requests/${id}/reject`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  })
}

export function getAccessGrants(params?: {
  principal?: string
  active?: boolean
}): Promise<AccessGrant[]> {
  const q = new URLSearchParams()
  if (params?.principal) q.set('principal', params.principal)
  if (params?.active) q.set('active', 'true')
  const qs = q.toString()
  return request<AccessGrant[]>(`/api/access-grants${qs ? `?${qs}` : ''}`)
}

export function revokeAccessGrant(id: number): Promise<void> {
  return request<void>(`/api/access-grants/${id}/revoke`, { method: 'POST' })
}

// ---- Query approvals -------------------------------------------------------

export function createApproval(input: CreateApprovalInput): Promise<CreateApprovalResponse> {
  return request<CreateApprovalResponse>('/api/approvals', {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

export function discoverApprovalRoles(input: DiscoverRolesRequest): Promise<DiscoverRolesResponse> {
  return request<DiscoverRolesResponse>('/api/approvals/discover-roles', {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

export function getMyApprovals(status?: string): Promise<AccessRequest[]> {
  const qs = status ? `?status=${encodeURIComponent(status)}` : ''
  return request<AccessRequest[]>(`/api/approvals${qs}`)
}

export function getApprovalInbox(): Promise<AccessRequest[]> {
  return request<AccessRequest[]>('/api/approvals/inbox')
}

export function getApproval(id: number): Promise<ApprovalDetail> {
  return request<ApprovalDetail>(`/api/approvals/${id}`)
}

export function approveApproval(id: number): Promise<AccessRequest> {
  return request<AccessRequest>(`/api/approvals/${id}/approve`, { method: 'POST' })
}

export function rejectApproval(id: number, reason: string): Promise<AccessRequest> {
  return request<AccessRequest>(`/api/approvals/${id}/reject`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  })
}

// ---- Task execution / result ------------------------------------------------

/** Submit an approved task for asynchronous execution. */
export function executeApproval(id: number): Promise<ExecuteApprovalResponse> {
  return request<ExecuteApprovalResponse>(`/api/approvals/${id}/execute`, { method: 'POST' })
}

/** Cancel an executing approved task. */
export function cancelApproval(id: number): Promise<AccessRequest> {
  return request<AccessRequest>(`/api/approvals/${id}/cancel`, { method: 'POST' })
}

/** Fetch decrypted rows after the latest child reaches DONE. */
export function getApprovalResult(id: number): Promise<QueryResultView> {
  return request<QueryResultView>(`/api/approvals/${id}/result`)
}

// ---- Wire tokens (expiring-only) -------------------------------------------

/** GET /api/tokens — the current principal's wire tokens (metadata only, never the secret). */
export function getTokens(): Promise<WireTokenInfo[]> {
  return request<WireTokenInfo[]>('/api/tokens')
}

/** POST /api/tokens — generate a managed (USER) expiring token; the plaintext is returned once. */
export function createToken(input: CreateTokenInput): Promise<IssuedToken> {
  return request<IssuedToken>('/api/tokens', { method: 'POST', body: JSON.stringify(input) })
}

/** DELETE /api/tokens/{id} — revoke a token. */
export function revokeToken(id: number): Promise<void> {
  return request<void>(`/api/tokens/${id}`, { method: 'DELETE' })
}
