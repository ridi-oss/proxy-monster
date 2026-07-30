// Wire contract shared with the control-plane. Mirrors the Kotlin shapes in
// control-plane/.../Decision.kt and the /auth surface in App.kt — keep the
// field names/shape in lockstep (docs/web-console.md: "one shape, no parallel UI").

/** Enforcement verdict (DESIGN.md). ERROR = internal failure, distinct from fail-closed DENY. */
export type Decision = 'ALLOW' | 'MASK' | 'DENY' | 'ERROR'

/** One audit event, as returned by GET /api/audit. */
export interface AuditEvent {
  id?: number | null // server-assigned
  ts: string | null // ISO-8601 instant; server fills if null
  kind: string
  principal: string
  roles: string[]
  datasource: string
  clientAddr: string | null
  statement: string
  decision: Decision
  failedStage: string | null // parse|validate|convert|lineage
  maskedColumns: string[]
  piiTouched: string[]
  latencyMs: number
  detail: string | null
  effectiveNamespace?: string[]
  channel?: string | null
  contextTags?: string[]
  authzAction?: string | null
  authzResource?: string | null
  outcome?: string | null
  rowsReturned?: number | null
  bytesReturned?: number | null
  decisionId?: number | null
}

/** The authenticated principal, as returned by GET /auth/me and POST /auth/debug. */
export interface Identity {
  principal: string
  roles: string[]
  /**
   * The simulated source address a debug-login session authorizes under, when one was chosen. Absent for
   * every ordinary session, and absent whenever the control-plane is not honoring it.
   */
  requesterIp?: string | null
}

/** Coarse Cedar-backed capabilities for the authenticated principal. */
export interface MePermissions {
  isAdmin: boolean
  canReadAllAudit: boolean
  canApprove: boolean
}

/** Why a web session could not be resolved by the authenticated session routes. */
export type SessionReason = 'none' | 'expired' | 'displaced' | 'bind_mismatch'

/** Server-authoritative web-session deadlines returned by the session status endpoints. */
export interface SessionStatus {
  now: string
  idleExpiresAt: string
  absoluteExpiresAt: string
  principal: string
  sessionId: number
}

/** Auth capabilities and web-session timings from GET /auth/config. */
export interface AuthConfig {
  oidcEnabled: boolean
  authDebug: boolean
  session: {
    heartbeatMs: number
    idleWarnLeadMs: number
    absoluteWarnLeadMs: number
    absoluteCapAmount: number
    absoluteCapUnit: 'hours' | 'minutes' | 'seconds'
  }
}

// ---- Datasources (control-plane/.../Datasources.kt) -------------------------

/** Supported target engines. */
export type Engine = 'postgres' | 'mysql'

/**
 * A registered target database. Carries NO credential: the control-plane never dials a target (the proxy
 * executes every query), so there is zero target secret at rest. host/port/dbName are advisory — the proxy
 * is authoritative and overwrites them on registration.
 */
export interface Datasource {
  id: number
  name: string
  engine: string
  host: string
  port: number
  dbName: string
  /** Policy-posture tags (`preset:*`, docs/access-model.md) — set by the proxy's `PM_DATASOURCE_TAGS` at
   *  registration, or by an admin edit. Empty by default (safe "production" posture). */
  tags: string[]
  defaultSchemas: string[]
  mysqlLowerCaseTableNames?: number | null
  catalogSyncedAt?: string | null
  /** Last time a proxy's Events stream opened for this datasource. Null = never seen. For CURRENT
   *  attachment (not just "seen at some point"), use `getDatasourcesLive()` / `useDatasourcesLive()`. */
  lastSeenAt?: string | null
  engineVersion?: string | null
  /** The client-facing `host:port` a wire client dials to reach this datasource's proxy — set by the proxy
   *  at registration, distinct from the advisory `host`/`port` above. Null until a proxy advertises one. */
  advertiseAddr?: string | null
  /** PEM certificate chain to trust for this datasource's proxy, leaf first, as advertised at registration.
   *  pmon uses it as its root pool; the console offers the same bytes for download. Null when the proxy
   *  published none — which is NOT the same as having no TLS (see advertiseWireTls). */
  advertiseCertChain?: string | null
  /** Whether the proxy serves TLS at all. Independent of the chain: an operator may serve a publicly-trusted
   *  certificate and publish nothing, so clients verify against their own trust store. Only false is plaintext. */
  advertiseWireTls?: boolean
}

/**
 * Create/update body for a datasource. Optional pre-provisioning only — a way to seed a row (name +
 * advisory connection fields) before its proxy first attaches; the proxy's registration is authoritative.
 * Only `name` is required; there are no credential fields.
 */
export interface DatasourceInput {
  name: string
  engine: Engine
  host?: string
  port?: number
  dbName?: string
}

/** Result of POST .../refresh — how many connected proxy streams were nudged to re-introspect. */
export interface RefreshResult {
  notified: number
}

/** Result of POST .../test — whether a proxy is currently attached; the target is never dialed. */
export interface TestResult {
  ok: boolean
  message: string
}

// ---- Catalog + classification (control-plane/.../Datasources.kt) ------------

/** A column's classification (tags + optional mask function), upserted by table+column. */
export interface Classification {
  schema: string
  table: string
  column: string
  tags: string[]
  maskFnId?: number | null
  maskFnName?: string | null
}

/** A catalog column joined with its classification (if any). */
export interface CatalogColumn {
  catalog: string
  schema: string
  table: string
  column: string
  dataType: string
  sqlType: string
  ordinal: number
  nullable: boolean
  classification?: Classification | null
}

// ---- Live table detail ------------------------------------------------------

export interface TableDetailColumn {
  name: string
  dataType: string
  ordinal: number
  nullable: boolean
  defaultValue: string | null
  characterMaximumLength: number | null
  numericPrecision: number | null
  numericScale: number | null
  partOfIndex: boolean
  autoIncrement: boolean
  comment: string | null
  charset: string | null
  collation: string | null
  classification: Classification | null
}

export interface TableIndexColumn {
  name: string
  position: number
  direction: string | null
}

export interface TableIndex {
  name: string
  columns: TableIndexColumn[]
  unique: boolean
  type: string
}

export interface TableRelation {
  name: string
  sourceSchema: string
  sourceTable: string
  sourceColumns: string[]
  targetSchema: string
  targetTable: string
  targetColumns: string[]
  onUpdate: string | null
  onDelete: string | null
}

export interface TableMetadata {
  engine: string
  estimatedRows: number | null
  rowFormat: string | null
  onDiskBytes: number | null
  collation: string | null
  comment: string | null
}

export interface TableDetail {
  schema: string
  table: string
  columns: TableDetailColumn[]
  indexes: TableIndex[]
  foreignKeys: TableRelation[]
  referencedBy: TableRelation[]
  metadata: TableMetadata
}

/** Upsert body for a classification. Omitted `schema` uses the captured non-system datasource default; it is required before introspection captures one. */
export interface ClassificationInput {
  schema?: string
  table: string
  column: string
  tags: string[]
  maskFnId?: number | null
}

/** Delete body for a classification. Omitted `schema` uses the same captured default as upsert. */
export interface ClassificationDelete {
  schema?: string
  table: string
  column: string
}

// ---- Roles & principal mapping (control-plane/.../Policies.kt) --------------

export interface Role {
  id: number
  name: string
  description?: string | null
}

export interface RoleInput {
  name: string
  description?: string | null
}

export interface RoleAssignment {
  id: number
  principal: string
  roleId: number
  roleName: string
}

export interface RoleAssignmentInput {
  principal: string
  roleId: number
}

// ---- Cedar policies (control-plane/.../authz/CedarPolicyStore.kt) -----------

/** A named Cedar policy row: source text + enabled flag + audit metadata. */
export interface CedarPolicy {
  id: number
  /** Provenance: SYSTEM rows are migration-owned and immutable through the API except
   *  enable/disable; USER rows are full CRUD. The backend enforces this — the console mirrors it. */
  origin: 'SYSTEM' | 'USER'
  /** Stable key of a shipped system policy (e.g. `system:catalog-read`); null for USER rows. */
  systemKey?: string | null
  name: string
  cedarSrc: string
  enabled: boolean
  updatedBy?: string | null
  updatedAt: string
}

/** Create/update body for a Cedar policy. Server validates `cedarSrc` (400 with messages on invalid). */
export interface CedarPolicyInput {
  name: string
  cedarSrc: string
  enabled: boolean
}

// ---- Users & groups (control-plane/.../Users.kt) ----

export interface GroupRef { id: number; name: string }
export interface AppUser { id: number; principal: string; displayName?: string | null;
  email?: string | null; source: string; externalId?: string | null; active: boolean;
  createdAt: string; groups: GroupRef[] }
export interface AppUserInput { principal: string; displayName?: string | null;
  email?: string | null; active: boolean }
export interface AppGroup { id: number; name: string; description?: string | null;
  source: string; externalId?: string | null; memberCount: number; roles: GroupRef[] }
export interface AppGroupInput { name: string; description?: string | null }
export interface GroupMember { userId: number; principal: string; displayName?: string | null }
export interface GroupRoleMapping { roleId: number; roleName: string }

// ---- Mask functions (control-plane/.../Policies.kt) -------------------------

export type MaskFnKind = 'FIXED' | 'LAST_N' | 'FORMAT_PRESERVING' | 'NULL'

export interface MaskFn {
  id: number
  name: string
  kind: string
}

export interface MaskFnInput {
  name: string
  kind: MaskFnKind
}

// ---- JIT access (control-plane/.../Access.kt) -------------------------------

export type AccessRequestStatus =
  | 'DRAFT' | 'PENDING' | 'APPROVED' | 'REJECTED'
  | 'EXECUTING' | 'EXECUTED' | 'FAILED' | 'CANCELLED' | 'DELETED'

export interface AccessRequest {
  id: number
  principal: string
  roleId?: number | null
  roleName?: string | null
  datasourceId?: number | null
  datasourceName?: string | null
  reason?: string | null
  requestedDurationSec: number
  status: string
  decidedBy?: string | null
  decidedAt?: string | null
  rejectionReason?: string | null
  createdAt: string
  kind: 'ROLE' | 'QUERY'
  sql?: string | null
  sqlHash?: string | null
  denyReason?: string | null
  sourceDecisionId?: number | null
  title?: string | null
  evaluatedDecision?: 'ALLOW' | 'MASK' | 'DENY' | null
  approvedAt?: string | null
  executingAt?: string | null
  executedAt?: string | null
  executeAs: string[]
  creatorKind?: 'WIRE' | 'EDITOR' | 'WORKFLOW' | null
}

export interface AccessRequestInput {
  roleId: number
  datasourceId?: number | null
  reason?: string | null
  requestedDurationSec: number
}

export interface AccessGrant {
  id: number
  principal: string
  roleId: number
  roleName: string
  grantedBy?: string | null
  grantedAt: string
  expiresAt?: string | null
  revokedAt?: string | null
}

export type CreateApprovalInput =
  | { sourceDecisionId: number; reason: string; title?: string; roleId?: number }
  | { datasourceId: number; sql: string; title: string; reason: string; roleId?: number }

export interface CreateApprovalResponse {
  request: AccessRequest
  wouldAllow: boolean
}

export interface DiscoverRolesRequest {
  datasourceId: number
  sql: string
}

export interface RoleOption {
  roleId: number
  roleName: string
  unmasksColumns: string[]
}

export interface DiscoverRolesResponse {
  baselineAllowed: boolean
  options: RoleOption[]
}

/** Latest task-child metadata — never the rows themselves. */
export interface QueryResultMeta {
  taskId: number
  executedBy?: string | null
  executedAt?: string | null
  rowCount?: number | null
  expiresAt?: string | null
  status?: 'RUNNING' | 'DONE' | 'FAILED' | 'CANCELLED' | null
  errorCode?: string | null
  columns: string[]
}

export interface ApprovalDetail {
  request: AccessRequest
  canDecide: boolean
  result?: QueryResultMeta | null
  canExecute?: boolean
  canCancel?: boolean
}

/** Decrypted rows of an APPROVER_EXEC result (returned only to an authorized viewer). */
export interface QueryResultView {
  meta: QueryResultMeta
  columns: string[]
  rows: (string | null)[][]
  /**
   * The verdict of the LIVE view re-decision these rows were released under — the viewer's own context can
   * narrow an execution's ALLOW to a MASK, so this describes the release, not the stored execution. Only
   * these two values reach a caller holding rows: a denied view is a 403 with no body.
   */
  decision: 'ALLOW' | 'MASK'
  maskedColumns: string[]
}

/** Submit acknowledgement; completion is observed through task polling. */
export interface ExecuteApprovalResponse {
  decision: 'EXECUTING'
}

// ---- Web SQL query (POST /api/datasources/{id}/query) ------------------------

/** Body for the enforcing query endpoint. */
export interface QueryRequest {
  sql: string
  maxRows?: number
}

/** One recalled query from the principal's editor history (GET /api/query-history). */
export interface QueryHistoryEntry {
  sql: string
  datasourceId?: number | null
  ranAt: string
}

// ---- Wire tokens (DESIGN.md — expiring-only) --------------------------------

/** A wire token's metadata (never the secret). `kind`: SESSION (daemon) | USER (generated). */
export interface WireTokenInfo {
  id: number
  kind: string
  principal: string
  name?: string | null
  createdAt: string
  expiresAt: string // always set — tokens are expiring-only
  revokedAt?: string | null
  lastUsedAt?: string | null
}

/** Returned exactly once at generation — the only time the plaintext token is shown. */
export interface IssuedToken {
  token: string
  id: number
  kind: string
  name?: string | null
  expiresAt: string
}

/** Generate a managed (USER) token: optional name + TTL in seconds (clamped server-side). */
export interface CreateTokenInput {
  name?: string | null
  ttlSeconds?: number
}

/**
 * Result of running SQL through the enforcement pipeline. A DENY blocks the
 * query and returns no rows; MASK returns rows with masked column values
 * already substituted; ALLOW returns rows verbatim. Shape mirrors the
 * control-plane `QueryResponse`.
 */
export interface QueryResponse {
  decision: 'ALLOW' | 'MASK' | 'DENY'
  decisionId?: number | null
  denyReason?: string | null
  maskedColumns: string[]
  piiTouched: string[]
  effectiveRoles: string[]
  columns: string[]
  rows: (string | null)[][]
  rowsAffected?: number | null
  latencyMs: number
}

// ---- Async editor tasks (editor-as-task) -----------------------------
// An editor submit runs ASYNC as an auto-approved task: POST returns a task id to poll (no rows
// inline), the result is saved server-side, and the client polls status → fetches rows when DONE.

/** POST /api/editor/sessions/{id}/query ack: the born-APPROVED task + its single result child. */
export interface EditorSubmitResponse {
  taskId: number
  childId: number
}

/** GET /api/editor/tasks/{taskId}: the parent task status + its child result metadata (rows are behind
 *  the /result endpoint). `result` is null until the child exists; `result.status` walks
 *  RUNNING → DONE / FAILED. */
export interface EditorTaskStatus {
  taskId: number
  status: 'APPROVED' | 'EXECUTING' | 'EXECUTED' | 'FAILED' | 'CANCELLED'
  result: {
    status: 'RUNNING' | 'DONE' | 'FAILED' | 'CANCELLED' | null
    rowCount: number | null
    columns: string[]
    errorCode: string | null
    executedAt?: string
    expiresAt?: string
  } | null
}

/** GET /api/editor/tasks/{taskId}/result: the saved, re-decided rows once the task is DONE. */
export interface EditorResultView {
  columns: string[]
  rows: (string | null)[][]
  meta?: unknown
  /**
   * The verdict of the re-decision that released these rows. The editor labels its result panel from this;
   * inferring it from the presence of rows cannot distinguish a masked result from a clean one. Only these
   * two values reach a caller holding rows: a denied view is a 403 with no body.
   */
  decision: 'ALLOW' | 'MASK'
  maskedColumns: string[]
}
