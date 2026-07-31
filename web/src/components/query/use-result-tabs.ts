'use client'

// Result-tab workspace (DataGrip/BigQuery-style). Each distinct query (and each opened table)
// gets a tab. Re-running the same query refreshes its tab; a new query reuses the single
// unpinned "scratch" tab — pinning a tab keeps it and forces the next run into a fresh one.
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslations } from 'next-intl'
import { toast } from 'sonner'
import {
  cancelEditorTask,
  closeEditorSession,
  deleteEditorTask,
  getEditorResult,
  getEditorTask,
  openEditorSession,
  submitEditorQuery,
} from '@/lib/api/client'
import { subscribeTaskEvents, waitForTaskEvent } from '@/lib/api/task-events'
import { translateApiError } from '@/lib/i18n/errors'
import type { Decision, QueryResponse } from '@/lib/api/types'
import type { TreeTable } from './catalog-schema'

export interface QueryLogEntry {
  id: string
  datasourceId: number
  statement: string
  decision: Decision
  denyReason: string | null
  rowsReturned: number
  latencyMs: number
  error: string | null
  timestamp: string
}

export interface ResultState {
  loading: boolean
  canceling: boolean
  canceled: boolean
  result: QueryResponse | null
  error: string | null
}

interface BaseTab {
  id: string
  key: string
  title: string
  pinned: boolean
  res: ResultState
  // The async editor task backing this tab's current run: the tab polls it to completion and
  // deletes it on re-run/close. Null before the first submit (or for a table tab yet to load).
  taskId: number | null
}
export interface QueryTab extends BaseTab {
  kind: 'query'
  sql: string
}
export interface TableTab extends BaseTab {
  kind: 'table'
  datasourceId: number
  table: TreeTable
}
export type ResultTab = QueryTab | TableTab

const TABLE_PREVIEW_ROWS = 100
const EMPTY: ResultState = {
  loading: false,
  canceling: false,
  canceled: false,
  result: null,
  error: null,
}
// Fallback poll tick. The task's SSE completion event normally wakes the poll well before this
// fires; it is a FOREGROUND best-effort ceiling on completion latency only when the push stream is absent or
// dropped (a backgrounded tab throttles timers and may reconcile later, typically on focus). A couple of
// seconds keeps the fallback snappy while cutting poll traffic for in-flight runs.
const POLL_INTERVAL_MS = 2500
// A newer run replaced this tab's poll — thrown to unwind the poll loop and dropped without patching/logging.
const SUPERSEDED = Symbol('superseded')

const norm = (sql: string) => sql.trim().replace(/\s+/g, ' ')
const label = (sql: string) => {
  const s = norm(sql)
  return s.length > 36 ? s.slice(0, 36) + '…' : s
}

export interface ResultTabsApi {
  tabs: ResultTab[]
  activeId: string | null
  active: ResultTab | null
  logs: QueryLogEntry[]
  run: (sql: string) => void
  openTable: (table: TreeTable) => void
  setActive: (id: string) => void
  pin: (id: string) => void
  cancel: (id: string) => void
  close: (id: string) => void
  clearLogs: () => void
}

export function useResultTabs(datasourceId: number | null, maxRows: number): ResultTabsApi {
  const t = useTranslations('Query')
  const [tabs, setTabs] = useState<ResultTab[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)
  const [logs, setLogs] = useState<QueryLogEntry[]>([])

  // Mirror state in a ref so the imperative handlers read the latest without stale closures.
  const tabsRef = useRef<ResultTab[]>([])
  useEffect(() => {
    tabsRef.current = tabs
  }, [tabs])

  // Keep the shared task-event stream open while the editor is mounted: its completion events
  // wake each tab's poll loop instantly (see waitForTaskEvent). Ref-counted, so it degrades to poll on absence.
  useEffect(() => subscribeTaskEvents(), [])
  const idRef = useRef(0)
  const executionRef = useRef(0)
  const executionOrderRef = useRef(new Map<string, number>())
  const tokenRef = useRef<Record<string, number>>({}) // per-tab fetch token (race guard)
  const newId = () => `t${++idRef.current}`

  // One persistent editor session (one held backend connection) per datasource, so SET/USE/temp
  // persist across queries. Opened lazily on the first query and reused; closed on datasource change/unmount.
  const sessionIdRef = useRef<string | null>(null)
  const sessionDsRef = useRef<number | null>(null)
  const openingRef = useRef<Promise<string> | null>(null)

  const ensureSession = useCallback(async (): Promise<string> => {
    if (datasourceId == null) throw new Error('no datasource selected')
    if (sessionIdRef.current && sessionDsRef.current === datasourceId) return sessionIdRef.current
    // De-dupe concurrent opens (two statements fired before the session is ready share one open).
    if (openingRef.current) return openingRef.current
    const p = openEditorSession(datasourceId).then(({ sessionId }) => {
      sessionIdRef.current = sessionId
      sessionDsRef.current = datasourceId
      return sessionId
    })
    openingRef.current = p
    try {
      return await p
    } finally {
      openingRef.current = null
    }
  }, [datasourceId])

  // Switching datasource invalidates every tab (catalog + rows differ) and closes the previous session's
  // held connection (the cleanup runs on datasource change AND on unmount).
  useEffect(() => {
    setTabs([])
    setActiveId(null)
    return () => {
      // Drop any live tab tasks (their saved rows) alongside closing the held session — the previous
      // datasource's tabs are being discarded, so their server-side results should go too (best-effort).
      for (const tab of tabsRef.current) {
        if (tab.taskId != null) void deleteEditorTask(tab.taskId).catch(() => {})
      }
      const sid = sessionIdRef.current
      if (sid) {
        void closeEditorSession(sid).catch(() => {})
        sessionIdRef.current = null
        sessionDsRef.current = null
      }
    }
  }, [datasourceId])

  const patch = useCallback((id: string, res: Partial<ResultState>) => {
    setTabs((ts) => ts.map((t) => (t.id === id ? { ...t, res: { ...t.res, ...res } } : t)))
  }, [])

  const setTabTaskId = useCallback((id: string, taskId: number | null) => {
    setTabs((ts) => ts.map((t) => (t.id === id ? { ...t, taskId } : t)))
  }, [])

  const appendLog = useCallback((entry: QueryLogEntry, execution: number) => {
    executionOrderRef.current.set(entry.id, execution)
    setLogs((current) =>
      [...current, entry].sort(
        (a, b) =>
          (executionOrderRef.current.get(b.id) ?? 0) -
          (executionOrderRef.current.get(a.id) ?? 0),
      ),
    )
  }, [])

  const clearLogs = useCallback(() => {
    setLogs([])
    executionOrderRef.current.clear()
  }, [])

  const fetchInto = useCallback(
    (id: string, sql: string, rows: number) => {
      if (datasourceId == null) return
      const token = (tokenRef.current[id] = (tokenRef.current[id] ?? 0) + 1)
      const statement = norm(sql)
      const execution = ++executionRef.current
      const executionId = `execution-${execution}`
      const timestamp = new Date().toISOString()
      const startedAt = performance.now()
      // A superseded poll (a newer run bumped this tab's token) is dropped without patching or logging.
      const current = () => tokenRef.current[id] === token
      patch(id, { loading: true, canceling: false, canceled: false, error: null })

      // Submit the run; supersede the tab's previous task first (best-effort) so a re-run REPLACES it.
      const submitOnce = async (sid: string) => {
        const prev = tabsRef.current.find((t) => t.id === id)?.taskId
        if (prev != null) void deleteEditorTask(prev).catch(() => {})
        return submitEditorQuery(sid, { sql: statement, maxRows: rows })
      }

      const run = async (): Promise<QueryResponse | null> => {
        let submit
        try {
          submit = await submitOnce(await ensureSession())
        } catch (e) {
          // The held session may have been reaped (idle) or expired — reopen once and retry.
          if (e instanceof Error && /session/i.test(e.message)) {
            sessionIdRef.current = null
            submit = await submitOnce(await ensureSession())
          } else {
            throw e
          }
        }
        if (!current()) {
          // The tab was superseded (re-run) or closed while this POST was in flight — the server task now
          // exists but no tab owns its id, so delete-on-close/re-run can never reach it. Reap it here
          // (best-effort) before unwinding, so a slow submit can't leak a persisted result.
          void deleteEditorTask(submit.taskId).catch(() => {})
          throw SUPERSEDED
        }
        setTabTaskId(id, submit.taskId)

        // Poll the task to a terminal state, then fetch the saved rows on DONE (the editor never blocks —
        // each tab polls independently). A FAILED task (incl. a DENY at execute) surfaces its error code.
        for (;;) {
          if (!current()) throw SUPERSEDED
          const status = await getEditorTask(submit.taskId)
          if (!current()) throw SUPERSEDED
          const child = status.result
          if (status.status === 'FAILED' || child?.status === 'FAILED') {
            // A policy DENY is a decision, not an error: returning it as a DENY result is what gives the
            // panel the reason and the decisionId it needs to offer "request approval". Throwing here
            // collapsed it into a generic failure and dropped both, leaving the requester nowhere to go.
            if (child?.errorCode === 'approval.execute_denied') {
              return {
                decision: 'DENY',
                decisionId: child.decisionId ?? null,
                denyReason: child.denyReason ?? null,
                maskedColumns: [],
                piiTouched: [],
                effectiveRoles: [],
                columns: [],
                rows: [],
                rowsAffected: null,
                latencyMs: Math.max(0, Math.round(performance.now() - startedAt)),
              }
            }
            // Any other failure really is one. errorCode is a catalog code (e.g. query.proxy_timeout) —
            // localize it here so the panel shows bilingual copy, never the raw code. ApiError messages are
            // already translated by the fetch wrapper; this covers the polled failure path.
            throw new Error(translateApiError(child?.errorCode ?? 'approval.query_failed'))
          }
          if (status.status === 'CANCELLED' || child?.status === 'CANCELLED') {
            appendLog(
              {
                id: executionId,
                datasourceId,
                statement,
                decision: 'ERROR',
                denyReason: null,
                rowsReturned: 0,
                latencyMs: Math.max(0, Math.round(performance.now() - startedAt)),
                error: t('logs.canceledLine', {
                  ms: Math.max(0, Math.round(performance.now() - startedAt)),
                }),
                timestamp,
              },
              execution,
            )
            if (current()) {
              patch(id, {
                loading: false,
                canceling: false,
                canceled: true,
                result: null,
                error: null,
              })
            }
            return null
          }
          if (child?.status === 'DONE') {
            const view = await getEditorResult(submit.taskId)
            return {
              // From the server's re-decision, never assumed: these rows are released under the viewer's
              // live context, which can mask columns the execution itself returned in the clear.
              decision: view.decision,
              decisionId: null,
              denyReason: null,
              maskedColumns: view.maskedColumns,
              piiTouched: [],
              effectiveRoles: [],
              columns: view.columns,
              rows: view.rows,
              rowsAffected: null,
              latencyMs: Math.max(0, Math.round(performance.now() - startedAt)),
            }
          }
          // Wait for this task's push (instant on completion) or the fallback tick, whichever comes first.
          await waitForTaskEvent(submit.taskId, POLL_INTERVAL_MS)
        }
      }

      run()
        .then((r) => {
          if (r == null) return
          appendLog(
            {
              id: executionId,
              datasourceId,
              statement,
              decision: r.decision,
              denyReason: r.denyReason ?? null,
              rowsReturned: r.rows.length,
              latencyMs: r.latencyMs,
              error: null,
              timestamp,
            },
            execution,
          )
          if (current()) {
            patch(id, {
              loading: false,
              canceling: false,
              canceled: false,
              result: r,
              error: null,
            })
          }
        })
        .catch((e) => {
          // A newer run replaced this tab (or deleted its task mid-poll, surfacing as a 404) — drop
          // silently: no patch, and no misleading ERROR log for a run the user already superseded.
          if (e === SUPERSEDED || !current()) return
          const message = e instanceof Error ? e.message : typeof e === 'string' ? e : 'query failed'
          appendLog(
            {
              id: executionId,
              datasourceId,
              statement,
              decision: 'ERROR',
              denyReason: null,
              rowsReturned: 0,
              latencyMs: Math.max(0, Math.round(performance.now() - startedAt)),
              error: message,
              timestamp,
            },
            execution,
          )
          if (current()) {
            patch(id, {
              loading: false,
              canceling: false,
              canceled: false,
              result: null,
              error: message,
            })
          }
        })
    },
    [appendLog, datasourceId, patch, ensureSession, setTabTaskId, t],
  )

  const run = useCallback(
    (sql: string) => {
      const key = norm(sql)
      if (!key || datasourceId == null) return
      // Re-running the same query refreshes its (unpinned) tab in place; a different query opens
      // its own tab — running never closes another tab. A pinned tab is a frozen snapshot, so
      // re-running it opens a fresh tab instead of overwriting it.
      const existing = tabsRef.current.find((t) => t.kind === 'query' && t.key === key && !t.pinned)
      if (existing) {
        setActiveId(existing.id)
        fetchInto(existing.id, sql, maxRows)
        return
      }
      const id = newId()
      const tab: QueryTab = { id, kind: 'query', key, title: label(sql), sql, pinned: false, taskId: null, res: { ...EMPTY, loading: true } }
      setTabs((ts) => [...ts, tab])
      setActiveId(id)
      fetchInto(id, sql, maxRows)
    },
    [datasourceId, fetchInto, maxRows],
  )

  const openTable = useCallback(
    (table: TreeTable) => {
      if (datasourceId == null) return
      const key = `tbl:${table.qualified}`
      const existing = tabsRef.current.find((t) => t.kind === 'table' && t.key === key)
      if (existing) {
        setActiveId(existing.id)
        return
      }
      const id = newId()
      const tab: TableTab = {
        id,
        kind: 'table',
        key,
        title: table.qualified,
        datasourceId,
        table,
        pinned: false,
        taskId: null,
        res: { ...EMPTY, loading: true },
      }
      setTabs((ts) => [...ts, tab])
      setActiveId(id)
      fetchInto(id, `SELECT * FROM ${table.insert} LIMIT ${TABLE_PREVIEW_ROWS}`, TABLE_PREVIEW_ROWS)
    },
    [datasourceId, fetchInto],
  )

  const pin = useCallback((id: string) => {
    setTabs((ts) => ts.map((t) => (t.id === id ? { ...t, pinned: !t.pinned } : t)))
  }, [])

  const cancel = useCallback(
    (id: string) => {
      const tab = tabsRef.current.find((candidate) => candidate.id === id)
      if (tab?.taskId == null || !tab.res.loading || tab.res.canceling) return
      patch(id, { canceling: true })
      void cancelEditorTask(tab.taskId).catch((error) => {
        patch(id, { canceling: false })
        toast.error(error instanceof Error ? error.message : translateApiError('common.fallback'))
      })
    },
    [patch],
  )

  const close = useCallback(
    (id: string) => {
      // Delete-on-close: drop the tab's saved result server-side (best-effort, idempotent).
      const closing = tabsRef.current.find((t) => t.id === id)
      if (closing?.taskId != null) void deleteEditorTask(closing.taskId).catch(() => {})
      setTabs((ts) => {
        const idx = ts.findIndex((t) => t.id === id)
        const next = ts.filter((t) => t.id !== id)
        setActiveId((cur) => {
          if (cur !== id) return cur
          if (next.length === 0) return null
          return next[Math.min(idx, next.length - 1)].id
        })
        return next
      })
    },
    [],
  )

  const active = tabs.find((t) => t.id === activeId) ?? null
  return {
    tabs,
    activeId,
    active,
    logs,
    run,
    openTable,
    setActive: setActiveId,
    pin,
    cancel,
    close,
    clearLogs,
  }
}
