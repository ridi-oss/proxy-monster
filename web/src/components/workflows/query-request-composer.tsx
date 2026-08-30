'use client'

import { useRef, useState, useEffect, useMemo, type FormEvent } from 'react'
import { useTranslations } from 'next-intl'
import { mutate } from 'swr'
import { toast } from 'sonner'
import { createApproval, discoverApprovalRoles, ApiError } from '@/lib/api/client'
import type { AccessRequest, DiscoverRolesResponse } from '@/lib/api/types'
import { pickRole } from './pick-role'
import { swrKeys, useAuditEvent, useDatasources } from '@/lib/hooks'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { DatasourceSelect } from '@/components/datasource-select'
import { ErrorState, LoadingState } from '@/components/page-scaffold'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

/** Colors the verdict so cleartext vs masked reads at a glance. A denying role is never offered. */
const OUTCOME_TONE: Record<string, string> = {
  ALLOW: 'text-emerald-600 dark:text-emerald-400',
  MASK: 'text-amber-600 dark:text-amber-400',
}

/** Wait this long after the query stops changing before re-listing roles, so it is not fetched per keystroke. */
const DISCOVER_DEBOUNCE_MS = 400

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    try {
      const parsed = JSON.parse(err.message) as { error?: string }
      return parsed.error ?? err.message
    } catch {
      return err.message
    }
  }
  return err instanceof Error ? err.message : String(err)
}

function formatTimestamp(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : '—'
}

export function QueryRequestComposer({
  sourceDecisionId,
  sourceDecisionError,
  onCreated,
  onCancel,
}: {
  sourceDecisionId: number | null
  sourceDecisionError?: string | null
  onCreated: (request: AccessRequest) => void
  onCancel: () => void
}) {
  const t = useTranslations('Workflows')
  const { data: record, error, isLoading } = useAuditEvent(sourceDecisionId)
  const { data: datasources } = useDatasources()
  const [datasourceId, setDatasourceId] = useState<number | null>(null)
  const [sql, setSql] = useState('')
  const [title, setTitle] = useState('')
  const [reason, setReason] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  // The role the user explicitly picked, remembered across query changes so it can be RECOVERED when it is
  // offered again. null = never overridden → the first offered role is selected by default.
  const [userChoice, setUserChoice] = useState<string | null>(null)
  // The discovery result, tagged with the inputs it was resolved FOR — that pairing is what makes a stale
  // result detectable without throwing it away on every derived-value flicker.
  const [discovery, setDiscovery] = useState<
    (DiscoverRolesResponse & { forSql: string; forDatasourceId: number }) | null
  >(null)
  const [discoverError, setDiscoverError] = useState<string | null>(null)
  // True while a discovery fetch for the CURRENT query is in flight (debounce + request). It gates a PRIOR
  // same-query result from reactivating before the fresh fetch lands (a query edited A→B→A back to A would
  // otherwise show A's earlier options while A is being re-listed), and drives the "checking…" copy.
  const [discovering, setDiscovering] = useState(false)
  // Bumped by the Retry control so a discovery that failed for the UNCHANGED query re-runs — the effect's
  // other deps have not moved, so without this a transient failure would leave the form permanently stuck.
  const [retryNonce, setRetryNonce] = useState(0)

  const fromDenied = sourceDecisionId != null

  // Effective (datasourceId, sql) used for role discovery, per composer branch.
  const effectiveSql = fromDenied ? (record?.statement ?? null) : sql.trim() || null
  const effectiveDatasourceId = fromDenied
    ? (datasources?.find((d) => d.name === record?.datasource)?.id ?? null)
    : datasourceId
  const canDiscover = effectiveDatasourceId != null && !!effectiveSql

  // Each discovery bumps this generation counter, so a response is applied only if its generation is still
  // current — an in-flight request that resolves after a newer one (or after the query cleared) cannot
  // repopulate the list.
  const discoverSeq = useRef(0)

  // Roles are re-listed automatically whenever the query changes, debounced. No manual "check roles" step.
  useEffect(() => {
    if (!canDiscover) {
      discoverSeq.current += 1 // cancel any in-flight response; the render guard already ignores a stale one
      setDiscovering(false)
      // Drop the stale list too: restoring the SAME query (A → cleared → A) would otherwise re-offer A's
      // prior options on the render BEFORE the fresh fetch marks itself in flight — a brief submit window on
      // outdated options. userChoice is preserved, so the pick recovers when the re-fetch lands.
      setDiscovery(null)
      return
    }
    const forDatasourceId = effectiveDatasourceId
    const forSql = effectiveSql
    const seq = (discoverSeq.current += 1)
    // Mark this query's fetch in flight and clear a stale error up front: until it lands, a prior result for
    // the same query text is not usable, and a leftover error must not mask the fresh "checking…".
    setDiscovering(true)
    setDiscoverError(null)
    const timer = setTimeout(() => {
      discoverApprovalRoles({ datasourceId: forDatasourceId, sql: forSql })
        .then((res) => {
          if (seq !== discoverSeq.current) return // a newer generation started → this response is stale
          setDiscovery({ ...res, forSql, forDatasourceId })
          setDiscovering(false)
        })
        .catch(() => {
          if (seq !== discoverSeq.current) return
          setDiscovery(null)
          setDiscoverError(t('queryComposer.discoverFailed'))
          setDiscovering(false)
        })
    }, DISCOVER_DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [canDiscover, effectiveSql, effectiveDatasourceId, retryNonce, t])

  // The discovery is usable only if it was resolved FOR the query now being composed. On the from-denied
  // branch effectiveSql/effectiveDatasourceId transition through null while SWR resolves, so comparing —
  // rather than resetting on change — is what keeps a valid list from being wiped by a derived-value flicker.
  const discoveryFresh =
    discovery != null &&
    discovery.forSql === effectiveSql &&
    discovery.forDatasourceId === effectiveDatasourceId
  // The list is usable only when it matches the current query AND no fetch for it is in flight — the latter is
  // what stops a prior same-query result from being offered while it is being re-listed.
  const resolved = discoveryFresh && !discovering
  const options = useMemo(
    () => (resolved && discovery ? discovery.options : []),
    [resolved, discovery],
  )

  // The selected role: the user's explicit pick while it is still offered (recovered), else the first offered
  // role. A query change that drops the picked role falls back to the first, without forgetting the pick.
  const selectedRoleId = useMemo(() => pickRole(options, userChoice), [options, userChoice])

  // A query approval always runs under an elevation role R (execute-under-R), so a role must be selected
  // before submitting — there is no requester-run / no-elevation mode.
  const canSubmit = selectedRoleId != null && (fromDenied
    ? reason.trim().length > 0 && record?.decision === 'DENY'
    : datasourceId != null && sql.trim().length > 0 && title.trim().length > 0 && reason.trim().length > 0)

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!canSubmit) return
    setSubmitting(true)
    setSubmitError(null)
    try {
      const pickedRoleId = selectedRoleId != null ? Number(selectedRoleId) : undefined
      const res = fromDenied
        ? await createApproval({
            sourceDecisionId: sourceDecisionId!,
            title: title.trim() || undefined,
            reason: reason.trim(),
            roleId: pickedRoleId,
          })
        : await createApproval({
            datasourceId: datasourceId!,
            sql: sql.trim(),
            title: title.trim(),
            reason: reason.trim(),
            roleId: pickedRoleId,
          })
      if (res.wouldAllow) {
        toast.info(t('queryComposer.wouldAllowToast'))
      }
      void mutate(
        swrKeys.myApprovals(undefined),
        (requests: AccessRequest[] | undefined) => [
          res.request,
          ...(requests ?? []).filter((request) => request.id !== res.request.id),
        ],
        { revalidate: true },
      )
      void mutate(swrKeys.approvalInbox)
      onCreated(res.request)
    } catch (err) {
      setSubmitError(errorMessage(err))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div data-workflow-composer-kind="QUERY" className="space-y-4">
      {sourceDecisionError != null ? (
        <ErrorState error={sourceDecisionError} />
      ) : fromDenied && isLoading && !record ? (
        <LoadingState label={t('queryComposer.loadingDenied')} />
      ) : fromDenied && error ? (
        <ErrorState error={error} />
      ) : fromDenied && record && record.decision !== 'DENY' ? (
        <ErrorState error={t('queryComposer.onlyDeniedApproval')} />
      ) : (
        <form className="space-y-4" onSubmit={handleSubmit}>
          {fromDenied && record ? (
            <Card>
              <CardHeader>
                <CardTitle>{t('queryComposer.deniedDecisionTitle', { id: sourceDecisionId })}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
                      {t('fields.datasource')}
                    </p>
                    <p className="font-mono">{record.datasource}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
                      {t('fields.timestamp')}
                    </p>
                    <p className="font-mono">{formatTimestamp(record.ts)}</p>
                  </div>
                </div>
                <div>
                  <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
                    {t('fields.denyReason')}
                  </p>
                  <p className="mt-1 text-sm">{record.detail ?? '—'}</p>
                </div>
                <div>
                  <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
                    {t('fields.sql')}
                  </p>
                  <pre className="border-border bg-muted/40 text-foreground/90 mt-1 overflow-x-auto rounded-lg border p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words">
                    {record.statement}
                  </pre>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>{t('queryComposer.queryToReview')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-1.5">
                  <Label htmlFor="approval-datasource">{t('fields.datasource')}</Label>
                  <DatasourceSelect
                    id="approval-datasource"
                    value={datasourceId}
                    onChange={setDatasourceId}
                    size="default"
                    className="w-full"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="approval-sql">{t('fields.sql')}</Label>
                  <Textarea
                    id="approval-sql"
                    value={sql}
                    onChange={(e) => setSql(e.target.value)}
                    placeholder={'SELECT id, ssn FROM users WHERE id = 1;\nUPDATE users SET status = 1 WHERE id = 1;'}
                    rows={8}
                    required
                    className="font-mono text-xs"
                  />
                  <p className="text-muted-foreground text-xs">{t('queryComposer.sqlHint')}</p>
                </div>
              </CardContent>
            </Card>
          )}

          {canDiscover && (
            <Card>
              <CardHeader>
                <CardTitle>{t('fields.role')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {discoverError ? (
                  // A failed discovery is not a dead end: since a role must be picked to submit, offer an
                  // explicit retry for the unchanged query (editing the query re-runs discovery on its own).
                  <div className="flex items-center justify-between gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                    <span>{discoverError}</span>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => setRetryNonce((n) => n + 1)}
                    >
                      {t('queryComposer.retry')}
                    </Button>
                  </div>
                ) : options.length > 0 ? (
                  <div className="space-y-1.5">
                    <Label htmlFor="approval-role">{t('fields.role')}</Label>
                    {/* `value` must be the state itself, INCLUDING null. Passing `undefined` for the empty
                        case makes the Select uncontrolled, and it then discards every selection. `null` is
                        "controlled, nothing selected"; `undefined` is "not controlled at all". */}
                    <Select value={selectedRoleId} onValueChange={(value: string | null) => setUserChoice(value)}>
                      <SelectTrigger id="approval-role" className="w-full">
                        {/* The trigger renders the raw value unless given this mapping, which would show the
                            role's numeric id — the one thing the requester must not misread, since the request
                            is submitted to run under whichever role this names. */}
                        <SelectValue placeholder={t('queryComposer.selectRole')}>
                          {(value: string | null) =>
                            options.find((option) => String(option.roleId) === value)?.roleName ??
                            t('queryComposer.selectRole')
                          }
                        </SelectValue>
                      </SelectTrigger>
                      <SelectContent>
                        {options.map((option) => (
                          <SelectItem key={option.roleId} value={String(option.roleId)}>
                            <span className="flex flex-col gap-0.5">
                              <span>{option.roleName}</span>
                              {/* The outcome under this role, previewed in your context; the approver's
                                  execution context can narrow it further. */}
                              <span className="text-muted-foreground text-xs">
                                <span className={OUTCOME_TONE[option.decision]}>
                                  {t(`queryComposer.outcome.${option.decision}`)}
                                </span>
                                {option.maskedColumns.length > 0
                                  ? ` (${option.maskedColumns.join(', ')})`
                                  : ''}
                              </span>
                            </span>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                ) : (
                  <p className="text-muted-foreground text-sm">
                    {resolved ? t('queryComposer.noRolesFound') : t('queryComposer.discovering')}
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {submitError && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
              {submitError}
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="approval-title">
              {fromDenied ? t('queryComposer.titleOptional') : t('queryComposer.titleRequired')}
            </Label>
            <Input
              id="approval-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder={t('queryComposer.titlePlaceholder')}
              required={!fromDenied}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="approval-reason">{t('fields.reasonRequired')}</Label>
            <Textarea
              id="approval-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder={t('queryComposer.reasonPlaceholder')}
              rows={4}
              required
            />
          </div>

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onCancel} disabled={submitting}>
              {t('actions.cancel')}
            </Button>
            <Button type="submit" disabled={!canSubmit || submitting}>
              {submitting ? t('actions.submitting') : t('actions.submitRequest')}
            </Button>
          </div>
        </form>
      )}
    </div>
  )
}
