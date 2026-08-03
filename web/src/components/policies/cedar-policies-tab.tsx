'use client'

// Cedar policies tab — author/validate/enable/disable the Cedar policy source
// rows evaluated by the control-plane's authz decision service (authorize()/
// authorizeColumns()/authorizeDatasourceAction()) against the union of enabled
// rows here — the full action set (ACTION_REFERENCE below), not just admin.*/
// task.*: admin.*, task lifecycle, result.read.{unmasked,masked} (per-column),
// datasource.connect + sql.{select,insert,update,delete,ddl} (per-statement).
// The source editor uses @ridi/codemirror-lang-cedar for Cedar syntax
// highlighting + keyword completion; server-side validation stays on the
// Validate button, while cedar-wasm drives the client-side linter and
// schema-aware completion.
import { Fragment, useMemo, useState } from 'react'
import { useTranslations } from 'next-intl'
import { useTheme } from 'next-themes'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView, tooltips } from '@codemirror/view'
import { cedar, cedarCompletion, cedarLinter } from '@ridi/codemirror-lang-cedar'
import { useCedarWasm } from '@/lib/cedar-wasm'
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Loader2,
  Pencil,
  Plus,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { mutate } from 'swr'
import {
  createCedarPolicy,
  deleteCedarPolicy,
  setCedarPolicyEnabled,
  updateCedarPolicy,
  validateCedarPolicy,
} from '@/lib/api/client'
import { useCedarPolicies, useCedarSchema, swrKeys } from '@/lib/hooks'
import type { CedarPolicy, CedarPolicyInput } from '@/lib/api/types'
import { editorTheme } from '@/lib/cm-theme'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { EmptyState, ErrorState, LoadingState } from '@/components/page-scaffold'
import { toast } from 'sonner'

const PLACEHOLDER =
  'permit(\n  principal in Role::"analyst",\n  action in [Action::"datasource.connect", Action::"sql.select"],\n  resource in Datasource::"acme-mysql"\n);'

/** The full Cedar action set (docs/authz-model.md), grouped by the resource each applies to —
 *  shown inline next to the source editor so an admin isn't guessing action names from memory.
 *  noteKey resolves to a Policies.cedarPolicies.actionNotes.* translation at render. */
const ACTION_REFERENCE: { resource: string; actions: { name: string; noteKey: string }[] }[] = [
  {
    resource: 'System',
    actions: [
      { name: 'admin.datasources', noteKey: 'adminDatasources' },
      { name: 'admin.policies', noteKey: 'adminPolicies' },
      { name: 'admin.identity', noteKey: 'adminIdentity' },
    ],
  },
  {
    resource: 'Request (in Datasource, in Role)',
    actions: [
      { name: 'task.approve', noteKey: 'taskApprove' },
      { name: 'task.read', noteKey: 'taskRead' },
      { name: 'task.assume', noteKey: 'taskAssume' },
      { name: 'task.cancel', noteKey: 'taskCancel' },
      { name: 'task.delete', noteKey: 'taskDelete' },
    ],
  },
  {
    resource: 'AccessGrant',
    actions: [
      { name: 'task.read', noteKey: 'taskRead' },
      { name: 'grant.revoke', noteKey: 'grantRevoke' },
    ],
  },
  {
    resource: 'Column (in Table, in Tag)',
    actions: [
      { name: 'result.read.unmasked', noteKey: 'resultReadUnmasked' },
      { name: 'result.read.masked', noteKey: 'resultReadMasked' },
    ],
  },
  {
    resource: 'Datasource',
    actions: [
      { name: 'task.request', noteKey: 'taskRequest' },
      { name: 'datasource.connect', noteKey: 'datasourceConnect' },
      { name: 'sql.select', noteKey: 'sqlSelect' },
      { name: 'sql.insert', noteKey: 'sqlInsert' },
      { name: 'sql.update', noteKey: 'sqlUpdate' },
      { name: 'sql.delete', noteKey: 'sqlDelete' },
      { name: 'sql.ddl', noteKey: 'sqlDdl' },
    ],
  },
]

/**
 * Read-only Cedar source, highlighted with the same language package the edit dialog uses
 * (@ridi/codemirror-lang-cedar) so a policy reads identically wherever it appears. Line wrapping is
 * required, not cosmetic: a single-line policy would otherwise set the editor's min-content width and
 * push the table sideways.
 */
function CedarSource({ src }: { src: string }) {
  const { resolvedTheme } = useTheme()
  const extensions = useMemo(
    () => [
      editorTheme(resolvedTheme),
      cedar(),
      EditorView.lineWrapping,
      EditorView.editable.of(false),
    ],
    [resolvedTheme],
  )
  return (
    <CodeMirror
      value={src}
      // theme="none" (as the editor dialog and sql-editor do): without it @uiw/react-codemirror layers
      // its own LIGHT default on top of editorTheme, so the surface goes white under dark foreground.
      theme="none"
      extensions={extensions}
      editable={false}
      basicSetup={{
        lineNumbers: false,
        foldGutter: false,
        highlightActiveLine: false,
        highlightActiveLineGutter: false,
        autocompletion: false,
        searchKeymap: false,
      }}
      className="overflow-hidden rounded-lg border px-2 text-xs"
    />
  )
}

export function CedarPoliciesTab() {
  const t = useTranslations('Policies')
  const { data, error, isLoading } = useCedarPolicies()
  const [editing, setEditing] = useState<CedarPolicy | null>(null)
  const [creating, setCreating] = useState(false)
  // Policy pending deletion — show inline confirm row
  const [deleting, setDeleting] = useState<CedarPolicy | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [deleteBusy, setDeleteBusy] = useState(false)
  const [togglingId, setTogglingId] = useState<number | null>(null)
  // Ids whose source row is expanded. Source is hidden by default: a page of policies is a list to
  // scan, and every source shown at once buries the names.
  const [expanded, setExpanded] = useState<ReadonlySet<number>>(() => new Set())

  const allExpanded = !!data && data.length > 0 && data.every((p) => expanded.has(p.id))
  const toggleExpanded = (id: number) =>
    setExpanded((prev) => {
      const next = new Set(prev)
      if (!next.delete(id)) next.add(id)
      return next
    })

  const handleDelete = async (policy: CedarPolicy) => {
    setDeleteBusy(true)
    setDeleteError(null)
    try {
      await deleteCedarPolicy(policy.id)
      await mutate(swrKeys.cedarPolicies)
      setDeleting(null)
      toast.success(t('cedarPolicies.toastDeleted', { name: policy.name }))
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : t('cedarPolicies.deleteFailed'))
    } finally {
      setDeleteBusy(false)
    }
  }

  const handleToggle = async (policy: CedarPolicy, enabled: boolean) => {
    setTogglingId(policy.id)
    try {
      await setCedarPolicyEnabled(policy.id, enabled)
      await mutate(swrKeys.cedarPolicies)
      toast.success(
        enabled
          ? t('cedarPolicies.toastEnabled', { name: policy.name })
          : t('cedarPolicies.toastDisabled', { name: policy.name }),
      )
    } catch (err) {
      toast.error(t('cedarPolicies.toggleFailed'), {
        description: err instanceof Error ? err.message : 'error',
      })
    } finally {
      setTogglingId(null)
    }
  }

  return (
    <div className="space-y-4">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <p className="text-muted-foreground text-sm">{t('cedarPolicies.blurb')}</p>
        <div className="flex shrink-0 items-center gap-2">
          {!!data && data.length > 0 && (
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                setExpanded(allExpanded ? new Set() : new Set(data.map((p) => p.id)))
              }
            >
              {allExpanded ? (
                <ChevronRight className="size-3.5" />
              ) : (
                <ChevronDown className="size-3.5" />
              )}
              {allExpanded ? t('cedarPolicies.hideAllSource') : t('cedarPolicies.showAllSource')}
            </Button>
          )}
          <Button size="sm" onClick={() => setCreating(true)}>
            <Plus className="size-3.5" />
            {t('cedarPolicies.add')}
          </Button>
        </div>
      </div>

      {isLoading && !data ? (
        <LoadingState label={t('cedarPolicies.loading')} />
      ) : error ? (
        <ErrorState error={error} />
      ) : !data || data.length === 0 ? (
        <EmptyState
          title={t('cedarPolicies.emptyTitle')}
          hint={t('cedarPolicies.emptyHint')}
          icon={<ShieldCheck className="size-8" />}
          action={
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus className="size-3.5" />
              {t('cedarPolicies.add')}
            </Button>
          }
        />
      ) : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('common.name')}</TableHead>
                <TableHead className="w-20">{t('cedarPolicies.colEnabled')}</TableHead>
                <TableHead>{t('cedarPolicies.colUpdatedBy')}</TableHead>
                <TableHead>{t('cedarPolicies.colUpdatedAt')}</TableHead>
                <TableHead className="w-[120px] text-right">{t('common.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((policy) => {
                const isSystem = policy.origin === 'SYSTEM'
                return (
                <Fragment key={policy.id}>
                  <TableRow
                    className="cursor-pointer"
                    onClick={() => toggleExpanded(policy.id)}
                    aria-expanded={expanded.has(policy.id)}
                    aria-label={
                      expanded.has(policy.id)
                        ? t('cedarPolicies.hideSourceAria')
                        : t('cedarPolicies.showSourceAria')
                    }
                  >
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {expanded.has(policy.id) ? (
                          <ChevronDown className="text-muted-foreground size-3.5 shrink-0" />
                        ) : (
                          <ChevronRight className="text-muted-foreground size-3.5 shrink-0" />
                        )}
                        <code className="font-mono text-sm font-semibold">{policy.name}</code>
                        {isSystem && (
                          <Tooltip>
                            <TooltipTrigger
                              render={
                                <Badge variant="secondary" className="cursor-default gap-1 font-normal" />
                              }
                            >
                              <ShieldCheck className="size-3" />
                              {t('cedarPolicies.systemBadge')}
                            </TooltipTrigger>
                            <TooltipContent>
                              {t('cedarPolicies.systemManagedHint', { key: policy.systemKey ?? '' })}
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </div>
                    </TableCell>
                    {/* The controls below live inside a row whose click expands the source, so each
                        stops propagation — toggling a policy or opening its editor must not also
                        expand it. */}
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Switch
                        size="sm"
                        checked={policy.enabled}
                        onCheckedChange={(checked) => handleToggle(policy, checked)}
                        disabled={togglingId === policy.id}
                        aria-label={
                          policy.enabled
                            ? t('cedarPolicies.disableAria')
                            : t('cedarPolicies.enableAria')
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <span
                        className={cn('text-sm', !policy.updatedBy && 'text-muted-foreground italic')}
                      >
                        {policy.updatedBy || '—'}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-muted-foreground text-xs">
                        {new Date(policy.updatedAt).toLocaleString()}
                      </span>
                    </TableCell>
                    <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                      {isSystem ? (
                        // SYSTEM policies are migration-owned + immutable through the API except
                        // enable/disable (the Switch above). No edit/delete — the backend 409s them anyway;
                        // the console mirrors that so an admin isn't offered an action that can't succeed.
                        <span className="text-muted-foreground text-xs italic">
                          {t('cedarPolicies.systemManaged')}
                        </span>
                      ) : (
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            size="icon-xs"
                            variant="ghost"
                            onClick={() => {
                              setDeleting(null)
                              setEditing(policy)
                            }}
                            aria-label={t('common.edit')}
                          >
                            <Pencil className="size-3.5" />
                          </Button>
                          <Button
                            size="icon-xs"
                            variant="ghost"
                            className="text-destructive hover:text-destructive"
                            onClick={() => {
                              setEditing(null)
                              setDeleteError(null)
                              setDeleting((prev) => (prev?.id === policy.id ? null : policy))
                            }}
                            aria-label={t('common.delete')}
                          >
                            <Trash2 className="size-3.5" />
                          </Button>
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                  {/* The policy source, on its own full-width row. The Cedar text IS the policy — the
                      columns above are metadata about it — so reading the table without it means opening
                      an edit dialog per row to answer "what does this actually permit". */}
                  {expanded.has(policy.id) && (
                    <TableRow className="hover:bg-transparent">
                      <TableCell colSpan={5} className="pt-2 pb-2">
                        <CedarSource src={policy.cedarSrc} />
                      </TableCell>
                    </TableRow>
                  )}
                  {/* Inline delete confirm row */}
                  {deleting?.id === policy.id && (
                    <TableRow key={`${policy.id}-confirm`} className="bg-red-500/5">
                      <TableCell colSpan={5}>
                        <div className="flex flex-wrap items-center justify-between gap-2 py-0.5">
                          <div>
                            <p className="text-sm font-medium text-red-500">
                              {t('cedarPolicies.deleteConfirm', { name: policy.name })}
                            </p>
                            <p className="text-muted-foreground text-xs">
                              {t('cedarPolicies.deleteConsequence')}
                            </p>
                            {deleteError && (
                              <p className="mt-1 text-xs text-red-500">{deleteError}</p>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            <Button
                              size="xs"
                              variant="outline"
                              onClick={() => setDeleting(null)}
                              disabled={deleteBusy}
                            >
                              {t('common.cancel')}
                            </Button>
                            <Button
                              size="xs"
                              variant="destructive"
                              onClick={() => handleDelete(policy)}
                              disabled={deleteBusy}
                            >
                              {deleteBusy ? (
                                <Loader2 className="size-3 animate-spin" />
                              ) : null}
                              {t('common.delete')}
                            </Button>
                          </div>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Create / edit dialog */}
      {(creating || editing !== null) && (
        <CedarPolicyDialog
          editing={editing}
          onClose={() => {
            setCreating(false)
            setEditing(null)
          }}
          // The schema carries the context.tag actions the stored policies derive, so a save can change
          // it — refetch, or editors opened afterwards lint against a stale vocabulary.
          onSaved={() => {
            mutate(swrKeys.cedarPolicies)
            mutate(swrKeys.cedarSchema)
          }}
        />
      )}
    </div>
  )
}

// ---- Cedar policy dialog -----------------------------------------------------

function CedarPolicyDialog({
  editing,
  onClose,
  onSaved,
}: {
  editing: CedarPolicy | null
  onClose: () => void
  onSaved: () => void
}) {
  const t = useTranslations('Policies')
  const { resolvedTheme } = useTheme()
  // Lazily load the Cedar WASM (~4MB) now that the editor dialog is open, for live
  // syntax linting. null until ready — the editor works without it until then.
  const cedarWasm = useCedarWasm(true)
  // The authz schema enables in-editor type validation + schema-aware completion.
  const storedSchema = useCedarSchema().data?.schema
  const [name, setName] = useState(editing?.name ?? '')
  const [cedarSrc, setCedarSrc] = useState(editing?.cedarSrc ?? '')
  const [enabled, setEnabled] = useState(editing?.enabled ?? true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [validating, setValidating] = useState(false)
  // Non-null once a Validate run has completed; empty array = valid.
  const [validationErrors, setValidationErrors] = useState<string[] | null>(null)

  const valid = name.trim().length > 0 && cedarSrc.trim().length > 0

  // The served schema declares the context.tag actions the STORED policies derive, so a tag name being
  // typed here — a new one, or a rename — is not in it yet and lints as an undeclared action even though
  // the server accepts it (it self-augments from the candidate). Declare the draft's own names too, so
  // the editor agrees with what Validate and Save will say. Mirrors CedarSchema.schemaTextFor.
  const cedarSchema = useMemo(() => {
    if (!storedSchema) return storedSchema
    const declared = new Set(
      [...storedSchema.matchAll(/action "context\.tag::([^"]+)"/g)].map((m) => m[1]),
    )
    const drafted = [...cedarSrc.matchAll(/Action::"context\.tag::([^"]+)"/g)]
      .map((m) => m[1])
      .filter((n) => !declared.has(n))
    if (drafted.length === 0) return storedSchema
    return `${storedSchema}\n${[...new Set(drafted)]
      .map(
        (n) =>
          `action "context.tag::${n}" appliesTo { principal: [User, Role], resource: [Datasource], ` +
          `context: { channel?: String, requester_ip?: ipaddr, tailscale_caps?: Set<String> } };`,
      )
      .join('\n')}`
  }, [storedSchema, cedarSrc])

  // Stable across keystrokes — see sql-editor.tsx: a fresh array here would
  // reconfigure the whole editor on every render.
  // Cedar language support (@ridi/codemirror-lang-cedar): syntax highlighting +
  // keyword completion. cedarCompletion is attached via the language's data facet
  // so basicSetup's autocompletion machinery (keymap, auto-trigger) drives it.
  const extensions = useMemo(() => {
    const lang = cedar()
    // Completion is keyword-only until the WASM + authz schema load, then schema-aware
    // (entity types, action ids, attributes). Attached via the language data facet so
    // basicSetup's autocompletion machinery (keymap, auto-trigger) drives it.
    // Schema-aware: entity types, action ids, and attributes when the schema is
    // present. (Known gap: action-id completion inside `Action::"…"` returns the
    // right options but CodeMirror doesn't render the popup for an in-string
    // completion; entity/attribute completion and everything else work.)
    const completion =
      cedarWasm && cedarSchema
        ? cedarCompletion({ cedar: cedarWasm, schema: cedarSchema })
        : cedarCompletion()
    const exts = [
      editorTheme(resolvedTheme),
      lang,
      lang.language.data.of({ autocomplete: completion }),
      // Lint/completion tooltips render into document.body, not the editor's parent: the editor sits in
      // an overflow-hidden, rounded container inside the dialog, which clips a tooltip near its edge.
      tooltips({ parent: typeof document === 'undefined' ? undefined : document.body }),
      // Wrap long policy lines (like sql-editor.tsx). Without this a long single-line
      // policy sets the editor's min-content width, and DialogContent's grid track
      // grows past the dialog card — the header/footer paint outside the modal.
      EditorView.lineWrapping,
    ]
    // Live linting once the WASM has loaded — precise syntax error ranges, plus strict
    // schema type-validation (unknown action, wrong attribute) once the schema loads.
    if (cedarWasm) {
      exts.push(
        cedarLinter(
          cedarSchema
            ? { cedar: cedarWasm, schema: cedarSchema, delay: 400 }
            : { cedar: cedarWasm, delay: 400 },
        ),
      )
    }
    return exts
  }, [resolvedTheme, cedarWasm, cedarSchema])

  const handleValidate = async () => {
    setValidating(true)
    setError(null)
    try {
      const res = await validateCedarPolicy(cedarSrc)
      setValidationErrors(res.errors)
      if (res.errors.length === 0) toast.success(t('cedarPolicies.validSource'))
    } catch (err) {
      setValidationErrors(null)
      setError(err instanceof Error ? err.message : t('cedarPolicies.validateFailed'))
    } finally {
      setValidating(false)
    }
  }

  const handleSave = async () => {
    if (!valid) return
    setBusy(true)
    setError(null)
    const input: CedarPolicyInput = { name: name.trim(), cedarSrc, enabled }
    try {
      if (editing) {
        await updateCedarPolicy(editing.id, input)
        toast.success(t('cedarPolicies.toastUpdated', { name: input.name }))
      } else {
        await createCedarPolicy(input)
        toast.success(t('cedarPolicies.toastCreated', { name: input.name }))
      }
      onSaved()
      onClose()
    } catch (err) {
      // The control-plane's 400 body carries the Cedar parse/validation message.
      setError(err instanceof Error ? err.message : t('cedarPolicies.saveFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {editing
              ? t('cedarPolicies.dialogEditTitle', { name: editing.name })
              : t('cedarPolicies.dialogAddTitle')}
          </DialogTitle>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        {validationErrors && validationErrors.length > 0 && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            <p className="font-medium">{t('cedarPolicies.validationFailed')}</p>
            <ul className="mt-1 list-disc space-y-0.5 pl-4">
              {validationErrors.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          </div>
        )}

        {validationErrors && validationErrors.length === 0 && (
          <div className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="size-3.5" />
            {t('cedarPolicies.validSource')}
          </div>
        )}

        <div className="space-y-4 py-1">
          <div className="flex items-end gap-4">
            <div className="flex-1 space-y-1.5">
              <Label htmlFor="cedar-name">{t('common.name')}</Label>
              <Input
                id="cedar-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="admin-write-team"
                autoFocus
                required
              />
            </div>
            <div className="flex items-center gap-2 pb-2">
              <Switch id="cedar-enabled" checked={enabled} onCheckedChange={setEnabled} />
              <Label htmlFor="cedar-enabled" className="text-sm font-normal">
                {t('cedarPolicies.enabledLabel')}
              </Label>
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <Label htmlFor="cedar-src">{t('cedarPolicies.sourceLabel')}</Label>
              <Button
                type="button"
                size="xs"
                variant="outline"
                onClick={handleValidate}
                disabled={validating || cedarSrc.trim().length === 0}
              >
                {validating ? (
                  <Loader2 className="size-3 animate-spin" />
                ) : (
                  <CheckCircle2 className="size-3" />
                )}
                {t('cedarPolicies.validate')}
              </Button>
            </div>
            <div id="cedar-src" className="overflow-hidden rounded-lg border">
              <CodeMirror
                value={cedarSrc}
                onChange={(v) => {
                  setCedarSrc(v)
                  setValidationErrors(null)
                }}
                theme="none"
                extensions={extensions}
                height="240px"
                style={{ fontSize: 13 }}
                placeholder={PLACEHOLDER}
                basicSetup={{ lineNumbers: true, foldGutter: false, highlightActiveLine: true }}
              />
            </div>
            <p className="text-muted-foreground text-xs">{t('cedarPolicies.sourceHint')}</p>
          </div>

          <details className="group rounded-lg border">
            <summary className="cursor-pointer list-none px-3 py-2 text-xs font-medium text-muted-foreground select-none">
              {t('cedarPolicies.actionReference')}{' '}
              <span className="text-muted-foreground/60">{t('cedarPolicies.clickToExpand')}</span>
            </summary>
            <div className="space-y-3 border-t px-3 py-3">
              {ACTION_REFERENCE.map((group) => (
                <div key={group.resource} className="space-y-1">
                  <p className="font-mono text-[11px] text-muted-foreground">
                    resource: <span className="text-foreground">{group.resource}</span>
                  </p>
                  <ul className="space-y-0.5 pl-3">
                    {group.actions.map((a) => (
                      <li key={a.name} className="flex items-baseline gap-2 text-xs">
                        <code className="shrink-0 font-mono text-[11px]">{a.name}</code>
                        <span className="text-muted-foreground">
                          — {t(`cedarPolicies.actionNotes.${a.noteKey}`)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </details>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button onClick={handleSave} disabled={!valid || busy}>
            {busy ? <Loader2 className="size-3.5 animate-spin" /> : null}
            {editing ? t('common.save') : t('cedarPolicies.add')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
