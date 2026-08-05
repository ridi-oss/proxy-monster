'use client'

// Add / edit a datasource (docs/datasource-registration.md). This is OPTIONAL pre-provisioning: only the name is
// required. The connection fields (host/port/database) are advisory — the proxy is authoritative and
// overwrites them when it registers — and there are NO credential fields: the control-plane never dials
// a target, so it stores no secret. The form key forces a full remount on each open so state initialises
// cleanly without an explicit reset effect.

import { useEffect, useState } from 'react'
import { useTranslations } from 'next-intl'
import { Loader2 } from 'lucide-react'
import { createDatasource, updateDatasource } from '@/lib/api/client'
import { mutate } from 'swr'
import { swrKeys } from '@/lib/hooks'
import type { CatalogAdoption, Datasource, DatasourceInput, Engine } from '@/lib/api/types'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

const DEFAULT_PORT: Record<Engine, number> = { postgres: 5432, mysql: 3306 }

/** The unset adoption mode. A select needs a value for it, and '' would submit as a blank string. */
const ADOPTION_ENGINE_DEFAULT = 'default'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** null = create mode; a Datasource = edit mode. */
  editing: Datasource | null
}

export function DatasourceFormDialog({ open, onOpenChange, editing }: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        {open && (
          // Remount the form when the dialog opens so state seeds cleanly.
          <DatasourceForm
            key={editing ? `edit-${editing.id}` : 'create'}
            editing={editing}
            onClose={() => onOpenChange(false)}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

function DatasourceForm({
  editing,
  onClose,
}: {
  editing: Datasource | null
  onClose: () => void
}) {
  const t = useTranslations('Datasources')
  const [name, setName] = useState(editing?.name ?? '')
  const [engine, setEngine] = useState<Engine>((editing?.engine as Engine) ?? 'postgres')
  const [host, setHost] = useState(editing?.host ?? '')
  const [port, setPort] = useState<string>(String(editing?.port ?? DEFAULT_PORT.postgres))
  const [dbName, setDbName] = useState(editing?.dbName ?? '')
  // Seeded from the current value the same way engine is, so an ordinary edit carries the mode unchanged
  // and only a deliberate switch to the default clears it.
  const [adoption, setAdoption] = useState<string>(
    editing?.catalogAdoption ?? ADOPTION_ENGINE_DEFAULT,
  )
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Auto-fill port default when engine changes in create mode.
  useEffect(() => {
    if (!editing) setPort(String(DEFAULT_PORT[engine]))
  }, [engine, editing])

  const portNum = Number(port)
  // Only the name is required — connection details are advisory pre-provisioning (the proxy fills them
  // in authoritatively on registration). The port still has to be a sensible number when present.
  const valid = name.trim() !== '' && portNum > 0 && portNum <= 65535

  const handleSubmit = async () => {
    if (!valid) return
    setSaving(true)
    setError(null)
    const input: DatasourceInput = {
      name: name.trim(),
      engine,
      host: host.trim(),
      port: portNum,
      dbName: dbName.trim(),
      catalogAdoption:
        adoption === ADOPTION_ENGINE_DEFAULT ? null : (adoption as CatalogAdoption),
    }
    try {
      if (editing) {
        await updateDatasource(editing.id, input)
      } else {
        await createDatasource(input)
      }
      await mutate(swrKeys.datasources)
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('form.saveFailed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>
          {editing ? t('form.editTitle', { name: editing.name }) : t('form.addTitle')}
        </DialogTitle>
        <DialogDescription>
          {editing ? t('form.editDescription') : t('form.addDescription')}
        </DialogDescription>
      </DialogHeader>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
          {error}
        </div>
      )}

      <div className="space-y-3 py-1">
        {/* Name */}
        <div className="space-y-1.5">
          <Label htmlFor="ds-name">{t('form.labelName')}</Label>
          <Input
            id="ds-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="prod-pg"
            autoFocus
            required
          />
        </div>

        {/* Engine + Port (side by side) */}
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label>{t('form.labelEngine')}</Label>
            {/* Engine is immutable after creation: a stored catalog can't be reinterpreted under a
                different dialect. Disable it in edit mode — the server rejects a change anyway. */}
            <Select
              value={engine}
              onValueChange={(v: string | null) => setEngine((v as Engine) ?? 'postgres')}
              disabled={editing !== null}
            >
              <SelectTrigger size="sm" className="w-full">
                <SelectValue>
                  {(v: string | null) => (v === 'mysql' ? 'MySQL' : 'PostgreSQL')}
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="postgres">PostgreSQL</SelectItem>
                <SelectItem value="mysql">MySQL</SelectItem>
              </SelectContent>
            </Select>
            {editing && (
              <p className="text-muted-foreground text-xs">{t('form.engineImmutableHint')}</p>
            )}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ds-port">{t('form.labelPort')}</Label>
            <Input
              id="ds-port"
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(e.target.value)}
              required
            />
          </div>
        </div>

        {/* Host */}
        <div className="space-y-1.5">
          <Label htmlFor="ds-host">{t('form.labelHost')}</Label>
          <Input
            id="ds-host"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="db.internal"
          />
        </div>

        {/* Database */}
        <div className="space-y-1.5">
          <Label htmlFor="ds-db">{t('form.labelDatabase')}</Label>
          <Input
            id="ds-db"
            value={dbName}
            onChange={(e) => setDbName(e.target.value)}
            placeholder="acme"
          />
        </div>

        {/* Catalog adoption */}
        <div className="space-y-1.5">
          <Label>{t('form.labelCatalogAdoption')}</Label>
          <Select value={adoption} onValueChange={(v: string | null) => setAdoption(v ?? ADOPTION_ENGINE_DEFAULT)}>
            <SelectTrigger size="sm" className="w-full">
              <SelectValue>
                {(v: string | null) =>
                  v === 'verify'
                    ? t('form.catalogAdoptionVerify')
                    : v === 'trust'
                      ? t('form.catalogAdoptionTrust')
                      : t('form.catalogAdoptionDefault', {
                          engine: engine === 'mysql' ? 'MySQL' : 'PostgreSQL',
                          mode: engine === 'mysql' ? 'trust' : 'verify',
                        })
                }
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ADOPTION_ENGINE_DEFAULT}>
                {t('form.catalogAdoptionDefault', {
                  engine: engine === 'mysql' ? 'MySQL' : 'PostgreSQL',
                  mode: engine === 'mysql' ? 'trust' : 'verify',
                })}
              </SelectItem>
              <SelectItem value="verify">{t('form.catalogAdoptionVerify')}</SelectItem>
              <SelectItem value="trust">{t('form.catalogAdoptionTrust')}</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-muted-foreground text-xs">{t('form.catalogAdoptionHint')}</p>
        </div>

        <p className="text-muted-foreground text-xs">{t('form.advisoryHint')}</p>
      </div>

      <DialogFooter>
        <Button variant="outline" onClick={onClose} disabled={saving}>
          {t('form.cancel')}
        </Button>
        <Button onClick={handleSubmit} disabled={!valid || saving}>
          {saving && <Loader2 className="size-3.5 animate-spin" />}
          {editing ? t('form.submitEdit') : t('form.submitCreate')}
        </Button>
      </DialogFooter>
    </>
  )
}
