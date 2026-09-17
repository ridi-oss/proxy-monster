'use client'

// Inline column classifier. A Popover anchored on each
// catalog row: add free tags + optionally pick a mask function, then PUT
// .../classification; or DELETE to clear. Seeds from the existing
// classification each time the popover opens.

import { useEffect, useState } from 'react'
import { useTranslations } from 'next-intl'
import { Loader2 } from 'lucide-react'
import { deleteClassification, putClassification } from '@/lib/api/client'
import { mutate } from 'swr'
import { swrKeys, useMaskFns } from '@/lib/hooks'
import { toneForTags } from '@/lib/decision'
import type { CatalogColumn, Classification } from '@/lib/api/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { TagsInput } from '@/components/tags-input'
import { cn } from '@/lib/utils'

interface Props {
  datasourceId: number
  col: CatalogColumn
}

export function ClassifyPopover({ datasourceId, col }: Props) {
  const t = useTranslations('Datasources')
  const { data: maskFns } = useMaskFns()

  // Trigger label: a tags summary when tagged, else the mask-fn name for a mask-only classification,
  // else the "add" affordance. A classification can be mask-only (tags empty, mask fn set) — it's still
  // classified, so it must not read as unclassified ('+ classify').
  const triggerLabel = (cl: Classification | null | undefined): string => {
    if (!cl) return t('classify.triggerClassify')
    const tags = cl.tags ?? []
    if (tags.length === 1) return tags[0]
    if (tags.length > 1) return `${tags[0]} +${tags.length - 1}`
    if (cl.maskFnName) return t('classify.triggerMask', { name: cl.maskFnName })
    return t('classify.triggerClassified')
  }

  const [open, setOpen] = useState(false)
  const [tags, setTags] = useState<string[]>([])
  const [maskFnId, setMaskFnId] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Seed from existing classification each time the popover opens.
  useEffect(() => {
    if (!open) return
    setError(null)
    if (col.classification) {
      setTags(col.classification.tags ?? [])
      setMaskFnId(col.classification.maskFnId != null ? String(col.classification.maskFnId) : null)
    } else {
      setTags([])
      setMaskFnId(null)
    }
  }, [open, col.classification])

  const handleSave = async () => {
    setBusy(true)
    setError(null)
    try {
      await putClassification(datasourceId, {
        catalog: col.catalog,
        schema: col.schema,
        table: col.table,
        column: col.column,
        tags,
        maskFnId: maskFnId != null ? Number(maskFnId) : null,
      })
      await mutate(swrKeys.catalog(datasourceId))
      setOpen(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('classify.classifyFailed'))
    } finally {
      setBusy(false)
    }
  }

  const handleClear = async () => {
    setBusy(true)
    setError(null)
    try {
      await deleteClassification(datasourceId, {
        catalog: col.catalog,
        schema: col.schema,
        table: col.table,
        column: col.column,
      })
      await mutate(swrKeys.catalog(datasourceId))
      setOpen(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('classify.clearFailed'))
    } finally {
      setBusy(false)
    }
  }

  const currentTags = col.classification?.tags ?? []

  return (
    <Popover open={open} onOpenChange={setOpen}>
      {/* Trigger: tags summary badge or plain "add" text */}
      <PopoverTrigger
        nativeButton={false}
        render={
          col.classification ? (
            <Badge
              className={cn('cursor-pointer border font-mono text-[10px]', toneForTags(currentTags))}
            />
          ) : (
            <span className="text-muted-foreground hover:text-foreground cursor-pointer text-xs transition-colors" />
          )
        }
      >
        {triggerLabel(col.classification)}
      </PopoverTrigger>

      <PopoverContent side="bottom" align="end" className="w-72 p-3">
        <div className="space-y-3">
          {/* Column identifier header */}
          <p className="text-muted-foreground font-mono text-xs">
            {col.table}.{col.column}
          </p>

          {/* Tags */}
          <div className="space-y-1.5">
            <Label className="text-xs">{t('classify.labelTags')}</Label>
            <TagsInput
              value={tags}
              onChange={setTags}
              placeholder={t('classify.tagsPlaceholder')}
              className="text-xs"
            />
          </div>

          {/* Mask function — optional transform applied when this column is masked */}
          <div className="space-y-1.5">
            <Label className="text-xs">{t('classify.labelMaskFn')}</Label>
            <Select value={maskFnId} onValueChange={(v: string | null) => setMaskFnId(v)}>
              <SelectTrigger className="w-full" size="sm">
                <SelectValue placeholder={t('classify.maskFnNone')}>
                  {(v: string | null) =>
                    v
                      ? (maskFns?.find((m) => String(m.id) === v)?.name ?? '')
                      : t('classify.maskFnNone')
                  }
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={null}>{t('classify.maskFnNone')}</SelectItem>
                {(maskFns ?? []).map((m) => (
                  <SelectItem key={m.id} value={String(m.id)}>
                    {m.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {error && <p className="text-xs text-red-500">{error}</p>}

          {/* Actions */}
          <div className="flex items-center justify-between pt-1">
            {col.classification ? (
              <Button
                variant="ghost"
                size="xs"
                className="text-destructive hover:text-destructive"
                onClick={handleClear}
                disabled={busy}
              >
                {t('classify.clear')}
              </Button>
            ) : (
              <span />
            )}
            <div className="flex gap-1.5">
              <Button variant="outline" size="xs" onClick={() => setOpen(false)} disabled={busy}>
                {t('classify.cancel')}
              </Button>
              <Button size="xs" onClick={handleSave} disabled={busy}>
                {busy && <Loader2 className="size-3 animate-spin" />}
                {t('classify.save')}
              </Button>
            </div>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  )
}
