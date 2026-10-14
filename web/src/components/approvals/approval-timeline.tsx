'use client'

import { useState } from 'react'
import { useTranslations } from 'next-intl'
import { toast } from 'sonner'
import { X } from 'lucide-react'
import { addApprovalCc, commentOnApproval, removeApprovalCc } from '@/lib/api/client'
import type { QueryRequestDetail, RequestEvent } from '@/lib/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'

function errorText(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback
}

function EventLine({ event }: { event: RequestEvent }) {
  const t = useTranslations('Workflows')
  const when = new Date(event.createdAt).toLocaleString()
  if (event.kind === 'comment' || event.kind === 'lgtm') {
    return (
      <li className="space-y-1" data-testid={`timeline-${event.kind}`}>
        <div className="text-muted-foreground flex flex-wrap items-center gap-1 text-xs">
          <span className="text-foreground font-medium">{event.actor}</span>
          {event.kind === 'lgtm' && (
            <span className="rounded-full bg-emerald-500/15 px-1.5 font-semibold text-emerald-600 dark:text-emerald-400">
              {t('timeline.lgtmBadge')}
            </span>
          )}
          <span>· {when}</span>
          {event.origin === 'slack' && <span>· {t('timeline.viaSlack')}</span>}
        </div>
        {event.body && <p className="text-sm whitespace-pre-wrap break-words">{event.body}</p>}
      </li>
    )
  }
  const text = t(`timeline.events.${event.kind}`, { body: event.body ?? '', revision: event.revision ?? 1 })
  return (
    <li className="text-muted-foreground text-xs" data-testid={`timeline-${event.kind}`}>
      {event.actor && <span className="text-foreground font-medium">{event.actor} </span>}
      {text} · {when}
    </li>
  )
}

/** A request's comments, LGTMs, CCs, and state changes, oldest first. */
export function ApprovalTimeline({
  id,
  detail,
  principal,
  onChanged,
}: {
  id: number
  detail: QueryRequestDetail
  principal?: string
  onChanged: () => void
}) {
  const t = useTranslations('Workflows')
  const [body, setBody] = useState('')
  const [cc, setCc] = useState('')
  const [busy, setBusy] = useState<'comment' | 'lgtm' | 'cc' | null>(null)
  const ccs = detail.request.ccs ?? []
  const isRequester = detail.request.principal === principal

  const run = async (kind: 'comment' | 'lgtm' | 'cc', action: () => Promise<unknown>, after: () => void) => {
    setBusy(kind)
    try {
      await action()
      after()
      onChanged()
    } catch (err) {
      toast.error(errorText(err, t('timeline.failed')))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="space-y-4 border-t pt-4" data-testid="approval-timeline">
      <div className="space-y-2">
        <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">{t('timeline.ccs')}</p>
        <div className="flex flex-wrap items-center gap-2">
          {ccs.length === 0 && <span className="text-muted-foreground text-sm">—</span>}
          {ccs.map((p) => (
            <span key={p} className="bg-muted inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-xs">
              {p}
              {detail.canCc && (
                <button
                  type="button"
                  aria-label={t('timeline.removeCc', { principal: p })}
                  disabled={busy !== null}
                  onClick={() => run('cc', () => removeApprovalCc(id, p), () => {})}
                >
                  <X className="size-3" />
                </button>
              )}
            </span>
          ))}
        </div>
        {detail.canCc && (
          <form
            className="flex max-w-md gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              if (cc.trim()) void run('cc', () => addApprovalCc(id, cc.trim()), () => setCc(''))
            }}
          >
            <Input
              id="approval-cc"
              value={cc}
              onChange={(e) => setCc(e.target.value)}
              placeholder={t('timeline.ccPlaceholder')}
              aria-label={t('timeline.ccPlaceholder')}
            />
            <Button type="submit" variant="outline" size="sm" disabled={!cc.trim() || busy !== null}>
              {t('timeline.addCc')}
            </Button>
          </form>
        )}
      </div>

      <div className="space-y-2">
        <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">{t('timeline.heading')}</p>
        <ol className="space-y-3">
          {(detail.timeline ?? []).map((event) => (
            <EventLine key={event.id} event={event} />
          ))}
        </ol>
      </div>

      {detail.canComment && (
        <div className="space-y-2">
          <Textarea
            id="approval-comment"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder={t('timeline.commentPlaceholder')}
            aria-label={t('timeline.commentPlaceholder')}
            rows={3}
          />
          <div className="flex gap-2">
            <Button
              size="sm"
              disabled={!body.trim() || busy !== null}
              onClick={() => run('comment', () => commentOnApproval(id, body.trim()), () => setBody(''))}
            >
              {t('timeline.comment')}
            </Button>
            {!isRequester && (
              <Button
                size="sm"
                variant="outline"
                disabled={busy !== null}
                onClick={() => run('lgtm', () => commentOnApproval(id, body.trim() || null, true), () => setBody(''))}
              >
                {t('timeline.giveLgtm')}
              </Button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
