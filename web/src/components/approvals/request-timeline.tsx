'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { toast } from 'sonner';
import { X } from 'lucide-react';
import { addApprovalCc, closeRequest, commentOnApproval, removeApprovalCc } from '@/lib/api/client';
import type { AccessRequest, RequestEvent } from '@/lib/api/types';
import { useRequestThread } from '@/lib/hooks';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';

function errorText(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

const URL_RE = /(https?:\/\/[^\s<>"]*[^\s<>".,;:!?)\]'])/;

/** Comment text with each http(s) URL as a link that opens in a new tab. */
export function Linkified({ text }: { text: string }) {
  return text.split(URL_RE).map((part, i) =>
    i % 2 === 1 ? (
      <a key={i} href={part} target="_blank" rel="noopener noreferrer" className="underline">
        {part}
      </a>
    ) : (
      part
    ),
  );
}

function EventLine({ event, onRequest }: { event: RequestEvent; onRequest: boolean }) {
  const t = useTranslations('Workflows');
  const when = new Date(event.createdAt).toLocaleString();
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
          {!onRequest && <span>· {t('timeline.notOnRequest')}</span>}
          {event.editedAt && !event.deleted && <span>· {t('timeline.edited')}</span>}
        </div>
        {event.deleted ? (
          <p className="text-muted-foreground text-sm italic">{t('timeline.deleted')}</p>
        ) : (
          event.body && (
            <p className="text-sm whitespace-pre-wrap break-words">
              <Linkified text={event.body} />
            </p>
          )
        )}
      </li>
    );
  }
  const text = t(`timeline.events.${event.kind}`, { body: event.body ?? '', revision: event.revision ?? 1 });
  return (
    <li className="text-muted-foreground text-xs" data-testid={`timeline-${event.kind}`}>
      {event.actor && <span className="text-foreground font-medium">{event.actor} </span>}
      {text} · {when}
    </li>
  );
}

/** A request's comments, LGTMs, CCs, and state changes, oldest first. Works for every request kind. */
export function RequestTimeline({
  request,
  principal,
  onChanged,
}: {
  request: AccessRequest;
  principal?: string;
  onChanged?: () => void;
}) {
  const t = useTranslations('Workflows');
  const id = request.id;
  const { data: thread, mutate } = useRequestThread(id, { refreshInterval: 15_000 });
  const [body, setBody] = useState('');
  const [cc, setCc] = useState('');
  const [busy, setBusy] = useState<'comment' | 'lgtm' | 'cc' | null>(null);
  if (!thread) return null;
  const ccs = thread.ccs;
  const isRequester = request.principal === principal;
  const members = new Set([request.principal, ...thread.participants, ...ccs]);
  // Only a Slack channel reply can come from someone not on the request; every other comment passed task.comment.
  const onRequest = (actor?: string | null) => actor == null || members.has(actor);

  const run = async (kind: 'comment' | 'lgtm' | 'cc', action: () => Promise<unknown>, after: () => void) => {
    setBusy(kind);
    try {
      await action();
      after();
      await mutate();
      onChanged?.();
    } catch (err) {
      toast.error(errorText(err, t('timeline.failed')));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-4 border-t pt-4" data-testid="approval-timeline">
      <div className="space-y-2">
        <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">{t('timeline.ccs')}</p>
        <div className="flex flex-wrap items-center gap-2">
          {ccs.length === 0 && <span className="text-muted-foreground text-sm">—</span>}
          {ccs.map((p) => (
            <span
              key={p}
              className="bg-muted inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-xs"
            >
              {p}
              {thread.canCc && (
                <button
                  type="button"
                  aria-label={t('timeline.removeCc', { principal: p })}
                  disabled={busy !== null}
                  onClick={() =>
                    run(
                      'cc',
                      () => removeApprovalCc(id, p),
                      () => {},
                    )
                  }
                >
                  <X className="size-3" />
                </button>
              )}
            </span>
          ))}
        </div>
        {thread.canCc && (
          <form
            className="flex max-w-md gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (cc.trim())
                void run(
                  'cc',
                  () => addApprovalCc(id, cc.trim()),
                  () => setCc(''),
                );
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
        <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
          {t('timeline.heading')}
        </p>
        <ol className="space-y-3">
          {thread.timeline.map((event) => (
            <EventLine key={event.id} event={event} onRequest={event.origin !== 'slack' || onRequest(event.actor)} />
          ))}
        </ol>
      </div>

      {thread.canComment && (
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
              onClick={() =>
                run(
                  'comment',
                  () => commentOnApproval(id, body.trim()),
                  () => setBody(''),
                )
              }
            >
              {t('timeline.comment')}
            </Button>
            {!isRequester && (
              <Button
                size="sm"
                variant="outline"
                disabled={busy !== null}
                onClick={() =>
                  run(
                    'lgtm',
                    () => commentOnApproval(id, body.trim() || null, true),
                    () => setBody(''),
                  )
                }
              >
                {t('timeline.giveLgtm')}
              </Button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/** Closes a request that has not started, for whoever Cedar lets do so. Renders nothing otherwise. */
export function CloseRequestButton({ request, onClosed }: { request: AccessRequest; onClosed?: () => void }) {
  const t = useTranslations('Workflows');
  const { data: thread, mutate } = useRequestThread(request.id);
  const [busy, setBusy] = useState(false);
  if (!thread?.canClose) return null;
  return (
    <Button
      variant="outline"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        try {
          await closeRequest(request.id);
          toast.success(t('approvalDetail.closedToast'));
          await mutate();
          onClosed?.();
        } catch (err) {
          toast.error(errorText(err, t('approvalDetail.closeFailed')));
        } finally {
          setBusy(false);
        }
      }}
    >
      {busy ? t('actions.closing') : t('actions.close')}
    </Button>
  );
}
