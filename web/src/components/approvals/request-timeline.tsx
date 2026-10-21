'use client';

import { useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';
import { toast } from 'sonner';
import { X } from 'lucide-react';
import { addApprovalCc, closeRequest, commentOnApproval, removeApprovalCc, searchCcCandidates } from '@/lib/api/client';
import type { AccessRequest, CcCandidate, Person, RequestEvent } from '@/lib/api/types';
import { useRequestThread } from '@/lib/hooks';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { PersonName } from './person-name';

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

function EventLine({
  event,
  onRequest,
  people,
}: {
  event: RequestEvent;
  onRequest: boolean;
  people?: Record<string, Person>;
}) {
  const t = useTranslations('Workflows');
  const when = new Date(event.createdAt).toLocaleString();
  if (event.kind === 'comment' || event.kind === 'lgtm') {
    return (
      <li className="space-y-1" data-testid={`timeline-${event.kind}`}>
        <div className="text-muted-foreground flex flex-wrap items-center gap-1 text-xs">
          {event.actor && <PersonName principal={event.actor} people={people} />}
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
      {event.actor && (
        <>
          <PersonName principal={event.actor} people={people} />{' '}
        </>
      )}
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
            <span key={p} className="bg-muted inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs">
              <PersonName principal={p} people={thread.people} />
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
          <CcPicker
            requestId={id}
            exclude={[request.principal, ...ccs]}
            busy={busy !== null}
            onPick={(principal, clear) => run('cc', () => addApprovalCc(id, principal), clear)}
          />
        )}
      </div>

      <div className="space-y-2">
        <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
          {t('timeline.heading')}
        </p>
        <ol className="space-y-3">
          {thread.timeline.map((event) => (
            <EventLine
              key={event.id}
              event={event}
              people={thread.people}
              onRequest={event.origin !== 'slack' || onRequest(event.actor)}
            />
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

/** The suggestions shown for `q`, and who submitting adds: an exact principal or email first, then the highlighted row, then `q` itself. */
export function ccChoice(
  q: string,
  found: { q: string; rows: CcCandidate[] },
  exclude: string[],
  active: number,
): { options: CcCandidate[]; chosen: string } {
  const options = q && found.q === q ? found.rows.filter((c) => !exclude.includes(c.principal)) : [];
  const lower = q.toLowerCase();
  const exact = options.find((c) => c.principal.toLowerCase() === lower || c.email?.toLowerCase() === lower);
  return { options, chosen: (exact ?? options[active])?.principal ?? q };
}

/** Adds a CC by name or email, suggesting active users as the caller types. */
function CcPicker({
  requestId,
  exclude,
  busy,
  onPick,
}: {
  requestId: number;
  exclude: string[];
  busy: boolean;
  onPick: (principal: string, clear: () => void) => Promise<void>;
}) {
  const t = useTranslations('Workflows');
  const [query, setQuery] = useState('');
  const [found, setFound] = useState<{ q: string; rows: CcCandidate[] }>({ q: '', rows: [] });
  const [active, setActive] = useState(0);
  const q = query.trim();
  useEffect(() => {
    if (!q) return;
    let stale = false;
    const timer = setTimeout(() => {
      searchCcCandidates(requestId, q)
        .then((rows) => {
          if (!stale) {
            setFound({ q, rows });
            setActive(0);
          }
        })
        .catch(() => {});
    }, 200);
    return () => {
      stale = true;
      clearTimeout(timer);
    };
  }, [requestId, q]);
  const { options, chosen } = ccChoice(q, found, exclude, active);
  const pick = (principal: string) => {
    if (busy) return;
    void onPick(principal, () => {
      setQuery('');
      setFound({ q: '', rows: [] });
    });
  };

  return (
    <form
      className="relative flex max-w-md gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (chosen) pick(chosen);
      }}
    >
      <Input
        id="approval-cc"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown' && options.length) {
            e.preventDefault();
            setActive((i) => (i + 1) % options.length);
          } else if (e.key === 'ArrowUp' && options.length) {
            e.preventDefault();
            setActive((i) => (i - 1 + options.length) % options.length);
          } else if (e.key === 'Escape') {
            setFound({ q: '', rows: [] });
          }
        }}
        placeholder={t('timeline.ccPlaceholder')}
        aria-label={t('timeline.ccPlaceholder')}
        autoComplete="off"
        role="combobox"
        aria-expanded={options.length > 0}
        aria-controls="approval-cc-options"
      />
      <Button type="submit" variant="outline" size="sm" disabled={!q || busy}>
        {t('timeline.addCc')}
      </Button>
      {options.length > 0 && (
        <ul
          id="approval-cc-options"
          role="listbox"
          className="bg-popover absolute top-full left-0 z-10 mt-1 w-full max-w-sm overflow-hidden rounded-md border text-sm shadow-md"
        >
          {options.map((c, i) => (
            <li
              key={c.principal}
              role="option"
              aria-selected={i === active}
              className={`cursor-pointer px-3 py-1.5 ${i === active ? 'bg-muted' : ''}`}
              onMouseEnter={() => setActive(i)}
              onMouseDown={(e) => {
                e.preventDefault();
                pick(c.principal);
              }}
            >
              <PersonName principal={c.principal} people={{ [c.principal]: c }} />
            </li>
          ))}
        </ul>
      )}
    </form>
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
