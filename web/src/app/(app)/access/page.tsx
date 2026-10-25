'use client';

// /access — manage expiring wire credentials (DESIGN.md). proxy-monster issues only time-limited
// tokens (no persistent secrets). Two ways to use the CLI: (1) generate a one-shot connection
// password to paste into psql/mysql, or (2) run the local `pmon` broker (which holds a token) and
// use a stable connection string. This page generates/lists/revokes the managed tokens.
import { useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';
import { KeyRound, Loader2, Terminal, Trash2, Clock } from 'lucide-react';
import { toast } from 'sonner';
import { mutate } from 'swr';
import { revokeToken } from '@/lib/api/client';
import { useTokens, swrKeys } from '@/lib/hooks';
import type { WireTokenInfo } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { PageHeader, PageContainer, LoadingState, ErrorState, EmptyState } from '@/components/page-scaffold';
import { GenerateTokenDialog } from '@/components/tokens/generate-token-dialog';
import { DirectConnect } from '@/components/access/direct-connect';

type Translate = (key: string, values?: Record<string, string | number>) => string;

function expiryLabel(t: Translate, token: WireTokenInfo, now: number): { text: string; tone: string } {
  if (token.revokedAt) return { text: t('expiry.revoked'), tone: 'text-muted-foreground line-through' };
  const ms = new Date(token.expiresAt).getTime() - now;
  if (ms <= 0) return { text: t('expiry.expired'), tone: 'text-muted-foreground' };
  const mins = Math.round(ms / 60000);
  if (mins < 60)
    return { text: t('expiry.inMinutes', { minutes: mins }), tone: mins <= 5 ? 'text-red-500' : 'text-amber-500' };
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return { text: t('expiry.inHours', { hours: hrs }), tone: 'text-emerald-500' };
  return {
    text: t('expiry.onDate', { date: new Date(token.expiresAt).toLocaleDateString() }),
    tone: 'text-emerald-500',
  };
}

function relative(t: Translate, iso: string, now: number): string {
  const s = Math.floor((now - new Date(iso).getTime()) / 1000);
  if (s < 60) return t('lastUsed.justNow');
  if (s < 3600) return t('lastUsed.minutesAgo', { minutes: Math.floor(s / 60) });
  if (s < 86400) return t('lastUsed.hoursAgo', { hours: Math.floor(s / 3600) });
  return new Date(iso).toLocaleDateString();
}

export default function WireTokenAccessPage() {
  const t = useTranslations('Access');
  const { data: tokens, isLoading, error } = useTokens({ refreshInterval: 30_000 });
  const [genOpen, setGenOpen] = useState(false);
  const [revoking, setRevoking] = useState<number | null>(null);
  const [now, setNow] = useState(0);

  useEffect(() => {
    const firstUpdate = window.requestAnimationFrame(() => setNow(Date.now()));
    const interval = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => {
      window.cancelAnimationFrame(firstUpdate);
      window.clearInterval(interval);
    };
  }, []);

  const active = (tokens ?? []).filter((t) => !t.revokedAt && new Date(t.expiresAt).getTime() > now);
  const inactive = (tokens ?? []).filter((t) => t.revokedAt || new Date(t.expiresAt).getTime() <= now);

  const handleRevoke = async (token: WireTokenInfo) => {
    setRevoking(token.id);
    try {
      await revokeToken(token.id);
      await mutate(swrKeys.tokens);
      toast.success(t('revoke.success'));
    } catch (err) {
      toast.error(t('revoke.failed'), { description: err instanceof Error ? err.message : 'error' });
    } finally {
      setRevoking(null);
    }
  };

  return (
    <>
      <PageHeader
        title={t('header.title')}
        subtitle={t('header.subtitle')}
        actions={
          <Button size="sm" onClick={() => setGenOpen(true)}>
            <KeyRound className="size-3.5" />
            {t('generate')}
          </Button>
        }
      />

      <PageContainer className="space-y-6">
        {/* Two usage modes */}
        <div className="grid gap-3 sm:grid-cols-2">
          <ModeCard
            icon={<KeyRound className="size-4" />}
            title={t('modes.oneShotTitle')}
            body={t('modes.oneShotBody')}
          />
          <ModeCard
            icon={<Terminal className="size-4" />}
            title={t('modes.brokerTitle')}
            body={t('modes.brokerBody')}
          />
        </div>

        {isLoading && !tokens ? (
          <LoadingState label={t('loading')} />
        ) : error ? (
          <ErrorState error={error} />
        ) : (tokens?.length ?? 0) === 0 ? (
          <EmptyState
            title={t('empty.title')}
            hint={t('empty.hint')}
            icon={<KeyRound className="size-8" />}
            action={
              <Button size="sm" onClick={() => setGenOpen(true)}>
                <KeyRound className="size-3.5" />
                {t('generate')}
              </Button>
            }
          />
        ) : (
          <div className="space-y-6">
            <TokenTable
              title={t('section.active')}
              tokens={active}
              revoking={revoking}
              now={now}
              onRevoke={handleRevoke}
            />
            {inactive.length > 0 && (
              <TokenTable
                title={t('section.inactive')}
                tokens={inactive}
                revoking={revoking}
                now={now}
                onRevoke={handleRevoke}
                muted
              />
            )}
          </div>
        )}
        <DirectConnect />
      </PageContainer>

      <GenerateTokenDialog open={genOpen} onOpenChange={setGenOpen} />
    </>
  );
}

function ModeCard({ icon, title, body }: { icon: React.ReactNode; title: string; body: string }) {
  return (
    <div className="bg-card rounded-xl border p-4">
      <div className="flex items-center gap-2 font-medium">
        {icon}
        {title}
      </div>
      <p className="text-muted-foreground mt-1.5 text-sm">{body}</p>
    </div>
  );
}

function TokenTable({
  title,
  tokens,
  revoking,
  now,
  onRevoke,
  muted,
}: {
  title: string;
  tokens: WireTokenInfo[];
  revoking: number | null;
  now: number;
  onRevoke: (token: WireTokenInfo) => void;
  muted?: boolean;
}) {
  const t = useTranslations('Access');
  if (tokens.length === 0) return null;
  return (
    <div className={cn('space-y-2', muted && 'opacity-70')}>
      <p className="text-muted-foreground text-xs font-medium tracking-wider uppercase">{title}</p>
      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('table.name')}</TableHead>
              <TableHead className="w-24">{t('table.kind')}</TableHead>
              <TableHead className="w-40">{t('table.status')}</TableHead>
              <TableHead className="w-32">{t('table.lastUsed')}</TableHead>
              <TableHead className="w-20 text-right">{t('table.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {tokens.map((token) => {
              const exp = expiryLabel(t, token, now);
              const dead = !!token.revokedAt || new Date(token.expiresAt).getTime() <= now;
              return (
                <TableRow key={token.id}>
                  <TableCell>
                    <span className={cn('text-sm', !token.name && 'text-muted-foreground italic')}>
                      {token.name || (token.kind === 'SESSION' ? t('name.daemonSession') : t('name.unnamed'))}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-[10px]">
                      {token.kind === 'SESSION' ? t('kind.broker') : t('kind.connect')}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <span className={cn('flex items-center gap-1.5 text-xs', exp.tone)}>
                      <Clock className="size-3" />
                      {exp.text}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className="text-muted-foreground text-xs">
                      {token.lastUsedAt ? relative(t, token.lastUsedAt, now) : t('lastUsed.never')}
                    </span>
                  </TableCell>
                  <TableCell className="text-right">
                    {!dead && (
                      <Button
                        size="icon-xs"
                        variant="ghost"
                        className="text-destructive hover:text-destructive"
                        onClick={() => onRevoke(token)}
                        disabled={revoking === token.id}
                        aria-label={t('revoke.action')}
                      >
                        {revoking === token.id ? (
                          <Loader2 className="size-3.5 animate-spin" />
                        ) : (
                          <Trash2 className="size-3.5" />
                        )}
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
