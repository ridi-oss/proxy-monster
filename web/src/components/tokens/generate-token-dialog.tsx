'use client';

// Generate a managed, expiring wire token. On success the plaintext is shown ONCE with copy
// buttons and a ready-to-paste connection string (it's a connect password, not a stored secret).
import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Check, Copy, KeyRound, Loader2, TriangleAlert } from 'lucide-react';
import { toast } from 'sonner';
import { mutate } from 'swr';
import { createToken } from '@/lib/api/client';
import { useAuth } from '@/lib/auth';
import { useDatasources, swrKeys } from '@/lib/hooks';
import type { IssuedToken } from '@/lib/api/types';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

const TTL_OPTIONS: Array<{ value: string; key: string }> = [
  { value: '900', key: 'm15' },
  { value: '3600', key: 'h1' },
  { value: '21600', key: 'h6' },
  { value: '43200', key: 'h12' },
  { value: '86400', key: 'h24Max' },
];

function CopyButton({ text, label }: { text: string; label?: string }) {
  const t = useTranslations('Workflows');
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? <Check className="size-3.5 text-emerald-500" /> : <Copy className="size-3.5" />}
      {label ?? (copied ? t('actions.copied') : t('actions.copy'))}
    </Button>
  );
}

export function GenerateTokenDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const t = useTranslations('Workflows');
  const { identity } = useAuth();
  const { data: datasources } = useDatasources();
  const ttls = TTL_OPTIONS.map((option) => ({ value: option.value, label: t(`ttls.${option.key}`) }));
  const [name, setName] = useState('');
  const [ttl, setTtl] = useState('3600');
  const [dsId, setDsId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<IssuedToken | null>(null);

  const reset = () => {
    setName('');
    setTtl('3600');
    setDsId(null);
    setIssued(null);
  };

  const handleGenerate = async () => {
    setBusy(true);
    try {
      const tok = await createToken({ name: name.trim() || null, ttlSeconds: Number(ttl) });
      setIssued(tok);
      await mutate(swrKeys.tokens);
    } catch (err) {
      toast.error(t('tokenDialog.generateFailed'), {
        description: err instanceof Error ? err.message : 'error',
      });
    } finally {
      setBusy(false);
    }
  };

  const close = () => {
    onOpenChange(false);
    setTimeout(reset, 200);
  };

  // Connection-string helper (the token is the password). Defaults to a chosen datasource.
  const ds = datasources?.find((d) => String(d.id) === dsId) ?? datasources?.[0];
  const user = identity?.principal ?? 'you@example.com';
  const connString =
    issued && ds
      ? ds.engine === 'mysql'
        ? `mysql --ssl-mode=VERIFY_IDENTITY --enable-cleartext-plugin -h <proxy-host> -P 6033 -u "${user}" -p"${issued.token}"`
        : `psql "host=<proxy-host> port=6432 dbname=${ds.dbName} user=${user} password=${issued.token} sslmode=verify-full sslrootcert=system"`
      : null;

  return (
    <Dialog open={open} onOpenChange={(o) => (o ? onOpenChange(true) : close())}>
      <DialogContent className="sm:max-w-xl">
        {!issued ? (
          <>
            <DialogHeader>
              <DialogTitle>{t('tokenDialog.generateTitle')}</DialogTitle>
              <DialogDescription>{t('tokenDialog.generateDescription')}</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-1">
              <div className="space-y-1.5">
                <Label htmlFor="tok-name">{t('tokenDialog.nameOptional')}</Label>
                <Input
                  id="tok-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={t('tokenDialog.namePlaceholder')}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label>{t('tokenDialog.expiresIn')}</Label>
                  <Select value={ttl} onValueChange={(v: string | null) => setTtl(v ?? '3600')}>
                    <SelectTrigger className="w-full">
                      <SelectValue>{(v: string | null) => ttls.find((opt) => opt.value === v)?.label}</SelectValue>
                    </SelectTrigger>
                    <SelectContent>
                      {ttls.map((opt) => (
                        <SelectItem key={opt.value} value={opt.value}>
                          {opt.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label>{t('tokenDialog.connectionStringFor')}</Label>
                  <Select value={dsId ?? (ds ? String(ds.id) : null)} onValueChange={(v: string | null) => setDsId(v)}>
                    <SelectTrigger className="w-full">
                      <SelectValue placeholder={t('tokenDialog.datasourcePlaceholder')}>
                        {(v: string | null) =>
                          datasources?.find((d) => String(d.id) === v)?.name ?? t('tokenDialog.datasourcePlaceholder')
                        }
                      </SelectValue>
                    </SelectTrigger>
                    <SelectContent>
                      {(datasources ?? []).map((d) => (
                        <SelectItem key={d.id} value={String(d.id)}>
                          {d.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={close} disabled={busy}>
                {t('actions.cancel')}
              </Button>
              <Button onClick={handleGenerate} disabled={busy}>
                {busy ? <Loader2 className="size-3.5 animate-spin" /> : <KeyRound className="size-3.5" />}
                {t('actions.generate')}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>{t('tokenDialog.generatedTitle')}</DialogTitle>
              <DialogDescription>
                {t('tokenDialog.generatedDescription', {
                  date: new Date(issued.expiresAt).toLocaleString(),
                })}
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-1">
              <div className="flex items-start gap-2.5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-600 dark:text-amber-400">
                <TriangleAlert className="mt-0.5 size-4 shrink-0" />
                {t('tokenDialog.warning')}
              </div>

              <div className="space-y-1.5">
                <Label>{t('tokenDialog.token')}</Label>
                <div className="flex items-center gap-2">
                  <code className="bg-muted min-w-0 flex-1 truncate rounded-md border px-2.5 py-2 font-mono text-xs">
                    {issued.token}
                  </code>
                  <CopyButton text={issued.token} />
                </div>
              </div>

              {connString && (
                <div className="space-y-1.5">
                  <Label>
                    {ds
                      ? t('tokenDialog.connectionStringWithName', { name: ds.name })
                      : t('tokenDialog.connectionString')}
                  </Label>
                  <div className="bg-muted rounded-md border p-2.5">
                    <code className="block font-mono text-xs break-all whitespace-pre-wrap">{connString}</code>
                  </div>
                  <div className="flex justify-end">
                    <CopyButton text={connString} label={t('actions.copyCommand')} />
                  </div>
                </div>
              )}
            </div>
            <DialogFooter>
              <Button onClick={close}>{t('actions.done')}</Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
