'use client';

// Per-datasource instructions for pointing psql / mysql / DataGrip at a proxy DIRECTLY, instead of
// through pmon. pmon remains the recommended path — it brokers a short-lived token, so no credential has to
// live in a client config. A direct client authenticates itself and verifies the proxy the ordinary TLS way,
// which is why this offers the advertised certificate chain for download: pass it as sslrootcert / --ssl-ca
// and the usual verify-full check does the rest. A publicly-trusted proxy publishes no chain and needs none.
//
// The client strings are built from advertiseAddr, so they only appear once a proxy has advertised a
// client-facing address; a datasource whose proxy has not registered one has nothing to connect to yet.
import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Check, Copy, Download, Lock, ShieldOff } from 'lucide-react';
import { toast } from 'sonner';
import { useDatasources } from '@/lib/hooks';
import type { Datasource } from '@/lib/api/types';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

/**
 * Split `host:port`. A bare host (no colon) or an IPv6 literal in brackets both have to survive: only a
 * colon after the closing bracket is a port separator, so `[::1]:6033` keeps its address intact.
 */
function splitAddr(addr: string): { host: string; port: string | null } {
  const lastColon = addr.lastIndexOf(':');
  const closing = addr.lastIndexOf(']');
  if (lastColon > closing && lastColon < addr.length - 1) {
    return { host: addr.slice(0, lastColon).replace(/^\[|\]$/g, ''), port: addr.slice(lastColon + 1) };
  }
  return { host: addr.replace(/^\[|\]$/g, ''), port: null };
}

/** Shell-quote a value for a copy-paste command. Single quotes with the `'\''` escape, so a datasource
 *  name or host carrying `$(...)`, a backtick, or a quote is inert text rather than something that runs
 *  when the line is pasted. Names are only checked non-blank server-side, so this is the boundary. */
function sh(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function CopyRow({ label, value }: { label: string; value: string }) {
  const t = useTranslations('Access.directConnect');
  const [copied, setCopied] = useState(false);
  return (
    <div className="space-y-1">
      <div className="text-muted-foreground text-xs font-medium">{label}</div>
      <div className="flex items-start gap-2">
        <code className="bg-muted flex-1 overflow-x-auto rounded px-2 py-1.5 font-mono text-xs whitespace-pre">
          {value}
        </code>
        <Button
          variant="ghost"
          size="sm"
          aria-label={t('copy')}
          onClick={() => {
            void navigator.clipboard.writeText(value);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          }}
        >
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
        </Button>
      </div>
    </div>
  );
}

function DatasourceCard({ ds }: { ds: Datasource }) {
  const t = useTranslations('Access.directConnect');
  const [downloading, setDownloading] = useState(false);
  const addr = ds.advertiseAddr ?? '';
  const { host, port } = splitAddr(addr);
  // Two independent facts. `tls` is whether the hop is encrypted at all; `chain` is whether this console has
  // a certificate to hand out. A proxy serving a publicly-trusted cert publishes no chain, so keying the
  // badge off the chain alone would label a perfectly secure datasource as plaintext.
  const chain = Boolean(ds.advertiseCertChain);
  const tls = ds.advertiseWireTls ?? chain;
  // Always verify-full: it checks the certificate AND that it covers what was dialed. That works for an IP
  // too when the certificate carries an IP SAN, so downgrading on sight of an IP would weaken verification
  // for a cert that did not need it. verifyModeNote tells the operator when to fall back to verify-ca.
  const mode = 'verify-full';
  // Matches the filename the route sets; derived from the id because a datasource name is barely
  // constrained and would be header-injection material in Content-Disposition.
  const certFile = `datasource-${ds.id}-wire-cert.pem`;

  // The cert is fetched rather than linked so a 403/404/409 surfaces as a message instead of navigating
  // the browser to a JSON error body.
  const download = async () => {
    setDownloading(true);
    try {
      const res = await fetch(`/api/datasources/${ds.id}/wire-cert`, { credentials: 'include' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = certFile;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast.error(t('downloadFailed'), { description: err instanceof Error ? err.message : 'error' });
    } finally {
      setDownloading(false);
    }
  };

  // Flags rather than a conninfo string, so each value is a separately shell-quoted argument and nothing
  // has to be escaped twice (shell, then libpq conninfo).
  // PGSSLROOTCERT / --ssl-ca only when there is a chain to point at. With a publicly-trusted proxy the client
  // verifies against its own trust store, and naming a file that was never downloaded just fails to open.
  const psql = [
    'PGSSLMODE=' + mode,
    ...(chain ? ['PGSSLROOTCERT=' + sh(certFile)] : []),
    'psql -h ' + sh(host) + (port ? ' -p ' + sh(port) : ''),
    '-d ' + sh(ds.dbName || '<db>'),
    '-U <you>',
  ].join(' ');
  // --enable-cleartext-plugin is required, not optional: the proxy authenticates via mysql_clear_password
  // (DESIGN.md), which the client refuses to use unless this is set.
  const mysql = [
    'mysql -h ' + sh(host) + (port ? ' -P ' + sh(port) : ''),
    '-u <you> -p',
    '-D ' + sh(ds.dbName || '<db>'),
    '--ssl-mode=VERIFY_IDENTITY --enable-cleartext-plugin',
    ...(chain ? ['--ssl-ca=' + sh(certFile)] : []),
  ].join(' ');

  return (
    <div className="rounded-lg border p-4">
      <div className="mb-3 flex items-center gap-2">
        <span className="font-medium">{ds.name}</span>
        <Badge variant="outline" className="font-mono text-xs">
          {ds.engine}
        </Badge>
        {tls ? (
          <Badge variant="outline" className="gap-1 text-xs">
            <Lock className="size-3" /> {t('tls')}
          </Badge>
        ) : (
          <Badge variant="destructive" className="gap-1 text-xs">
            <ShieldOff className="size-3" /> {t('tls')}
          </Badge>
        )}
      </div>

      {!addr ? (
        <p className="text-muted-foreground text-sm">{t('noAddress')}</p>
      ) : !tls ? (
        <p className="text-muted-foreground text-sm">{t('tlsOff')}</p>
      ) : (
        <div className="space-y-3">
          <p className="text-muted-foreground text-sm">{chain ? t('tlsOn') : t('tlsSystemTrust')}</p>
          {chain && (
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="secondary" onClick={download} disabled={downloading}>
                <Download className="mr-1.5 size-3.5" />
                {t('download')}
              </Button>
              <span className="text-muted-foreground text-xs">{t('rotationNote')}</span>
            </div>
          )}
          {ds.engine === 'postgres' ? (
            <CopyRow label={t('clients.psql')} value={psql} />
          ) : (
            <CopyRow label={t('clients.mysql')} value={mysql} />
          )}
          <p className="text-muted-foreground text-xs">{t('datagripHelp', { mode })}</p>
          <p className="text-muted-foreground text-xs">{t('verifyModeNote')}</p>
        </div>
      )}
    </div>
  );
}

/** Only datasources the caller may actually connect to — the same `datasource.connect` authority the
 *  download route enforces, so the list never advertises a connection the fetch would refuse. */
export function DirectConnect() {
  const t = useTranslations('Access.directConnect');
  const { data: datasources } = useDatasources(true);
  const connectable = datasources ?? [];

  return (
    <section className="space-y-3">
      <div>
        <h2 className="font-medium">{t('title')}</h2>
        <p className="text-muted-foreground text-sm">{t('intro')}</p>
      </div>
      {connectable.length === 0 ? (
        <p className="text-muted-foreground text-sm">{t('noneConnectable')}</p>
      ) : (
        <div className="space-y-3">
          {connectable.map((ds) => (
            <DatasourceCard key={ds.id} ds={ds} />
          ))}
        </div>
      )}
    </section>
  );
}
