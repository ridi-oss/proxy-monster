'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { mutate } from 'swr';
import { ShieldCheck } from 'lucide-react';
import { toast } from 'sonner';
import { revokeAccessGrant } from '@/lib/api/client';
import type { AccessGrant } from '@/lib/api/types';
import { useAuth } from '@/lib/auth';
import { swrKeys, useAccessGrants } from '@/lib/hooks';
import { GrantCountdown } from '@/components/access/grant-countdown';
import { EmptyState, ErrorState, LoadingState } from '@/components/page-scaffold';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

type Translator = ReturnType<typeof useTranslations>;

function formatRelative(iso: string, t: Translator): string {
  const diff = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return t('relativeTime.justNow');
  if (minutes < 60) return t('relativeTime.minutesAgo', { count: minutes });
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return t('relativeTime.hoursAgo', { count: hours });
  return t('relativeTime.daysAgo', { count: Math.floor(hours / 24) });
}

export function ActiveRoleGrants() {
  const t = useTranslations('Workflows');
  const { identity, status } = useAuth();
  const {
    data: grants,
    isLoading,
    error,
  } = useAccessGrants(true, {
    refreshInterval: 15_000,
  });
  const [revoking, setRevoking] = useState<number | null>(null);
  const principal = identity?.principal;
  const principalGrants = (grants ?? []).filter((grant) => principal != null && grant.principal === principal);

  const handleRevoke = async (grant: AccessGrant) => {
    setRevoking(grant.id);
    try {
      await revokeAccessGrant(grant.id);
      toast.success(t('activeGrants.revokedToast', { role: grant.roleName }));
      void mutate(swrKeys.accessGrants(true));
    } catch (revokeError) {
      toast.error(revokeError instanceof Error ? revokeError.message : t('activeGrants.revokeFailed'));
    } finally {
      setRevoking(null);
    }
  };

  return (
    <section data-workflow-detail-kind="ACTIVE_GRANTS" className="space-y-3">
      <h2 className="text-sm font-semibold">{t('activeGrants.heading')}</h2>

      {(status === 'loading' || (isLoading && !grants)) && <LoadingState label={t('activeGrants.loading')} />}

      {status !== 'loading' && error && <ErrorState error={error} />}

      {status !== 'loading' && !error && !isLoading && principalGrants.length === 0 && (
        <EmptyState
          icon={<ShieldCheck className="size-8" />}
          title={t('activeGrants.emptyTitle')}
          hint={t('activeGrants.emptyHint')}
        />
      )}

      {status !== 'loading' && !error && principalGrants.length > 0 && (
        <div className="space-y-2">
          {principalGrants.map((grant) => (
            <div key={grant.id} className="bg-card rounded-lg border p-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="secondary">{grant.roleName}</Badge>
                  <GrantCountdown expiresAt={grant.expiresAt} />
                </div>
                <Button
                  size="xs"
                  variant="ghost"
                  className="shrink-0 text-red-500 hover:bg-red-500/10 hover:text-red-500"
                  onClick={() => handleRevoke(grant)}
                  disabled={revoking === grant.id}
                >
                  {revoking === grant.id ? t('actions.revoking') : t('actions.revoke')}
                </Button>
              </div>
              {grant.grantedBy && (
                <p className="text-muted-foreground mt-1.5 text-xs">
                  {t.rich('activeGrants.grantedBy', {
                    grantedBy: grant.grantedBy,
                    time: grant.grantedAt ? ` · ${formatRelative(grant.grantedAt, t)}` : '',
                    code: (chunks) => <code className="text-foreground/70 font-mono">{chunks}</code>,
                  })}
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
