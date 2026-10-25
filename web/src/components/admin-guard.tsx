'use client';

import { useTranslations } from 'next-intl';
import { Loader2, ShieldAlert } from 'lucide-react';
import { EmptyState, ErrorState } from '@/components/page-scaffold';
import { useMePermissions } from '@/lib/hooks';

/** Gates admin surfaces on Cedar-backed capabilities without exposing content while unresolved. */
export function AdminGuard({ children }: { children: React.ReactNode }) {
  const t = useTranslations('Common');
  const { data, error } = useMePermissions();

  // Serve the cached verdict while it exists: SWR keeps the last-good `data` on a background
  // revalidation error (focus/reconnect), so gating on `error` first would flash the error state
  // over an already-authorized subtree mid-session. Still fail-closed — a first-load failure has
  // no cached `data`, so it falls through to the error/loading states below.
  if (!data) {
    if (error) {
      return (
        <div className="flex min-h-0 flex-1 items-center justify-center px-6">
          <div className="w-full max-w-lg">
            <ErrorState error={t('unableToVerifyAdmin')} />
          </div>
        </div>
      );
    }
    return (
      <div className="flex min-h-0 flex-1 items-center justify-center">
        <Loader2 className="text-muted-foreground size-5 animate-spin" />
      </div>
    );
  }

  if (!data.isAdmin) {
    return (
      <div className="flex min-h-0 flex-1 items-center justify-center">
        <EmptyState title={t('notAuthorized')} hint={t('adminRequired')} icon={<ShieldAlert className="size-8" />} />
      </div>
    );
  }

  return <>{children}</>;
}
