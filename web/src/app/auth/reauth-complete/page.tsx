'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { REAUTH_COMPLETE_MESSAGE_TYPE } from '@/lib/reauth';

export default function ReauthCompletePage() {
  const t = useTranslations('Session');

  useEffect(() => {
    if (window.opener && !window.opener.closed) {
      try {
        window.opener.postMessage({ type: REAUTH_COMPLETE_MESSAGE_TYPE }, window.location.origin);
      } catch {}
      window.close();
    } else {
      window.location.replace('/');
    }
  }, []);

  return (
    <main className="flex min-h-svh items-center justify-center px-4 text-center">
      <div className="max-w-sm space-y-2" data-testid="reauth-complete">
        <h1 className="text-lg font-semibold">{t('reauthComplete.title')}</h1>
        <p className="text-muted-foreground text-sm">{t('reauthComplete.body')}</p>
      </div>
    </main>
  );
}
