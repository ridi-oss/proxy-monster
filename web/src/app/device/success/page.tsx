'use client';

// /device/success — where the control-plane lands the browser once the pmon
// device login is authorized. Purely informational: pmon's poll picks up the
// grant and finishes on its own, so this tab just confirms and can be closed.
// Styled to match /login (same header + card).

import { useTranslations } from 'next-intl';
import { CircleCheck, ShieldHalf } from 'lucide-react';

export default function DeviceSuccessPage() {
  const t = useTranslations('Device');

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 px-4">
      <div className="flex flex-col items-center gap-2">
        <div className="flex items-center gap-2">
          <ShieldHalf className="size-5" />
          <span className="font-mono text-lg font-semibold tracking-tight">proxy-monster</span>
        </div>
        <p className="text-muted-foreground text-sm">{t('tagline')}</p>
      </div>

      <div className="bg-card flex w-full max-w-sm flex-col items-center gap-4 rounded-xl border p-6 text-center shadow-sm">
        <CircleCheck className="size-10 text-emerald-500" />
        <div className="space-y-2">
          <h1 className="text-base font-semibold">{t('success.title')}</h1>
          <p className="text-muted-foreground text-sm">{t('success.body')}</p>
        </div>
      </div>
    </div>
  );
}
