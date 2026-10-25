'use client';

import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { MonitorSmartphone } from 'lucide-react';
import { Button } from '@/components/ui/button';

export default function DisplacedPage() {
  const t = useTranslations('Session');
  const router = useRouter();

  return (
    <div className="flex min-h-svh items-center justify-center px-4">
      <div className="bg-card flex w-full max-w-md flex-col items-center gap-5 rounded-xl border p-8 text-center shadow-sm">
        <div className="bg-muted flex size-12 items-center justify-center rounded-full">
          <MonitorSmartphone className="text-muted-foreground size-6" />
        </div>
        <div className="space-y-2">
          <h1 className="text-lg font-semibold">{t('displaced.title')}</h1>
          <p className="text-muted-foreground text-sm">{t('displaced.body')}</p>
        </div>
        <Button onClick={() => router.replace('/login')}>{t('displaced.signInAgain')}</Button>
      </div>
    </div>
  );
}
