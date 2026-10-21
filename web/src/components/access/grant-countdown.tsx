'use client';

// Live countdown badge for a JIT grant. Ticks every second toward expiresAt;
// turns red in the last 5 minutes as a visual urgency cue (docs/web-console.md).
import { useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';
import { cn } from '@/lib/utils';

function formatCountdown(remaining: number): string {
  const totalSec = Math.floor(remaining / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return `${h}h ${m.toString().padStart(2, '0')}m`;
  if (m > 0) return `${m}m ${s.toString().padStart(2, '0')}s`;
  return `${s}s`;
}

const WARN_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes

export function GrantCountdown({ expiresAt }: { expiresAt?: string | null }) {
  const t = useTranslations('Access');
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  if (!expiresAt) {
    return (
      <span className="border-border text-muted-foreground rounded border px-1.5 py-0.5 font-mono text-[10px]">
        {t('countdown.noExpiry')}
      </span>
    );
  }

  const remaining = new Date(expiresAt).getTime() - now;
  const expired = remaining <= 0;
  const nearExpiry = !expired && remaining < WARN_THRESHOLD_MS;

  return (
    <span
      className={cn(
        'rounded border px-1.5 py-0.5 font-mono text-[10px] tabular-nums',
        expired && 'border-border text-muted-foreground',
        nearExpiry && 'border-red-500/30 bg-red-500/10 text-red-500',
        !expired && !nearExpiry && 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
      )}
    >
      {expired ? t('countdown.expired') : formatCountdown(remaining)}
    </span>
  );
}
