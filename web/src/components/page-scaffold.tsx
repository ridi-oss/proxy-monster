'use client';

import { useTranslations } from 'next-intl';
import { AlertCircle, Inbox, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

/** Page header: title + optional subtitle on the left, actions on the right. */
export function PageHeader({
  title,
  subtitle,
  actions,
  className,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex flex-wrap items-end justify-between gap-4 border-b px-6 py-5', className)}>
      <div className="space-y-1">
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="text-muted-foreground max-w-2xl text-sm">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Scrollable content container with comfortable max width and padding. */
export function PageContainer({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className="min-h-0 flex-1 overflow-y-auto">
      <div className={cn('mx-auto w-full max-w-6xl px-6 py-6', className)}>{children}</div>
    </div>
  );
}

export function LoadingState({ label }: { label?: string }) {
  const t = useTranslations('Common');
  return (
    <div className="text-muted-foreground flex items-center gap-2 px-1 py-6 text-sm">
      <Loader2 className="size-4 animate-spin" />
      {label ?? t('loading')}
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className="text-destructive flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2.5 text-sm">
      <AlertCircle className="mt-0.5 size-4 shrink-0" />
      <span className="break-words">{message}</span>
    </div>
  );
}

export function EmptyState({
  title,
  hint,
  icon,
  action,
}: {
  title: string;
  hint?: string;
  icon?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <div className="text-muted-foreground/60">{icon ?? <Inbox className="size-8" />}</div>
      <div className="space-y-1">
        <p className="text-sm font-medium">{title}</p>
        {hint && <p className="text-muted-foreground text-xs">{hint}</p>}
      </div>
      {action}
    </div>
  );
}
