'use client';

// A RATE_RESET request is history only: resets are gone, so none is ever pending again.
import type { ReactNode } from 'react';
import { useTranslations } from 'next-intl';
import { mutate } from 'swr';
import type { AccessRequest } from '@/lib/api/types';
import { swrKeys } from '@/lib/hooks';
import { cn } from '@/lib/utils';
import { RequestTimeline } from '@/components/approvals/request-timeline';
import { useAuth } from '@/lib/auth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const STATUS_STYLE: Record<string, string> = {
  APPROVED: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  REJECTED: 'border-red-500/30 bg-red-500/10 text-red-500',
};

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">{label}</p>
      <div className="text-sm">{children}</div>
    </div>
  );
}

function refresh(id: number) {
  void mutate(swrKeys.requestThread(id));
  void mutate(swrKeys.involvedApprovals);
  void mutate(swrKeys.accessRequests('PENDING'));
  void mutate(swrKeys.accessRequests(undefined));
}

export function RateResetRequestDetail({ request }: { request: AccessRequest }) {
  const t = useTranslations('Workflows');
  const { identity } = useAuth();

  return (
    <div data-workflow-detail-kind="RATE_RESET">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="space-y-2">
              <CardTitle>{t('rateResetDetail.title', { id: request.id })}</CardTitle>
              <span
                className={cn(
                  'inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium',
                  STATUS_STYLE[request.status] ?? 'border-border text-muted-foreground',
                )}
              >
                {request.status}
              </span>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label={t('fields.requester')}>
              <code className="font-mono">{request.principal}</code>
            </Field>
            <Field label={t('rateResetDetail.spentRate')}>
              <code className="font-mono">{request.denyReason ?? '—'}</code>
            </Field>
            <Field label={t('fields.created')}>
              <code className="font-mono">{new Date(request.createdAt).toLocaleString()}</code>
            </Field>
            <Field label={t('fields.decided')}>
              <code className="font-mono">
                {request.decidedAt ? new Date(request.decidedAt).toLocaleString() : '—'}
              </code>
            </Field>
            <Field label={t('fields.decidedBy')}>
              <code className="font-mono">{request.decidedBy ?? '—'}</code>
            </Field>
          </div>
          <Field label={t('fields.reason')}>{request.reason ?? '—'}</Field>
          {request.rejectionReason && (
            <Field label={t('fields.rejectionReason')}>
              <span className="text-red-500">{request.rejectionReason}</span>
            </Field>
          )}
          <p className="text-muted-foreground text-xs">{t('rateResetDetail.note')}</p>
          <RequestTimeline request={request} principal={identity?.principal} onChanged={() => refresh(request.id)} />
        </CardContent>
      </Card>
    </div>
  );
}
