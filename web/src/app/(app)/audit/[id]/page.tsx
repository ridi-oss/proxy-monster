'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useAuth } from '@/lib/auth';
import { useAuditEvent } from '@/lib/hooks';
import { Button } from '@/components/ui/button';
import { DecisionDetail } from '@/components/audit/decision-detail';
import { ErrorState, LoadingState, PageContainer, PageHeader } from '@/components/page-scaffold';

export default function AuditDecisionPage() {
  const t = useTranslations('Audit');
  const params = useParams<{ id: string }>();
  const id = Number(params.id);
  const { identity } = useAuth();
  const { data: record, error, isLoading } = useAuditEvent(Number.isFinite(id) ? id : null);

  if (!Number.isFinite(id)) return null;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <PageHeader
        title={t('permalink.title', { id })}
        subtitle={t('permalink.subtitle')}
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link href="/audit">{t('permalink.back')}</Link>
          </Button>
        }
      />
      <PageContainer className="max-w-4xl space-y-4">
        {isLoading && !record ? (
          <LoadingState label={t('permalink.loading')} />
        ) : error ? (
          <ErrorState error={error} />
        ) : record ? (
          <>
            {record.decision === 'DENY' && record.principal === identity?.principal && record.id != null && (
              <div className="flex justify-end">
                <Button size="sm" asChild>
                  <Link href={`/workflows/new?from=${record.id}`}>{t('permalink.requestApproval')}</Link>
                </Button>
              </div>
            )}
            <div className="h-[70vh] overflow-hidden rounded-xl border">
              <DecisionDetail record={record} />
            </div>
          </>
        ) : null}
      </PageContainer>
    </div>
  );
}
