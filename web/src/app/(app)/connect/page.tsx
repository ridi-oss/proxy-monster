'use client'

import { useTranslations } from 'next-intl'
import { useMcpConnect } from '@/lib/hooks'
import { ConnectAgent } from '@/components/connect/connect-agent'
import { PageHeader, PageContainer, LoadingState, ErrorState } from '@/components/page-scaffold'

export default function ConnectAgentPage() {
  const t = useTranslations('Connect')
  const { data, error, isLoading } = useMcpConnect()
  return (
    <>
      <PageHeader title={t('header.title')} subtitle={t('header.subtitle')} />
      <PageContainer className="max-w-3xl">
        {isLoading && <LoadingState />}
        {error && <ErrorState error={error} />}
        {data && <ConnectAgent info={data} />}
      </PageContainer>
    </>
  )
}
