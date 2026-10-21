import { useTranslations } from 'next-intl';
import { PageContainer, PageHeader } from '@/components/page-scaffold';

export default function PoliciesLayout({ children }: { children: React.ReactNode }) {
  const t = useTranslations('Policies');
  return (
    <>
      <PageHeader title={t('layout.title')} subtitle={t('layout.subtitle')} />
      <PageContainer>{children}</PageContainer>
    </>
  );
}
