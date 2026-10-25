'use client';

import { useParams } from 'next/navigation';
import { DatasourceCatalog } from '@/components/datasources/datasource-catalog';

export default function DatasourceCatalogPage() {
  const params = useParams<{ id: string }>();
  const id = Number(params.id);
  if (!Number.isFinite(id)) return null;
  return <DatasourceCatalog id={id} />;
}
