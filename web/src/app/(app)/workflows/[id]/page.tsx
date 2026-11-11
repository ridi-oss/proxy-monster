'use client';

import { useParams } from 'next/navigation';
import { WorkflowDetailPanel } from '@/components/workflows/workflows-master-detail';

export default function WorkflowRequestDetailPage() {
  const params = useParams<{ id: string }>();
  const id = Number(params.id);
  const selectedId = Number.isFinite(id) && id > 0 ? id : Number.NaN;

  return <WorkflowDetailPanel selectedId={selectedId} />;
}
