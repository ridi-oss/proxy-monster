'use client';

import { useParams } from 'next/navigation';
import { GroupDetail } from '@/components/groups/group-detail';

export default function GroupDetailPage() {
  const params = useParams<{ id: string }>();
  const id = Number(params.id);
  if (!Number.isFinite(id)) return null;
  return <GroupDetail id={id} />;
}
