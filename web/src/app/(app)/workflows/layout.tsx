import { WorkflowsMasterDetail } from '@/components/workflows/workflows-master-detail';

export default function WorkflowsLayout({ children }: { children: React.ReactNode }) {
  return <WorkflowsMasterDetail>{children}</WorkflowsMasterDetail>;
}
