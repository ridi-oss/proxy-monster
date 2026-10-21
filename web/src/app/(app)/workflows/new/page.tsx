'use client'

import { Suspense } from 'react'
import { useSearchParams } from 'next/navigation'
import { useTranslations } from 'next-intl'
import {
  WorkflowsMasterDetail,
  type WorkflowComposeDraft,
} from '@/components/workflows/workflows-master-detail'

type Translator = ReturnType<typeof useTranslations>

function parseDraft(search: URLSearchParams, t: Translator): WorkflowComposeDraft {
  const kind = search.get('kind')
  const fromRaw = search.get('from')
  const from = fromRaw == null ? null : Number(fromRaw)
  const sourceDecisionId = from != null && Number.isFinite(from) && from > 0 ? from : null

  if (kind != null && kind !== 'role' && kind !== 'query') {
    return {
      kind: 'QUERY',
      sourceDecisionId: null,
      sourceDecisionError: t('newPage.unknownKind', { kind }),
    }
  }
  if (fromRaw != null && sourceDecisionId == null) {
    return {
      kind: 'QUERY',
      sourceDecisionId: null,
      sourceDecisionError: t('newPage.sourceDecisionPositive'),
    }
  }
  if (kind === 'role' && fromRaw != null) {
    return {
      kind: 'QUERY',
      sourceDecisionId: null,
      sourceDecisionError: t('newPage.sourceDecisionQueryOnly'),
    }
  }
  if (sourceDecisionId != null) return { kind: 'QUERY', sourceDecisionId }
  if (kind === 'role') return { kind: 'ROLE' }
  return { kind: 'QUERY', sourceDecisionId: null }
}

function NewWorkflowRequestInner() {
  const search = useSearchParams()
  const t = useTranslations('Workflows')
  return <WorkflowsMasterDetail compose={parseDraft(search, t)} />
}

export default function NewWorkflowRequestPage() {
  return (
    <Suspense fallback={<WorkflowsMasterDetail />}>
      <NewWorkflowRequestInner />
    </Suspense>
  )
}
