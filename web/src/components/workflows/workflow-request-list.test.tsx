import { renderToStaticMarkup } from 'react-dom/server'
import { NextIntlClientProvider } from 'next-intl'
import { expect, it } from 'vitest'
import en from '../../../messages/en/workflows.json'
import type { AccessRequest } from '@/lib/api/types'
import { WorkflowRequestList } from './workflow-request-list'

const githubAlreadyRan: AccessRequest = {
  id: 7,
  principal: 'alice@example.com',
  datasourceName: 'orders',
  requestedDurationSec: 0,
  status: 'ALREADY_RAN',
  createdAt: '2026-10-01T00:00:00Z',
  kind: 'QUERY',
  executeAs: [],
  revision: 1,
  sql: 'UPDATE t SET a = 1',
  source: 'github',
  scope: 'prod',
  pullRequest: {
    repository: 'acme/db',
    pr: 12,
    prUrl: 'https://github.com/acme/db/pull/12',
    path: 'sql/x.sql',
  },
}

const consolePending: AccessRequest = {
  id: 8,
  principal: 'bob@example.com',
  datasourceName: 'orders',
  requestedDurationSec: 0,
  status: 'PENDING',
  createdAt: '2026-10-02T00:00:00Z',
  kind: 'QUERY',
  executeAs: [],
  revision: 1,
  sql: 'SELECT 1',
}

function render(): string {
  return renderToStaticMarkup(
    <NextIntlClientProvider locale="en" messages={{ Workflows: en }}>
      <WorkflowRequestList
        entries={[
          { request: githubAlreadyRan, incoming: false, outgoing: true },
          { request: consolePending, incoming: true, outgoing: false },
        ]}
      />
    </NextIntlClientProvider>,
  )
}

it('badges a GitHub request that already ran and names its pull request in plain text', () => {
  const html = render()
  expect(html).toContain('data-status="ALREADY_RAN"')
  expect(html).toMatch(/>ALREADY_RAN</)
  expect(html).toContain('data-source="github"')
  expect(html).toContain('GitHub acme/db#12 · prod')
  expect(html).toContain('data-source="console"')
})

it('nests no link inside a row', () => {
  const html = render()
  expect(html.match(/<a[\s>]/g)).toHaveLength(2)
  expect(html).not.toContain('github.com/acme/db/pull/12')
})
