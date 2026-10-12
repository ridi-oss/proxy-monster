import { renderToStaticMarkup } from 'react-dom/server'
import { NextIntlClientProvider } from 'next-intl'
import { expect, it } from 'vitest'
import en from '../../../messages/en/workflows.json'
import ko from '../../../messages/ko/workflows.json'
import type { AccessRequest } from '@/lib/api/types'
import { approveLabelKey, runsOnMerge } from '@/lib/approvals'
import { RequestOrigin } from './request-origin'

const base: AccessRequest = {
  id: 1,
  principal: 'alice@example.com',
  requestedDurationSec: 0,
  status: 'PENDING',
  createdAt: '2026-10-01T00:00:00Z',
  kind: 'QUERY',
  executeAs: [],
  revision: 1,
}

const github: AccessRequest = {
  ...base,
  source: 'github',
  pullRequest: {
    repository: 'acme/db',
    pr: 12,
    prUrl: 'https://github.com/acme/db/pull/12',
    path: 'sql/x.sql',
  },
  scope: 'prod',
}

function render(request: AccessRequest, locale = 'en'): string {
  return renderToStaticMarkup(
    <NextIntlClientProvider locale={locale} messages={{ Workflows: locale === 'en' ? en : ko }}>
      <RequestOrigin request={request} />
    </NextIntlClientProvider>,
  )
}

it('links a GitHub request to its pull request and shows its path and scope', () => {
  const html = render(github)
  expect(html).toContain('href="https://github.com/acme/db/pull/12"')
  expect(html).toContain('acme/db#12')
  expect(html).toContain('sql/x.sql')
  expect(html).toContain('prod')
  expect(html).toContain(en.fields.source)
  expect(html).toContain(en.fields.scope)
})

it('shows MCP without a link', () => {
  const html = render({ ...base, source: 'mcp' })
  expect(html).toContain('MCP')
  expect(html).not.toContain('href')
})

it('renders nothing for a console request with no scope', () => {
  expect(render({ ...base, source: 'console' })).toBe('')
  expect(render(base)).toBe('')
})

it('resolves every label in Korean', () => {
  const html = render(github, 'ko')
  expect(html).toContain(ko.fields.source)
  expect(html).toContain(ko.fields.scope)
  expect(html).not.toContain('Workflows.')
})

it('approves a GitHub request without running it', () => {
  expect(runsOnMerge(github)).toBe(true)
  expect(runsOnMerge({ source: 'console' })).toBe(false)
  expect(runsOnMerge({ source: 'mcp' })).toBe(false)
  expect(runsOnMerge({})).toBe(false)
  expect(runsOnMerge(undefined)).toBe(false)
  expect(runsOnMerge(null)).toBe(false)
  expect(approveLabelKey(github)).toBe('actions.approve')
  expect(approveLabelKey({ source: 'console' })).toBe('actions.approveAndRun')
  expect(approveLabelKey({ source: 'mcp' })).toBe('actions.approveAndRun')
  expect(approveLabelKey(null)).toBe('actions.approveAndRun')
})
