import { renderToStaticMarkup } from 'react-dom/server';
import { NextIntlClientProvider } from 'next-intl';
import { expect, it } from 'vitest';
import en from '../../../messages/en/workflows.json';
import ko from '../../../messages/ko/workflows.json';
import type { AccessRequest } from '@/lib/api/types';
import { runsOnMerge } from '@/lib/approvals';
import { RequestOrigin, RunsAs } from './request-origin';

const base: AccessRequest = {
  id: 1,
  principal: 'alice@example.com',
  requestedDurationSec: 0,
  status: 'PENDING',
  createdAt: '2026-10-01T00:00:00Z',
  kind: 'QUERY',
  executeAs: [],
  revision: 1,
};

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
};

function render(request: AccessRequest, locale = 'en', Component: typeof RunsAs = RequestOrigin): string {
  return renderToStaticMarkup(
    <NextIntlClientProvider locale={locale} messages={{ Workflows: locale === 'en' ? en : ko }}>
      <Component request={request} />
    </NextIntlClientProvider>,
  );
}

it('links a GitHub request to its pull request and shows its path and scope', () => {
  const html = render(github);
  expect(html).toContain('href="https://github.com/acme/db/pull/12"');
  expect(html).toContain('acme/db#12');
  expect(html).toContain('sql/x.sql');
  expect(html).toContain('prod');
  expect(html).toContain(en.fields.source);
  expect(html).toContain(en.fields.scope);
});

it('shows MCP without a link', () => {
  const html = render({ ...base, source: 'mcp' });
  expect(html).toContain('MCP');
  expect(html).not.toContain('href');
});

it('renders nothing for a console request with no scope', () => {
  expect(render({ ...base, source: 'console' })).toBe('');
  expect(render(base)).toBe('');
});

it('resolves every label in Korean', () => {
  const html = render(github, 'ko');
  expect(html).toContain(ko.fields.source);
  expect(html).toContain(ko.fields.scope);
  expect(html).not.toContain('Workflows.');
});

it('approves a GitHub request without running it', () => {
  expect(runsOnMerge(github)).toBe(true);
  expect(runsOnMerge({ source: 'console' })).toBe(false);
  expect(runsOnMerge({ source: 'mcp' })).toBe(false);
  expect(runsOnMerge({})).toBe(false);
  expect(runsOnMerge(undefined)).toBe(false);
  expect(runsOnMerge(null)).toBe(false);
});

it('shows the role a query request runs as', () => {
  const html = render({ ...github, executeAs: ['schema-migrator'] }, 'en', RunsAs);
  expect(html).toContain(en.fields.runsAs);
  expect(html).toContain('schema-migrator');
  expect(render({ ...base, executeAs: ['analyst'] }, 'ko', RunsAs)).toContain(ko.fields.runsAs);
});

it('shows a dash when a query request has no execute-as role, and nothing for a role request', () => {
  expect(render(base, 'en', RunsAs)).toContain('—');
  expect(render({ ...base, kind: 'ROLE', executeAs: ['analyst'] }, 'en', RunsAs)).toBe('');
});
