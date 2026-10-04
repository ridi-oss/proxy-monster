import { renderToStaticMarkup } from 'react-dom/server'
import { NextIntlClientProvider } from 'next-intl'
import { expect, it } from 'vitest'
import en from '../../../messages/en/device.json'
import ko from '../../../messages/ko/device.json'
import { DeviceScopes } from './device-scopes'

function render(scopes: string[], elevatedTtlSeconds: number | null, locale = 'en'): string {
  return renderToStaticMarkup(
    <NextIntlClientProvider locale={locale} messages={{ Device: locale === 'en' ? en : ko }}>
      <DeviceScopes scopes={scopes} elevatedTtlSeconds={elevatedTtlSeconds} />
    </NextIntlClientProvider>,
  )
}

it('lists each scope beyond the default pair in plain words, with its window', () => {
  const html = render(['mcp:query', 'mcp:read', 'mcp:approvals:write', 'mcp:tokens'], 3600)
  expect(html).toContain(en.scopes.names.mcp_approvals_write)
  expect(html).toContain('mcp:approvals:write')
  expect(html).toContain(en.scopes.names.mcp_tokens)
  expect(html).toContain('for 1 hour')
  expect(html).not.toContain('mcp:read')
  expect(html).not.toContain('mcp:query')
  expect(html.match(/<li>/g)).toHaveLength(2)
})

it('localizes the window and the scope lines', () => {
  const html = render(['mcp:policies:write'], 1800, 'ko')
  expect(html).toContain(ko.scopes.names.mcp_policies_write)
  expect(html).toContain('30분')
})

it('shows nothing extra for the default pair or a subset of it', () => {
  expect(render(['mcp:read', 'mcp:query'], null)).toBe('')
  expect(render(['mcp:read'], null)).toBe('')
})
