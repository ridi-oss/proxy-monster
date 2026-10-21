import { renderToStaticMarkup } from 'react-dom/server';
import { NextIntlClientProvider } from 'next-intl';
import { expect, it } from 'vitest';
import en from '../../../messages/en/consent.json';
import ko from '../../../messages/ko/consent.json';
import { ConsentForm, type PendingConsent } from './consent-form';

const pending: PendingConsent = {
  clientName: 'Test MCP Client',
  clientId: 'https://client.example.com/oauth/client.json',
  redirectUri: 'http://127.0.0.1:43123/callback',
  loopback: true,
  scopes: ['mcp:read', 'mcp:future'],
  csrf: 'csrf_abc',
};

function render(p: PendingConsent, locale = 'en'): string {
  return renderToStaticMarkup(
    <NextIntlClientProvider locale={locale} messages={{ Consent: locale === 'en' ? en : ko }}>
      <ConsentForm pending={p} />
    </NextIntlClientProvider>,
  );
}

it('discloses the client, its redirect, and each scope, and posts the CSRF token', () => {
  const html = render(pending);
  expect(html).toContain('action="/oauth/consent"');
  expect(html).toContain('Test MCP Client');
  expect(html).toContain('http://127.0.0.1:43123/callback');
  expect(html).toContain(en.localhostWarning);
  expect(html).toContain(en.scope.mcp_read);
  expect(html).toContain('mcp:future');
  expect(html).toContain('name="csrf" value="csrf_abc"');
  expect(html).toMatch(/<button type="submit"[^>]*value="approve"[^>]*name="decision">Authorize</);
  expect(html).toMatch(/<button type="submit"[^>]*value="deny"[^>]*name="decision">Deny</);
});

it('warns about loopback redirects only', () => {
  expect(render({ ...pending, loopback: false })).not.toContain(en.localhostWarning);
});

it('localizes', () => {
  expect(render(pending, 'ko')).toContain(ko.scope.mcp_read);
});

it('has the same keys in every locale', () => {
  const keys = (o: object, p = ''): string[] =>
    Object.entries(o).flatMap(([k, v]) => (typeof v === 'object' ? keys(v, `${p}${k}.`) : [`${p}${k}`]));
  expect(keys(ko).sort()).toEqual(keys(en).sort());
});
