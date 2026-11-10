import { expect, test, type Page } from 'playwright/test';

const SESSION_CONFIG = {
  heartbeatMs: 90_000,
  idleWarnLeadMs: 60_000,
  absoluteWarnLeadMs: 300_000,
  absoluteCapAmount: 2,
  absoluteCapUnit: 'hours',
};

const ISSUERS = [
  { name: 'aws-prod', kind: 'aws-sts', url: 'https://example.tokens.sts.global.api.aws' },
  { name: 'github', kind: 'github-actions', url: 'https://token.actions.githubusercontent.com' },
];

const BINDING = {
  id: 7,
  name: 'batch-settlement',
  issuer: 'aws-prod',
  subject: 'arn:aws:iam::111122223333:role/batch-settlement',
  conditions: { 'principal_tags.kubernetes-namespace': ['batch'] },
  principal: 'svc:batch-settlement',
  purposes: ['wire'],
  mcpScopes: [],
  ttlSeconds: 900,
  enabled: true,
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
};

async function boot(page: Page, bindings: unknown[]) {
  await page.route('**/auth/config', (r) =>
    r.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ oidcEnabled: false, authDebug: true, session: SESSION_CONFIG }),
    }),
  );
  await page.route('**/auth/me', (r) =>
    r.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ principal: 'admin@example.com', roles: ['system:admin'], admin: true }),
    }),
  );
  await page.route('**/api/me/permissions', (r) =>
    r.fulfill({ contentType: 'application/json', body: JSON.stringify({ isAdmin: true }) }),
  );
  await page.route('**/api/workload-issuers', (r) =>
    r.fulfill({ contentType: 'application/json', body: JSON.stringify(ISSUERS) }),
  );
  await page.route('**/api/workload-bindings', (r) => {
    if (r.request().method() === 'GET') {
      return r.fulfill({ contentType: 'application/json', body: JSON.stringify(bindings) });
    }
    return r.fallback();
  });
}

test('lists a binding with its issuer kind, subject, condition, and principal', async ({ page }) => {
  await boot(page, [BINDING]);
  await page.goto('/admin/workload-bindings');
  await expect(page.getByText('batch-settlement', { exact: true })).toBeVisible();
  await expect(page.getByText('AWS STS')).toBeVisible();
  await expect(page.getByText(BINDING.subject)).toBeVisible();
  await expect(page.getByText('principal_tags.kubernetes-namespace=batch')).toBeVisible();
  await expect(page.getByText('svc:batch-settlement')).toBeVisible();
});

test('creating a binding posts the parsed conditions and purposes', async ({ page }) => {
  await boot(page, []);
  let posted: unknown = null;
  await page.route('**/api/workload-bindings', (r) => {
    if (r.request().method() === 'POST') {
      posted = r.request().postDataJSON();
      return r.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(BINDING) });
    }
    return r.fallback();
  });
  await page.goto('/admin/workload-bindings');
  await page.getByRole('button', { name: 'Add binding' }).first().click();
  await page.locator('#binding-name').fill('batch-settlement');
  await page.locator('#binding-subject').fill(BINDING.subject);
  await page.locator('#binding-conditions').fill('principal_tags.kubernetes-namespace=batch');
  await page.getByRole('dialog').getByRole('button', { name: 'Add binding' }).click();
  await expect.poll(() => posted).not.toBeNull();
  expect(posted).toMatchObject({
    name: 'batch-settlement',
    issuer: 'aws-prod',
    subject: BINDING.subject,
    conditions: { 'principal_tags.kubernetes-namespace': ['batch'] },
    purposes: ['wire'],
    mcpScopes: [],
    ttlSeconds: 900,
    enabled: true,
  });
});

test('delete asks for confirmation and calls DELETE', async ({ page }) => {
  await boot(page, [BINDING]);
  let deleted = false;
  await page.route('**/api/workload-bindings/7', (r) => {
    if (r.request().method() === 'DELETE') {
      deleted = true;
      return r.fulfill({ status: 204, body: '' });
    }
    return r.fallback();
  });
  await page.goto('/admin/workload-bindings');
  await page.getByRole('button', { name: 'More actions' }).click();
  await page.getByRole('menuitem', { name: 'Delete' }).click();
  await expect(page.getByText(/Every token it minted is revoked/)).toBeVisible();
  await page.getByRole('button', { name: 'Delete' }).click();
  await expect.poll(() => deleted).toBe(true);
});
