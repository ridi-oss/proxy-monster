import { expect, test, type Page } from 'playwright/test';

// The Cedar policy editor lints in the browser through @cedar-policy/cedar-wasm: a parse error and a
// schema type error both mark the source, and a valid policy leaves it clean.

const SESSION_CONFIG = {
  heartbeatMs: 90_000,
  idleWarnLeadMs: 60_000,
  absoluteWarnLeadMs: 300_000,
  absoluteCapAmount: 2,
  absoluteCapUnit: 'hours',
};

const SCHEMA = `entity User;
entity Datasource;
action "datasource.connect" appliesTo { principal: [User], resource: [Datasource] };`;

async function boot(page: Page) {
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
  await page.route('**/api/policies', (r) => r.fulfill({ contentType: 'application/json', body: '[]' }));
  await page.route('**/api/policies/schema', (r) =>
    r.fulfill({ contentType: 'application/json', body: JSON.stringify({ schema: SCHEMA }) }),
  );
}

async function typeSource(page: Page, src: string) {
  await page.goto('/admin/policies/cedar-policies');
  await page.getByRole('button', { name: 'Add policy' }).first().click();
  const editor = page.getByRole('dialog').locator('.cm-content');
  await editor.click();
  await page.keyboard.insertText(src);
}

const lintError = (page: Page) => page.getByRole('dialog').locator('.cm-lintRange-error, .cm-lintPoint-error');

test('a parse error is marked by the in-browser linter', async ({ page }) => {
  await boot(page);
  await typeSource(page, 'permit(principal, action resource);');
  await expect(lintError(page).first()).toBeVisible({ timeout: 20_000 });
});

test('an action the schema does not declare is marked', async ({ page }) => {
  await boot(page);
  await typeSource(page, 'permit(principal, action == Action::"no.such.action", resource);');
  await expect(lintError(page).first()).toBeVisible({ timeout: 20_000 });
});

test('a valid policy lints clean', async ({ page }) => {
  await boot(page);
  await typeSource(page, 'permit(principal, action == Action::"datasource.connect", resource);');
  await page.waitForTimeout(3_000);
  await expect(lintError(page)).toHaveCount(0);
  // Proves the linter was live, not just absent.
  await page.keyboard.insertText(' when {');
  await expect(lintError(page).first()).toBeVisible({ timeout: 20_000 });
});
