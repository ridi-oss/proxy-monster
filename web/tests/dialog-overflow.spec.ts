import { expect, test, type Page, type Route } from 'playwright/test';

const SESSION_CONFIG = {
  heartbeatMs: 90_000,
  idleWarnLeadMs: 60_000,
  absoluteWarnLeadMs: 300_000,
  absoluteCapAmount: 2,
  absoluteCapUnit: 'hours',
};

function sessionStatus() {
  const now = Date.now();
  return {
    now: new Date(now).toISOString(),
    idleExpiresAt: new Date(now + 15 * 60_000).toISOString(),
    absoluteExpiresAt: new Date(now + 2 * 60 * 60_000).toISOString(),
    principal: 'sam@example.com',
    sessionId: 41,
  };
}

async function fulfillJson(route: Route, status: number, body: object) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function mockAppShell(page: Page) {
  await page.route('**/auth/config', (route) =>
    fulfillJson(route, 200, { oidcEnabled: false, authDebug: true, session: SESSION_CONFIG }),
  );
  await page.route('**/auth/me', (route) => fulfillJson(route, 200, { principal: 'sam@example.com', roles: [] }));
  await page.route('**/auth/session/heartbeat', (route) => fulfillJson(route, 200, sessionStatus()));
  await page.route('**/auth/session/status', (route) => fulfillJson(route, 200, sessionStatus()));
  await page.route('**/api/me/permissions', (route) =>
    fulfillJson(route, 200, { isAdmin: false, canReadAllAudit: false, canApprove: false }),
  );
}

// Far taller than any viewport once the textarea sizes itself to the content, and led by an IN list with no
// break opportunity — far wider than the dialog.
const LONG_SQL = [
  `SELECT id, email FROM users WHERE id IN (${Array.from({ length: 300 }, (_, i) => i + 1).join(',')});`,
  ...Array.from(
    { length: 200 },
    (_, i) => `SELECT id, email, name FROM users WHERE id = ${i + 1} AND email LIKE '%example_${i + 1}%';`,
  ),
].join('\n');

const LONG_REQUEST = {
  id: 7,
  kind: 'QUERY',
  principal: 'sam@example.com',
  datasourceId: 1,
  datasourceName: 'demo',
  status: 'PENDING',
  title: 'Long query',
  sql: LONG_SQL,
  reason: 'Monthly report',
  createdAt: '2026-07-24T00:00:00Z',
  evaluatedDecision: 'ALLOW',
  executeAs: ['analyst'],
  roleName: 'analyst',
  source: 'console',
  revision: 1,
  ccs: [],
  private: false,
};

test('the edit dialog of a long query stays inside the viewport with its actions reachable', async ({ page }) => {
  await mockAppShell(page);
  await page.route('**/api/access-requests**', (route) => fulfillJson(route, 200, []));
  await page.route('**/api/approvals/inbox', (route) => fulfillJson(route, 200, []));
  await page.route('**/api/requests/involved', (route) => fulfillJson(route, 200, [LONG_REQUEST]));
  await page.route('**/api/approvals/7', (route) =>
    fulfillJson(route, 200, {
      request: LONG_REQUEST,
      canDecide: false,
      canEdit: true,
      canClose: true,
      timeline: [],
      statements: [],
    }),
  );

  await page.goto('/workflows/7');
  await page.getByRole('button', { name: 'Edit', exact: true }).click();

  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel('SQL')).toHaveValue(LONG_SQL);

  const viewport = page.viewportSize()!;
  const box = (await dialog.boundingBox())!;
  expect(box.y).toBeGreaterThanOrEqual(0);
  expect(box.y + box.height).toBeLessThanOrEqual(viewport.height);

  const sqlBox = (await dialog.getByLabel('SQL').boundingBox())!;
  expect(sqlBox.x + sqlBox.width).toBeLessThanOrEqual(box.x + box.width);
  expect(await dialog.evaluate((el) => el.scrollWidth - el.clientWidth)).toBe(0);

  await expect(dialog.getByRole('heading', { name: 'Edit request' })).toBeInViewport({ ratio: 1 });
  await expect(dialog.getByRole('button', { name: 'Save', exact: true })).toBeInViewport({ ratio: 1 });
  await expect(dialog.getByRole('button', { name: 'Cancel', exact: true })).toBeInViewport({ ratio: 1 });
});
