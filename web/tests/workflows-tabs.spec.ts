import { expect, test, type Page, type Route } from 'playwright/test';

const SESSION_CONFIG = {
  heartbeatMs: 90_000,
  idleWarnLeadMs: 60_000,
  absoluteWarnLeadMs: 300_000,
  absoluteCapAmount: 2,
  absoluteCapUnit: 'hours',
};

async function fulfillJson(route: Route, status: number, body: object) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function mockAppShell(page: Page) {
  await page.route('**/auth/config', (route) =>
    fulfillJson(route, 200, { oidcEnabled: false, authDebug: true, session: SESSION_CONFIG }),
  );
  await page.route('**/auth/me', (route) =>
    fulfillJson(route, 200, { principal: 'sam@example.com', roles: ['system:admin'], admin: true }),
  );
  await page.route('**/api/me/permissions', (route) =>
    fulfillJson(route, 200, { isAdmin: true, canReadAllAudit: false, canApprove: true }),
  );
}

function roleRequest(id: number, principal: string, roleName: string, status = 'PENDING') {
  return {
    id,
    principal,
    roleId: id,
    roleName,
    requestedDurationSec: 3600,
    status,
    createdAt: `2026-10-0${id}T00:00:00Z`,
    kind: 'ROLE',
    reason: 'on-call',
    executeAs: [],
  };
}

const INCOMING = [roleRequest(1, 'alice@example.com', 'analyst'), roleRequest(2, 'bob@example.com', 'auditor')];
const OWN = roleRequest(3, 'sam@example.com', 'operator', 'APPROVED');

test('the selected tab stays put while opening requests from it', async ({ page }) => {
  await mockAppShell(page);
  await page.route('**/api/access-requests?status=PENDING', (route) => fulfillJson(route, 200, INCOMING));
  await page.route('**/api/access-requests', (route) => fulfillJson(route, 200, [...INCOMING, OWN]));
  await page.route('**/api/approvals/inbox', (route) => fulfillJson(route, 200, []));
  await page.route('**/api/requests/involved', (route) => fulfillJson(route, 200, []));

  await page.goto('/workflows');
  const incomingTab = page.getByRole('tab', { name: /^Incoming/ });
  const rows = page.getByTestId('workflow-request-row');
  await expect(rows).toHaveCount(3);

  await incomingTab.click();
  await expect(rows).toHaveCount(2);

  await rows.filter({ hasText: 'analyst' }).click();
  await expect(page).toHaveURL(/\/workflows\/1$/);
  await expect(incomingTab).toHaveAttribute('aria-selected', 'true');
  await expect(rows).toHaveCount(2);

  await rows.filter({ hasText: 'auditor' }).click();
  await expect(page).toHaveURL(/\/workflows\/2$/);
  await expect(incomingTab).toHaveAttribute('aria-selected', 'true');
  await expect(rows).toHaveCount(2);
  await expect(rows.filter({ hasText: 'auditor' })).toHaveAttribute('aria-current', 'page');
});
