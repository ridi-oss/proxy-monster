import { expect, test, type Page, type Route } from 'playwright/test'

// The console's side of the result caps (docs/result-caps.md): a cap-truncated result says so; an old
// RATE_RESET request still shows on Workflows as history.

const SESSION_CONFIG = {
  heartbeatMs: 90_000,
  idleWarnLeadMs: 60_000,
  absoluteWarnLeadMs: 300_000,
  absoluteCapAmount: 2,
  absoluteCapUnit: 'hours',
}

async function fulfillJson(route: Route, status: number, body: object) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
}

async function mockAppShell(page: Page, admin = false, principal = 'sam@example.com') {
  await page.route('**/auth/config', (route) =>
    fulfillJson(route, 200, { oidcEnabled: false, authDebug: true, session: SESSION_CONFIG }),
  )
  await page.route('**/auth/me', (route) =>
    fulfillJson(route, 200, { principal, roles: admin ? ['system:admin'] : [], admin }),
  )
  await page.route('**/api/me/permissions', (route) =>
    fulfillJson(route, 200, { isAdmin: admin, canReadAllAudit: false, canApprove: admin }),
  )
}

function datasource(overrides: Record<string, unknown> = {}) {
  return {
    id: 1,
    name: 'demo',
    engine: 'mysql',
    host: 'db.internal',
    port: 3306,
    dbName: 'acme',
    tags: [],
    defaultSchemas: [],
    ...overrides,
  }
}

async function mockEditorShell(page: Page) {
  await page.route('**/api/datasources**', (route) => fulfillJson(route, 200, [datasource()]))
  await page.route('**/api/datasources/1/catalog', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/query-history**', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/editor/sessions', (route) => fulfillJson(route, 200, { sessionId: 'session-1' }))
  await page.route('**/api/editor/sessions/session-1/query', (route) =>
    fulfillJson(route, 202, { taskId: 9, childId: 10 }),
  )
}

async function runInEditor(page: Page, sql: string) {
  await page.goto('/query')
  await page.locator('.cm-content').click()
  await page.keyboard.insertText(sql)
  await page.getByRole('button', { name: 'Run' }).click()
}

const RATE_RESET_REQUEST = {
  id: 77,
  principal: 'sam@example.com',
  requestedDurationSec: 0,
  status: 'APPROVED',
  createdAt: '2026-09-16T10:00:00Z',
  decidedBy: 'approver@example.com',
  decidedAt: '2026-09-16T10:05:00Z',
  kind: 'RATE_RESET',
  reason: 'monthly export re-run',
  denyReason: 'rate 10000/1h spent',
  executeAs: [],
}

test('a cap-truncated result shows the incomplete-set notice', async ({ page }) => {
  await mockAppShell(page)
  await mockEditorShell(page)
  await page.route('**/api/editor/tasks/9', (route) =>
    fulfillJson(route, 200, {
      taskId: 9,
      status: 'EXECUTED',
      result: { taskId: 9, status: 'DONE', ordinal: 0, rowCount: 2, columns: ['id'] },
    }),
  )
  await page.route('**/api/editor/tasks/9/result**', (route) =>
    fulfillJson(route, 200, {
      meta: { taskId: 9, status: 'DONE', ordinal: 0, rowCount: 2, columns: ['id'] },
      columns: ['id'],
      rows: [['1'], ['2']],
      decision: 'ALLOW',
      maskedColumns: [],
      // The EXECUTION's cap ended these rows; the view released all of them, so truncatedAt is absent —
      // exactly the shape a run capped at its verdict produces.
      truncatedByCap: true,
    }),
  )

  await runInEditor(page, 'select id from users')

  await expect(page.getByTestId('result-cap-notice')).toBeVisible()
  await expect(page.getByTestId('result-cap-notice')).toContainText('incomplete')
})

test('a view cut by the viewer cap shows the same notice', async ({ page }) => {
  await mockAppShell(page)
  await mockEditorShell(page)
  await page.route('**/api/editor/tasks/9', (route) =>
    fulfillJson(route, 200, {
      taskId: 9,
      status: 'EXECUTED',
      result: { taskId: 9, status: 'DONE', ordinal: 0, rowCount: 12, columns: ['id'] },
    }),
  )
  await page.route('**/api/editor/tasks/9/result**', (route) =>
    fulfillJson(route, 200, {
      meta: { taskId: 9, status: 'DONE', ordinal: 0, rowCount: 12, columns: ['id'] },
      columns: ['id'],
      rows: [['1'], ['2'], ['3'], ['4'], ['5']],
      decision: 'ALLOW',
      maskedColumns: [],
      truncatedAt: 5,
      truncatedByCap: false,
    }),
  )

  await runInEditor(page, 'select id from users')

  await expect(page.getByTestId('result-cap-notice')).toBeVisible()
  await expect(page.getByRole('row')).toHaveCount(6)
})

test('an ordinary policy denial offers approval and access', async ({ page }) => {
  await mockAppShell(page)
  await mockEditorShell(page)
  await page.route('**/api/editor/tasks/9', (route) =>
    fulfillJson(route, 200, {
      taskId: 9,
      status: 'FAILED',
      result: {
        taskId: 9,
        status: 'FAILED',
        ordinal: 0,
        errorCode: 'approval.execute_denied',
        denyReason: 'ssn is off-limits',
        decisionId: 4242,
        columns: [],
      },
    }),
  )

  await runInEditor(page, 'select ssn from users')

  const results = page.getByLabel('Results')
  await expect(results.getByText('Query denied')).toBeVisible()
  await expect(results.getByRole('button', { name: 'Request access' })).toBeVisible()
  await expect(results.getByRole('button', { name: 'Request approval' })).toBeVisible()
})

test('an old RATE_RESET request still shows on Workflows as read-only history', async ({ page }) => {
  await mockAppShell(page)
  await page.route('**/api/access-requests?status=PENDING', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/access-requests', (route) => fulfillJson(route, 200, [RATE_RESET_REQUEST]))
  await page.route('**/api/approvals/inbox', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/requests/involved', (route) => fulfillJson(route, 200, []))

  await page.goto('/workflows')
  const row = page.getByTestId('workflow-request-row').filter({ hasText: 'Rate reset' })
  await expect(row).toBeVisible()
  await expect(row).toContainText('sam@example.com · rate 10000/1h spent')
  await row.click()

  const detail = page.locator('[data-workflow-detail-kind="RATE_RESET"]')
  await expect(detail).toBeVisible()
  await expect(detail.getByText('Rate reset request #77')).toBeVisible()
  await expect(detail.getByText('monthly export re-run')).toBeVisible()
  await expect(detail.getByText('Rate resets were removed.', { exact: false })).toBeVisible()
  await expect(detail.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0)
  await expect(detail.getByRole('button', { name: 'Reject', exact: true })).toHaveCount(0)

  await page.getByRole('button', { name: 'New request' }).click()
  await expect(page.getByRole('menuitem', { name: 'Role access request' })).toBeVisible()
  await expect(page.getByRole('menuitem', { name: /rate reset/i })).toHaveCount(0)
})
