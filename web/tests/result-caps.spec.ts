import { expect, test, type Page, type Route } from 'playwright/test'

// The console's side of the result caps (docs/result-caps.md): a result the cap cut short says so instead
// of reading as a complete page.

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

async function mockAppShell(page: Page, admin = false) {
  await page.route('**/auth/config', (route) =>
    fulfillJson(route, 200, { oidcEnabled: false, authDebug: true, session: SESSION_CONFIG }),
  )
  await page.route('**/auth/me', (route) =>
    fulfillJson(route, 200, { principal: 'sam@example.com', roles: [], admin }),
  )
  await page.route('**/api/me/permissions', (route) =>
    fulfillJson(route, 200, { isAdmin: admin, canReadAllAudit: false, canApprove: false }),
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

test('a cap-truncated result shows the incomplete-set notice', async ({ page }) => {
  await mockAppShell(page)
  await page.route('**/api/datasources**', (route) => fulfillJson(route, 200, [datasource()]))
  await page.route('**/api/datasources/1/catalog', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/query-history**', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/editor/sessions', (route) => fulfillJson(route, 200, { sessionId: 'session-1' }))
  await page.route('**/api/editor/sessions/session-1/query', (route) =>
    fulfillJson(route, 202, { taskId: 9, childId: 10 }),
  )
  await page.route('**/api/editor/tasks/9', (route) =>
    fulfillJson(route, 200, {
      taskId: 9,
      status: 'EXECUTED',
      result: { status: 'DONE', ordinal: 0, rowCount: 2, columns: ['id'] },
    }),
  )
  await page.route('**/api/editor/tasks/9/result**', (route) =>
    fulfillJson(route, 200, {
      meta: { status: 'DONE', ordinal: 0, rowCount: 2, columns: ['id'] },
      columns: ['id'],
      rows: [['1'], ['2']],
      decision: 'ALLOW',
      maskedColumns: [],
      // The EXECUTION's cap ended these rows; the view released all of them, so truncatedAt is absent —
      // exactly the shape a run capped at its verdict produces.
      truncatedByCap: true,
    }),
  )

  await page.goto('/query')
  await page.locator('.cm-content').click()
  await page.keyboard.insertText('select id from users')
  await page.getByRole('button', { name: 'Run' }).click()

  await expect(page.getByTestId('result-cap-notice')).toBeVisible()
  await expect(page.getByTestId('result-cap-notice')).toContainText('incomplete')
})
