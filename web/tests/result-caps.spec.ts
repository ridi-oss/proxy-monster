import { expect, test, type Page, type Route } from 'playwright/test'

// The console's side of the result caps (docs/result-caps.md): a cap-truncated result says so; a spent rate
// offers a RATE_RESET request instead of a role; the request is decided on the Workflows page; an admin
// resets a principal's rates from the Users page.

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
  status: 'PENDING',
  createdAt: '2026-09-16T10:00:00Z',
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

test('a spent rate offers a rate-reset request and files it with the deny reason', async ({ page }) => {
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
        denyReason: 'rate 10000/1h spent',
        decisionId: 4242,
        columns: [],
      },
    }),
  )
  let filed: Record<string, unknown> | null = null
  await page.route('**/api/access-requests/rate-reset', async (route) => {
    filed = route.request().postDataJSON()
    await fulfillJson(route, 201, RATE_RESET_REQUEST)
  })

  await runInEditor(page, 'select id from users')

  // The workbench toolbar has its own "Request access"; the callout is what a denial changes.
  const results = page.getByLabel('Results')
  await expect(results.getByText('Query denied')).toBeVisible()
  await expect(results.getByText('rate 10000/1h spent')).toBeVisible()
  // A rate denial is not a role problem: neither "Request approval" nor "Request access" is offered.
  await expect(results.getByRole('button', { name: 'Request access' })).toHaveCount(0)
  await expect(results.getByRole('button', { name: 'Request approval' })).toHaveCount(0)

  await page.getByTestId('request-rate-reset').click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText('rate 10000/1h spent')).toBeVisible()
  const submit = dialog.getByRole('button', { name: 'Request reset' })
  await expect(submit).toBeDisabled()
  await dialog.locator('#rate-reset-reason').fill('monthly export re-run')
  await submit.click()

  await expect(dialog.getByText('Requested — awaiting approval')).toBeVisible()
  await expect.poll(() => filed).toEqual({ reason: 'monthly export re-run', denyReason: 'rate 10000/1h spent' })
})

test('an ordinary policy denial still offers approval and access, never a rate reset', async ({ page }) => {
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
  await expect(results.getByTestId('request-rate-reset')).toHaveCount(0)
})

test('an approver sees the RATE_RESET request on Workflows and approves it', async ({ page }) => {
  await mockAppShell(page, true, 'approver@example.com')
  await page.route('**/api/access-requests?status=PENDING', (route) => fulfillJson(route, 200, [RATE_RESET_REQUEST]))
  await page.route('**/api/access-requests', (route) => fulfillJson(route, 200, [RATE_RESET_REQUEST]))
  await page.route('**/api/approvals/inbox', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/approvals', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/approvals?**', (route) => fulfillJson(route, 200, []))
  let approved = false
  await page.route('**/api/access-requests/77/approve', async (route) => {
    approved = true
    await fulfillJson(route, 200, { ...RATE_RESET_REQUEST, status: 'APPROVED', decidedBy: 'approver@example.com', decidedAt: '2026-09-16T10:05:00Z' })
  })

  await page.goto('/workflows')
  const row = page.getByTestId('workflow-request-row').filter({ hasText: 'Rate reset' })
  await expect(row).toBeVisible()
  await expect(row).toContainText('sam@example.com · rate 10000/1h spent')
  await row.click()

  const detail = page.locator('[data-workflow-detail-kind="RATE_RESET"]')
  await expect(detail).toBeVisible()
  await expect(detail.getByText('Rate reset request #77')).toBeVisible()
  await expect(detail.getByText('rate 10000/1h spent')).toBeVisible()
  await expect(detail.getByText('monthly export re-run')).toBeVisible()
  await detail.getByRole('button', { name: 'Approve', exact: true }).click()

  await expect.poll(() => approved).toBe(true)
  await expect(page.getByText("Approved — reset sam@example.com's result rates")).toBeVisible()
})

test('an admin resets a principal\'s result rates from the Users page', async ({ page }) => {
  await mockAppShell(page, true, 'admin@example.com')
  await page.route('**/api/users', (route) =>
    fulfillJson(route, 200, [
      { id: 1, principal: 'sam@example.com', source: 'LOCAL', active: true, createdAt: '2026-09-01T00:00:00Z', groups: [] },
    ]),
  )
  await page.route('**/api/groups', (route) => fulfillJson(route, 200, []))
  let reset: Record<string, unknown> | null = null
  await page.route('**/api/access/principals/sam%40example.com/rate-reset', async (route) => {
    if (route.request().method() === 'POST') {
      reset = route.request().postDataJSON()
      return fulfillJson(route, 200, { principal: 'sam@example.com', resetAt: '2026-09-16T10:10:00Z', resetBy: 'admin@example.com', reason: 'false positive' })
    }
    return route.fulfill({ status: 204, body: '' })
  })

  await page.goto('/admin/users')
  const row = page.getByRole('row').filter({ hasText: 'sam@example.com' })
  await row.getByRole('button', { name: 'More actions' }).click()
  await page.getByRole('menuitem', { name: 'Reset result rates' }).click()

  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  await expect(dialog.getByTestId('rate-reset-last')).toHaveText('Never reset.')
  const submit = dialog.getByRole('button', { name: 'Reset', exact: true })
  await expect(submit).toBeDisabled()
  await dialog.locator('#admin-rate-reset-reason').fill('false positive')
  await submit.click()

  await expect.poll(() => reset).toEqual({ reason: 'false positive' })
  await expect(page.getByText('Reset result rates for sam@example.com')).toBeVisible()
  await expect(dialog).toHaveCount(0)
})

test('the reset dialog shows the last reset when one exists', async ({ page }) => {
  await mockAppShell(page, true, 'admin@example.com')
  await page.route('**/api/users', (route) =>
    fulfillJson(route, 200, [
      { id: 1, principal: 'sam@example.com', source: 'LOCAL', active: true, createdAt: '2026-09-01T00:00:00Z', groups: [] },
    ]),
  )
  await page.route('**/api/groups', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/access/principals/sam%40example.com/rate-reset', (route) =>
    fulfillJson(route, 200, { principal: 'sam@example.com', resetAt: '2026-09-16T10:10:00Z', resetBy: 'ops@example.com', reason: 'earlier' }),
  )

  await page.goto('/admin/users')
  await page.getByRole('row').filter({ hasText: 'sam@example.com' }).getByRole('button', { name: 'More actions' }).click()
  await page.getByRole('menuitem', { name: 'Reset result rates' }).click()

  await expect(page.getByTestId('rate-reset-last')).toContainText('by ops@example.com')
})
