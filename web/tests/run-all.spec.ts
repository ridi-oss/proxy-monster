import { expect, test, type Page, type Route } from 'playwright/test'

const SESSION_CONFIG = {
  heartbeatMs: 90_000,
  idleWarnLeadMs: 60_000,
  absoluteWarnLeadMs: 300_000,
  absoluteCapAmount: 2,
  absoluteCapUnit: 'hours',
}

function sessionStatus() {
  const now = Date.now()
  return {
    now: new Date(now).toISOString(),
    idleExpiresAt: new Date(now + 15 * 60_000).toISOString(),
    absoluteExpiresAt: new Date(now + 2 * 60 * 60_000).toISOString(),
    principal: 'sam@example.com',
    sessionId: 41,
  }
}

async function fulfillJson(route: Route, status: number, body: object) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
}

const SCRIPT = 'start transaction;\n-- bump the stamps\nupdate stamp set mission_id = mission_id + 4;\nrollback;'
const STATEMENTS = ['start transaction', '-- bump the stamps\nupdate stamp set mission_id = mission_id + 4', 'rollback']

interface Recorded {
  sessionQueries: string[]
  scripts: Array<{ sql: string; timeoutSeconds?: number }>
  deletedTasks: string[]
}

async function mockEditor(page: Page): Promise<Recorded> {
  const recorded: Recorded = { sessionQueries: [], scripts: [], deletedTasks: [] }
  await page.route('**/auth/config', (route) => fulfillJson(route, 200, { oidcEnabled: false, authDebug: true, session: SESSION_CONFIG }))
  await page.route('**/auth/me', (route) => fulfillJson(route, 200, { principal: 'sam@example.com', roles: [] }))
  await page.route('**/auth/session/heartbeat', (route) => fulfillJson(route, 200, sessionStatus()))
  await page.route('**/auth/session/status', (route) => fulfillJson(route, 200, sessionStatus()))
  await page.route('**/api/me/permissions', (route) => fulfillJson(route, 200, { isAdmin: false, canReadAllAudit: false, canApprove: false }))
  await page.route('**/api/datasources**', (route) => fulfillJson(route, 200, [{ id: 1, name: 'demo', engine: 'mysql' }]))
  await page.route('**/api/datasources/1/catalog', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/query-history**', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/editor/sessions', (route) => fulfillJson(route, 200, { sessionId: 'session-1' }))
  await page.route('**/api/editor/sessions/session-1/query', (route) => {
    recorded.sessionQueries.push(route.request().postDataJSON().sql)
    return fulfillJson(route, 202, { taskId: 9, childId: 10 })
  })
  await page.route('**/api/editor/scripts', (route) => {
    recorded.scripts.push(route.request().postDataJSON())
    return fulfillJson(route, 202, { taskId: 50, childId: 51, statements: STATEMENTS })
  })
  await page.route('**/api/editor/tasks/50', (route) => {
    if (route.request().method() === 'DELETE') {
      recorded.deletedTasks.push('50')
      return route.fulfill({ status: 204 })
    }
    return fulfillJson(route, 200, {
      taskId: 50,
      status: 'EXECUTED',
      result: null,
      statements: STATEMENTS.map((sql, ordinal) => ({
        taskId: 50,
        ordinal,
        sql,
        status: 'DONE',
        rowCount: ordinal === 1 ? 124 : 0,
        columns: [],
      })),
    })
  })
  await page.route('**/api/editor/tasks/50/result**', (route) => fulfillJson(route, 200, {
    decision: 'ALLOW',
    maskedColumns: [],
    columns: [],
    rows: [],
    truncatedByCap: false,
    truncatedAt: null,
  }))
  return recorded
}

async function typeScript(page: Page, text: string) {
  await page.locator('.cm-content').click()
  await page.keyboard.insertText(text)
}

async function selectAllInEditor(page: Page) {
  await page.locator('.cm-content').click()
  await page.keyboard.press('ControlOrMeta+a')
}

test('Run needs one selected statement once the editor holds several', async ({ page }) => {
  const recorded = await mockEditor(page)
  await page.goto('/query')
  await typeScript(page, 'select 1;\nselect 2;')

  await page.getByRole('button', { name: 'Run', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('Select the one statement to run')

  await selectAllInEditor(page)
  await page.getByRole('button', { name: 'Run', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('use Run All')
  expect(recorded.sessionQueries).toEqual([])
})

test('Run All needs the whole script selected, then runs it raw and groups its tabs', async ({ page }) => {
  const recorded = await mockEditor(page)
  await page.goto('/query')
  await typeScript(page, SCRIPT)

  await page.getByRole('button', { name: 'Run All' }).click()
  await expect(page.getByRole('status')).toContainText('Select all of it')
  expect(recorded.scripts).toEqual([])

  await selectAllInEditor(page)
  await page.keyboard.press('Shift+ControlOrMeta+Enter')
  await expect.poll(() => recorded.scripts).toEqual([{ datasourceId: 1, sql: SCRIPT, maxRows: 200, timeoutSeconds: 300 }])

  await expect(page.getByText('Every statement ran. The connection is closed.')).toBeVisible()
  await expect(page.getByText('124 affected')).toBeVisible()
  await expect(page.locator('[data-group-tab]')).toHaveCount(4)

  await page.locator('[data-script-statement="1"]').click()
  await expect(page.locator('[data-result-tab][aria-selected="true"]')).toContainText('2. -- bump the stamps')

  await page.getByRole('button', { name: "Hide the script's tabs" }).click()
  await expect(page.locator('[data-group-tab]')).toHaveCount(1)

  await page.getByRole('button', { name: "Close the script's tabs" }).click()
  await expect(page.locator('[data-group-tab]')).toHaveCount(0)
  await expect.poll(() => recorded.deletedTasks).toEqual(['50'])
})

test('Run All asks before running a script that would autocommit each statement', async ({ page }) => {
  const recorded = await mockEditor(page)
  await page.goto('/query')
  await typeScript(page, 'update stamp set mission_id = 1;\nselect 1;')
  await selectAllInEditor(page)
  await page.getByRole('button', { name: 'Run All' }).click()

  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText('Run without a transaction?')
  await dialog.getByRole('button', { name: 'Go back' }).click()
  expect(recorded.scripts).toEqual([])

  await page.getByRole('button', { name: 'Run All' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Run anyway' }).click()
  await expect.poll(() => recorded.scripts.length).toBe(1)
})
