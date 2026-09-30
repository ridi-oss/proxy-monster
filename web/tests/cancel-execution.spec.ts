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

async function mockAppShell(page: Page) {
  await page.route('**/auth/config', (route) => fulfillJson(route, 200, {
    oidcEnabled: false,
    authDebug: true,
    session: SESSION_CONFIG,
  }))
  await page.route('**/auth/me', (route) => fulfillJson(route, 200, {
    principal: 'sam@example.com',
    roles: [],
  }))
  await page.route('**/auth/session/heartbeat', (route) => fulfillJson(route, 200, sessionStatus()))
  await page.route('**/auth/session/status', (route) => fulfillJson(route, 200, sessionStatus()))
  await page.route('**/api/me/permissions', (route) => fulfillJson(route, 200, {
    isAdmin: false,
    canReadAllAudit: false,
    canApprove: false,
  }))
}

function request(id: number, status: string) {
  return {
    id,
    kind: 'QUERY',
    principal: 'sam@example.com',
    datasourceId: 1,
    datasourceName: 'demo',
    status,
    title: 'Long-running query',
    sql: 'select sleep(30)',
    reason: 'Investigating a report',
    createdAt: '2026-07-24T00:00:00Z',
    decidedAt: '2026-07-24T00:01:00Z',
    decidedBy: 'approver@example.com',
    evaluatedDecision: 'ALLOW',
  }
}

test('a running editor task can be canceled and polling settles on the canceled state', async ({ page }) => {
  await mockAppShell(page)
  await page.route('**/api/datasources**', (route) => fulfillJson(route, 200, [
    { id: 1, name: 'demo', engine: 'mysql' },
  ]))
  await page.route('**/api/datasources/1/catalog', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/query-history**', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/editor/sessions', (route) => fulfillJson(route, 200, { sessionId: 'session-1' }))
  await page.route('**/api/editor/sessions/session-1/query', (route) => {
    expect(route.request().method()).toBe('POST')
    return fulfillJson(route, 202, { taskId: 9, childId: 10 })
  })

  let canceled = false
  let statusPolls = 0
  let cancelPosts = 0
  await page.route('**/api/editor/tasks/9/cancel', async (route) => {
    expect(route.request().method()).toBe('POST')
    cancelPosts += 1
    await fulfillJson(route, 200, {
      taskId: 9,
      status: 'CANCELLED',
      result: { status: 'CANCELLED', rowCount: null, columns: [], errorCode: 'approval.canceled' },
    })
    canceled = true
  })
  await page.route('**/api/editor/tasks/9', (route) => {
    statusPolls += 1
    return fulfillJson(route, 200, {
      taskId: 9,
      status: canceled ? 'CANCELLED' : 'EXECUTING',
      result: {
        status: canceled ? 'CANCELLED' : 'RUNNING',
        rowCount: null,
        columns: [],
        errorCode: canceled ? 'approval.canceled' : null,
      },
    })
  })

  await page.goto('/query')
  const editor = page.locator('.cm-content')
  await editor.click()
  await page.keyboard.insertText('select sleep(30)')
  await page.getByRole('button', { name: 'Run', exact: true }).click()

  await page.getByTestId('cancel-editor-task').click()
  await expect.poll(() => cancelPosts).toBe(1)
  await expect(page.getByText('Query canceled')).toBeVisible()

  const settledPollCount = statusPolls
  await page.waitForTimeout(1_200)
  expect(statusPolls).toBe(settledPollCount)
})

test('ending the editor session closes it, settles its running task, and the next run opens a new one', async ({ page }) => {
  await mockAppShell(page)
  await page.route('**/api/datasources**', (route) => fulfillJson(route, 200, [
    { id: 1, name: 'demo', engine: 'mysql' },
  ]))
  await page.route('**/api/datasources/1/catalog', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/query-history**', (route) => fulfillJson(route, 200, []))

  let opened = 0
  await page.route('**/api/editor/sessions', (route) => {
    opened += 1
    return fulfillJson(route, 200, { sessionId: `session-${opened}` })
  })
  const submittedOn: string[] = []
  await page.route('**/api/editor/sessions/*/query', (route) => {
    submittedOn.push(new URL(route.request().url()).pathname.split('/')[4]!)
    return fulfillJson(route, 202, { taskId: 20 + submittedOn.length, childId: 30 })
  })
  const closed: string[] = []
  await page.route('**/api/editor/sessions/session-*', (route) => {
    if (route.request().method() !== 'DELETE') return route.fallback()
    closed.push(new URL(route.request().url()).pathname.split('/')[4]!)
    return route.fulfill({ status: 204 })
  })
  await page.route('**/api/editor/tasks/*', (route) => {
    if (route.request().method() === 'DELETE') return route.fulfill({ status: 204 })
    const ended = closed.length > 0
    return fulfillJson(route, 200, {
      taskId: 21,
      status: ended ? 'CANCELLED' : 'EXECUTING',
      result: {
        status: ended ? 'CANCELLED' : 'RUNNING',
        rowCount: null,
        columns: [],
        errorCode: ended ? 'query.session_closed' : null,
      },
    })
  })

  await page.goto('/query')
  const endSession = page.getByRole('button', { name: 'End session' })
  await expect(endSession).toBeDisabled()

  const editor = page.locator('.cm-content')
  await editor.click()
  await page.keyboard.insertText('select sleep(30)')
  await page.getByRole('button', { name: 'Run', exact: true }).click()
  await expect.poll(() => submittedOn).toEqual(['session-1'])

  await endSession.click()
  await page.getByRole('dialog').getByRole('button', { name: 'End session' }).click()
  await expect.poll(() => closed).toEqual(['session-1'])
  await expect(page.getByText('Query canceled')).toBeVisible()
  await expect(endSession).toBeDisabled()

  await editor.click()
  await page.keyboard.insertText(' ')
  await page.getByRole('button', { name: 'Run', exact: true }).click()
  await expect.poll(() => submittedOn).toEqual(['session-1', 'session-2'])
})

test('an executing workflow can be canceled and refreshes to CANCELLED', async ({ page }) => {
  await mockAppShell(page)
  let canceled = false
  let cancelPosts = 0

  await page.route('**/api/access-requests**', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/approvals/inbox', (route) => fulfillJson(route, 200, []))
  await page.route('**/api/approvals/7/cancel', async (route) => {
    expect(route.request().method()).toBe('POST')
    cancelPosts += 1
    await fulfillJson(route, 200, request(7, 'CANCELLED'))
    canceled = true
  })
  await page.route('**/api/approvals/7', (route) => fulfillJson(route, 200, {
    request: request(7, canceled ? 'CANCELLED' : 'EXECUTING'),
    canDecide: false,
    canExecute: false,
    canCancel: true,
    result: {
      taskId: 7,
      status: canceled ? 'CANCELLED' : 'RUNNING',
      rowCount: null,
      columns: [],
      errorCode: canceled ? 'approval.canceled' : null,
    },
  }))
  await page.route('**/api/approvals', (route) => fulfillJson(route, 200, [
    request(7, canceled ? 'CANCELLED' : 'EXECUTING'),
  ]))

  await page.goto('/workflows/7')
  await page.getByTestId('cancel-approval-execution').click()

  await expect.poll(() => cancelPosts).toBe(1)
  await expect(page.getByText('CANCELLED', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Execution canceled.')).toBeVisible()
  await expect(page.getByTestId('cancel-approval-execution')).toHaveCount(0)
})
