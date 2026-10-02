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

async function fulfillJson(route: Route, status: number, body: unknown) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
}

function column(schema: string, table: string, name: string, system = false) {
  return {
    catalog: 'app', schema, table, column: name, dataType: 'int', sqlType: 'int', ordinal: 1, nullable: true,
    classification: null, system,
  }
}

const detailColumn = (name: string, ordinal: number) => ({
  name, dataType: 'int', ordinal, nullable: true, defaultValue: null, characterMaximumLength: null,
  numericPrecision: null, numericScale: null, partOfIndex: false, autoIncrement: false, comment: null,
  charset: null, collation: null, classification: null,
})
const catalogColumns = () => [
  column('public', 'users', 'id'),
  column('public', 'users', 'user_email'),
  column('public', 'orders', 'user_id'),
  column('pg_catalog', 'pg_class', 'relname', true),
]
const tableDetail = (schema: string, table: string) => ({
  catalog: 'app', schema, table,
  columns: catalogColumns().filter((c) => c.schema === schema && c.table === table).map((c, i) => detailColumn(c.column, i + 1)),
  indexes: [], foreignKeys: [], referencedBy: [],
  metadata: { engine: 'postgres', estimatedRows: null, rowFormat: null, onDiskBytes: null, collation: null, comment: null },
})

const datasource = (id: number, name: string) => ({
  id, name, engine: 'postgres', host: 'db.example.test', port: 5432, dbName: 'app', tags: [], defaultSchemas: ['public'],
})

async function mockEditor(page: Page, connectable: () => object[], isAdmin = false) {
  await page.route('**/api/**', (route) => fulfillJson(route, 200, []))
  await page.route('**/auth/config', (route) => fulfillJson(route, 200, {
    oidcEnabled: false,
    authDebug: true,
    session: SESSION_CONFIG,
  }))
  await page.route('**/auth/me', (route) => fulfillJson(route, 200, { principal: 'sam@example.com', roles: [] }))
  await page.route('**/auth/session/heartbeat', (route) => fulfillJson(route, 200, sessionStatus()))
  await page.route('**/auth/session/status', (route) => fulfillJson(route, 200, sessionStatus()))
  await page.route('**/api/me/permissions', (route) => fulfillJson(route, 200, {
    isAdmin,
    canReadAllAudit: false,
    canApprove: false,
  }))
  await page.route('**/api/datasources?connectable=true', (route) => fulfillJson(route, 200, connectable()))
  await page.route('**/api/datasources', (route) => fulfillJson(route, 200, connectable()))
  await page.route(/\/api\/datasources\/\d+\/table-detail/, (route) => {
    const params = new URL(route.request().url()).searchParams
    return fulfillJson(route, 200, tableDetail(params.get('schema')!, params.get('table')!))
  })
  await page.route(/\/api\/datasources\/\d+\/catalog$/, (route) => fulfillJson(route, 200, catalogColumns()))
}

const schemas = (page: Page) => page.getByTestId('schema-group')
const table = (page: Page, name: string) => page.locator(`[data-testid=schema-table][data-table=${name}]`)
const marked = (page: Page) => page.locator('[data-testid=schema-tree] [aria-current=true]')
// Clicks the tree's scroll area below its last row.
const blank = (page: Page) => page.locator('[data-testid=schema-tree] > div').nth(1).click({ position: { x: 100, y: 400 } })

test('system schemas start hidden and the view option shows them', async ({ page }) => {
  await mockEditor(page, () => [datasource(1, 'app')])
  await page.goto('/query')

  await expect(schemas(page)).toHaveCount(1)
  await expect(page.getByText('1 system schema hidden.')).toBeVisible()

  await page.getByRole('button', { name: 'View options' }).click()
  await page.getByRole('menuitemcheckbox', { name: 'Show system schemas' }).click()
  await page.keyboard.press('Escape')
  await expect(page.locator('[data-testid=schema-group][data-schema=pg_catalog]')).toBeVisible()

  await page.reload()
  await expect(page.locator('[data-testid=schema-group][data-schema=pg_catalog]')).toBeVisible()
})

test('expand all, collapse all, and row clicks toggle the tree', async ({ page }) => {
  await mockEditor(page, () => [datasource(1, 'app')])
  await page.goto('/query')
  const usersToggle = table(page, 'users').locator('button[aria-expanded]')

  await page.getByRole('button', { name: 'Expand all' }).click()
  await expect(usersToggle).toHaveAttribute('aria-expanded', 'true')
  await expect(table(page, 'orders').locator('button[aria-expanded]')).toHaveAttribute('aria-expanded', 'true')

  await page.getByRole('button', { name: 'Collapse all' }).click()
  await expect(page.locator('[data-testid=schema-table]')).toHaveCount(0)

  await page.getByRole('button', { name: 'Expand schema public' }).click()
  await table(page, 'users').getByText('users', { exact: true }).click()
  await expect(usersToggle).toHaveAttribute('aria-expanded', 'true')
  await expect(table(page, 'users').locator('[aria-current=true]')).toHaveCount(1)
  await expect(table(page, 'orders').locator('[aria-current=true]')).toHaveCount(0)
  // Both the tree row and the opened table tab show the name.
  await expect.poll(() => page.getByText('users', { exact: true }).count()).toBeGreaterThan(1)

  await table(page, 'users').getByRole('button', { name: /^user_email/ }).click()
  await expect(marked(page)).toHaveCount(1)
  await expect(marked(page)).toContainText('user_email')
  await page.getByRole('button', { name: 'Collapse schema public' }).click()
  await expect(marked(page)).toContainText('public')
  await expect(page.getByRole('button', { name: 'Expand schema public' })).toBeVisible()
  await blank(page)
  await expect(marked(page)).toHaveCount(0)
})

test('only the search-path schema starts expanded', async ({ page }) => {
  await mockEditor(page, () => [datasource(1, 'app')])
  await page.route(/\/api\/datasources\/\d+\/catalog$/, (route) => fulfillJson(route, 200, [
    column('audit', 'events', 'id'),
    column('public', 'users', 'id'),
  ]))
  await page.goto('/query')

  await expect(page.getByRole('button', { name: 'Collapse schema public' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Expand schema audit' })).toBeVisible()
  await expect(table(page, 'events')).toHaveCount(0)

  await page.getByRole('button', { name: 'Expand schema audit' }).click()
  await page.reload()
  await expect(table(page, 'events')).toBeVisible()
})

test('the filter highlights matches, opens tables matched by a column, and clears', async ({ page }) => {
  await mockEditor(page, () => [datasource(1, 'app')])
  await page.goto('/query')
  const filter = page.getByPlaceholder('Filter schemas, tables, columns…')

  await filter.fill('user')
  // users matches by name and stays closed; orders opens to show its matching user_id column.
  await expect(page.locator('mark')).toHaveText(['user', 'user'])
  await expect(table(page, 'orders').locator('button[aria-expanded]')).toHaveAttribute('aria-expanded', 'true')
  await expect(table(page, 'users').locator('button[aria-expanded]')).toHaveAttribute('aria-expanded', 'false')

  await filter.press('Escape')
  await expect(filter).toHaveValue('')
  await filter.fill('relname')
  await expect(page.getByText('No schemas, tables, or columns match.')).toBeVisible()
  await page.getByRole('button', { name: 'Clear filter' }).click()
  await expect(filter).toHaveValue('')
  await expect(page.locator('mark')).toHaveCount(0)
})

test('the saved datasource survives navigating away while the cached list is stale', async ({ page }) => {
  let listed = [datasource(1, 'first')]
  await mockEditor(page, () => listed)
  await page.goto('/query')
  await expect(page.getByRole('combobox').first()).toHaveText(/first/)

  listed = [datasource(1, 'first'), datasource(2, 'second')]
  await page.evaluate(() => localStorage.setItem('pm.query.datasourceId', '2'))
  await page.getByRole('link', { name: 'Workflows' }).click()
  await expect(page).toHaveURL(/\/workflows/)
  await page.getByRole('link', { name: 'Query' }).click()

  await expect(page.getByRole('combobox').first()).toHaveText(/second/)
  expect(await page.evaluate(() => localStorage.getItem('pm.query.datasourceId'))).toBe('2')
})

test('the datasource catalog lists tables in the same tree, without column nodes', async ({ page }) => {
  await mockEditor(page, () => [datasource(1, 'app')], true)
  await page.goto('/admin/datasources/1')

  await expect(schemas(page)).toHaveCount(1)
  await expect(page.getByText('1 system schema hidden.')).toBeVisible()
  await expect(marked(page)).toHaveCount(0)
  await expect(page.getByRole('cell', { name: 'user_email' })).toBeVisible()

  await table(page, 'orders').click()
  await expect(table(page, 'orders').locator('[aria-current=true]')).toHaveCount(1)
  await expect(page.getByRole('cell', { name: 'user_id' })).toBeVisible()
  await blank(page)
  await expect(marked(page)).toHaveCount(0)
  await expect(page.getByRole('cell', { name: 'user_id' })).toBeVisible()

  const filter = page.getByPlaceholder('Filter schemas, tables…')
  await filter.fill('email')
  await expect(page.getByText('No schemas or tables match.')).toBeVisible()
  await filter.fill('ord')
  await expect(page.locator('mark')).toHaveText(['ord'])
  await expect(page.locator('[data-testid=schema-table]')).toHaveCount(1)

  await filter.press('Escape')
  await page.getByRole('button', { name: 'Collapse all' }).click()
  await expect(page.locator('[data-testid=schema-table]')).toHaveCount(0)
  await page.getByRole('button', { name: 'Expand all' }).click()
  await expect(page.locator('[data-testid=schema-table]')).toHaveCount(2)
})

test('a column opens its table with the column flashed; hover actions copy and insert names', async ({ page, context, baseURL }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: baseURL })
  await mockEditor(page, () => [datasource(1, 'app')])
  await page.goto('/query')
  await table(page, 'users').locator('button[aria-expanded]').click()
  const column = table(page, 'users').getByRole('button', { name: /^user_email/ })

  await column.click()
  const flashed = page.getByTestId('table-columns-panel').locator('tr[data-focused]')
  await expect(flashed).toContainText('user_email')
  await expect(flashed).toHaveCount(0, { timeout: 5000 })
  await expect(page.locator('.cm-content')).not.toContainText('user_email')

  await page.getByRole('tab', { name: 'Indexes' }).click()
  await column.click()
  await expect(page.getByRole('tab', { name: 'Columns' })).toHaveAttribute('aria-selected', 'true')
  await expect(flashed).toContainText('user_email')

  const editor = page.locator('.cm-content')
  await editor.click()
  await page.keyboard.press('ControlOrMeta+a')
  await page.keyboard.press('Delete')
  await column.hover()
  await page.getByRole('button', { name: 'Insert user_email into the editor' }).click()
  await expect(editor).toHaveText('user_email')
  await expect(page.locator('[data-testid=table-detail-tabs]')).toBeVisible()

  await table(page, 'users').getByText('users', { exact: true }).hover()
  await page.getByRole('button', { name: 'Copy public.users' }).click()
  await expect(page.getByRole('button', { name: 'Copied' })).toBeVisible()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('public.users')
})

test('a column flash leaves Logs, and each table tab keeps its own sub-view', async ({ page }) => {
  await mockEditor(page, () => [datasource(1, 'app')])
  await page.goto('/query')
  await table(page, 'users').locator('button[aria-expanded]').click()
  const column = table(page, 'users').getByRole('button', { name: /^user_email/ })
  await column.click()
  await page.getByRole('tab', { name: 'Indexes' }).click()

  await table(page, 'orders').getByText('orders', { exact: true }).click()
  await expect(page.getByRole('tab', { name: 'Columns' })).toHaveAttribute('aria-selected', 'true')
  await page.getByRole('tab', { name: /^users/ }).click()
  await expect(page.getByRole('tab', { name: 'Indexes' })).toHaveAttribute('aria-selected', 'true')

  await page.getByRole('tab', { name: 'Logs' }).click()
  await column.click()
  await expect(page.getByTestId('table-columns-panel').locator('tr[data-focused]')).toContainText('user_email')
})

test('the tree marks the session search path and switches it without a result tab', async ({ page }) => {
  await mockEditor(page, () => [{ ...datasource(1, 'app'), defaultSchemaSettable: true }])
  await page.route(/\/api\/datasources\/\d+\/catalog$/, (route) => fulfillJson(route, 200, [
    column('public', 'users', 'id'),
    column('billing', 'invoices', 'id'),
    column('pg_catalog', 'pg_class', 'relname', true),
  ]))
  let searchPath: string[] | null = ['pg_catalog', 'public']
  const defaults: string[] = []
  await page.route('**/api/editor/sessions', (route) => fulfillJson(route, 200, { sessionId: 's1' }))
  await page.route('**/api/editor/sessions/s1', (route) => fulfillJson(route, 200, { searchPath }))
  await page.route('**/api/editor/sessions/s1/default-schema', (route) => {
    const schema = route.request().postDataJSON().schema as string
    defaults.push(schema)
    searchPath = ['pg_catalog', schema]
    return fulfillJson(route, 200, {
      statement: `SET search_path TO "${schema}"`, result: { taskId: 9, ordinal: 0, status: 'DONE' }, searchPath,
    })
  })
  await page.route('**/api/editor/sessions/s1/query', (route) => {
    const sql = route.request().postDataJSON().sql as string
    return fulfillJson(route, 202, { taskId: 1, childId: 1, statements: [sql] })
  })
  await page.route(/\/api\/editor\/tasks\/\d+$/, (route) => {
    const taskId = Number(route.request().url().split('/').pop())
    return route.request().method() === 'DELETE'
      ? route.fulfill({ status: 204 })
      : fulfillJson(route, 200, { taskId, status: 'EXECUTED', result: { taskId, ordinal: 0, status: 'DONE' } })
  })
  await page.route(/\/api\/editor\/tasks\/\d+\/result/, (route) => fulfillJson(route, 200, {
    meta: { taskId: 1, ordinal: 0, status: 'DONE' }, columns: ['id'], rows: [['1']], decision: 'ALLOW', maskedColumns: [],
  }))
  const marker = (schema: string) => page.locator(`[data-testid=schema-group][data-schema=${schema}] > div`).first()

  await page.goto('/query')
  await expect(marker('public')).toContainText('default')
  await expect(marker('billing')).not.toContainText('default')

  await marker('billing').hover()
  await page.getByRole('button', { name: 'Make billing the default' }).click()
  await expect(marker('billing')).toContainText('default')
  await expect(marker('public')).not.toContainText('default')
  // The server builds the statement from the schema name; the console logs what it ran.
  expect(defaults).toEqual(['billing'])
  await expect(page.getByRole('tab', { name: /^SET search_path/ })).toHaveCount(0)
  await page.getByRole('tab', { name: 'Logs' }).click()
  await expect(page.getByText('SET search_path TO "billing"')).toBeVisible()

  // A path the proxy could not read marks nothing rather than keeping the last one.
  searchPath = null
  await page.locator('.cm-content').click()
  await page.keyboard.press('ControlOrMeta+a')
  await page.keyboard.type('SELECT 1')
  await page.getByRole('button', { name: 'Run' }).click()
  await expect(marker('billing')).not.toContainText('default')
  await expect(marker('public')).not.toContainText('default')
})

test('a datasource that cannot set a default schema offers no switch', async ({ page }) => {
  await mockEditor(page, () => [{ ...datasource(1, 'app'), defaultSchemaSettable: false }])
  await page.goto('/query')
  const users = table(page, 'users')
  await users.hover()
  await expect(page.getByRole('button', { name: /^Copy / }).first()).toBeVisible()
  await page.getByTestId('schema-group').first().locator(':scope > div').first().hover()
  await expect(page.getByRole('button', { name: /the default$/ })).toHaveCount(0)
})

