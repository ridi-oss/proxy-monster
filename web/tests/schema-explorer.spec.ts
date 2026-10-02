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
