import { expect, test, type Page } from 'playwright/test'

// The console driven end to end against the smoke stack, nothing mocked. Per datasource: debug login as the
// production viewer, the editor masks the classified column, the explorer's table detail names the
// classification and asks for the table by catalog, and its Data tab masks the same column.

const MASK = '####'
const datasources = (process.env.SMOKE_DATASOURCES ?? '').split(',').filter(Boolean).map((spec) => {
  const [engine, name, catalog, schema] = spec.split(':')
  return { engine, name, catalog, schema }
})

async function login(page: Page, principal: string, roles: string[]) {
  await page.goto('/login')
  const status = await page.evaluate(
    ([principal, roles]) =>
      fetch('/auth/debug', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ principal, roles }),
      }).then((r) => r.status),
    [principal, roles] as const,
  )
  expect(status).toBe(200)
}

for (const ds of datasources) {
  test(`${ds.engine}: the console masks email in the editor and the table detail`, async ({ page }) => {
    await login(page, 'smoke-viewer', ['system:production-viewer'])
    await page.goto('/query')

    await page.getByRole('combobox').first().click()
    await page.getByRole('option', { name: ds.name }).click()
    await expect(page.getByRole('combobox').first()).toContainText(ds.name)
    await expect(page.getByTestId('schema-tree')).toBeVisible()

    await page.locator('.cm-content').click()
    await page.keyboard.press('ControlOrMeta+A')
    await page.keyboard.insertText('SELECT id, email, name FROM users ORDER BY id')
    await page.getByRole('button', { name: 'Run', exact: true }).click()
    await expect(page.getByText('MASK', { exact: true })).toBeVisible({ timeout: 30_000 })
    const rows = page.locator('table tbody tr')
    await expect(rows).toHaveCount(3)
    for (let i = 0; i < 3; i++) {
      const cells = rows.nth(i).locator('td')
      await expect(cells.nth(2)).toHaveText(MASK)
      await expect(cells.nth(3)).not.toHaveText(MASK)
    }

    const group = page.locator(`[data-testid="schema-group"][data-schema="${ds.schema}"]`)
    await expect(group).toBeVisible()
    const detailRequest = page.waitForResponse((r) => r.url().includes('/table-detail?'))
    await group.locator('[data-testid="schema-table"][data-table="users"]').getByTitle(/^Open .*users \(schema \+ data\)$/).click()
    const detail = await detailRequest
    expect(detail.status()).toBe(200)
    const query = new URL(detail.url()).searchParams
    expect(query.get('catalog')).toBe(ds.catalog)
    expect(query.get('schema')).toBe(ds.schema)
    expect(query.get('table')).toBe('users')

    const columns = page.getByTestId('table-columns-panel')
    await expect(columns).toBeVisible()
    const emailRow = columns.locator('tbody tr', { has: page.getByText('email', { exact: true }) })
    await expect(emailRow).toContainText('pii')
    await expect(emailRow).toContainText('smoke-fixed')

    await page.getByTestId('table-detail-tabs').getByRole('tab', { name: 'Data', exact: true }).click()
    const dataRows = page.locator('table').last().locator('tbody tr')
    await expect(dataRows).toHaveCount(3, { timeout: 30_000 })
    for (let i = 0; i < 3; i++) await expect(dataRows.nth(i).locator('td').nth(2)).toHaveText(MASK)
  })
}
