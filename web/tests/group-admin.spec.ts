import { expect, test, type Page } from 'playwright/test'

// Renaming and deleting a group, over the real console against a stubbed control plane. The source a
// group came from decides what is allowed, so each case fixes one: LOCAL is freely editable, SYSTEM is
// immutable server-side, and an OIDC group returns on the next login however it is deleted here.

const SESSION_CONFIG = {
  heartbeatMs: 90_000,
  idleWarnLeadMs: 60_000,
  absoluteWarnLeadMs: 300_000,
  absoluteCapAmount: 2,
  absoluteCapUnit: 'hours',
}

const GROUPS = [
  { id: 1, name: 'pii-readers', description: 'local', source: 'LOCAL', memberCount: 0, roles: [] },
  { id: 2, name: 'system:admin', description: 'seeded', source: 'SYSTEM', memberCount: 0, roles: [] },
  { id: 3, name: 'idp-analysts', description: 'from okta', source: 'OIDC', memberCount: 0, roles: [] },
]

async function boot(page: Page) {
  await page.route('**/auth/config', (r) => r.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ oidcEnabled: false, authDebug: true, session: SESSION_CONFIG }),
  }))
  await page.route('**/auth/me', (r) => r.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ principal: 'admin@example.com', roles: ['system:admin'], admin: true }),
  }))
  await page.route('**/api/me/permissions', (r) => r.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ isAdmin: true }),
  }))
  await page.route('**/api/groups', (r) => r.fulfill({
    contentType: 'application/json', body: JSON.stringify(GROUPS),
  }))
  await page.route('**/api/groups/*/members', (r) => r.fulfill({ contentType: 'application/json', body: '[]' }))
  await page.route('**/api/groups/*/roles', (r) => r.fulfill({ contentType: 'application/json', body: '[]' }))
  await page.route('**/api/users', (r) => r.fulfill({ contentType: 'application/json', body: '[]' }))
  await page.route('**/api/roles', (r) => r.fulfill({ contentType: 'application/json', body: '[]' }))
}

test('detail page offers rename and delete for a LOCAL group', async ({ page }) => {
  await boot(page)
  await page.goto('/admin/groups/1')
  await expect(page.getByRole('button', { name: 'Rename' })).toBeEnabled()
  await expect(page.getByRole('button', { name: 'Delete group' })).toBeEnabled()
})

test('rename opens the form dialog prefilled with the current name', async ({ page }) => {
  await boot(page)
  await page.goto('/admin/groups/1')
  await page.getByRole('button', { name: 'Rename' }).click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await expect(page.locator('#group-name')).toHaveValue('pii-readers')
})

test('delete asks for confirmation and calls DELETE', async ({ page }) => {
  await boot(page)
  let deleted = false
  await page.route('**/api/groups/1', (r) => {
    if (r.request().method() === 'DELETE') { deleted = true; return r.fulfill({ status: 204, body: '' }) }
    return r.continue()
  })
  await page.goto('/admin/groups/1')
  await page.getByRole('button', { name: 'Delete group' }).click()
  await expect(page.getByText(/Delete group.*pii-readers/)).toBeVisible()
  // The header button and the confirm button share a label, so the confirm is the second one.
  await page.getByRole('button', { name: 'Delete group' }).last().click()
  await expect.poll(() => deleted).toBe(true)
})

test('SYSTEM group cannot be renamed or deleted', async ({ page }) => {
  await boot(page)
  await page.goto('/admin/groups/2')
  await expect(page.getByRole('button', { name: 'Rename' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Delete group' })).toBeDisabled()
})

test('OIDC group delete warns that the IdP will re-create it', async ({ page }) => {
  await boot(page)
  await page.goto('/admin/groups/3')
  await page.getByRole('button', { name: 'Delete group' }).click()
  await expect(page.getByText(/returns the next time a member signs in/)).toBeVisible()
})

test('list page disables edit and delete for a SYSTEM group', async ({ page }) => {
  await boot(page)
  await page.goto('/admin/groups')
  const row = page.getByRole('row').filter({ hasText: 'system:admin' })
  await row.getByRole('button', { name: 'More actions' }).click()
  await expect(page.getByRole('menuitem', { name: 'Edit' })).toBeDisabled()
  await expect(page.getByRole('menuitem', { name: 'Delete' })).toBeDisabled()
})
