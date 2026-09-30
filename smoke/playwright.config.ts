import { defineConfig } from 'playwright/test'

// Run from web/ by smoke/run.sh; SMOKE_WEB_URL is the console already started against the smoke stack.
export default defineConfig({
  testDir: '.',
  testMatch: 'browser.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: { baseURL: process.env.SMOKE_WEB_URL, browserName: 'chromium' },
})
