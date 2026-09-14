import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

// Unit tests only. `tests/` is Playwright's directory (playwright.config.ts testDir), and its specs
// import from 'playwright/test' — picking them up here would fail at import time, so the include
// glob is scoped to the colocated `*.test.ts` files outside it.
export default defineConfig({
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  test: {
    include: ['src/**/*.test.ts', 'messages/**/*.test.ts'],
  },
})
