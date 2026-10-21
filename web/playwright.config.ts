import { defineConfig } from 'playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  use: {
    baseURL: 'http://localhost:41310',
  },
  webServer: {
    command: 'pnpm dev -p 41310',
    url: 'http://localhost:41310',
    reuseExistingServer: true,
    timeout: 120_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
});
