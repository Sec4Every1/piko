import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';

process.env.PLAYWRIGHT_BROWSERS_PATH ??= fileURLToPath(new URL('./node_modules/.cache/ms-playwright', import.meta.url));

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 2,
  reporter: 'list',
  use: { baseURL: 'http://127.0.0.1:1420', trace: 'retain-on-failure', colorScheme: 'light' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run dev',
    url: 'http://127.0.0.1:1420',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
