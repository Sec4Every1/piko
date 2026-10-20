import { test, expect } from '@playwright/test';
test('guided expression is explicit, saved across reloads and deletable', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, 'isTauri', { value: true });
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: { invoke: async (command: string, args?: { filter?: { expression?: string } }) => {
      if (command === 'get_health') return { product: 'piko', version: '0.2.0', protection_state: 'limited', runtime_mode: 'development_console', uptime_seconds: 1, stored_events: 0, queue_depth: 0, dropped_events: 0, sensors: [] };
      if (command === 'list_alerts') return [];
      if (command === 'list_events') {
        (window as unknown as { lastExpression: string }).lastExpression = args?.filter?.expression ?? '';
        if (args?.filter?.expression === 'invalid') throw Error('query_syntax: unsupported field');
        return [];
      }
      throw Error(command);
    } } });
  });
  await page.goto('/');
  await page.locator('.sidebar nav').getByRole('button', { name: 'Log tecnici', exact: true }).click();
  await page.getByText('Ricerca avanzata e ricerche salvate', { exact: true }).click();
  await page.getByLabel('Valore', { exact: true }).fill('browser.exe');
  await page.getByRole('button', { name: 'Aggiungi condizione', exact: true }).click();
  await expect(page.getByLabel('Espressione', { exact: true })).toHaveValue('process.name = "browser.exe"');
  expect(await page.evaluate(() => (window as unknown as { lastExpression: string }).lastExpression)).toBe('');
  await page.getByLabel('Nome della ricerca', { exact: true }).fill('Browser');
  await page.getByRole('button', { name: 'Salva espressione', exact: true }).click();
  await page.getByRole('button', { name: 'Applica filtri', exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as unknown as { lastExpression: string }).lastExpression)).toBe('process.name = "browser.exe"');
  await page.reload();
  await page.locator('.sidebar nav').getByRole('button', { name: 'Log tecnici', exact: true }).click();
  await page.getByText('Ricerca avanzata e ricerche salvate', { exact: true }).click();
  await page.getByRole('button', { name: 'Browser', exact: true }).click();
  await expect(page.getByLabel('Espressione', { exact: true })).toHaveValue('process.name = "browser.exe"');
  await page.getByRole('button', { name: 'Elimina ricerca Browser', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Browser', exact: true })).toHaveCount(0);
  await page.getByLabel('Espressione', { exact: true }).fill('invalid');
  await page.getByRole('button', { name: 'Applica filtri', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Ricerca non completata', exact: true })).toBeVisible();
});
