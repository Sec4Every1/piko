import { test, expect } from '@playwright/test';

test('machine browser registrations remain unverified and failures are visible', async ({ page }) => {
  await page.addInitScript(() => {
    let reads = 0;
    Object.defineProperty(window, 'isTauri', { value: true });
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
      invoke: async (command: string) => {
        if (command === 'get_health') return { product: 'piko', version: '0.2.0', protection_state: 'degraded', runtime_mode: 'development_console', uptime_seconds: 1, stored_events: 0, queue_depth: 0, dropped_events: 0, sensors: [] };
        if (command === 'list_alerts' || command === 'list_alert_reviews') return [];
        if (command === 'browser_inventory') {
          if (++reads > 1) throw new Error('synthetic unavailable');
          return { candidates: [{ family: 'chrome', registration_id: 'machine-fixture', registered_name: 'Google Chrome', registered_publisher: null, registered_version: '1', scope: 'machine' }], registration_scan_complete: false, truncated: false, oversized_metadata: false, browser_discovery_complete: false, profiles_known: false, executable_identity_verified: false, protection_status_known: false };
        }
        throw new Error('synthetic unavailable');
      },
    } });
  });
  await page.goto('/');
  await page.locator('.sidebar nav').getByRole('button', { name: 'Permessi app', exact: true }).click();
  const section = page.getByRole('region', { name: 'Browser rilevati' });
  await section.getByRole('button', { name: 'Cerca registrazioni' }).click();
  await expect(section.getByText('Google Chrome')).toBeVisible();
  await expect(section.getByText(/registrazione di sistema, non verificata/)).toBeVisible();
  await expect(section.getByText(/Ricerca incompleta/)).toBeVisible();
  await section.getByRole('button', { name: 'Cerca registrazioni' }).click();
  await expect(section.getByRole('alert')).toContainText('Inventario non disponibile');
  await expect(section.getByText('Google Chrome')).toHaveCount(0);
});
