
async function openAlert(page: Page, id: string) {
  const rules: Record<string, string> = { 'test-service': 'service-installed', 'test-audit': 'audit-policy-changed', 'test-cleared': 'audit-log-cleared' };
  await page.locator('[data-group-rule="' + rules[id] + '"]').click();
  await expect(page.locator('[data-alert-id="' + id + '"]')).toBeVisible();
}
async function closeAlert(page: Page) { await page.getByRole('button', { name: 'Chiudi dettaglio', exact: true }).click(); }
import { test, expect, type Page } from '@playwright/test';
import type { Alert, AlertAssessment, HealthSnapshot, SecurityEvent } from '../src/lib/api';

// Synthetic inputs are confined to browser tests. Native smoke uses the actual runtime.
const observedAt = Date.UTC(2026, 9, 6, 10, 0);
const health: HealthSnapshot = {
  product: 'piko', version: '0.2.0', protection_state: 'degraded', runtime_mode: 'development_console',
  uptime_seconds: 60, stored_events: 5, queue_depth: 0, dropped_events: 0,
  sensors: ['System', 'Application', 'Security'].map(name => ({
    id: `windows.event_log.${name}`, state: name === 'Security' ? 'degraded' : 'active',
    detail: name === 'Security' ? 'Access denied' : 'Reading Windows records', last_seen_unix_ms: observedAt,
  })),
};
const heartbeat: SecurityEvent = {
  schema_version: 1, event_id: 'test-heartbeat', host_id: 'test-host', boot_id: null,
  runtime_instance_id: 'test-runtime', sensor_id: 'piko.runtime', sequence: 1,
  wall_clock_time: observedAt, monotonic_time: 1000, observation_time: observedAt, ingestion_time: observedAt,
  event_category: 'sensor_health', event_type: 'runtime.heartbeat', severity: 'info',
  actor_identity: null, logon_session: null, process: null, parent_process: null, target: null,
  operation: 'heartbeat', result: 'observed', causal_parents: [], correlation_ids: [], raw_evidence_reference: null,
  integrity_metadata: { normalization_version: 1, source_integrity: null },
};
const sourceEvent: SecurityEvent = {
  ...heartbeat, event_id: 'test-cleared-event', sensor_id: 'windows.event_log.Security', sequence: 2,
  event_category: 'windows_event_log', event_type: 'windows.event_log.1102', severity: 'high',
  target: { kind: 'windows_event_record', identifier: 'Security:Microsoft-Windows-Eventlog:42' },
  operation: 'observe', raw_evidence_reference: 'test-evidence',
};
const context: AlertAssessment['context'] = { evidence_status: 'verified', service_name: null, image_path: null,
  subject_user: null, subject_domain: null, service_account: null, log_channel: null, audit_changes: null, installer_process: null };
const assessments: Record<string, AlertAssessment> = {
  'service-installed': { model_version: 'piko-risk-v1', risk_score: 25, false_positive_probability: null,
    factors: [{ code: 'service_installed', points: 25 }],
    context: { ...context, service_name: 'Example Updater', image_path: 'C:\\Example\\updater.exe', service_account: 'LocalSystem' } },
  'audit-policy-changed': { model_version: 'piko-risk-v1', risk_score: 40, false_positive_probability: null,
    factors: [{ code: 'audit_policy_changed', points: 40 }, { code: 'audit_change_unknown', points: 0 }],
    context: { ...context, subject_user: 'test-admin', subject_domain: 'TEST-PC' } },
  'audit-log-cleared': { model_version: 'piko-risk-v1', risk_score: 70, false_positive_probability: null,
    factors: [{ code: 'audit_log_cleared', points: 70 }],
    context: { ...context, subject_user: 'test-admin', subject_domain: 'TEST-PC', log_channel: 'Security' } },
};
const alerts: Alert[] = [
  { id: 'test-service', rule_id: 'service-installed', severity: 'low' },
  { id: 'test-audit', rule_id: 'audit-policy-changed', severity: 'medium' },
  { id: 'test-cleared', rule_id: 'audit-log-cleared', severity: 'high' },
].map(item => ({ ...item, rule_version: 1, event_id: sourceEvent.event_id, evidence_id: 'test-evidence',
  observed_at: observedAt, event_time: observedAt - 3600000, title: 'Backend rule title', explanation: 'Backend rule explanation',
  assessment: assessments[item.rule_id] }));

type TestBridge = { failAlerts: boolean; failEvidence: boolean; failReference: boolean; alerts: Alert[]; calls: { command: string; args?: Record<string, unknown> }[] };
declare global { interface Window { __PIKO_TEST__: TestBridge } }

async function installBridge(page: Page, mode: 'populated' | 'empty' | 'error' = 'populated') {
  await page.addInitScript(({ health, events, alerts, failAlerts }) => {
    const reviews: Record<string,unknown> = {};
    const state: TestBridge = { failAlerts, failEvidence: false, failReference: false, alerts, calls: [] };
    window.__PIKO_TEST__ = state;
    Object.defineProperty(window, 'isTauri', { value: true });
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
      invoke: async (command: string, args?: Record<string, unknown>) => {
        state.calls.push({ command, args });
        if (command === 'get_health') return health;
        if (command === 'list_alert_reviews') return Object.values(reviews);
        if (command === 'save_alert_review') {const value={alert_id:args?.alertId,state:args?.state,note:args?.note,updated_at:Date.now(),reviewer_sid:'S-1-5-21-1-2-3-1000'};reviews[String(args?.alertId)]=value;return value;}
        if (command === 'startup_status') return {enabled:false,conflict:false,command:'test-only startup'};
        if (command === 'set_startup') return {enabled:args?.enabled,conflict:false,command:'test-only startup'};
        if (command === 'software_inventory') return { entries: [], complete: true, truncated: false, warnings: [] };
        if (command === 'network_snapshot') return { active_profiles: 2, local_policy_modify_state: 'ok', complete: true, warnings: [], rules: [],
          profiles: [1, 2, 4].map(id => ({ id, name: ({ 1: 'domain', 2: 'private', 4: 'public' } as Record<number, string>)[id],
            active: id === 2, firewall_enabled: true, block_all_inbound: false, excluded_interfaces: false })) };
        if (command === 'open_attack_reference') {
          if (state.failReference) throw new Error('Test-only browser failure');
          return null;
        }
        if (command === 'list_alerts') {
          if (state.failAlerts) throw new Error('Test-only unavailable detection store');
          return state.alerts;
        }
        if (command === 'response_status') return { roots: ['C:\\Users\\Test\\Downloads'], max_file_bytes: 16711680, vault_budget_bytes: 134217728, actions: [] };
        if (command === 'list_events') {
          const filter = (args?.filter ?? {}) as { search?: string; severity?: string; event_type?: string };
          return events.filter(event => (!filter.search || JSON.stringify(event).includes(filter.search))
            && (!filter.severity || event.severity === filter.severity)
            && (!filter.event_type || event.event_type === filter.event_type));
        }
        if (command === 'verify_store') return { verified_events: events.length, head_hash: 'a'.repeat(64), externally_anchored: false };
        if (command === 'get_evidence') {
          if (state.failEvidence) throw new Error('Test-only unavailable evidence');
          return {
            evidence_id: args?.evidenceId, source: 'Windows Event Log', content_type: 'application/xml',
            bytes: [...new TextEncoder().encode('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager"/><EventID>7045</EventID><Channel>System</Channel><Computer>TEST-PC</Computer></System><EventData><Data Name="SubjectUserName">test-user</Data><Data Name="ServiceName">&lt;script&gt;window.evidenceWasExecuted=true&lt;/script&gt;</Data><Data Name="ImagePath">C:\\Example\\service.exe</Data></EventData></Event>')],
          };
        }
        throw new Error(`Unexpected test command: ${command}`);
      },
    } });
  }, { health, events: [heartbeat, sourceEvent], alerts: mode === 'empty' ? [] : alerts, failAlerts: mode === 'error' });
}

function nav(page: Page, label: string) {
  return page.locator('.sidebar nav').getByRole('button', { name: label, exact: true });
}

test('standalone dashboard distinguishes unavailable telemetry from zero alerts', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await expect(page.getByTestId('security-dashboard')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Dati non disponibili', exact: true })).toBeVisible();
  await expect(page.locator('.priority-count')).toHaveText('—');
  await expect(page.getByText('Segnalazioni non aggiornate', { exact: true })).toBeVisible();
  await expect(page.getByText('runtime.heartbeat', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Nessuna segnalazione nelle regole disponibili', exact: true })).toHaveCount(0);
  await nav(page, 'Log tecnici').click();
  await expect(page.getByRole('button', { name: 'Esporta JSON' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Verifica integrità' })).toBeDisabled();
  await nav(page, 'Quarantena e ripristino').click();
  await expect(page.getByRole('button', { name: 'Prepara quarantena', exact: true })).toBeDisabled();
  expect(errors).toEqual([]);
});

test('dashboard stays compact and moves explanation, MITRE and remediation into event details', async ({ page }) => {
  await installBridge(page); await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Visibilità parziale', exact: true })).toBeVisible();
  await expect(page.locator('.priority-count')).toHaveText('1');
  await expect(page.locator('.group-row').first()).toHaveAttribute('data-group-rule', 'audit-log-cleared');
  await expect(page.locator('.alert-card')).toHaveCount(0);
  await expect(page.getByText('runtime.heartbeat', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Cosa puoi fare', { exact: true })).toHaveCount(0);
  for (const [id, technique, url] of [
    ['test-cleared', 'T1685.005', 'https://attack.mitre.org/techniques/T1685/005/'],
    ['test-audit', 'T1685.001', 'https://attack.mitre.org/techniques/T1685/001/'],
    ['test-service', 'T1543.003', 'https://attack.mitre.org/techniques/T1543/003/'],
  ]) {
    await openAlert(page, id);
    const card = page.locator('[data-alert-id="' + id + '"]');
    await expect(card.getByText('Passi suggeriti da svolgere manualmente. Nessuna correzione è stata eseguita.')).toBeVisible();
    await card.locator('.mapping-detail > summary').click();
    await expect(card.locator('.technique-chip')).toHaveText(technique);
    await expect(card.getByRole('link', { name: /Apri il riferimento ufficiale MITRE/ })).toHaveAttribute('href', url);
    await expect(card.getByText(/non conferma un attacco su questo PC/)).toBeVisible();
    await closeAlert(page);
  }
  expect(await page.evaluate(() => window.__PIKO_TEST__.calls.some(call => ['prepare_quarantine', 'prepare_restore', 'execute_action'].includes(call.command)))).toBe(false);
  const colors = await page.locator('.group-priority').evaluateAll(elements => elements.map(element => getComputedStyle(element).color));
  expect(new Set(colors).size).toBe(3);
  await page.getByLabel('Mostra', { exact: true }).selectOption('high');
  await expect(page.locator('.group-row')).toHaveCount(1);
  await page.getByLabel('Mostra', { exact: true }).selectOption('all');
  await page.screenshot({ path: 'test-results/piko-dashboard-light.png', fullPage: true });
});

test('dashboard names verified services and explains risk without fabricated false-positive percentages', async ({ page }) => {
  await installBridge(page);
  await page.goto('/');
  await openAlert(page, 'test-service');
  const service = page.locator('[data-alert-id="test-service"]');
  await expect(service.getByRole('heading', { name: 'Installato il servizio «Example Updater»', exact: true })).toBeVisible();
  await expect(service.locator('.named-context')).toContainText('C:\\Example\\updater.exe');
  await expect(service.locator('.attribution-note')).toContainText('Processo che ha installato il servizio: non identificato');
  await expect(service.getByTestId('risk-score')).toHaveText('25/100');
  await expect(page.getByTestId('maximum-risk')).toHaveText('70/100');

  await expect(page.locator('.false-positive strong')).toHaveText(['Non stimabile']);
  await service.locator('.score-detail > summary').click();
  await expect(service.locator('.score-factors')).toContainText('Installazione di un servizio Windows');
  await expect(service.locator('.score-factors')).toContainText('+25');
  await expect(service.locator('.score-detail')).toContainText('non si ottiene sottraendo l’indice da 100');
  expect(await page.evaluate(() => window.__PIKO_TEST__.calls.some(call => call.command === 'get_evidence'))).toBe(false);
});

test('unsupported assessments remain visible without guessed names or scores, and source names stay escaped', async ({ page }) => {
  await installBridge(page);
  await page.goto('/');
  await page.evaluate(() => {
    for (const alert of window.__PIKO_TEST__.alerts) if (alert.assessment) alert.assessment.model_version = 'future-risk';
  });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await openAlert(page, 'test-service');
  const service = page.locator('[data-alert-id="test-service"]');
  await expect(service.getByRole('heading', { name: 'Servizio installato · nome non disponibile', exact: true })).toBeVisible();
  await expect(service.getByTestId('risk-score')).toHaveText('—');
  await expect(page.getByTestId('maximum-risk')).toHaveText('—');
  await expect(service.locator('.named-context')).toHaveCount(0);
  await closeAlert(page);
  await page.evaluate(() => {
    const alert = window.__PIKO_TEST__.alerts.find(item => item.id === 'test-service')!;
    alert.assessment!.model_version = 'piko-risk-v1';
    alert.assessment!.context.service_name = '<img src=x onerror="window.nameWasExecuted=true">';
  });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await openAlert(page, 'test-service');
  await expect(service.getByRole('heading')).toContainText('<img src=x onerror="window.nameWasExecuted=true">');
  await expect(service.locator('img')).toHaveCount(0);
  expect(await page.evaluate(() => Object.hasOwn(window, 'nameWasExecuted'))).toBe(false);
  await expect(page.getByTestId('maximum-risk')).toHaveText('25/100');

});

test('MITRE reference clicks send the technique ID and show a recoverable browser error', async ({ page }) => {
  await installBridge(page);
  await page.goto('/');
  await openAlert(page, 'test-cleared');
  const card = page.locator('[data-alert-id="test-cleared"]');
  await card.locator('.mapping-detail > summary').click();
  const link = card.getByRole('link', { name: /Apri il riferimento ufficiale MITRE/ });
  await page.evaluate(() => { window.__PIKO_TEST__.failReference = true; });
  await link.click();
  await expect(card.getByRole('alert')).toContainText('Non è stato possibile aprire il browser.');
  await page.evaluate(() => { window.__PIKO_TEST__.failReference = false; });
  await link.click();
  await expect(card.getByRole('alert')).toHaveCount(0);
  expect(await page.evaluate(() => window.__PIKO_TEST__.calls.filter(call => call.command === 'open_attack_reference').at(-1)?.args)).toEqual({ techniqueId: 'T1685.005' });
});

test('event details render original values safely, allow evidence retry and keep raw XML optional', async ({ page }) => {
  await installBridge(page);
  await page.goto('/');
  await openAlert(page, 'test-service');
  const service = page.locator('[data-alert-id="test-service"]');
  await service.locator('.evidence-detail > summary').click();
  await page.evaluate(() => { window.__PIKO_TEST__.failEvidence = true; });
  await service.getByRole('button', { name: 'Leggi i dettagli dell’evento', exact: true }).click();
  await expect(service.getByRole('alert')).toContainText('Non è stato possibile leggere l’evidenza. Puoi riprovare.');
  await expect(service.locator('.event-facts')).toHaveCount(0);
  await page.evaluate(() => { window.__PIKO_TEST__.failEvidence = false; });
  await service.getByRole('button', { name: 'Leggi i dettagli dell’evento', exact: true }).click();
  await expect(service.locator('.event-facts')).toContainText('<script>window.evidenceWasExecuted=true</script>');
  await expect(service.locator('.event-facts')).toContainText('C:\\Example\\service.exe');
  await expect(service.getByRole('alert')).toHaveCount(0);
  expect(await page.evaluate(() => Object.hasOwn(window, 'evidenceWasExecuted'))).toBe(false);
  await expect(service.locator('.source-evidence')).not.toBeVisible();
  await service.getByText('XML originale e riferimenti tecnici', { exact: true }).click();
  await expect(service.locator('.source-evidence')).toBeVisible();
  await expect(service.locator('.source-evidence')).toContainText('&lt;script&gt;window.evidenceWasExecuted=true&lt;/script&gt;');
});

test('the manual explains startup and separates executable network control from other application permissions', async ({ page }) => {
  await installBridge(page);
  await page.goto('/');
  await nav(page, 'Manuale').click();
  await expect(page.getByRole('heading', { name: 'Aprire piko, ogni volta che serve', exact: true })).toBeVisible();
  await expect(page.getByText('Open-Piko.cmd', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Una palette con un significato', exact: true })).toBeVisible();
  await expect(page.getByText(/I passi di remediation indicati sono manuali/)).toBeVisible();
  await page.locator('.guide-navigation').getByRole('button', { name: /^Log tecnici/ }).click();
  await expect(page.getByText('runtime.heartbeat', { exact: true })).toBeVisible();
  await nav(page, 'Permessi app').click();
  await expect(page.getByRole('heading', { name: 'Decidi quali app possono collegarsi alla rete', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Stato del Firewall di Windows', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Ambito dei permessi', exact: true })).toBeVisible();
  await expect(page.getByText(/non cambiano ciò che gli altri programmi possono leggere, scrivere o eseguire/)).toBeVisible();
  await page.getByText('Percorso manuale e anteprima', { exact: true }).click();
  await expect(page.getByRole('button', { name: 'Prepara blocco', exact: true })).toBeDisabled();
  await expect(page.locator('.capability-workspace').getByRole('switch')).toHaveCount(0);
  expect(await page.evaluate(() => window.__PIKO_TEST__.calls.some(call => ['prepare_quarantine', 'prepare_restore', 'execute_action', 'prepare_network_action', 'execute_network_action'].includes(call.command)))).toBe(false);
});

test('technical logs retain heartbeats, query filters, evidence and local integrity checks', async ({ page }) => {
  await installBridge(page);
  await page.goto('/');
  await nav(page, 'Log tecnici').click();
  await expect(page.getByText('runtime.heartbeat', { exact: true })).toBeVisible();
  await page.getByPlaceholder('Cerca un tipo, un processo o un’evidenza…').fill('runtime.heartbeat');
  await page.getByRole('button', { name: 'Applica filtri', exact: true }).click();
  await expect(page.getByText('windows.event_log.1102', { exact: true })).toHaveCount(0);
  await expect(page.getByText('runtime.heartbeat', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.__PIKO_TEST__.calls.filter(call => call.command === 'list_events').at(-1)?.args)).toEqual({ filter: { limit: 200, search: 'runtime.heartbeat' } });
  await page.getByPlaceholder('Cerca un tipo, un processo o un’evidenza…').fill('');
  await page.getByRole('button', { name: 'Applica filtri', exact: true }).click();
  await page.getByText('windows.event_log.1102', { exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'windows.event_log.1102', exact: true });
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Leggi evidenza originale', exact: true }).click();
  await expect(dialog.locator('.source-evidence')).toContainText('<Data Name="SubjectUserName">test-user</Data>');
  await dialog.getByRole('button', { name: 'Chiudi', exact: true }).click();
  await page.getByRole('button', { name: 'Verifica integrità', exact: true }).click();
  await expect(page.getByText('Catena locale verificata', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Esporta JSON', exact: true })).toBeEnabled();
});

test('failed and stale alert reads never become a reassuring zero count', async ({ page }) => {
  await installBridge(page, 'error');
  await page.goto('/');
  await expect(page.getByText('Runtime collegato', { exact: true })).toBeVisible();
  await expect(page.getByText('Segnalazioni non aggiornate', { exact: true })).toBeVisible();
  await expect(page.locator('.priority-count')).toHaveText('—');
  await expect(page.getByTestId('maximum-risk')).toHaveText('—');
  await expect(page.getByRole('heading', { name: 'Nessuna segnalazione nelle regole disponibili', exact: true })).toHaveCount(0);
  await page.evaluate(() => { window.__PIKO_TEST__.failAlerts = false; });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await expect(page.locator('.priority-count')).toHaveText('1');
  await expect(page.getByTestId('maximum-risk')).toHaveText('70/100');
  await expect(page.locator('.group-row')).toHaveCount(3);
  await page.evaluate(() => { window.__PIKO_TEST__.failAlerts = true; });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await expect(page.locator('.priority-count')).toHaveText('—');
  await expect(page.getByTestId('maximum-risk')).toHaveText('—');
  await expect(page.getByText('I dati sotto provengono dall’ultima lettura riuscita.', { exact: true })).toBeVisible();
  await expect(page.locator('.group-row')).toHaveCount(3);
});

test('a successful empty read shows zero with explicit coverage limits', async ({ page }) => {
  await installBridge(page, 'empty');
  await page.goto('/');
  await expect(page.locator('.priority-count')).toHaveText('0');
  await expect(page.getByTestId('maximum-risk')).toHaveText('—');
  await expect(page.getByRole('heading', { name: 'Nessuna segnalazione nelle regole disponibili', exact: true })).toBeVisible();
  await expect(page.getByText('L’assenza di segnalazioni non garantisce l’assenza di minacce.', { exact: true })).toBeVisible();
  await expect(page.locator('.coverage-banner')).toHaveClass(/warning/);
});

test('100 repeated events use one compact group and each occurrence remains inspectable', async ({ page }) => {
  await installBridge(page);
  await page.goto('/');
  await page.evaluate(() => {
    const template = window.__PIKO_TEST__.alerts.find(a => a.rule_id === 'service-installed')!;
    window.__PIKO_TEST__.alerts = Array.from({ length: 100 }, (_, i) => ({ ...template, id: `repeated-${i}`, event_id: `source-${i}`, observed_at: template.observed_at + i }));
  });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await expect(page.locator('.group-row')).toHaveCount(1);
  await expect(page.locator('.group-count')).toContainText('100');
  await expect(page.locator('.alert-card')).toHaveCount(0);
  expect(await page.locator('[data-testid="security-dashboard"]').evaluate(e => e.getBoundingClientRect().height)).toBeLessThan(700);
  await page.locator('.group-row').click();
  await expect(page.locator('.alert-card')).toHaveCount(1);
  await page.getByLabel(/Occorrenza/).selectOption('99');
  await expect(page.getByLabel(/Occorrenza/)).toHaveValue('99');
  await expect(page.getByRole('button', { name: 'Evento successivo', exact: true })).toBeDisabled();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).not.toBeVisible();
  await expect(page.locator('.group-row')).toBeFocused();
});

test('keyboard navigation and preferences preserve an English dark dashboard', async ({ page }) => {
  await installBridge(page);
  await page.goto('/');
  await page.keyboard.press('Control+k');
  await expect(page.getByRole('dialog', { name: 'Dove vuoi andare?' })).toBeVisible();
  await page.getByPlaceholder('Cerca una pagina o un evento…').fill('impost');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Il tuo spazio, a modo tuo.' })).toBeVisible();
  await page.getByRole('button', { name: 'Scuro', exact: true }).click();
  await page.getByLabel('Lingua', { exact: true }).selectOption('en');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(page.getByRole('heading', { name: 'Partial visibility', exact: true })).toBeVisible();
  await page.locator('[data-group-rule="audit-log-cleared"]').click();
  await expect(page.getByRole('heading', { name: '“TEST-PC\\test-admin” cleared Windows security history', exact: true })).toBeVisible();
  await expect(page.getByText('Suggested steps to carry out manually. No correction has been performed.').first()).toBeVisible();
  await page.keyboard.press('Control+k');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).not.toBeVisible();
  await page.screenshot({ path: 'test-results/piko-dashboard-dark.png', fullPage: true });
});

test('mobile dashboard keeps navigation, severity labels and live system appearance usable', async ({ page }) => {
  await installBridge(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await expect(nav(page, 'Impostazioni')).toBeVisible();
  await expect(page.locator('.group-priority').first()).toContainText('Alta');
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBe(false);
  await page.screenshot({ path: 'test-results/piko-dashboard-mobile.png', fullPage: true });
  await nav(page, 'Impostazioni').click();
  await expect(page.getByRole('button', { name: 'Sistema', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.emulateMedia({ colorScheme: 'light' });
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBe(false);
});

test('alert JSON export preserves the selected alert and only explicitly loaded raw evidence', async ({ page }) => {
  await installBridge(page); await page.goto('/'); await openAlert(page, 'test-service');
  const card = page.locator('[data-alert-id="test-service"]');
  async function download() {
    const pending = page.waitForEvent('download');
    await card.getByRole('button', { name: 'Esporta segnalazione JSON', exact: true }).click();
    const file = await pending; expect(file.suggestedFilename()).toMatch(/^piko-alert-.*\.json$/);
    const stream = await file.createReadStream(); if (!stream) throw new Error('Missing download');
    let data = ''; for await (const chunk of stream) data += chunk.toString(); return JSON.parse(data);
  }
  const before = await download(); expect(before.alert.id).toBe('test-service'); expect(before.raw_evidence.state).toBe('not_loaded'); expect(before.raw_evidence.content).toBeNull();
  expect(before.integrity).toBe('unsigned_export'); expect(before.false_positive_probability).toBeNull(); expect(before.interpretation.title).toBeTruthy();
  await card.locator('.evidence-detail > summary').click();
  await card.getByRole('button', { name: 'Leggi i dettagli dell’evento', exact: true }).click();
  await expect(card.locator('.event-facts')).toBeVisible();
  const after = await download(); expect(after.raw_evidence.state).toBe('loaded'); expect(after.raw_evidence.content).toContain('&lt;script&gt;'); expect(after.alert).toEqual(before.alert);
});

test('new detections stay grouped and name tasks and Defender reports without claiming cleanup',async({page})=>{
  await installBridge(page); await page.goto('/');
  await page.evaluate(()=>{
    const base=window.__PIKO_TEST__.alerts[0];
    window.__PIKO_TEST__.alerts=[
      {...base,id:'new-task',rule_id:'scheduled-task-created',severity:'medium',assessment:{...base.assessment!,risk_score:35,factors:[{code:'scheduled_task_created',points:35}],context:{...base.assessment!.context,task_name:'Example Maintenance'}}},
      {...base,id:'new-action',rule_id:'defender-action-reported',severity:'medium',assessment:{...base.assessment!,risk_score:45,factors:[{code:'defender_action_reported',points:45}],context:{...base.assessment!.context,threat_name:'TestThreat',defender_action:'Allow'}}},
    ];
  });
  await page.getByRole('button',{name:'Aggiorna',exact:true}).click();
  await page.locator('[data-group-rule="scheduled-task-created"]').click(); await expect(page.getByRole('heading',{name:'Attività pianificata creata · Example Maintenance',exact:true})).toBeVisible();
  await page.locator('[data-alert-id="new-task"] .mapping-detail > summary').click();
  await expect(page.getByRole('link',{name:/Apri il riferimento ufficiale MITRE/})).toHaveAttribute('href','https://attack.mitre.org/techniques/T1053/005/'); await closeAlert(page);
  await page.locator('[data-group-rule="defender-action-reported"]').click();
  await expect(page.getByRole('heading',{name:'Defender ha registrato un’azione · TestThreat',exact:true})).toBeVisible();
 await expect(page.getByText(/L’azione può anche essere Consenti/)).toBeVisible();
});
test('settings show measured monitor resources and distinguish unavailable CPU',async({page})=>{
  await installBridge(page);
  await page.addInitScript(()=>{
    const bridge=(window as unknown as {__TAURI_INTERNALS__:{invoke:(command:string,args?:Record<string,unknown>)=>Promise<Record<string,unknown>>}}).__TAURI_INTERNALS__;
    const original=bridge.invoke;
    bridge.invoke=async(command:string,args?:Record<string,unknown>)=>{const value=await original(command,args);return command==='get_health'?{...value,performance:{sampled_at_unix_ms:Date.now(),working_set_bytes:10485760,private_bytes:20971520,cpu_percent_x100:null,interval_ms:0,logical_processors:4}}:value;};
  });
  await page.goto('/'); await nav(page,'Impostazioni').click();
  const panel=page.getByRole('region',{name:'Consumi del monitor',exact:true}); await expect(panel).toContainText('10 MiB'); await expect(panel).toContainText('20 MiB'); await expect(panel).toContainText('La CPU richiede due campioni validi.');
});

test('startup is opt-in and can be disabled again',async({page})=>{await installBridge(page);await page.goto('/');await nav(page,'Impostazioni').click();const panel=page.locator('.startup-panel');await expect(panel.getByText('Disattivato',{exact:true})).toBeVisible();expect((await page.evaluate(()=>window.__PIKO_TEST__.calls)).filter(c=>c.command==='set_startup')).toHaveLength(0);await panel.getByRole('button',{name:'Attiva al login',exact:true}).click();await expect(panel.getByText('Configurato al login',{exact:true})).toBeVisible();await panel.getByRole('button',{name:'Disattiva',exact:true}).click();await expect(panel.getByText('Disattivato',{exact:true})).toBeVisible();expect((await page.evaluate(()=>window.__PIKO_TEST__.calls)).filter(c=>c.command==='set_startup').map(c=>c.args?.enabled)).toEqual([true,false]);});

test('manual review moves only one occurrence and can reopen it',async({page})=>{await installBridge(page);await page.goto('/');await openAlert(page,'test-service');await page.getByLabel('Stato di revisione',{exact:true}).selectOption('expected');await page.getByLabel('Nota personale',{exact:true}).fill('Aggiornamento approvato');await page.getByRole('button',{name:'Salva valutazione',exact:true}).click();await expect(page.getByText('Ultimo salvataggio:',{exact:false})).toBeVisible();await page.getByLabel('Nota personale',{exact:true}).fill('Bozza non salvata');const reads=await page.evaluate(()=>window.__PIKO_TEST__.calls.filter(c=>c.command==='list_alert_reviews').length);await page.getByRole('button',{name:'Aggiorna',exact:true}).evaluate(button=>(button as HTMLButtonElement).click());await expect.poll(()=>page.evaluate(()=>window.__PIKO_TEST__.calls.filter(c=>c.command==='list_alert_reviews').length)).toBeGreaterThan(reads);await expect(page.getByLabel('Nota personale',{exact:true})).toHaveValue('Bozza non salvata');await closeAlert(page);await expect(page.locator('[data-group-rule="service-installed"]')).toHaveCount(0);await page.getByLabel('Filtro revisione',{exact:true}).selectOption('reviewed');await openAlert(page,'test-service');await expect(page.getByLabel('Nota personale',{exact:true})).toHaveValue('Aggiornamento approvato');await expect(page.getByTestId('risk-score')).toHaveText('25/100');await page.getByLabel('Stato di revisione',{exact:true}).selectOption('open');await page.getByRole('button',{name:'Salva valutazione',exact:true}).click();await closeAlert(page);await page.getByLabel('Filtro revisione',{exact:true}).selectOption('open');await expect(page.locator('[data-group-rule="service-installed"]')).toBeVisible();const calls=await page.evaluate(()=>window.__PIKO_TEST__.calls);expect(calls.filter(c=>c.command==='save_alert_review').map(c=>c.args?.state)).toEqual(['expected','open']);expect(calls.filter(c=>c.command==='execute_action')).toHaveLength(0);});

test('archive pressure exposes the effective database cap and explicit retention policy',async({page})=>{
 await installBridge(page);
 await page.addInitScript(()=>{const bridge=(window as unknown as {__TAURI_INTERNALS__:{invoke:(command:string,args?:Record<string,unknown>)=>Promise<unknown>}}).__TAURI_INTERNALS__;const original=bridge.invoke;bridge.invoke=async(command,args)=>{const v=await original(command,args);return command==='get_health'?{...(v as object),archive:{sampled_at_unix_ms:Date.now(),budget_bytes:268435456,database_limit_bytes:134217728,database_bytes:134217728,total_bytes:135266304},sensors:[{id:'piko.storage',state:'degraded',detail:'database or disk is full',last_seen_unix_ms:null}]}:v;};});
 await page.goto('/');await page.locator('.sidebar nav').getByRole('button',{name:'Impostazioni',exact:true}).click();const panel=page.locator('.archive-panel');await expect(panel.getByRole('heading',{name:'Capacità archivio'})).toBeVisible();await expect(panel.getByText('128 MiB / 128 MiB',{exact:true})).toBeVisible();await expect(panel.getByRole('status')).toContainText('Scritture sospese');await expect(panel).toContainText('Conservazione automatica disattivata.');await expect(panel).toContainText('Il limite di spazio non accorcia il periodo di conservazione');
});

test('failed-logon bursts name the attempted account and expose bounded original records',async({page})=>{
 await installBridge(page);await page.goto('/');await page.evaluate(()=>{const base=window.__PIKO_TEST__.alerts[0];const uuid=(i:number)=>'00000000-0000-0000-0000-'+i.toString(16).padStart(12,'0');window.__PIKO_TEST__.alerts=[{...base,id:'test-logon',rule_id:'failed-logon-burst',severity:'medium',assessment:{...base.assessment!,risk_score:50,factors:[{code:'repeated_bad_credentials',points:50}],context:{...base.assessment!.context,target_user:'alice',target_domain:'PC',source_ip:'192.0.2.10',logon_type:'10',failed_logons:{bucket_start:1791885600000,bucket_end:1791885660000,count:6,records:Array.from({length:6},(_,i)=>({event_id:uuid(i+1),evidence_id:uuid(i+100),event_time:1791885605000}))}}}}];});
 await page.getByRole('button',{name:'Aggiorna',exact:true}).click();await page.locator('[data-group-rule="failed-logon-burst"]').click();await expect(page.getByRole('heading',{name:'Accessi falliti ripetuti · PC\\alice',exact:true})).toBeVisible();await expect(page.getByTestId('risk-score')).toHaveText('50/100');await page.locator('.authentication-evidence > summary').click();const panel=page.locator('.authentication-evidence');await expect(panel.locator('.record')).toHaveCount(5);await panel.getByRole('button',{name:'Apri XML',exact:true}).first().click();await expect(panel.locator('pre')).toContainText('<Event');await panel.getByRole('button',{name:'Successive',exact:true}).click();await expect(panel.locator('.record')).toHaveCount(1);
});
