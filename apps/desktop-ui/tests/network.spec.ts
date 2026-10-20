import { expect, test, type Page } from '@playwright/test';
import type { InventorySnapshot, NetworkPlan, NetworkSnapshot } from '../src/lib/appControl';

// Browser-only fixtures exercise the confirmation flow. No host firewall is modified.
const executable = 'C:\\Program Files\\Example\\app.exe';
const ruleId = 'a'.repeat(64);
const inventory: InventorySnapshot = { complete: true, truncated: false, warnings: [], entries: [
  { id: 'example', display_name: 'Example App', publisher: 'Example Publisher', version: '1.2', install_location: 'C:\\Program Files\\Example', scope: 'machine', registry_view: '64', source: 'windows_uninstall_registry', uninstall_key: 'Example' },
  { id: 'other', display_name: 'Other App', publisher: 'Other Publisher', version: null, install_location: null, scope: 'user', registry_view: '64', source: 'windows_uninstall_registry', uninstall_key: 'Other' },
  { id: 'untrusted', display_name: '<img src=x onerror="window.inventoryExecuted=true">', publisher: null, version: null, install_location: null, scope: 'user', registry_view: '32', source: 'windows_uninstall_registry', uninstall_key: 'Untrusted' },
] };
const network: NetworkSnapshot = { active_profiles: 2, profiles: [
  { id: 1, name: 'domain', active: false, firewall_enabled: true, block_all_inbound: false, excluded_interfaces: false },
  { id: 2, name: 'private', active: true, firewall_enabled: true, block_all_inbound: false, excluded_interfaces: false },
  { id: 4, name: 'public', active: false, firewall_enabled: true, block_all_inbound: false, excluded_interfaces: false },
], local_policy_modify_state: 'ok', rules: [], complete: true, warnings: [] };
type BridgeState = { inventory: InventorySnapshot; network: NetworkSnapshot; failNetwork: boolean; failInventory: boolean;
  failHistory?: boolean;
  failPrepare: boolean; failPrepareAt?: number; candidatePaths?: string[]; failExecute: boolean; failExecuteAt?: number; invalidExecute: boolean; expired: boolean;
  plans: NetworkPlan[]; calls: { command: string; args?: Record<string, unknown> }[] };
declare global { interface Window { __PIKO_NETWORK_TEST__: BridgeState } }

async function installBridge(page: Page) {
  await page.addInitScript(({ inventory, network, ruleId }) => {
    const state: BridgeState = { inventory, network, failNetwork: false, failInventory: false, failPrepare: false,
      failExecute: false, invalidExecute: false, expired: false, plans: [], calls: [] };
    window.__PIKO_NETWORK_TEST__ = state;
    Object.defineProperty(window, 'isTauri', { value: true });
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: { invoke: async (command: string, args?: Record<string, unknown>) => {
      state.calls.push({ command, args });
      if (command === 'get_health') return { product: 'piko', version: '0.2.0', protection_state: 'degraded', runtime_mode: 'development_console', uptime_seconds: 2, stored_events: 0, queue_depth: 0, dropped_events: 0, sensors: [] };
      if (command === 'list_alerts') return [];
      if (command === 'response_status') return { roots: [], max_file_bytes: 1000, vault_budget_bytes: 10000, actions: [] };
      if (command === 'registry_history') {
        const scopes=['HKLM','HKCU'].flatMap(h=>['64','32'].flatMap(v=>['Run','RunOnce'].map(k=>h+':'+v+':SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\'+k)));
        const before={scope_id:scopes[0],value_name:'Example Startup',value_type:1,data_hex:'4100',text:'A'};
        return {entries:Array.from({length:6},(_,i)=>({sequence:6-i,observed_at:1791800000000,kind:'changed',before,after:{...before,text:'B',data_hex:'4200'}})),scopes:scopes.map((id,i)=>({id,complete:i!==0,warnings:i===0?['Access denied']:[]})),observed_at:1791800000000,first_observed_at:1791790000000,has_more:false,retained_limit:500};
      }
      if (command === 'software_history') {
        if (state.failHistory) throw new Error('History storage unavailable');
        const before = { id:'history-example',name:'Example App',publisher:'Example Publisher',version:'1',install_location:null };
        const entries = args?.beforeSequence ? [{sequence:1,observed_at:1791800000000,kind:'appeared',before:null,after:before}] : Array.from({length:6},(_,i)=>({sequence:7-i,observed_at:1791800000000,kind:'version_changed',before,after:{...before,version:'2'}}));
        return {entries,observed_at:1791800000000,first_observed_at:1791790000000,inventory_complete:false,has_more:!args?.beforeSequence,retained_limit:2000};
      }
      if (command === 'executable_signature') return {executable:args?.path,sha256:'b'.repeat(64),status:'no_embedded_signature',native_status:'0x800B0100',checked_at:Math.floor(Date.now()/1000),revocation_checked:false,catalog_checked:false};
      if (command === 'sandbox_status') return { launcher_available: false, max_sessions: 8 };
      if (command === 'sandbox_sessions') return [];
      if (command === 'software_inventory') { if (state.failInventory) throw new Error('Inventory access denied'); return state.inventory; }
      if (command === 'application_executables') return { app_id: args?.appId, complete: true, warnings: [], paths: state.candidatePaths ?? [String(args?.appId) === 'example' ? 'C:\\Program Files\\Example\\app.exe' : 'C:\\Other\\other.exe'] };
      if (command === 'discard_network_plans') return null;
      if (command === 'network_snapshot') { if (state.failNetwork) throw new Error('Firewall read unavailable'); return state.network; }
      if (command === 'prepare_network_action') {
        if (state.failPrepare || state.calls.filter(c => c.command === 'prepare_network_action').length === state.failPrepareAt) throw new Error('Executable identity could not be verified');
        const action = args?.action as NetworkPlan['action'];
        const path = String(args?.path);
        const plan: NetworkPlan = { id: `b16b49e1-13f1-41f6-bf5b-${String(state.plans.length).padStart(12, '0')}`, action, direction: args?.direction as NetworkPlan['direction'], rule_id: path.includes('Other') ? 'c'.repeat(64) : ruleId,
          executable: path, display_name: path.split('\\').pop()!, sha256: action === 'block' ? 'b'.repeat(64) : null,
          expires_at: Math.floor(Date.now() / 1000) + (state.expired ? -1 : 300) };
        state.plans.push(plan); return plan;
      }
      if (command === 'execute_network_action') {
        if (state.failExecute || state.calls.filter(c => c.command === 'execute_network_action').length === state.failExecuteAt) throw new Error('Operazione annullata nella richiesta di Windows');
        const plan = [...state.plans].reverse().find(plan => plan.id === args?.planId);
        if (!plan) throw new Error('Unknown plan');
        state.network.rules = plan.action === 'block'
          ? [...state.network.rules.filter(r => r.id !== plan.rule_id || (r.direction??'outbound')!==(plan.direction??'outbound')), { id: plan.rule_id, executable: plan.executable, direction:plan.direction, enabled: true, verified: true }] : state.network.rules.filter(r => r.id !== plan.rule_id || (r.direction??'outbound')!==(plan.direction??'outbound'));
        return state.invalidExecute ? { success: true } : null;
      }
      throw new Error(`Unexpected command: ${command}`);
    } } });
  }, { inventory, network, ruleId });
  await page.goto('/');
  await page.locator('.sidebar nav').getByRole('button', { name: 'Permessi app', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Stato del Firewall di Windows', exact: true })).toBeVisible();
  await expect(page.locator('.inventory article')).toHaveCount(3);
}
async function openManual(page: Page) { if (await page.locator('.manual-panel').getAttribute('open') === null) await page.getByText('Percorso manuale e anteprima', { exact: true }).click(); }
async function prepareBlock(page: Page) {
  await openManual(page);
  await page.getByLabel('Percorso del file .exe', { exact: true }).fill(executable);
  await page.getByRole('button', { name: 'Prepara blocco', exact: true }).click();
  await expect(page.getByTestId('network-plan')).toBeVisible();
}
const executeCalls = (page: Page) => page.evaluate(() => window.__PIKO_NETWORK_TEST__.calls.filter(call => call.command === 'execute_network_action'));

test('inventory is searchable metadata and selection never guesses an executable or applies a rule', async ({ page }) => {
  await installBridge(page);
  await expect(page.locator('.inventory img')).toHaveCount(0);
  expect(await page.evaluate(() => Object.hasOwn(window, 'inventoryExecuted'))).toBe(false);
  await page.getByLabel('Cerca applicazione o editore', { exact: true }).fill('example publisher');
  await expect(page.locator('.inventory article')).toHaveCount(1);
  await page.locator('.inventory').getByRole('button', { name: 'Configura rete · percorso manuale', exact: true }).click();
  await expect(page.getByLabel('Percorso del file .exe', { exact: true })).toBeEmpty();
  await openManual(page);
  await expect(page.getByRole('button', { name: 'Prepara blocco', exact: true })).toBeDisabled();
  await expect(page.getByText('Cartella dichiarata dall’installatore', { exact: false })).toContainText('C:\\Program Files\\Example');
  expect(await page.evaluate(() => window.__PIKO_NETWORK_TEST__.calls.some(call => ['prepare_network_action', 'execute_network_action'].includes(call.command)))).toBe(false);
});

test('block preview is read-only and requires explicit confirmation before one execution and refreshed rules', async ({ page }) => {
  await installBridge(page);
  await prepareBlock(page);
  const plan = page.getByTestId('network-plan');
  await expect(plan).toContainText(executable);
  await expect(plan).toContainText('ANTEPRIMA — NESSUNA MODIFICA ESEGUITA');
  await expect(plan.getByRole('button', { name: 'Conferma con Windows', exact: true })).toBeDisabled();
  expect(await executeCalls(page)).toEqual([]);
  await expect(page.getByText('Nessun blocco piko configurato.', { exact: true })).toBeVisible();
  await plan.getByRole('checkbox').check();
  await plan.getByRole('button', { name: 'Conferma con Windows', exact: true }).click();
  await expect(plan).toHaveCount(0);
  await expect(page.locator('.rule')).toHaveCount(1);
  await expect(page.locator('.rule')).toContainText('Regola piko presente e abilitata');
  await expect(page.locator('.result')).toContainText('Modifica completata per app.exe');
  expect(await executeCalls(page)).toEqual([{ command: 'execute_network_action', args: { planId: 'b16b49e1-13f1-41f6-bf5b-000000000000' } }]);
  expect(await page.evaluate(() => window.__PIKO_NETWORK_TEST__.calls.filter(call => call.command === 'network_snapshot').length)).toBeGreaterThanOrEqual(2);
});

test('removal previews only the piko rule and does not promise universal network permission', async ({ page }) => {
  await installBridge(page);
  await page.evaluate(({ executable, ruleId }) => { window.__PIKO_NETWORK_TEST__.network.rules = [{ id: ruleId, executable, enabled: true, verified: true }]; }, { executable, ruleId });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await page.getByRole('button', { name: 'Prepara rimozione', exact: true }).click();
  const plan = page.getByTestId('network-plan');
  await expect(plan.getByRole('heading')).toHaveText('Rimuovere il blocco piko di app.exe');
  await expect(plan).toContainText('non è un’autorizzazione universale alla rete');
  await expect(plan.getByText('Impronta del file verificato (SHA-256)', { exact: true })).toHaveCount(0);
  expect(await executeCalls(page)).toEqual([]);
  await plan.getByRole('checkbox').check();
  await plan.getByRole('button', { name: 'Conferma con Windows', exact: true }).click();
  await expect(page.locator('.rule')).toHaveCount(0);
  await expect(page.getByText('Nessun blocco piko configurato.', { exact: true })).toBeVisible();
});

test('cancel and path edits discard the confirmation without applying a rule', async ({ page }) => {
  await installBridge(page);
  await prepareBlock(page);
  await page.getByTestId('network-plan').getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Annulla', exact: true }).click();
  await expect(page.getByTestId('network-plan')).toHaveCount(0);
  await prepareBlock(page);
  await page.getByTestId('network-plan').getByRole('checkbox').check();
  await page.getByLabel('Percorso del file .exe', { exact: true }).fill('C:\\Example\\different.exe');
  await expect(page.getByTestId('network-plan')).toHaveCount(0);
  expect(await executeCalls(page)).toEqual([]);
});

test('an owned block can still be removed when system policy or a disabled firewall prevents new blocks', async ({ page }) => {
  await installBridge(page);
  await page.evaluate(({ executable, ruleId }) => {
    const state = window.__PIKO_NETWORK_TEST__;
    state.network.rules = [{ id: ruleId, executable, enabled: true, verified: true }];
    state.network.profiles[1].firewall_enabled = false;
    state.network.local_policy_modify_state = 'group_policy_override';
  }, { executable, ruleId });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await openManual(page);
  await expect(page.getByRole('button', { name: 'Prepara blocco', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Prepara rimozione', exact: true }).click();
  await page.getByTestId('network-plan').getByRole('checkbox').check();
  await expect(page.getByRole('button', { name: 'Conferma con Windows', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Conferma con Windows', exact: true }).click();
  await expect(page.locator('.rule')).toHaveCount(0);
  expect(await executeCalls(page)).toHaveLength(1);
});

test('expired previews and disabled firewall cannot be confirmed', async ({ page }) => {
  await installBridge(page);
  await page.evaluate(() => { window.__PIKO_NETWORK_TEST__.expired = true; });
  await prepareBlock(page);
  await expect(page.getByTestId('network-plan')).toContainText('Anteprima scaduta: preparala di nuovo.');
  await expect(page.getByTestId('network-plan').getByRole('checkbox')).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Conferma con Windows', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Annulla', exact: true }).click();
  await page.evaluate(() => { window.__PIKO_NETWORK_TEST__.expired = false; });
  await prepareBlock(page);
  await page.getByTestId('network-plan').getByRole('checkbox').check();
  await page.evaluate(() => { window.__PIKO_NETWORK_TEST__.network.profiles[1].firewall_enabled = false; });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await expect(page.getByText('Firewall disabilitato', { exact: true })).toBeVisible();
  await openManual(page);
  await expect(page.getByRole('button', { name: 'Prepara blocco', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Conferma con Windows', exact: true })).toBeDisabled();
  expect(await executeCalls(page)).toEqual([]);
});

test('stale snapshots suspend actions and externally changed rules cannot be removed by piko', async ({ page }) => {
  await installBridge(page);
  await page.evaluate(({ executable, ruleId }) => { window.__PIKO_NETWORK_TEST__.network.rules = [{ id: ruleId, executable, enabled: false, verified: false }]; }, { executable, ruleId });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await expect(page.locator('.rule')).toContainText('Regola modificata esternamente');
  await expect(page.getByRole('button', { name: 'Prepara rimozione', exact: true })).toBeDisabled();
  await openManual(page);
  await page.getByLabel('Percorso del file .exe', { exact: true }).fill(executable);
  await page.evaluate(() => { window.__PIKO_NETWORK_TEST__.failNetwork = true; });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Stato non aggiornato. Le modifiche sono sospese.');
  await openManual(page);
  await expect(page.getByRole('button', { name: 'Prepara blocco', exact: true })).toBeDisabled();
  await expect(page.getByText('Nessun blocco piko configurato.', { exact: true })).toHaveCount(0);
  expect(await executeCalls(page)).toEqual([]);
});

test('preparation failures and Windows cancellation show errors and never report successful changes', async ({ page }) => {
  await installBridge(page);
  await page.evaluate(() => { window.__PIKO_NETWORK_TEST__.failPrepare = true; });
  await openManual(page);
  await page.getByLabel('Percorso del file .exe', { exact: true }).fill(executable);
  await page.getByRole('button', { name: 'Prepara blocco', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Executable identity could not be verified');
  await expect(page.getByTestId('network-plan')).toHaveCount(0);
  await page.evaluate(() => { window.__PIKO_NETWORK_TEST__.failPrepare = false; window.__PIKO_NETWORK_TEST__.failExecute = true; });
  await prepareBlock(page);
  await page.getByTestId('network-plan').getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Conferma con Windows', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Operazione annullata nella richiesta di Windows');
  await expect(page.locator('.result')).toHaveCount(0);
  await expect(page.getByTestId('network-plan')).toHaveCount(0);
  expect(await executeCalls(page)).toHaveLength(1);
  expect(await page.evaluate(() => window.__PIKO_NETWORK_TEST__.calls.filter(call => call.command === 'network_snapshot').length)).toBeGreaterThanOrEqual(2);
});

test('unexpected execution response is not accepted as success; refreshed rules show actual state', async ({ page }) => {
  await installBridge(page);
  await page.evaluate(() => { window.__PIKO_NETWORK_TEST__.invalidExecute = true; });
  await prepareBlock(page);
  await page.getByTestId('network-plan').getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Conferma con Windows', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Invalid application control response');
  await expect(page.locator('.result')).toHaveCount(0);
  await expect(page.locator('.rule')).toHaveCount(1);
});

test('partial inventory and firewall policy limits stay explicit with a usable narrow viewport', async ({ page }) => {
  await installBridge(page);
  await page.evaluate(() => {
    window.__PIKO_NETWORK_TEST__.inventory.complete = false;
    window.__PIKO_NETWORK_TEST__.inventory.warnings = ['One installer registry scope was unavailable'];
    window.__PIKO_NETWORK_TEST__.network.local_policy_modify_state = 'group_policy_override';
  });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await expect(page.getByText('Inventario parziale: alcune voci non sono state lette.', { exact: true })).toBeVisible();
  await expect(page.getByText('Le policy di sistema impediscono o non confermano le modifiche locali.', { exact: true })).toBeVisible();
  await openManual(page);
  await expect(page.getByRole('button', { name: 'Prepara blocco', exact: true })).toBeDisabled();
  await page.screenshot({ path: 'test-results/piko-network-light.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBe(false);
  await page.screenshot({ path: 'test-results/piko-network-mobile.png', fullPage: true });
});

test('grid selection discovers exact executables and previews multiple blocks without effects', async ({ page }) => {
  await installBridge(page);
  await page.getByLabel('Seleziona Example App', { exact: true }).check();
  await page.getByLabel('Seleziona Other App', { exact: true }).check();
  await expect(page.getByRole('button', { name: 'Prepara blocchi selezionati', exact: true })).toBeEnabled();
  await expect(page.getByRole('option', { name: 'File di sistema — non disponibile', exact: true })).toHaveJSProperty('disabled', true);
  await page.getByRole('button', { name: 'Prepara blocchi selezionati', exact: true }).click();
  await expect(page.getByTestId('batch-network-plan').locator('li')).toHaveCount(2);
  expect(await executeCalls(page)).toHaveLength(0);
  await expect(page.getByRole('button', { name: 'Applica blocchi con Windows', exact: true })).toBeDisabled();
  await page.getByLabel('Ho verificato tutti i percorsi e autorizzo questi blocchi.', { exact: true }).check();
  await page.getByRole('button', { name: 'Applica blocchi con Windows', exact: true }).click();
  await expect(page.getByLabel('Esiti dei blocchi').locator('li')).toHaveCount(2);
  expect(await executeCalls(page)).toHaveLength(2);
});
test('batch cancellation stops subsequent mutations and retains individual outcomes', async ({ page }) => {
  await installBridge(page);
  await page.getByLabel('Seleziona Example App', { exact: true }).check();
  await page.getByLabel('Seleziona Other App', { exact: true }).check();
  await page.getByRole('button', { name: 'Prepara blocchi selezionati', exact: true }).click();
  await page.getByLabel('Ho verificato tutti i percorsi e autorizzo questi blocchi.', { exact: true }).check();
  await page.evaluate(() => window.__PIKO_NETWORK_TEST__.failExecute = true);
  await page.getByRole('button', { name: 'Applica blocchi con Windows', exact: true }).click();
  await expect(page.getByLabel('Esiti dei blocchi')).toContainText('Non eseguita');
  expect(await executeCalls(page)).toHaveLength(1);
  await expect(page.getByLabel('Esiti dei blocchi')).toContainText('Da verificare');
});
test('grid sorts dates, paginates and retains selections across search', async ({ page }) => {
  await installBridge(page);
  await page.evaluate(() => { window.__PIKO_NETWORK_TEST__.inventory.entries = Array.from({ length: 15 }, (_, i) => ({ ...window.__PIKO_NETWORK_TEST__.inventory.entries[0], id: 'app-' + i, display_name: 'App ' + i, install_date: '202601' + String(i + 1).padStart(2, '0') })); });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await expect(page.locator('.inventory article')).toHaveCount(12);
  await expect(page.locator('.inventory article').first()).toContainText('App 14');
  await page.getByLabel('Seleziona App 14', { exact: true }).check();
  await page.getByRole('button', { name: 'Successive', exact: true }).click();
  await expect(page.locator('.inventory article')).toHaveCount(3);
  await page.getByLabel('Cerca applicazione o editore', { exact: true }).fill('App 14');
  await expect(page.getByLabel('Seleziona App 14', { exact: true })).toBeChecked();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await page.screenshot({ path: 'test-results/piko-app-grid-mobile.png', fullPage: true });
});

test('partial batch keeps a successful first rule and reports the second cancellation', async ({ page }) => {
  await installBridge(page);
  await page.getByLabel('Seleziona Example App', { exact: true }).check();
  await page.getByLabel('Seleziona Other App', { exact: true }).check();
  await page.getByRole('button', { name: 'Prepara blocchi selezionati', exact: true }).click();
  await page.getByLabel('Ho verificato tutti i percorsi e autorizzo questi blocchi.', { exact: true }).check();
  await page.evaluate(() => window.__PIKO_NETWORK_TEST__.failExecuteAt = 2);
  await page.getByRole('button', { name: 'Applica blocchi con Windows', exact: true }).click();
  await expect(page.getByLabel('Esiti dei blocchi')).toContainText('Modifica completata');
  await expect(page.getByLabel('Esiti dei blocchi')).toContainText('Da verificare');
  await expect(page.locator('.rule')).toHaveCount(1);
  expect(await executeCalls(page)).toHaveLength(2);
});

test('grid applies and removes both directions with one explicit preview per batch', async ({ page }) => {
  await installBridge(page);
  await page.getByLabel('Seleziona Example App', { exact: true }).check();
  await page.getByLabel('Seleziona Other App', { exact: true }).check();
  await page.getByLabel('Blocco da applicare', { exact: true }).selectOption('both');
  await page.getByRole('button', { name: 'Prepara blocchi selezionati', exact: true }).click();
  const preview = page.getByTestId('batch-network-plan');
  await expect(preview.locator('li')).toHaveCount(4);
  expect(await executeCalls(page)).toHaveLength(0);
  await preview.getByRole('checkbox').check();
  await preview.getByRole('button', { name: 'Applica blocchi con Windows', exact: true }).click();
  await expect(page.locator('.rule')).toHaveCount(4);
  // Undo must remain possible even when policy no longer permits new blocks.
  await page.evaluate(() => window.__PIKO_NETWORK_TEST__.network.profiles[1].firewall_enabled = false);
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Prepara blocchi selezionati', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Prepara rimozione selezionati', exact: true }).click();
  await expect(preview.locator('li')).toHaveCount(4);
  await expect(preview).toContainText('tutte le altre regole di Windows continueranno a valere');
  expect(await executeCalls(page)).toHaveLength(4);
  await expect(preview.getByRole('button', { name: 'Rimuovi blocchi con Windows', exact: true })).toBeDisabled();
  await preview.getByRole('checkbox').check();
  await preview.getByRole('button', { name: 'Rimuovi blocchi con Windows', exact: true }).click();
  await expect(page.locator('.rule')).toHaveCount(0);
  expect(await executeCalls(page)).toHaveLength(8);
});

test('grid removal excludes changed rules and keeps the unselected direction', async ({ page }) => {
  await installBridge(page);
  await page.evaluate(({ executable, ruleId }) => {
    window.__PIKO_NETWORK_TEST__.network.rules = [
      { id: ruleId, executable, direction: 'outbound', enabled: true, verified: true },
      { id: ruleId, executable, direction: 'inbound', enabled: true, verified: true },
      { id: 'c'.repeat(64), executable: 'C:\\Other\\other.exe', direction: 'outbound', enabled: true, verified: false },
    ];
  }, { executable, ruleId });
  await page.getByRole('button', { name: 'Aggiorna', exact: true }).click();
  await page.getByLabel('Seleziona Example App', { exact: true }).check();
  await page.getByLabel('Seleziona Other App', { exact: true }).check();
  await page.getByRole('button', { name: 'Prepara rimozione selezionati', exact: true }).click();
  const preview = page.getByTestId('batch-network-plan');
  await expect(preview.locator('li')).toHaveCount(1);
  await expect(preview).toContainText('In uscita');
  await preview.getByRole('checkbox').check();
  await preview.getByRole('button', { name: 'Rimuovi blocchi con Windows', exact: true }).click();
  await expect(page.locator('.rule')).toHaveCount(2);
  await expect(page.locator('.rule').filter({ hasText: executable })).toContainText('In ingresso');
  const removalPlans = await page.evaluate(() => window.__PIKO_NETWORK_TEST__.plans.filter(p => p.action === 'remove_block'));
  expect(removalPlans.map(p => [p.executable, p.direction])).toEqual([[executable, 'outbound']]);
});

test('partial two-direction batch labels each outcome and stops after cancellation', async ({ page }) => {
  await installBridge(page);
  await page.getByLabel('Seleziona Example App', { exact: true }).check();
  await page.getByLabel('Seleziona Other App', { exact: true }).check();
  await page.getByLabel('Blocco da applicare', { exact: true }).selectOption('both');
  await page.getByRole('button', { name: 'Prepara blocchi selezionati', exact: true }).click();
  await page.getByTestId('batch-network-plan').getByRole('checkbox').check();
  await page.evaluate(() => window.__PIKO_NETWORK_TEST__.failExecuteAt = 2);
  await page.getByRole('button', { name: 'Applica blocchi con Windows', exact: true }).click();
  const outcomes = page.getByLabel('Esiti dei blocchi').locator('li');
  await expect(outcomes).toHaveCount(4);
  await expect(outcomes.nth(0)).toContainText('In uscita · Modifica completata');
  await expect(outcomes.nth(1)).toContainText('In ingresso · Da verificare');
  await expect(outcomes.nth(2)).toContainText('Non eseguita');
  await expect(outcomes.nth(3)).toContainText('Non eseguita');
  expect(await executeCalls(page)).toHaveLength(2);
  await expect(page.locator('.rule')).toHaveCount(1);
});

test('two-direction batch respects the native plan limit and discards a partially prepared batch', async ({ page }) => {
  await installBridge(page);
  await page.evaluate(() => window.__PIKO_NETWORK_TEST__.candidatePaths = Array.from({ length: 17 }, (_, i) => `C:\\Example\\app${i}.exe`));
  await page.getByLabel('Seleziona Example App', { exact: true }).check();
  await page.getByLabel('Blocco da applicare', { exact: true }).selectOption('both');
  await expect(page.getByRole('button', { name: 'Prepara blocchi selezionati', exact: true })).toBeDisabled();
  await page.getByLabel('Blocco da applicare', { exact: true }).selectOption('outbound');
  await page.evaluate(() => window.__PIKO_NETWORK_TEST__.failPrepareAt = 2);
  await page.getByRole('button', { name: 'Prepara blocchi selezionati', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Executable identity could not be verified');
  await expect(page.getByTestId('batch-network-plan')).toHaveCount(0);
  expect(await executeCalls(page)).toHaveLength(0);
  const discarded = await page.evaluate(() => window.__PIKO_NETWORK_TEST__.calls.filter(c => c.command === 'discard_network_plans'));
  expect(discarded).toHaveLength(1);
  expect(discarded[0].args?.planIds).toHaveLength(1);
});

test('history is lazy, compact, paginated and distinguishes partial readings and stale failures', async ({page}) => {
  await installBridge(page);
  expect(await page.evaluate(()=>window.__PIKO_NETWORK_TEST__.calls.some(c=>c.command==='software_history'))).toBe(false);
  await page.getByText('Storico applicazioni e versioni',{exact:true}).click();
  const panel=page.locator('.history-panel'); await expect(panel.locator('article')).toHaveCount(5);
  await expect(panel.getByText(/Inventario parziale/)).toBeVisible();
  await panel.getByRole('button',{name:'Successive',exact:true}).click(); await expect(panel.locator('article')).toHaveCount(1);
  await panel.getByRole('button',{name:'Carica variazioni più vecchie',exact:true}).click(); await expect(panel.getByText('Nuova voce osservata',{exact:true})).toBeVisible();
  await panel.getByRole('button',{name:'Letture più recenti',exact:true}).click(); await expect(panel.locator('article')).toHaveCount(5);
  await page.evaluate(()=>window.__PIKO_NETWORK_TEST__.failHistory=true);
  await panel.getByRole('button',{name:'Aggiorna storico',exact:true}).click(); await expect(panel.getByRole('alert')).toContainText('Storico non aggiornato'); await expect(panel.locator('article')).toHaveCount(5);
  await expect(panel.getByRole('button',{name:'Esporta storico caricato',exact:true})).toBeDisabled();
});
test('history search covers loaded records, shows before and after, and fits a narrow viewport', async ({page}) => {
  await installBridge(page); await page.getByText('Storico applicazioni e versioni',{exact:true}).click();
  const panel=page.locator('.history-panel'); await expect(panel.locator('article')).toHaveCount(5);
  await panel.getByLabel('Cerca nelle 50 variazioni caricate',{exact:true}).fill('absent'); await expect(panel.locator('article')).toHaveCount(0);
  await panel.getByLabel('Cerca nelle 50 variazioni caricate',{exact:true}).fill('Example');
  await panel.locator('article').first().getByText('Vedi cosa è cambiato',{exact:true}).click(); await expect(panel.locator('article').first().locator('dl')).toContainText('1 → 2');
  await page.setViewportSize({width:390,height:844}); expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});

test('inbound and outbound blocks coexist and removal keeps the other direction',async({page})=>{await installBridge(page);await prepareBlock(page);let preview=page.getByTestId('network-plan');await preview.getByRole('checkbox').check();await preview.getByRole('button',{name:'Conferma con Windows',exact:true}).click();await page.getByLabel('Direzione del blocco',{exact:true}).selectOption('inbound');await page.getByRole('button',{name:'Prepara blocco',exact:true}).click();await expect(preview).toContainText('In ingresso');await preview.getByRole('checkbox').check();await preview.getByRole('button',{name:'Conferma con Windows',exact:true}).click();await expect(page.locator('.rule')).toHaveCount(2);const inbound=page.locator('.rule').filter({has:page.getByRole('heading',{name:'app.exe · In ingresso',exact:true})});await inbound.getByRole('button',{name:'Prepara rimozione',exact:true}).click();await expect(preview).toContainText('In ingresso');await preview.getByRole('checkbox').check();await preview.getByRole('button',{name:'Conferma con Windows',exact:true}).click();await expect(page.locator('.rule')).toHaveCount(1);await expect(page.locator('.rule')).toContainText('In uscita');expect((await page.evaluate(()=>window.__PIKO_NETWORK_TEST__.plans)).map(p=>[p.action,p.direction])).toEqual([['block','outbound'],['block','inbound'],['remove_block','inbound']]);});

test('signature inspection is explicit and never applies a network block',async({page})=>{await installBridge(page);await openManual(page);await page.getByLabel('Percorso del file .exe',{exact:true}).fill(executable);await page.getByRole('button',{name:'Verifica firma locale',exact:true}).click();await expect(page.getByText('Firma incorporata non trovata',{exact:true})).toBeVisible();await expect(page.getByText('Revoca e cataloghi non verificati.',{exact:false})).toBeVisible();expect((await page.evaluate(()=>window.__PIKO_NETWORK_TEST__.calls)).filter(c=>c.command==='prepare_network_action'||c.command==='execute_network_action')).toHaveLength(0);await page.getByLabel('Percorso del file .exe',{exact:true}).fill('C:\\Other\\other.exe');await expect(page.getByText('Firma incorporata non trovata',{exact:true})).toHaveCount(0);});

test('registry history is lazy, bounded and exposes previous raw values with partial coverage',async({page})=>{
 await installBridge(page);expect(await page.evaluate(()=>window.__PIKO_NETWORK_TEST__.calls.some(c=>c.command==='registry_history'))).toBe(false);
 await page.getByText('Registro: avvio automatico',{exact:true}).click();const panel=page.locator('.registry-panel');await expect(panel.locator('article')).toHaveCount(5);await expect(panel).toContainText('Lettura parziale');
 await panel.getByText('Confronta prima e dopo',{exact:true}).first().click();await expect(panel.locator('.comparison').first()).toContainText('A');await expect(panel.locator('.comparison').first()).toContainText('B');
 await panel.getByText('Dati grezzi (esadecimale)',{exact:true}).first().click();await expect(panel.locator('pre').first()).toContainText('4100');await panel.getByRole('button',{name:'Successive',exact:true}).click();await expect(panel.locator('article')).toHaveCount(1);
});
