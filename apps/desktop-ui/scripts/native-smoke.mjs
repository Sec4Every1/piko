// Development-only test of the actual Tauri -> Rust -> named-pipe -> runtime path.
// DevTools is enabled only on the child process created by this test.
import { chromium } from 'playwright-core';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, writeFile, readFile, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import net from 'node:net';

const checks=[];
const execute = promisify(execFile);
const desktopRoot = fileURLToPath(new URL('../', import.meta.url));
const root = path.resolve(desktopRoot, '../..');
const profile = process.env.PIKO_TEST_PROFILE === 'release' ? 'release' : 'debug';
const runDir = path.join(root, '.runtime', `native-smoke-${Date.now()}`);
const resultsDir = path.join(desktopRoot, 'test-results');
await mkdir(runDir, { recursive: true });
await mkdir(resultsDir, { recursive: true });
const configPath = path.join(runDir, 'config.json');
const responseRoot = path.join(root, '.runtime', `native-input-${Date.now()}`);
await mkdir(responseRoot, { recursive: true });
const responseFile = path.join(responseRoot, 'innocent.txt');
await writeFile(responseFile, 'piko native benign quarantine and recovery test');
await writeFile(configPath, JSON.stringify({ data_dir: runDir, response_roots: [responseRoot], heartbeat_seconds: 1, flush_seconds: 1, max_disk_mib: 16, queue_capacity: 32 }));
const port = await new Promise((resolve, reject) => {
  const server = net.createServer();
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => {
    const assigned = server.address().port;
    server.close(() => resolve(assigned));
  });
});
const service = spawn(path.join(root, 'target', profile, 'piko-service.exe'), ['--config', configPath, '--run-for-seconds', '45'], {
  cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
});
let serviceLog = '';
service.stderr.on('data', chunk => { serviceLog += chunk.toString(); });
service.on('error', error => { serviceLog += error.message; });
let desktop;
let browser;
let nativePage;
let desktopLog = '';
const deadline = Date.now() + 35000;

async function waitUntil(check, label) {
  while (Date.now() < deadline) {
    if (service.exitCode !== null) throw new Error(`Runtime exited: ${serviceLog}`);
    try { const value = await check(); if (value) return value; } catch { /* bounded startup retry */ }
    await delay(100);
  }
  throw new Error(`Timeout: ${label}; desktop: ${desktopLog}; runtime: ${serviceLog}`);
}

async function health() {
  const { stdout } = await execute(path.join(root, 'target', profile, 'piko.exe'), ['health'], { windowsHide: true, timeout: 5000 });
  return JSON.parse(stdout);
}

try {
  await waitUntil(async () => (await health()).stored_events >= 2, 'runtime persistence');
  await copyFile(path.join(root,'target',profile,'piko.exe'),path.join(desktopRoot,'src-tauri/target',profile,'piko.exe'));
  desktop = spawn(path.join(desktopRoot, 'src-tauri/target', profile, 'piko-desktop.exe'), [], {
    cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      WEBVIEW2_USER_DATA_FOLDER: path.join(runDir, 'webview'),
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port} --remote-debugging-address=127.0.0.1`,
    },
  });
  desktop.stderr.on('data', chunk => { desktopLog += chunk.toString(); });
  desktop.on('error', error => { desktopLog += error.message; });
  await waitUntil(async () => {
    const response = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(700) });
    return response.ok;
  }, 'WebView2 DevTools');
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
  const page = await waitUntil(() => browser.contexts().flatMap(context => context.pages()).find(value => value.url().includes('tauri.localhost')), 'native page');
  nativePage = page;
  page.setDefaultTimeout(10000);
  await page.getByText('Runtime collegato', { exact: true }).waitFor({ timeout: 12000 });
  const resourceHealth = await waitUntil(async()=>{const h=await health();return h.sensors.some(s=>s.id==='windows.etw.process_image' && ['active','limited','degraded'].includes(s.state)) && h;},'ETW explicit coverage');
  checks.push('native ETW state without stopping complementary sources');
  assert(resourceHealth.archive && resourceHealth.archive.database_bytes>0 && resourceHealth.archive.database_limit_bytes===resourceHealth.archive.budget_bytes/2 && resourceHealth.archive.total_bytes>=resourceHealth.archive.database_bytes);
  checks.push('native archive footprint and actual SQLite database cap');
  const advisorySnapshot=await page.evaluate(()=>window.__TAURI_INTERNALS__.invoke('advisory_status'));
  assert(Array.isArray(advisorySnapshot.entries) && Array.isArray(advisorySnapshot.advisories) && typeof advisorySnapshot.inventory_complete==='boolean');
  checks.push('native advisory state without guessed product or vulnerability');
  const trials=await page.evaluate(()=>window.__TAURI_INTERNALS__.invoke('restricted_sessions'));assert(Array.isArray(trials) && trials.length<=2);
  checks.push('native restricted-session state without launching applications');
  const stops=await page.evaluate(()=>window.__TAURI_INTERNALS__.invoke('process_actions'));assert(Array.isArray(stops) && stops.length<=50);
  checks.push('native bounded process action journal');
  assert(resourceHealth.performance && resourceHealth.performance.working_set_bytes>0 && resourceHealth.performance.private_bytes>0);
  assert(resourceHealth.sensors.some(s=>s.id==='windows.event_log.Microsoft-Windows-Windows Defender/Operational'));
  await page.locator('.sidebar nav').getByRole('button',{name:'Impostazioni',exact:true}).click();
  await page.getByRole('heading',{name:'Consumi del monitor',exact:true}).waitFor();
  assert((await page.locator('.performance-panel').innerText()).includes('MiB'));
  const login = await page.evaluate(()=>window.__TAURI_INTERNALS__.invoke('startup_status'));
  assert.equal(typeof login.enabled,'boolean');assert.equal(typeof login.conflict,'boolean');assert(login.command.endsWith('--monitor-only'));
  checks.push('read-only startup status from fixed HKCU entry');
  await page.screenshot({path:path.join(resultsDir,'piko-native-performance.png'),fullPage:true});
  await page.locator('.sidebar nav').getByRole('button',{name:'Dashboard',exact:true}).click();
  await page.getByTestId('security-dashboard').waitFor();
  await page.getByRole('heading', { name: 'Eventi importanti', exact: true }).waitFor();
  assert.equal(await page.getByText('runtime.heartbeat', { exact: true }).count(), 0, 'dashboard must not promote runtime heartbeats into security alerts');
  await page.screenshot({ path: path.join(resultsDir, 'piko-native-dashboard.png'), fullPage: true });
  await page.locator('.sidebar nav').getByRole('button', { name: 'Attività applicazioni', exact: true }).click();
  await page.getByTestId('application-activity').waitFor();
  const observations = await waitUntil(async () => page.evaluate(async () => window.__TAURI_INTERNALS__.invoke('get_observations')), 'process observations');
  const self = observations.processes.find(p => p.pid === service.pid);
  assert(self && self.instance_id && typeof self.creation_filetime === 'string');
  assert.match(self.name, /piko-service.exe/i);
  const rejectedStop=await page.evaluate(async p=>{try{await window.__TAURI_INTERNALS__.invoke('prepare_process_stop',{pid:p.pid,creationFiletime:p.creation_filetime});return false;}catch{return true;}},self);
  assert(rejectedStop);assert.equal(service.exitCode,null);
  checks.push('native process response excludes piko and preserves the runtime');
  assert(observations.connections.length <= 2048);
  const processEvents = await waitUntil(async () => {
    const rows = await page.evaluate(async id => window.__TAURI_INTERNALS__.invoke('list_events', { filter: { limit: 100, search: id } }), self.instance_id);
    return rows.some(e => e.event_type === 'process.snapshot.observed') && rows;
  }, 'durable process observations');
  const observed = processEvents.find(e => e.event_type === 'process.snapshot.observed');
  assert.equal(observed.process.pid, service.pid);
  assert.equal(observed.process.instance_id, self.instance_id);
  assert.equal(observed.causal_parents.length, 0);
  const processEvidence = await page.evaluate(async id => window.__TAURI_INTERNALS__.invoke('get_evidence', { evidenceId: id }), observed.raw_evidence_reference);
  assert.equal(processEvidence.content_type, 'application/json');
  const rawProcess = JSON.parse(new TextDecoder().decode(new Uint8Array(processEvidence.bytes)));
  assert.equal(rawProcess.process.creation_filetime, self.creation_filetime);
  await page.getByLabel('Cerca nome, percorso o PID', { exact: true }).fill(String(service.pid));
  await page.getByRole('button', { name: self.name, exact: true }).click();
  await page.getByRole('heading', { name: self.name, exact: true }).waitFor();
  const structured = await page.evaluate(async id => window.__TAURI_INTERNALS__.invoke('list_events', { filter: { limit: 10, expression: 'process.instance = ' + JSON.stringify(id) + ' AND sensor.id = "windows.observations"' } }), self.instance_id);
  assert(structured.length > 0 && structured.every(e => e.process?.instance_id === self.instance_id));
  const graph = await page.evaluate(async id => window.__TAURI_INTERNALS__.invoke('get_investigation', { processInstance: id }), self.instance_id);
  assert.equal(graph.process_instance, self.instance_id);
  assert(graph.events_considered > 0 && graph.nodes.length >= 2);
  assert(graph.edges.every(e => e.source === 'process' && e.event_ids.length > 0));
  await page.getByRole('button', { name: 'Carica relazioni', exact: true }).click();
  await page.locator('.relation-map').waitFor();
  await page.locator('.relation-map li button').first().click();
  await page.getByRole('button', { name: 'Osservazione 1', exact: true }).click();
  await page.locator('.event-dialog[open]').waitFor();
  await page.getByRole('button', { name: 'Leggi evidenza originale', exact: true }).click();
  await page.locator('.source-evidence').waitFor();
  assert.equal(JSON.parse(await page.locator('.source-evidence').innerText()).process.pid, service.pid);
  await page.getByRole('button', { name: 'Chiudi', exact: true }).click();
  const syntaxError = await page.evaluate(async () => {
    try { await window.__TAURI_INTERNALS__.invoke('list_events', { filter: { limit: 1, expression: 'unknown.field = 1' } }); return ''; }
    catch (error) { return String(error); }
  });
  assert.match(syntaxError, /query_syntax/);
  await page.screenshot({ path: path.join(resultsDir, 'piko-native-activity.png'), fullPage: true });
  await page.getByRole('button', { name: 'Gestisci accesso alla rete', exact: true }).click();
  assert.equal(await page.getByLabel('Percorso del file .exe', { exact: true }).inputValue(), self.executable);
  await page.locator('.sidebar nav').getByRole('button', { name: 'Manuale', exact: true }).click();
  await page.getByText('Open-Piko.cmd', { exact: true }).waitFor();
  await page.locator('.sidebar nav').getByRole('button', { name: 'Permessi app', exact: true }).click();
  await page.getByRole('heading', { name: 'Decidi quali app possono collegarsi alla rete', exact: true }).waitFor();
  const applicationInventory = await page.evaluate(async () => window.__TAURI_INTERNALS__.invoke('software_inventory'));
  assert(Array.isArray(applicationInventory.entries) && applicationInventory.entries.length <= 4096);
  const reviews=await page.evaluate(()=>window.__TAURI_INTERNALS__.invoke('list_alert_reviews'));assert(Array.isArray(reviews)&&reviews.length<=2000);checks.push('native per-user review archive read');
  assert(applicationInventory.entries.every(app => app.source === 'windows_uninstall_registry' && typeof app.display_name === 'string'));
  assert.equal(typeof applicationInventory.complete, 'boolean');
  assert(applicationInventory.entries.every(app => app.install_date === null || typeof app.install_date === 'string'));
  await page.locator('.inventory article').first().waitFor();
  assert((await page.locator('.inventory article').count()) <= 12);
  let discoveredApp;
  for (const app of applicationInventory.entries.filter(a => a.display_icon && /\.exe/i.test(a.display_icon)).slice(0, 12)) {
    const result = await page.evaluate(async appId => window.__TAURI_INTERNALS__.invoke('application_executables', { appId }), app.id);
    assert.equal(result.app_id, app.id);
    assert(result.paths.length <= 32 && typeof result.complete === 'boolean');
    if (result.paths.length > 0 && result.paths.length <= 20) { discoveredApp = app; break; }
  }
  assert(discoveredApp, 'at least one installed app has discoverable executable candidates on this host');
  await page.getByLabel('Cerca applicazione o editore', { exact: true }).fill(discoveredApp.display_name);
  await page.getByRole('checkbox', { name: 'Seleziona ' + discoveredApp.display_name, exact: true }).first().check();
  await waitUntil(async () => await page.locator('.selection').innerText().then(text => !text.includes('Ricerca eseguibili')), 'native app executable discovery');
  await page.locator('.app-browser').scrollIntoViewIfNeeded();
  await page.screenshot({ path: path.join(resultsDir, 'piko-native-app-grid.png'), fullPage: false });
  await page.getByRole('button', { name: 'Svuota selezione', exact: true }).click();
  await page.getByLabel('Cerca applicazione o editore', { exact: true }).fill('');
  await page.getByText('Storico applicazioni e versioni', {exact:true}).click();
  const independentCheck=await page.evaluate(async()=>Promise.all([window.__TAURI_INTERNALS__.invoke('verify_store'),window.__TAURI_INTERNALS__.invoke('get_health')]));assert(Number.isSafeInteger(independentCheck[0].verified_events));assert.equal(independentCheck[1].product,'piko');checks.push('dedicated integrity reader and simultaneous cached health through IPC');
  const registry=await page.evaluate(()=>window.__TAURI_INTERNALS__.invoke('registry_history',{beforeSequence:null}));
  assert.equal(registry.scopes.length,8);assert(registry.entries.length<=50 && registry.retained_limit===500);assert(Number.isSafeInteger(registry.observed_at));checks.push('native read-only Run/RunOnce history and explicit per-key coverage');
  await page.getByText('Registro: avvio automatico',{exact:true}).click();await page.locator('.registry-panel .reading').first().waitFor();await page.locator('.registry-panel').scrollIntoViewIfNeeded();await page.screenshot({path:path.join(resultsDir,'piko-native-registry.png'),fullPage:false});await page.getByText('Registro: avvio automatico',{exact:true}).click();
  const udpSnapshot=await page.evaluate(()=>window.__TAURI_INTERNALS__.invoke('get_observations'));assert(Array.isArray(udpSnapshot.udp_endpoints) && udpSnapshot.udp_endpoints.length<=2048);assert.equal(typeof udpSnapshot.udp_complete,'boolean');assert(udpSnapshot.udp_endpoints.every(e=>!('remote_address' in e)));checks.push('native bounded UDP local binds without fabricated destinations');
  const nativeHistory = await page.evaluate(()=>window.__TAURI_INTERNALS__.invoke('software_history',{beforeSequence:null}));
  assert(nativeHistory.entries.length<=50 && nativeHistory.retained_limit===2000 && Number.isSafeInteger(nativeHistory.observed_at));
  assert.equal(typeof nativeHistory.inventory_complete,'boolean');
  await page.locator('.history-panel .reading').first().waitFor();
  await page.getByText('Storico applicazioni e versioni', {exact:true}).click();
  const firewallSnapshot = await page.evaluate(async () => window.__TAURI_INTERNALS__.invoke('network_snapshot'));
  assert.deepEqual(firewallSnapshot.profiles.map(profile => profile.id).sort((a, b) => a - b), [1, 2, 4]);
  assert(firewallSnapshot.profiles.every(profile => profile.active === Boolean(firewallSnapshot.active_profiles & profile.id)));
  assert(firewallSnapshot.rules.every(rule => /^[0-9a-f]{64}$/.test(rule.id) && (!rule.verified || rule.enabled)));
  assert.equal(typeof firewallSnapshot.complete, 'boolean');
  await page.locator('.profiles .profile').first().waitFor();
  assert.equal(await page.locator('.profiles .profile').count(), 3, 'native Windows firewall profiles reach the UI');
  assert.equal(await page.getByLabel('Percorso del file .exe', { exact: true }).inputValue(), self.executable, 'explicit activity selection is preserved');
  assert.equal(await page.getByTestId('network-plan').count(), 0, 'read-only inventory and firewall status never prepare an action');
  const networkProbe = path.join(responseRoot, 'network-probe.exe');
  await copyFile(path.join(root, 'target', profile, 'piko.exe'), networkProbe);
  const signature=await page.evaluate(path=>window.__TAURI_INTERNALS__.invoke('executable_signature',{path}),networkProbe);assert.equal(signature.status,'no_embedded_signature');assert.equal(signature.native_status,'0x800B0100');assert.match(signature.sha256,/^[a-f0-9]{64}$/);assert.equal(signature.revocation_checked,false);checks.push('native isolated Authenticode check on unsigned benign PE');
  // Real native Sandbox profile creation, with an inert copy of our CLI; never launches it.
  const sandboxBefore = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('sandbox_sessions'));
  const sandboxPlan = await page.evaluate(path => window.__TAURI_INTERNALS__.invoke('prepare_sandbox', { path }), networkProbe);
  assert.match(sandboxPlan.sha256, /^[a-f0-9]{64}$/);
  const sandboxSession = await page.evaluate(planId => window.__TAURI_INTERNALS__.invoke('create_sandbox', { planId }), sandboxPlan.id);
  try {
    const wsb = await readFile(sandboxSession.configuration, 'utf8');
    for (const setting of ['Networking', 'AudioInput', 'VideoInput', 'PrinterRedirection', 'ClipboardRedirection', 'vGPU']) assert(wsb.includes('<' + setting + '>Disable</' + setting + '>'));
    assert(wsb.includes('<ReadOnly>true</ReadOnly>')); assert(!wsb.includes('LogonCommand'));
    assert.deepEqual(await readFile(path.join(path.dirname(sandboxSession.configuration), 'input', 'payload.exe')), await readFile(networkProbe));
    await page.getByText('Prova isolata · Windows Sandbox', { exact: true }).click();
    await page.getByRole('button', { name: 'Aggiorna stato Sandbox', exact: true }).click();
    await page.locator('.sessions').getByText('network-probe.exe', { exact: true }).waitFor();
    await page.locator('.sandbox-panel').scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(resultsDir, 'piko-native-sandbox.png'), fullPage: false });
  } finally {
    await page.evaluate(sessionId => window.__TAURI_INTERNALS__.invoke('remove_sandbox', { sessionId }), sandboxSession.id);
  }
  const sandboxAfter = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('sandbox_sessions'));
  assert.deepEqual(sandboxAfter, sandboxBefore);
  const networkPreviewAvailable = firewallSnapshot.complete && firewallSnapshot.active_profiles !== 0
    && ['ok', 'inbound_blocked'].includes(firewallSnapshot.local_policy_modify_state)
    && firewallSnapshot.profiles.filter(p => p.active).every(p => p.firewall_enabled && !p.excluded_interfaces);
  if (networkPreviewAvailable) {
    await page.getByLabel('Percorso del file .exe', { exact: true }).fill(networkProbe);
    await page.getByRole('button', { name: 'Prepara blocco', exact: true }).click();
    await page.getByTestId('network-plan').waitFor();
  const incoming=await page.evaluate(async()=>{const path=document.querySelector('#network-executable').value;const plan=await window.__TAURI_INTERNALS__.invoke('prepare_network_action',{action:'block',path,direction:'inbound'});await window.__TAURI_INTERNALS__.invoke('discard_network_plans',{planIds:[plan.id]});return plan;});assert.equal(incoming.direction,'inbound');assert.equal(incoming.action,'block');checks.push('inbound plan preparation and discard without Firewall mutation');
    assert(await page.getByRole('button', { name: 'Conferma con Windows', exact: true }).isDisabled());
    assert.match(await page.getByTestId('network-plan').innerText(), /network-probe.exe/);
    await page.getByRole('button', { name: 'Annulla', exact: true }).click();
    const afterPreview = await page.evaluate(async () => window.__TAURI_INTERNALS__.invoke('network_snapshot'));
    assert.deepEqual(afterPreview.rules, firewallSnapshot.rules, 'native prepare/cancel must not change Firewall rules');
  }
  await page.screenshot({ path: path.join(resultsDir, 'piko-native-network.png'), fullPage: false });
  await page.locator('.sidebar nav').getByRole('button', { name: 'Log tecnici', exact: true }).click();
  await page.getByLabel('Tipo di evento', { exact: true }).fill('runtime.started');
  await page.getByRole('button', { name: 'Applica filtri', exact: true }).click();
  await page.getByText('runtime.started', { exact: true }).first().waitFor();
  await page.getByRole('button', { name: 'Verifica integrità', exact: true }).click();
  await page.getByText('Catena locale verificata', { exact: true }).waitFor();
  const eventPayload = await page.evaluate(async () => {
    // Calls the same registered Tauri command as the frontend, without fixtures.
    return window.__TAURI_INTERNALS__.invoke('list_events', { filter: { limit: 20, event_type: 'runtime.started' } });
  });
  assert(eventPayload.some(event => event.process?.pid === service.pid));
  assert(eventPayload.every(event => event.boot_id === null && event.logon_session === null));
  const sourceRecords = await page.evaluate(async () => window.__TAURI_INTERNALS__.invoke('list_events', { filter: { limit: 100, search: 'windows.event_log' } }));
  assert(sourceRecords.length > 0, 'actual Windows events must reach the native UI');
  const sourceRecord = sourceRecords.find(event => event.raw_evidence_reference);
  assert(sourceRecord && sourceRecord.process === null);
  const evidence = await page.evaluate(async id => window.__TAURI_INTERNALS__.invoke('get_evidence', { evidenceId: id }), sourceRecord.raw_evidence_reference);
  assert.equal(evidence.evidence_id, sourceRecord.raw_evidence_reference);
  assert.match(new TextDecoder().decode(new Uint8Array(evidence.bytes)), /<Event/);
  await page.getByLabel('Tipo di evento', { exact: true }).fill(sourceRecord.event_type);
  await page.getByRole('button', { name: 'Applica filtri', exact: true }).click();
  await page.getByText(sourceRecord.event_type, { exact: true }).first().click();
  await page.getByRole('button', { name: 'Leggi evidenza originale', exact: true }).click();
  await page.locator('.source-evidence').waitFor();
  assert.match(await page.locator('.source-evidence').innerText(), /<Event/);
  await page.getByRole('button', { name: 'Chiudi', exact: true }).click();
  const queryError = await page.evaluate(async () => {
    try { await window.__TAURI_INTERNALS__.invoke('list_events', { filter: { limit: 1001 } }); return null; }
    catch (error) { return String(error); }
  });
  assert.match(queryError ?? '', /invalid_query/);
  await page.locator('.sidebar nav').getByRole('button', { name: 'Quarantena e ripristino', exact: true }).click();
  await page.getByRole('button', { name: 'Prepara quarantena', exact: true }).waitFor();
  await page.getByLabel('Percorso completo del file', { exact: true }).fill(responseFile);
  await page.getByRole('button', { name: 'Prepara quarantena', exact: true }).click();
  await page.getByRole('heading', { name: 'Conferma quarantena', exact: true }).waitFor();
  const executeButton = page.getByRole('button', { name: 'Esegui azione confermata', exact: true });
  assert(await executeButton.isDisabled(), 'explicit confirmation is required');
  assert.equal(await readFile(responseFile, 'utf8'), 'piko native benign quarantine and recovery test');
  await page.getByLabel('Ho verificato il percorso e autorizzo questa azione.').check();
  await executeButton.click();
  await page.getByText('In quarantena', { exact: true }).first().waitFor();
  await assert.rejects(readFile(responseFile), { code: 'ENOENT' });
  await page.getByRole('button', { name: 'Prepara ripristino', exact: true }).click();
  await page.getByRole('heading', { name: 'Conferma ripristino', exact: true }).waitFor();
  await page.getByLabel('Ho verificato il percorso e autorizzo questa azione.').check();
  await page.getByRole('button', { name: 'Esegui azione confermata', exact: true }).click();
  await page.getByText('Ripristinato', { exact: true }).first().waitFor();
  assert.equal(await readFile(responseFile, 'utf8'), 'piko native benign quarantine and recovery test');
  const responseStatus = await page.evaluate(async () => window.__TAURI_INTERNALS__.invoke('response_status'));
  assert.equal(responseStatus.actions.filter(action => action.status === 'quarantined').length, 1);
  assert.equal(responseStatus.actions.filter(action => action.status === 'restored').length, 1);
  const detections = await page.evaluate(async () => window.__TAURI_INTERNALS__.invoke('list_alerts'));
  assert(Array.isArray(detections));
  await page.screenshot({ path: path.join(resultsDir, 'piko-native.png'), fullPage: true });
  const before = await health();
  desktop.kill();
  await delay(1200);
  const after = await health();
  assert(after.uptime_seconds >= before.uptime_seconds);
  assert.equal(service.exitCode, null);
  const result = { result: 'PASS', real_service_pid: service.pid, tests: ['native process resource metrics through IPC and UI', 'Defender channel explicitly included in native coverage', 'native persisted software history and partial coverage', 'native Sandbox profile and read-only single-file copy', 'native Sandbox deletion preserves original and existing sessions', 'native app grid and installer date metadata', 'bounded executable discovery without execution', 'structured native query filters exact instance', 'native syntax errors stay explicit', 'observed graph from stored process evidence', 'graph opens original JSON evidence', 'real process and TCP snapshot', 'stable process identity through IPC and storage', 'original JSON process evidence', 'activity page and exact executable handoff', 'native UI connected', 'important-events dashboard', 'heartbeats excluded from dashboard', 'in-app launch manual', 'real installed software inventory', 'real Windows firewall profile and rule snapshot', 'read-only network page does not prepare actions', 'real persisted events in technical logs', 'integrity query', 'Rust command roundtrip', 'Windows records', 'original XML displayed', 'bounded query rejected', 'action preview preserves original', 'explicit confirmation required', 'actual quarantine removes original', 'actual recovery restores identical bytes', 'durable action journal', 'detection API', 'UI termination leaves runtime active'], screenshot: path.join(resultsDir, 'piko-native.png'), dashboard_screenshot: path.join(resultsDir, 'piko-native-dashboard.png'), network_screenshot: path.join(resultsDir, 'piko-native-network.png'), network_preview_checked: networkPreviewAvailable, inventory_entries: applicationInventory.entries.length, firewall_active_profiles: firewallSnapshot.active_profiles, firewall_snapshot_complete: firewallSnapshot.complete, protection: after.protection_state };
  result.tests.push(...checks);
  if (networkPreviewAvailable) result.tests.push('native network preview and cancellation without Firewall changes');
  await writeFile(path.join(resultsDir, 'native-smoke.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  if (nativePage && !nativePage.isClosed()) {
    await nativePage.screenshot({ path: path.join(runDir, 'failure.png'), fullPage: true }).catch(() => {});
    await writeFile(path.join(runDir, 'failure.txt'), await nativePage.locator('body').innerText().catch(() => 'No page text'));
  }
  throw error;
} finally {
  if (browser) await Promise.race([browser.close().catch(() => {}), delay(5000, undefined, { ref: false })]);
  if (desktop && desktop.exitCode === null) desktop.kill();
  // Do not kill unrelated processes. Allow the owned runtime its scheduled flush.
  if (service.exitCode === null) {
    await Promise.race([new Promise(resolve => service.once('exit', resolve)), delay(47000, undefined, { ref: false })]);
  }
  if (service.exitCode === null) service.kill();
  await writeFile(path.join(runDir, 'service.log'), serviceLog);
  await writeFile(path.join(runDir, 'desktop.log'), desktopLog);
}

