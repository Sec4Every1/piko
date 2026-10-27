import { test, expect, type Page } from '@playwright/test';
async function setup(page: Page, mode = 'normal') {
  await page.addInitScript(({ mode }) => {
    const observation = { started_at_unix_ms: Date.now(), completed_at_unix_ms: Date.now() - (mode === 'stale' ? 90000 : 0), process_complete: mode !== 'partial', network_complete: true, udp_complete: true, udp_endpoints: [{pid:42,process_creation_filetime:mode==='reuse'?'133000000000000002':'133000000000000001',family:'ipv4',local_address:'127.0.0.1',local_port:5353}], warnings: [], processes: [{ instance_id: '12345678-1234-8234-9234-123456789012', pid: 42, parent_pid: 1, name: 'example.exe', executable: 'C:\\Example\\example.exe', creation_filetime: '133000000000000001', sid: null, session_id: 1, access_error: null }], connections: [{ pid: 42, process_creation_filetime: mode === 'reuse' ? '133000000000000002' : '133000000000000001', family: 'ipv4', local_address: '127.0.0.1', local_port: 1234, remote_address: '192.0.2.1', remote_port: 443, state: 5 }] };
    const processCalls:string[]=[];Object.defineProperty(window,'__PIKO_PROCESS_CALLS__',{value:processCalls});
    const target={pid:42,creation_filetime:'133000000000000001',executable:'C:\\Example\\example.exe',name:'example.exe',sid:'S-1-5-21-1-2-3-1000',session_id:1};
    Object.defineProperty(window, 'isTauri', { value: true });
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: { invoke: async (command: string) => {
      processCalls.push(command);
      if(command==='prepare_process_stop')return{id:'a711ffa0-269d-4b23-8c30-30b31cdb7922',target,expires_at:Math.floor(Date.now()/1000)+60};
      if(command==='discard_process_stop')return null;
      if(command==='confirm_process_stop')return{id:'a711ffa0-269d-4b23-8c30-30b31cdb7922',target,requested_at:Math.floor(Date.now()/1000),completed_at:Math.floor(Date.now()/1000),status:'uncertain',detail:'Test-only exit not confirmed'};
      if (command === 'get_health') return { product: 'piko', version: '0.2.0', protection_state: 'limited', runtime_mode: 'development_console', uptime_seconds: 1, stored_events: 1, queue_depth: 0, dropped_events: 0, sensors: [] };
      if (command === 'get_observations') { if (mode === 'error') throw Error('Source inaccessible'); return observation; }
      if (command === 'get_investigation') return { process_instance: observation.processes[0].instance_id, events_considered: 2, query_truncated: false, graph_truncated: false, references_truncated: false, nodes: [{ id: 'process', kind: 'process', label: 'example.exe' }, { id: 'node-1', kind: 'tcp_endpoint', label: '[192.0.2.1]:443 (state 5)' }], edges: [{ source: 'process', target: 'node-1', relation: 'observed_tcp', event_ids: ['12345678-1234-4234-9234-123456789012'], evidence_ids: [], observation_count: 2, first_observed: 100, last_observed: 200 }], observations: [{ event_id: '12345678-1234-4234-9234-123456789013', evidence_id: null, process_instance: observation.processes[0].instance_id, event_type: 'process.snapshot.observed', observed_at: 100, process_name: 'example.exe' }], observations_truncated: false, observations_available: true, observation_paging_available: true, next_observation_cursor: null };
      if (command === 'list_alerts' || command === 'list_events') return [];
      if (command === 'software_inventory') return { entries: [], complete: true, truncated: false, warnings: [] };
      if (command === 'network_snapshot') return { active_profiles: 2, local_policy_modify_state: 'ok', rules: [], complete: true, warnings: [], profiles: [1,2,4].map(id => ({ id, name: String(id), active: id === 2, firewall_enabled: true, block_all_inbound: false, excluded_interfaces: false })) };
      throw Error(`Unexpected mutation or command: ${command}`);
    } } });
  }, { mode });
  await page.goto('/');
  await page.locator('.sidebar nav').getByRole('button', { name: 'Attività applicazioni', exact: true }).click();
}
test('named process exposes connections and hands exact path to network preview', async ({ page }) => {
  await setup(page);
  await page.getByRole('button', { name: 'example.exe', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'example.exe', exact: true })).toBeVisible();
  await expect(page.getByText('[192.0.2.1]:443', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Gestisci accesso alla rete', exact: true }).click();
  await expect(page.getByLabel('Percorso del file .exe', { exact: true })).toHaveValue('C:\\Example\\example.exe');
  await expect(page.getByTestId('network-plan')).toHaveCount(0);
});
test('PID reuse never associates a connection from another process instance', async ({ page }) => {
  await setup(page, 'reuse'); await page.getByRole('button', { name: 'example.exe', exact: true }).click();
  await expect(page.getByText('[192.0.2.1]:443', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Nessuna connessione associabile', { exact: false })).toBeVisible();
});
test('stale and partial snapshots stay explicit; failed reads do not show a clean machine', async ({ page }) => {
  await setup(page, 'stale'); await page.getByRole('button', { name: 'example.exe', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Gestisci accesso alla rete', exact: true })).toBeDisabled();
  await expect(page.getByText('Fotografia obsoleta', { exact: false })).toBeVisible();
});
test('source failure is displayed as unavailable', async ({ page }) => {
  await setup(page, 'error'); await expect(page.getByRole('alert')).toContainText('Lettura non disponibile');
  await expect(page.getByText('Processi osservati', { exact: true })).toHaveCount(0);
});

test('relationships load on request and expose supporting observations', async ({ page }) => {
  await setup(page);
  await page.getByRole('button', { name: 'example.exe', exact: true }).click();
  await expect(page.locator('.relation-map')).toHaveCount(0);
  await page.getByRole('button', { name: 'Carica relazioni', exact: true }).click();
  await expect(page.locator('.relation-map')).toContainText('[192.0.2.1]:443 (state 5)');
  const timeline = page.locator('.timeline');
  await timeline.locator('summary').click();
  await expect(timeline).toContainText('Orari di osservazione, non di esecuzione');
  await expect(timeline.locator('li')).toHaveCount(1);
  await expect(timeline.locator('li strong')).toHaveText('example.exe');
  await timeline.getByLabel('Programma', { exact: true }).fill('absent-program.exe');
  await expect(timeline.locator('li')).toHaveCount(0);
  await expect(timeline).toContainText('Nessuna osservazione corrispondente nel campione.');
  await page.locator('.relation-map li button').click();
  await page.getByRole('button', { name: 'Osservazione 1', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Evento non più disponibile');
});

test('parent process relationship is named, historical and opens evidence', async ({ page }) => {
  await setup(page);
  await page.evaluate(() => {
    const bridge = (window as unknown as { __TAURI_INTERNALS__: { invoke: (command: string) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const previous = bridge.invoke;
    bridge.invoke = async command => command === 'get_investigation' ? {
      process_instance: '12345678-1234-8234-9234-123456789012', events_considered: 1,
      query_truncated: false, graph_truncated: false, references_truncated: false,
      nodes: [{ id: 'process', kind: 'process', label: 'example.exe' }, { id: 'node-1', kind: 'parent_process', label: 'launcher.exe' }],
      edges: [{ source: 'process', target: 'node-1', relation: 'observed_parent', event_ids: ['12345678-1234-4234-9234-123456789012'], evidence_ids: [], observation_count: 1, first_observed: 100, last_observed: 200 }],
      observations: [{ event_id: '12345678-1234-4234-9234-123456789013', evidence_id: null, process_instance: '12345678-1234-8234-9234-123456789012', event_type: 'process.snapshot.observed', observed_at: 100, process_name: 'example.exe' }],
      observations_truncated: false, observations_available: true, observation_paging_available: true, next_observation_cursor: null,
    } : previous(command);
  });
  await page.getByRole('button', { name: 'example.exe', exact: true }).click();
  await page.getByRole('button', { name: 'Carica relazioni', exact: true }).click();
  await expect(page.locator('.relation-map')).toContainText('Processo padre osservato');
  await expect(page.locator('.relation-map')).toContainText('launcher.exe');
  await expect(page.getByText('Non descrivono necessariamente lo stato attuale.', { exact: false })).toBeVisible();
  await page.locator('.relation-map li button').click();
  await page.getByRole('button', { name: 'Osservazione 1', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Evento non più disponibile');
});

test('process response requires confirmation and keeps uncertain outcome explicit',async({page})=>{await setup(page);await page.getByRole('button',{name:'example.exe',exact:true}).click();await page.getByRole('button',{name:'Prepara arresto di example.exe',exact:true}).click();await expect(page.getByRole('button',{name:'Arresta processo',exact:true})).toBeDisabled();expect(await page.evaluate(()=>(window as unknown as {__PIKO_PROCESS_CALLS__:string[]}).__PIKO_PROCESS_CALLS__.filter(c=>c==='confirm_process_stop').length)).toBe(0);await page.getByLabel('Confermo l’arresto forzato di questa istanza.',{exact:true}).check();await page.getByRole('button',{name:'Arresta processo',exact:true}).click();await expect(page.getByText('Esito da verificare:',{exact:false})).toBeVisible();await expect(page.getByText('Windows ha confermato la fine',{exact:false})).toHaveCount(0);});

test('UDP stays a local bind and never exposes a fabricated destination',async({page})=>{await setup(page);await page.getByRole('button',{name:'example.exe',exact:true}).click();await page.locator('summary').filter({hasText:'Porte locali UDP'}).click();const panel=page.locator('.udp-detail');await expect(panel).toContainText('[127.0.0.1]:5353');await expect(panel).toContainText('Destinazioni e contenuto non disponibili.');await expect(panel).not.toContainText('192.0.2.1');});
