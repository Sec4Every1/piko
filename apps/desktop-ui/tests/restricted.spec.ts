import { test, expect, type Page } from '@playwright/test';

// Browser fixtures only. These commands never launch a native process or change ACLs.
async function bridge(page: Page, uncertain = false, expired = false) {
  await page.addInitScript(({ uncertain, expired }) => {
    const calls: {command: string; args?: Record<string, unknown>}[] = [];
    const plans = new Map<string, Record<string, unknown>>();
    let sessions: Record<string, unknown>[] = [], sequence = 0;
    const fixture = { calls, mismatchPrepare:false, mismatchLaunch:false };
    (window as unknown as { __PIKO_RESTRICTED_TEST__: {calls: typeof calls} }).__PIKO_RESTRICTED_TEST__ = fixture;
    const apps = ['Alpha','Beta'].map((name, i) => ({ id: name.toLowerCase(), display_name: name, publisher:'Test fixture', version:'1.0', install_location:`C:\\Apps\\${name}`, install_date:`2026100${i + 1}`, display_icon:null, scope:'user', registry_view:'64', source:'windows_uninstall_registry', uninstall_key:name }));
    const policy = {network_capabilities:0,max_processes:1,memory_limit_bytes:536870912,original_unchanged:true,staged_read_only:true,stop_on_ui_exit:true};
    Object.defineProperty(window, 'isTauri', {value:true});
    Object.defineProperty(window, '__TAURI_INTERNALS__', {value:{invoke:async (command: string,args?: Record<string,unknown>) => {
      calls.push({command,args});
      if (command === 'get_health') return {product:'piko',version:'0.2.0',protection_state:'degraded',runtime_mode:'development_console',uptime_seconds:1,stored_events:0,queue_depth:0,dropped_events:0,sensors:[]};
      if (['list_alerts','list_alert_reviews','list_events'].includes(command)) return [];
      if (command === 'software_inventory') return {entries:apps,complete:true,truncated:false,warnings:[]};
      if (command === 'application_executables') return {app_id:args?.appId,paths:[`C:\\Apps\\${apps.find(a => a.id===args?.appId)?.display_name}\\app.exe`],complete:true,warnings:[]};
      if (command === 'network_snapshot') return {active_profiles:2,local_policy_modify_state:'ok',rules:[],complete:true,warnings:[],profiles:[1,2,4].map(id=>({id,name:({1:'domain',2:'private',4:'public'} as Record<number,string>)[id],active:id===2,firewall_enabled:true,block_all_inbound:false,excluded_interfaces:false}))};
      if (command === 'sandbox_status') return {launcher_available:false,max_sessions:8};
      if (command === 'sandbox_sessions') return [];
      if (command === 'restricted_sessions') return sessions;
      if (command === 'prepare_restricted') {const id=`00000000-0000-4000-8000-${String(++sequence).padStart(12,'0')}`;const value={id,executable:args?.path,sha256:'a'.repeat(64),expires_at:Math.floor(Date.now()/1000)+(expired?-1:300),policy:{...policy,network_access:fixture.mismatchPrepare ? (args?.networkAccess === 'internet_client' ? 'none' : 'internet_client') : (args?.networkAccess ?? 'none'),network_capabilities:fixture.mismatchPrepare ? (args?.networkAccess === 'internet_client' ? 0 : 1) : (args?.networkAccess === 'internet_client' ? 1 : 0)}};plans.set(id,value);return value;}
      if (command === 'discard_restricted') {plans.delete(String(args?.planId));return null;}
      if (command === 'launch_restricted') {const p=plans.get(String(args?.planId));if(!p)throw Error('Fixture single-use plan absent');plans.delete(String(args?.planId));const value={...p,pid:123,created_at:Math.floor(Date.now()/1000),running:true,data_directory:'C:\\TestFixtureProfile'};sessions.push(value);if(uncertain)throw Error('Fixture transport disconnected after request');return fixture.mismatchLaunch ? {...value,policy:{...policy,network_access:'none',network_capabilities:0}} : value;}
      if (command === 'stop_restricted') {sessions=sessions.filter(s=>s.id!==args?.sessionId);return null;}
      throw Error(`Unexpected fixture command ${command}`);
    }}});
  }, {uncertain,expired});
}
async function open(page: Page) {await page.goto('/');await page.locator('.sidebar nav').getByRole('button',{name:'Permessi app',exact:true}).click();await page.locator('.restricted-panel > summary').click();}
async function calls(page: Page, command: string) {return page.evaluate(command => (window as unknown as {__PIKO_RESTRICTED_TEST__:{calls:{command:string;args?:Record<string,unknown>}[]}}).__PIKO_RESTRICTED_TEST__.calls.filter(c=>c.command===command),command);}

test('restricted copy requires explicit consent, exposes scope and stops only selected trial',async({page})=>{
  await bridge(page);await open(page);
  const panel=page.locator('.restricted-panel');
  await panel.getByLabel('Eseguibile da provare',{exact:true}).fill('C:\\Fixture\\sample.exe');
  await panel.getByRole('button',{name:'Prepara avvio limitato',exact:true}).click();
  await expect(panel.getByRole('button',{name:'Avvia copia limitata',exact:true})).toBeDisabled();
  expect(await calls(page,'launch_restricted')).toHaveLength(0);
  await panel.getByRole('checkbox',{name:'Confermo l’esecuzione di questa copia con i limiti indicati.',exact:true}).check();
  await panel.getByRole('button',{name:'Avvia copia limitata',exact:true}).click();
  await expect(panel.getByText('In esecuzione · PID 123',{exact:true})).toBeVisible();
  await expect(panel.getByRole('status')).toContainText('L’app originale conserva i suoi permessi');
  await panel.locator('.scope > summary').click();
  await expect(panel.getByText(/L’originale e gli aggiornamenti dell’app installata non sono congelati/)).toBeVisible();
  await panel.getByRole('button',{name:'Termina e rimuovi prova',exact:true}).click();
  await expect(panel.getByRole('status')).toHaveText('Prova terminata; copia e profilo rimossi.');
  expect(await calls(page,'launch_restricted')).toHaveLength(1);
  expect(await calls(page,'stop_restricted')).toHaveLength(1);
  await expect(panel.locator('article')).toHaveCount(0);
});

test('network permission is denied by default and edits invalidate the preview and consent',async({page})=>{
  await bridge(page);await open(page);
  const panel=page.locator('.restricted-panel');
  await panel.getByLabel('Eseguibile da provare',{exact:true}).fill('C:\\Fixture\\sample.exe');
  const network=panel.getByLabel('Accesso rete della copia',{exact:true});
  await expect(network).toHaveValue('none');
  await network.selectOption('internet_client');
  await panel.getByRole('button',{name:'Prepara avvio limitato',exact:true}).click();
  await expect(panel.getByRole('region',{name:'Anteprima avvio limitato'})).toContainText('potrà tentare connessioni di rete');
  await panel.getByRole('checkbox').check();
  await network.selectOption('none');
  await expect(panel.getByRole('region',{name:'Anteprima avvio limitato'})).toHaveCount(0);
  expect(await calls(page,'discard_restricted')).toHaveLength(1);
  await panel.getByRole('button',{name:'Prepara avvio limitato',exact:true}).click();
  await expect(panel.getByRole('region',{name:'Anteprima avvio limitato'})).toContainText('Nessuna capability di rete concessa');
  await expect(panel.getByRole('button',{name:'Avvia copia limitata',exact:true})).toBeDisabled();
  expect(await calls(page,'launch_restricted')).toHaveLength(0);
});

test('internet permission is frozen per trial and existing cleanup remains available',async({page})=>{
  await bridge(page);await open(page);
  const panel=page.locator('.restricted-panel');
  await panel.getByLabel('Eseguibile da provare',{exact:true}).fill('C:\\Fixture\\sample.exe');
  await panel.getByLabel('Accesso rete della copia',{exact:true}).selectOption('internet_client');
  await panel.getByRole('button',{name:'Prepara avvio limitato',exact:true}).click();
  await panel.getByRole('checkbox').check();
  await panel.getByRole('button',{name:'Avvia copia limitata',exact:true}).click();
  await expect(panel.locator('article')).toContainText('Rete: internetClient');
  await panel.getByLabel('Accesso rete della copia',{exact:true}).selectOption('none');
  await expect(panel.locator('article')).toContainText('Rete: internetClient');
  expect((await calls(page,'prepare_restricted'))[0].args?.networkAccess).toBe('internet_client');
  await panel.getByRole('button',{name:'Termina e rimuovi prova',exact:true}).click();
  await expect(panel.locator('article')).toHaveCount(0);
});

test('unexpected network policy in a preview is rejected without execution',async({page})=>{
  await bridge(page);await open(page);
  await page.evaluate(()=>{ (window as unknown as {__PIKO_RESTRICTED_TEST__:{mismatchPrepare:boolean}}).__PIKO_RESTRICTED_TEST__.mismatchPrepare=true; });
  const panel=page.locator('.restricted-panel');
  await panel.getByLabel('Eseguibile da provare',{exact:true}).fill('C:\\Fixture\\sample.exe');
  await panel.getByRole('button',{name:'Prepara avvio limitato',exact:true}).click();
  await expect(panel.getByRole('alert')).toContainText('Invalid restricted trial response');
  await expect(panel.getByRole('region',{name:'Anteprima avvio limitato'})).toHaveCount(0);
  expect(await calls(page,'launch_restricted')).toHaveLength(0);
  expect(await calls(page,'discard_restricted')).toHaveLength(1);
});

test('unexpected launch policy stays uncertain and offers cleanup of the owned trial',async({page})=>{
  await bridge(page);await open(page);
  const panel=page.locator('.restricted-panel');
  await panel.getByLabel('Eseguibile da provare',{exact:true}).fill('C:\\Fixture\\sample.exe');
  await panel.getByLabel('Accesso rete della copia',{exact:true}).selectOption('internet_client');
  await panel.getByRole('button',{name:'Prepara avvio limitato',exact:true}).click();
  await page.evaluate(()=>{ (window as unknown as {__PIKO_RESTRICTED_TEST__:{mismatchLaunch:boolean}}).__PIKO_RESTRICTED_TEST__.mismatchLaunch=true; });
  await panel.getByRole('checkbox').check();
  await panel.getByRole('button',{name:'Avvia copia limitata',exact:true}).click();
  await expect(panel.getByRole('alert')).toContainText('Esito dell’avvio non confermato');
  await expect(panel.getByRole('status')).toHaveCount(0);
  await panel.getByRole('button',{name:'Termina e rimuovi prova',exact:true}).click();
  await expect(panel.locator('article')).toHaveCount(0);
});

test('uncertain launch refreshes owned trials and offers stop without claiming success',async({page})=>{
  await bridge(page,true);await open(page);
  const panel=page.locator('.restricted-panel');
  await panel.getByLabel('Eseguibile da provare',{exact:true}).fill('C:\\Fixture\\sample.exe');
  await panel.getByRole('button',{name:'Prepara avvio limitato',exact:true}).click();
  await panel.getByRole('checkbox').check();
  await panel.getByRole('button',{name:'Avvia copia limitata',exact:true}).click();
  await expect(panel.getByRole('alert')).toContainText('Esito dell’avvio non confermato');
  await expect(panel.getByRole('status')).toHaveCount(0);
  await expect(panel.getByText('In esecuzione · PID 123',{exact:true})).toBeVisible();
  await panel.getByRole('button',{name:'Termina e rimuovi prova',exact:true}).click();
  await expect(panel.locator('article')).toHaveCount(0);
});

test('expired plan cannot execute and selecting another grid app replaces the pending path',async({page})=>{
  await bridge(page,false,true);await open(page);
  const panel=page.locator('.restricted-panel');
  await panel.getByLabel('Eseguibile da provare',{exact:true}).fill('C:\\Fixture\\sample.exe');
  await panel.getByRole('button',{name:'Prepara avvio limitato',exact:true}).click();
  await expect(panel.getByRole('button',{name:'Avvia copia limitata',exact:true})).toBeDisabled();
  await expect(panel.getByRole('checkbox')).toBeDisabled();
  const grid=page.getByRole('region',{name:'Selezione applicazioni',exact:true});
  await grid.getByRole('checkbox',{name:'Seleziona Alpha',exact:true}).check();
  await grid.locator('.selection > details > summary').click();
  await grid.getByRole('button',{name:'Avvio limitato · AppContainer',exact:true}).click();
  await expect(panel.getByLabel('Eseguibile da provare',{exact:true})).toHaveValue('C:\\Apps\\Alpha\\app.exe');
  await panel.getByRole('button',{name:'Prepara avvio limitato',exact:true}).click();
  await grid.getByRole('checkbox',{name:'Seleziona Beta',exact:true}).check();
  const beta=grid.locator('.selection > details').filter({has:page.locator('summary').filter({hasText:'Beta ·'})});
  await beta.locator('summary').click();
  await beta.getByRole('button',{name:'Avvio limitato · AppContainer',exact:true}).click();
  await expect(panel.getByLabel('Eseguibile da provare',{exact:true})).toHaveValue('C:\\Apps\\Beta\\app.exe');
  await expect(panel.getByRole('region',{name:'Anteprima avvio limitato'})).toHaveCount(0);
  expect(await calls(page,'discard_restricted')).toHaveLength(2);
  expect(await calls(page,'launch_restricted')).toHaveLength(0);
});
