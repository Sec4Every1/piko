import { expect, test, type Page } from '@playwright/test';
async function setup(page: Page, available = true, expired = false) {
  await page.addInitScript(({available, expired}) => {
    const calls: string[] = []; const sessions: Record<string, unknown>[] = [];
    Object.assign(window, { sandboxCalls: calls });
    Object.defineProperty(window, 'isTauri', { value: true });
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: { invoke: async (cmd: string) => {
      calls.push(cmd);
      const plan = { id: 'bc1e69ce-8b01-4d27-955a-6078d3d65ea3', executable: 'C:\\Example\\setup.exe', sha256: 'a'.repeat(64), expires_at: Math.floor(Date.now()/1000) + (expired ? -1 : 300) };
      if (cmd === 'get_health') return { product:'piko',version:'0.2.0',protection_state:'degraded',runtime_mode:'development_console',uptime_seconds:1,stored_events:0,queue_depth:0,dropped_events:0,sensors:[] };
      if (cmd === 'list_alerts') return [];
      if (cmd === 'response_status') return { roots:[],max_file_bytes:100,vault_budget_bytes:1000,actions:[] };
      if (cmd === 'software_inventory') return { entries:[],complete:true,truncated:false,warnings:[] };
      if (cmd === 'network_snapshot') return {active_profiles:0,profiles:[],rules:[],complete:false,warnings:[],local_policy_modify_state:'unknown'};
      if (cmd === 'sandbox_status') return { launcher_available:available,max_sessions:8 };
      if (cmd === 'sandbox_sessions') return [...sessions];
      if (cmd === 'prepare_sandbox') return plan;
      if (cmd === 'discard_sandbox') return null;
      if (cmd === 'create_sandbox') { const session = {id:plan.id,executable:plan.executable,sha256:plan.sha256,created_at:Math.floor(Date.now()/1000),configuration:'C:\\Piko\\piko.wsb'}; sessions.push(session); return session; }
      if (cmd === 'launch_sandbox') return null;
      if (cmd === 'remove_sandbox') { sessions.length = 0; return null; }
      throw new Error('Unexpected command '+cmd);
    } } });
  }, { available, expired });
  await page.goto('/'); await page.locator('.sidebar nav').getByRole('button',{name:'Permessi app',exact:true}).click();
  await page.getByText('Prova isolata · Windows Sandbox',{exact:true}).click();
  await page.getByLabel('Eseguibile da provare in isolamento',{exact:true}).fill('C:\\Example\\setup.exe');
  await page.getByRole('button',{name:'Prepara prova isolata',exact:true}).click();
}
const calls = (page: Page) => page.evaluate(() => (window as unknown as {sandboxCalls:string[]}).sandboxCalls);
test('isolated trial requires explicit confirmation, persists a profile, and never auto launches', async ({page}) => {
  await setup(page); await expect(page.getByRole('button',{name:'Crea profilo isolato',exact:true})).toBeDisabled();
  expect(await calls(page)).not.toContain('create_sandbox'); expect(await calls(page)).not.toContain('launch_sandbox');
  await page.getByRole('checkbox',{name:'Confermo la copia del file e il profilo senza rete.',exact:true}).check();
  await page.getByRole('button',{name:'Crea profilo isolato',exact:true}).click();
  await expect(page.getByText('Profilo e copia creati. Nessun programma è stato avviato.',{exact:true})).toBeVisible();
  expect(await calls(page)).not.toContain('launch_sandbox');
  await page.getByRole('button',{name:'Apri Windows Sandbox',exact:true}).click();
  await expect(page.getByRole('status').filter({hasText:'Avvio richiesto a Windows'})).toBeVisible();
  await page.getByRole('button',{name:'Elimina copia e profilo',exact:true}).click();
  expect(await calls(page)).not.toContain('remove_sandbox');
  await page.getByRole('button',{name:'Conferma eliminazione copia',exact:true}).click();
  await expect(page.getByRole('button',{name:'Apri Windows Sandbox',exact:true})).toHaveCount(0);
});
test('missing launcher stays explicit and cannot launch; mobile layout fits', async ({page}) => {
  await setup(page,false); await page.setViewportSize({width:390,height:844});
  await expect(page.getByText(/Launcher Windows Sandbox non trovato/)).toBeVisible();
  await page.getByRole('checkbox',{name:'Confermo la copia del file e il profilo senza rete.',exact:true}).check();
  await page.getByRole('button',{name:'Crea profilo isolato',exact:true}).click();
  await expect(page.getByRole('button',{name:'Apri Windows Sandbox',exact:true})).toBeDisabled();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({path:'test-results/piko-sandbox-mobile.png',fullPage:true});
});
test('expired and edited previews cannot be reused', async ({page}) => {
  await setup(page,true,true); await expect(page.getByText('Anteprima scaduta. Preparala di nuovo.',{exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'Crea profilo isolato',exact:true})).toBeDisabled();
  await page.getByLabel('Eseguibile da provare in isolamento',{exact:true}).fill('C:\\Other.exe');
  await expect(page.getByRole('region',{name:'Anteprima prova isolata',exact:true})).toHaveCount(0);
  expect(await calls(page)).toContain('discard_sandbox'); expect(await calls(page)).not.toContain('create_sandbox');
});
