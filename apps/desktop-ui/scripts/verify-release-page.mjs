// Read-only proof that a release loads embedded assets and reaches the SCM service.
import { chromium } from 'playwright-core';
import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
const root = fileURLToPath(new URL('../../../', import.meta.url));
const exe = process.argv[2] ?? path.join(root, 'apps/desktop-ui/src-tauri/target/release/piko-desktop.exe');
const run = path.join(root, '.runtime', `release-page-${Date.now()}`);
await mkdir(run, { recursive: true });
const port = await new Promise(resolve => {
  const server = net.createServer();
  server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(() => resolve(port)); });
});
const child = spawn(exe, [], { cwd: root, windowsHide: true, stdio: 'ignore', env: {
  ...process.env, WEBVIEW2_USER_DATA_FOLDER: path.join(run, 'webview'),
  WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port} --remote-debugging-address=127.0.0.1`,
} });
let browser;
try {
  const deadline = Date.now() + 25000;
  while (true) {
    if (child.exitCode !== null) throw new Error('Desktop exited before page verification');
    try { if ((await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(700) })).ok) break; } catch {}
    if (Date.now() > deadline) throw new Error('WebView2 unavailable');
    await delay(150);
  }
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
  let page;
  while (!(page = browser.contexts().flatMap(c => c.pages()).find(p => p.url().includes('tauri.localhost')))) {
    if (Date.now() > deadline) throw new Error('Embedded page was not loaded; development URL is forbidden in release');
    await delay(150);
  }
  await page.getByText('Runtime collegato', { exact: true }).waitFor({ timeout: 15000 });
  const health = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('get_health'));
  assert.equal(health.runtime_mode, 'windows_service');
  let identity;
  if (process.argv.includes('--identity')) {
    identity = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('authentication_activity',{filter:{before_position:null,kind:null,limit:5}}));
    assert(identity.records.length <= 5);
    assert(identity.records.length > 0, 'Installed archive has no identity evidence for this qualification');
    assert(identity.records.some(record => record.context.evidence_status === 'verified'));
    await page.locator('.sidebar nav').getByRole('button',{name:'Attività applicazioni',exact:true}).click();
    const panel=page.locator('.identity-activity');
    await panel.locator('summary').first().click();
    await panel.locator('.content>ul>li').first().waitFor();
    assert((await panel.locator('.content>ul>li').count())<=5);
    await panel.locator('.record-details>summary').first().click();
    await panel.locator('.record-details[open]').getByRole('button',{name:'Apri evento e dati grezzi',exact:true}).click();
    await page.getByRole('dialog').getByRole('button',{name:'Leggi evidenza originale',exact:true}).click();
    await page.locator('.source-evidence').waitFor();
    assert((await page.locator('.source-evidence').innerText()).includes('Microsoft-Windows-Security-Auditing'));
    await page.getByRole('dialog').getByRole('button',{name:'Chiudi',exact:true}).click();
    await panel.getByLabel('Categoria accessi',{exact:true}).selectOption('special_privileges');
    await panel.getByRole('button',{name:'Aggiorna',exact:true}).waitFor({state:'visible'});
    await page.waitForFunction(()=>!document.querySelector('.identity-activity select')?.disabled);
    assert(!(await panel.getByRole('alert').count()));
    await page.screenshot({path:path.join(run,'identity-activity.png')});
  }
  if (health.archive?.retention_months) {
    await page.locator('.sidebar nav').getByRole('button',{name:'Impostazioni',exact:true}).click();
    await page.getByRole('heading',{name:'Capacità archivio',exact:true}).waitFor();
    await page.getByText(`Conservazione: ${health.archive.retention_months} mesi.`,{exact:false}).waitFor();
    assert(await page.getByText('Spazio usato',{exact:true}).isVisible());
  }
  const report = { result: 'PASS', exe, url: page.url(), runtime_mode: health.runtime_mode, stored_events: health.stored_events, archive:health.archive,identity:identity?{records:identity.records.length,verified:identity.records.filter(r=>r.context.evidence_status==='verified').length,has_older:identity.next_before!==null}:undefined };
  await page.screenshot({ path: path.join(run, 'dashboard.png') });
  await writeFile(path.join(root, '.runtime', 'release-page-verification.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
} finally {
  await browser?.close();
  child.kill();
}
