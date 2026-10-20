<script lang="ts">
  import { onMount, onDestroy, tick } from 'svelte';
  import type { Language } from './i18n';
  import { sandboxStatus, sandboxSessions, prepareSandbox, createSandbox, discardSandbox, launchSandbox, removeSandbox, type SandboxStatus, type SandboxPlan, type SandboxSession } from './sandbox';
  let { language, initialPath = '' }: { language: Language; initialPath?: string } = $props();
  const it = $derived(language === 'it');
  let open = $state(false), path = $state(''), status = $state<SandboxStatus | null>(null), sessions = $state<SandboxSession[]>([]);
  let plan = $state<SandboxPlan | null>(null), confirmed = $state(false), busy = $state(false), error = $state(''), message = $state(''), removal = $state(''), now = $state(Date.now());
  let alive = true;
  const expired = $derived(plan !== null && plan.expires_at * 1000 <= now);
  const name = (path: string) => path.split('\\').pop() ?? path;
  async function refresh() {
    try { const [s, entries] = await Promise.all([sandboxStatus(), sandboxSessions()]); if (alive) { status = s; sessions = entries; } }
    catch(e) { if (alive) { status = null; error = String(e); } }
  }
  async function discard() { const old = plan; plan = null; confirmed = false; if (old) await discardSandbox(old.id).catch(() => {}); }
  async function prepare() {
    busy = true; error = ''; message = ''; await discard();
    try { const result = await prepareSandbox(path.trim()); if (alive) { plan = result; now = Date.now(); } else await discardSandbox(result.id); }
    catch(e) { error = String(e); } finally { busy = false; }
  }
  async function create() {
    if (!plan || !confirmed || expired || busy) return;
    const submitted = plan; plan = null; confirmed = false; busy = true; error = '';
    try { await createSandbox(submitted.id); message = it ? 'Profilo e copia creati. Nessun programma è stato avviato.' : 'Profile and copy created. No program was started.'; await refresh(); }
    catch(e) { error = String(e); } finally { busy = false; }
  }
  async function launch(id: string) {
    busy = true; error = ''; message = '';
    try { await launchSandbox(id); message = it ? 'Avvio richiesto a Windows. Verifica che compaia Windows Sandbox: piko non certifica l’avvio né l’isolamento. Dentro la sandbox apri C:\\PikoInput, copia payload.exe sul desktop virtuale e avvialo solo lì.' : 'Launch requested from Windows. Verify the Windows Sandbox window: piko does not attest startup or isolation. Inside the sandbox, open C:\\PikoInput, copy payload.exe to the virtual desktop and run it only there.'; }
    catch(e) { error = String(e); } finally { busy = false; }
  }
  async function remove(id: string) {
    busy = true; error = ''; message = '';
    try { await removeSandbox(id); removal = ''; await refresh(); }
    catch(e) { error = String(e); } finally { busy = false; }
  }
  onMount(() => { path = initialPath; open = !!initialPath; void refresh(); const timer = setInterval(() => now = Date.now(), 1000); if (initialPath) void tick().then(() => document.getElementById('sandbox-path')?.focus()); return () => clearInterval(timer); });
  onDestroy(() => { alive = false; void discard(); });
</script>
<details class="sandbox-panel" bind:open>
  <summary>{it ? 'Prova isolata · Windows Sandbox' : 'Isolated trial · Windows Sandbox'}</summary>
  <p>{it ? 'Per installer e programmi portabili: prepara una copia separata senza esporre le cartelle personali. Non modifica i permessi del programma già installato sul PC.' : 'For installers and portable apps: prepare a separate copy without sharing personal folders. This does not change permissions of the app already installed on this PC.'}</p>
  <div class="restrictions"><span>{it ? 'Rete disattivata' : 'Network disabled'}</span><span>{it ? 'Appunti e periferiche non condivisi' : 'Clipboard and devices not shared'}</span><span>{it ? 'Un solo file in sola lettura' : 'One read-only file'}</span></div>
  {#if status}<p class="availability">{status.launcher_available ? (it ? 'Launcher Windows presente. Virtualizzazione, feature e policy vengono verificate da Windows all’avvio.' : 'Windows launcher present. Virtualization, feature and policy requirements are checked by Windows at startup.') : (it ? 'Launcher Windows Sandbox non trovato. Puoi preparare il profilo; per aprirlo occorre abilitare Windows Sandbox su un’edizione compatibile.' : 'Windows Sandbox launcher not found. You can prepare a profile; opening it requires Windows Sandbox on a compatible edition.')}</p>{/if}
  <button class="text-button" disabled={busy} onclick={() => { error = ''; void refresh(); }}>{it ? 'Aggiorna stato Sandbox' : 'Refresh Sandbox status'}</button>
  <form onsubmit={event => { event.preventDefault(); void prepare(); }}><label for="sandbox-path">{it ? 'Eseguibile da provare in isolamento' : 'Executable for isolated trial'}</label><div class="path-row"><input id="sandbox-path" bind:value={path} oninput={() => { void discard(); message = ''; }} disabled={busy} maxlength="2048" placeholder="C:\Downloads\setup.exe" /><button class="button primary contain-action" disabled={busy || !path.trim() || !status || sessions.length >= 8}>{it ? 'Prepara prova isolata' : 'Prepare isolated trial'}</button></div></form>
  {#if plan}<section class="preview" aria-label={it ? 'Anteprima prova isolata' : 'Isolated trial preview'}><h3>{name(plan.executable)}</h3><code>{plan.executable}</code><p>{it ? 'Verrà copiato soltanto questo eseguibile. DLL, dati, licenze e dipendenze installate non sono inclusi: alcuni programmi non funzioneranno.' : 'Only this executable will be copied. Installed DLLs, data, licenses and dependencies are not included: some apps will not work.'}</p><details><summary>SHA-256</summary><code>{plan.sha256}</code></details><label class="confirmation"><input type="checkbox" bind:checked={confirmed} disabled={busy || expired} />{it ? 'Confermo la copia del file e il profilo senza rete.' : 'I confirm copying the file and creating the offline profile.'}</label>{#if expired}<p class="warning">{it ? 'Anteprima scaduta. Preparala di nuovo.' : 'Preview expired. Prepare it again.'}</p>{/if}<div class="buttons"><button class="button contain-action" onclick={create} disabled={busy || !confirmed || expired}>{it ? 'Crea profilo isolato' : 'Create isolated profile'}</button><button class="button secondary" onclick={discard} disabled={busy}>{it ? 'Annulla anteprima' : 'Cancel preview'}</button></div></section>{/if}
  {#if error}<p class="warning" role="alert">{error}</p>{/if}{#if message}<p class="message" role="status">{message}</p>{/if}
  {#if sessions.length}<h3>{it ? 'Profili salvati' : 'Saved profiles'} · {sessions.length}/8</h3><div class="sessions">{#each sessions as session (session.id)}<article><strong>{name(session.executable)}</strong><small>{new Date(session.created_at * 1000).toLocaleString(language)}</small><details><summary>{it ? 'Percorsi e impronta' : 'Paths and fingerprint'}</summary><code>{session.executable}</code><code>{session.configuration}</code><code>{session.sha256}</code></details><div class="buttons"><button class="button primary" onclick={() => launch(session.id)} disabled={busy || !status?.launcher_available}>{it ? 'Apri Windows Sandbox' : 'Open Windows Sandbox'}</button><button class="text-button" onclick={() => removal = session.id} disabled={busy}>{it ? 'Elimina copia e profilo' : 'Delete copy and profile'}</button></div>{#if removal === session.id}<div class="delete-confirm"><p>{it ? 'Chiudi prima la sandbox. Elimina la copia di piko e il profilo; il file originale resta sul PC.' : 'Close the sandbox first. Deletes the piko copy and profile; the original file remains on this PC.'}</p><button class="button secondary" disabled={busy} onclick={() => remove(session.id)}>{it ? 'Conferma eliminazione copia' : 'Confirm copy deletion'}</button><button class="text-button" onclick={() => removal = ''}>{it ? 'Annulla' : 'Cancel'}</button></div>{/if}</article>{/each}</div>{/if}
  <details class="limits"><summary>{it ? 'Cosa limita questa modalità' : 'Limits of this mode'}</summary><p>{it ? 'Nessun eseguibile parte automaticamente. In Windows Sandbox trovi la copia in C:\\PikoInput\\payload.exe. La sessione virtuale si elimina alla chiusura; la copia di piko resta finché la elimini qui. Massimo 8 profili da 256 MiB ciascuno. Non inserire credenziali o dati sensibili nella prova. Il software può scrivere nel Windows virtuale; non è un blocco dei file di sistema all’interno della sandbox, né un congelamento della versione sul PC. Senza rete non può scaricare aggiornamenti, ma può usare file già inclusi. piko non raccoglie la telemetria interna della sandbox.' : 'No executable starts automatically. The copy is at C:\\PikoInput\\payload.exe inside Windows Sandbox. The virtual session is discarded on close; the piko copy remains until deleted here. Up to 8 profiles, each at most 256 MiB. Do not enter credentials or sensitive data. Apps can write within virtual Windows; this is neither a guest system-file block nor a host version freeze. Without networking they cannot download updates but may use bundled files. piko does not collect guest telemetry.'}</p></details>
</details>
<style>
  .sandbox-panel { padding: 24px; background: var(--surface); border: 1px solid var(--border); border-radius: 14px; min-width: 0; }
  summary { cursor: pointer; font-size: .88rem; } p { color: var(--muted); font-size: .81rem; margin: 13px 0; } .restrictions { display: flex; gap: 8px; flex-wrap: wrap; } .restrictions span { color: var(--selection); background: var(--selection-soft); padding: 6px 9px; border-radius: 6px; font-size: .72rem; }
  label { display: block; font-size: .8rem; margin: 16px 0 8px; } .path-row, .buttons { display: flex; flex-wrap: wrap; gap: 10px; } input:not([type=checkbox]) { flex: 1; min-width: 140px; background: var(--surface); color: var(--text); border: 1px solid var(--border-strong); border-radius: 8px; padding: 10px; } .button { white-space: normal; }
  .preview { margin: 18px 0; padding: 18px; background: var(--contain-soft); border: 1px solid var(--contain-border); border-radius: 10px; } code { display: block; margin: 8px 0; overflow-wrap: anywhere; } .confirmation { display: flex; align-items: start; gap: 10px; } .warning { background: var(--warning-surface); color: var(--warning); padding: 12px; border-radius: 8px; } .message { background: var(--accent-soft); color: var(--accent-ink); padding: 12px; border-radius: 8px; }
  .sessions { max-height: 440px; overflow: auto; margin-top: 12px; } article { padding: 16px 0; border-top: 1px solid var(--border); } article small { display: block; color: var(--muted); margin: 7px 0; } article details { margin: 12px 0; } .delete-confirm { padding: 10px; background: var(--warning-surface); } .limits { margin-top: 18px; }
</style>
