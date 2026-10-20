<script lang="ts">
  import SignatureCheck from './SignatureCheck.svelte';
  import { onDestroy, tick } from 'svelte';
  import type { Language } from './i18n';
  import { applicationExecutables, prepareNetworkAction, executeNetworkAction, discardNetworkPlans, directionLabel, type InstalledSoftware, type InventorySnapshot, type ExecutableCandidates, type NetworkPlan, type NetworkDirection } from './appControl';
  import { installDate, sortApps } from './appGrid';
  let { language, inventory, inventoryError, canBlock, busy = $bindable(false), loading, focusApplicationId = '', focusRequest = 0, prepareFocusedApplication = false, onRefresh, onManual, onSandbox, onRestricted }: { language: Language; inventory: InventorySnapshot | null; inventoryError: string; canBlock: boolean; busy?: boolean; loading: boolean; focusApplicationId?: string; focusRequest?: number; prepareFocusedApplication?: boolean; onRefresh: () => Promise<void>; onManual: (app: InstalledSoftware) => void; onSandbox: (path: string) => void; onRestricted: (path: string) => void } = $props();
  const it = $derived(language === 'it');
  let search = $state(''), order = $state('newest'), page = $state(0), ids = $state<string[]>([]);
  let found = $state<Record<string, ExecutableCandidates>>({}), errors = $state<Record<string, string>>({}), resolving = $state<string[]>([]), excluded = $state<string[]>([]);
  let plans = $state<NetworkPlan[]>([]), confirmation = $state(false), error = $state(''), outcomes = $state<{ path: string; status: string }[]>([]), now = $state(Date.now());
  let direction=$state<NetworkDirection>('outbound');
  let handledFocusRequest = 0;
  let alive = true;
  const timer = setInterval(() => now = Date.now(), 1000);
  const entries = $derived(sortApps((inventory?.entries ?? []).filter(a => `${a.display_name} ${a.publisher ?? ''} ${a.version ?? ''}`.toLocaleLowerCase().includes(search.toLocaleLowerCase())), order));
  const pages = $derived(Math.max(1, Math.ceil(entries.length / 12)));
  const visible = $derived(entries.slice(Math.min(page, pages - 1) * 12, (Math.min(page, pages - 1) + 1) * 12));
  const selected = $derived((inventory?.entries ?? []).filter(a => ids.includes(a.id)));
  const targets = $derived([...new Map(ids.flatMap(id => found[id]?.paths ?? []).filter(p => !excluded.includes(p.toLowerCase())).map(p => [p.toLowerCase(), p])).values()]);
  const missing = $derived(ids.some(id => !inventory?.entries.some(a => a.id === id) || !found[id]?.paths.length || !!errors[id]));
  const expired = $derived(plans.some(p => p.expires_at * 1000 <= now));
  $effect(() => {
    const request = focusRequest, id = focusApplicationId, shouldPrepare = prepareFocusedApplication, snapshot = inventory;
    if (!request || request === handledFocusRequest || !id || !snapshot || busy || loading) return;
    const app = snapshot.entries.find(entry => entry.id === id);
    if (!app) return;
    handledFocusRequest = request;
    void (async () => {
      await discard();
      if (!alive) return;
      ids = []; excluded = []; outcomes = []; error = '';
      search = app.display_name; order = 'newest'; page = 0;
      if (shouldPrepare) direction = 'outbound';
      await tick();
      await toggle(app);
      await tick();
      if (shouldPrepare) {
        if (errors[app.id] || !found[app.id]?.paths.length) error = it ? `Non ho trovato eseguibili per ${app.display_name}. Apri i dettagli o usa il percorso manuale.` : `No executables found for ${app.display_name}. Open its details or use the manual path.`;
        else if (found[app.id].paths.length > 20) error = it ? `Ho trovato più di 20 eseguibili per ${app.display_name}. Seleziona manualmente quelli da limitare.` : `More than 20 executables were found for ${app.display_name}. Select which ones to restrict manually.`;
        else if (!canBlock) error = it ? 'Il Firewall o la policy di Windows non consente di preparare il blocco.' : 'Windows Firewall or policy does not allow preparing this block.';
        else await prepare();
      }
      document.querySelector('.app-browser')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    })();
  });
  async function discard() { const old = plans; plans = []; confirmation = false; if (old.length) { try { await discardNetworkPlans(old.map(p => p.id)); } catch (e) { if (alive) error = String(e); } } }
  onDestroy(() => { alive = false; clearInterval(timer); void discard(); });
  async function toggle(app: InstalledSoftware) {
    if (busy || loading) return;
    await discard(); outcomes = []; error = '';
    if (ids.includes(app.id)) { ids = ids.filter(id => id !== app.id); return; }
    if (ids.length >= 10) { error = it ? 'Seleziona al massimo 10 app per operazione.' : 'Select up to 10 apps per operation.'; return; }
    ids = [...ids, app.id];
    if (found[app.id]) return;
    resolving = [...resolving, app.id];
    try { const result = await applicationExecutables(app.id); if (alive) { found = { ...found, [app.id]: result }; errors = { ...errors, [app.id]: '' }; } }
    catch (e) { if (alive) errors = { ...errors, [app.id]: String(e) }; }
    finally { if (alive) resolving = resolving.filter(id => id !== app.id); }
  }
  async function prepare() {
    if (busy || loading || !canBlock || resolving.length || missing || !targets.length || targets.length > 20 || inventoryError) return;
    const paths = [...targets]; busy = true; error = ''; outcomes = []; await discard();
    const prepared: NetworkPlan[] = [];
    try { for (const path of paths) prepared.push(await prepareNetworkAction('block', path,direction)); if (alive) plans = prepared; else await discardNetworkPlans(prepared.map(p => p.id)); }
    catch (e) { try { await discardNetworkPlans(prepared.map(p => p.id)); } catch { /* plans also expire server-side */ } if (alive) error = String(e); }
    finally { busy = false; }
  }
  async function execute() {
    if (busy || loading || !confirmation || !plans.length || expired || !canBlock || inventoryError) return;
    const submitted = plans; plans = []; confirmation = false; busy = true; error = ''; outcomes = [];
    let completed = 0;
    try {
      for (const plan of submitted) {
        try { await executeNetworkAction(plan.id); completed++; outcomes = [...outcomes, { path: plan.executable, status: it ? 'Modifica completata' : 'Change completed' }]; }
        catch (e) { error = String(e); outcomes = [...outcomes, { path: plan.executable, status: it ? 'Da verificare: operazione interrotta' : 'Check outcome: operation interrupted' }]; break; }
      }
      if (completed < submitted.length) {
        const pending = submitted.slice(completed + 1);
        outcomes = [...outcomes, ...pending.map(p => ({ path: p.executable, status: it ? 'Non eseguita' : 'Not executed' }))];
        await discardNetworkPlans(submitted.slice(completed).map(p => p.id));
      }
    } catch (e) { error = String(e); }
    finally { busy = false; if (alive) await onRefresh(); }
  }
</script>

<section class="app-browser" aria-label={it ? 'Selezione applicazioni' : 'Application selection'}>
  <div class="heading"><div><h2>{it ? 'Le tue applicazioni' : 'Your applications'}</h2><p>{it ? 'Seleziona una o più app, poi scegli il blocco.' : 'Select one or more apps, then choose a restriction.'}</p></div><span>{ids.length} {it ? 'selezionate' : 'selected'}</span></div>
  <div class="toolbar"><label class="search">{it ? 'Cerca applicazione o editore' : 'Search application or publisher'}<input type="search" bind:value={search} oninput={() => page = 0} maxlength="200" placeholder={it ? 'Nome, editore o versione…' : 'Name, publisher or version…'} /></label><label>{it ? 'Ordina per' : 'Sort by'}<select bind:value={order} onchange={() => page = 0}><option value="newest">{it ? 'Più recenti' : 'Newest'}</option><option value="oldest">{it ? 'Meno recenti' : 'Oldest'}</option><option value="name">{it ? 'Nome A–Z' : 'Name A–Z'}</option></select></label></div>
  <p class="hint">{it ? 'Data dichiarata dall’installatore: può indicare un aggiornamento. Date sconosciute in fondo. Nomi ed editori non sono firme verificate.' : 'Installer-declared date: may indicate an update. Unknown dates come last. Names and publishers are not verified signatures.'}</p>
  {#if inventoryError}<p role="alert" class="warning">{inventoryError}</p>{/if}
  {#if inventory && (!inventory.complete || inventory.truncated)}<p class="warning">{it ? 'Inventario parziale: alcune voci non sono state lette.' : 'Partial inventory: some entries were not read.'}</p>{/if}
  {#each inventory?.warnings ?? [] as warning}<p class="warning">{warning}</p>{/each}
  <div class="inventory">{#each visible as app (app.id)}<article class:chosen={ids.includes(app.id)}>
    <label class="app-select"><input type="checkbox" checked={ids.includes(app.id)} disabled={busy || loading} onchange={() => toggle(app)} aria-label={`${it ? 'Seleziona' : 'Select'} ${app.display_name}`} /><span class="app-avatar" aria-hidden="true">{app.display_name.slice(0, 2).toLocaleUpperCase()}</span><span class="app-copy"><strong>{app.display_name}</strong><small>{app.publisher ?? (it ? 'Editore sconosciuto' : 'Unknown publisher')}</small><small>{app.version ?? '—'} · {installDate(app.install_date) ?? (it ? 'Data sconosciuta' : 'Unknown date')}</small></span></label>
    <button class="text-button" disabled={busy} onclick={() => onManual(app)}>{it ? 'Configura rete' : 'Configure network'} · {it ? 'percorso manuale' : 'manual path'}</button>
  </article>{/each}</div>
  {#if inventory && !entries.length}<p>{it ? 'Nessuna applicazione corrispondente.' : 'No matching application.'}</p>{/if}
  <div class="pager"><span>{entries.length} {it ? 'app' : 'apps'} · {Math.min(page, pages - 1) + 1} / {pages}</span><div><button class="button secondary small" disabled={page === 0} onclick={() => page--}>{it ? 'Precedenti' : 'Previous'}</button><button class="button secondary small" disabled={page >= pages - 1} onclick={() => page++}>{it ? 'Successive' : 'Next'}</button></div></div>
  {#if ids.length}<div class="selection">
    <div class="heading"><strong>{ids.length} {it ? 'app selezionate' : 'selected apps'} · {targets.length} .exe</strong><button class="text-button" disabled={busy} onclick={async () => { await discard(); ids = []; excluded = []; outcomes = []; }}>{it ? 'Svuota selezione' : 'Clear selection'}</button></div>
    {#each selected as app}<details><summary>{app.display_name} · {resolving.includes(app.id) ? (it ? 'Ricerca eseguibili…' : 'Finding executables…') : `${found[app.id]?.paths.length ?? 0} .exe`}</summary>
      {#if errors[app.id]}<p class="warning" role="alert">{errors[app.id]}</p>{/if}
      {#each found[app.id]?.warnings ?? [] as warning}<p class="warning">{warning}</p>{/each}
      {#each found[app.id]?.paths ?? [] as executable}<label class="exe"><input type="checkbox" checked={!excluded.includes(executable.toLowerCase())} disabled={busy} onchange={async () => { await discard(); const key = executable.toLowerCase(); excluded = excluded.includes(key) ? excluded.filter(p => p !== key) : [...excluded, key]; }} /><code>{executable}</code></label><button class="text-button" disabled={busy} onclick={() => onSandbox(executable)}>{it ? 'Prova questo eseguibile in isolamento' : 'Try this executable in isolation'}</button><button class="text-button" disabled={busy} onclick={() => onRestricted(executable)}>{it ? "Avvio limitato · AppContainer" : "Restricted launch · AppContainer"}</button><SignatureCheck {executable} {language} />{/each}
    </details>{/each}
    {#if missing && !resolving.length}<p class="warning">{it ? 'Alcune app non hanno eseguibili individuati. Apri i dettagli e usa il percorso manuale, oppure rimuovile dalla selezione.' : 'Some apps have no discovered executable. Open details and use a manual path, or remove them from the selection.'}</p>{/if}
    <div class="toolbar"><label class="search">{it ? 'Blocco da applicare' : 'Restriction to apply'}<select aria-label={it?'Blocco da applicare':'Restriction to apply'} bind:value={direction} disabled={busy} onchange={discard}><option value="outbound">{it ? 'Accesso alla rete — connessioni in uscita' : 'Network access — outbound connections'}</option><option value="inbound">{it?'Accesso alla rete — connessioni in ingresso':'Network access — inbound connections'}</option><option disabled>{it ? 'Percorsi fuori dall’installazione — non disponibile' : 'Paths outside installation — unavailable'}</option><option disabled>{it ? 'File di sistema — non disponibile' : 'System files — unavailable'}</option><option disabled>{it ? 'Aggiornamento versione — non disponibile' : 'Version updates — unavailable'}</option></select></label><button class="button primary contain-action" disabled={busy || loading || !canBlock || !!inventoryError || !!resolving.length || missing || !targets.length || targets.length > 20} onclick={prepare}>{it ? 'Prepara blocchi selezionati' : 'Prepare selected blocks'}</button></div>
    <p class="hint">{it ? 'Massimo 10 app e 20 eseguibili. I file trovati sono candidati dalla cartella e dall’icona dichiarate, non una copertura completa del prodotto. Verifica i percorsi nell’anteprima.' : 'Up to 10 apps and 20 executables. Files are candidates from the declared folder and icon, not complete product coverage. Check paths in the preview.'}</p>
  </div>{/if}
  {#if error}<p class="warning" role="alert">{error}</p>{/if}
  {#if plans.length}<div class="batch-plan" data-testid="batch-network-plan"><h3>{it ? 'Conferma i blocchi di rete' : 'Confirm network blocks'}</h3><p>{it ? 'Nessuna modifica ancora eseguita. Tutti gli utenti, tutte le destinazioni/sorgenti nella direzione indicata, anche rete locale. Le regole restano attive chiudendo piko e valgono per le versioni future allo stesso percorso.' : 'No change applied yet. All users and destinations/sources in the indicated direction, including LAN. Rules persist after piko closes and apply to future versions at the same path.'}</p><ul>{#each plans as p}<li><strong>{p.display_name} · {directionLabel(p.direction,it)}</strong><code>{p.executable}</code></li>{/each}</ul><p>{it ? 'Windows può chiedere conferma per ciascun eseguibile. Al primo errore o annullamento ci fermiamo: i blocchi già applicati rimangono, quelli successivi non vengono eseguiti.' : 'Windows may prompt for each executable. We stop at the first error or cancellation: completed blocks remain and later blocks are not executed.'}</p>
    {#if expired}<p class="warning">{it ? 'Anteprima scaduta: prepara di nuovo.' : 'Preview expired: prepare again.'}</p>{/if}
    <label class="exe"><input type="checkbox" bind:checked={confirmation} disabled={busy || expired} />{it ? 'Ho verificato tutti i percorsi e autorizzo questi blocchi.' : 'I reviewed all paths and authorize these blocks.'}</label><div class="toolbar"><button class="button primary contain-action" disabled={busy || loading || !confirmation || expired || !canBlock || !!inventoryError} onclick={execute}>{it ? 'Applica blocchi con Windows' : 'Apply blocks with Windows'}</button><button class="button secondary" disabled={busy} onclick={discard}>{it ? 'Annulla selezione blocchi' : 'Cancel block preview'}</button></div></div>{/if}
  {#if busy}<p role="status">{it ? 'Operazione in corso…' : 'Operation in progress…'}</p>{/if}
  {#if outcomes.length}<ul class="outcomes" aria-label={it ? 'Esiti dei blocchi' : 'Block outcomes'}>{#each outcomes as outcome}<li><strong>{outcome.status}</strong><code>{outcome.path}</code></li>{/each}</ul>{/if}
</section>
<style>
  .app-browser { padding: 26px; background: var(--surface); border: 1px solid var(--border); border-radius: 14px; min-width: 0; }
  h2 { font-size: 1.2rem; margin: 0; } p { color: var(--muted); font-size: .86rem; line-height: 1.6; } .hint { font-size: .77rem; }
  .heading, .toolbar, .pager { display: flex; gap: 14px; align-items: center; justify-content: space-between; flex-wrap: wrap; } .toolbar { align-items: end; margin: 18px 0; } .toolbar label { display: grid; gap: 8px; font-size: .82rem; } .search { flex: 1; min-width: 200px; }
  input[type=search], select { width: 100%; min-width: 0; border: 1px solid var(--border); background: var(--surface); color: var(--text); border-radius: 8px; padding: 10px; }
  .inventory { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; } article { border: 1px solid var(--border); border-radius: 12px; padding: 14px; min-width: 0; } article:hover { border-color: var(--border-strong); box-shadow: 0 3px 10px #192f480a; } article.chosen { border-color: var(--selection); background: var(--selection-soft); box-shadow: none; }
  .app-select { display: flex; gap: 10px; cursor: pointer; align-items: flex-start; } input[type=checkbox] { margin-top: 5px; accent-color: var(--selection); } .app-avatar { padding: 8px; background: var(--surface-subtle); border-radius: 9px; font-weight: 700; color: var(--muted); font-size: .8rem; } .app-copy { display: grid; gap: 7px; min-width: 0; } .app-copy strong { font-size: .85rem; overflow-wrap: anywhere; } small { color: var(--muted); font-size: .74rem; overflow-wrap: anywhere; } article button { color: var(--muted); font-size: .72rem; margin-top: 14px; }
  .pager { margin-top: 18px; font-size: .8rem; } .pager > div { display: flex; gap: 8px; } .selection, .batch-plan { margin-top: 22px; border: 1px solid var(--selection-border); padding: 18px; border-radius: 12px; background: var(--selection-soft); } details { margin: 12px 0; } summary { cursor: pointer; font-size: .85rem; } .exe { display: flex; gap: 10px; padding: 8px 0; font-size: .8rem; align-items: start; } code { overflow-wrap: anywhere; font-size: .75rem; } .warning { padding: 10px; color: var(--warning); background: var(--warning-surface); border-radius: 8px; } .batch-plan ul, .outcomes { max-height: 240px; overflow: auto; padding-left: 20px; } li { padding: 8px 0; } li code { display: block; }
  .app-browser > .heading { padding-bottom: 16px; border-bottom: 1px solid var(--border); }
  .app-browser > .heading > span { color: var(--selection); background: var(--selection-soft); border-radius: 20px; padding: 7px 11px; font-size: .76rem; font-weight: 600; }
  article.chosen .app-avatar { color: var(--selection); background: var(--surface); }
  .selection > .heading strong { color: var(--selection); }
  .batch-plan { background: var(--contain-soft); border-color: var(--contain-border);  }
  .batch-plan h3 { color: var(--contain); }
  @media(max-width: 1050px) { .inventory { grid-template-columns: repeat(2, minmax(0, 1fr)); } } @media(max-width: 650px) { .inventory { grid-template-columns: 1fr; } .app-browser { padding: 18px; } }
</style>
