<script lang="ts">
  import SignatureCheck from './SignatureCheck.svelte';
  import { onMount, tick } from 'svelte';
  import SandboxPanel from './SandboxPanel.svelte';
  let sandboxPath = $state(''), sandboxRequest = $state(0), restrictedPath = $state(''), restrictedRequest = $state(0);
  import Advisories from './Advisories.svelte';
  import RestrictedLaunch from './RestrictedLaunch.svelte';
  import SoftwareHistory from './SoftwareHistory.svelte';
  import RegistryHistory from './RegistryHistory.svelte';
  import AppGrid from './AppGrid.svelte';
  import { softwareInventory, networkSnapshot, prepareNetworkAction, executeNetworkAction, directionLabel, type InventorySnapshot, type NetworkSnapshot, type NetworkPlan, type NetworkDirection, type InstalledSoftware } from './appControl';
  import type { Language } from './i18n';
  let { language, initialPath = '' }: { language: Language; initialPath?: string } = $props();
  const it = $derived(language === 'it');
  let inventory = $state<InventorySnapshot | null>(null), network = $state<NetworkSnapshot | null>(null);
  let inventoryError = $state(''), networkError = $state(''), actionError = $state('');
  let loading = $state(false), busy = $state(false), path = $state('');
  let direction=$state<NetworkDirection>('outbound');
  let manualOpen = $state(false);
  let selected = $state<InstalledSoftware | null>(null), plan = $state<NetworkPlan | null>(null);
  let networkFocus = $state({ applicationId: '', request: 0, prepare: false });
  let confirmed = $state(false), result = $state(''), currentTime = $state(Date.now());
  const canBlock = $derived(!!network && !networkError && network.complete && network.active_profiles !== 0
    && ['ok', 'inbound_blocked'].includes(network.local_policy_modify_state) && network.profiles.filter(p => p.active).every(p => p.firewall_enabled && !p.excluded_interfaces));
  const expired = $derived(plan !== null && currentTime >= plan.expires_at * 1000);
  const canConfirm = $derived(!!plan && confirmed && !expired && !busy && !loading && !networkError && !!network?.complete
    && (plan.action === 'block' ? canBlock : network.rules.some(rule => rule.id === plan?.rule_id && (rule.direction??'outbound')===(plan?.direction??'outbound') && rule.verified)));
  const name = (p: string) => p.split('\\').pop() ?? p;
  const errorText = (error: unknown) => error instanceof Error ? error.message : String(error);
  export async function refresh(): Promise<void> {
    if (loading || busy) return;
    loading = true;
    const [apps, firewall] = await Promise.allSettled([softwareInventory(), networkSnapshot()]);
    if (apps.status === 'fulfilled') { inventory = apps.value; inventoryError = ''; } else inventoryError = errorText(apps.reason);
    if (firewall.status === 'fulfilled') { network = firewall.value; networkError = ''; } else networkError = errorText(firewall.reason);
    loading = false;
  }
  async function selectApp(app: InstalledSoftware) { manualOpen = true; selected = app; path = ''; plan = null; confirmed = false; actionError = ''; result = ''; await tick(); document.getElementById('network-executable')?.focus(); }
  function openNetworkForApplication(applicationId: string) { networkFocus = { applicationId, request: networkFocus.request + 1, prepare: true }; }
  async function prepare(action: NetworkPlan['action'], executable: string, selectedDirection:NetworkDirection=direction) {
    if (busy || loading || networkError || !network?.complete || (action === 'block' ? !canBlock : !network.rules.some(rule => rule.executable === executable && (rule.direction??'outbound')===selectedDirection && rule.verified))) return;
    manualOpen = true; busy = true; plan = null; confirmed = false; actionError = ''; result = '';
    try { plan = await prepareNetworkAction(action, executable.trim().replace(/^"(.*)"$/, '$1'),selectedDirection); currentTime = Date.now(); }
    catch (error) { actionError = errorText(error); } finally { busy = false; }
  }
  async function execute() {
    if (!plan || !canConfirm) return;
    const submitted = plan; plan = null; confirmed = false; busy = true; actionError = ''; result = '';
    try { await executeNetworkAction(submitted.id); result = it ? `Modifica completata per ${submitted.display_name}. Controlla le regole aggiornate sotto.` : `Change completed for ${submitted.display_name}. Review the refreshed rules below.`; }
    catch (error) { actionError = errorText(error); }
    finally { busy = false; await refresh(); }
  }
  onMount(() => { path = initialPath; manualOpen = !!initialPath; void refresh(); const timer = window.setInterval(() => currentTime = Date.now(), 1000); return () => window.clearInterval(timer); });
</script>

<div class="capability-workspace" data-testid="app-permissions">
  <section class="intro"><span class="section-label">{it ? 'CONTROLLO PER ESEGUIBILE' : 'PER-EXECUTABLE CONTROL'}</span><h2>{it ? 'Decidi quali app possono collegarsi alla rete' : 'Choose which apps can connect to the network'}</h2><p>{it ? 'Blocca le connessioni in uscita o in ingresso di un file .exe attraverso Windows Firewall. Prima vedi il percorso esatto, poi confermi: Windows richiederà un amministratore.' : 'Block outbound or inbound connections for an .exe file through Windows Firewall. Review its exact path, then confirm: Windows will request an administrator.'}</p></section>
  <AppGrid {language} {inventory} {inventoryError} {canBlock} network={networkError ? null : network} bind:busy {loading} focusApplicationId={networkFocus.applicationId} focusRequest={networkFocus.request} prepareFocusedApplication={networkFocus.prepare} onRefresh={refresh} onManual={selectApp} onSandbox={(path) => { sandboxPath = path; sandboxRequest++; }} onRestricted={(path) => { restrictedPath = path; restrictedRequest++; }} />
  <SoftwareHistory {language} />
  <RegistryHistory {language} />
  <Advisories {language} onOpenNetwork={openNetworkForApplication} />
  {#key restrictedRequest}<RestrictedLaunch {language} initialPath={restrictedPath} />{/key}
  {#key sandboxRequest}<SandboxPanel {language} initialPath={sandboxPath} />{/key}
  <section class="control-panel"><h2>{it ? 'Stato del Firewall di Windows' : 'Windows Firewall status'}</h2>
    {#if loading}<p role="status">{it ? 'Lettura in corso…' : 'Reading…'}</p>{/if}
    {#if networkError}<p class="warning" role="alert">{it ? 'Stato non aggiornato. Le modifiche sono sospese.' : 'Status unavailable or stale. Changes are suspended.'} {networkError}</p>{/if}
    {#if network}<div class="profiles">{#each network.profiles as profile}<div class="profile" class:enabled={profile.firewall_enabled} class:warning={profile.active && (!profile.firewall_enabled || profile.excluded_interfaces)}><strong>{({ domain: it ? 'Dominio' : 'Domain', private: it ? 'Privata' : 'Private', public: it ? 'Pubblica' : 'Public' } as Record<string, string>)[profile.name] ?? profile.name}</strong><span>{profile.active ? (it ? 'Rete attuale' : 'Current network') : (it ? 'Non in uso' : 'Not in use')}</span><b>{profile.firewall_enabled ? (it ? 'Firewall abilitato' : 'Firewall enabled') : (it ? 'Firewall disabilitato' : 'Firewall disabled')}</b>{#if profile.excluded_interfaces}<small>{it ? 'Sono presenti interfacce escluse' : 'Some interfaces are excluded'}</small>{/if}</div>{/each}</div>
      {#if !canBlock}<p class="warning">{it ? 'Non è possibile confermare l’applicazione di nuovi blocchi locali con lo stato attuale. Le regole già presenti restano elencate; la loro presenza non prova che il traffico venga filtrato.' : 'The current state cannot confirm enforcement of new local blocks. Existing rules remain listed; their presence alone does not prove traffic filtering.'}</p>{/if}
      {#if !['ok', 'inbound_blocked'].includes(network.local_policy_modify_state)}<p class="warning">{it ? 'Le policy di sistema impediscono o non confermano le modifiche locali.' : 'System policy prevents or cannot confirm local changes.'}</p>{/if}
      {#each network.warnings as warning}<p class="warning">{warning}</p>{/each}
    {/if}
  </section>
  <details class="control-panel manual-panel" bind:open={manualOpen}><summary>{it ? 'Percorso manuale e anteprima' : 'Manual path and preview'}</summary><h2>{it ? 'Prepara un blocco di rete' : 'Prepare a network block'}</h2>
    {#if selected}<p><strong>{selected.display_name}</strong> · {selected.publisher ?? '—'}</p>{#if selected.install_location}<p>{it ? 'Cartella dichiarata dall’installatore' : 'Installer-declared folder'}: <code>{selected.install_location}</code></p>{/if}{/if}
    <p>{it ? 'Inserisci il percorso completo dell’eseguibile. Puoi trovarlo in Gestione attività → Dettagli → clic destro sul programma → Apri percorso file. L’inventario sotto aiuta a riconoscere i programmi, ma non identifica automaticamente tutti i loro eseguibili.' : 'Enter the full executable path. Find it in Task Manager → Details → right-click the program → Open file location. The inventory below helps identify programs but does not automatically identify all of their executables.'}</p>
    <label>{it?'Direzione del blocco':'Block direction'}<select aria-label={it?'Direzione del blocco':'Block direction'} bind:value={direction} disabled={busy} onchange={()=>{plan=null;confirmed=false;}}><option value="outbound">{it?'In uscita':'Outbound'}</option><option value="inbound">{it?'In ingresso':'Inbound'}</option></select></label>
    <form onsubmit={event => { event.preventDefault(); void prepare('block', path); }}><label for="network-executable">{it ? 'Percorso del file .exe' : '.exe file path'}</label><div class="path-row"><input id="network-executable" bind:value={path} oninput={() => { plan = null; confirmed = false; }} placeholder="C:\Program Files\Example\app.exe" maxlength="2048" disabled={busy} /><button class="button primary contain-action" disabled={!canBlock || loading || busy || !path.trim()}>{it ? 'Prepara blocco' : 'Prepare block'}</button></div></form>
    <SignatureCheck executable={path} {language} />
    <p class="scope-note">{it ? 'Tutte le destinazioni/sorgenti e i protocolli nella direzione scelta, per tutti gli utenti del PC. Comprende Internet e rete locale, può interrompere aggiornamenti o sincronizzazioni e resta attivo dopo la chiusura di piko. Gli altri eseguibili dello stesso prodotto non sono compresi. In ingresso limita le connessioni avviate dall’esterno: per impedire all’app di collegarsi serve anche il blocco in uscita.' : 'All destinations/sources and protocols in the selected direction for every PC user. Includes Internet and LAN traffic, may interrupt updates or synchronization, and persists after piko closes. Other executables in the same product are not covered. Inbound restricts connections initiated remotely; preventing the app from connecting also requires an outbound block.'}</p>
    {#if busy}<p role="status">{it ? 'Operazione in corso. Se compare la richiesta Windows, verifica e autorizza la modifica.' : 'Operation in progress. Review and authorize the Windows prompt if it appears.'}</p>{/if}
    {#if actionError}<p class="warning" role="alert">{actionError}</p>{/if}
    {#if result}<p class="result" role="status">{result}</p>{/if}
    {#if plan}<div class="plan" class:restore={plan.action === 'remove_block'} data-testid="network-plan"><span class="section-label">{it ? 'ANTEPRIMA — NESSUNA MODIFICA ESEGUITA' : 'PREVIEW — NO CHANGE APPLIED'}</span><h3>{plan.action === 'block' ? (it ? 'Bloccare' : 'Block') : (it ? 'Rimuovere il blocco piko di' : 'Remove the piko block for')} {plan.display_name}</h3><strong>{directionLabel(plan.direction,it)}</strong><code>{plan.executable}</code>
      {#if plan.sha256}<details><summary>{it ? 'Impronta del file verificato (SHA-256)' : 'Verified file fingerprint (SHA-256)'}</summary><code>{plan.sha256}</code></details>{/if}
      <p>{plan.action === 'block' ? (it ? 'Windows applica la regola al percorso, anche alle versioni future del file in quel percorso. L’impronta controlla che il file non cambi tra anteprima e conferma.' : 'Windows applies this rule to the path, including future file versions at that path. The fingerprint checks for changes between preview and confirmation.') : (it ? 'Verrà rimossa solo questa regola piko. Le altre regole di Windows continuano a valere: non è un’autorizzazione universale alla rete.' : 'Only this piko rule will be removed. Other Windows rules remain in effect; this does not grant universal network access.')}</p>
      <p>{expired ? (it ? 'Anteprima scaduta: preparala di nuovo.' : 'Preview expired: prepare it again.') : (it ? 'Anteprima valida per cinque minuti.' : 'Preview valid for five minutes.')}</p>
      <label class="confirmation"><input type="checkbox" bind:checked={confirmed} disabled={expired || busy} />{it ? 'Ho verificato il percorso e voglio applicare questa modifica.' : 'I verified the path and want to apply this change.'}</label><div class="actions"><button class="button primary" class:contain-action={plan.action === 'block'} class:restore-outline={plan.action === 'remove_block'} disabled={!canConfirm} onclick={execute}>{it ? 'Conferma con Windows' : 'Confirm with Windows'}</button><button class="button secondary" disabled={busy} onclick={() => { plan = null; confirmed = false; }}>{it ? 'Annulla' : 'Cancel'}</button></div></div>{/if}
  </details>
  <section class="control-panel"><h2>{it ? 'Blocchi di rete di piko' : 'piko network blocks'}</h2><p>{it ? 'Regole lette direttamente da Windows. Una regola presente è una configurazione, non una misura del traffico effettivamente bloccato.' : 'Rules read directly from Windows. A present rule is a configuration, not a measurement of blocked traffic.'}</p>
    {#if network && !networkError && network.complete && !network.rules.length}<p>{it ? 'Nessun blocco piko configurato.' : 'No piko block configured.'}</p>{/if}
    {#each network?.rules ?? [] as rule}<article class="rule"><div><h3>{name(rule.executable)} · {directionLabel(rule.direction,it)}</h3><code>{rule.executable}</code><p>{rule.verified ? (it ? 'Regola piko presente e abilitata' : 'piko rule present and enabled') : (it ? 'Regola modificata esternamente: verifica in Windows Firewall' : 'Rule changed externally: inspect Windows Firewall')}</p></div><button class="button secondary restore-outline" disabled={busy || loading || !!networkError || !network?.complete || !rule.verified} onclick={() => prepare('remove_block', rule.executable,rule.direction??'outbound')}>{it ? 'Prepara rimozione' : 'Prepare removal'}</button></article>{/each}
    <p class="scope-note">{it ? 'Richieste ed esiti sono registrati nel registro Application di Windows, origine piko. Dopo un errore o un timeout aggiorna questa pagina prima di riprovare.' : 'Requests and results are recorded in the Windows Application log, source piko. After an error or timeout refresh this page before retrying.'}</p>
  </section>
  <section class="limits"><h2>{it ? 'Ambito dei permessi' : 'Permission scope'}</h2><p>{it ? 'Questo pannello controlla la rete per percorso eseguibile. Le prove AppContainer applicano limiti a una nuova esecuzione isolata. Il blocco generale di file, cartelle, registro e dispositivi per tutte le app installate richiede altri punti di enforcement e non è ancora disponibile. Le cartelle autorizzate nella quarantena limitano le operazioni di piko; non cambiano ciò che gli altri programmi possono leggere, scrivere o eseguire.' : 'This panel controls networking by executable path. AppContainer trials restrict a new isolated execution. General file, folder, registry and device controls across installed apps require other enforcement mechanisms and are not available yet. Authorized quarantine folders limit piko operations; they do not change what other programs may read, write or execute.'}</p></section>
</div>
<style>
  .manual-panel > summary { cursor: pointer; font-weight: 600; }
  .capability-workspace { display: grid; gap: 22px; } .intro, .control-panel, .limits { padding: 26px; background: var(--surface); border: 1px solid var(--border); border-radius: 14px; min-width: 0; }
  .intro { border: 0; background: transparent; padding: 0 4px; } .intro .section-label { color: var(--muted); } h2 { font-size: 1.12rem; margin: 7px 0 12px; } h3 { font-size: .96rem; margin: 0 0 8px; } p { color: var(--muted); line-height: 1.7; font-size: .86rem; margin: 12px 0; } code { overflow-wrap: anywhere; font-size: .8rem; }
  .profiles { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; } .profile { display: grid; gap: 8px; padding: 16px; background: var(--surface-subtle); border: 1px solid var(--border); border-radius: 10px; } .profile span, .profile small { color: var(--muted); font-size: .8rem; } .profile b { font-size: .86rem; }
  .warning { color: var(--warning); background: var(--warning-surface); padding: 12px; border-radius: 8px; overflow-wrap: anywhere; } .result { color: var(--success); background: var(--success-soft); padding: 12px; border-radius: 8px; }
  label { display: block; font-size: .86rem; margin: 14px 0 8px; } input:not([type=checkbox]) { width: 100%; min-width: 0; padding: 12px; border: 1px solid var(--border); border-radius: 8px; color: var(--text); background: var(--surface); } .path-row { display: flex; gap: 12px; } .path-row button { flex-shrink: 0; } .scope-note { font-size: .8rem; } .plan { margin-top: 24px; padding: 20px; border: 1px solid var(--contain-border); background: var(--contain-soft); border-radius: 12px; } .plan h3 { margin: 14px 0; } .plan details { margin-top: 16px; } .plan details code { display: block; margin-top: 12px; } .confirmation { display: flex; gap: 10px; align-items: flex-start; line-height: 1.5; } .confirmation input { margin-top: 4px; } .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 16px; }
  .rule { display: flex; justify-content: space-between; align-items: center; gap: 16px; border-top: 1px solid var(--border); padding: 18px 0; } .rule > div { min-width: 0; } .rule button { flex-shrink: 0; }  .limits { background: var(--surface-subtle); }
  .rule h3, .plan h3 { overflow-wrap: anywhere; unicode-bidi: plaintext; }
  .profile.enabled b { color: var(--success); } .profile.warning b { color: var(--warning); }
  .plan .section-label { color: var(--contain); } .plan.restore { background: var(--lavender); border-color: var(--selection-border); } .plan.restore .section-label { color: var(--lavender-ink); }
  .rule { border-left: 3px solid var(--contain-border); padding-left: 16px; }
  @media (max-width: 800px) { .profiles { grid-template-columns: 1fr; } .path-row, .rule { flex-direction: column; align-items: stretch; } .intro, .control-panel, .limits { padding: 20px; } }
</style>
