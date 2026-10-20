<script lang="ts">
  import { onMount } from 'svelte';
  import { responseStatus, prepareQuarantine, prepareRestore, executeAction } from './api';
  import type { ResponseAction, ResponseStatus } from './api';
  import type { Language } from './i18n';
  let { language }: { language: Language } = $props();
  const it = $derived(language === 'it');
  let status = $state<ResponseStatus | null>(null);
  let path = $state('');
  let plan = $state<ResponseAction | null>(null);
  let confirmed = $state(false);
  let busy = $state(false);
  let loading = $state(false);
  let error = $state('');
  let result = $state<ResponseAction | null>(null);
  export async function refresh() {
    if (loading) return;
    loading = true;
    try { status = await responseStatus(); error = ''; }
    catch (e) { error = String(e); }
    finally { loading = false; }
  }
  async function preview(restore?: string) {
    if (busy) return;
    busy = true; error = ''; plan = null; confirmed = false; result = null;
    try { plan = restore ? await prepareRestore(restore) : await prepareQuarantine(path.trim()); }
    catch (e) { error = String(e); }
    finally { busy = false; }
  }
  async function execute() {
    if (!plan || !confirmed || busy) return;
    busy = true; error = '';
    try { result = await executeAction(plan); plan = null; await refresh(); }
    catch (e) { error = `${String(e)} — ${it ? 'Aggiorna il registro prima di riprovare: l’esito potrebbe essere ancora in attesa.' : 'Refresh the journal before retrying: the outcome may still be pending.'}`; }
    finally { busy = false; }
  }
  function label(s: string) {
    const labels: Record<string, string> = it ? { planned: 'In attesa di conferma', executing: 'In esecuzione', backup_ready: 'Backup verificato', quarantined: 'In quarantena', restored: 'Ripristinato', uncertain: 'Da verificare', expired: 'Scaduto' } : {};
    return labels[s] ?? s;
  }
  onMount(() => { void refresh(); });
</script>

<div class="protection-workspace">
  <div class="response-toolbar"><p>{it ? 'Ogni azione richiede un file preciso e la tua conferma. Le segnalazioni e i consigli si trovano nella Dashboard.' : 'Every action requires a specific file and your confirmation. Alerts and guidance are on the Dashboard.'}</p><button class="button secondary" onclick={refresh} disabled={loading || busy}>{it ? 'Aggiorna registro azioni' : 'Refresh action journal'}</button></div>
  {#if error}<div class="response-error" role="alert">{error}</div>{/if}
  {#if !status}<p>{it ? 'Dati di protezione non ancora disponibili.' : 'Protection data not available yet.'}</p>{/if}
  <section class="panel">
    <span class="section-label">ENFORCEMENT / RESPONSE</span><h2>{it ? 'Quarantena controllata' : 'Controlled quarantine'}</h2>
    <p>{it ? 'Scegli un file preciso. piko prepara un’anteprima, verifica identità e contenuto e, dopo la tua conferma, conserva una copia cifrata prima di rimuovere l’originale. I processi già in esecuzione non vengono arrestati.' : 'Choose one file. piko previews and verifies its identity and content, then saves an encrypted copy before removing the original after your confirmation. Running processes are not stopped.'}</p>
    {#if status}<details><summary>{it ? 'Ambito e limiti delle azioni' : 'Action scope and limits'}</summary><p>{it ? 'Cartelle autorizzate' : 'Authorized folders'}:</p>{#each status.roots as root}<code>{root}</code>{/each}<p>{(status.max_file_bytes / 1048576).toFixed(2)} MiB / file · 128 MiB vault · {it ? 'ultime 100 azioni mostrate' : 'last 100 actions shown'}</p><p>{it ? 'File aperti, link, stream alternativi e directory protette vengono rifiutati. In modalità servizio serve un amministratore elevato; il viewer non può eseguire azioni.' : 'Open files, links, alternate streams and protected directories are rejected. Service mode requires an elevated administrator; the viewer cannot execute actions.'}</p></details>{/if}
    {#if status && status.roots.length === 0}<p class="response-error">{it ? 'Nessuna cartella autorizzata: configura response_roots nel runtime.' : 'No authorized folders: configure response_roots in the runtime.'}</p>{/if}
    <form onsubmit={(e) => { e.preventDefault(); void preview(); }}><label for="quarantine-path">{it ? 'Percorso completo del file' : 'Full file path'}</label><div class="path-row"><input id="quarantine-path" bind:value={path} placeholder="C:\Users\…\Downloads\file.exe" required disabled={busy} /><button class="button primary contain-action" disabled={busy || !status?.roots.length}>{it ? 'Prepara quarantena' : 'Prepare quarantine'}</button></div></form>
    {#if plan}<div class="preview" class:restore={plan.kind === 'restore'} role="region" aria-label={it ? 'Conferma azione' : 'Confirm action'}><h3>{plan.kind === 'quarantine' ? (it ? 'Conferma quarantena' : 'Confirm quarantine') : (it ? 'Conferma ripristino' : 'Confirm recovery')}</h3><code>{plan.path}</code><p>{plan.bytes.toLocaleString(language)} bytes · {it ? 'Scade alle' : 'Expires at'} {new Date(plan.expires_at).toLocaleTimeString(language)}</p><code>SHA-256: {plan.sha256}</code><p>{it ? 'Il piano vale solo per questo contenuto. Il ripristino recupera i dati con i permessi ereditati dalla cartella, senza ripristinare ACL e date originali. Non sovrascrive file esistenti.' : 'This plan applies only to this content. Recovery inherits folder permissions; original ACLs and timestamps are not restored. Existing files are never overwritten.'}</p><label class="confirm"><input type="checkbox" bind:checked={confirmed} disabled={busy} />{it ? 'Ho verificato il percorso e autorizzo questa azione.' : 'I checked the path and authorize this action.'}</label><div class="buttons"><button class="button" class:danger-action={plan.kind === "quarantine"} class:recovery-action={plan.kind === "restore"} onclick={execute} disabled={!confirmed || busy}>{busy ? (it ? 'Operazione in corso…' : 'Working…') : (it ? 'Esegui azione confermata' : 'Execute confirmed action')}</button><button class="button secondary" onclick={() => { plan = null; confirmed = false; }} disabled={busy}>{it ? 'Chiudi anteprima' : 'Close preview'}</button></div></div>{/if}
    {#if result}<div class="entry outcome" class:success={["quarantined", "restored"].includes(result.status)} class:warning={["uncertain", "executing", "backup_ready"].includes(result.status)} role="status"><strong>{label(result.status)}</strong><code>{result.path}</code><p>{result.detail}</p></div>{/if}
  </section>

  <section class="panel recovery-panel"><span class="section-label">RECOVERY</span><h2>{it ? 'Registro azioni e ripristino' : 'Action journal and recovery'}</h2><p>{it ? 'Le copie di recovery restano cifrate per l’identità Windows del runtime. Il backup viene conservato anche dopo un ripristino. Uno stato “Da verificare” richiede un controllo: non indica un’operazione riuscita.' : 'Recovery copies remain encrypted for the runtime’s Windows identity and are retained after recovery. An uncertain result requires inspection and does not mean success.'}</p>
    {#if status?.actions.length === 0}<p class="empty">{it ? 'Nessuna azione richiesta.' : 'No actions requested.'}</p>{/if}
    {#each status?.actions ?? [] as action (action.id)}<article class="entry"><div class="heading"><strong>{action.kind === 'quarantine' ? (it ? 'Quarantena' : 'Quarantine') : (it ? 'Ripristino' : 'Recovery')}</strong><span class="state" class:success={["quarantined", "restored"].includes(action.status)} class:warning={["uncertain", "executing", "backup_ready"].includes(action.status)}>{label(action.status)}</span></div><code>{action.path}</code><small>{new Date(action.created_at).toLocaleString(language)} · {action.id}</small><details><summary>{it ? 'Dettagli dell’esito' : 'Outcome details'}</summary><p>{action.detail}</p><code>{action.sha256}</code></details>{#if action.kind === 'quarantine' && action.backup_id}<button class="button secondary restore-outline" disabled={busy} onclick={() => preview(action.id)}>{it ? 'Prepara ripristino' : 'Prepare recovery'}</button>{/if}</article>{/each}
  </section>
</div>

<style>
  .protection-workspace { display: grid; gap: 22px; }
  .response-toolbar { display: flex; align-items: center; gap: 20px; justify-content: space-between; } .response-toolbar p { font-size: .82rem; color: var(--muted); }
  .panel { padding: 28px; border: 1px solid var(--border); border-radius: 18px; background: var(--surface); min-width: 0; }
  .heading, .path-row, .buttons { display: flex; gap: 16px; align-items: center; justify-content: space-between; }
  h2 { font-size: 24px; margin: 10px 0 14px; } h3 { font-size: 17px; margin: 0; }
  p { line-height: 1.65; } code { display: block; overflow-wrap: anywhere; margin: 10px 0; font-size: 12px; }
  .entry { border-top: 1px solid var(--border); padding: 20px 0; } .entry .button { margin-top: 12px; }
  .state { font-size: 12px; border: 1px solid var(--border); border-radius: 20px; padding: 5px 12px; white-space: nowrap; }
  .empty { padding: 16px 0; } small { opacity: .75; }
  form { margin-top: 22px; } label { display: block; margin-bottom: 10px; font-size: 14px; }
  .path-row input { flex: 1; min-width: 140px; padding: 12px; border: 1px solid var(--border); border-radius: 9px; background: transparent; color: inherit; }
  .preview { margin-top: 22px; border: 2px solid var(--contain-border); background: var(--contain-soft); padding: 22px; border-radius: 14px; }
  .recovery-panel { border-top: 3px solid var(--lavender-ink); } .recovery-panel > .section-label { color: var(--lavender-ink); }
  .success { color: var(--success); background: var(--success-soft); border-color: var(--success-border); }
  .warning { color: var(--warning); background: var(--warning-surface); border-color: var(--warning-border); }
  .outcome { margin-top: 20px; padding: 18px; border-radius: 9px; border: 1px solid var(--border-strong); }
  .danger-action { background: var(--contain); color: var(--action-on); } .danger-action:hover:not(:disabled) { background: var(--contain-hover); } .recovery-action { background: var(--lavender-ink); color: var(--action-on); } .preview.restore { border-color: var(--selection-border); background: var(--lavender); }
  .confirm { display: flex; gap: 10px; align-items: center; margin: 20px 0; } .buttons { justify-content: flex-start; flex-wrap: wrap; }
  .response-error { padding: 14px; border-left: 3px solid var(--danger); background: var(--danger-soft); color: var(--danger); overflow-wrap: anywhere; }
  summary { cursor: pointer; font-size: 13px; margin: 12px 0; }
  @media (max-width: 850px) { .heading, .path-row, .response-toolbar { align-items: stretch; flex-direction: column; } .panel { padding: 20px; } }
</style>
