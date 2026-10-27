<script lang="ts">
  import type { Language } from './i18n';
  import { formatTime } from './format';
  import { getArchiveMaintenance, type ArchiveMaintenanceStatus } from './maintenance';
  let { connected, language }: { connected: boolean; language: Language } = $props();
  const it = $derived(language === 'it');
  let status = $state<ArchiveMaintenanceStatus | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);
  let generation = 0;
  async function load(ticket: number) {
    busy = true;
    error = null;
    try {
      const value = await getArchiveMaintenance();
      if (ticket === generation) status = value;
    } catch (reason) {
      if (ticket === generation) { status = null; error = String(reason); }
    } finally {
      if (ticket === generation) busy = false;
    }
  }
  $effect(() => {
    const active = connected;
    const ticket = ++generation;
    status = null;
    error = null;
    busy = false;
    if (active) void load(ticket);
    return () => { generation++; };
  });
  const label = $derived(!status ? (it ? 'Non disponibile' : 'Unavailable')
    : !status.enabled ? (it ? 'Disattivata' : 'Disabled')
    : status.state === 'blocked' ? (it ? 'In pausa' : 'Paused')
    : status.state === 'running' ? (it ? 'In corso' : 'Running')
    : status.state === 'completed_batch' ? (it ? 'Ultimo lotto completato' : 'Last batch completed')
    : (it ? 'In attesa' : 'Waiting'));
</script>

<div class="maintenance" aria-busy={busy}>
  <div class="heading"><strong>{it ? 'Manutenzione automatica' : 'Automatic maintenance'}</strong>
    <button type="button" disabled={!connected || busy} onclick={() => void load(++generation)}>{it ? 'Aggiorna stato' : 'Refresh status'}</button></div>
  <p class:blocked={status?.state === 'blocked'} role="status">{label}</p>
  {#if status?.state === 'completed_batch' && status.sampled_at_unix_ms !== null}
    <small>{it ? `${status.changed} evidenze compresse su ${status.scanned} esaminate.` : `${status.changed} evidence records compressed out of ${status.scanned} examined.`}
      {it ? 'Riduzione dei dati' : 'Data reduction'}: {(status.logical_bytes_saved / 1024).toLocaleString(language, { maximumFractionDigits: 1 })} KiB.
      {it ? 'Non equivale a spazio liberato sul disco.' : 'This is not disk space freed.'}</small>
    {#if status.cycle_complete}<small>{it ? 'Passaggio terminato; Piko controllerà anche le nuove evidenze.' : 'Pass finished; Piko will also check new evidence.'}</small>{/if}
  {:else if status?.enabled && status.sampled_at_unix_ms === null && status.state === 'waiting'}
    <small>{it ? 'Nessun lotto completato in questa sessione.' : 'No batch completed in this session.'}</small>
  {/if}
  {#if status?.sampled_at_unix_ms != null}<small>{it ? 'Ultimo esito' : 'Last outcome'}: {formatTime(status.sampled_at_unix_ms, language)}</small>{/if}
  {#if !connected || error}<small>{it ? 'Stato non disponibile: non conferma che la manutenzione funzioni.' : 'Status unavailable: this does not confirm maintenance is working.'}</small>{/if}
  <details><summary>{it ? 'Dettagli manutenzione' : 'Maintenance details'}</summary>
    <p>{it ? 'Piko comprime le evidenze storiche in piccoli lotti quando la coda è libera. Non elimina eventi e non modifica il periodo di conservazione. Un archivio pieno può impedire anche la compressione.' : 'Piko compresses historical evidence in small batches when the queue is idle. It does not delete events or change retention. A full archive may also prevent compression.'}</p>
    {#if status?.detail || error}<pre>{status?.detail ?? error}</pre>{/if}
  </details>
</div>
<style>
  .maintenance{padding:16px 22px;border-top:1px solid var(--border);font-size:.78rem}
  .heading{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
  strong{font-weight:600}p{margin:10px 0}small{display:block;color:var(--muted);line-height:1.6}
  .blocked{color:var(--warning)}button{font:inherit}details{margin-top:10px;color:var(--muted)}summary{cursor:pointer}
  details p,pre{line-height:1.6;white-space:pre-wrap;overflow-wrap:anywhere;font-size:inherit}
</style>
