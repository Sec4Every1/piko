<script lang="ts">
  import type { InvestigationObservation } from './investigation';
  import type { Language } from './i18n';
  import { formatTime } from './format';
  let { observations, truncated, language, disabled, onOpen }: {
    observations: InvestigationObservation[]; truncated: boolean; language: Language;
    disabled: boolean; onOpen: (observation: InvestigationObservation) => void;
  } = $props();
  const it = $derived(language === 'it');
  let page = $state(0);
  let category = $state('all');
  let search = $state('');
  let recentFirst = $state(false);
  $effect(() => { observations; category; search; recentFirst; page = 0; });
  const filtered = $derived(observations.filter(o =>
    (category === 'all' || o.event_type.startsWith(category))
    && o.process_name.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())));
  const ordered = $derived(recentFirst ? [...filtered].reverse() : filtered);
  const rows = $derived(ordered.slice(page * 5, page * 5 + 5));
  function label(kind: string) {
    if (kind.startsWith('process.')) return it ? 'Processo osservato' : 'Process observed';
    if (kind.startsWith('network.udp.')) return it ? 'Porta UDP osservata' : 'UDP port observed';
    return it ? 'Endpoint TCP osservato' : 'TCP endpoint observed';
  }
</script>
<details class="timeline">
  <summary>{it ? 'Sequenza delle osservazioni' : 'Observation timeline'} · {observations.length}</summary>
  <p class="muted">{it ? 'Orari di osservazione, non di esecuzione: la successione non prova che un evento abbia causato il successivo.' : 'Observation times, not execution times: sequence does not prove that one event caused the next.'}</p>
  {#if truncated}<p class="inline-warning">{it ? 'Sequenza parziale: fino a 128 osservazioni nel campione caricato. I filtri riguardano questo campione.' : 'Partial timeline: up to 128 observations in the loaded sample. Filters apply to this sample.'}</p>{/if}
  <div class="filters">
    <label>{it ? 'Programma' : 'Program'}<input type="search" maxlength="128" bind:value={search} placeholder={it ? 'Cerca nel campione' : 'Search sample'} /></label>
    <label>{it ? 'Attività' : 'Activity'}<select bind:value={category}><option value="all">{it ? 'Tutte' : 'All'}</option><option value="process.">{it ? 'Processi' : 'Processes'}</option><option value="network.snapshot.">TCP</option><option value="network.udp.">UDP</option></select></label>
    <label>{it ? 'Ordine' : 'Order'}<select bind:value={recentFirst}><option value={false}>{it ? 'Prima le meno recenti' : 'Oldest first'}</option><option value={true}>{it ? 'Prima le più recenti' : 'Newest first'}</option></select></label>
  </div>
  <ol>
    {#each rows as row (row.event_id)}
      <li><div><time>{formatTime(row.observed_at, language)}</time><strong>{row.process_name}</strong><span>{label(row.event_type)}</span></div><button class="button secondary small" disabled={disabled} onclick={() => onOpen(row)}>{it ? 'Dettagli' : 'Details'}</button></li>
    {/each}
  </ol>
  {#if !rows.length}<p>{it ? 'Nessuna osservazione corrispondente nel campione.' : 'No matching observations in this sample.'}</p>{/if}
  {#if ordered.length > 5}<nav aria-label={it ? 'Pagine sequenza eventi' : 'Timeline pages'}><button class="button secondary small" disabled={page === 0} onclick={() => page--}>{it ? 'Precedenti' : 'Previous'}</button><span>{page + 1} / {Math.ceil(ordered.length / 5)}</span><button class="button secondary small" disabled={(page + 1) * 5 >= ordered.length} onclick={() => page++}>{it ? 'Successivi' : 'Next'}</button></nav>{/if}
</details>
<style>
  .timeline { border-top: 1px solid var(--border); padding-top: 14px; margin-top: 18px; }
  summary { cursor: pointer; font-weight: 600; }
  .filters { display: flex; gap: 12px; flex-wrap: wrap; align-items: end; }
  label { display: grid; gap: 4px; font-size: 12px; color: var(--muted); }
  input, select { color: var(--text); background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 8px; max-width: 100%; }
  ol { list-style: none; padding: 0; margin: 12px 0; }
  li { display: flex; justify-content: space-between; gap: 12px; align-items: center; border-bottom: 1px solid var(--border); padding: 10px 0; }
  li div { min-width: 0; } strong { display: block; overflow-wrap: anywhere; font-size: 13px; }
  time, li span { color: var(--muted); font-size: 12px; } nav { display: flex; gap: 12px; align-items: center; }
</style>
