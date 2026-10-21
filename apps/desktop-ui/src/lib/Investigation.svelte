<script lang="ts">
  import { onDestroy } from 'svelte';
  import type { Language } from './i18n';
  import { getInvestigation, type Investigation } from './investigation';
  import { listEvents, type SecurityEvent } from './api';
  import { formatTime } from './format';
  let { instance, language, onEvent }: { instance: string; language: Language; onEvent: (event: SecurityEvent) => void } = $props();
  const it = $derived(language === 'it');
  let graph = $state<Investigation | null>(null), loading = $state(false), error = $state(''), page = $state(0), selected = $state(''), eventLoading = $state(false);
  let alive = true;
  onDestroy(() => { alive = false; });
  const edges = $derived(graph?.edges.slice(page * 5, page * 5 + 5) ?? []);
  const edge = $derived(graph?.edges.find(e => e.target === selected));
  async function load() {
    if (loading) return; loading = true; error = '';
    try { const result = await getInvestigation(instance); if (alive) { graph = result; page = 0; selected = ''; } }
    catch (e) { if (alive) error = String(e); }
    finally { if (alive) loading = false; }
  }
  async function openEvent(id: string) {
    if (eventLoading) return; eventLoading = true; error = '';
    try {
      const events = await listEvents({ limit: 1, expression: `event.id = ${JSON.stringify(id)} AND process.instance = ${JSON.stringify(instance)}` });
      if (alive) { if (events.length === 1) onEvent(events[0]); else error = it ? 'Evento non più disponibile.' : 'Event no longer available.'; }
    } catch (e) { if (alive) error = String(e); }
    finally { if (alive) eventLoading = false; }
  }
</script>
<section class="investigation" aria-label={it ? 'Relazioni osservate' : 'Observed relationships'}>
  <div class="heading"><h3>{it ? 'Relazioni osservate' : 'Observed relationships'}</h3><button class="button secondary small" disabled={loading} onclick={load}>{loading ? (it ? 'Lettura…' : 'Reading…') : (it ? 'Carica relazioni' : 'Load relationships')}</button></div>
  <p>{it ? 'Mostra account, endpoint TCP e processi padre identificati negli eventi conservati. La parentela dichiarata da Windows non prova chi ha avviato un’azione. Apri un collegamento per le evidenze.' : 'Shows accounts, TCP endpoints and identified parent processes in stored events. Windows-reported parentage does not prove who initiated an action. Open a connection for evidence.'}</p>
  {#if error}<p role="alert">{error}</p>{/if}
  {#if graph}
    <p class="muted">{graph.events_considered} {it ? 'osservazioni storiche, fino alle ultime 500. Non descrivono necessariamente lo stato attuale.' : 'historical observations, up to the latest 500. They may not describe the current state.'}</p>
    {#if graph.query_truncated || graph.graph_truncated || graph.references_truncated}<p class="inline-warning">{it ? 'Vista limitata: massimo 500 osservazioni, 64 nodi e 16 riferimenti per collegamento. Apri lo storico per altre evidenze.' : 'Limited view: up to 500 observations, 64 nodes and 16 references per connection. Open history for more evidence.'}</p>{/if}
    {#if graph.nodes.length}
      <div class="relation-map"><div class="root"><span>{it ? 'Programma' : 'Program'}</span><strong>{graph.nodes[0].label}</strong></div><ul>{#each edges as e}<li><button class:selected={selected === e.target} aria-pressed={selected === e.target} onclick={() => selected = e.target}><span>{e.relation === 'observed_identity' ? (it ? 'Account osservato' : 'Observed account') : e.relation === 'observed_parent' ? (it ? 'Processo padre osservato' : 'Observed parent process') : 'TCP'} · {e.observation_count}</span><strong>{graph.nodes.find(n => n.id === e.target)?.label}</strong></button></li>{/each}</ul></div>
      {#if !graph.edges.length}<p>{it ? 'Nessuna associazione disponibile nei dati raccolti.' : 'No association available in collected data.'}</p>{/if}
      {#if graph.edges.length > 5}<div class="pager"><button class="button secondary small" disabled={page === 0} onclick={() => { page--; selected = ''; }}>{it ? 'Precedenti' : 'Previous'}</button><span>{page + 1} / {Math.ceil(graph.edges.length / 5)}</span><button class="button secondary small" disabled={(page + 1) * 5 >= graph.edges.length} onclick={() => { page++; selected = ''; }}>{it ? 'Successivi' : 'Next'}</button></div>{/if}
      {#if edge}<div class="references"><p>{formatTime(edge.first_observed, language)} — {formatTime(edge.last_observed, language)}</p><p>{it ? 'Apri un evento per leggerne i dettagli e, su richiesta, l’evidenza grezza.' : 'Open an event for details and, on request, raw evidence.'}</p><div>{#each edge.event_ids as id, index}<button class="button secondary small" disabled={eventLoading} onclick={() => openEvent(id)}>{it ? 'Osservazione' : 'Observation'} {index + 1}</button>{/each}</div></div>{/if}
    {:else}<p>{it ? 'Nessuna osservazione conservata per questa istanza. La raccolta può essere parziale o ancora in corso.' : 'No stored observation for this instance. Collection may be partial or still in progress.'}</p>{/if}
  {/if}
</section>
<style>
  .investigation { border-top: 1px solid var(--border); margin-top: 22px; padding-top: 16px; }
  .heading, .pager { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; } h3 { margin: 0; }
  .relation-map { display: grid; grid-template-columns: minmax(120px, 1fr) minmax(180px, 2fr); gap: 26px; align-items: center; margin: 18px 0; }
  .root { border: 1px solid var(--border); border-left: 3px solid #568ce8; padding: 16px; border-radius: 10px; }
  strong { display: block; overflow-wrap: anywhere; font-size: 12px; margin-top: 6px; } span { font-size: 12px; }
  ul { list-style: none; padding: 0 0 0 20px; margin: 0; border-left: 2px solid var(--border); }
  li { position: relative; margin: 8px 0; } li::before { content: ''; position: absolute; left: -20px; top: 50%; width: 20px; border-top: 2px solid var(--border); }
  li button { width: 100%; text-align: left; background: var(--surface); color: var(--text); border: 1px solid var(--border); border-radius: 10px; padding: 12px; cursor: pointer; }
  li button.selected { border-color: #568ce8; } .references { border-top: 1px solid var(--border); margin-top: 16px; } .references > div { display: flex; flex-wrap: wrap; gap: 8px; }
  @media(max-width: 600px) { .relation-map { grid-template-columns: 1fr; gap: 10px; } }
</style>
