<script lang="ts">
  import { onDestroy } from 'svelte';
  import type { Language } from './i18n';
  import { getInvestigation, type Investigation, type InvestigationWindow, type ObservationCursor } from './investigation';
  import { listEvents, type SecurityEvent } from './api';
  import { formatTime } from './format';
  import ObservationTimeline from './ObservationTimeline.svelte';
  let { instance, language, onEvent }: { instance: string; language: Language; onEvent: (event: SecurityEvent) => void } = $props();
  const it = $derived(language === 'it');
  let graph = $state<Investigation | null>(null), loading = $state(false), error = $state(''), page = $state(0), selected = $state(''), eventLoading = $state(false);
  let activeInstance = $state('');
  let trail = $state<string[]>([]);
  let appliedWindow = $state<InvestigationWindow | null>(null);
  let archivePage = $state(0);
  let fromDate = $state(''), untilDate = $state('');
  let generation = 0;
  let alive = true;
  onDestroy(() => { alive = false; generation++; });
  $effect(() => {
    activeInstance = instance;
    generation++;
    trail = []; graph = null; page = 0; selected = ''; error = '';
    appliedWindow = null; fromDate = ''; untilDate = '';
    archivePage = 0;
    loading = false; eventLoading = false;
  });
  const edges = $derived(graph?.edges.slice(page * 5, page * 5 + 5) ?? []);
  const edge = $derived(graph?.edges.find(e => e.target === selected));
  const selectedNode = $derived(graph?.nodes.find(n => n.id === edge?.target));
  const parentCycle = $derived(!!selectedNode?.instance_id && (selectedNode.instance_id === activeInstance || trail.includes(selectedNode.instance_id)));
  async function load(target = activeInstance || instance, mode: 'refresh' | 'parent' | 'back' | 'root' = 'refresh', window: InvestigationWindow | null = appliedWindow, before: ObservationCursor | null = null) {
    if (loading || eventLoading) return;
    if (mode === 'parent' && (trail.length >= 8 || target === activeInstance || trail.includes(target))) {
      error = it ? 'Limite di navigazione raggiunto o relazione già visitata.' : 'Navigation limit reached or relationship already visited.';
      return;
    }
    const nextTrail = mode === 'root' ? [] : mode === 'back' ? trail.slice(0, -1) : mode === 'parent' ? [...trail, activeInstance] : [...trail];
    const request = ++generation, origin = instance;
    loading = true; error = '';
    try {
      const result = await getInvestigation(target, window, before);
      if (alive && request === generation && origin === instance) {
        graph = result; activeInstance = target; trail = nextTrail; page = 0; selected = '';
        appliedWindow = window;
        archivePage = before ? archivePage + 1 : 0;
      }
    }
    catch (e) { if (alive && request === generation) error = String(e); }
    finally { if (alive && request === generation) loading = false; }
  }
  function applyWindow() {
    const from = Date.parse(fromDate), until = Date.parse(untilDate);
    if (!fromDate || !untilDate || !Number.isSafeInteger(from) || from < 0 || !Number.isSafeInteger(until) || until <= from) {
      error = it ? 'Scegli un intervallo valido: fine successiva all’inizio.' : 'Choose a valid interval with the end after the start.';
      return;
    }
    void load(activeInstance || instance, 'refresh', { from, until });
  }
  async function openEvent(id: string, observedInstance?: string) {
    if (eventLoading || loading || !graph) return;
    const eventInstance = observedInstance ?? (edge?.relation === 'observed_child' ? selectedNode?.instance_id : graph.process_instance);
    if (!eventInstance) return;
    const request = ++generation, origin = instance;
    eventLoading = true; error = '';
    try {
      const events = await listEvents({ limit: 1, expression: `event.id = ${JSON.stringify(id)} AND process.instance = ${JSON.stringify(eventInstance)}` });
      if (alive && request === generation && origin === instance) { if (events.length === 1) onEvent(events[0]); else error = it ? 'Evento non più disponibile.' : 'Event no longer available.'; }
    } catch (e) { if (alive && request === generation) error = String(e); }
    finally { if (alive && request === generation) eventLoading = false; }
  }
</script>
<section class="investigation" aria-label={it ? 'Relazioni osservate' : 'Observed relationships'}>
  <div class="heading"><h3>{it ? 'Relazioni osservate' : 'Observed relationships'}</h3><button class="button secondary small" disabled={loading || eventLoading} onclick={() => load()}>{loading ? (it ? 'Lettura…' : 'Reading…') : (it ? 'Carica relazioni' : 'Load relationships')}</button></div>
  <details class="history-window"><summary>{it ? 'Periodo dello storico' : 'History period'}</summary>
    <p class="muted">{it ? 'Orario locale. Il periodo filtra le osservazioni nell’archivio prima del limite di 128 eventi per pagina; la fine è esclusa.' : 'Local time. The period filters archive observations before the 128-event page limit; the end is exclusive.'}</p>
    <div><label>{it ? 'Da' : 'From'}<input type="datetime-local" bind:value={fromDate} disabled={loading || eventLoading} /></label><label>{it ? 'A' : 'Until'}<input type="datetime-local" bind:value={untilDate} disabled={loading || eventLoading} /></label><button class="button secondary small" disabled={loading || eventLoading} onclick={applyWindow}>{it ? 'Carica periodo' : 'Load period'}</button><button class="button secondary small" disabled={loading || eventLoading || !appliedWindow} onclick={() => void load(activeInstance || instance, 'refresh', null)}>{it ? 'Tutto lo storico' : 'All history'}</button></div>
  </details>
  {#if trail.length}<nav class="ancestry-nav" aria-label={it ? 'Navigazione genealogia processi' : 'Process genealogy navigation'}><button class="button secondary small" disabled={loading || eventLoading} onclick={() => load(trail[trail.length - 1], 'back')}>{it ? 'Indietro' : 'Back'}</button><span>{it ? 'Livello' : 'Level'} {trail.length} / 8</span><button class="button secondary small" disabled={loading || eventLoading} onclick={() => load(instance, 'root')}>{it ? 'Programma iniziale' : 'Initial program'}</button></nav>{/if}
  <p>{it ? 'Mostra account, endpoint TCP, porte locali UDP e processi padre e figli identificati negli eventi conservati. La parentela dichiarata da Windows non prova chi ha avviato un’azione. Apri un collegamento per le evidenze.' : 'Shows accounts, TCP endpoints, local UDP ports and identified parent and child processes in stored events. Windows-reported parentage does not prove who initiated an action. Open a connection for evidence.'}</p>
  {#if error}<p role="alert">{error}</p>{/if}
  {#if graph}
    <nav class="ancestry-nav" aria-label={it ? 'Pagine dello storico' : 'History pages'}>
      <span>{it ? 'Campione' : 'Sample'} {archivePage + 1}: {it ? 'massimo 128 eventi, ordinati per osservazione. Ogni pagina sostituisce anche le relazioni mostrate.' : 'up to 128 events, ordered by observation. Each page also replaces the displayed relationships.'}</span>
      <button class="button secondary small" disabled={loading || eventLoading || archivePage === 0} onclick={() => load()}>{it ? 'Piu recenti' : 'Newest'}</button>
      <button class="button secondary small" disabled={loading || eventLoading || !graph.next_observation_cursor} onclick={() => { if (graph?.next_observation_cursor) void load(activeInstance, 'refresh', appliedWindow, graph.next_observation_cursor); }}>{it ? 'Carica precedenti' : 'Load older'}</button>
    </nav>
    {#if appliedWindow}<p class="muted">{it ? 'Periodo caricato' : 'Loaded period'}: {formatTime(appliedWindow.from, language)} — {formatTime(appliedWindow.until, language)} ({it ? 'fine esclusa' : 'end exclusive'}).</p>{/if}
    <p class="muted">{graph.events_considered} {it ? 'osservazioni storiche, in questa pagina (massimo 128). Non descrivono necessariamente lo stato attuale.' : 'historical observations, in this page (up to 128). They may not describe the current state.'}</p>
    {#if trail.length}<p class="muted">{it ? 'Ogni livello usa le proprie evidenze storiche: le relazioni possono riferirsi a momenti diversi e non provano una catena di attacco.' : 'Each level uses its own historical evidence: relationships may concern different times and do not prove an attack chain.'}</p>{/if}
    {#if graph.query_truncated || graph.graph_truncated || graph.references_truncated}<p class="inline-warning">{it ? 'Vista limitata: massimo 128 osservazioni per pagina, 64 nodi e 16 riferimenti per collegamento. Apri lo storico per altre evidenze.' : 'Limited view: up to 128 observations per page, 64 nodes and 16 references per connection. Open history for more evidence.'}</p>{/if}
    {#if graph.observations_available && graph.observations !== undefined}
      {#key graph}<ObservationTimeline observations={graph.observations} truncated={!!graph.observations_truncated || graph.query_truncated} {language} disabled={loading || eventLoading} onOpen={row => void openEvent(row.event_id, row.process_instance)} />{/key}
    {:else}<p class="muted">{it ? 'Sequenza temporale non disponibile in questa versione del servizio.' : 'Timeline unavailable in this service version.'}</p>{/if}
    {#if graph.nodes.length}
      <div class="relation-map"><div class="root"><span>{it ? 'Programma' : 'Program'}</span><strong>{graph.nodes.find(n => n.id === 'process')?.label}</strong></div><ul>{#each edges as e}<li><button class:selected={selected === e.target} aria-pressed={selected === e.target} onclick={() => selected = e.target}><span>{e.relation === 'observed_identity' ? (it ? 'Account osservato' : 'Observed account') : e.relation === 'observed_parent' ? (it ? 'Processo padre osservato' : 'Observed parent process') : e.relation === 'observed_child' ? (it ? 'Processo figlio osservato' : 'Observed child process') : e.relation === 'observed_udp_bind' ? (it ? 'Porta locale UDP' : 'Local UDP port') : 'TCP'} · {e.observation_count}</span><strong>{graph.nodes.find(n => n.id === e.target)?.label}</strong></button></li>{/each}</ul></div>
      {#if !graph.edges.length}<p>{it ? 'Nessuna associazione disponibile nei dati raccolti.' : 'No association available in collected data.'}</p>{/if}
      {#if edge?.relation === 'observed_udp_bind'}<p class="muted">{it ? 'Porta locale associata a questa istanza. Questi dati non indicano destinazioni, pacchetti inviati o contenuto delle comunicazioni.' : 'Local port associated with this instance. These records do not identify destinations, sent packets or communication contents.'}</p>{/if}
      {#if edge?.relation === 'observed_parent' || edge?.relation === 'observed_child'}
        <div class="parent-navigation">
          {#if selectedNode?.instance_id}
            <button class="button secondary small" disabled={loading || eventLoading || trail.length >= 8 || parentCycle} onclick={() => { if (selectedNode?.instance_id) void load(selectedNode.instance_id, 'parent'); }}>{edge.relation === 'observed_child' ? (it ? 'Esplora questo processo figlio' : 'Explore this child process') : (it ? 'Esplora questo processo padre' : 'Explore this parent process')}</button>
            {#if parentCycle}<p class="muted">{it ? 'Questa istanza è già nel percorso: apri le evidenze o torna indietro.' : 'This instance is already in the path: open evidence or go back.'}</p>
            {:else if trail.length >= 8}<p class="muted">{it ? 'Raggiunto il limite di otto livelli. Le evidenze restano consultabili.' : 'The eight-level limit has been reached. Evidence remains available.'}</p>{/if}
          {:else}<p class="muted">{it ? 'Identità navigabile non disponibile per questo processo. Puoi leggere le osservazioni originali.' : 'A navigable identity is unavailable for this process. You can read the original observations.'}</p>{/if}
        </div>
      {/if}
      {#if graph.edges.length > 5}<div class="pager"><button class="button secondary small" disabled={page === 0} onclick={() => { page--; selected = ''; }}>{it ? 'Precedenti' : 'Previous'}</button><span>{page + 1} / {Math.ceil(graph.edges.length / 5)}</span><button class="button secondary small" disabled={(page + 1) * 5 >= graph.edges.length} onclick={() => { page++; selected = ''; }}>{it ? 'Successivi' : 'Next'}</button></div>{/if}
      {#if edge}<div class="references"><p>{formatTime(edge.first_observed, language)} — {formatTime(edge.last_observed, language)}</p><p>{it ? 'Apri un evento per leggerne i dettagli e, su richiesta, l’evidenza grezza.' : 'Open an event for details and, on request, raw evidence.'}</p><div>{#each edge.event_ids as id, index}<button class="button secondary small" disabled={eventLoading} onclick={() => openEvent(id)}>{it ? 'Osservazione' : 'Observation'} {index + 1}</button>{/each}</div></div>{/if}
    {:else}<p>{it ? 'Nessuna osservazione conservata per questa istanza. La raccolta può essere parziale o ancora in corso.' : 'No stored observation for this instance. Collection may be partial or still in progress.'}</p>{/if}
  {/if}
</section>
<style>
  .investigation { border-top: 1px solid var(--border); margin-top: 22px; padding-top: 16px; }
  .heading, .pager { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; } h3 { margin: 0; }
  .ancestry-nav { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
  .parent-navigation { padding: 12px 0; }
  .history-window { margin-top: 12px; } .history-window summary { cursor: pointer; font-size: 12px; }
  .history-window > div { display: flex; flex-wrap: wrap; align-items: end; gap: 10px; }
  .history-window label { display: grid; gap: 4px; font-size: 12px; color: var(--muted); }
  .history-window input { color: var(--text); background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 8px; }
  .relation-map { display: grid; grid-template-columns: minmax(120px, 1fr) minmax(180px, 2fr); gap: 26px; align-items: center; margin: 18px 0; }
  .root { border: 1px solid var(--border); border-left: 3px solid #568ce8; padding: 16px; border-radius: 10px; }
  strong { display: block; overflow-wrap: anywhere; font-size: 12px; margin-top: 6px; } span { font-size: 12px; }
  ul { list-style: none; padding: 0 0 0 20px; margin: 0; border-left: 2px solid var(--border); }
  li { position: relative; margin: 8px 0; } li::before { content: ''; position: absolute; left: -20px; top: 50%; width: 20px; border-top: 2px solid var(--border); }
  li button { width: 100%; text-align: left; background: var(--surface); color: var(--text); border: 1px solid var(--border); border-radius: 10px; padding: 12px; cursor: pointer; }
  li button.selected { border-color: #568ce8; } .references { border-top: 1px solid var(--border); margin-top: 16px; } .references > div { display: flex; flex-wrap: wrap; gap: 8px; }
  @media(max-width: 600px) { .relation-map { grid-template-columns: 1fr; gap: 10px; } }
</style>
