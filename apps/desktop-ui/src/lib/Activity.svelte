<script lang="ts">
  import { onMount } from 'svelte';
  import type { Language } from './i18n';
  import { getObservations, belongsTo, tcpState, type ObservationSnapshot, type ObservedProcess } from './observations';
  import { listEvents, type SecurityEvent } from './api';
  import { eventTypeLabel, formatTime } from './format';
  import ProcessJournal from './ProcessJournal.svelte';
  import ProcessResponse from './ProcessResponse.svelte';
  import Investigation from './Investigation.svelte';
  import IdentityActivity from './IdentityActivity.svelte';
  let { language, onNetwork, onEvent }: { language: Language; onNetwork: (path: string) => void; onEvent: (event: SecurityEvent) => void } = $props();
  const it = $derived(language === 'it');
  let snapshot = $state<ObservationSnapshot | null>(null), error = $state(''), loading = $state(false), search = $state('');
  let selected = $state<ObservedProcess | null>(null), history = $state<SecurityEvent[]>([]), historyError = $state(''), historyLoading = $state(false);
  let mounted = false, generation = 0, now = $state(Date.now());
  const processes = $derived((snapshot?.processes ?? []).filter(p => `${p.name} ${p.executable ?? ''} ${p.pid}`.toLocaleLowerCase(language).includes(search.toLocaleLowerCase(language))));
  const connections = $derived(selected ? (snapshot?.connections ?? []).filter(c => belongsTo(c, selected!)) : []);
  let udpPage=$state(0);
  const udp=$derived(selected?(snapshot?.udp_endpoints??[]).filter(c=>belongsTo(c,selected!)):[]);
  const udpPages=$derived(Math.max(1,Math.ceil(udp.length/5)));
  const unknownUdp=$derived((snapshot?.udp_endpoints??[]).filter(e=>e.process_creation_filetime===null).length);
  const unknownConnections = $derived((snapshot?.connections ?? []).filter(c => c.process_creation_filetime === null).length);
  const selectedCurrent = $derived(!!selected && !!snapshot?.processes.some(p => p.instance_id !== null && p.instance_id === selected?.instance_id));
  const stale = $derived(snapshot !== null && (now - snapshot.completed_at_unix_ms > 30000 || now < snapshot.completed_at_unix_ms - 5000));
  export async function refresh() {
    if (loading) return; loading = true;
    try { const value = await getObservations(); if (mounted) { snapshot = value; error = ''; } }
    catch (e) { if (mounted) error = e instanceof Error ? e.message : String(e); }
    finally { loading = false; }
  }
  async function select(process: ObservedProcess) {
    udpPage=0; selected = process; history = []; historyError = ''; const current = ++generation;
    if (!process.instance_id) { historyLoading = false; return; }
    historyLoading = true;
    try {
      const values = await listEvents({ limit: 100, expression: `process.instance = ${JSON.stringify(process.instance_id)}` });
      if (mounted && generation === current) history = values.filter(e => e.process?.instance_id === process.instance_id);
    } catch (e) { if (mounted && generation === current) historyError = String(e); }
    finally { if (generation === current) historyLoading = false; }
  }
  onMount(() => { mounted = true; void refresh(); const timer = setInterval(() => { now = Date.now(); if (document.visibilityState === 'visible') void refresh(); }, 10000); return () => { mounted = false; generation++; clearInterval(timer); }; });
</script>

<div class="activity-workspace" data-testid="application-activity">
  <div class="scope-note"><strong>{it ? 'Chi sta usando il computer e la rete' : 'Who is using this computer and network'}</strong><p>{it ? 'Fotografie ogni 10 secondi. Le attività molto brevi possono sfuggire. Una connessione, da sola, non indica un attacco; indirizzi IP e porte non rivelano il contenuto del traffico.' : 'Snapshots every 10 seconds. Brief activity can be missed. A connection alone is not an attack; IP addresses and ports do not reveal traffic content.'}</p></div>
  <IdentityActivity {language} {onEvent} />
  {#if error}<div class="notice warning-notice" role="alert"><strong>{it ? 'Lettura non disponibile. I dati precedenti possono essere obsoleti.' : 'Reading unavailable. Earlier data may be stale.'}</strong><code>{error}</code></div>{/if}
  {#if snapshot}
    <div class="activity-stats"><div><strong>{snapshot.processes.length}</strong><span>{it ? 'Processi osservati' : 'Observed processes'}</span></div><div><strong>{snapshot.connections.length}</strong><span>{it ? 'Connessioni e porte TCP' : 'TCP connections and listeners'}</span></div><div><strong>{unknownConnections}</strong><span>{it ? 'Associazioni non verificabili' : 'Unverified owners'}</span></div></div>
    <p class="muted">UDP: {snapshot.udp_complete==null?(it?'Non disponibile':'Unavailable'):(snapshot.udp_endpoints??[]).length+' '+(it?'porte locali':'local binds')+' · '+unknownUdp+' '+(it?'associazioni non verificabili':'unverified owners')}. {it?'Non indica destinazioni o datagrammi inviati.':'Does not indicate destinations or sent datagrams.'}</p>
    <p class="muted">{it ? 'Ultima fotografia:' : 'Last snapshot:'} {formatTime(snapshot.completed_at_unix_ms, language)} · {it ? 'Acquisizione:' : 'Capture:'} {snapshot.completed_at_unix_ms - snapshot.started_at_unix_ms} ms</p>
    {#if stale}<p class="inline-warning" role="status">{it ? 'Fotografia obsoleta o orologio cambiato. Aggiorna prima di interpretare lo stato corrente.' : 'Stale snapshot or clock change. Refresh before interpreting current state.'}</p>{/if}
    {#if !snapshot.process_complete || !snapshot.network_complete || snapshot.udp_complete===false}<p class="inline-warning">{it ? 'Copertura parziale: il conteggio non rappresenta tutta l’attività.' : 'Partial coverage: counts do not represent all activity.'}</p>{/if}
    {#each snapshot.warnings as warning}<p class="inline-warning">{warning}</p>{/each}
    <section class="panel"><div class="panel-heading"><h2>{it ? 'Applicazioni osservate' : 'Observed applications'}</h2><label>{it ? 'Cerca nome, percorso o PID' : 'Search name, path or PID'}<input bind:value={search} maxlength="256" /></label></div>
      <div class="table-scroll"><table><thead><tr><th>{it ? 'Programma' : 'Program'}</th><th>PID</th><th>TCP</th><th>UDP</th><th>{it ? 'Identità' : 'Identity'}</th></tr></thead><tbody>
        {#each processes.slice(0, 100) as p}<tr><td><button class="event-title-button" onclick={() => select(p)}>{p.name}</button><span class="event-row-detail">{p.executable ?? (it ? 'Percorso non accessibile' : 'Path inaccessible')}</span></td><td>{p.pid}</td><td>{p.creation_filetime ? snapshot.connections.filter(c => belongsTo(c, p)).length : '—'}</td><td>{snapshot.udp_complete==null||!p.creation_filetime?'—':(snapshot.udp_endpoints??[]).filter(c=>belongsTo(c,p)).length}</td><td>{p.instance_id ? (it ? 'Istanza distinta' : 'Distinct instance') : (it ? 'Non verificata' : 'Unverified')}{#if p.access_error}<span class="event-row-detail">{it ? 'Dettagli parziali' : 'Partial details'}</span>{/if}</td></tr>{/each}
      </tbody></table></div><p class="panel-footer">{it ? 'Visualizzati fino a 100 risultati su' : 'Showing up to 100 results out of'} {processes.length}. {it ? 'Seleziona un programma per approfondire.' : 'Select a program to investigate.'}</p>
    </section>
  {:else if !error}<p role="status">{it ? 'Acquisizione delle osservazioni…' : 'Reading observations…'}</p>{/if}
  {#if selected}
    <section class="panel process-detail"><div class="panel-heading"><div><h2>{selected.name}</h2><p>PID {selected.pid} · {selectedCurrent ? (it ? 'Presente nella fotografia' : 'Present in snapshot') : (it ? 'Presenza attuale non verificata' : 'Current presence unverified')}</p></div>{#if selected.executable}<button class="button secondary" disabled={!!error || stale || !selectedCurrent} onclick={() => onNetwork(selected!.executable!)}>{it ? 'Gestisci accesso alla rete' : 'Manage network access'}</button>{/if}</div>
      <dl><dt>{it ? 'Percorso' : 'Path'}</dt><dd><code>{selected.executable ?? '—'}</code></dd><dt>{it ? 'Identità dell’istanza' : 'Instance identity'}</dt><dd><code>{selected.instance_id ?? '—'}</code></dd><dt>SID</dt><dd><code>{selected.sid ?? '—'}</code></dd><dt>{it ? 'PID padre riportato da Windows' : 'Parent PID reported by Windows'}</dt><dd>{selected.parent_pid || '—'} · {it ? 'Non dimostra da solo una relazione causale.' : 'Does not by itself prove a causal relationship.'}</dd></dl>
      {#if selected.access_error}<details><summary>{it ? 'Dettagli non accessibili' : 'Inaccessible details'}</summary><code>{selected.access_error}</code></details>{/if}
      <h3>{it ? 'Relazioni di rete osservate' : 'Observed network relationships'}</h3>
      <p>{it ? 'Programma → indirizzo locale → destinazione remota. LISTEN indica una porta in ascolto; la direzione delle altre connessioni non è determinabile da questa fotografia.' : 'Program → local address → remote endpoint. LISTEN is a listening port; other connection directions cannot be established from this snapshot.'}</p>
      <details class="udp-detail"><summary>{it?'Porte locali UDP':'Local UDP binds'} · {snapshot?.udp_complete==null?'—':udp.length}</summary><p>{it?'Una porta associata non prova invio, ricezione o ascolto raggiungibile dalla rete. Destinazioni e contenuto non disponibili.':'An associated bind does not prove sending, receiving or network reachability. Destinations and content are unavailable.'}</p>{#if snapshot?.udp_complete===false}<p class="inline-warning">{it?'Lettura UDP parziale.':'Partial UDP reading.'}</p>{/if}{#each udp.slice(Math.min(udpPage,udpPages-1)*5,(Math.min(udpPage,udpPages-1)+1)*5) as e}<p class="mono">[{e.local_address}]:{e.local_port} · {e.family}</p>{/each}{#if udpPages>1}<div class="actions"><button class="text-button" disabled={udpPage===0} onclick={()=>udpPage--}>{it?'Precedenti':'Previous'}</button><span>{Math.min(udpPage,udpPages-1)+1}/{udpPages}</span><button class="text-button" disabled={udpPage>=udpPages-1} onclick={()=>udpPage++}>{it?'Successive':'Next'}</button></div>{/if}</details>
      {#if connections.length}<div class="table-scroll"><table><thead><tr><th>{it ? 'Indirizzo locale' : 'Local address'}</th><th>{it ? 'Destinazione remota' : 'Remote endpoint'}</th><th>{it ? 'Stato' : 'State'}</th></tr></thead><tbody>{#each connections as c}<tr><td class="mono">[{c.local_address}]:{c.local_port}</td><td class="mono">[{c.remote_address}]:{c.remote_port}</td><td>{tcpState(c.state)}</td></tr>{/each}</tbody></table></div>{:else}<p>{it ? 'Nessuna connessione associabile in questa fotografia. Non prova l’assenza di traffico.' : 'No attributable connection in this snapshot. This does not prove no traffic occurred.'}</p>{/if}
      {#if selected.instance_id}{#key selected.instance_id}{#key selected.creation_filetime}<ProcessResponse process={selected} {language} available={selectedCurrent&&!stale&&!error} onChanged={()=>void refresh()} />{/key}
      <Investigation instance={selected.instance_id} {language} {onEvent} />{/key}{/if}
      <h3>{it ? 'Storico di questa istanza' : 'This instance’s history'}</h3><p>{it ? 'Ultimi 100 eventi conservati; la scrittura può essere in corso. “Non osservato” non equivale a “terminato”.' : 'Latest 100 stored events; writes may still be pending. “Not observed” does not mean “terminated”.'}</p>
      <button class="button secondary small" disabled={!selected.instance_id || historyLoading} onclick={() => select(selected!)}>{it ? 'Aggiorna storico' : 'Refresh history'}</button>
      {#if historyError}<p role="alert">{historyError}</p>{/if}
      {#if !selected.instance_id}<p>{it ? 'Identità insufficiente per distinguere le diverse istanze di questo PID.' : 'Insufficient identity to distinguish different instances of this PID.'}</p>{/if}
      <ol class="process-timeline">{#each history as event}<li><time>{formatTime(event.observation_time, language)}</time><button class="event-title-button" onclick={() => onEvent(event)}>{eventTypeLabel(event.event_type, language)}</button><code>{event.target?.identifier ?? event.process?.executable_path ?? ''}</code></li>{/each}</ol>
    </section>
  {/if}
  <ProcessJournal {language} />
</div>

<style>
  .activity-workspace { display: grid; gap: 18px; }
  .scope-note { border-left: 3px solid #568ce8; padding: 8px 18px; }
  .scope-note p { margin-bottom: 0; }
  .activity-stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .activity-stats div { display: grid; gap: 8px; padding: 20px; border: 1px solid var(--border); border-radius: 12px; }
  .activity-stats strong { font-size: 28px; }
  label { display: grid; gap: 6px; font-size: 12px; }
  td:first-child { max-width: 440px; overflow-wrap: anywhere; }
  .process-detail { padding: 22px; min-width: 0; }
  .process-detail .panel-heading { padding: 0 0 18px; flex-wrap: wrap; }
  dd { margin: 4px 0 14px; overflow-wrap: anywhere; }
  dt { font-size: 12px; opacity: .75; }
  h3 { margin-top: 24px; }
  .process-timeline { padding-left: 22px; }
  .process-timeline li { padding: 12px 0; border-bottom: 1px solid var(--border); }
  .process-timeline time, .process-timeline code { display: block; overflow-wrap: anywhere; }
  .process-timeline time { font-size: 12px; opacity: .75; }
  .notice { display: grid; overflow-wrap: anywhere; }
  @media(max-width: 850px) { .activity-stats { grid-template-columns: 1fr; } }
</style>
