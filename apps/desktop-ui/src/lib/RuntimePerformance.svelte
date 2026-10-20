<script lang="ts">
  import { onMount } from 'svelte';
  import type { HealthSnapshot } from './api';
  import type { Language } from './i18n';
  import { formatTime } from './format';
  let { health, connected, language }: { health: HealthSnapshot | null; connected: boolean; language: Language } = $props();
  const it=$derived(language==='it');
  const metrics=$derived(connected ? health?.performance : null);
  let now=$state(Date.now());
  const stale=$derived(!!metrics && now-metrics.sampled_at_unix_ms>Math.max(15000,metrics.interval_ms*2));
  const mib=(bytes:number|null|undefined)=>bytes==null ? '—' : (bytes/1048576).toLocaleString(language,{maximumFractionDigits:1})+' MiB';
  onMount(()=>{const timer=setInterval(()=>now=Date.now(),1000);return()=>clearInterval(timer);});
</script>
<section class="panel performance-panel" aria-label={it ? 'Consumi del monitor' : 'Monitor resource usage'}>
  <div class="panel-heading"><div><h2>{it ? 'Consumi del monitor' : 'Monitor resource usage'}</h2><p>{it ? 'Risorse del processo monitor; la finestra e gli helper hanno consumi separati.' : 'Resources of the monitor process; the window and helpers consume resources separately.'}</p></div></div>
  {#if !connected || !metrics}<p class="notice-text" role="status">{it ? 'Misure non disponibili.' : 'Measurements unavailable.'} {health?.performance_error ?? ''}</p>{/if}
  {#if stale}<p class="stale" role="status">{it ? 'Campione non recente: i valori sotto appartengono all’ultima lettura.' : 'Stale sample: values below belong to the last reading.'}</p>{/if}
  <dl><div><dt>CPU</dt><dd>{metrics?.cpu_percent_x100 != null ? (metrics.cpu_percent_x100/100).toLocaleString(language,{maximumFractionDigits:1})+'%' : '—'}</dd><small>{it ? 'Percentuale sui processori logici disponibili' : 'Share of available logical processors'}</small></div><div><dt>{it ? 'RAM del monitor' : 'Monitor RAM'}</dt><dd>{mib(metrics?.working_set_bytes)}</dd><small>{it ? 'Working set: pagine attualmente in memoria' : 'Working set: currently resident pages'}</small></div><div><dt>{it ? 'Memoria privata impegnata' : 'Private committed memory'}</dt><dd>{mib(metrics?.private_bytes)}</dd><small>{it ? 'Allocazione privata; può includere memoria paginata' : 'Private allocation; may include paged memory'}</small></div><div><dt>{it ? 'Eventi in attesa' : 'Queued events'}</dt><dd>{connected && health ? health.queue_depth : '—'}</dd><small>{it ? 'Coda e batch in attesa di salvataggio' : 'Queue and batch awaiting persistence'}</small></div></dl>
  {#if metrics}<p class="sample">{it ? 'Campione' : 'Sample'}: {formatTime(metrics.sampled_at_unix_ms,language)} · {it ? 'Intervallo CPU' : 'CPU interval'}: {(metrics.interval_ms/1000).toLocaleString(language,{maximumFractionDigits:1})} s · {metrics.logical_processors ?? '—'} {it ? 'processori logici' : 'logical processors'}. {metrics.cpu_percent_x100===null ? (it ? 'La CPU richiede due campioni validi.' : 'CPU requires two valid samples.') : ''}</p>{/if}
</section>
<style>
  .performance-panel {margin-bottom:22px;} dl {display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:22px;margin:0;padding:22px;} dt {font-size:.75rem;color:var(--muted);} dd {font-size:1.45rem;margin:10px 0;font-weight:500;} small {font-size:.69rem;color:var(--muted);line-height:1.6;display:block;} .notice-text,.sample {color:var(--muted);font-size:.75rem;padding:14px 22px;} .stale {background:var(--warning-surface);color:var(--warning);font-size:.75rem;padding:12px 22px;} @media(max-width:980px){dl{grid-template-columns:repeat(2,minmax(0,1fr));}} @media(max-width:490px){dl{grid-template-columns:1fr;}}
</style>
