<script lang="ts">
  import { onDestroy } from 'svelte';
  import type { Language } from './i18n';
  import { getEvidence, type FailedLogonSummary } from './api';
  let { summary,language }: {summary:FailedLogonSummary;language:Language}=$props();
  const it=$derived(language==='it');let page=$state(0),selected=$state(''),raw=$state(''),error=$state(''),busy=$state(false),request=0;
  const pages=$derived(Math.ceil(summary.records.length/5)),visible=$derived(summary.records.slice(Math.min(page,pages-1)*5,(Math.min(page,pages-1)+1)*5));
  const date=(t:number)=>new Date(t).toLocaleString(it?'it-IT':'en-GB');
  onDestroy(()=>request++);
  async function open(id:string){const current=++request;selected=id;raw='';error='';busy=true;try{const value=await getEvidence(id);if(current===request)raw=value;}catch(e){if(current===request)error=String(e);}finally{if(current===request)busy=false;}}
</script>
<details class="authentication-evidence">
 <summary>{it?'Record correlati':'Correlated records'} · {summary.count}</summary>
 <p>{it?'Finestra UTC fissa di un minuto':'Fixed one-minute UTC window'}: {date(summary.bucket_start)} – {date(summary.bucket_end)}. {it?'Non è una catena causale.':'This is not a causal chain.'}</p>
 {#each visible as record(record.event_id)}<div class="record"><span>{date(record.event_time)}</span><button class="text-button" onclick={()=>open(record.evidence_id)}>{it?'Apri XML':'Open XML'}</button><code>{record.event_id}</code></div>{/each}
 {#if pages>1}<div class="pager"><button class="text-button" disabled={page===0} onclick={()=>page--}>{it?'Precedenti':'Previous'}</button><span>{Math.min(page,pages-1)+1}/{pages}</span><button class="text-button" disabled={page>=pages-1} onclick={()=>page++}>{it?'Successive':'Next'}</button></div>{/if}
 {#if busy}<p role="status">{it?'Caricamento evidenza…':'Loading evidence…'}</p>{/if}
 {#if error}<p role="alert" class="error">{it?'Evidenza non disponibile:':'Evidence unavailable:'} {error}</p>{/if}
 {#if raw}<p>{it?'Evidenza':'Evidence'}: <code>{selected}</code></p><pre>{raw}</pre>{/if}
 <p>{it?'Analizza gli ultimi 256 record 4625 archiviati (massimo 16 MiB). Se il limite taglia il minuto più vecchio, quel minuto viene escluso. Gli errori a cavallo di due minuti, senza account/IP verificabili o con stato diverso non sono inclusi. L’assenza di una segnalazione non dimostra assenza di tentativi.':'Analyzes the last 256 archived 4625 records (up to 16 MiB). The oldest minute is excluded when clipped by the limit. Errors across minute boundaries, without verifiable account/IP or with other statuses are excluded. No alert does not establish absence of attempts.'}</p>
</details>
<style>
.authentication-evidence{border:1px solid var(--border);border-radius:10px;padding:14px;margin:16px 0;font-size:.78rem}summary{cursor:pointer}p{color:var(--muted);overflow-wrap:anywhere}.record{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--border)}.record code{font-size:.68rem;overflow-wrap:anywhere}.pager{display:flex;gap:16px;align-items:center;margin:12px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto;padding:12px;background:var(--surface-subtle);font-size:.72rem}.error{color:var(--danger)}
</style>
