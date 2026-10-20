<script lang="ts">
  import type { Language } from './i18n';
  import { softwareInventory, type InstalledSoftware } from './appControl';
  import { advisoryStatus, importAdvisoryFeed, bindAdvisoryProduct, unbindAdvisoryProduct, advisoryLevel, type AdvisorySnapshot, type ApplicationAssessment } from './advisories';
  let { language, onOpenNetwork }: { language: Language; onOpenNetwork?: (applicationId: string) => void } = $props();
  const it=$derived(language==='it');
  let snapshot=$state<AdvisorySnapshot|null>(null), apps=$state<InstalledSoftware[]>([]), busy=$state(false), error=$state(''), result=$state('');
  let search=$state(''), page=$state(0), appSearch=$state(''), applicationId=$state(''), productId=$state(''), exactVersion=$state(''), confirmed=$state(false);
  let selected=$state<ApplicationAssessment|null>(null), advisoryPage=$state(0), bindingOpen=$state(false);
  const filtered=$derived((snapshot?.entries??[]).filter(e=>`${e.binding.application_name} ${e.binding.product_id}`.toLocaleLowerCase().includes(search.toLocaleLowerCase())));
  const visible=$derived(filtered.slice(page*5,page*5+5)), pages=$derived(Math.max(1,Math.ceil(filtered.length/5)));
  const appOptions=$derived(apps.filter(a=>`${a.display_name} ${a.publisher??''}`.toLocaleLowerCase().includes(appSearch.toLocaleLowerCase())).sort((a,b)=>a.display_name.localeCompare(b.display_name)).slice(0,50));
  const application=$derived(apps.find(a=>a.id===applicationId));
  const product=$derived(snapshot?.feed?.products.find(p=>p.product_id===productId));
  const matches=$derived(selected?.state==='matched' ? (snapshot?.advisories??[]).filter(a=>a.product_id===selected!.binding.product_id && a.affected_versions.includes(selected!.binding.exact_version)) : []);
  const matchPages=$derived(Math.max(1,Math.ceil(matches.length/5)));
  const date=(seconds:number)=>new Date(seconds*1000).toLocaleString(language==='it'?'it-IT':'en-GB');
  const stateLabel=(entry:ApplicationAssessment)=>({matched:it?`${entry.advisory_count} avvisi`:`${entry.advisory_count} advisories`,no_known_advisory:it?'Nessun avviso nel feed':'No advisory in this feed',product_not_covered:it?'Prodotto non coperto':'Product not covered',version_not_covered:it?'Versione non coperta':'Version not covered',metadata_changed:it?'Ricontrolla associazione':'Review binding',not_observed:it?'App non osservata':'App not observed',no_feed:it?'Feed assente':'No feed'}[entry.state]);
  async function load() {
    if(busy) return; busy=true; error='';
    try { const [next,inventory]=await Promise.all([advisoryStatus(),softwareInventory()]); snapshot=next; apps=inventory.entries; page=0; selected=null; }
    catch(e) { error=String(e); } finally { busy=false; }
  }
  async function importFile(event:Event) {
    const input=event.currentTarget as HTMLInputElement, file=input.files?.[0]; if(!file || busy) return;
    busy=true; error=''; result='';
    try {
      if(file.size>1024*1024) throw new Error(it?'Il feed supera 1 MiB.':'Feed exceeds 1 MiB.');
      const json=await file.text(); await importAdvisoryFeed(json);
      snapshot=await advisoryStatus(); page=0; selected=null;
      result=it?'Feed importato. La provenienza non è autenticata da piko.':'Feed imported. Its provenance is not authenticated by piko.';
    } catch(e) { error=String(e); } finally { busy=false; input.value=''; }
  }
  async function save() {
    if(busy || !application || !product || !exactVersion || !confirmed) return; busy=true; error=''; result='';
    try { await bindAdvisoryProduct(applicationId,productId,exactVersion); snapshot=await advisoryStatus(); page=0; bindingOpen=false; selected=null; confirmed=false; result=it?'Associazione personale salvata.':'Personal binding saved.'; }
    catch(e) { error=String(e); } finally { busy=false; }
  }
  async function remove(id:string) {
    if(busy) return; busy=true; error=''; result='';
    try { await unbindAdvisoryProduct(id); snapshot=await advisoryStatus(); selected=null; page=0; result=it?'Associazione rimossa.':'Binding removed.'; }
    catch(e) { error=String(e); } finally { busy=false; }
  }
  function review(e:ApplicationAssessment) {
    applicationId=e.binding.application_id; appSearch=e.binding.application_name; productId=e.binding.product_id; exactVersion=e.binding.exact_version; confirmed=false; bindingOpen=true;
  }
</script>
<details class="advisory-panel" data-testid="software-advisories" ontoggle={e=>{if(e.currentTarget.open&&!snapshot&&!busy&&!error) void load();}}>
  <summary>{it?'Vulnerabilità e fine supporto':'Vulnerabilities and end of support'}</summary>
  <p>{it?'Confronta prodotti e versioni che hai verificato con un feed JSON importato. Nessun collegamento automatico basato sul nome dell’app.':'Compare products and versions you have checked against an imported JSON feed. Apps are not matched automatically by name.'}</p>
  <div class="toolbar"><label class="import">{it?'Importa feed JSON':'Import JSON feed'}<input type="file" accept=".json,application/json" disabled={busy} onchange={importFile}/></label><button class="button secondary small" disabled={busy} onclick={load}>{it?'Aggiorna advisory':'Refresh advisories'}</button><button class="button secondary small" disabled={busy||!snapshot?.feed} onclick={()=>{bindingOpen=!bindingOpen;confirmed=false;}}>{it?'Associa applicazione':'Bind application'}</button></div>
  {#if busy}<p role="status">{it?'Verifica locale…':'Local check…'}</p>{/if}
  {#if error}<p class="warning" role="alert">{it?'Operazione non completata; i dati precedenti restano conservati.':'Operation not completed; earlier data is preserved.'} {error}</p>{/if}
  {#if result}<p class="notice" role="status">{result}</p>{/if}
  {#if snapshot}
    {#if !snapshot.feed}<p class="empty">{it?'Nessun feed configurato. Importa dati del fornitore convertiti nello schema piko v1; consulta il manuale per il formato. Non vengono caricati esempi nel prodotto.':'No feed configured. Import vendor data converted to piko schema v1; the manual describes the format. The product does not load sample data.'}</p>
    {:else}<div class="feed"><strong>{snapshot.feed.source_name}</strong><span>{snapshot.feed.advisory_count} {it?'avvisi':'advisories'} · {snapshot.feed.product_count} {it?'prodotti':'products'}</span></div>
      {#if snapshot.feed.stale}<p class="warning">{it?'Feed scaduto: gli avvisi restano visibili, ma il confronto non è aggiornato. Importa una lettura recente.':'Feed expired: advisories remain visible, but the comparison is out of date. Import a recent snapshot.'}</p>{/if}
      <details class="source"><summary>{it?'Fonte e copertura':'Source and coverage'}</summary><p>{it?'Generato':'Generated'}: {date(snapshot.feed.generated_at)} · {it?'Scade':'Expires'}: {date(snapshot.feed.expires_at)}</p><p class="source-url">{snapshot.feed.source_url}</p><p>{it?'Il digest verifica soltanto la copia locale. Piko non verifica una firma del feed né l’autenticità della fonte. CVSS è un indice dichiarato dalla fonte, non la probabilità di un attacco o di un falso positivo.':'The digest checks only the local copy. Piko does not verify a feed signature or its source authenticity. CVSS is a source-declared index, not an attack or false-positive probability.'}</p><code>{snapshot.feed.sha256}</code></details>
    {/if}
    <p class="reading">{snapshot.entries.length} {it?'app associate':'bound apps'} · {snapshot.unbound_count} {it?'voci inventario non valutate':'inventory entries not assessed'} · {it?'Controllato':'Checked'}: {date(snapshot.checked_at)}</p>
    {#if !snapshot.inventory_complete}<p class="warning">{it?'Inventario parziale: un’app non osservata non prova una disinstallazione.':'Partial inventory: an unobserved app does not prove it was uninstalled.'}</p>{/if}
    {#if bindingOpen}<form class="binding" onsubmit={e=>{e.preventDefault();void save();}}>
      <h3>{it?'Associazione verificata da te':'Binding checked by you'}</h3>
      <label>{it?'Cerca applicazione':'Search application'}<input type="search" bind:value={appSearch} maxlength="200"/></label>
      <label>{it?'Applicazione osservata (primi 50 risultati)':'Observed app (first 50 matches)'}<select bind:value={applicationId} onchange={()=>{confirmed=false;exactVersion=apps.find(a=>a.id===applicationId)?.version??'';}}><option value="">{it?'Scegli applicazione':'Choose application'}</option>{#each appOptions as app (app.id)}<option value={app.id}>{app.display_name} · {app.version??(it?'versione sconosciuta':'unknown version')} · {app.publisher??(it?'editore sconosciuto':'unknown publisher')} · {app.scope}/{app.registry_view}</option>{/each}</select></label>
      <label>{it?'Prodotto nel feed':'Product in the feed'}<select bind:value={productId} onchange={()=>{confirmed=false;}}><option value="">{it?'Scegli prodotto verificato':'Choose the checked product'}</option>{#each snapshot.feed?.products??[] as p (p.product_id)}<option value={p.product_id}>{p.display_name} · {p.product_id}</option>{/each}</select></label>
      <label>{it?'Versione esatta verificata':'Exact version you checked'}<input bind:value={exactVersion} maxlength="80" oninput={()=>confirmed=false}/></label>
      {#if product}<p class="reading">{it?'Versioni coperte dal feed':'Versions covered by feed'}: {product.covered_versions.join(', ')}</p>{/if}
      <label class="confirmation"><input type="checkbox" bind:checked={confirmed}/>{it?'Ho verificato fornitore, prodotto e versione esatta nella fonte; i dati dell’installer da soli non bastano.':'I checked vendor, product and exact version against the source; installer data alone is insufficient.'}</label>
      <div class="toolbar"><button class="button small" disabled={busy||!application||!product||!exactVersion||!confirmed}>{it?'Salva associazione':'Save binding'}</button><button type="button" class="text-button" onclick={()=>bindingOpen=false}>{it?'Chiudi associazione':'Close binding'}</button></div>
    </form>{/if}
    {#if snapshot.entries.length}<label class="search">{it?'Cerca nelle app associate':'Search bound apps'}<input type="search" bind:value={search} maxlength="200" oninput={()=>{page=0;selected=null;}}/></label>{/if}
    {#each visible as entry (entry.binding.application_id)}<article class="app-row"><button class="row-button" onclick={()=>{selected=selected?.binding.application_id===entry.binding.application_id?null:entry;advisoryPage=0;}}><strong>{entry.binding.application_name}</strong><span class:attention={entry.state==='matched'}>{stateLabel(entry)}</span><small>{entry.binding.product_id} · {entry.binding.exact_version}</small></button></article>{/each}
    {#if pages>1}<div class="pager"><button class="text-button" disabled={page===0} onclick={()=>{page--;selected=null;}}>{it?'App precedenti':'Previous apps'}</button><span>{page+1}/{pages}</span><button class="text-button" disabled={page>=pages-1} onclick={()=>{page++;selected=null;}}>{it?'App successive':'Next apps'}</button></div>{/if}
    {#if selected}<section class="assessment" aria-label={it?'Dettaglio advisory':'Advisory details'}><div class="feed"><h3>{selected.binding.application_name}</h3><button class="text-button" onclick={()=>selected=null}>{it?'Chiudi dettagli advisory':'Close advisory details'}</button></div><p>{selected.binding.product_id} · {selected.binding.exact_version} · {stateLabel(selected)}</p>
      {#if selected.state==='metadata_changed'}<p class="warning">{it?'Nome, editore o versione dichiarata sono cambiati. Piko sospende il confronto: verifica di nuovo l’associazione.':'Declared name, publisher or version changed. Piko suspends matching: check the binding again.'}</p>{/if}
      {#if selected.state==='no_known_advisory'}<p>{it?'Questo feed non contiene avvisi per la versione associata. Non dimostra che il software sia sicuro o privo di vulnerabilità.':'This feed contains no advisory for the bound version. It does not prove that the software is safe or free of vulnerabilities.'}</p>{/if}
      {#each matches.slice(advisoryPage*5,advisoryPage*5+5) as advisory (advisory.id)}<article class="advisory"><div class="feed"><strong>{advisory.title}</strong><span class="score" class:critical={advisoryLevel(advisory)==='critical'} class:high={advisoryLevel(advisory)==='high'}>{advisory.kind==='end_of_support'?(it?'Fine supporto':'End of support'):advisory.cvss_x100===null?(it?'CVSS sconosciuto':'Unknown CVSS'):`CVSS ${advisory.cvss_version} ${(advisory.cvss_x100/100).toFixed(1)}/10`}</span></div><small>{advisory.id} · {date(advisory.published_at)}</small><p>{advisory.summary}</p><details><summary>{it?'Azioni suggerite e fonte':'Suggested actions and source'}</summary><ul>{#each advisory.remediation as action}<li>{action}</li>{/each}</ul><p class="source-url">{advisory.source_url}</p>{#if advisory.cvss_vector}<p class="reading">{it?'Vettore dichiarato dalla fonte; piko non ricalcola il punteggio. CVSS appartiene a FIRST ed è usato con permesso.':'Source-declared vector; piko does not recalculate the score. CVSS is owned by FIRST and used by permission.'}</p><code>{advisory.cvss_vector}</code>{/if}<p class="reading">{it?'Indicazioni della fonte da verificare. Puoi usare le sezioni rete e sandbox di piko per mitigazioni manuali; qui non viene applicato alcun blocco o aggiornamento.':'Check the source’s guidance. Use piko’s network and sandbox sections for manual mitigations; this section does not apply blocks or updates.'}</p></details></article>{/each}
      {#if matchPages>1}<div class="pager"><button class="text-button" disabled={advisoryPage===0} onclick={()=>advisoryPage--}>{it?'Avvisi precedenti':'Previous advisories'}</button><span>{advisoryPage+1}/{matchPages}</span><button class="text-button" disabled={advisoryPage>=matchPages-1} onclick={()=>advisoryPage++}>{it?'Avvisi successivi':'Next advisories'}</button></div>{/if}
      <div class="toolbar">{#if matches.length&&apps.some(a=>a.id===selected?.binding.application_id)}<button class="button secondary small" disabled={busy} onclick={()=>selected&&onOpenNetwork?.(selected.binding.application_id)}>{it?`Prepara blocco rete per ${selected.binding.application_name}`:`Prepare network block for ${selected.binding.application_name}`}</button>{/if}<button class="button secondary small" disabled={busy||!apps.some(a=>a.id===selected?.binding.application_id)||!snapshot.feed} onclick={()=>selected&&review(selected)}>{it?'Ricontrolla associazione':'Review binding'}</button><button class="text-button" disabled={busy} onclick={()=>selected&&remove(selected.binding.application_id)}>{it?'Rimuovi associazione':'Remove binding'}</button></div>
    </section>{/if}
    {#if !filtered.length&&snapshot.entries.length}<p>{it?'Nessuna app associata corrisponde alla ricerca.':'No bound app matches the search.'}</p>{/if}
  {/if}
  <p class="reading">{it?'Solo confronto offline su versioni esatte. Nessuna scansione CVE automatica, verifica dei binari, upload, download o patch. App portatili e prodotti non associati restano fuori dal confronto.':'Offline exact-version comparison only. No automatic CVE scan, binary verification, upload, download or patch. Portable apps and unbound products remain outside the comparison.'}</p>
</details>
<style>
  .advisory-panel{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;min-width:0}summary{cursor:pointer;font-size:.85rem}p{font-size:.8rem;color:var(--muted);line-height:1.65;margin:12px 0}.toolbar,.feed,.pager{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.toolbar{margin:18px 0}.feed strong,h3{font-size:.88rem;margin:0}.feed span,.reading,small{font-size:.73rem;color:var(--muted)}.source{margin-top:12px}.source-url,code{overflow-wrap:anywhere;font-size:.72rem}label{display:grid;gap:8px;font-size:.76rem;min-width:0}input:not([type=checkbox]),select{width:100%;min-width:0;border:1px solid var(--border-strong);border-radius:8px;padding:10px;background:var(--surface);color:var(--text)}input[type=file]{max-width:360px}.binding,.assessment{border:1px solid var(--border);background:var(--surface-raised,var(--surface));padding:18px;border-radius:12px;margin:16px 0}.binding label{margin-top:15px}.confirmation{display:flex;align-items:start;line-height:1.6}.confirmation input{margin-top:4px}.search{margin:18px 0}.app-row{border-top:1px solid var(--border)}.row-button{width:100%;border:0;background:none;cursor:pointer;color:var(--text);display:grid;grid-template-columns:1fr auto;gap:8px;text-align:left;padding:16px 0;font:inherit}.row-button strong{font-size:.85rem;overflow-wrap:anywhere}.row-button span{font-size:.74rem;color:var(--muted)}.row-button small{grid-column:1/-1}.attention{color:var(--warning)!important}.warning{color:var(--warning);background:var(--warning-surface);padding:12px;border-radius:10px}.notice{color:var(--accent-ink)}.advisory{padding:18px 0;border-top:1px solid var(--border)}.advisory details{margin-top:12px}.score{border-radius:12px;background:var(--accent-soft);padding:5px 9px;color:var(--accent-ink)!important;white-space:nowrap}.score.high{background:var(--warning-surface);color:var(--warning)!important}.score.critical{background:var(--danger-surface);color:var(--danger)!important}ul{font-size:.8rem;color:var(--text);line-height:1.7;padding-left:20px}.pager{font-size:.76rem;margin-top:16px}.button{white-space:normal}@media(max-width:650px){.advisory-panel{padding:18px}.row-button{grid-template-columns:1fr}.row-button small{grid-column:auto}}
</style>
