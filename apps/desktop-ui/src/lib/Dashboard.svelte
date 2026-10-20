<script lang="ts">
  import { onMount } from 'svelte';
  import Icon from './Icon.svelte';
  import AlertGroups from './AlertGroups.svelte';
  import { groupAlerts } from './alertGroups';
  import { listAlerts, responseStatus, listAlertReviews } from './api';
  import type { Alert, AlertReview, HealthSnapshot, ResponseStatus } from './api';
  import type { Language } from './i18n';
  import { formatTime } from './format';
  import { maximumRisk } from './insights';

  let { language, health, connected, onNavigate }: {
    language: Language; health: HealthSnapshot | null; connected: boolean;
    onNavigate: (page: 'protection' | 'securityLog' | 'capabilities' | 'guide' | 'settings') => void;
  } = $props();
  const it = $derived(language === 'it');
  let alerts = $state<Alert[]>([]);
  let actions = $state<ResponseStatus | null>(null);
  let alertsReadAt = $state<number | null>(null);
  let alertsError = $state('');
  let actionsError = $state('');
  let loading = $state(false);
  let priority = $state('all');
  let reviewFilter = $state('open');
  let reviews = $state<Record<string,AlertReview>>({});
  let reviewError = $state('');
  const reviewed = $derived(alerts.filter(a=>['expected','handled'].includes(reviews[a.id]?.state??'open')).length);
  const reviewFiltered = $derived(reviewError || reviewFilter==='all' ? alerts : alerts.filter(a=>reviewFilter==='open' ? !['expected','handled'].includes(reviews[a.id]?.state??'open') : ['expected','handled'].includes(reviews[a.id]?.state??'open')));
  function reviewedSaved(value:AlertReview){reviews={...reviews,[value.alert_id]:value};}
  let active = true;
  const high = $derived(alerts.filter(a => ['high', 'critical'].includes(a.severity)).length);
  const risk = $derived(maximumRisk(alerts));
  const groups = $derived(groupAlerts(alerts));
  const filtered = $derived(priority === 'all' ? reviewFiltered : reviewFiltered.filter(a => priority === 'high' ? ['high', 'critical'].includes(a.severity) : !['high', 'critical'].includes(a.severity)));
  const windowsSources = $derived(['System', 'Application', 'Security', 'Microsoft-Windows-Windows Defender/Operational'].map(name => ({
    name,
    state: health?.sensors.find(s => s.id === `windows.event_log.${name}`)?.state ?? 'unknown',
  })));
  const available = $derived(windowsSources.filter(s => ['active', 'healthy', 'running', 'available'].includes(s.state)).length);
  const partial = $derived(available < 4 || !['healthy', 'active', 'protected'].includes(health?.protection_state ?? '') || (health?.dropped_events ?? 0) > 0);
  const uncertain = $derived(actions?.actions.filter(a => ['uncertain', 'executing', 'backup_ready'].includes(a.status)) ?? []);

  export async function refresh(): Promise<void> {
    if (loading) return;
    loading = true;
    await Promise.allSettled([
      listAlerts().then(value => { if (active) { alerts = value; alertsReadAt = Date.now(); alertsError = ''; } }).catch(e => { if (active) alertsError = String(e); }),
      listAlertReviews().then(value=>{if(active){reviews=Object.fromEntries(value.map(v=>[v.alert_id,(reviews[v.alert_id]?.updated_at??0)>v.updated_at ? reviews[v.alert_id] : v]));reviewError='';}}).catch(e=>{if(active)reviewError=String(e);}),
      responseStatus().then(value => { if (active) { actions = value; actionsError = ''; } }).catch(e => { if (active) actionsError = String(e); }),
    ]);
    loading = false;
  }
  onMount(() => { active = true; void refresh(); return () => { active = false; }; });
</script>

<div class="dashboard" data-testid="security-dashboard">
  <section class="coverage-banner" class:warning={connected && partial} aria-labelledby="coverage-title">
    <Icon name={connected ? 'shield' : 'link'} size={23} />
    <div><h2 id="coverage-title">{!connected ? (it ? 'Dati non disponibili' : 'Data unavailable') : partial ? (it ? 'Visibilità parziale' : 'Partial visibility') : (it ? 'Registri disponibili' : 'Logs available')}</h2><p>{!connected ? (it ? 'Collega il runtime per leggere le segnalazioni.' : 'Connect the runtime to read alerts.') : (it ? available + '/4 registri Windows · 12 regole disponibili' : available + '/4 Windows logs · 12 available rules')}</p></div>
    <button class="text-button" onclick={() => onNavigate('settings')}>{it ? 'Stato sorgenti' : 'Source status'} <Icon name="arrow" size={15} /></button>
  </section>
  {#if connected && (health?.dropped_events ?? 0) > 0}<p class="inline-warning" role="status">{health?.dropped_events} {it ? 'eventi persi · raccolta incompleta.' : 'events lost · incomplete collection.'}</p>{/if}
  <section class="dashboard-stats" aria-label={it ? 'Segnalazioni disponibili' : 'Available alerts'}>
    <button class="metric" class:urgent={high > 0 && !alertsError} aria-pressed={priority === 'high'} onclick={() => priority = priority === 'high' ? 'all' : 'high'}><span>{it ? 'Priorità alta' : 'High priority'}</span><strong class="priority-count">{alertsReadAt === null || alertsError ? '—' : high}</strong><small>{it ? 'Eventi da verificare' : 'Events to review'}</small></button>
    <button class="metric" aria-pressed={priority === 'all'} onclick={() => priority = 'all'}><span>{it ? 'Gruppi di eventi' : 'Event groups'}</span><strong>{alertsReadAt === null || alertsError ? '—' : groups.length}</strong><small>{alertsReadAt !== null && !alertsError ? alerts.length : '—'} {it ? 'eventi nelle ultime 100 segnalazioni' : 'events in the latest 100 alerts'}</small></button>
    <div class="metric risk-metric" class:urgent={!alertsError && risk !== null && risk.score >= 60}><span>{it ? 'Indice massimo osservato' : 'Highest observed index'}</span><strong data-testid="maximum-risk">{alertsReadAt === null || alertsError || !risk ? '—' : risk.score + '/100'}</strong><small>{it ? 'Euristico · non è una probabilità' : 'Heuristic · not a probability'}</small></div>
  </section>
  <section class="panel important-panel" aria-labelledby="important-title">
    <div class="panel-heading"><div><h2 id="important-title">{it ? 'Eventi importanti' : 'Important events'}</h2><p>{it ? 'Raggruppati per tipo. Apri un gruppo per esaminare i singoli eventi.' : 'Grouped by type. Open a group to inspect its events.'}</p></div><label class="priority-filter"><span class="sr-only">{it ? 'Mostra' : 'Show'}</span><select aria-label={it ? 'Mostra' : 'Show'} bind:value={priority}><option value="all">{it ? 'Tutte le priorità' : 'All priorities'}</option><option value="high">{it ? 'Priorità alta' : 'High priority'}</option><option value="other">{it ? 'Altre segnalazioni' : 'Other alerts'}</option></select></label></div>
    <div class="review-filter"><label>{it?'Revisione':'Review'} <select aria-label={it?'Filtro revisione':'Review filter'} bind:value={reviewFilter}><option value="open">{it?'Da esaminare':'To review'}</option><option value="reviewed">{it?'Esaminati':'Reviewed'}</option><option value="all">{it?'Tutti':'All'}</option></select></label><span>{reviewed} {it?'attesi o gestiti · ultime 100 segnalazioni':'expected or handled · latest 100 alerts'}</span></div>
    {#if reviewError}<p class="inline-warning" role="status">{it?'Valutazioni non aggiornate: tutti gli eventi restano visibili.':'Reviews not refreshed: all events remain visible.'}</p>{/if}
    {#if alertsError}<div class="inline-warning" role="status"><strong>{it ? 'Segnalazioni non aggiornate' : 'Alerts not refreshed'}</strong><p>{alertsReadAt ? (it ? 'I dati sotto provengono dall’ultima lettura riuscita.' : 'Data below is from the last successful reading.') : (it ? 'Il numero di segnalazioni è sconosciuto.' : 'The alert count is unknown.')}</p><details><summary>{it ? 'Dettagli tecnici' : 'Technical details'}</summary><code>{alertsError}</code></details></div>{/if}
    <AlertGroups alerts={filtered} {language} {reviews} onReview={reviewedSaved} />
    {#if !filtered.length && alertsReadAt !== null && !alertsError}<div class="empty-state"><h3>{priority === 'all' && (reviewFilter==='all'||alerts.length===0) ? (it ? 'Nessuna segnalazione nelle regole disponibili' : 'No alerts from available rules') : (it ? 'Nessuna segnalazione per questo filtro' : 'No alerts match this filter')}</h3><p>{it ? 'L’assenza di segnalazioni non garantisce l’assenza di minacce.' : 'No alerts does not guarantee there are no threats.'}</p></div>
    {:else if !filtered.length && !alertsError}<p class="panel-footer" role="status">{it ? 'Lettura delle segnalazioni…' : 'Reading alerts…'}</p>{/if}
    <div class="panel-footer"><span>{it ? 'Ultima lettura: ' : 'Last read: '}{formatTime(alertsReadAt, language, '—')}</span><span>{it ? 'I gruppi non sono incidenti accertati.' : 'Groups are not confirmed incidents.'}</span></div>
  </section>
  {#if uncertain.length}<div class="action-notice" role="status"><span>{uncertain.length} {it ? 'operazioni con esito da verificare' : 'operations need outcome review'}</span><button class="text-button" onclick={() => onNavigate('protection')}>{it ? 'Apri registro azioni' : 'Open action journal'} →</button></div>{/if}
  {#if actionsError}<p class="inline-warning">{it ? 'Registro azioni non aggiornato.' : 'Action journal not refreshed.'}</p>{/if}
  <div class="dashboard-shortcuts"><button class="text-button" onclick={() => onNavigate('protection')}><Icon name="shield" size={16} />{it ? 'Quarantena e ripristino' : 'Quarantine and recovery'}</button><button class="text-button" onclick={() => onNavigate('securityLog')}><Icon name="terminal" size={16} />{it ? 'Log tecnici' : 'Technical logs'}</button><button class="text-button" onclick={() => onNavigate('guide')}><Icon name="info" size={16} />{it ? 'Manuale' : 'User guide'}</button></div>
</div>

<style>
  .review-filter {display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 22px;font-size:.72rem;color:var(--muted);flex-wrap:wrap}.review-filter select{font-size:.72rem;padding:6px 8px;}
  .dashboard { display: grid; gap: 18px; }
  .coverage-banner { display: flex; align-items: center; gap: 14px; padding: 15px 20px; background: var(--accent-soft); border: 1px solid var(--border-strong); border-radius: 14px; }
  .coverage-banner.warning { background: var(--warning-surface); border-color: var(--warning-border);  }
  .coverage-banner > div { flex: 1; }
  .coverage-banner h2 { font-size: .95rem; } .coverage-banner p { font-size: .73rem; color: var(--muted); margin-top: 4px; }
  .coverage-banner button { white-space: nowrap; font-size: .74rem; }
  .dashboard-stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
  .metric { display: grid; text-align: left; gap: 7px; padding: 16px 20px; border: 1px solid var(--border); border-radius: 16px; background: var(--surface); color: var(--text); }
  .metric.urgent { border-color: transparent; background: var(--danger-soft); } .metric.urgent strong { color: var(--danger); }
  .metric[aria-pressed='true'] { border-color: var(--accent); box-shadow: none; }
  .metric > span { font-size: .76rem; color: var(--muted); }
  .metric strong { font-size: 1.8rem; line-height: 1.15; font-weight: 650; }
  .metric small { font-size: .66rem; color: var(--muted); }
  .important-panel { min-width: 0; }
  .important-panel .panel-heading { gap: 14px; padding: 18px 22px; }
  .important-panel .panel-heading p { font-size: .74rem; }
  .priority-filter select { font-size: .74rem; padding: 7px 10px; }
  .panel-footer { display: flex; justify-content: space-between; gap: 10px; flex-wrap: wrap; font-size: .66rem; }
  .dashboard-shortcuts { display: flex; justify-content: flex-end; flex-wrap: wrap; gap: 24px; }
  .dashboard-shortcuts button { font-size: .74rem; }
  .action-notice { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 12px 18px; background: var(--warning-surface); border: 1px solid var(--warning-border); border-radius: 8px; font-size: .78rem; }
  @media(max-width: 650px) { .dashboard { gap: 14px; } .dashboard-stats { gap: 8px; } .metric { padding: 12px 10px; } .metric strong { font-size: 1.4rem; } .metric small { font-size: .62rem; } .metric > span { font-size: .7rem; } .coverage-banner { padding: 12px; gap: 10px; flex-wrap: wrap; } .coverage-banner > div { min-width: 170px; } .important-panel .panel-heading { padding: 16px 14px; flex-wrap: wrap; } .dashboard-shortcuts { gap: 16px; justify-content: flex-start; } }
</style>
