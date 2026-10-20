<script lang="ts">
  import { tick } from 'svelte';
  import Icon from './Icon.svelte';
  import AlertReviewPanel from './AlertReview.svelte';
  import AlertFeed from './AlertFeed.svelte';
  import type { Alert, AlertReview } from './api';
  import type { Language } from './i18n';
  import { groupAlerts, groupTitle, groupSubjects, type AlertGroup } from './alertGroups';
  import { interpretAlert } from './insights';
  import { formatTime } from './format';
  let { alerts, language, reviews = {}, onReview }: { alerts: Alert[]; language: Language; reviews?: Record<string,AlertReview>; onReview?: (value:AlertReview)=>void } = $props();
  const it = $derived(language === 'it');
  const groups = $derived(groupAlerts(alerts));
  let page = $state(0), selected = $state<AlertGroup | null>(null), index = $state(0);
  let dialog: HTMLDialogElement;
  const pages = $derived(Math.max(1, Math.ceil(groups.length / 5)));
  const currentPage = $derived(Math.min(page, pages - 1));
  const visible = $derived(groups.slice(currentPage * 5, currentPage * 5 + 5));
  const alert = $derived(selected?.alerts[index]);
  async function open(group: AlertGroup) {
    // Freeze this reading while the background dashboard refreshes.
    selected = { ...group, alerts: [...group.alerts] }; index = 0;
    await tick(); dialog.showModal();
  }
  function priority(severity: string) {
    return ['critical', 'high'].includes(severity) ? (it ? 'Alta' : 'High') : severity === 'medium' ? (it ? 'Media' : 'Medium') : (it ? 'Bassa' : 'Low');
  }
</script>

<div class="alert-groups" data-testid="alert-groups">
  {#each visible as group (group.key)}
    <button class="group-row {group.severity}" data-group-rule={group.ruleId} onclick={() => open(group)} aria-label={`${it ? 'Apri' : 'Open'}: ${groupTitle(group, language)} · ${group.alerts.length} ${it ? 'eventi' : 'events'}`}>
      <span class="group-mark"><Icon name={['high', 'critical'].includes(group.severity) ? 'warning' : 'activity'} size={19} /></span>
      <span class="group-copy"><strong>{groupTitle(group, language)}</strong><span class="group-subjects">{groupSubjects(group, language)}</span></span>
      <span class="group-count">{group.alerts.length}<small>{group.alerts.length === 1 ? (it ? 'evento' : 'event') : (it ? 'eventi' : 'events')}</small></span>
      <span class="group-priority">{priority(group.severity)}<small>{group.risk === null ? '—' : `${group.risk}/100`}</small></span>
      <Icon name="chevron" size={17} />
    </button>
  {/each}
  {#if pages > 1}<div class="group-pagination"><button class="text-button" disabled={currentPage === 0} onclick={() => page = currentPage - 1}>{it ? 'Precedenti' : 'Previous'}</button><span>{currentPage + 1} / {pages}</span><button class="text-button" disabled={currentPage + 1 === pages} onclick={() => page = currentPage + 1}>{it ? 'Successivi' : 'Next'}</button></div>{/if}
</div>

<dialog bind:this={dialog} class="alert-detail-dialog" aria-labelledby="alert-detail-title" onclose={() => { selected = null; }}>
  {#if selected && alert}
    <header class="detail-heading"><div><span class="eyebrow">{it ? 'DETTAGLIO EVENTO' : 'EVENT DETAILS'}</span><h2 id="alert-detail-title">{groupTitle(selected, language)}</h2><p>{selected.alerts.length} {it ? 'eventi dello stesso tipo · raggruppamento, non un incidente accertato' : 'events of the same type · a grouping, not a confirmed incident'}</p></div><button class="icon-button" aria-label={it ? 'Chiudi dettaglio' : 'Close details'} onclick={() => dialog.close()}><Icon name="close" size={22} /></button></header>
    <div class="occurrence-bar"><label for="alert-occurrence">{it ? 'Occorrenza' : 'Occurrence'} {index + 1} / {selected.alerts.length}</label><select id="alert-occurrence" bind:value={index}>{#each selected.alerts as item, i}<option value={i}>{formatTime(item.event_time ?? item.observed_at, language)} · {interpretAlert(item, language).title}</option>{/each}</select><div><button class="icon-button" aria-label={it ? 'Evento precedente' : 'Previous event'} disabled={index === 0} onclick={() => index--}>←</button><button class="icon-button" aria-label={it ? 'Evento successivo' : 'Next event'} disabled={index + 1 === selected.alerts.length} onclick={() => index++}>→</button></div></div>
    <div class="detail-body">{#key alert.id}<AlertFeed alerts={[alert]} {language} review={reviews[alert.id]} />{#if onReview}<AlertReviewPanel alertId={alert.id} review={reviews[alert.id]} {language} onSaved={onReview} />{/if}{/key}</div>
  {/if}
</dialog>

<style>
  .group-row { display: flex; align-items: center; gap: 16px; width: 100%; padding: 17px 22px; border: 0; border-bottom: 1px solid var(--border); background: transparent; text-align: left; color: var(--text); --tone: var(--accent-ink); --tone-soft: var(--accent-soft);  }
  .group-row:hover { background: var(--surface-subtle); }
  .group-row.high, .group-row.critical { --tone: var(--danger); --tone-soft: var(--danger-soft); }
  .group-row.medium { --tone: var(--warning); --tone-soft: var(--warning-surface); }
  .group-mark { color: var(--tone); display: flex; background: var(--tone-soft); padding: 9px; border-radius: 10px; }
  .group-copy { flex: 1; min-width: 0; }
  .group-copy strong { display: block; font-size: .87rem; line-height: 1.4; overflow-wrap: anywhere; }
  .group-subjects { display: block; margin-top: 5px; font-size: .73rem; color: var(--muted); overflow: hidden; white-space: nowrap; text-overflow: ellipsis; unicode-bidi: plaintext; }
  .group-count, .group-priority { display: grid; gap: 4px; text-align: right; font-size: .85rem; flex-shrink: 0; min-width: 42px; }
  .group-priority { color: var(--tone); font-weight: 650; background: var(--tone-soft); border-radius: 12px; padding: 7px 10px; } .group-priority small { color: inherit; font-weight: 600; }
  small { color: var(--muted); font-size: .66rem; font-weight: 400; }
  .group-pagination { display: flex; justify-content: space-between; padding: 12px 22px; font-size: .75rem; }
  .alert-detail-dialog { width: min(900px, calc(100vw - 32px)); max-width: none; height: min(900px, 90dvh); max-height: 90dvh; padding: 0; border: 1px solid var(--border-strong); border-radius: 16px; color: var(--text); background: var(--surface); }
  .alert-detail-dialog[open] { display: flex; flex-direction: column; }
  .alert-detail-dialog::backdrop { background: rgb(12 20 34 / .6); backdrop-filter: blur(3px); }
  .detail-heading { display: flex; align-items: start; justify-content: space-between; gap: 16px; padding: 22px 24px 15px; flex-shrink: 0; }
  .detail-heading h2 { font-size: 1.2rem; margin: 6px 0; overflow-wrap: anywhere; }
  .detail-heading p { font-size: .72rem; color: var(--muted); }
  .occurrence-bar { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; padding: 12px 24px; border-block: 1px solid var(--border); background: var(--surface-subtle); flex-shrink: 0; }
  .occurrence-bar label { font-size: .73rem; color: var(--muted); }
  .occurrence-bar select { flex: 1; min-width: 0; max-width: 100%; font-size: .75rem; }
  .occurrence-bar > div { display: flex; }
  .detail-body { overflow-y: auto; min-height: 0; padding: 20px 24px; overscroll-behavior: contain; }
  @media(max-width: 650px) { .group-row { gap: 10px; padding: 14px; } .group-mark { display: none; } .group-copy strong { font-size: .8rem; } .group-count, .group-priority { min-width: 34px; } .detail-heading { padding: 18px 16px 12px; } .occurrence-bar { padding: 10px 16px; } .occurrence-bar label { flex-basis: 100%; } .detail-body { padding: 12px; } }
</style>
