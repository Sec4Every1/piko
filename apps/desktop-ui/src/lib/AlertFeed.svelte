<script lang="ts">
  import AuthenticationEvidence from './AuthenticationEvidence.svelte';
  import { supportedAssessment } from './insights';
  import { onDestroy } from 'svelte';
  import { isTauri } from '@tauri-apps/api/core';
  import { getEvidence, openAttackReference } from './api';
  import type { Alert, AlertReview } from './api';
  import type { Language } from './i18n';
  import { interpretAlert, sortAlerts, summarizeEvidence, assessmentFacts, riskInsight, ATTACK_REVIEWED_AT } from './insights';
  import type { AttackReference } from './insights';
  import { formatTime, downloadJson } from './format';

  let { alerts, language, compact = false, review }: { alerts: Alert[]; language: Language; compact?: boolean; review?: AlertReview } = $props();
  const italian = $derived(language === 'it');
  const ordered = $derived(sortAlerts(alerts));
  let evidence = $state<Record<string, { loading: boolean; loaded: boolean; text: string; error: string }>>(Object.create(null));
  let references = $state<Record<string, { loading: boolean; error: string }>>(Object.create(null));
  let exportError = $state('');
  function exportAlert(alert: Alert) {
    exportError = '';
    try {
      const raw = alert.evidence_id ? evidence[alert.evidence_id] : undefined;
      downloadJson(JSON.stringify({ product: 'piko', export_schema_version: 1, kind: 'alert_detail', exported_at: new Date().toISOString(), language,
        alert, manual_review: review?.alert_id===alert.id ? review : null, interpretation: interpretAlert(alert, language), risk: riskInsight(alert, language), false_positive_probability: null,
        raw_evidence: { id: alert.evidence_id, state: raw?.loaded ? 'loaded' : raw?.error ? 'error' : raw?.loading ? 'loading' : alert.evidence_id ? 'not_loaded' : 'not_referenced', content: raw?.loaded ? raw.text : null },
        integrity: 'unsigned_export', risk_meaning: 'heuristic_priority_not_probability'
      }, null, 2), 'alert');
    } catch(e) { exportError = String(e); }
  }
  let mounted = true;
  onDestroy(() => { mounted = false; });

  function isoTime(value: number): string | undefined {
    return Number.isFinite(value) && Math.abs(value) <= 8.64e15 ? new Date(value).toISOString() : undefined;
  }

  function priorityLabel(severity: string): string {
    if (severity === 'critical' || severity === 'high') return italian ? 'Da verificare subito' : 'Review promptly';
    if (severity === 'medium') return italian ? 'Da approfondire' : 'Investigate';
    if (severity === 'low') return italian ? 'Da riconoscere' : 'Check familiarity';
    return italian ? 'Da esaminare' : 'Review';
  }
  function tone(severity: string): string {
    return ['critical', 'high', 'medium', 'low'].includes(severity) ? severity : 'info';
  }
  async function loadEvidence(id: string) {
    if (evidence[id]?.loading) return;
    evidence = { ...evidence, [id]: { loading: true, loaded: false, text: '', error: '' } };
    try {
      const text = await getEvidence(id);
      if (mounted) evidence = { ...evidence, [id]: { loading: false, loaded: true, text, error: '' } };
    } catch (error) {
      if (mounted) evidence = { ...evidence, [id]: { loading: false, loaded: false, text: '', error: String(error) } };
    }
  }
  async function openReference(event: MouseEvent, attack: AttackReference) {
    if (!isTauri()) return;
    event.preventDefault();
    if (references[attack.id]?.loading) return;
    references = { ...references, [attack.id]: { loading: true, error: '' } };
    try {
      await openAttackReference(attack.id);
      if (mounted) references = { ...references, [attack.id]: { loading: false, error: '' } };
    } catch (error) {
      if (mounted) references = { ...references, [attack.id]: { loading: false, error: String(error) } };
    }
  }
</script>

<div class="alert-feed" class:compact>
  {#if ordered.length === 0}
    <div class="no-alerts">
      <span class="empty-symbol" aria-hidden="true">—</span>
      <div><h3>{italian ? 'Nessuna segnalazione nelle regole disponibili' : 'No alerts from the available rules'}</h3>
        <p>{italian ? 'Le segnalazioni dipendono dai registri accessibili e dalle dodici regole disponibili. Un elenco vuoto non garantisce l’assenza di minacce.' : 'Alerts depend on accessible logs and the twelve available rules. An empty list does not guarantee the absence of threats.'}</p>
      </div>
    </div>
  {/if}
  {#each ordered as alert (alert.id)}
    {@const insight = interpretAlert(alert, language)}
    {@const risk = riskInsight(alert, language)}
    {@const knownFacts = assessmentFacts(alert, language)}
    <article class="alert-card {tone(alert.severity)}" data-alert-id={alert.id}>
      <div class="alert-topline"><span class="priority-chip">{priorityLabel(alert.severity)}</span><time datetime={isoTime(alert.event_time ?? alert.observed_at)}>{alert.event_time == null ? (italian ? 'Raccolto da piko' : 'Collected by piko') : (italian ? 'Evento Windows' : 'Windows event')} · {formatTime(alert.event_time ?? alert.observed_at, language)}</time></div>
      <h3>{insight.title}</h3>
      <p class="observed">{insight.observed}</p>
      {#if alert.rule_id === 'service-installed' && alert.rule_version === 1}
        <p class="attribution-note">{italian ? 'Processo che ha installato il servizio: non identificato. Il record 7045 descrive il servizio; non identifica il programma che lo ha creato.' : 'Process that installed the service: not identified. Record 7045 describes the service; it does not identify the program that created it.'}</p>
      {/if}
      {#if knownFacts.length}
        <dl class="named-context" aria-label={italian ? 'Nomi riportati nell’evento' : 'Names reported in the event'}>{#each knownFacts as fact}<div><dt>{fact.label}</dt><dd>{fact.value}</dd></div>{/each}</dl>
      {/if}
      <div class="assessment-summary">
        <div class="risk-index" class:elevated={risk !== null && risk.score >= 60}>
          <span>{italian ? 'Indice di rischio' : 'Risk index'}</span>
          <strong data-testid="risk-score">{risk ? `${risk.score}/100` : '—'}</strong>
          <small>{italian ? 'Euristico · non è una probabilità' : 'Heuristic · not a probability'}</small>
          {#if risk}<meter min="0" max="100" value={risk.score} aria-label={italian ? 'Indice di rischio euristico' : 'Heuristic risk index'}>{risk.score}/100</meter>{/if}
        </div>
        <div class="false-positive"><span>{italian ? 'Probabilità di falso positivo' : 'False-positive probability'}</span><strong>{italian ? 'Non stimabile' : 'Not estimable'}</strong><small>{italian ? 'Mancano dati di validazione con esiti accertati.' : 'Validation data with confirmed outcomes is unavailable.'}</small></div>
      </div>
      {#if supportedAssessment(alert)?.context.failed_logons}<AuthenticationEvidence summary={supportedAssessment(alert)!.context.failed_logons!} {language} />{/if}
      <details class="score-detail">
        <summary>{italian ? 'Come leggere questo indice' : 'How to read this index'}</summary>
        {#if risk}
          <p>{italian ? 'Modello piko-risk-v1. Somma dei fattori qui sotto, limitata tra 0 e 100: aiuta a scegliere cosa verificare prima. I pesi sono scelte del modello, non frequenze misurate di attacco.' : 'Model piko-risk-v1. Sum of the factors below, bounded between 0 and 100: helps choose what to review first. Weights are model choices, not measured attack frequencies.'}</p>
          <ul class="score-factors">{#each risk.factors as factor}<li><span>{factor.label}</span><strong>{factor.points > 0 ? '+' : ''}{factor.points}</strong></li>{/each}</ul>
          <p>{risk.evidenceNote}</p>
        {:else}<p>{italian ? 'Il runtime non ha fornito una valutazione compatibile con questa regola e versione. Nessun indice viene inventato.' : 'The runtime supplied no assessment compatible with this rule and version. No index is invented.'}</p>{/if}
        <p>{italian ? 'Un valore 70/100 non significa il 70% di probabilità di attacco. La probabilità di falso positivo richiede casi verificati e un modello calibrato; non si ottiene sottraendo l’indice da 100. Un valore basso non certifica che il file o il PC siano sicuri.' : 'A value of 70/100 does not mean a 70% chance of attack. False-positive probability requires verified cases and a calibrated model; it is not 100 minus this index. A low value does not establish that the file or PC is safe.'}</p>
      </details>
      {#if alert.event_time == null}<p class="context">{italian ? 'Il runtime non ha fornito l’orario originale: quello mostrato è l’orario di raccolta. Verifica la data Windows nell’evidenza prima di confrontarla con un intervento.' : 'The runtime did not provide the original event time: the time shown is collection time. Check the Windows timestamp in the evidence before comparing it with a change.'}</p>{/if}
      <p class="impact"><strong>{italian ? 'Perché conta.' : 'Why it matters.'}</strong> {insight.why}</p>
      <p class="context">{insight.expected}</p>

      <details class="guided-detail" open={!compact}>
        <summary>{italian ? 'Cosa puoi fare' : 'What you can do'}</summary>
        <p class="manual-label">{italian ? 'Passi suggeriti da svolgere manualmente. Nessuna correzione è stata eseguita.' : 'Suggested steps to carry out manually. No correction has been performed.'}</p>
        <ol>{#each insight.nextSteps as step}<li>{step}</li>{/each}</ol>
      </details>

      <details class="mapping-detail">
        <summary><span>MITRE ATT&amp;CK</span>{#if insight.attack}<span class="technique-chip">{insight.attack.id}</span>{/if}<span class="mapping-caption">{italian ? 'Contesto da verificare' : 'Context to verify'}</span></summary>
        <p>{insight.mappingContext}</p>
        {#if insight.attack}
          <p class="technique-name"><strong>{insight.attack.name}</strong> · {insight.attack.tactics.join(' / ')}</p>
          <a href={insight.attack.url} target="_blank" rel="noopener noreferrer" onclick={event => openReference(event, insight.attack!)} aria-busy={references[insight.attack.id]?.loading ?? false}>{italian ? 'Apri il riferimento ufficiale MITRE' : 'Open the official MITRE reference'} ↗</a>
          {#if references[insight.attack.id]?.error}
            <p class="reference-error" role="alert">{italian ? 'Non è stato possibile aprire il browser. Puoi copiare questo indirizzo nel tuo browser:' : 'The browser could not be opened. You can copy this address into your browser:'} <code>{insight.attack.url}</code></p>
          {/if}
          <p class="catalog-note">{italian ? 'Mappatura verificata il' : 'Mapping reviewed on'} {ATTACK_REVIEWED_AT}. {italian ? 'Il riferimento descrive una tecnica, non conferma un attacco su questo PC.' : 'The reference describes a technique; it does not confirm an attack on this PC.'}</p>
        {/if}
      </details>

      <details class="evidence-detail">
        <summary>{italian ? 'Dettagli dell’evento' : 'Event details'}</summary>
        <p>{italian ? 'Leggi i dati riportati da Windows, per riconoscere l’operazione. I campi mancanti non vengono ricostruiti.' : 'Read the information reported by Windows to help recognize the operation. Missing fields are not reconstructed.'}</p>
        {#if alert.evidence_id}
          <button class="button secondary small" onclick={() => loadEvidence(alert.evidence_id!)} disabled={evidence[alert.evidence_id]?.loading}>
            {evidence[alert.evidence_id]?.loading ? (italian ? 'Lettura…' : 'Loading…') : (italian ? 'Leggi i dettagli dell’evento' : 'Read event details')}
          </button>
          {#if evidence[alert.evidence_id]?.error}<p class="evidence-error" role="alert">{italian ? 'Non è stato possibile leggere l’evidenza. Puoi riprovare.' : 'The evidence could not be read. You can try again.'} {evidence[alert.evidence_id].error}</p>{/if}
          {#if evidence[alert.evidence_id]?.loaded}
            {@const facts = summarizeEvidence(evidence[alert.evidence_id].text, alert, language)}
            {#if facts.length}
              <dl class="event-facts" aria-label={italian ? 'Informazioni riportate da Windows' : 'Information reported by Windows'}>{#each facts as fact}<div><dt>{fact.label}</dt><dd>{fact.value}</dd></div>{/each}</dl>
              <p class="source-note">{italian ? 'Valori dell’evidenza originale. Nomi e percorsi non attestano la sicurezza di un programma; eventuali codici Windows richiedono una verifica tecnica.' : 'Values from original evidence. Names and paths do not establish that a program is safe; Windows codes may need technical review.'}</p>
            {:else}<p>{italian ? 'Questo record non contiene campi leggibili nel formato supportato. L’evidenza originale rimane disponibile qui sotto per l’assistenza tecnica.' : 'This record has no readable fields in the supported format. The original evidence remains available below for technical assistance.'}</p>{/if}
          {/if}
        {:else}<p>{italian ? 'Il runtime non ha fornito un riferimento all’evidenza originale.' : 'The runtime did not provide a reference to original evidence.'}</p>{/if}
        <details class="technical-detail">
          <summary>{italian ? 'XML originale e riferimenti tecnici' : 'Original XML and technical references'}</summary>
          <dl><div><dt>{italian ? 'Regola' : 'Rule'}</dt><dd>{alert.rule_id} · v{alert.rule_version}</dd></div><div><dt>{italian ? 'ID evento' : 'Event ID'}</dt><dd><code>{alert.event_id}</code></dd></div>{#if alert.evidence_id}<div><dt>{italian ? 'ID evidenza' : 'Evidence ID'}</dt><dd><code>{alert.evidence_id}</code></dd></div>{/if}</dl>
          <p>{insight.evidenceFields}</p>
          {#if alert.evidence_id && evidence[alert.evidence_id]?.loaded}
            {#if evidence[alert.evidence_id]?.text}
              <!-- svelte-ignore a11y_no_noninteractive_tabindex (Scrollable evidence must be reachable and scrollable with a keyboard.) -->
              <pre class="source-evidence" role="region" tabindex="0" aria-label={italian ? 'XML originale' : 'Original XML'}>{evidence[alert.evidence_id].text}</pre>
            {:else}<p>{italian ? 'L’evidenza restituita è vuota.' : 'The returned evidence is empty.'}</p>{/if}
          {:else}<p>{italian ? 'Carica i dettagli dell’evento per consultare l’XML disponibile.' : 'Load event details to view available XML.'}</p>{/if}
        </details>
      </details>
      <div class="export-row"><button class="button secondary small" onclick={() => exportAlert(alert)}>{italian ? 'Esporta segnalazione JSON' : 'Export alert JSON'}</button><span>{italian ? 'Include l’evidenza grezza solo se caricata. Esportazione non firmata.' : 'Includes raw evidence only when loaded. Unsigned export.'}</span></div>
      {#if exportError}<p role="alert">{exportError}</p>{/if}
    </article>
  {/each}
</div>

<style>
  .export-row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-top: 20px; } .export-row span { color: var(--muted); font-size: .72rem; }
  .alert-feed { display: grid; gap: 16px; }
  .alert-card { --priority: var(--accent-ink); --priority-soft: var(--accent-soft); min-width: 0; padding: 22px 24px; border: 1px solid var(--border); border-left: 4px solid var(--priority); border-radius: 12px; background: var(--surface); }
  .alert-card.high, .alert-card.critical { --priority: var(--danger); --priority-soft: var(--danger-soft); }
  .alert-card.medium { --priority: var(--warning); --priority-soft: var(--warning-surface); }
  .alert-topline { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 13px; }
  .priority-chip { color: var(--priority); background: var(--priority-soft); border: 1px solid var(--priority); font-size: .68rem; font-weight: 650; padding: 4px 9px; border-radius: 5px; }
  time { color: var(--muted); font-size: .71rem; }
  h3 { font-size: 1.05rem; line-height: 1.4; letter-spacing: -.2px; }
  p { font-size: .8rem; line-height: 1.65; }
  .observed { margin-top: 10px; }
  .observed, h3 { overflow-wrap: anywhere; unicode-bidi: plaintext; }
  .attribution-note { color: var(--muted); font-size: .73rem; margin-top: 8px; }
  .named-context { padding: 9px 14px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface-subtle); }
  .named-context > div { grid-template-columns: minmax(140px, 1fr) 2fr; }
  .named-context dd { unicode-bidi: plaintext; white-space: pre-wrap; }
  .assessment-summary { display: grid; grid-template-columns: 1fr 1.3fr; gap: 12px; margin: 16px 0; }
  .assessment-summary > div { display: flex; align-items: flex-start; flex-direction: column; gap: 7px; padding: 13px 15px; background: var(--surface-subtle); border: 1px solid var(--border); border-radius: 8px; }
  .assessment-summary span { font-size: .72rem; color: var(--muted); }
  .assessment-summary strong { font-size: 1.08rem; }
  .assessment-summary small { color: var(--muted); font-size: .68rem; line-height: 1.6; }
  .risk-index strong { color: var(--accent-ink); }
  .risk-index.elevated strong { color: var(--danger); }
  meter { width: 100%; height: 8px; accent-color: var(--accent); }
  meter::-webkit-meter-bar { background: var(--border); border: 0; }
  meter::-webkit-meter-optimum-value { background: var(--accent); }
  meter::-moz-meter-bar { background: var(--accent); }
  .elevated meter { accent-color: var(--danger); }
  .elevated meter::-webkit-meter-optimum-value { background: var(--danger); }
  .elevated meter::-moz-meter-bar { background: var(--danger); }
  .score-detail p { color: var(--muted); font-size: .73rem; margin: 10px 0; }
  .score-factors { list-style: none; margin: 10px 0; padding: 0; }
  .score-factors li { display: flex; justify-content: space-between; align-items: start; gap: 14px; padding: 7px 0; margin: 0; border-bottom: 1px solid var(--border); font-size: .74rem; }
  .score-factors strong { color: var(--accent-ink); font-variant-numeric: tabular-nums; }
  .impact { margin-top: 8px; }
  .impact strong { font-weight: 650; }
  .context { color: var(--muted); font-size: .75rem; margin: 10px 0 17px; }
  details { border-top: 1px solid var(--border); padding-top: 12px; margin-top: 12px; }
  summary { line-height: 1.7; font-size: .77rem; }
  .manual-label { color: var(--muted); font-size: .73rem; margin: 8px 0; }
  ol { padding-left: 22px; margin: 10px 0 4px; }
  li { font-size: .79rem; line-height: 1.65; padding-left: 4px; margin: 8px 0; }
  li::marker { color: var(--accent-ink); font-weight: 650; }
  .technique-chip { color: var(--accent-ink); background: var(--accent-soft); border-radius: 4px; padding: 3px 6px; margin-left: 9px; font-size: .66rem; font-family: 'Cascadia Code', 'Consolas', monospace; }
  .mapping-caption { font-weight: 400; font-size: .71rem; color: var(--muted); margin-left: 8px; }
  .technique-name { margin: 10px 0; }
  a { color: var(--accent-ink); font-size: .76rem; text-underline-offset: 3px; }
  .catalog-note { font-size: .7rem; color: var(--muted); margin-top: 10px; }
  .reference-error { color: var(--danger); overflow-wrap: anywhere; margin-top: 10px; }
  dl { margin: 8px 0 12px; }
  dl > div { display: grid; grid-template-columns: 90px 1fr; gap: 14px; margin: 8px 0; font-size: .73rem; }
  dt { color: var(--muted); } dd { margin: 0; overflow-wrap: anywhere; }
  dd code { font-size: .71rem; }
  .event-facts { padding: 10px 15px; margin-top: 16px; border-radius: 8px; background: var(--surface-subtle); }
  .event-facts > div { grid-template-columns: minmax(140px, 1fr) 2fr; }
  .event-facts dd { white-space: pre-wrap; unicode-bidi: plaintext; }
  .source-note, .technical-detail p { color: var(--muted); font-size: .73rem; }
  .evidence-detail > p { color: var(--muted); font-size: .74rem; margin: 10px 0; }
  .evidence-detail .button { margin-top: 8px; }
  .evidence-detail .evidence-error { color: var(--danger); overflow-wrap: anywhere; }
  pre { white-space: pre-wrap; overflow-wrap: anywhere; }
  .no-alerts { display: flex; gap: 16px; padding: 26px; border: 1px dashed var(--border-strong); border-radius: 12px; background: var(--surface-subtle); }
  .no-alerts h3 { font-size: .94rem; }
  .no-alerts p { color: var(--muted); margin-top: 7px; font-size: .77rem; }
  .empty-symbol { display: flex; justify-content: center; align-items: center; flex: 0 0 32px; width: 32px; height: 32px; border: 1px solid var(--border-strong); border-radius: 8px; color: var(--muted); }
  .compact .alert-card { padding: 19px 21px; }
  @media (max-width: 740px) { .alert-card, .compact .alert-card { padding: 17px; } h3 { font-size: .95rem; } .mapping-caption { display: block; margin-left: 14px; } dl > div, .event-facts > div, .named-context > div { grid-template-columns: 1fr; gap: 4px; } .no-alerts { padding: 20px; } .assessment-summary { grid-template-columns: 1fr; } }
  @media (forced-colors: active) { .priority-chip, .technique-chip { border: 1px solid CanvasText; } }
</style>
