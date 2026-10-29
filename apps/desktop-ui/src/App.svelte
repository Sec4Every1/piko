<script lang="ts">
  import { onMount, tick } from 'svelte';
  import StartupSettings from './lib/StartupSettings.svelte';
  import RuntimePerformance from './lib/RuntimePerformance.svelte';
  import ArchiveUsage from './lib/ArchiveUsage.svelte';
  import Icon from './lib/Icon.svelte';
  import Protection from './lib/Protection.svelte';
  import Dashboard from './lib/Dashboard.svelte';
  import Guide from './lib/Guide.svelte';
  import Capabilities from './lib/Capabilities.svelte';
  import BrowserInventory from './lib/BrowserInventory.svelte';
  import { loadBrowserInventory } from './lib/browserInventory';
  import Activity from './lib/Activity.svelte';
  import QueryBuilder from './lib/QueryBuilder.svelte';
  import Investigation from './lib/Investigation.svelte';
  import { ApiError, buildFilter, getHealth, listEvents, verifyStore, getEvidence } from './lib/api';
  import type { HealthSnapshot, IntegrityReport, SecurityEvent } from './lib/api';
  import { messages, sensorStateLabel, severityLabel } from './lib/i18n';
  import type { Language } from './lib/i18n';
  import { eventOperationLabel, eventResultLabel, eventSourceLabel, eventTypeLabel, exportEvents, formatCount, formatDuration, formatTime } from './lib/format';
  import { preferenceKey, readPreferences } from './lib/preferences';
  import type { Theme } from './lib/preferences';

  type Page = 'activity' | 'overview' | 'protection' | 'securityLog' | 'capabilities' | 'guide' | 'settings';
  const initialPreferences = readPreferences();
  let language = $state<Language>(initialPreferences.language);
  let theme = $state<Theme>(initialPreferences.theme);
  let systemDark = $state(window.matchMedia('(prefers-color-scheme: dark)').matches);
  let preferencesSaved = $state(true);
  let page = $state<Page>('overview');
  let health = $state<HealthSnapshot | null>(null);
  let healthError = $state<Error | null>(null);
  let logError = $state<Error | null>(null);
  let logEvents = $state<SecurityEvent[]>([]);
  let loading = $state(false);
  let querying = $state(false);
  let healthReadAt = $state<number | null>(null);
  let logReadAt = $state<number | null>(null);
  let search = $state('');
  let severity = $state('');
  let eventType = $state('');
  let hours = $state(0);
  let expression = $state('');
  let appliedCriteria = $state({ search: '', severity: '', eventType: '', hours: 0, expression: '' });
  let verification = $state<IntegrityReport | null>(null);
  let verificationError = $state<string | null>(null);
  let verifying = $state(false);
  let selectedEvent = $state<SecurityEvent | null>(null);
  let evidenceText = $state<string | null>(null);
  let evidenceError = $state<string | null>(null);
  let evidenceLoading = $state(false);
  let eventDialog: HTMLDialogElement;
  let commandDialog: HTMLDialogElement;
  let commandInput: HTMLInputElement;
  let commandSearch = $state('');
  let commandIndex = $state(0);
  let mounted = false;
  let protectionPanel = $state<{ refresh(): Promise<void> }>();
  let dashboardPanel = $state<{ refresh(): Promise<void> }>();
  let capabilitiesPanel = $state<{ refresh(): Promise<void> }>();
  let activityPanel = $state<{ refresh(): Promise<void> }>();
  let networkPath = $state('');
  const t = $derived(messages[language]);
  const navItems = $derived([
    { id: 'overview' as Page, label: t.overview, icon: 'grid' },
    { id: 'protection' as Page, label: t.protection, icon: 'shield' },
    { id: 'activity' as Page, label: t.activity, icon: 'activity' },
    { id: 'securityLog' as Page, label: t.securityLog, icon: 'log' },
    { id: 'capabilities' as Page, label: t.capabilities, icon: 'lock' },
    { id: 'guide' as Page, label: t.guide, icon: 'info' },
    { id: 'settings' as Page, label: t.settings, icon: 'settings' },
  ]);
  const filteredCommands = $derived(navItems.filter(item => item.label.toLocaleLowerCase(language).includes(commandSearch.toLocaleLowerCase(language))));
  const connected = $derived(health !== null && healthError === null);
  const title = $derived(page === 'activity' ? t.activityTitle : page === 'protection' ? (language === 'it' ? 'Intervieni, con controllo.' : 'Take controlled action.') : page === 'overview' ? t.overviewTitle : page === 'securityLog' ? t.logTitle : page === 'capabilities' ? t.capabilitiesTitle : page === 'guide' ? t.guideTitle : t.settingsTitle);
  const subtitle = $derived(page === 'activity' ? t.activitySubtitle : page === 'protection' ? (language === 'it' ? 'Quarantena su conferma e ripristino dei file, con registro delle operazioni.' : 'Confirmed file quarantine and recovery, with an action journal.') : page === 'overview' ? t.overviewSubtitle : page === 'securityLog' ? t.logSubtitle : page === 'capabilities' ? t.capabilitiesSubtitle : page === 'guide' ? t.guideSubtitle : t.settingsSubtitle);
  const filtersPending = $derived(search !== appliedCriteria.search || severity !== appliedCriteria.severity || eventType !== appliedCriteria.eventType || hours !== appliedCriteria.hours || expression !== appliedCriteria.expression);
  const errorMessage = $derived(healthError instanceof ApiError && healthError.code === 'invalid_response' ? t.invalidResponse : t.serviceUnavailable);

  $effect(() => {
    document.documentElement.lang = language;
    document.documentElement.dataset.theme = theme === 'system' ? (systemDark ? 'dark' : 'light') : theme;
    try {
      localStorage.setItem(preferenceKey, JSON.stringify({ language, theme }));
      preferencesSaved = true;
    } catch { preferencesSaved = false; }
  });

  function asError(error: unknown): Error { return error instanceof Error ? error : new Error(String(error)); }

  async function refreshLog(): Promise<void> {
    if (querying) return;
    querying = true;
    try {
      const criteria = appliedCriteria;
      const filter = buildFilter(criteria.search, criteria.severity, criteria.eventType, criteria.hours);
      if (criteria.expression.trim()) filter.expression = criteria.expression.trim();
      const values = await listEvents(filter);
      if (mounted) { logEvents = values; logError = null; logReadAt = Date.now(); }
    } catch (error) { if (mounted) logError = asError(error); }
    finally { querying = false; }
  }

  async function refresh(): Promise<void> {
    if (loading) return;
    loading = true;
    await Promise.allSettled([
      getHealth().then(value => {
        if (mounted) { health = value; healthError = null; healthReadAt = Date.now(); }
      }).catch(error => { if (mounted) healthError = asError(error); }),
      ...(page === 'overview' && dashboardPanel ? [dashboardPanel.refresh()] : []),
      ...(page === 'securityLog' ? [refreshLog()] : []),
      ...(page === 'protection' && protectionPanel ? [protectionPanel.refresh()] : []),
      ...(page === 'activity' && activityPanel ? [activityPanel.refresh()] : []),
      ...(page === 'capabilities' && capabilitiesPanel ? [capabilitiesPanel.refresh()] : []),
    ]);
    loading = false;
  }

  function navigate(next: Page): void {
    page = next;
    if (next === 'securityLog') void refreshLog();
  }

  async function applyFilters(): Promise<void> {
    if (querying) return;
    appliedCriteria = { search, severity, eventType, hours, expression };
    await refreshLog();
  }

  async function clearFilters(): Promise<void> {
    search = ''; severity = ''; eventType = ''; hours = 0; expression = '';
    await applyFilters();
  }

  async function verify(): Promise<void> {
    if (verifying) return;
    verifying = true; verificationError = null; verification = null;
    try { verification = await verifyStore(); }
    catch (error) { verificationError = asError(error).message; }
    finally { verifying = false; }
  }

  async function showEvent(event: SecurityEvent): Promise<void> {
    selectedEvent = event;
    evidenceText = null;
    evidenceError = null;
    evidenceLoading = false;
    await tick();
    eventDialog.showModal();
  }

  async function loadEvidence(): Promise<void> {
    const id = selectedEvent?.raw_evidence_reference;
    if (!id || evidenceLoading) return;
    evidenceLoading = true;
    evidenceError = null;
    try {
      const text = await getEvidence(id);
      if (selectedEvent?.raw_evidence_reference === id) evidenceText = text;
    } catch (error) {
      if (selectedEvent?.raw_evidence_reference === id) evidenceError = asError(error).message;
    } finally {
      if (selectedEvent?.raw_evidence_reference === id) evidenceLoading = false;
    }
  }

  async function openCommands(): Promise<void> {
    commandSearch = ''; commandIndex = 0;
    commandDialog.showModal();
    await tick();
    commandInput.focus();
  }

  function selectCommand(index: number): void {
    const item = filteredCommands[index];
    if (item) navigate(item.id);
    else if (commandSearch.trim()) {
      search = commandSearch; severity = ''; eventType = ''; hours = 0; expression = '';
      page = 'securityLog'; void applyFilters();
    }
    commandDialog.close();
  }

  function commandKey(event: KeyboardEvent): void {
    const count = filteredCommands.length + (commandSearch.trim() ? 1 : 0);
    if (!count) return;
    if (event.key === 'ArrowDown') { event.preventDefault(); commandIndex = (commandIndex + 1) % count; }
    if (event.key === 'ArrowUp') { event.preventDefault(); commandIndex = (commandIndex - 1 + count) % count; }
    if (event.key === 'Enter') { event.preventDefault(); selectCommand(commandIndex); }
  }

  function globalKey(event: KeyboardEvent): void {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      for (const open of document.querySelectorAll<HTMLDialogElement>('dialog[open]')) { if (open !== commandDialog) open.close(); }
      if (commandDialog.open) commandDialog.close(); else void openCommands();
    }
  }

  onMount(() => {
    mounted = true;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const onColorScheme = (event: MediaQueryListEvent) => { systemDark = event.matches; };
    media.addEventListener('change', onColorScheme);
    void refresh();
    const interval = window.setInterval(() => {
      if (document.visibilityState === 'visible' && ['overview', 'protection', 'securityLog', 'settings'].includes(page)) void refresh();
    }, 15000);
    return () => { mounted = false; window.clearInterval(interval); media.removeEventListener('change', onColorScheme); };
  });
</script>

<svelte:window onkeydown={globalKey} />

<a class="skip-link" href="#main">{t.skipContent}</a>
<div class="app-shell">
  <aside class="sidebar">
    <div class="brand"><span class="brand-symbol" aria-hidden="true"><i></i><i></i><i></i></span><span>piko<span class="brand-dot">.</span></span></div>
    <div class="device-label"><Icon name="device" size={16} /><span>{t.localEndpoint}</span><span class="local-dot" aria-hidden="true"></span></div>
    <div class="nav-caption">{t.workspace}</div>
    <nav aria-label={t.navigation}>
      {#each navItems as item}
        {#if item.id === 'securityLog'}<div class="nav-group">{language === 'it' ? 'Comprendere' : 'Understand'}</div>{/if}
        {#if item.id === 'settings'}<div class="nav-group">{language === 'it' ? 'Preferenze' : 'Preferences'}</div>{/if}
        <button class:active={page === item.id} aria-label={item.label} aria-current={page === item.id ? 'page' : undefined} onclick={() => navigate(item.id)}><Icon name={item.icon} /><span>{item.label}</span>{#if page === item.id}<span class="nav-current" aria-hidden="true"></span>{/if}</button>
      {/each}
    </nav>
    <div class="sidebar-bottom">
      <div class="local-card"><div class="local-card-icon"><Icon name="lock" size={19} /></div><strong>{t.localFirst}</strong><p>{t.localFirstDescription}</p></div>
      <div class="sidebar-version"><span>piko <span class="mono">0.2.0</span></span><span>{t.development}</span></div>
    </div>
  </aside>

  <div class="main-shell">
    <header class="topbar">
      <div class="breadcrumb"><span>piko</span><span class="breadcrumb-divider">/</span><strong>{t[page]}</strong></div>
      <div class="topbar-actions">
        <span class:online={connected} class="connection-badge"><span class="status-dot" aria-hidden="true"></span>{loading && !healthReadAt && !healthError ? t.connecting : connected ? t.connected : t.disconnected}</span>
        <button class="command-trigger" onclick={openCommands} aria-label={t.openSearch}><Icon name="search" size={17} /><span>{t.search}</span><kbd>Ctrl K</kbd></button>
      </div>
    </header>

    <main id="main" tabindex="-1">
      <div class="page-heading">
        <div><div class="eyebrow">{t[page]}</div><h1>{title}</h1><p>{subtitle}</p></div>
        {#if page !== 'settings'}<button class="button secondary refresh-button" disabled={loading || querying} onclick={refresh}><span class:spinning={loading}><Icon name="refresh" size={17} /></span>{loading ? t.refreshing : t.refresh}</button>{/if}
      </div>

      {#if healthError && ['overview', 'protection', 'securityLog'].includes(page)}
        <div class="notice connection-notice" role="status"><div class="notice-icon"><Icon name="link" size={19} /></div><div><strong>{errorMessage}</strong><p>{healthError instanceof ApiError && healthError.code === 'browser' ? t.browserUnavailable : t.serviceUnavailableDescription}</p>{#if !(healthError instanceof ApiError && healthError.code === 'browser')}<details><summary>{t.errorDetails}</summary><code>{healthError.message}</code></details>{/if}</div></div>
      {/if}

      {#if page === 'overview'}
        <Dashboard {language} {health} {connected} onNavigate={navigate} bind:this={dashboardPanel} />
      {:else if page === 'protection'}
        <Protection {language} bind:this={protectionPanel} />
      {:else if page === 'activity'}
        <Activity {language} bind:this={activityPanel} onEvent={showEvent} onNetwork={(path) => { networkPath = path; navigate('capabilities'); }} />
      {:else if page === 'capabilities'}
        <Capabilities {language} initialPath={networkPath} bind:this={capabilitiesPanel} />
        <BrowserInventory {language} load={loadBrowserInventory} />
      {:else if page === 'guide'}
        <Guide {language} onNavigate={navigate} />
      {:else if page === 'securityLog'}
        <section class="panel query-panel"><form onsubmit={(event) => { event.preventDefault(); void applyFilters(); }}><label class="search-field"><Icon name="search" size={20} /><span class="sr-only">{t.searchEvents}</span><input bind:value={search} placeholder={t.searchPlaceholder} maxlength="512" /></label><div class="filter-row"><label>{t.severity}<select bind:value={severity}><option value="">{t.allSeverities}</option>{#each ['info', 'low', 'medium', 'high', 'critical'] as value}<option value={value}>{severityLabel(value, t)}</option>{/each}</select></label><label>{t.eventType}<input bind:value={eventType} placeholder={t.allTypes} maxlength="128" /></label><label>{t.since}<select bind:value={hours}><option value={0}>{t.allTime}</option><option value={1}>{t.lastHour}</option><option value={24}>{t.lastDay}</option><option value={168}>{t.lastWeek}</option></select></label><button class="button primary" type="submit" disabled={querying}>{querying ? t.refreshing : t.applyFilters}<Icon name="arrow" size={16} /></button><button class="text-button reset-button" type="button" onclick={clearFilters} disabled={querying}>{t.clearFilters}</button></div><QueryBuilder {language} bind:expression /></form>{#if filtersPending}<p class="filter-pending" role="status">{t.filterPending}</p>{/if}</section>

        <section class="panel log-panel"><div class="panel-heading"><div><h2>{t.securityLog}<span class="heading-count">{logEvents.length}</span></h2><p>{t.resultLimit} · {t.lastRead}: {formatTime(logReadAt, language, t.noReading)}</p></div><button class="button secondary small" disabled={!logEvents.length} title={t.exportDescription} onclick={() => exportEvents(logEvents)}><Icon name="download" size={16} />{t.exportJson}</button></div>
          {#if logError && logEvents.length}<p class="inline-warning">{t.eventsQueryError}</p>{/if}
          {#if logError && connected}<details class="inline-warning"><summary>{t.errorDetails}</summary><code>{logError.message}</code></details>{/if}
          {#if logEvents.length}<div class="table-scroll"><table><thead><tr><th>{t.time}</th><th>{t.event}</th><th>{t.severity}</th><th>{t.source}</th><th><span class="sr-only">{t.details}</span></th></tr></thead><tbody>{#each logEvents as event}<tr><td class="time-cell">{formatTime(event.wall_clock_time, language)}</td><td><button class="event-title-button" onclick={() => showEvent(event)}>{eventTypeLabel(event.event_type, language)}</button><span class="event-row-detail">{event.event_type === "image.etw.repeated" ? (event.target?.identifier ?? "") : (event.process?.name ?? event.operation)}</span></td><td><span class="severity-badge {event.severity}">{severityLabel(event.severity, t)}</span></td><td class="mono">{eventSourceLabel(event.sensor_id, language)}</td><td><button class="icon-button" aria-label={`${t.viewDetails}: ${eventTypeLabel(event.event_type, language)}`} onclick={() => showEvent(event)}><Icon name="chevron" size={17} /></button></td></tr>{/each}</tbody></table></div>
          {:else if logError}<div class="empty-state large" role="alert"><h3>{language === 'it' ? 'Ricerca non completata' : 'Search did not complete'}</h3><p>{language === 'it' ? 'Controlla l’espressione o la connessione. Nessun risultato valido disponibile.' : 'Check the expression or connection. No valid result is available.'}</p></div>{:else}<div class="empty-state large"><div class="empty-illustration"><Icon name="search" size={32} /></div><h3>{logReadAt && (appliedCriteria.search || appliedCriteria.severity || appliedCriteria.eventType || appliedCriteria.hours || appliedCriteria.expression) ? t.noResults : t.noEvents}</h3><p>{logReadAt ? t.noResultsDescription : t.noEventsDescription}</p></div>{/if}
        </section>

        <section class="integrity-panel"><div class="integrity-copy"><div class="stat-icon mint"><Icon name="lock" /></div><div><h2>{t.integrity}</h2><p>{t.integrityHelp}</p></div></div><button class="button secondary" disabled={!connected || verifying} onclick={verify}><Icon name="check" size={17} />{verifying ? t.verifying : t.verifyIntegrity}</button></section>
        {#if verification}<div class="verification-result" role="status"><strong><Icon name="check" size={17} />{t.verificationOk}</strong><p>{t.verifiedEvents}: {verification.verified_events} · {language==='it'?'Eventi scaduti':'Expired events'}: {verification.expired_events??0} · {t.notAnchored}</p><details><summary>{t.headHash}</summary><code>{verification.head_hash ?? t.noHash}</code></details></div>{/if}
        {#if verificationError}<div class="notice warning-notice" role="alert"><Icon name="warning" /><div><strong>{t.verificationFailed}</strong><details><summary>{t.errorDetails}</summary><code>{verificationError}</code></details></div></div>{/if}

      {:else if page === 'settings'}
        <section class="panel settings-panel"><div class="panel-heading"><div><h2>{t.preferences}</h2><p>{preferencesSaved ? t.savedLocally : t.preferencesUnavailable}</p></div><Icon name="settings" size={22} /></div><div class="setting-row"><div><h3>{t.appearance}</h3><p>{t.appearanceDescription}</p></div><div class="theme-picker" role="group" aria-label={t.appearance}>{#each [{ id: 'system', icon: 'device', label: t.system }, { id: 'light', icon: 'sun', label: t.light }, { id: 'dark', icon: 'moon', label: t.dark }] as item}<button aria-pressed={theme === item.id} class:selected={theme === item.id} onclick={() => theme = item.id as Theme}><Icon name={item.icon} size={17} />{item.label}</button>{/each}</div></div><div class="setting-row"><div><label for="language-select">{t.language}</label><p>{t.languageDescription}</p></div><select id="language-select" bind:value={language}><option value="it">{t.italian}</option><option value="en">{t.english}</option></select></div></section>
        <section class="panel settings-panel"><div class="panel-heading"><div><h2>{t.storagePreferences}</h2><p>{t.storagePreferencesDescription}</p></div><Icon name="layers" size={22} /></div><div class="setting-row retention-row"><div><h3>{t.retention}</h3><p>{t.retentionDescription}</p></div><span class="state-badge">{t.notImplemented}</span></div><div class="setting-row privacy-row"><div><h3><Icon name="lock" size={17} />{t.privacy}</h3><p>{t.privacyDescription}</p></div></div></section>
        <div class="scope-card"><Icon name="info" size={22} /><div><h2>{t.foundationScope}</h2><p>{t.scopeDescription}</p><strong>{t.foundationLimit}</strong></div></div>
        <StartupSettings {language} />
        <RuntimePerformance {health} {connected} {language} />
        <ArchiveUsage {health} {connected} {language} />
        {#if connected && health}<section class="panel settings-panel"><div class="panel-heading"><h2>{t.runtimeDetails}</h2></div><dl class="runtime-details"><div><dt>{t.version}</dt><dd>{health.product} {health.version}</dd></div><div><dt>{t.mode}</dt><dd>{health.runtime_mode}</dd></div><div><dt>{t.uptime}</dt><dd>{formatDuration(health.uptime_seconds, t)}</dd></div><div><dt>{t.droppedEvents}</dt><dd>{health.dropped_events}</dd></div></dl></section>{/if}
        {#if connected && health}
          <section class="panel settings-panel"><div class="panel-heading"><div><h2>{t.sensorHealth}</h2><p>{language === 'it' ? 'Diagnostica dei moduli: i dettagli originali del runtime sono riportati sotto.' : 'Module diagnostics: original runtime details appear below.'}</p></div></div><div class="sensor-list">{#each health.sensors as sensor}<div class="sensor-row"><div class="source-icon"><Icon name="activity" size={18} /></div><div class="sensor-copy"><strong>{sensor.id}</strong><p>{sensor.detail}</p><small>{t.lastSeen}: {formatTime(sensor.last_seen_unix_ms, language)}</small></div><span class="state-badge" class:healthy={['active', 'healthy', 'running', 'available'].includes(sensor.state)} class:warning={['degraded', 'unavailable', 'stopped'].includes(sensor.state)}>{sensorStateLabel(sensor.state, t)}</span></div>{/each}</div><div class="panel-footer">{formatCount(health.stored_events, language)} {t.observedEvents.toLowerCase()} · {t.lastRead}: {formatTime(healthReadAt, language)}</div></section>
        {/if}
      {/if}

      <footer class="main-footer"><span><Icon name="lock" size={13} />{t.localOnly}</span><span>{t.readOnly}</span></footer>
    </main>
  </div>
</div>

<dialog bind:this={commandDialog} class="command-dialog" aria-labelledby="command-title">
  <div class="command-header"><Icon name="search" size={22} /><label id="command-title" class="sr-only" for="command-input">{t.commandTitle}</label><input id="command-input" bind:this={commandInput} bind:value={commandSearch} oninput={() => commandIndex = 0} onkeydown={commandKey} placeholder={t.commandPlaceholder} aria-controls="command-results" /><button class="icon-button" onclick={() => commandDialog.close()} aria-label={t.close}><Icon name="close" size={18} /></button></div>
  <div id="command-results" class="command-results"><div class="command-group-label">{t.pages}</div>{#each filteredCommands as item, index}<button class:highlighted={index === commandIndex} onclick={() => selectCommand(index)}><Icon name={item.icon} size={20} /><span>{item.label}</span><Icon name="arrow" size={16} /></button>{/each}{#if commandSearch.trim()}<button class:highlighted={commandIndex === filteredCommands.length} onclick={() => selectCommand(filteredCommands.length)}><Icon name="search" size={20} /><span>{t.searchEventAction}: <strong>{commandSearch}</strong></span><Icon name="arrow" size={16} /></button>{/if}</div><div class="command-footer"><span><kbd>↑ ↓</kbd> {t.commandHint}</span><span><kbd>↵</kbd> {t.selectHint}</span><span><kbd>Esc</kbd> {t.closeHint}</span></div>
</dialog>

<dialog bind:this={eventDialog} class="event-dialog" aria-labelledby="event-title"><div class="event-dialog-heading"><div><span class="eyebrow">{t.eventDetails}</span><h2 id="event-title">{selectedEvent ? eventTypeLabel(selectedEvent.event_type, language) : t.eventDetails}</h2></div><button class="icon-button" onclick={() => eventDialog.close()} aria-label={t.close}><Icon name="close" size={21} /></button></div>{#if selectedEvent}<div class="event-dialog-body"><div class="event-summary-line"><span class="severity-badge {selectedEvent.severity}">{severityLabel(selectedEvent.severity, t)}</span><span>{formatTime(selectedEvent.wall_clock_time, language)}</span></div>{#if selectedEvent.event_type === "image.etw.repeated"}<p class="muted">{language === "it" ? "Riepilogo derivato dal primo campione completo. Conteggio e intervallo sono nelle evidenze; il record grezzo collegato resta disponibile separatamente." : "Derived summary from the first full sample. Count and time range are in the evidence; the linked raw record remains available separately."}</p>{/if}<dl class="event-metadata"><div><dt>{t.eventId}</dt><dd class="mono">{selectedEvent.event_id}</dd></div><div><dt>{t.source}</dt><dd>{eventSourceLabel(selectedEvent.sensor_id, language)}</dd></div><div><dt>{t.host}</dt><dd class="mono">{selectedEvent.host_id}</dd></div><div><dt>{t.operation}</dt><dd>{eventOperationLabel(selectedEvent.operation, selectedEvent.event_type, language)}</dd></div><div><dt>{t.result}</dt><dd>{eventResultLabel(selectedEvent.result, selectedEvent.event_type, language)}</dd></div>{#if selectedEvent.process}<div><dt>{t.process}</dt><dd>{selectedEvent.process.name ?? '—'} <span class="mono">(PID {selectedEvent.process.pid})</span>{#if selectedEvent.process.executable_path}<code>{selectedEvent.process.executable_path}</code>{/if}</dd></div>{/if}{#if selectedEvent.actor_identity}<div><dt>{t.identity}</dt><dd>{selectedEvent.actor_identity.display_name ?? selectedEvent.actor_identity.sid ?? '—'}</dd></div>{/if}{#if selectedEvent.target}<div><dt>{t.target}</dt><dd>{selectedEvent.target.kind}: <code>{selectedEvent.target.identifier}</code></dd></div>{/if}</dl>{#if selectedEvent.process?.instance_id}{#key selectedEvent.process.instance_id}<Investigation instance={selectedEvent.process.instance_id} {language} onEvent={showEvent} />{/key}{/if}<section class="causal-detail"><h3>{t.causalParents}</h3><p>{t.causalDescription}</p>{#if selectedEvent.causal_parents.length}<ul>{#each selectedEvent.causal_parents as parent}<li><code>{parent}</code></li>{/each}</ul>{:else}<span class="muted">{t.noCausalParents}</span>{/if}</section><section class="causal-detail"><p>{t.sourceSeverity}</p>{#if selectedEvent.raw_evidence_reference}<h3>{t.evidenceTitle}</h3><button class="button secondary" disabled={evidenceLoading} onclick={loadEvidence}>{evidenceLoading ? t.loadingEvidence : t.loadEvidence}</button>{#if evidenceError}<p role="alert">{evidenceError}</p>{/if}{#if evidenceText}<pre class="source-evidence">{evidenceText}</pre>{/if}{/if}</section><details class="raw-detail"><summary>{t.rawEvent}</summary><p>{t.rawEventDescription}</p><pre>{JSON.stringify(selectedEvent, null, 2)}</pre></details></div>{/if}</dialog>

