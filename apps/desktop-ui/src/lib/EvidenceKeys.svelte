<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import { ApiError } from './api';
  import {
    authorizeEvidenceKeyBackup, beginEvidenceKeyBackup, confirmEvidenceKeyBackup, cancelEvidenceKeyBackup,
    authorizeEvidenceProtection, beginEvidenceProtection, resumeEvidenceProtection,
    getEvidenceKeyStatus, readEvidenceKeyBackup, validRecoveryCode,
    type EvidenceKeyBackup, type EvidenceKeyStatus, type EvidenceKeyTicket,
  } from './evidence_keys';

  let { connected, language }: { connected: boolean; language: 'it' | 'en' } = $props();
  const it = $derived(language === 'it');
  let status = $state<EvidenceKeyStatus | null>(null);
  let busy = $state(false);
  let step = $state<'idle' | 'warning' | 'backup'>('idle');
  let accepted = $state(false);
  let ticket = $state<EvidenceKeyTicket | null>(null);
  let backup = $state<EvidenceKeyBackup | null>(null);
  let code = $state('');
  let savedExternally = $state(false);
  let activationAccepted = $state(false);
  let resumeAccepted = $state(false);
  let resuming = $state(false);
  let resumeResult = $state<'completed' | 'failed' | 'browser' | null>(null);
  let mounted = true;
  let message = $state<'failed' | 'browser' | 'expired' | 'completed' | 'activated' | null>(null);
  let generation = 0;
  let expiryTimer: ReturnType<typeof setTimeout> | undefined;
  let downloadTimer: ReturnType<typeof setTimeout> | undefined;
  let downloadUrl: string | null = null;

  function releaseDownload() {
    if (downloadTimer !== undefined) clearTimeout(downloadTimer);
    downloadTimer = undefined;
    if (downloadUrl !== null) URL.revokeObjectURL(downloadUrl);
    downloadUrl = null;
  }
  function clearSensitive() {
    if (expiryTimer !== undefined) clearTimeout(expiryTimer);
    expiryTimer = undefined;
    releaseDownload();
    ticket = null;
    backup = null;
    code = '';
    accepted = false;
    savedExternally = false;
    activationAccepted = false;
    step = 'idle';
  }
  function cancel() {
    const id = ticket?.id;
    if (id) void cancelEvidenceKeyBackup(id).catch(() => {});
    generation++;
    clearSensitive();
    busy = false;
    message = null;
  }
  function current(operation: number) { return operation === generation && connected; }
  function activeTicket(operation: number, id: string) {
    return current(operation) && ticket?.id === id && ticket.expires_at_unix_ms > Date.now();
  }
  function expire() {
    generation++;
    clearSensitive();
    busy = false;
    message = 'expired';
  }
  function fail(reason: unknown) {
    const id = ticket?.id;
    if (id) void cancelEvidenceKeyBackup(id).catch(() => {});
    clearSensitive();
    message = reason instanceof ApiError && reason.code === 'browser' ? 'browser' : 'failed';
  }
  async function refresh() {
    cancel();
    const operation = generation;
    status = null;
    busy = true;
    try {
      const value = await getEvidenceKeyStatus();
      if (current(operation)) status = value;
    } catch (reason) {
      if (current(operation)) fail(reason);
    } finally { if (current(operation)) busy = false; }
  }
  function startWarning() {
    cancel();
    step = 'warning';
  }
  async function reveal() {
    if (!connected || busy || !accepted || step !== 'warning') return;
    const operation = ++generation;
    busy = true;
    message = null;
    try {
      const issued = await beginEvidenceKeyBackup();
      if (!current(operation)) { void cancelEvidenceKeyBackup(issued.id).catch(() => {}); return; }
      ticket = issued;
      expiryTimer = setTimeout(expire, Math.max(0, issued.expires_at_unix_ms - Date.now()));
      await authorizeEvidenceKeyBackup(issued.id);
      if (!activeTicket(operation, issued.id)) {
        if (current(operation)) expire();
        return;
      }
      const revealed = await readEvidenceKeyBackup(issued.id);
      if (!activeTicket(operation, issued.id)) {
        if (current(operation)) expire();
        return;
      }
      backup = revealed;
      step = 'backup';
    } catch (reason) {
      if (current(operation)) fail(reason);
    } finally { if (current(operation)) busy = false; }
  }
  function download() {
    if (!ticket || !backup || busy) return;
    if (!activeTicket(generation, ticket.id)) { expire(); return; }
    releaseDownload();
    // Created only by this explicit click. Neither secret nor ticket enters a
    // URL, storage, clipboard, log or diagnostic. The Blob URL is short lived.
    const blob = new Blob([
      'Piko evidence recovery backup\nKeep this file secret and outside this computer.\n',
      `Archive: ${backup.archive_id}\nRecipient: ${backup.recipient}\nRecovery code: ${backup.recovery_code}\n`,
    ], { type: 'text/plain;charset=utf-8' });
    const link = document.createElement('a');
    try {
      downloadUrl = URL.createObjectURL(blob);
      link.href = downloadUrl;
      link.download = 'piko-evidence-recovery.txt';
      link.rel = 'noopener';
      document.body.appendChild(link);
      link.click();
      downloadTimer = setTimeout(releaseDownload, 1_000);
    } catch { fail(null); }
    finally { link.remove(); }
  }
  async function confirm() {
    if (!ticket || !backup || busy || !savedExternally || !validRecoveryCode(code)) return;
    const id = ticket.id;
    const operation = generation;
    if (!activeTicket(operation, id)) { expire(); return; }
    busy = true;
    message = null;
    try {
      const result = await confirmEvidenceKeyBackup(id, code);
      if (!activeTicket(operation, id)) {
        if (current(operation)) expire();
        return;
      }
      if (result.state !== 'ready' || !result.backup_confirmed) throw new Error('Unconfirmed');
      clearSensitive();
      status = result;
      message = 'completed';
    } catch (reason) {
      if (current(operation)) fail(reason);
    } finally { if (current(operation)) busy = false; }
  }
  async function activateProtection() {
    const fresh = status?.new_raw_enabled === false && status.recoverable_mode === false;
    const resume = status?.new_raw_enabled === true && status.recoverable_mode === true && status.activation_pending;
    if (busy || !activationAccepted || status?.state !== 'ready' || (!fresh && !resume)) return;
    const operation = ++generation;
    busy = true; message = null;
    try {
      const activation = await beginEvidenceProtection();
      if (!current(operation)) { void cancelEvidenceKeyBackup(activation.id).catch(() => {}); return; }
      ticket = activation;
      await authorizeEvidenceProtection(activation.id);
      if (!current(operation)) return;
      const result = await getEvidenceKeyStatus();
      if (!result.backup_confirmed || !result.new_raw_enabled || !result.recoverable_mode || result.activation_pending) throw new Error('Activation not confirmed');
      clearSensitive(); status = result; message = 'activated';
    } catch (reason) { if (current(operation)) fail(reason); }
    finally { if (current(operation)) busy = false; }
  }
  async function resumeProtection() {
    if (busy || resuming || !resumeAccepted) return;
    resuming = true;
    resumeResult = null;
    cancel();
    try {
      await resumeEvidenceProtection();
      if (mounted) {
        resumeResult = 'completed';
        if (connected) await refresh();
      }
    } catch (reason) {
      if (mounted) resumeResult = reason instanceof ApiError && reason.code === 'browser' ? 'browser' : 'failed';
    } finally {
      if (mounted) { resuming = false; resumeAccepted = false; }
    }
  }
  $effect(() => {
    const active = connected;
    untrack(() => {
      cancel();
      status = null;
      if (active) void refresh();
    });
    return () => { generation++; clearSensitive(); };
  });
  onDestroy(() => { mounted = false; generation++; clearSensitive(); });

  const label = $derived(!connected || !status || status.state === 'unavailable'
    ? (it ? 'Stato non disponibile' : 'Status unavailable')
    : status.state === 'not_prepared' ? (it ? 'Chiave da preparare' : 'Key not prepared')
    : status.state === 'backup_required' ? (it ? 'Backup da confermare' : 'Backup confirmation required')
    : (it ? 'Chiave pronta' : 'Key ready'));
</script>

<div class="keys" aria-busy={busy || resuming}>
  <fieldset disabled={resuming}>
  <div class="heading"><strong>{it ? 'Chiave di recupero evidenze' : 'Evidence recovery key'}</strong>
    <button type="button" disabled={!connected || busy} onclick={() => void refresh()}>{it ? 'Aggiorna stato' : 'Refresh status'}</button></div>
  <p role="status">{label}</p>
  {#if resumeResult}
    <p role="status" class:warning={resumeResult !== 'completed'}>{resumeResult === 'completed'
      ? (it ? 'Ripresa confermata dal monitor. Aggiorna lo stato dopo la riconnessione.' : 'Resume confirmed by the monitor. Refresh status after reconnecting.')
      : resumeResult === 'browser' ? (it ? 'Apri Piko nell’app desktop per richiedere l’autorizzazione Windows.' : 'Open the Piko desktop app to request Windows authorization.')
      : (it ? 'Ripresa non completata o annullata. Copie e stato conservati; nessuna attivazione nuova viene avviata da questo comando.' : 'Resume refused or cancelled. Backups and transaction state retained; this command cannot start a new activation.')}</p>
  {/if}
  {#if !connected}
    <details>
      <summary>{it ? 'Riprendi un’attivazione interrotta' : 'Resume interrupted activation'}</summary>
      <p>{it ? 'Usa questa procedura soltanto se avevi già autorizzato l’attivazione. Windows richiederà il consenso; Piko riprende solo lo stato riconosciuto e conserva le copie. Il monitor potrebbe restare fermo se i dati sono cambiati.' : 'Use this only after an activation you already authorized. Windows requests consent; Piko resumes only a recognized transaction and preserves backups. The monitor may remain stopped if data changed.'}</p>
      <label><input type="checkbox" bind:checked={resumeAccepted} disabled={resuming || busy} />{it ? 'Voglio riprendere l’attivazione interrotta.' : 'I want to resume the interrupted activation.'}</label>
      <button type="button" disabled={!resumeAccepted || resuming || busy} onclick={() => void resumeProtection()}>{resuming ? (it ? 'Ripresa in corso…' : 'Resuming…') : (it ? 'Autorizza e riprendi' : 'Authorize and resume')}</button>
    </details>
  {/if}
  {#if message}
    <p class:warning={message !== 'completed' && message !== 'activated'} role="status">
      {#if message === 'activated'}
        {it ? 'Protezione recuperabile delle nuove evidenze confermata dal monitor.' : 'Recoverable protection for new evidence confirmed by the monitor.'}
      {:else}
      {message === 'completed' ? (it ? 'Backup confermato tramite il codice reinserito. La chiave è pronta; la cifratura non è stata attivata da questa operazione.' : 'Backup confirmed using the re-entered code. The key is ready; this operation did not activate encryption.')
      : message === 'browser' ? (it ? 'Apri Piko nell’app desktop: il browser non può richiedere questa autorizzazione.' : 'Open Piko in the desktop app: the browser cannot request this authorization.')
      : message === 'expired' ? (it ? 'Sessione scaduta. I dati sensibili sono stati rimossi dalla schermata. Ripeti la preparazione.' : 'Session expired. Sensitive data was removed from the screen. Start preparation again.')
      : (it ? 'Operazione non riuscita o autorizzazione non disponibile. I dati sensibili sono stati rimossi; aggiorna lo stato e riprova.' : 'Operation failed or authorization unavailable. Sensitive data was removed; refresh status and retry.')}
      {/if}
    </p>
  {/if}
  <details ontoggle={(event) => { if (!event.currentTarget.open && step !== 'idle') cancel(); }}>
    <summary>{it ? 'Dettagli e backup della chiave' : 'Key details and backup'}</summary>
    <p>{it ? 'Se il monitor resta scollegato dopo un’interruzione, apri Resume-PikoEvidenceProtection.cmd dal pacchetto. La procedura conserva le copie e riprende solo una transazione riconosciuta; non disattiva la protezione.' : 'If the monitor remains disconnected after an interruption, open Resume-PikoEvidenceProtection.cmd from the package. It preserves backups and resumes only a recognized transaction; it does not disable protection.'}</p>
    <p>{it ? 'Il codice riguarda solo il nuovo formato recuperabile. Per recuperare la chiave locale, apri Restore-PikoEvidenceKey.cmd nel pacchetto e seleziona il backup salvato. La procedura è ancora da collaudare e non recupera vecchie evidenze protette solo dal profilo Windows.' : 'The code covers only the new recoverable format. To restore the local key, open Restore-PikoEvidenceKey.cmd in the package and select your saved backup. This flow still needs qualification and cannot recover older evidence protected only by the Windows profile.'}</p>
    <p>{it ? 'Una chiave pronta non significa che l’archivio sia cifrato. La protezione riguarda solo le nuove evidenze grezze quando configurata; indici ed eventi normalizzati restano in chiaro. Le evidenze esistenti non vengono ricifrate.' : 'A ready key does not mean the archive is encrypted. Protection covers only new raw evidence when configured; normalized events and indexes remain plaintext. Existing evidence is not re-encrypted.'}</p>
    {#if connected && status && status.state !== 'unavailable'}
      <p>{it ? 'Protezione nuove evidenze grezze configurata' : 'New raw evidence protection configured'}: {status.new_raw_enabled ? (it ? 'sì' : 'yes') : (it ? 'no' : 'no')}.
        {it ? 'Modalità recuperabile configurata' : 'Recoverable mode configured'}: {status.recoverable_mode ? (it ? 'sì' : 'yes') : (it ? 'no' : 'no')}.</p>
      {#if status.state === 'ready' && ((!status.new_raw_enabled && !status.recoverable_mode) || (status.new_raw_enabled && status.recoverable_mode && status.activation_pending))}
        <div class="activation">
          <p class="warning">{status.activation_pending
            ? (it ? 'Un’attivazione precedente è stata interrotta dopo il riavvio del monitor. Completa la chiusura protetta della transazione.' : 'A previous activation was interrupted after the monitor restarted. Complete the protected transaction cleanup.')
            : (it ? 'Attiva solo dopo aver verificato la copia esterna. Windows riavvierà brevemente il monitor. Da quel momento saranno cifrate soltanto le nuove evidenze grezze; eventi, indici e dati precedenti restano invariati. Dopo il primo salvataggio protetto la modalità non può essere semplicemente disattivata.' : 'Activate only after checking the external copy. Windows will briefly restart the monitor. From then on, only new raw evidence is encrypted; events, indexes and previous data remain unchanged. After the first protected write, this mode cannot simply be disabled.')}</p>
          <label><input type="checkbox" bind:checked={activationAccepted} disabled={busy} />{status.activation_pending ? (it ? 'Confermo di voler completare l’attivazione interrotta.' : 'I confirm that I want to complete the interrupted activation.') : (it ? 'Confermo di voler attivare la protezione recuperabile delle nuove evidenze.' : 'I confirm that I want to enable recoverable protection for new evidence.')}</label>
          <button type="button" disabled={busy || !activationAccepted} onclick={() => void activateProtection()}>{busy ? (it ? 'Attivazione…' : 'Activating…') : status.activation_pending ? (it ? 'Completa attivazione' : 'Complete activation') : (it ? 'Autorizza e attiva' : 'Authorize and activate')}</button>
        </div>
      {:else if status.new_raw_enabled !== status.recoverable_mode}
        <p class="warning">{it ? 'Configurazione incoerente: la protezione non è confermata. Usa il recupero dell’installazione.' : 'Inconsistent configuration: protection is not confirmed. Use installation recovery.'}</p>
      {:else if status.new_raw_enabled && status.recoverable_mode && !status.activation_pending}
        <p>{it ? 'Le nuove evidenze grezze vengono protette con la chiave recuperabile confermata.' : 'New raw evidence is protected with the confirmed recoverable key.'}</p>
      {/if}
      {#if step === 'idle'}
        <button type="button" disabled={busy} onclick={startWarning}>{it ? 'Prepara backup' : 'Prepare backup'}</button>
      {:else if step === 'warning'}
        <p class="warning">{it ? 'Il codice permette di decifrare le evidenze del nuovo formato recuperabile. Chi lo possiede può leggerle. Salva una copia esterna a questo PC e custodiscila in segreto; un download nella cartella locale non è ancora una copia esterna. Windows chiederà un’autorizzazione amministratore (UAC) prima di mostrarlo. La sessione dura al massimo 5 minuti.' : 'The code can decrypt evidence in the new recoverable format. Anyone holding it can read that evidence. Save a copy outside this PC and keep it secret; downloading into a local folder does not make an external copy. Windows will request administrator authorization (UAC) before revealing it. The session lasts at most 5 minutes.'}</p>
        <label><input type="checkbox" bind:checked={accepted} disabled={busy} />{it ? 'Ho compreso e autorizzo la visualizzazione del codice segreto.' : 'I understand and authorize revealing the secret code.'}</label>
        <button type="button" disabled={busy || !accepted} onclick={() => void reveal()}>{busy ? (it ? 'In attesa di autorizzazione…' : 'Waiting for authorization…') : (it ? 'Autorizza e mostra il codice' : 'Authorize and reveal code')}</button>
      {:else if backup}
        <p class="warning">{it ? 'Codice segreto: proteggi lo schermo e conserva una copia esterna.' : 'Secret code: protect your screen and keep an external copy.'}</p>
        <pre class="secret" aria-label={it ? 'Codice di recupero segreto' : 'Secret recovery code'}>{backup.recovery_code}</pre>
        <button type="button" disabled={busy} onclick={download}>{it ? 'Scarica il backup .txt' : 'Download .txt backup'}</button>
        <small>{it ? 'Sposta il file su un supporto esterno sicuro o in un archivio segreto. Piko non può verificare dove lo custodisci.' : 'Move the file to secure external storage or a secret vault. Piko cannot verify where you keep it.'}</small>
        <label for="piko-recovery-code">{it ? 'Reinserisci il codice dalla copia salvata' : 'Re-enter the code from your saved copy'}</label>
        <input id="piko-recovery-code" class="code-input" type="password" maxlength="128" bind:value={code} disabled={busy} autocomplete="off" autocapitalize="none" spellcheck="false" />
        <label><input type="checkbox" bind:checked={savedExternally} disabled={busy} />{it ? 'Dichiaro di aver custodito una copia esterna e segreta.' : 'I confirm that I have stored a secret external copy.'}</label>
        <button type="button" disabled={busy || !savedExternally || !validRecoveryCode(code)} onclick={() => void confirm()}>{it ? 'Conferma il backup' : 'Confirm backup'}</button>
      {/if}
      {#if step !== 'idle'}<button type="button" onclick={cancel}>{it ? 'Annulla e nascondi' : 'Cancel and hide'}</button>{/if}
    {:else}
      <small>{it ? 'Lo stato sconosciuto non conferma che una chiave o un backup siano disponibili.' : 'Unknown status does not confirm that a key or backup is available.'}</small>
    {/if}
  </details>
  </fieldset>
</div>

<style>
  .keys{padding:16px 22px;border-top:1px solid var(--border);font-size:.78rem}
  fieldset{border:0;padding:0;margin:0;min-width:0}
  .heading{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
  strong{font-weight:600}p{margin:10px 0;line-height:1.6}small{display:block;color:var(--muted);line-height:1.6;margin:8px 0}
  details{margin-top:10px;color:var(--muted)}summary{cursor:pointer}button,input{font:inherit}button{margin:6px 8px 6px 0}
  label{display:flex;align-items:flex-start;gap:8px;margin:12px 0;line-height:1.5}.warning{color:var(--warning)}
  .secret{padding:12px;border:1px solid var(--border);white-space:pre-wrap;overflow-wrap:anywhere;user-select:text;color:var(--text)}
  .code-input{box-sizing:border-box;width:100%;max-width:38rem;padding:8px}
</style>
