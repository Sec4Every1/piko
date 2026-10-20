<script lang="ts">
 import { onMount } from 'svelte';
 import { startupStatus, setStartup, type StartupStatus } from './api';
 import type { Language } from './i18n';
 let {language}:{language:Language}=$props();
 const it=$derived(language==='it');
 let status=$state<StartupStatus|null>(null), busy=$state(false), error=$state('');
 async function load(){busy=true;error='';try{status=await startupStatus();}catch(e){status=null;error=String(e);}finally{busy=false;}}
 async function toggle(){if(!status||status.conflict)return;busy=true;error='';try{status=await setStartup(!status.enabled);}catch(e){error=String(e);}finally{busy=false;}}
 onMount(load);
</script>
<section class="panel startup-panel" aria-label={it?'Avvio automatico':'Automatic startup'}>
 <div class="panel-heading"><div><h2>{it?'Avvio automatico':'Automatic startup'}</h2><p>{it?'Avvia il monitor quando accedi a Windows con questo utente. La finestra resta chiusa.':'Start the monitor when this user signs in to Windows. The window stays closed.'}</p></div></div>
 <div class="startup-body"><div><strong>{status ? (status.conflict ? (it?'Configurazione diversa rilevata':'Different configuration detected') : status.enabled ? (it?'Configurato al login':'Configured at sign-in') : (it?'Disattivato':'Disabled')) : (it?'Stato non disponibile':'Status unavailable')}</strong><p>{it?'Windows può ritardare o disabilitare l’avvio. Controlla piko anche in Impostazioni Windows → App → Avvio. Il monitor termina alla disconnessione; un servizio Windows già installato ha la precedenza.':'Windows may delay or disable startup. Check piko in Windows Settings → Apps → Startup too. The monitor stops at sign-out; an installed Windows service takes precedence.'}</p></div><button class="button primary" disabled={busy||!status||status.conflict} onclick={toggle}>{busy ? (it?'Attendi…':'Please wait…') : status?.enabled ? (it?'Disattiva':'Disable') : (it?'Attiva al login':'Enable at sign-in')}</button><button class="button secondary" disabled={busy} onclick={load}>{it?'Aggiorna':'Refresh'}</button></div>
 {#if status?.conflict}<p class="notice">{it?'La voce PikoMonitor appartiene a un’altra configurazione. Gestiscila da Windows prima di modificarla qui.':'The PikoMonitor entry belongs to another configuration. Manage it in Windows before changing it here.'}</p>{/if}
 {#if status?.last_startup_error}<p class="notice" role="status">{it?'Ultimo tentativo di avvio non riuscito:':'Last startup attempt failed:'} {status.last_startup_error}</p>{/if}
 {#if error}<p class="notice" role="alert">{error}</p>{/if}
</section>
<style>
.startup-panel{margin-bottom:22px}.startup-body{display:flex;align-items:center;gap:12px;padding:22px}.startup-body>div{flex:1}strong{font-size:.85rem;font-weight:500}p{color:var(--muted);font-size:.75rem;line-height:1.7}.notice{padding:0 22px 16px;color:var(--warning)}@media(max-width:650px){.startup-body{flex-wrap:wrap}.startup-body>div{flex-basis:100%}}
</style>
