<script lang="ts">
 import { executableSignature, type ExecutableSignature } from './appControl';
 import type { Language } from './i18n';
 import { formatTime } from './format';
 let {executable,language}:{executable:string;language:Language}=$props();
 const it=$derived(language==='it');
 let result=$state<ExecutableSignature|null>(null),error=$state(''),busy=$state(false);
 let previous='';$effect(()=>{if(previous!==executable){previous=executable;result=null;error='';}});
 const label=$derived(!result ? '' : result.status==='verified_locally' ? (it?'Firma incorporata verificata localmente':'Embedded signature verified locally') : result.status==='no_embedded_signature' ? (it?'Firma incorporata non trovata':'Embedded signature not found') : result.status==='digest_mismatch' ? (it?'Il file non corrisponde alla firma':'File does not match signature') : (it?'Firma non verificata':'Signature not verified'));
 async function inspect(){const path=executable;busy=true;result=null;error='';try{const value=await executableSignature(path);if(path===executable)result=value;}catch(e){if(path===executable)error=String(e);}finally{busy=false;}}
</script>
<div class="signature-check"><button class="text-button" disabled={busy||!executable.trim()} onclick={inspect}>{busy ? (it?'Verifica firma…':'Checking signature…') : (it?'Verifica firma locale':'Check local signature')}</button>{#if result}<div class="signature-result" class:mismatch={result.status==='digest_mismatch'} role="status"><strong>{label}</strong><p>{it?'Revoca e cataloghi non verificati. Una firma non garantisce assenza di malware o vulnerabilità.':'Revocation and catalogs not checked. A signature does not guarantee absence of malware or vulnerabilities.'}</p><details><summary>{it?'Impronta e dettaglio':'Fingerprint and details'}</summary><code>{result.executable}</code><code>SHA-256: {result.sha256}</code><small>{formatTime(result.checked_at*1000,language)} · WinVerifyTrust {result.native_status}</small></details></div>{/if}{#if error}<p class="signature-error" role="alert">{error}</p>{/if}</div>
<style>.signature-check{margin:8px 0}.signature-result{padding:12px;border:1px solid var(--border);border-radius:10px;background:var(--surface-subtle)}strong{font-size:.78rem;font-weight:500}p,small,summary{font-size:.7rem;color:var(--muted);line-height:1.6}code{display:block;font-size:.67rem;overflow-wrap:anywhere;margin:6px 0}.mismatch{border-color:var(--warning-border)}.signature-error{color:var(--warning)}</style>
