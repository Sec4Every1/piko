<script lang="ts">
  import type { Language } from './i18n';
  import { parseBrowserInventory, type BrowserInventory } from './browserInventory';

  let { language, load }: { language: Language; load: () => Promise<unknown> } = $props();
  const it = $derived(language === 'it');
  let inventory = $state<BrowserInventory | null>(null);
  let loading = $state(false), failed = $state(false);
  async function refresh() {
    if (loading) return;
    loading = true; failed = false; inventory = null;
    try { inventory = parseBrowserInventory(await load()); }
    catch { failed = true; }
    finally { loading = false; }
  }
</script>

<section aria-labelledby="browser-inventory-title">
  <h2 id="browser-inventory-title">{it ? 'Browser rilevati' : 'Browser registrations'}</h2>
  <p>{it ? 'Registrazioni di sistema non verificate. Profili utente, identità degli eseguibili e protezione browser non sono verificati.' : 'Unverified system registrations. User profiles, executable identities and browser protection are not verified.'}</p>
  <button type="button" onclick={refresh} disabled={loading}>
    {loading ? (it ? 'Ricerca…' : 'Loading…') : (it ? 'Cerca registrazioni' : 'Find registrations')}
  </button>
  {#if failed}
    <p role="alert">{it ? 'Inventario non disponibile. La copertura rimane sconosciuta.' : 'Inventory unavailable. Coverage remains unknown.'}</p>
  {:else if inventory}
    {#if !inventory.registration_scan_complete || inventory.truncated || inventory.oversized_metadata}
      <p role="status">{it ? 'Ricerca incompleta: alcune registrazioni potrebbero mancare.' : 'Incomplete scan: some registrations may be missing.'}</p>
    {/if}
    {#if inventory.candidates.length === 0}
      <p>{it ? 'Nessuna registrazione trovata. Altri browser o profili potrebbero essere presenti.' : 'No registrations found. Other browsers or profiles may still exist.'}</p>
    {:else}
      <ul>
        {#each inventory.candidates as candidate}
          <li><strong>{candidate.registered_name}</strong>
            {#if candidate.registered_version} — {candidate.registered_version}{/if}
            {#if candidate.registered_publisher} — {candidate.registered_publisher}{/if}
            <span> ({it ? 'registrazione di sistema, non verificata' : 'unverified system registration'})</span>
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
</section>
