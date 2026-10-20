<script lang="ts">
  import type { Language } from './i18n';
  import { queryFields, clause, appendClause, readSavedQueries, saveQuery, savedQueryKey, type SavedQuery } from './queries';
  let { language, expression = $bindable('') }: { language: Language; expression?: string } = $props();
  const it = $derived(language === 'it');
  let field = $state<string>('process.name'), operator = $state('='), value = $state(''), join = $state<'AND' | 'OR'>('AND');
  let name = $state(''), saved = $state(readSavedQueries()), error = $state('');
  const numeric = $derived(field === 'process.pid' || field === 'event.time');
  const operators = $derived([...(numeric ? ['=', '!=', '>', '>=', '<', '<='] : ['=', '!=', 'CONTAINS']), 'IS NULL', 'IS NOT NULL']);
  function add() {
    try { expression = appendClause(expression, clause(field, operator, value), join); error = ''; }
    catch (e) { error = String(e); }
  }
  function persist(next: SavedQuery[]) {
    try { localStorage.setItem(savedQueryKey, JSON.stringify({ version: 1, queries: next })); saved = next; error = ''; }
    catch { error = it ? 'Salvataggio locale non disponibile.' : 'Local saving unavailable.'; }
  }
  function save() { try { persist(saveQuery(saved, name, expression)); } catch (e) { error = String(e); } }
</script>
<details class="query-builder">
  <summary>{it ? 'Ricerca avanzata e ricerche salvate' : 'Advanced search and saved searches'}{#if expression.trim()} <span>· {it ? 'Espressione impostata' : 'Expression set'}</span>{/if}</summary>
  <p>{it ? 'Combina i campi raccolti. I filtri sopra restano validi. Premi “Applica filtri” per eseguire la ricerca.' : 'Combine collected fields. Filters above still apply. Press “Apply filters” to run the search.'}</p>
  <div class="builder-row">
    <label>{it ? 'Campo' : 'Field'}<select bind:value={field} onchange={() => { operator = '='; }}>{#each queryFields as f}<option value={f}>{f}</option>{/each}</select></label>
    <label>{it ? 'Operatore' : 'Operator'}<select bind:value={operator}>{#each operators as op}<option value={op}>{op}</option>{/each}</select></label>
    <label class="value">{it ? 'Valore' : 'Value'}<input bind:value maxlength="1024" disabled={operator.startsWith('IS ')} placeholder={numeric ? '42' : 'example.exe'} /></label>
    <label>{it ? 'Collega con' : 'Join with'}<select bind:value={join}><option>AND</option><option>OR</option></select></label>
    <button type="button" class="button secondary small" onclick={add}>{it ? 'Aggiungi condizione' : 'Add condition'}</button>
  </div>
  <label>{it ? 'Espressione' : 'Expression'}<textarea bind:value={expression} rows="3" maxlength="4096" spellcheck="false" placeholder={'process.name = "example.exe" AND process.pid >= 1'}></textarea></label>
  <details class="syntax"><summary>{it ? 'Sintassi e limiti' : 'Syntax and limits'}</summary><p>{it ? 'AND, OR e parentesi; AND ha precedenza. Testo tra virgolette doppie, con escape JSON nei percorsi. CONTAINS ignora maiuscole ASCII. NULL indica un dato assente: != non include i dati assenti. event.time è Unix in millisecondi. Massimo 4096 byte, 32 condizioni, 8 livelli di parentesi. FOLLOWED_BY e RELATED_TO non disponibili.' : 'AND, OR and parentheses; AND takes precedence. Double-quoted text with JSON escapes in paths. CONTAINS ignores ASCII case. NULL means missing data: != excludes missing values. event.time is Unix milliseconds. Maximum 4096 bytes, 32 conditions, 8 parenthesis levels. FOLLOWED_BY and RELATED_TO unavailable.'}</p></details>
  <div class="builder-row"><label class="value">{it ? 'Nome della ricerca' : 'Search name'}<input bind:value={name} maxlength="80" /></label><button type="button" class="button secondary small" disabled={!name.trim() || !expression.trim()} onclick={save}>{it ? 'Salva espressione' : 'Save expression'}</button></div>
  <p class="hint">{it ? 'Fino a 20 espressioni, solo su questo profilo. Gli altri filtri non vengono salvati.' : 'Up to 20 expressions in this profile. Other filters are not saved.'}</p>
  {#if error}<p role="alert">{error}</p>{/if}
  {#if saved.length}<ul>{#each saved as q}<li><button type="button" class="text-button" onclick={() => { expression = q.expression; error = ''; }}>{q.name}</button><button type="button" class="text-button" aria-label={`${it ? 'Elimina ricerca' : 'Delete search'} ${q.name}`} onclick={() => persist(saved.filter(item => item.name !== q.name))}>{it ? 'Elimina' : 'Delete'}</button></li>{/each}</ul>{/if}
</details>
<style>
  .query-builder { border-top: 1px solid var(--border); padding-top: 16px; margin-top: 16px; }
  summary { cursor: pointer; font-weight: 600; } summary span, .hint { font-size: 12px; opacity: .75; }
  label { display: grid; gap: 6px; font-size: 12px; min-width: 0; }
  .builder-row { display: flex; gap: 12px; flex-wrap: wrap; align-items: end; margin: 14px 0; }
  .value { flex: 1; min-width: 180px; }
  textarea { width: 100%; box-sizing: border-box; resize: vertical; color: var(--text); background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px; font-family: monospace; }
  .syntax { margin-top: 12px; font-size: 12px; }
  ul { padding: 0; list-style: none; max-height: 180px; overflow: auto; } li { display: flex; justify-content: space-between; gap: 12px; padding: 8px 0; }
</style>
