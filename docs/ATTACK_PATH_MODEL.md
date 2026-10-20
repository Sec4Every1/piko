# Attack Path Engine: contratto di architettura

Data: 2026-10-04. Stato: **design, non implementazione runtime**. Deriva dalle sezioni 4–14 dell'[addendum](ARCHITECTURAL_ADDENDUM.md). Nessuna UI fittizia, nessuna topologia inventata dagli heartbeat. Linguaggio previsto: safe Rust; dati nel Security Graph di piko.

## Identità e piani separati

`ObjectId` identifica stabilmente una risorsa nel suo namespace/host e tipo; processi/token includono un'epoca che impedisce riuso ambiguo. SID, Windows session, authentication LUID e credenziale sono distinti. Le tre viste condividono tali ID; ciascun arco ha ID e semantica propri. Una label o un nome software non sono sufficienti per unire oggetti.

- **Observed**: `ObservedEdge {from,to,relation,event_refs,source,observed_interval,causal_basis,confidence}`. Event refs obbligatori; distinguere causa provata, inferenza e correlazione. Un evento di tentativo non prova successo.
- **Potential**: `PotentialEdge {from,to,capability,state_refs,snapshot_version,valid_from,valid_to,preconditions,scope,confidence,freshness}`. La permission deve corrispondere a operazione, risorsa, identità/token e contesto. Un'osservazione incompleta produce `unknown`, non `deny` o `allow` inventati.
- **Counterfactual**: `Scenario {scenario_id,base_snapshot,proposal_id,added_edges,removed_edges,changed_conditions,assumptions,expires_at}`. Overlay immutabile e separato; proposte concorrenti non vengono mescolate. Se cambia la base, il risultato è obsoleto e va ricalcolato prima di un'azione.

Un'API espone `view_kind` esplicito. Non usa l'assenza di event refs per indovinare il tipo di grafo. I payload normalizzati originali restano immutati: non aggiungere retroattivamente una permission come se fosse un evento causale.

## Nodi, relazioni e precondizioni

Nodi: User, Group, Machine, Process, Application, Token, Credential, Certificate, Service, Driver, BrowserSession, RemoteSession, CloudIdentity, NetworkResource, SensitiveData, Policy, DeveloperTool, Package, Dependency, AIAgent, FleetEndpoint. Sono entità comuni al modello; i collector per cloud/fleet sono opzionali.

Relazioni potenziali: `CAN_ADMIN`, `CAN_AUTHENTICATE`, `CAN_IMPERSONATE`, `CAN_READ`, `CAN_WRITE`, `CAN_MODIFY`, `CAN_EXECUTE`, `CAN_INSTALL`, `CAN_CONTROL_SERVICE`, `CAN_LOAD_DRIVER`, `CAN_READ_CREDENTIAL`, `CAN_CHANGE_POLICY`, `CAN_ACCESS_DATA`, `CAN_REACH_NETWORK`, `CAN_DELEGATE`, `CAN_OBTAIN_TOKEN`, `CAN_MODIFY_IDENTITY`.

Queste relazioni non sono liberamente transitive. Per esempio `CAN_REACH_NETWORK(A,B)` non implica `CAN_AUTHENTICATE(A,B)`; leggere un file cifrato di credenziali non prova possesso di un segreto utilizzabile; appartenenza a un gruppo non prova che il token corrente abbia privilegi abilitati. Condizioni congiunte diventano una transizione con prerequisiti AND, non più archi OR erroneamente equivalenti.

Le API Windows Authz/AccessCheck aiutano a valutare accesso per contesto e security descriptor. Non coprono da sole protocollo remoto, MFA, token/session lifecycle, protezioni applicative o exploitability. Vanno conservati DACL/ACE rilevanti, generic mapping, token/gruppi/privilegi e versione stato utilizzati; negazioni e contesto incompleto restano visibili. [Checking Access with Authz API](https://learn.microsoft.com/en-us/windows/win32/secauthz/checking-access-with-authz-api), verificato 2026-10-04. L'uso di tali risultati nel grafo è una scelta progettuale di piko, non una prova di sfruttabilità fornita dall'API.

Ogni transizione deve rispondere a: quale permesso la consente, chi lo ha osservato, quando, quali condizioni mancano, quale modifica l'ha introdotta e se è ancora valida. Snapshot di epoche incompatibili non possono comporre un percorso apparentemente attuale.

## Query bounded e aggiornamenti incrementali

Stato/index: adjacency forward/reverse, object→edges, state-evidence→edges, edge→cached-paths, schema/collector versions, limite LRU e budget byte. Le cache non sono autorità; le risposte riportano versione snapshot.

`state/event change → affected objects → edge delta → invalidate impacted paths → bounded query → reevaluate detections`.

Shortest path usa ricerca per hop compatibile con precondizioni; il percorso con meno hop non è automaticamente il più probabile o quello con remediation più sicura. Ogni query riceve limiti espliciti. Budget iniziali da misurare, non promesse: profondità 8, 10.000 stati esplorati, 100 percorsi, 100 ms budget CPU cooperativo, cache 16 MiB. Il runner di test può usare soglie più piccole per verificare saturazione. I valori effettivi saranno configurati e misurati nel primo vertical slice.

Risposta: `paths`, `snapshot_version`, `explored_states`, `limits_reached`, `coverage`, `missing_sources`, `stale_conditions`, `elapsed`. Nessun percorso trovato con budget esaurito → **ricerca incompleta**, non “nessun rischio”. Cicli e più percorsi verso lo stesso oggetto richiedono deduplicazione per stato/precondizioni; i soli ID nodi non bastano per eliminare stati distinti. Il numero di combinazioni è limitato prima dell'espansione.

Metriche: graph update latency, query latency p50/p95/p99, RAM per nodi/archi, crescita storage, stati esplorati, cache hit/eviction, CPU durante cambi di topologia. Una modifica locale deve avere test differenziali contro un ricalcolo completo di piccole fixture, mantenendo la produzione incrementale.

## Counterfactual e capability expansion

Per software permissions, account/group, firewall, privilege elevation, driver/service, credential access, package install, policy, remote access e permessi AI agent:

1. Fissare base/versione, modifica e autorizzatore proposto.
2. Applicare soltanto all'overlay le relazioni/precondizioni interessate.
3. Confrontare percorsi e risorse critiche raggiungibili, riportando nuovi, rimossi e incerti.
4. Mostrare la differenza e l'ACE/capability/route che la causa; non eseguire il cambiamento.
5. Prima dell'eventuale autorizzazione, verificare freschezza della base e scope reale dell'enforcement.

Esempio di fixture test: package v1 accede al progetto; v2 propone accesso a una chiave di deployment. Il risultato è “la capability proposta introduce un percorso privilegiato”, con condizioni remote eventualmente ignote. Non significa “package malevolo”. Informerà probation, policy e conferme; non incrementa automaticamente la fiducia dell'update firmato.

## Known Attack Path In Progress

La correlazione usa Potential + Observed + Identity State + Historical Behavior + User Intent + Capability Contracts. Per ogni risultato: path/snapshot IDs, posizione corrente osservata, target critico, remaining hops condizionali, evidence refs, identities/credential refs, timeline causale, alternative paths, fattori di confidence e punto di contenimento proposto.

Un prefisso osservato deve corrispondere a soggetti/azioni e tempi compatibili, non soltanto a stringhe o eventi vicini nel tempo. Tentativi falliti e log mancanti non si promuovono a successo. Le condizioni non osservabili restano incerte. Fonti duplicate non contano come evidenze indipendenti; le finestre temporali e i criteri di escalation devono essere deterministici e versionati.

Progressione `OBSERVE → WARN → RESTRICT → CONTAIN → BLOCK`. L'esistenza del solo percorso può produrre una raccomandazione di hardening. Per response automatica servono osservazioni concordanti sufficienti oppure policy esplicita, oltre a permesso dell'azione e capacità reale di blocco. Un engine di analisi non crea capacità kernel mancanti.

## Criticità e remediation

Criticità nodi LOW/MEDIUM/HIGH/CRITICAL. Asset critici includono identity privilegiate, DC quando presente, infrastruttura di sicurezza, backup/recovery, chiavi signing/deployment, amministrazione CI/CD, credential vault, core piko e recovery store protetto.

Spiegare separatamente: hop, privilegi guadagnabili, valore della credenziale senza acquisirne il segreto, affidabilità/freschezza del percorso, esposizione, posizione osservata, evidenze comportamentali, intento, sfruttabilità e criticità target. Non ridurre il risultato a un punteggio opaco.

Cut point candidato: arco/transizione o protezione risorsa che interrompe uno o più percorsi. Per ciascuno, indicare precondizioni, percorsi coperti, alternative residue, attività legittime interessate, specificità, reversibilità, autorizzazione richiesta e piano di rollback. Preferire impatto operativo basso con motivazione esplicita; non proclamare un minimo globale con esplorazione troncata. Nessuna raccomandazione si applica automaticamente.

Azioni considerate: rimuovere o limitare un permesso, proteggere una credenziale, ridurre un privilegio, modificare capability/policy, autenticazione più forte, segmentazione rete. “Rimuovere amministratore” è soltanto una candidata e può essere sproporzionata.

## Fleet e importazione

Una conferma d'incidente può condividere causal fingerprint, topology pattern, relazioni identity minimizzate, precondizioni e punto di prevenzione. Il destinatario verifica autenticità/freschezza del messaggio, mapping degli oggetti, equivalenza dello scope e precondizioni locali; condizioni mancanti → observe/warn, non blocco universale. Nessun invio di segreti o contenuti personali. Coordinator indisponibile non interrompe analisi locale.

BloodHound/OpenGraph potrà essere importato da adapter indipendente e non obbligatorio. Provenienza, timestamp, mapping semantico e limiti payload devono essere preservati; dati importati non diventano evidenza osservata locale. Nessun nuovo database o runtime graph pesante è introdotto da questo design.

## UI e criteri di accettazione

Mostrare `Attack Paths` quando esistono dati/query reali utili, anche su singolo PC; niente tab disabilitata per insinuare una funzione inesistente. Separare viste con etichette testuali, tratto continuo/tratteggiato/punteggiato, legenda e descrizioni screen reader. Il dettaglio indica quale relazione è accaduta, quale è disponibile e quale dipende dalla proposta.

Query utente: perché è possibile; quale permission lo crea; percorso più corto; remediation meno impattante; modifica che lo interromperebbe; progressione osservata attuale; cambiamento che lo ha introdotto; prima epoca in cui è divenuto possibile. “Prima osservato” non equivale a “prima esistito” quando manca storia.

Il primo vertical slice richiede test per: separazione dei tipi, evidenza obbligatoria Observed, ACL deny/unknown, ciclo/depth/exploration bounds, stale snapshot, invalidazione incrementale, overlay non mutante, assenza di response da sola possibilità, progressione con tentativo fallito, alternative paths/cut coverage e precondizioni fleet assenti. Fixture sintetiche identificate; UI solo dopo acquisizione locale reale e test end-to-end.
