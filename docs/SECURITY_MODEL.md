# Modello di sicurezza di piko

Aggiornamento 2026-10-06: detection Event Log, quarantena manuale e recovery del
contenuto sono implementati (ADR 0009, RESPONSE.md). Le ulteriori policy di
prevenzione descritte qui rimangono design futuro. Il viewer SCM conserva la
sola lettura; prepare/execute richiedono il token elevato del vero caller.

## Principi di autorizzazione

L'identità risponde a “chi”, la provenienza a “da dove”, l'integrità a “è cambiato”, l'autorizzazione a “che cosa è consentito”, la capacità a “che cosa può tecnicamente fare” e il comportamento a “che cosa ha fatto”. Nessuna delle sei sostituisce le altre. L'unknown e la firma valida sono elementi di contesto, non verdetti.

Una futura `SecurityTransaction` contiene ID, soggetto che autorizza, risorse e operazioni consentite, limiti, inizio, scadenza, versione policy, motivazione e stato. L'autorizzazione a installare un software non si estende indefinitamente ai suoi discendenti. L'ereditarietà tra processi e versioni è esplicita; capability sensibili nuove richiedono una nuova valutazione. Mancanza di transazione può produrre alert, mentre “deny” è dichiarato solo dove esiste un enforcement point affidabile.

Il decision record futuro include evidenze e lacune, regola/versione, decisione proposta, attore autorizzante, enforcement disponibile, stato dell'azione e verifica del risultato. `requested`, `attempted`, `succeeded`, `failed`, `unsupported` sono distinti. “Bloccato” richiede un risultato verificato: una detection o un tentativo di terminare il processo non bastano.

## API locale

Aggiornamento implementato: endpoint installato `piko.service.v1`, account virtuale
dedicato, SID lettore iscritto dall'amministratore. Il lettore vede tutti i canali
raccolti sul dispositivo, inclusi eventuali dati di altre sessioni; non esiste
ancora una segmentazione row-level. I comandi di mutazione verificano il token
della richiesta con impersonation di sola identificazione, senza await, con
RevertToSelf obbligatorio. Il SID richiedente e confermante è registrato nel journal.
Anche un runtime console elevato richiede chiamanti elevati. Il client chiede
diritti dati minimi e verifica il PID nel SCM. Se piko è installato ma fermo o
non autenticabile, non passa al runtime console. Hash del pacchetto non equivale
a firma del publisher. Test amministrativi/cross-user restano da eseguire.

La base usa named pipe Windows locale con nome per utente/sessione. La configurazione prevede DACL esplicita del SID, esclusione client remoti, primo server esclusivo, framing e limiti, timeout e richieste tipizzate. SID/session ricavati dalle API Windows hanno precedenza sui campi inviati dal client. Le primitive `FILE_FLAG_FIRST_PIPE_INSTANCE` e `PIPE_REJECT_REMOTE_CLIENTS` sono documentate da Microsoft. [CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew), verificato 2026-10-04.

| Ruolo futuro | Operazioni | Condizioni |
| --- | --- | --- |
| Utente/sessione del dev runtime | Status, eventi interni, verifica storage | Solo self-health e richieste bounded |
| Viewer | Query su dati esplicitamente visibili | Identità e scope host/sessione; export separato |
| Operatore | Response consentite dalla policy | Evidenze, capability e risultato auditato |
| Amministratore policy | Versionare policy, enrollment, retention | Autorizzazione amministrativa e audit |
| Updater | Installare pacchetti piko verificati | Firma, versione, canale, anti-rollback |

Il client Rust della UI è un trasporto, non un'autorità. Non sono previsti endpoint generici “esegui comando”, “apri file come SYSTEM” o SQL arbitrario. L'API di query avrà AST limitato e parametri bindati. Il prototipo verifica il SID/session del processo peer su entrambi i lati; non autentica l'identità esclusiva del binario. Autenticazione OS allo stesso SID permette anche a un altro processo di quell'utente di connettersi o presentarsi come server: non prova che la richiesta provenga dalla UI piko né da una volontà umana. Quando il runtime diventerà servizio, il modello per-user corrente dovrà evolvere in un broker con scope, token effettivo del caller e ACL verificati; non basta aprire la pipe a tutti gli utenti.

## Service, storage e chiavi

Il deployment futuro separa binari firmati, configurazione amministrativa, dati del servizio, cache utente e preferenze UI. Il writer è unico; i client leggono via API. ACL e service SID impediscono all'utente ordinario di modificare policy/history. I percorsi sono risolti sotto root ammesse, con difesa contro reparse point e link nei flussi privilegiati.

CNG/key storage provider e protezione TPM vengono valutati per le chiavi di identità e firma. La disponibilità hardware è verificata, non presunta; la degradazione software è visibile. Il sistema di chiavi non deve perdere l'accesso alle evidenze offline senza un piano esplicito di recovery/escrow. Microsoft documenta provider sostituibili per archiviazione e gestione delle chiavi. [Key Storage and Retrieval](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval), verificato 2026-10-04.

Un hash chain rileva alterazioni soltanto rispetto a un riferimento di fiducia. Chi controlla dati e chiave sullo stesso host può cancellare una coda o ricreare una storia; signed checkpoint locali migliorano l'integrità ma non offrono automaticamente freshness. L'ancoraggio remoto opzionale rende verificabili checkpoint precedenti alla compromissione. Il vault di quarantena usa DPAPI con scope utente; registro eventi e metadati del journal rimangono in chiaro. Checkpoint firmati e anchoring non sono operativi.

## Response e recovery

Per Attack Path Management, `Potential` descrive possibilità condizionali e `Counterfactual` una proposta: nessuno dei due costituisce attività malevola osservata. Predictive containment richiede evidenza osservata sufficiente oppure policy esplicita applicabile, autorizzazione dell'azione e enforcement disponibile. Proposte e snapshot hanno versioni e scadenze; una modifica della base invalida una decisione controfattuale precedente. Cut points indicano impatto/reversibilità e percorsi alternativi non interrotti; una ricerca troncata non certifica assenza di percorsi. Il contratto è in [ATTACK_PATH_MODEL.md](ATTACK_PATH_MODEL.md).

Le response sono tipizzate e fanno prima acquisizione di evidenze minima e poi azione, senza ritardare irragionevolmente un blocco urgente supportato. Ogni operazione ha precondizioni, scadenza, limite d'impatto, verifica e recovery. Non esiste rollback generale di un processo: operazioni di rete, credenziali sottratte o scritture concorrenti non si annullano. Undo appare soltanto per azioni per le quali resta sicuro.

Quarantena user-mode è soggetta a race e handle aperti; ACL sono basate sull'identità e non distinguono sempre applicazioni dello stesso utente. Un filtro file può mediare operazioni ma introduce rischi kernel, compatibilità, latenza e deadlock che vanno verificati. Per account creation e accesso sensibile non si inventano hook universali: vedere [FEASIBILITY.md](FEASIBILITY.md).

## Self-defense e trust del kernel

Service recovery, watchdog e heartbeat sono misure di disponibilità. Non rendono un processo invulnerabile. Protected anti-malware services richiedono condizioni specifiche, tra cui integrazione ELAM e vincoli di firma; non sono una semplice opzione di ogni servizio. [Protecting anti-malware services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-), verificato 2026-10-04.

Il kernel opzionale contiene callback minime e enforcement limitato; niente rete, UI o ML. Nessun bypass di PatchGuard, hook non documentato o sospensione indiscriminata di thread. I driver saranno firmati e testati su HVCI e sulle versioni supportate prima di qualsiasi deployment.

## Update e dipendenze

Le release richiederanno lockfile, audit vulnerabilità/licenze, SBOM, hash, prove di build, test e provenienza. Installer e updater devono verificare contenuto, firma, publisher, applicabilità e versione minima; installazione transazionale e rollback sicuro non equivalgono a consentire downgrade vulnerabili. Il prototipo non comprende questo canale di distribuzione.
