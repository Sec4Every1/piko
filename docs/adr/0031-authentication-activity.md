# ADR 0031 — Accessi, credenziali e privilegi osservati

14 ottobre 2026. KEEP safe Rust: parser e semantica nel security-core, query
nel worker event-storage, API IPC readonly, UI TypeScript/Svelte. Nessun nuovo
FFI, privilegio, audit Windows o sensore; si riusano le evidenze già raccolte.

Eventi supportati: Security-Auditing 4624 versioni 0/1/2/3, 4625/4648/4672 versione 0.
XML canonico e bounded: namespace, provider, canale, record ID, tipo, timestamp,
UUID raw e sorgente devono corrispondere all'evento. DTD, campi duplicati,
namespace estranei, versioni future e ambiguità non diventano nomi affidabili.
Stati missing/invalid/unsupported_version restano espliciti, con campi vuoti.
Verified indica coerenza dell'evidenza, non autenticità del programma o innocuità.

Microsoft Learn documenta 4624 fino alla versione 2; il log reale usa v3.
V3 verificata nel template locale tramite API Windows ProviderMetadata.Events:
i campi interpretati conservano nomi/tipi della v2; l'unica aggiunta osservata è
RemoteCredentialGuard (qui non interpretato). Evidenza di schema in

Distinzione account richiedente / account coinvolto; SID quando presente.
ProcessId/ProcessName provengono dai campi EventData, mai dal PID Execution.
Nessuna identità di istanza o causalità fabbricata da un PID storico.
4624 riporta la sessione TargetLogonId creata; 4625/4648 riportano SubjectLogonId
del richiedente. 4672 riporta sessione/identità Subject e PrivilegeList.
4648 non conferma successo; 4672 non dimostra uso di privilegi o escalation.
Si interpretano soltanto campi documentati per il relativo tipo di evento.
Indirizzi IP e nomi sono quelli della fonte; non si identifica un attaccante remoto.
ID sessione senza boot verificato non sono collegati automaticamente tra record.

GetAuthenticationActivity: filtri per categoria prima di LIMIT, cursore per
posizione globale esclusiva, ordine di raccolta decrescente, 1–20 record (UI 5).
Un solo snapshot WAL per eventi/raw; budget 4 MiB di evidenze esaminate e deadline
worker 750 ms. Nuovi append non spostano le pagine già iniziate. Manutenzione che
ricostruisce le posizioni richiede aggiorna/ripartenza della vista; non è un cursor
firmato o permanente. Non si restituisce l'XML nella lista: si apre su richiesta.

Vista compatta espandibile in Attività applicazioni, subito dopo la nota di
copertura: cinque righe, filtro, più vecchi/recenti, dettagli e verifiche manuali.
Routine non aggiunte alla dashboard come minacce. UI non conserva righe precedenti
come un risultato riuscito quando il nuovo filtro fallisce. Nessun blocco account.
CLI piko identity offre la prima pagina. Corretto anche il caricamento automatico
del registro arresti: usa lo stato DOM dell'evento toggle, prima del binding Svelte.

Test: account/subject e PID distinti, versioni supportate, XML ambiguo/alterato,
assenza di dati, cursor/filtri, archivio invariato; frontend contro risposte
incoerenti, lazy load, cinque righe, navigazione, dettagli e raw separati.
Restano token lineage, identity graph, correlazione con boot, credential protection,
policy account e qualificazione Windows client/Server completa.

Qualifica richiesta: fixture per formati XML supportati, versioni e dati mancanti/alterati; controlli di paging e separazione fra dettaglio e raw; verifica su Windows client e server con accesso autorizzato al canale Security. Non presume assenza di perdite sotto carico.

Fonti primarie:
- [Microsoft 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft 4648](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648)
- [Microsoft 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)


