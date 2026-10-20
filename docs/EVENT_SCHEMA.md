# Contratto eventi di piko

Versione documento: 1. Data: 2026-10-04. Il contratto Rust è definito in `crates/event-schema`; i tipi condivisi in `crates/common-model`. La normalizzazione iniziale comprende self-health, non telemetria generale Windows.

## Envelope v1

Normalizzazione corrente aggiuntiva: `windows.event_log.<EventID>`, sensor ID per
canale, target `canale:provider:recordID`. Wall-clock dalla sorgente, observation
dal runtime. Actor/process restano null: Execution ProcessID non prova l'attore.
`source_integrity` contiene il bookmark (checkpoint, non attestazione del provider),
raw evidence conserva XML UTF-8 originale. Severity è il livello operativo Windows.

| Campo | Tipo wire JSON / Rust | Semantica |
| --- | --- | --- |
| `schema_version` | integer / `u32` | `1`; versioni non supportate sono rifiutate |
| `event_id` | string UUID / `Uuid` | Identità dell'evento, distinta da ordine e timestamp |
| `host_id` | string UUID / `Uuid` | Identità locale persistita della installazione; non fingerprint hardware |
| `boot_id` | UUID o null / `Option<Uuid>` | Boot Windows solo se acquisito da fonte verificata; inizialmente null |
| `runtime_instance_id` | string UUID / `Uuid` | Nuovo ID a ogni avvio collector; epoca di sequenze e monotonic time |
| `sensor_id` | string | Adapter che produce l'osservazione |
| `sequence` | integer / `u64` | Sequenza nel suo contesto `(host, runtime, sensor)` |
| `wall_clock_time` | integer / `i64` | Tempo UTC dichiarato dalla sorgente, millisecondi Unix |
| `monotonic_time` | integer / `u64` | Nanosecondi da `Instant` del runtime; non uptime del kernel |
| `observation_time` | integer / `i64` | UTC ms alla ricezione locale |
| `ingestion_time` | integer / `i64` | UTC ms all'ingresso nella pipeline |
| `event_category`, `event_type` | string | Namespace e tipo dell'evento |
| `severity` | string / enum | `info`, `low`, `medium`, `high`, `critical` |
| `actor_identity` | object o null | SID e contesto disponibili; nessun segreto/credenziale |
| `logon_session` | string o null | Sessione di autenticazione; non equiparare al nome utente |
| `process`, `parent_process` | object o null | Contesto processo; PID da solo non identifica una vita di processo |
| `target` | object o null | Risorsa osservata, quando disponibile |
| `operation`, `result` | string | Operazione e risultato osservato, non decisione presunta |
| `causal_parents` | array UUID | Eventi con relazione causale supportata da evidenza |
| `correlation_ids` | array UUID | Gruppi di correlazione senza implicare causalità |
| `raw_evidence_reference` | UUID o null | Riferimento al raw salvato con l'evento |
| `integrity_metadata` | object | Versione di normalizzazione e descrizione della sorgente |

`IntegrityMetadata` v1 contiene `normalization_version: u32` e `source_integrity: Option<String>`. Questo campo non è una firma digitale e non certifica la sorgente. La chain di persistenza è gestita dallo storage, separatamente dall'envelope.

I timestamp, sequenze e contatori `u64` sono rappresentabili esattamente in Rust; il frontend JavaScript non deve effettuare aritmetica sui nanosecondi come se tutti i valori fossero entro `Number.MAX_SAFE_INTEGER`. Prima di telemetria con uptime lungo occorre un wire encoding sicuro per interi a 64 bit, oppure DTO con stringhe decimali. La prima UI non usa questi contatori per inferire causalità.

## Ordine e identità

Gli UUID non stabiliscono l'ordine. La sequenza e il monotonic time ordinano osservazioni solo nella loro epoca; ordini tra fonti possono essere parziali. Eventi in ritardo mantengono i loro tempi. Un salto di wall clock genera evidenza di clock drift quando la sorgente viene implementata, senza riordinare la storia già persistita.

L'assenza di `boot_id` è informazione reale. Un UUID generato a ogni avvio del servizio non sarebbe un boot ID corretto; per questo esiste `runtime_instance_id`. Restart, sleep/resume, reboot e fast startup richiederanno test separati della futura sorgente boot. `process` dovrà usare host + boot/epoca + PID + creation time/chiave sorgente, con uncertainty quando manca un dato. Windows espone il tempo di creazione tramite `GetProcessTimes`, con limiti di accesso al processo. [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes), verificato 2026-10-04.

## Raw, normalizzazione e derivazioni

`EventRecord` associa `SecurityEvent` e `RawEvidence` opzionale. Il raw comprende bytes, sorgente, content type e tempo osservato; viene salvato e collegato atomicamente quando presente. Riferimenti invalidi devono essere rifiutati. Un evento interno può non avere un payload Windows originale; la mancanza è dichiarata tramite null e non sostituita con XML inventato.

Limiti iniziali: evento JSON massimo 256 KiB, raw massimo 1 MiB, batch massimo 128 record e 4 MiB serializzati complessivi. Il raw iniziale è serializzato come JSON con array di byte: il costo su disco può essere maggiore della dimensione originaria; la compressione a segmenti è futura. Le query hanno massimo 1.000 eventi e 4 MiB complessivi di payload, oltre ai limiti del trasporto. I limiti sono guardrail del prototipo, non garanzie di performance. Ogni parser aggiunto deve avere limiti più specifici per profondità, array, dimensioni stringa, codifica, buffer decompressione e numero di entità derivate; non basta il solo limite del frame IPC.

Il design successivo introduce riferimenti `segment_id + offset + length + digest`, identificatore provider/event/versione, metadati di decodifica e payload raw immutabile. L'enrichment aggiunge nuove entità/relazioni con versione, provenienza e timestamp; non modifica silenziosamente un record normalizzato. La rianalisi produce nuove derivazioni, deduplicate con chiave parser+input.

## Negative evidence

`ObservationIntegrityEvent` e `TelemetryLossEvent` appartengono alla stessa pipeline degli altri eventi. Il loro modello futuro deve distinguere perdita upstream ETW, decoder rejection, queue full, storage budget esaurito, sequenza saltata e interruzione sensore. Riporta intervallo, conteggio noto/minimo, epoca, causa, stato di recupero e precisione. `unknown_count` non deve diventare zero.

La perdita può impedire di conoscere esattamente quanti eventi siano mancati; un heartbeat attivo non dimostra copertura semantica. I test devono saturare la queue e verificare che la segnalazione sia preservata o recuperabile da un contatore affidabile. La pipeline iniziale fornisce le primitive, mentre la copertura ETW e cross-sensor è in roadmap.

## Compatibilità e sicurezza del formato

La versione schema riguarda semantica e wire format; le migrazioni storage hanno numerazione indipendente. V1 usa `deny_unknown_fields`: anche campi aggiuntivi sono rifiutati. Una futura compatibilità additiva richiede una decisione esplicita, non è già disponibile. Cambi di unità, significato o tipo richiedono nuova versione. Versioni future, enum sconosciuti e frame corrotti devono produrre errori espliciti, mai un fallback “healthy”.

La validazione corrente rifiuta UUID nil per event/host/runtime, sequence zero o oltre `i64::MAX`, timestamp negativi, label vuote/oltre 128 byte/con caratteri di controllo, più di 128 causal parents o correlation IDs e autoriferimento causale. Non dimostra che un event reference appartenga a un evento realmente acquisito: quella verifica richiederà il grafo. I nested model sono `IdentityContext { sid, display_name }`, `ProcessContext { pid, instance_id, name, executable_path, creation_time_unix_ms }` ed `EventTarget { kind, identifier }`; tutti i campi process salvo PID possono essere null.

`event_type` testuale evita di compilare ogni consumer per aggiungere un tipo, ma deve essere validato in un catalogo per sorgente. Raw text non viene interpretato come HTML, codice, query o comando. Query ed export mantengono origine e incertezza. Eventi sintetici appartengono esclusivamente al replay harness e portano origine di test; non alimentano un dashboard di produzione fingendo attività reale.

## Criteri di verifica

Round-trip, schema non supportato, campo obbligatorio mancante, timestamp negativo rifiutato, limiti payload, UUID malformati, raw mismatch, duplicate ID, sequenza riavviata in nuova epoca, inversione wall clock, corruzione raw e cancellazione interna della chain. Property tests e fuzz del decoder/IPC sono richiesti prima di ampliare la superficie a eventi esterni non controllati.
