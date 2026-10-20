# Budget e verifica performance di piko

0.2.0: worker response separato, una operazione file alla volta, coda di quattro
richieste, contenuto massimo 16 MiB meno 64 KiB. Buffer limitati, ma la verifica
DPAPI richiede più copie simultanee del contenuto (budget transitorio nell'ordine
di 80 MiB, da misurare sotto carico). Vault massimo 128 MiB inclusi journal/file;
journal SQLite massimo 32 MiB e 1000 piani di quarantena (recovery escluso dal
tetto logico). Un solo runtime per vault tramite lock esclusivo. Nessuna scansione ricorsiva delle
radici utente. Le query mostrano al massimo 100 alert e 100 azioni. I timeout di
response non annullano effetti già accettati; consultare il journal per l'esito.

Data: 2026-10-04. Tutti i numeri seguenti sono obiettivi o limiti di configurazione, **non risultati misurati né promesse commerciali**. Un benchmark del solo storage non certifica overhead endpoint.

## Budget iniziali

| Area | Obiettivo / limite | Come verificare |
| --- | --- | --- |
| Runtime idle | Idealmente meno di 100–150 MiB RAM | Private bytes e working set separati; UI chiusa; 30 minuti dopo warmup |
| CPU idle | Media inferiore a 0,5% del sistema | Tempo CPU / tempo parete / processori logici; riportare anche un-core equivalent |
| Monitoraggio normale futuro | Media inferiore a 2% del sistema | Workload documentato office/browser/build e confronto con baseline senza piko |
| Evento normalizzato | 256 KiB massimo | Rifiuto prima di inserimento; misurare dimensione serializzata |
| Raw per evento | 1 MiB massimo | Rifiuto esplicito; nessuna allocazione da lunghezze non validate |
| Batch storage | Fino a 128 record e 4 MiB serializzati | Una transazione per batch, rifiuto oltre entrambi i limiti |
| Storage dev | Default 256 MiB, minimo 8 MiB | DB + WAL e capacità residua; esaurimento visibile |
| Queue | Runtime default 256, configurabile 4–4.096 eventi | Saturazione controllata, contatore dropped e memoria massima |
| Query UI | Fino a 1.000 eventi e 4 MiB payload | Richiesta ampia rifiutata; niente dump dell'intero DB |
| UI chiusa | Nessuna WebView in background | Process census dopo chiusura; runtime rimane raggiungibile |

La taglia massima del singolo evento non autorizza buffer simultanei illimitati. Lo storage limita il batch a 4 MiB serializzati; la queue resta limitata per numero di eventi, ciascuno validato fino a 256 KiB. Alla capacità runtime massima il worst case può superare largamente il budget idle: prima di first real telemetry serve anche un budget in bytes della queue. Il runtime di self-health ha payload piccoli ma non sostituisce questo test.

Il prototipo riserva metà quota alle pagine del database e controlla DB/WAL/SHM con una stima conservativa della crescita. Mancano ancora una policy di free-space reserve del volume e retention automatica. La verifica chain all'avvio è O(N); ricerca testuale e verifica esplicita possono scansionare la storia. La ricerca SQLite corrente usa `lower`/`instr`, senza full-text index né case folding Unicode completo. Questi costi devono guidare la separazione futura tra writer, query e verifier; un timeout async non interrompe automaticamente una chiamata SQLite sincrona.

## Strategie

Il runtime corrente separa il writer/query worker dal loop async, con coda8 e quattro client massimi. La snapshot health resta disponibile senza interrogare SQLite. Le letture scadute non vengono avviate e SQLite ha un progress handler; I/O del sistema operativo bloccato rimane un limite da fault-injectare. La verifica intera all'avvio rimane O(N); non viene spacciata per controllo costante.

Per Attack Path Engine misurare update latency, path-query p50/p95/p99, RAM/nodi/archi, storage growth, esplorazioni massime e CPU durante cambi topologia. Budget proposti (non implementati) e gestione di risposte incomplete sono in [ATTACK_PATH_MODEL.md](ATTACK_PATH_MODEL.md). Vietata ricomputazione completa continua; il ricalcolo completo su piccole fixture resta un oracolo di test per l'algoritmo incrementale.

Acquisizione event-driven, callback brevi, enqueue non bloccante sui thread critici, enrichment pigro, indici scelti da query reali e writer unico. Async soltanto dove semplifica I/O e cancellazione; concurrency limitata. Nessun scan completo periodico aggressivo o ML pesante nel percorso eventi. La UI richiede dati quando aperta e annulla richieste obsolete.

La telemetria adattiva futura passa da risoluzione normale a maggiore fedeltà per un tempo e scope limitati dopo un segnale. La transizione stessa è auditata; se si riduce copertura per carico si espone ciò che manca. Non scartare silenziosamente gli eventi che avrebbero dimostrato un incidente.

WAL, file temporanei, indici, backup e segmenti contano nel budget disco. Un solo limite alla dimensione del `.db` non basta. Un writer deve considerare il batch prima del commit, mantenere margine per checkpoint e segnalare disco pieno. La futura retention non può attendere che il volume sia già saturo. Lettori lunghi e checkpoint vanno misurati separatamente. [SQLite WAL](https://www.sqlite.org/wal.html), verificato 2026-10-04.

## Protocollo benchmark riproducibile

Registrare commit, build release, rustc/dependency lock, Windows edition/build/patch, CPU/core, RAM, disco/filesystem, power mode e altre protezioni attive. Un benchmark di sviluppo in debug non è comparabile a una release. Conservare dati grezzi, mediana, p95/p99 quando pertinenti e variabilità tra almeno cinque ripetizioni.

| Workload | Dimensioni | Metriche |
| --- | --- | --- |
| Ingest sintetico innocuo | Piccoli eventi realistici e payload worst case | events/s, commit latency, MiB/s, bytes/event, memoria |
| Query | DB da 10 mila, 100 mila e 1 milione eventi | p50/p95, indice usato, paginazione, query cancellata |
| Overload | Producer 2× e 10× capacità sostenibile | queue high-water, dropped, loss reporting, RAM bounded |
| Churn runtime | Restart, client disconnect, orologio indietro | startup, shutdown/drain, recupero WAL, handle/thread leaks |
| UI | Apertura/chiusura, grandi pagine, cambio tema/lingua | memoria/processi, input latency, accessibilità |
| Storage pressure | Budget ridotto, write failure, WAL occupato | Errore comprensibile, nessun loop infinito né saturazione volume |
| Corruption | Copia di database alterata/troncata | Rilevazione senza crash; nessun auto-repair distruttivo |

I benchmark automatici del workspace forniscono un primo baseline locale; riportare i risultati reali nell'output di validazione, non precompilare questa tabella con numeri inventati. Finché non esiste una baseline conservata e hardware controllato, CI può pubblicare misure ma non dichiarare una regressione percentuale attendibile.

## Gate futuri di regressione

Su runner dedicato: warning iniziale per regressione ripetuta superiore a 10% in throughput/latency o 15% memoria; failure dopo conferma e soglia assoluta pertinente. Le soglie sono proposte da calibrare, non gate già attivi. Binary size, startup e writes hanno baseline separata. Un miglioramento di throughput non giustifica perdita silenziosa, memoria illimitata o peggioramento del threat model.

Metriche interne richieste: received/accepted/persisted/dropped/rejected, queue utilization, batch count/bytes, latenza osservazione/ingest/commit, stato sensore, disk usage, CPU/RAM, query latency. “Zero” si mostra solo quando misurato: indisponibile è distinto da zero.
