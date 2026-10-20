# Architecture & Language Audit

Delta 2026-10-14 — ADR 0031: fatti di autenticazione da evidenze esistenti in
security-core safe Rust; snapshot/cursore nel worker SQLite, API IPC readonly e
vista Svelte compatta. Nessun sensore, FFI, privilegio o migrazione aggiunto.

Delta 2026-10-14 — ADR 0029/0030: conservazione del prefisso e copia selettiva
verificata in event-storage safe Rust; heartbeat/health nel runtime, filtro ETW
nel boundary esistente win-platform. Backup e sostituzione offline amministrativi
con script PowerShell. KEEP Rust, nessuna nuova FFI o migrazione; UI/IPC esistenti.

Delta 2026-10-14 — ADR 0032: aggregazione contestuale immagini nel runtime safe Rust.
Riuso delle aperture file protette e della verifica firma/catalogo cache-only in
win-platform; anchor committati solo dopo conferma del writer SQLite. Nessuna nuova
FFI, libreria, permesso Windows o modifica degli eventi Security.

Delta 2026-10-13 — ADR 0023–0025: query Registry e UDP nel solo boundary win-platform; storico SQLite e correlazione credenziali in safe Rust; bridge Tauri serializzato e viste paginabili. Nessuna migrazione di linguaggio, driver, modifica registro/account o cattura pacchetti. I 116 requisiti restano parziali.

Delta 2026-10-08 — ADR 0010/0011: inventario e Firewall COM con helper UAC,
fotografie ToolHelp/TCP bounded con RAII nel boundary win-platform; DTO in
common-model; differenze, identita di istanza e normalizzazione in win-sensors
safe Rust; API nel runtime/IPC. UI TypeScript/Svelte per attivita e dashboard
raggruppata con dettaglio modale. Nessuna migrazione di linguaggio o driver.
La baseline sotto rimane storica, non un elenco corrente di funzioni mancanti.


Delta 2026-10-06 — ADR 0009: aggiunti `security-core` (modelli/regole safe Rust)
e `response-engine` (policy/journal/recovery safe Rust). Lo storage mantiene
l'atomicità tra evento, bookmark e detection. Un worker separato limita a una
operazione file alla volta; non blocca heartbeat/query SQLite. FFI aggiunte solo
in win-platform: query token della pipe, file handle esclusivi, identità/stream,
delete per handle e DPAPI. Nessuna migrazione o riscrittura dei componenti.

## Delta implementato dopo questo audit iniziale

La tabella originale sotto resta la baseline pre-modifica. [ADR 0008](adr/0008-windows-service-and-event-log.md)
estende win-platform (SCM, Event Log, pipe dedicata) e aggiunge win-sensors in safe
Rust. Fabric conserva raw con limiti 16 MiB/coda e 2 MiB/batch. Storage riprende
dall'ultimo bookmark committato; un test verifica che il rollback non lo avanzi.
IPC/UI espongono XML per UUID; installer/uninstaller usano account virtuale e ACL.
Nessuna migrazione di linguaggio o driver. Le fixture sintetiche restano nei test.
La conta dei 17 blocchi unsafe sotto si riferisce alla baseline: le nuove API sono
sempre confinate in win-platform. Installazione amministrativa e test SCM/ACL
non sono dichiarati eseguiti; consultare VALIDATION.md.

Data: 2026-10-04. Ambito: repository esistente `piko`, dopo la prima fondazione e prima di nuove feature. Fonte normativa: [addendum originale](ARCHITECTURAL_ADDENDUM.md), che integra e modifica i [requisiti iniziali](REQUIREMENTS.md). Non è stato creato un nuovo progetto.

## Esito

**Nessuna migrazione Rust → C è giustificata dal codice attuale.** I componenti applicativi sono safe Rust; i 17 blocchi `unsafe` proprietari sono concentrati nel solo `crates/win-platform/src/native.rs` e avvolgono API Win32 documentate. La UI è già TypeScript/Svelte. SQLite e WebView2 hanno implementazioni native di terze parti: `forbid(unsafe_code)` non rende memory-safe l'intero albero di dipendenze.

Il prodotto è un prototipo reale e parziale: esegue self-health → storage → IPC → UI/CLI. Non simula una protezione attiva. La distinzione fra sorgenti assenti e runtime attivo è visibile. I risultati definitivi di compilazione e test sono in [VALIDATION.md](VALIDATION.md); non si attribuiscono percentuali di coverage senza strumentazione.

## Inventario e classificazione

`working` significa che quella funzione ha implementazione reale e test indicati, non che il componente sia qualificato per produzione. `partial` indica limiti funzionali o verifiche mancanti. Nessun componente è classificato `MIGRATE` o `DELETE` per uniformare il linguaggio.

| Component | Current Language | Status | Unsafe/FFI | Windows dependency | Test coverage | Recommendation |
|---|---|---|---|---|---|---|
| `common-model` | Safe Rust | working: DTO health | assente proprietario | bassa | serializzazione esercitata da IPC/frontend; nessuna coverage misurata | KEEP: piccolo contratto stabile |
| `event-schema` | Safe Rust | working: schema v1, raw references, validazione | assente proprietario | bassa | 3 unit test: roundtrip, limiti, versioni, causal self-reference | KEEP; estendere compatibilità in modo versionato |
| `event-fabric` | Safe Rust | working: coda limitata e contatori perdita | assente proprietario | bassa | 3 unit test: overflow, configurazione, evento oversize | KEEP; aggiungere budget complessivo in byte prima di sensori ad alto volume |
| `event-storage` | Safe Rust; SQLite C dipendenza | working/partial: WAL, batch, chain, raw, query | nessuno proprietario; FFI in rusqlite/libsqlite3-sys | bassa | 9 integration test: replay, atomicità, restart, corruzione, budget, tail limitation | KEEP; segmenti/retention/cifratura restano futuri |
| `event-storage/examples/storage_bench` | Safe Rust | working: misura sintetica locale | indiretto SQLite | bassa | esecuzione benchmark; non misura monitoraggio Windows | KEEP; baseline hardware distinta da soglie commerciali |
| `win-platform/lib` e `native` | Rust + unsafe Win32 FFI | working/partial: identità e named pipe | 17 blocchi, confine piccolo | alta | 2 test nativi e smoke IPC; cross-user/session, failure injection e stress non completi | KEEP linguaggio; REFACTOR incrementale documentazione/test del boundary |
| `ipc` | Safe Rust | working: protocollo read-only v1 e frame bounded | wrapper Windows indiretto | alta per trasporto; bassa per decoder | 2 unit test + smoke; no metodi privilegiati | REFACTOR futuro DTO query/integrity fuori da storage, evitando SQLite transitivo nella UI |
| `security-service/main` | Safe Rust | partial: console runner, non SCM | assente | alta per runtime | exit/error e smoke; lifecycle SCM assente | KEEP; aggiungere adapter SCM quando autorizzazione/storage di produzione pronti |
| `security-service/runtime` | Safe Rust | working/partial: heartbeat, queue, health e shutdown | wrapper Windows indiretto | alta | configurazione limitata + test integrazione processo; proprietà shutdown da stressare | REFACTOR completato con worker storage separato; nessun motivo per C |
| `security-service/runtime/storage_worker` | Safe Rust | working/partial: singolo writer, queue8 e scadenze | SQLite indiretto | bassa | queue full e richiesta scaduta; smoke reale | KEEP; fault injection I/O e saturazione prima di produzione |
| `cli` | Safe Rust | working: health/events/verify | wrapper Windows indiretto | alta | smoke vero verso backend; parser argomenti minimale | KEEP |
| `desktop-ui/src-tauri` | Safe Rust/Tauri | working/partial: bridge di tre comandi | Tauri/WebView2 nativo indiretto | alta | build Windows; prova end-to-end descritta nella validazione | KEEP; nessuna decisione di sicurezza nel bridge |
| `desktop-ui/src/App.svelte`, `app.css`, `Icon.svelte` | Svelte/TypeScript/CSS/SVG | working: quattro viste | nessuno proprietario | WebView2 alla distribuzione | 3 test browser; keyboard/theme/layout e stato offline | KEEP; Attack Paths nascosta finché esiste un backend utile |
| `desktop-ui/src/lib/api` | TypeScript | working: presentazione/validazione risposta | invoke Tauri, non Win32 diretto | media | unit test DTO, filtri, errori | KEEP; precisione interi64 da evolvere prima di runtime molto lunghi |
| `desktop-ui/src/lib/i18n`, `format`, `preferences` | TypeScript | working: it/en, formattazione, persistenza UI | assente | bassa | unit test preferenze; test browser lingua/tema | KEEP; nessuna policy persistita in localStorage |
| `desktop-ui/tests`, `*.test.ts`, fixture storage | TypeScript/Rust | working: dati sintetici development-only | harness soltanto | mista | unit/integration/browser; nessun malware reale | KEEP: fixture utili, non mock di produzione |
| `fuzz` | Rust/libFuzzer | partial: target definiti | dipendenza harness | bassa | campagna non eseguita; nessuna falsa promessa di fuzz coverage | KEEP; aggiungere runner dedicato |
| `scripts/smoke.ps1`, `scripts/smoke-runtime.ps1` | PowerShell | working/partial: harness unico e wrapper CI | .NET/processi test | alta | smoke reale con PID proprio, protocollo e persistenza | REFACTOR completato: CI/README usano le stesse asserzioni |
| `scripts/ci-*`, `.github/workflows/ci.yml`, `deny.toml` | PowerShell/YAML/TOML | partial: configurazione CI | tool esterni, non prodotto | alta runner Windows | workflow remoto non eseguito in questa sessione | KEEP; verificare tool pin, download browser e artefatti prima di chiamarla green |
| `docs`, `piko.dev.json`, manifest/lockfile | Markdown/JSON/TOML | working/partial: contratti e configurazione dev | nessuno | mista | parsing config; revisione link e coerenza | KEEP; allineare addendum e stato verificato |

## Prototipi e componenti assenti

- Il processo `piko-service.exe` ha un nome orientato al servizio futuro, ma è oggi un runtime console. Non si registra nello SCM, non richiede elevazione e non fornisce self-defense.
- Health, eventi e verifica chain derivano dal backend. `not_implemented` indica ETW, Event Log, detection ed enforcement assenti. Browser standalone mostra indisponibilità senza inventare dati.
- Il database è un archivio di sviluppo in chiaro. Hash chain senza ancoraggio indipendente non protegge da riscrittura completa/troncamento; il relativo test ne documenta il limite.
- Driver, recovery nativa, `causal-graph`, `attack-path-engine`, `counterfactual-engine`, policy engine e sensori di topologia **non sono implementati**. La loro presenza nei diagrammi è una decisione di architettura, non una feature finta.
- I due grafi potenziale e controfattuale non vengono ricavati dagli heartbeat. Non sono stati creati dataset di demo per riempire la UI.

## Findings e azioni

1. Le operazioni SQLite sincrone dentro il loop async potevano sospendere heartbeat e timeout. Il refactor mantiene Rust, introduce un worker dedicato, queue limitata, massimo quattro richieste attive, snapshot health e scadenze. È manutenzione del codice esistente, non migrazione di linguaggio.
2. `TokenSessionId` identifica una sessione Windows/Terminal Services; non è `TOKEN_STATISTICS.AuthenticationId`. `logon_session` resta `None`; il SID/sessione del peer serve soltanto al confine IPC di sviluppo.
3. Il controllo dimensione della configurazione deve precedere l'allocazione senza limite: lettura limitata a 16 KiB + un byte sentinella.
4. Le garanzie del trasporto sono same-user/same-session, non autenticità dell'app o consenso dell'utente. Non aggiungere azioni privilegiate a questo endpoint.
5. Una migrazione C del piccolo boundary Win32 attuale aggiungerebbe ABI, build, ownership e test duplicati senza eliminare alcuna API problematica. **KEEP**.
6. Dipendenze, SBOM e CI richiedono verifica separata: un lockfile o una pipeline definita non dimostrano assenza di vulnerabilità né riproducibilità binaria.

## Componenti che potrebbero beneficiare del C

Sono candidati futuri, non migrazioni approvate: driver minimo WDK/minifilter/callback, boot/recovery nativa, adapter low-level per cui i binding Rust risultassero materialmente immaturi. Ciascuno richiede confronto concreto API/tooling, test comuni, protocollo stretto e decisione secondo [LANGUAGE_DECISIONS.md](LANGUAGE_DECISIONS.md). Il core, i grafi e la policy rimangono safe Rust.

## Metodo e limiti dell'audit

Inventario da manifest e sorgenti del repository; ricerca di `unsafe`, test e mock; lettura dei boundary e dei lifecycle; confronto con i requisiti. Non sono stati eseguiti audit formali, pentest, Driver Verifier o misure di code coverage. Non esiste un driver su cui eseguirli. Le API e i vincoli futuri sono verificati su documentazione primaria, riportata nelle decisioni linguistiche e nella matrice di fattibilità.



Delta 14 ottobre — ADR 0028: codec gzip bounded in safe Rust/event-storage, flate2 rust_backend. Digest del JSON originale, lettura legacy compatibile, nessun nuovo FFI o conversione C. Limiti originali del lotto mantenuti, decompressione e integrità testate.
