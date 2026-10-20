# Language Decisions

Delta 2026-10-06 — ADR 0009: regole deterministiche, DTO, journal, conferme e
recovery restano safe Rust. Le API file/token/DPAPI documentate richiedono un
boundary Windows in win-platform, con ownership e buffer limitati. Non emerge
un motivo per introdurre C o driver in questa implementazione.

Estensione ADR 0008: SCM usa `windows-service 0.8.1`; Event Log e apertura pipe
restano binding `windows-sys` in `win-platform`. Normalizzazione XML, code,
persistenza e UI rimangono safe Rust/TypeScript. Gli handle Event Log sono
non-Send/non-Sync e non lasciano il thread creatore. Nessun C proprietario aggiunto.

Data: 2026-10-04. Decisione applicata al repository esistente; dipende da [COMPONENT_AUDIT.md](COMPONENT_AUDIT.md). Regola: **Memory-safe by default. Platform-native when justified.** Nessuna percentuale obiettivo di Rust e nessuna conversione automatica.

Priorità dell'addendum: correctness → security → reliability → platform support → memory safety → explainability → performance → development convenience. La scelta non dipende dal numero di esempi disponibili o dalla familiarità dell'autore con il linguaggio.

## Decisioni attuali

| Ambito | Decisione | Motivazione verificabile |
|---|---|---|
| Modelli, fabric, storage, runtime, CLI | KEEP safe Rust | Logica già separata, testabile, senza unsafe proprietario; nessuna carenza Win32 che giustifichi C |
| Windows FFI per token e named pipe | KEEP Rust + boundary dedicato | Poche API documentate, ownership locale e RAII, buffer limitati; un ABI C aggiuntivo non rimuoverebbe rischi |
| UI | KEEP Tauri 2/Rust + Svelte/TypeScript | Frontend presenta dati; decisioni/autorizzazione rimangono nel backend |
| Worker SQLite | REFACTOR in safe Rust, non MIGRATE | Il problema era isolamento del lavoro bloccante e backpressure, indipendente dal linguaggio |
| Attack Path / Counterfactual / Causal Graph | Safe Rust per la futura implementazione | Algoritmi, indici, snapshot e policy non necessitano kernel/FFI; riusare identità e graph storage di piko |
| Driver minimo WDK | C ammesso e candidato preferibile dopo confronto concreto | Scegliere in base a supporto DDI/WDK/debugger/analisi per il driver effettivo; nessun driver o progetto C creato in anticipo |
| Boot/recovery low-level | Decisione differita per componente | Il reader/evidence planner può restare Rust; solo il confine nativo motivato potrà essere C |
| SQLite/WebView2 | Dipendenze native esplicite | Non riscrivere librerie mature per eliminare C; registrare versioni, advisories, licenze e superfici native |

## Tre livelli

1. **Safe Rust**: Security Core, fabric/storage, tutti gli engine, orchestrazione response/crypto, coordinator, CLI e logica di servizio. `#![forbid(unsafe_code)]` dove possibile.
2. **Unsafe Rust/Windows FFI**: boundary piccoli e dedicati, con contratto scritto e test. Nessun puntatore nativo attraversa la API verso engine/frontend. Ogni blocco significativo ha `SAFETY`; ownership e lifetime non dipendono dalla memoria di un chiamante non fidato.
3. **C/WDK/native**: soltanto quando riduce il rischio totale. Driver e adattatori minimi; nessun parser complesso, database, SIEM, ML, calcolo percorsi, reputazione o business logic nel kernel.

L'architettura kernel è `Windows → minimal native sensor/enforcement → protocollo stretto/versionato → Security Core`. Buffer, code e concorrenza limitati; nessun puntatore userspace conservato senza il contratto Windows appropriato; IRQL, cancellation, unload e cleanup devono essere verificati per le DDI scelte.

## Registro del boundary esistente

Il contratto operativo completo è in [win-platform/README.md](../crates/win-platform/README.md).

| Aspetto | Contratto corrente |
|---|---|
| Ownership | `OpenProcess`/`OpenProcessToken` → `OwnedHandle` → `CloseHandle`; conversioni SID/SDDL → `LocalAllocation` → `LocalFree` |
| Lifetime | Token e buffer restano vivi fino alla copia SID; SECURITY_ATTRIBUTES/SDDL restano vivi durante creazione pipe; Tokio possiede poi l'handle |
| Buffer size / pointers | Token buffer allineato con `usize`, dimensione OS limitata a 64 KiB; SID ottenuto da token OS, nessun puntatore JSON |
| Threading / synchronization | Nessuna impersonazione persistente; handle non esposti; pipe async gestita da Tokio; writer su worker dedicato |
| Caller guarantees | Identità ottenuta da Windows; nessun SID dichiarato dal frontend usato per autorizzare; pipe locale, client identification-level |
| Trusted/untrusted | API kernel Windows fonte di token; ogni messaggio IPC resta non fidato; stesso SID non implica software benigno |
| Failure modes | Accesso negato, peer terminato, sizing/encoding fallito, pipe occupata: errore esplicito, nessun fallback permissivo |
| Cleanup | RAII anche su early return; buffer non condivisi, nessun puntatore conservato oltre la chiamata |
| Copertura mancante | Cross-account/session/remoto, failure injection allocazioni/handle e stress non ancora esaustivi |

## Language Migration Decision: boundary named pipe attuale

**Component:** `piko-win-platform`.

**Current implementation:** Rust con Win32 FFI confinata, 17 blocchi unsafe proprietari.

**Problem:** completare prove dei failure path e autorizzazione di produzione; nessuna API mancante rilevata.

**Why Rust is materially worse here:** non dimostrato. Il binding espone le API necessarie senza wrapper privati o hooking.

**Why C reduces total risk:** non dimostrato; introdurrebbe un ABI e ulteriori regole manuali di ownership.

**Security impact:** mantenere DACL, remote rejection e verifica peer; non ampliare i comandi verso privilegi elevati.

**Memory-safety impact:** mantenere safe API con RAII; C non migliorerebbe la protezione dei buffer.

**Testing strategy:** characterization attuale identità/duplicato pipe più IPC reale; aggiungere identità diversa, peer chiuso e deadline/failure injection.

**Rollback strategy:** nessuna migrazione da invertire; refactor piccoli verificati contro gli stessi test.

**Expected performance difference:** nessun vantaggio misurato di C; vietato attribuirgli un numero ipotetico.

**Final recommendation:** **KEEP Rust; migliorare contratto e test del boundary.**

## Gate per ogni futura migrazione

Creare una decisione con tutti i campi sopra prima della conversione. Definire I/O, ownership, invarianti, fault model e comportamento corrente; creare characterization test e baseline; implementare una sola alternativa; far eseguire entrambe contro gli stessi input; confrontare output/errori/cleanup/performance; adottare dopo verifica, con rollback; rimuovere la precedente soltanto allora. Assenza di motivazione convincente → KEEP. `DELETE` si applica a duplicati/mock/codice inutilizzato o errato, non a codice funzionante per preferenza stilistica.

## Verifica del futuro codice C

L'eventuale componente C avrà compilazione separata, C ABI versionata con tipi a larghezza fissa e ownership esplicita, warning trattati come errori, SAL ove appropriato, static analysis/CodeQL, test di error/unload/cancellation, fuzz dei decoder in harness user-mode e Driver Verifier su VM di test. Hardening compiler/linker e HVCI devono essere compatibili con il modello WDK selezionato, non copiati indiscriminatamente dal user mode. Driver e impostazioni di sicurezza non devono essere modificati durante un audit senza una specifica esigenza e autorizzazione.

Le indicazioni Microsoft attuali privilegiano CodeQL per le verifiche statiche dei driver; SDV non è più supportato nei WDK recenti. Non basare un nuovo gate sull'obbligo di un tool ritirato. [Driver development tools](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/monitoring-driver-verifier), [stato di SDV](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/using-static-driver-verifier-to-find-defects-in-drivers), verificati 2026-10-04.

Contratti primari: [named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation), [TOKEN_STATISTICS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics), verificati 2026-10-04. Queste fonti definiscono i contratti Windows; la scelta KEEP è una valutazione del codice piko, non una raccomandazione Microsoft su Rust contro C.


## Decisione incrementale 0011 — Processi e TCP

ToolHelp, GetProcessTimes e IP Helper hanno contratti Win32 utilizzabili dalle
binding windows-sys gia presenti. Si mantiene un piccolo boundary unsafe Rust,
con handle RAII e parsing bounded. Modelli, polling, delta, hash di identita e
normalizzazione rimangono safe Rust. Non e giustificata una migrazione in C.
Vedere ADR 0011 per input, lifetime, fallimenti, limiti e test.

