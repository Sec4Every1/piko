# piko

**Open source under the [MIT License](LICENSE).** Windows x64 release packages
are built from this repository by [GitHub Actions](.github/workflows/release-windows.yml)
when a version tag is pushed.

Monitor locale di sicurezza per Windows, con evidenze consultabili e azioni manuali
confermate. La prima consegna ha un [perimetro chiuso](docs/FIRST_RELEASE.md):
le funzionalità future della piattaforma restano nella matrice dei requisiti.
I sorgenti in sviluppo non sono una nuova release verificata o installata.

Strategia: **memory-safe by default, platform-native when justified**. L'[audit del repository](docs/COMPONENT_AUDIT.md) conserva i componenti validi; le [decisioni linguistiche](docs/LANGUAGE_DECISIONS.md) non richiedono migrazioni Rust → C attuali. Il [modello Attack Paths](docs/ATTACK_PATH_MODEL.md) distingue grafi osservati, potenziali e controfattuali; questi engine sono pianificati e non ancora presenti nel runtime.

**Stato: `0.2.0`, detection, quarantena, recovery e controllo rete per eseguibile.** Dodici regole analizzano eventi Windows reali, con segnalazioni persistenti ed evidenze. UI e CLI preparano azioni con scadenza: dopo conferma, la quarantena salva e verifica un backup cifrato prima di rimuovere il file. Il recovery verifica il contenuto e non sovrascrive destinazioni esistenti. Non è una protezione endpoint completa: permette l’arresto confermato di una singola istanza, ma non previene operazioni kernel. L'esecuzione SCM amministrativa e la qualifica di produzione restano da verificare.

La dashboard raggruppa le segnalazioni in righe compatte; aprendo un gruppo si
consultano le singole occorrenze, i dettagli e l'evidenza grezza. La pagina
**Attività applicazioni** mostra processi e TCP IPv4/IPv6 osservati ogni 10 secondi,
identità di istanza e storico; si affianca al collector ETW processi/immagini, disponibile secondo i diritti Windows.
La [matrice dei requisiti](docs/REQUIREMENT_MATRIX.md) mantiene visibili le lacune.

I nuovi controlli di rete usano Windows Firewall e un helper amministrativo separato;
non richiedono di elevare la UI. Il rischio 0–100 è euristico e spiegato; la probabilità
di falso positivo resta non stimabile. [Dettagli architetturali](docs/adr/0010-app-network-control.md).

## Cosa funziona

- Runtime Rust indipendente dall'interfaccia, lifecycle SCM e console, eventi propri e sensori Windows Event Log System/Application/Security/Defender Operational secondo i diritti effettivi.
- Importazione iniziale limitata, sottoscrizioni continue, evidenze XML originali consultabili e ripresa dal bookmark dell'ultimo evento durabile. Nessun avanzamento del cursore dopo un commit fallito.
- Eventi versionati, identificatori persistenti dell'archivio, sequenza per istanza e tempo monotono. Il boot Windows e la sessione di autenticazione restano sconosciuti finché una sorgente li misura.
- SQLite WAL, scritture in batch, coda limitata, budget disco e verifica della catena SHA-256; errori e perdita di eventi espliciti.
- API Windows tramite named pipe: DACL esplicita, rifiuto client remoti e messaggi limitati. Console: controllo SID/sessione. Servizio: lettore iscritto per SID, diritti dati minimi e verifica del PID server nel SCM; mutazioni consentite solo a token elevati verificati dopo lettura della richiesta.
- Dodici regole su Security, System e Defender Operational, con verifica di provider e canale. Il livello dell'evento Windows non viene confuso con un verdetto malware.
- Quarantena manuale di file locali nelle radici autorizzate, con identità file/hash SHA-256, piano di 5 minuti, journal SQLite, backup DPAPI e recovery senza overwrite. Link, stream alternativi e directory protette sono rifiutati. Dettagli e limiti in [RESPONSE.md](docs/RESPONSE.md).
- CLI e desktop Tauri 2 con Svelte/TypeScript: dashboard di segnalazioni comprensibili con contesto MITRE ATT&CK e verifiche/remediation manuali; log tecnici separati con heartbeat, XML e JSON; quarantena/ripristino, manuale, stato dei permessi app, italiano/inglese e temi chiaro/scuro/sistema.

L'anteprima nel browser dichiara di non avere il collegamento nativo: non genera dati dimostrativi. I dati sintetici dei test non entrano nella release.

## Avvio su Windows x86-64

Il pacchetto compilato è in `artifacts/piko-0.2.0-windows-x64-release`.
Per usarlo senza installazione fare doppio clic su **Open-Piko.cmd** da una
sessione utente normale, oppure eseguire `Start-Piko.ps1` da PowerShell.
Il [manuale utente](docs/MANUALE_UTENTE.md) è disponibile anche nella pagina Manuale
dell’app. In Permessi app trovi inventario software e blocco/rimozione rete per percorso .exe,
con anteprima e helper UAC. Trovi anche prove AppContainer (copia isolata, zero capacità di rete, un processo, 512 MiB) e advisory locali con associazione esplicita prodotto/versione. I blocchi generali su file e dispositivi per tutte le app restano da implementare.
Per installare il servizio con avvio automatico, estrarre lo ZIP e fare doppio clic
su **Install-Piko.cmd**. Una richiesta UAC standard autorizza Windows a registrare
il servizio; l’installer identifica automaticamente l’utente e apre la dashboard
al termine. La UI resta non elevata. Per avviare piko senza installazione usare
**Open-Piko.cmd**. Il pacchetto attuale non è firmato, quindi Windows può mostrare
un avviso di reputazione; pubblicazione e hash sono generati dalla pipeline.
I dettagli sono in [INSTALLATION.md](docs/INSTALLATION.md).

Prerequisiti: Rust stabile MSVC, C++ Build Tools e Windows SDK, WebView2, Node.js LTS. `rust-toolchain.toml` sceglie MSVC per questo progetto senza cambiare il toolchain globale. Sono necessari Internet e accesso ai registri solo per la prima installazione delle dipendenze.

Dalla cartella del progetto, in un terminale:

```powershell
cargo build --workspace --locked
.\target\debug\piko-service.exe --config .\piko.dev.json
```

Questo comando usa la modalità console e salva in `.runtime/events.db`; Ctrl+C richiede flush e arresto. Non richiede diritti amministrativi. La modalità `--service` è riservata al servizio registrato dall'installer.

In un secondo terminale:

```powershell
cd apps\desktop-ui
npm ci
npm run tauri dev
```

In modalità console runtime e UI devono appartenere allo stesso utente/sessione. Il servizio installato usa invece un endpoint comune e il SID lettore configurato. Chiudere la UI lascia il monitoraggio attivo. Non viene creata un'icona tray.

Per ottenere l'app desktop con frontend incorporato:

```powershell
cd apps\desktop-ui
npm run build
cargo build --manifest-path src-tauri\Cargo.toml --features custom-protocol --locked
.\src-tauri\target\debug\piko-desktop.exe
```

Client da terminale, dalla radice del progetto:

```powershell
.\target\debug\piko.exe health
.\target\debug\piko.exe events "runtime.heartbeat"
.\target\debug\piko.exe verify
.\target\debug\piko.exe evidence <UUID>
```

## Configurazione e confini attuali

`piko.dev.json` controlla percorso dati, heartbeat, frequenza del batch, capacità della coda e budget disco. Le modifiche richiedono il riavvio del runtime. Il percorso dati relativo è risolto rispetto alla cartella da cui viene avviato il processo.

Nuove installazioni e profili creati da Open-Piko.cmd usano 2 GiB e retention
di 12 mesi. Configurazioni esistenti e `piko.dev.json` mantengono i propri valori
(il file di sviluppo usa 256 MiB). WAL/checkpoint richiedono margine: a capacità
esaurita il runtime segnala degrado e rifiuta scritture, senza accorciare la
retention per liberare spazio. Nessuna garanzia universale di 12 mesi per qualsiasi
volume di eventi. La protezione recuperabile delle nuove evidenze è opt-in e
rimane da qualificare; eventi normalizzati e indici restano in chiaro. La catena
locale non certifica l'assenza di riscrittura completa o troncamento della coda.

L'identità del chiamante deriva da Windows. Qualsiasi processo dello stesso utente/sessione può connettersi al runtime console: questo non prova l'intento umano e non protegge da malware con la stessa identità. Le azioni seguono comunque piano/hash/conferma e scope. Il servizio installato usa una pipe separata: il lettore autorizzato per SID accede dalle proprie sessioni; le mutazioni richiedono il token elevato effettivo del caller. Il client verifica il PID tramite SCM e non effettua fallback se il servizio installato è fermo.

Restano da completare la qualifica amministrativa e cross-user del servizio, packaging firmato e aggiornamenti; da implementare ETW, detection comportamentale, grafo causale, policy estese, enforcement processi/kernel e rete avanzata, recovery generale, cifratura del registro eventi e fleet. La [roadmap](docs/ROADMAP.md) distingue questi requisiti dalle capacità effettivamente presenti.

## Verifica

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
powershell -NoProfile -File scripts\smoke.ps1
cargo run --release --locked -p piko-event-storage --example storage_bench

cd apps\desktop-ui
npm run check
npm test
npm run build
npm run test:ui:install
npm run test:ui
```

Lo smoke test avvia un runtime temporaneo, verifica le richieste IPC reali e il client CLI e lo lascia arrestare normalmente. Conserva log e database di prova in una sottocartella `.runtime/smoke-*`. Eseguirlo senza un altro runtime piko già attivo nella stessa sessione.

I test di corruzione e replay usano soltanto eventi sintetici innocui. I fuzz target e i comandi sono in [fuzz/README.md](fuzz/README.md). La CI è configurata nel repository; la sua presenza non equivale a una pipeline remota già eseguita.

## Documentazione

- [Architettura](docs/ARCHITECTURE.md) e [decisioni ADR](docs/adr/0001-scope-and-vertical-slices.md)
- [Audit componenti](docs/COMPONENT_AUDIT.md), [decisioni linguistiche](docs/LANGUAGE_DECISIONS.md), [Attack Path Engine](docs/ATTACK_PATH_MODEL.md)
- [Threat model](docs/THREAT_MODEL.md) e [modello di sicurezza](docs/SECURITY_MODEL.md)
- [Schema eventi](docs/EVENT_SCHEMA.md), [privacy](docs/PRIVACY.md), [budget prestazionali](docs/PERFORMANCE_BUDGET.md)
- [Fattibilità e API Windows](docs/FEASIBILITY.md), [roadmap](docs/ROADMAP.md), [requisiti originali](docs/REQUIREMENTS.md)
- [Risultati di verifica](docs/VALIDATION.md)



Ricerca strutturata e relazioni osservate: in Log tecnici aprire Ricerca avanzata; in Attivita applicazioni selezionare un processo e Carica relazioni. Vedere il manuale aggiornato e ADR 0012.

Le nuove integrazioni includono dodici regole con nomi da evidenza validata, CPU/RAM del monitor, avvio al login facoltativo, annotazioni personali e filtri di revisione, blocchi rete in entrambe le direzioni e Authenticode locale su richiesta. Limiti e istruzioni: docs/MANUALE_UTENTE.md, docs/IMPLEMENTATION_STATUS.md.

Nuove letture locali: storico Run/RunOnce prima/dopo/raw (Permessi app), correlazione di credenziali errate 4625 con T1110 e remediation (Dashboard), porte locali UDP per istanza (Attività applicazioni). Limiti e qualificazione in ADR 0023–0025 e MANUALE_UTENTE.md; nessuna modifica automatica account/registro.
