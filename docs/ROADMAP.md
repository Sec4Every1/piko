# Roadmap di piko

Data: 2026-10-04. Per le scelte di implementazione prevale l'addendum: correttezza → sicurezza → affidabilità → supporto piattaforma → memory safety → spiegabilità → prestazioni → convenienza di sviluppo. Basso consumo, usabilità e qualità visiva restano obiettivi del prodotto, senza prevalere su queste garanzie. Nessuna data commerciale è promessa.

## Stato della prima consegna

Aggiornamento 0.2.0 (2026-10-06): implementati detection Event Log a quattro
regole, quarantena manuale, risposta con piano/conferma/journal e recovery del
contenuto da vault DPAPI. UI/CLI collegate e prova nativa completa. Questo
anticipa una parte limitata delle fasi response/recovery; non rende complete
le fasi di telemetria, policy, causalità o qualifica di produzione.

La phase 0 produce gli otto documenti richiesti e ADR. La `0.1.0-dev` avvia una **slice parziale della phase 1**: workspace Rust modulare, modelli e schema versionato, fabric bounded, SQLite WAL/batch con verifica chain, runtime console indipendente, API locale read-only, CLI e UI Tauri/Svelte/TypeScript. La slice successiva aggiunge Event Log reale con bookmark e raw, adapter SCM e installer locale; non implementa prevenzione endpoint.

L'effettiva esecuzione dei test/build e le eventuali limitazioni dell'ambiente devono essere riportate nel README e nell'output di validazione. La presenza del sorgente non viene confusa con installazione riuscita o qualifica di produzione.

**Phase 1 non completa:** restano il servizio SCM installato/verificato, installer/uninstaller firmato, verifica delle ACL installate e della policy lettore SID, test lifecycle/reboot, matrice OS e prove di robustezza/performance. Dal 13 ottobre 2026 ETW processi/immagini, risposta manuale su singoli processi, controlli rete e prove AppContainer sono integrati secondo i limiti in IMPLEMENTATION_STATUS. Restano assenti driver, detection comportamentale generale, cifratura del registro eventi, protected history separata dall'utente console, recovery generale, checkpoint firmati/esterni, aggiornamenti sicuri e fleet.

## Milestone e criteri di uscita

| Fase | Vertical slice | Criterio verificabile di completamento |
| --- | --- | --- |
| 0 — Architecture | Documenti, matrice API/limiti, threat model, ADR | Ogni promessa distinta da design e implementazione; requisiti preservati |
| 1 — Foundation | Runtime/service, UI, IPC, config, ingestion, storage, health | UI ↔ servizio reale; ACL/session/caller testati; chiusura UI non ferma servizio; restart/uninstall puliti; degradazione visibile |
| 2 — First real telemetry | ETW process/thread/image, Event Log, Registry/network/auth di base | Fixture da eventi reali su build target; raw/provenance; PID reuse; loss/gap/bookmark e sensore fermo verificati |
| 3 — Fabric + SIEM | Normalizzazione, segmenti, indici, filtri, dettaglio, retention, integrity | Ricerca locale utile su dati reali; replay parser; budget disco; segment corruption; checkpoint/freshness descritti correttamente |
| 4 — Causal graph | Processi, identità, file, rete, timeline e grafo incidenti | Relazioni provate distinte da correlazioni; edge con event refs; query bounded e UI aggregata |
| 4A — Potential attack paths | Identità condivise, stato locale/permission, archi CAN_*, indici incrementali | Single-host reale; precondizioni AND, unknown/stale, deny/allow qualificati; query limitata e incompleta esplicita; nessun blocco da sola possibilità |
| 4B — Path progression | Prefissi osservati confrontati con percorsi potenziali e asset critici | Evidenze compatibili, tentativi distinti da successi, fattori di confidence spiegati e remaining hops condizionali |
| 5 — Software/Registry history | Inventory, hash/firme, genealogia, expected state, behavior diff | Storia versionata e WOW64; A→B→A preservato quando osservato; lacune esposte; supply-chain attribution con confidence |
| 6 — Policy/intent/capability | SecurityTransaction, contratti, probation, policy history | Scope/scadenza/identità testati; nuove capability non ereditate ciecamente; enforcement capability esplicita |
| 6A — Counterfactual e cut points | Overlay di proposte, capability expansion, diff percorsi e remediation | Snapshot base immutabile; stale revalidation; alternative residue e impatto/reversibilità spiegati; nessuna applicazione implicita |
| 7 — Ransomware | Canary set, rate/breadth detection, capsule, metadata recovery | Simulatori innocui; misura file modificati prima di azione; nessun “blocco garantito” finché manca mediazione; restore verificato |
| 8 — Deception | Decoy file, Registry, identity/credentials opt-in | Nessun accesso utile/backdoor; enumeration vs auth distinti; rimozione pulita e privacy |
| 9 — Identity | Session/token/privilege/account/group/remote context | Lineage con evidenze; limiti PPL e account veto documentati; test provisioning legittimo |
| 10 — Network intelligence | Attribution, DNS/TLS metadata, first-seen e modelli per software | IPv4/IPv6/loopback/VPN; dati mancanti espliciti; nessuna TLS interception implicita; nessun criterio geografico determinante |
| 11 — Response | Terminate, quarantine, restrizione rete, containment, rollback mirato | Ogni azione autorizzata/auditata; precondizioni, race, partial failure e undo sicuro testati; prove preservate |
| 12 — Kernel sensor | Soltanto gap dimostrati di visibility/enforcement | Driver minimo firmato; HLK/HVCI/Verifier; timeout/fail mode e compatibilità filesystem; niente hook privati |
| 13 — Boot/driver/system integrity | BootIdentity, Secure Boot/TPM/measured boot/VBS/HVCI, BYOVD/genealogy | Hardware assente/degrado testati; osservazione distinta da attestazione; drift expected/explained/unexplained |
| 14 — Vulnerability/patching | Inventory→advisory→remediation; componenti e dipendenze | Feed isolati/verificati e opzionali; applicability/firma; snapshot, install, verifica, probation e rollback quando possibile |
| 15 — Collective immunity | Enrollment, mTLS/protocollo, fingerprint causali, patient zero | Più endpoint reali; offline autonomy; sharing minimo; poisoning/replay; prevented incident visibile; niente blocco fleet per mera correlazione |
| 16 — PQC provider | Algoritmi/hybrid qualificati dietro astrazioni crypto | Test vector, audit/interoperabilità, downgrade handling e migrazione chiavi/evidenze; nessuna crypto custom |

La numerazione conserva il piano originale, ma contiene dipendenze: la phase 7 non può dichiarare un blast radius preventivo garantito prima che la phase 12 o un'alternativa Windows supportata fornisca mediazione equivalente. La phase 6 può valutare policy prima di poterle applicare ovunque. La phase 16 parte con crypto agility in phase 0, mentre i provider effettivi vengono introdotti solo dopo qualifica.

L'addendum è integrato senza ricominciare il repository. [COMPONENT_AUDIT.md](COMPONENT_AUDIT.md) e [LANGUAGE_DECISIONS.md](LANGUAGE_DECISIONS.md) sono il gate prima di nuove feature/migrazioni. Gli engine 4A/4B/6A sono progettati, non ancora implementati. Attack Paths appare solo dopo collector locali e query reali utili; AD/Entra/fleet non sono prerequisiti. Il driver fase12 può essere C minimale se la decisione comparativa lo giustifica. Il coordinator fase15 distribuisce topology pattern/precondizioni insieme al fingerprint; ogni endpoint verifica applicabilità prima di prevenire.

Offline recovery è una milestone futura dopo formati e history verificabili: reader indipendente, confronto current/last-verified/historical e piano di chiavi recuperabili. Non è inclusa nella prima consegna. Counterfactual analysis richiede incidenti e grafo affidabili; suggerisce punti di interruzione con evidenze e rischio di falso positivo, senza convertire correlazioni in causalità.

## Tracciabilità dei requisiti

I numeri sono quelli di [REQUIREMENTS.md](REQUIREMENTS.md); questa mappa non modifica il testo originale.

| Requisiti | Proprietario/milestone |
| --- | --- |
| 1–6, 112–116 | Principi, workspace, ADR e strategia di tutte le fasi |
| 7–14 | Fasi 1–3; raw, tempo, storage, integrity e loss; anchoring in 15 |
| 15–19 | Fasi 4–5; grafo, stato, Registry, genealogia/supply-chain |
| 20–23 | Fase 6 e enforcement dipendente da 11–12 |
| 24–27 | Fase 7 con dipendenze 11–12 e recovery |
| 28–31 | Fase 8 deception e protezione authority |
| 32–35 | Fase 10 e feed opzionali |
| 36–45 | Fase 9; data/device graph nelle fasi 4–5 e network in 10 |
| 46–51 | Fasi 12–13; self-health da 1; deep census dopo sorgenti reali |
| 52–55 | Classificazione multidimensionale, fasi 5/9/14 e detection trasversale |
| 56–60 | Fase 15; single-host senza sezioni fleet inutili |
| 61–64 | ADR crypto da 0, update sicuro prima di release, provider PQC in 16 |
| 65–68 | Flight recorder 3, capsule 7/11, counterfactual 4/15, privacy trasversale |
| 69–72 | Performance/bounds/adaptive telemetry in ogni slice |
| 73–95 | UI progressiva da 1; incidenti/grafo/query soltanto con backend reale |
| 96–99 | Deployment phase 1 completo, degrado/offline, recovery futura |
| 100–111 | Gate di qualità, replay, fuzz, audit e capability matrix per ogni fase |

## Test e release gates

Ogni milestone richiede analisi API, implementazione, test innocui, misura performance, documentazione aggiornata, formatter/linter e prova di integrazione. Unit/integration test verificano la logica realizzata; property tests e replay verificano invarianti temporali e causalità. Storage corruption deve coprire bit flip, reorder, missing raw, cancellazione interna e distinguere ciò che una chain non ancorata non rileva.

Fuzz target progressivi: event decoder e IPC prima di sorgenti ampie; poi telemetry, query parser dedicato senza eval, policy e parser intelligence. CI produce lockfile verificato, test report, SBOM, hash e benchmark summary per release. Build riproducibili sono un obiettivo da dimostrare confrontando artifact, non una proprietà ottenuta soltanto usando Cargo.lock.

La UI evolve da Dashboard/Activity/Security Log/Settings a incidenti, applicazioni, rete, identity, device, vulnerabilità, recovery e investigazione quando le rispettive capacità sono reali. Italiano/inglese, tema system/light/dark, keyboard navigation, screen reader, high DPI e progressive disclosure sono requisiti permanenti. Un dettaglio “Perché?” deve esporre la stessa verità dei dati tecnici; nessun pulsante produce un incidente finto. Simulazioni rimangono nel replay harness identificato come development-only.

