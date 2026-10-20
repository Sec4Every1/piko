# Tracciabilita dei 116 requisiti

Aggiornamento: 20 ottobre 2026. Questa matrice non dichiara completato il prodotto.
Le righe sono sezioni della specifica, ciascuna contiene piu criteri di accettazione.
Parziale significa codice funzionante per una porzione; non implementato significa nessun percorso completo disponibile.
Le decisioni architetturali da sole non contano come implementazione.

Filtri essenziali installati, storico ripulito dopo consenso specifico con backup
e nuova catena esplicita. ADR 0029/0030; non segmentazione HOT/WARM/COLD,
checkpoint firmati o garanzia di 12 mesi per qualsiasi volume entro 2 GB.

| ID | Requisito | Stato | Evidenza | Mancanza / limite |
|---|---|---|---|---|
| 1 | PRINCIPI FONDAMENTALI | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 2 | ARCHITETTURA GENERALE | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 3 | STACK TECNOLOGICO | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 4 | REGOLE PER UNSAFE | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 5 | COMPONENTE KERNEL | Non implementato | docs/REQUIREMENTS.md, sezione 5 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 6 | CARGO WORKSPACE | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 11 | PROTEZIONE DEI LOG | Parziale | crates/event-storage; crates/win-platform/src/file_response.rs; docs/SECURITY_MODEL.md | Catena hash locale e DPAPI recovery; non cifratura completa dei log, checkpoint firmati o ancoraggio indipendente. |
| 12 | REMOTE LOG ANCHORING | Non implementato | docs/REQUIREMENTS.md, sezione 12 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 15 | CAUSAL SECURITY GRAPH | Parziale | crates/security-core/src/investigation.rs; ADR 0012 | Associazioni osservate per istanza con riferimenti evento. Causalita, process tree verificato e percorsi di attacco non implementati. |
| 17 | REGISTRY HISTORY | Parziale | crates/app-control/src/registry_history.rs; crates/win-platform/src/registry_history.rs; ADR 0023 | Run/RunOnce HKCU/HKLM 32/64 bit, prima/dopo/raw e letture incomplete; pagina compatta e storico locale bounded. Non raccolta continua, autore, tutte le chiavi o recovery del registro. |
| 18 | SOFTWARE GENEALOGY | Parziale | crates/app-control; crates/response-engine; ADR 0009 e 0010 | Inventario in griglia con date dichiarate, discovery eseguibili e blocchi rete multipli confermati; quarantena/ripristino file. Storico metadati installer in ADR 0014; contratti granulari, genealogia verificata e storia completa policy mancanti. |
| 19 | SOFTWARE SUPPLY CHAIN | Parziale | crates/app-control; crates/response-engine; ADR 0009 e 0010 | Inventario in griglia con date dichiarate, discovery eseguibili e blocchi rete multipli confermati; quarantena/ripristino file. Contratti granulari e storia completa policy mancanti. |
| 20 | SECURITY TRANSACTIONS | Parziale | crates/app-control; crates/response-engine; ADR 0009 e 0010 | Inventario in griglia con date dichiarate, discovery eseguibili e blocchi rete multipli confermati; quarantena/ripristino file. Contratti granulari e storia completa policy mancanti. |
| 21 | CAPABILITY & BEHAVIORAL CONTRACT ENGINE | Parziale | crates/app-control; crates/response-engine; ADR 0009 e 0010 | Inventario in griglia con date dichiarate, discovery eseguibili e blocchi rete multipli confermati; quarantena/ripristino file. Contratti granulari e storia completa policy mancanti. |
| 22 | BEHAVIOR DIFF TRA VERSIONI | Non implementato | docs/REQUIREMENTS.md, sezione 22 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 23 | PROBATION MODE | Parziale | crates/app-control/src/sandbox.rs; crates/app-control/src/restricted.rs; ADR 0013,0021 | Windows Sandbox manuale e prova host AppContainer con conferma e copia del solo exe. No probation automatica per versione, permessi granulari globali o congelamento aggiornamenti. |
| 24 | RANSOMWARE ENGINE | Non implementato | docs/REQUIREMENTS.md, sezione 24 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 25 | CRYPTOGRAPHIC CANARIES | Non implementato | docs/REQUIREMENTS.md, sezione 25 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 27 | PROTECTED RECOVERY HISTORY | Parziale | crates/app-control; crates/response-engine; ADR 0009 e 0010 | Inventario in griglia con date dichiarate, discovery eseguibili e blocchi rete multipli confermati; quarantena/ripristino file. Contratti granulari e storia completa policy mancanti. |
| 28 | DECEPTION FABRIC | Non implementato | docs/REQUIREMENTS.md, sezione 28 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 29 | DECOY IDENTITY | Non implementato | docs/REQUIREMENTS.md, sezione 29 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 30 | DECOY CREDENTIALS | Non implementato | docs/REQUIREMENTS.md, sezione 30 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 31 | DECOY DATA | Non implementato | docs/REQUIREMENTS.md, sezione 31 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 33 | DESTINATION REPUTATION | Non implementato | docs/REQUIREMENTS.md, sezione 33 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 35 | DNS / ENCRYPTED TRAFFIC INTELLIGENCE | Non implementato | docs/REQUIREMENTS.md, sezione 35 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 36 | IDENTITY ENGINE | Parziale | crates/security-core/src/authentication.rs; identity_activity.rs; crates/event-storage; ADR 0024/0031 | Correlazione 4625 e fatti XML 4624/4625/4648/4672 e ciclo account 4720/4722/4725/4726 (ADR 0033), account/subject/PID distinti, categorie/cursore, cinque righe, dettagli/raw e verifiche manuali. Audit/accesso Security richiesti; niente token lineage, identity graph, protezione credenziali, causalità o blocco account. |
| 37 | TOKEN LINEAGE | Non implementato | docs/REQUIREMENTS.md, sezione 37 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 38 | PRIVILEGE TRANSITIONS | Non implementato | docs/REQUIREMENTS.md, sezione 38 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 39 | ACCOUNT CREATION POLICY | Non implementato | docs/REQUIREMENTS.md, sezione 39 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 40 | CREDENTIAL ACCESS FIREWALL | Non implementato | docs/REQUIREMENTS.md, sezione 40 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 41 | BROWSER SESSION PROTECTION | Non implementato | docs/REQUIREMENTS.md, sezione 41 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 42 | SENSITIVE RESOURCES | Parziale | crates/app-control; crates/response-engine; ADR 0009 e 0010 | Inventario in griglia con date dichiarate, discovery eseguibili e blocchi rete multipli confermati; quarantena/ripristino file. Contratti granulari e storia completa policy mancanti. |
| 43 | DATA SECURITY GRAPH | Non implementato | docs/REQUIREMENTS.md, sezione 43 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 44 | DEVICES / PERIPHERALS | Non implementato | docs/REQUIREMENTS.md, sezione 44 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 45 | REMOTE ADMINISTRATION | Non implementato | docs/REQUIREMENTS.md, sezione 45 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 46 | BOOT & FIRMWARE INTEGRITY | Non implementato | docs/REQUIREMENTS.md, sezione 46 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 47 | DRIVER TRUST ENGINE | Non implementato | docs/REQUIREMENTS.md, sezione 47 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 48 | SYSTEM INVARIANTS | Non implementato | docs/REQUIREMENTS.md, sezione 48 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 49 | SELF-DEFENSE | Non implementato | docs/REQUIREMENTS.md, sezione 49 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 50 | SEMANTIC HEARTBEAT | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 51 | DEEP DIAGNOSTIC ENGINE | Non implementato | docs/REQUIREMENTS.md, sezione 51 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 52 | PUP CLASSIFICATION | Non implementato | docs/REQUIREMENTS.md, sezione 52 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 53 | VULNERABILITY ENGINE | Parziale | crates/app-control/src/advisories.rs; ADR 0022; docs/ADVISORY_FEED.md | Feed locale bounded, binding manuale prodotto/versione esatta, CVSS attribuito, advisory/fine supporto e remediation. No identita dedotta, feed firmato/live o patch automatiche; assenza di match non prova sicurezza. |
| 54 | PATCH MANAGEMENT | Non implementato | docs/REQUIREMENTS.md, sezione 54 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 55 | TARGETED SURVEILLANCE DETECTION | Non implementato | docs/REQUIREMENTS.md, sezione 55 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 56 | COLLECTIVE IMMUNITY | Non implementato | docs/REQUIREMENTS.md, sezione 56 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 57 | FLEET RESPONSE | Non implementato | docs/REQUIREMENTS.md, sezione 57 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 58 | PATIENT ZERO | Non implementato | docs/REQUIREMENTS.md, sezione 58 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 59 | PREVENTED INCIDENT | Non implementato | docs/REQUIREMENTS.md, sezione 59 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 60 | SINGLE-HOST MODE | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 61 | CRYPTOGRAPHIC CORE | Parziale | crates/event-storage; crates/win-platform/src/file_response.rs; docs/SECURITY_MODEL.md | Catena hash locale e DPAPI recovery; non cifratura completa dei log, checkpoint firmati o ancoraggio indipendente. |
| 62 | POST-QUANTUM CRYPTOGRAPHY | Non implementato | docs/REQUIREMENTS.md, sezione 62 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 63 | KEY STORAGE | Parziale | crates/event-storage; crates/win-platform/src/file_response.rs; docs/SECURITY_MODEL.md | Catena hash locale e DPAPI recovery; non cifratura completa dei log, checkpoint firmati o ancoraggio indipendente. |
| 64 | SECURITY UPDATE SYSTEM | Non implementato | docs/REQUIREMENTS.md, sezione 64 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 66 | EVIDENCE CAPSULE | Non implementato | docs/REQUIREMENTS.md, sezione 66 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 67 | COUNTERFACTUAL ANALYSIS | Non implementato | docs/REQUIREMENTS.md, sezione 67 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 68 | PRIVACY | Parziale | crates/event-storage; crates/win-platform/src/file_response.rs; docs/SECURITY_MODEL.md | Catena hash locale e DPAPI recovery; non cifratura completa dei log, checkpoint firmati o ancoraggio indipendente. |
| 69 | PERFORMANCE ARCHITECTURE | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 72 | NIENTE HEAVY AI PER DEFAULT | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 73 | UI TECHNOLOGY | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 74 | UI PROCESS MODEL | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 75 | UX PHILOSOPHY | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 76 | LIGHT / DARK MODE | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 77 | ACCESSIBILITÀ | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 78 | LOCALIZZAZIONE | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 79 | PROGRESSIVE DISCLOSURE | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 80 | TOOLTIPS EDUCATIVI | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 81 | "PERCHÉ?" | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 82 | UI NAVIGATION | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 83 | DASHBOARD | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 84 | INCIDENT VIEW | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 85 | GRAPHICAL INCIDENT VIEW | Parziale | apps/desktop-ui/src/lib/Investigation.svelte; ADR 0012 | Vista paginata delle relazioni osservate, dettagli ed evidenze. Nessuna ricostruzione causale di incidenti. |
| 86 | SECURITY LOG / SIEM UI | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 87 | QUERY LANGUAGE | Parziale | crates/event-storage/src/query_language.rs; tests/storage.rs | Campi in allowlist, confronti tipizzati, AND/OR/parentesi, parametri SQL. Mancano FOLLOWED_BY, RELATED_TO e campi non raccolti. |
| 88 | QUERY BUILDER | Parziale | apps/desktop-ui/src/lib/QueryBuilder.svelte; queries.ts | Builder di condizioni e 20 espressioni salvate locali. Mancano sequenze temporali e query di grafo avanzate. |
| 89 | COMMAND PALETTE | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 90 | ONBOARDING | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 91 | SAFE DEFAULTS | Parziale | crates/app-control; crates/response-engine; ADR 0009 e 0010 | Inventario in griglia con date dichiarate, discovery eseguibili e blocchi rete multipli confermati; quarantena/ripristino file. Contratti granulari e storia completa policy mancanti. |
| 92 | REVERSIBLE ACTIONS | Parziale | crates/app-control; crates/response-engine; ADR 0009 e 0010 | Inventario in griglia con date dichiarate, discovery eseguibili e blocchi rete multipli confermati; quarantena/ripristino file. Contratti granulari e storia completa policy mancanti. |
| 93 | POLICY HISTORY | Parziale | crates/app-control; crates/response-engine; ADR 0009 e 0010 | Inventario in griglia con date dichiarate, discovery eseguibili e blocchi rete multipli confermati; quarantena/ripristino file. Contratti granulari e storia completa policy mancanti. |
| 94 | PERFORMANCE UI | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | CPU su campioni, working set, memoria privata e coda reali in UI. Non auto-tuning o consumi complessivi. |
| 95 | STARTUP | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | HKCU Run facoltativo per utente, comando nativo, default off, conflitto/errore espliciti e SCM prioritario. Login reale da qualificare; non protezione pre-login. |
| 96 | INSTALLER | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 97 | DEGRADED MODES | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 98 | NO CLOUD REQUIREMENT | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 99 | OFFLINE RECOVERY | Non implementato | docs/REQUIREMENTS.md, sezione 99 | Da implementare e qualificare end-to-end; nessuna funzionalita dichiarata disponibile. |
| 100 | TESTING | Parziale | docs/VALIDATION.md; fuzz; .github; deny.toml | Test e harness presenti; restano qualificazione amministrativa, matrice Windows, carico, firma e prove di produzione. |
| 101 | SECURITY REPLAY HARNESS | Parziale | docs/VALIDATION.md; fuzz; .github; deny.toml | Test e harness presenti; restano qualificazione amministrativa, matrice Windows, carico, firma e prove di produzione. |
| 102 | FUZZING | Parziale | docs/VALIDATION.md; fuzz; .github; deny.toml | Test e harness presenti; restano qualificazione amministrativa, matrice Windows, carico, firma e prove di produzione. |
| 103 | DEPENDENCY SECURITY | Parziale | docs/VALIDATION.md; fuzz; .github; deny.toml | Test e harness presenti; restano qualificazione amministrativa, matrice Windows, carico, firma e prove di produzione. |
| 104 | REPRODUCIBLE BUILDS | Parziale | docs/VALIDATION.md; fuzz; .github; deny.toml | Test e harness presenti; restano qualificazione amministrativa, matrice Windows, carico, firma e prove di produzione. |
| 106 | PERFORMANCE REGRESSION CI | Parziale | docs/VALIDATION.md; fuzz; .github; deny.toml | Test e harness presenti; restano qualificazione amministrativa, matrice Windows, carico, firma e prove di produzione. |
| 107 | CODING STANDARD | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 108 | ERROR HANDLING | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 109 | NO SILENT FAILURE | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 110 | FEATURE CAPABILITY MATRIX | Parziale | apps/desktop-ui; apps/security-service; scripts; docs/MANUALE_UTENTE.md | Interfaccia reale e funzioni documentate; non equivalgono al prodotto completo. Consultare IMPLEMENTATION_STATUS per limiti e qualificazione. |
| 111 | NON CREARE FUNZIONI FINTE | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 112 | IMPLEMENTATION STRATEGY | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 113 | REQUIREMENT FINALE PER CODEX | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 114 | PRIORITÀ ASSOLUTE | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 115 | OBIETTIVO UX FINALE | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |
| 116 | DEFINIZIONE DEL PRODOTTO | Parziale | Cargo.toml; docs/ARCHITECTURE.md; docs/LANGUAGE_DECISIONS.md | Principi e struttura presenti; la copertura funzionale integrale non e ancora realizzata. |

