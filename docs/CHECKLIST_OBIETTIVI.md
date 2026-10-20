# Checklist piko — 14 ottobre 2026

Confronto con REQUIREMENTS.md, ARCHITECTURAL_ADDENDUM.md e richieste successive.
Spunta = capacità circoscritta implementata; non certificazione di produzione.
Parziale = esiste una funzione reale, ma mancano criteri del requisito completo.
La matrice delle 116 sezioni registra 80 parziali e 36 non implementate: non è
una percentuale di completamento e nessuna sezione ampia è dichiarata conclusa.

## Capacità implementate

- [x] Nome piko e base progetto Windows: workspace, servizio, CLI e desktop separati.
- [x] Servizio installato con account virtuale, avvio automatico ritardato e UI normale.
- [x] Dashboard incorporata: nessun server di sviluppo necessario per aprirla.
- [x] UI minimale, palette per rischio/azioni, temi chiaro/scuro e italiano/inglese.
- [x] Dashboard compatta: cinque gruppi per pagina, dettaglio, occorrenze e raw separati.
- [x] Descrizioni e remediation manuali per gli avvisi supportati; MITRE ATT&CK contestuale.
- [x] Nomi osservati dei programmi quando disponibili; dati ignoti lasciati espliciti.
- [x] Score euristico 0–100 spiegabile. Non una probabilità o una percentuale calibrata.
- [x] Pagina log, filtri, query strutturate, builder, query salvate ed export locale.
- [x] Griglia app, ricerca, selezione multipla e ordinamento per date disponibili.
- [x] Fotografie processi/TCP e porte UDP locali, con limiti di visibilità dichiarati.
- [x] Dodici regole Event Log e correlazione di accessi falliti ripetuti.
- [x] Vista accessi 4624/4625, credenziali 4648 e privilegi 4672: account/programma/origine da XML, categorie, cinque righe per pagina, dettagli e raw separati.
- [x] Lettura e storico Run/RunOnce: utente/computer, 32/64 bit, prima/dopo e raw.
- [x] Compressione delle nuove evidenze e manutenzione dello storico con backup, senza eliminazione.
- [x] Nuova raccolta essenziale: heartbeat e unload DLL esclusi; stati ripetitivi ridotti; Security, errori e perdite conservati.
- [x] Caricamenti DLL ripetuti raggruppati soltanto con identità del processo, sessione, hash e firma locale verificati; primo caricamento e verifiche incerte restano completi. Non è un giudizio di sicurezza assoluta. Qualifica dell’aggregazione live in servizio ancora da completare.
- [x] Hash chain locale e verifica in reader separato; nessun ancoraggio esterno dichiarato.
- [x] Manuale, istruzioni di avvio e metriche del monitor e dell'archivio.
- [x] Addendum: safe Rust predefinito, FFI Windows isolate, audit e decisioni linguistiche documentati; nessuna riscrittura massiva.

## Motori presenti ma incompleti

- [ ] **Endpoint protection / enforcement:** regole Firewall per exe e helper UAC implementati; traffico effettivamente bloccato da qualificare. Nessuna mediazione generale di file/registro/dispositivi o blocco preventivo kernel.
- [ ] **Permessi per applicazione:** rete e prove limitate AppContainer presenti. Mancano blocco dei path esterni all'installazione, file di sistema e aggiornamenti per tutte le app installate.
- [ ] **Software rischiosi o non supportati:** advisory locali, binding manuale prodotto/versione e prove AppContainer. Mancano intelligence aggiornata, policy per versione e contenimento persistente completo.
- [ ] **Probation / isolamento:** copia di un singolo exe AppContainer senza capacità rete, un processo e memoria limitata; Windows Sandbox manuale. Non isolamento completo di un programma installato con dipendenze e servizi.
- [ ] **Detection comportamentale:** regole spiegabili presenti; mancano modelli completi e correlazioni su attività file/registro/rete/identità.
- [ ] **State integrity / stato storico:** log e Run/RunOnce presenti; mancano invarianti di sistema, storia generale di file/registro e ripristino dello stato.
- [ ] **Analisi causale / forensics:** eventi, raw e relazioni osservate per istanza; niente causalità provata, albero processi completo, attack paths o evidence capsule firmate.
- [ ] **SIEM locale:** query e dettagli presenti; mancano FOLLOWED_BY, RELATED_TO, analisi di grafo avanzata e retention HOT/WARM/COLD/DELETE.
- [ ] **Identity protection:** correlazione 4625 e fatti XML 4624/4625/4648/4672 presenti; mancano token lineage, identity graph, transizioni di token verificate e policy account.
- [ ] **Provenienza / supply chain:** inventario, metadati installer e Authenticode locale; niente genealogia e dipendenze verificate, reputation aggiornata o confronto comportamentale tra versioni.
- [ ] **Network analysis:** TCP osservato e bind UDP locali; niente destinatari UDP, DNS/TLS o reputation delle destinazioni.
- [ ] **Vulnerability / patch intelligence:** advisory offline e CVSS attribuiti; niente feed autenticato/live, patch automatiche o congelamento aggiornamenti.
- [ ] **Risposta / recovery:** piani confermati, journal, quarantena e ripristino del singolo file con backup DPAPI. Nel servizio attuale response_roots è vuoto: interventi file non configurati, richiedono amministratore e cartelle autorizzate. Niente rollback generale/offline/sistema.
- [ ] **Protezione archivio / privacy:** ACL, hash e backup recovery cifrati; mancano cifratura dei log, checkpoint firmati, remote anchoring, crypto agility e post-quantum operativo.
- [ ] **Policy / capability / intent:** controlli circoscritti e review manuali; mancano contratti comportamentali, limiti persistenti per app e cronologia completa delle policy.

## Motori ancora mancanti

- [ ] Driver minimale firmato ed enforcement kernel.
- [ ] Ransomware engine e cryptographic canaries.
- [ ] Deception/honeypot, identità/credenziali/dati esca.
- [ ] Firewall delle credenziali e protezione delle sessioni browser.
- [ ] Controllo periferiche, amministrazione remota e risorse sensibili completo.
- [ ] Boot/firmware integrity, driver trust e self-defense.
- [ ] Diagnostica profonda, classificazione PUP e targeted surveillance detection.
- [ ] Counterfactual graph, potential attack graph e analisi controfattuale operative.
- [ ] Collective immunity, fleet response, patient zero e incidenti prevenuti multi-endpoint.
- [ ] Aggiornamento firmato del prodotto e recovery offline/sistema.

## Qualificazione ancora aperta

- [ ] Traffico inbound/outbound con regole Firewall realmente applicate e ripristinate.
- [ ] Reboot/login reali e prove di accesso tra utenti/sessioni o da remoto.
- [ ] Matrice Windows client/Server/WOW64 supportata.
- [ ] Stress prolungato, fault injection, fuzzing esteso, prestazioni e build riproducibili.
- [ ] Firma codice/driver, installer/updater distribuibili e qualifica di produzione.
- [ ] Probabilità di falso positivo e rischio percentuale calibrati su dati etichettati.

Le prove di sviluppo non sostituiscono una qualifica indipendente della build di rilascio. Compressione non equivale a retention: il file SQLite resta allocato e riusa pagine.

## Ordine di completamento proposto

1. Archiviazione a livelli e riduzione contestuale aggiuntiva: la scadenza del prefisso e i filtri essenziali sono presenti, ma 12 mesi di qualsiasi volume non sono garantiti entro 2 GB.
2. Qualifica Firewall e controlli file/registro per applicazione.
3. Telemetria file/registro/identità e correlazioni causali verificabili.
4. Ransomware/canary e recovery protetto più ampio.
5. Contratti per software vulnerabili, behavior diff e policy versionate.
6. Driver/self-defense, intelligence/updater firmati e qualifica Windows.
7. Motori avanzati e multi-endpoint opzionali.

Dettaglio delle singole 116 sezioni: REQUIREMENT_MATRIX.md.


