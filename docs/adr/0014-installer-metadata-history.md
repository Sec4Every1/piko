# ADR 0014 — Storico locale dei metadati installer

Data: 2026-10-12. Stato: implementato; genealogia e behavior diff completi restano mancanti.

La UI non elevata osserva HKLM/HKCU della sessione tramite l'inventario esistente.
Il nuovo comando Tauri software_history acquisisce una lettura nativa, esegue
un confronto safe Rust in app-control e salva stato/variazioni in una transazione
SQLite per profilo. Non accetta snapshot o SQL dal frontend. Gli ID sono chiavi
installer, non identità prodotto/firma/binario. L'istante è di osservazione,
non una data verificata d'installazione.

Prima lettura: baseline silenziosa. Letture uguali: nessun evento aggiunto.
Versioni note differenti: version_changed; dato versione sconosciuto: metadata_changed.
Assenza: soltanto lettura completa non troncata. Ricomparsa conserva la stessa
identità di registro. Non si ricostruisce la causalità tra due snapshot.

SQLite DELETE journal/synchronous FULL, timeout 500 ms, 4096 pagine da 4096 byte;
controllo formato, dimensione e reparse point del file. Stato massimo 4096 ID,
storico massimo 2000 variazioni con cancellazione delle più vecchie. Query
parametrizzata per cursore e limite 51 (50 risultati + indicatore has_more).
Errori visibili e nessun degrado dei controlli rete. Non archivio anti-tampering:
l'account utente e amministratore possono modificarlo. Non telemetria continua.

UI lazy in un details: cinque righe per pagina, ricerca nelle 50 voci caricate,
confronto prima/dopo, caricamento record più vecchi, export non firmato.
Test: baseline/idempotenza, reopen, partial/truncated, ricomparsa/versione ignota,
snapshot duplicato senza effetti, retention/cursore, validazione payload,
UI stale/error/ricerca/mobile; smoke nativo su inventario reale senza modificarlo.

