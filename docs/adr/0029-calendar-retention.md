# ADR 0029 — Conservazione per mesi e quota esplicita

KEEP safe Rust, dopo COMPONENT_AUDIT e LANGUAGE_DECISIONS.

La retention riguarda gli eventi raccolti dalla policy di sicurezza e deve essere esplicita.

retention_months è opzionale (1–120; null disattiva). La scadenza usa ingestion_time
e mesi UTC di calendario, con clamp dei giorni di fine mese. Il worker elimina
solo un prefisso contiguo scaduto: un record recente ferma l'avanzamento, anche
se segue un record con timestamp più vecchio. Massimo quattro passi da 32 righe /
4 MiB originali per append. Raw e detection del prefisso sono eliminati nella
stessa transazione del checkpoint; nessun evento recente è sacrificato alla quota.

Checkpoint locale SHA-256 conserva hash/posizione finali, sequenze e bookmark.
Verifica riparte dal checkpoint; expired_events distingue scaduti e conservati.
Non è un checkpoint firmato o ancorato esternamente. Schema 2 dopo la prima
scadenza; versioni precedenti devono rifiutarlo. Nessun HOT/WARM/COLD implementato.

Set-PikoRetention.ps1 salva configurazione e SQLite/WAL/SHM a servizio fermo.
deve restare consultabile e segnalare le scritture fallite. Corruzione e altri
errori non vengono trattati come semplice quota. Verifica dedicata 30 s, IPC 32 s;
timeout esterno leggermente successivo alla deadline dell'operazione.

UI distingue spazio usato da file allocato e mostra mesi/contatori. Test di calendario, corruzione, bookmark, riavvio, prefisso interamente scaduto e clock fuori ordine sono richiesti. La retention reale e il volume dipendono dai sistemi supportati; non promettere una durata minima con quota fissa.

