# ADR 0030 — Riduzione del rumore basata sulla rilevanza

14 ottobre 2026. KEEP safe Rust; nessuna nuova libreria o FFI proprietaria.

La raccolta privilegia eventi utili alle indagini. Gli scaricamenti di immagini ETW e gli heartbeat periodici non vengono persistiti; eventi di sicurezza, caricamenti, errori, transizioni e perdite restano disponibili secondo la policy del sensore. La frequenza da sola non è un criterio per eliminare dati. Non modificare l’audit policy o i log Windows globali; non assegnare fiducia soltanto dal nome del programma o dal percorso.

ETW filtra alla sorgente gli ID configurati per avvio processo, arresto e caricamento immagini; gli eventi di scaricamento non vengono richiesti. La normalizzazione storica resta compatibile. Health dichiara la copertura ridotta: la scelta riduce la capacità di ricostruire la permanenza delle DLL in memoria.

Le statistiche operative restano disponibili in memoria; persistenza su transizioni, errori e condizioni degradate. Eventi interni importanti non devono essere scartati silenziosamente in condizioni di coda piena.

La manutenzione di record storici richiede un backup separato, verifica della copia, preservazione degli eventi di sicurezza/raw/bookmark/detection, tracciabilità della nuova catena d’integrità e arresto controllato del servizio. Nessun backup viene eliminato automaticamente. La manutenzione storica non recupera eventi mai raccolti e non equivale a una policy di retention.

La copertura e i limiti devono essere qualificati su sistemi Windows supportati prima di una release stabile.
