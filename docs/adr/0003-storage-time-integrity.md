# ADR-0003 — Storage sostituibile, tempo esplicito e integrità limitata

- Stato: accettato.
- Data: 2026-10-04.

## Decisione

SQLite locale in WAL, writer unico e batch tramite interfaccia sostituibile. Evento v1 conserva identità, sequenza, wall/observation/ingestion time e monotonic time per runtime. `boot_id` resta null finché la sorgente non è qualificata; `runtime_instance_id` non finge di essere un boot Windows.

Raw e normalizzato sono collegati atomicamente, con limiti di dimensione. La prima chain SHA-256 non keyed/non anchored aiuta a rilevare corruzione e modifiche interne quando non viene ricostruita. Non certifica che un amministratore non abbia riscritto l'intero database o cancellato la coda. Il budget iniziale ferma scritture oltre limite; non è ancora retention.

## Evoluzione

Segmenti compressi append-only, retention HOT/WARM/COLD/DELETE, AEAD, manifest e checkpoint firmati richiedono nuove slice. L'ancoraggio esterno esiste soltanto con coordinator o riferimento esportato affidabile. La conservazione del raw è subordinata alla minimizzazione privacy; non autorizza raccolta indiscriminata.

## Alternative

Database server esterno violerebbe la semplicità single-host; custom database aggiungerebbe rischio prima di avere workload. Un timestamp UTC come unico ordine fallisce con clock rollback; UUID per runtime chiamato boot ID sarebbe semanticamente falso.

