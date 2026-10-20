# ADR 0028 — Evidenze compresse e lettura compatibile

14 ottobre 2026. Dopo lettura di COMPONENT_AUDIT.md e LANGUAGE_DECISIONS.md:
KEEP safe Rust. flate2 1.1.10 usa rust_backend; nessun nuovo FFI proprietario.

Le nuove evidenze grezze SQLite sono compresse lossless con gzip veloce quando
la rappresentazione risparmia almeno 64 byte oltre al proprio header. Record
piccoli o poco comprimibili restano JSON. Envelope PIKOEV/versione 1 e lunghezza
originale little endian; decoder bounded a 4 MiB, CRC verificato, niente membri
concatenati o byte finali. Versioni/header/troncamenti non validi sono errori.
Il limite originale di 4 MiB per lotto resta applicato prima della compressione.

Digest SHA-256 e catena continuano a riferirsi agli originali JSON non compressi.
La rappresentazione su disco non cambia l'identità dell'evidenza, i bookmark,
le regole o i byte mostrati all'utente. Lettore ordinario e reader di integrità
usano lo stesso decoder. Archivi misti sono supportati. La manutenzione offline opzionale ricomprime
le evidenze storiche senza cancellarle o cambiarne digest e catena. Nessun
VACUUM automatico: il file resta allocato, SQLite riutilizza le pagine liberate. Compressione non equivale a cifratura,
retention HOT/WARM/COLD/DELETE o segmenti esterni append-only: questi restano aperti.

Una build precedente al codec non può aprire un archivio contenente nuove
evidenze compresse: la verifica iniziale fallisce. Non fare downgrade del solo
eseguibile; conservare la build compatibile e i dati. Backup binari UAC non
equivale a backup dell'archivio né garantisce rollback del formato.

## Qualifica

Compressione e manutenzione devono essere verificate con fixture legacy e compresse, dati corrotti o oltre i limiti, e controlli di integrità prima e dopo. Le prove d'integrazione su Windows devono coprire arresto controllato, backup, ripresa del servizio e spazio aggiuntivo richiesto. Il file SQLite può restare allocato alla stessa dimensione: le pagine liberate sono riutilizzate. Nessuna compressione recupera eventi mai raccolti o elimina automaticamente il backup.

