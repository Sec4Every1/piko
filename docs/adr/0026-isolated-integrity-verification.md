# ADR 0026 — Verifica dell’archivio senza occupare il writer

Stato: implementato dopo un timeout riproducibile sul vero archivio locale (oltre 37 mila eventi). La query di verifica usava il limite 750 ms delle letture brevi, insufficiente per la catena completa.

VerifyStore usa un thread dedicato con una sola operazione attiva e una coda di capacità uno. Un lettore SQLite OPEN_READ_ONLY apre esclusivamente l’archivio esistente, verifica versione/host, reparse/file/budget e non crea schema, cambia journal o riserva scritture. quick_check, catena/indici/raw e controllo orfani condividono una transazione read snapshot: le append WAL possono proseguire senza rendere incoerente il report.

Il limite server è 10 s compresa la coda; IPC client 12 s solo per VerifyStore. Le normali query mantengono 750 ms e IPC 3 s. Progress handler SQLite interrompe verifiche scadute; richieste obsolete/disconnesse non iniziano. Coda piena/stopped/deadline/corruzione rimangono errori, mai successo parziale. Nessuna verifica completa viene inoltrata alla coda del writer. Un lettore può mantenere temporaneamente WAL: il normale budget continua a essere controllato; nessuna retention o aumento automatico.

Report relativo allo snapshot, non a ogni evento aggiunto dopo. La catena locale resta non ancorata esternamente e non dimostra autenticità, assenza di riscrittura completa o tail truncation. Il controllo all’apertura del writer resta completo e separato.

Verifiche: reader non crea file e rifiuta append, writer pieno non impedisce l’invio al verifier, snapshot coerente durante append concorrenti, test corruzione preesistenti; collaudo IPC/GUI release e verifica del vero archivio locale. Nessuna modifica o eliminazione delle evidenze per far passare la verifica.
Fonti primarie SQLite: [WAL](https://www.sqlite.org/wal.html) e [Isolation](https://www.sqlite.org/isolation.html). Un lettore mantiene il proprio snapshot mentre nuove transazioni possono essere aggiunte al WAL; un lettore lungo può ritardare il checkpoint.
## Motore SQLite aggiornato

Il controllo del motore ha rilevato SQLite bundled 3.46.0. Aggiornati rusqlite 0.40.2/libsqlite3-sys 0.38.2 in tutti i componenti e nei due lockfile: amalgamation compilata SQLite 3.53.2, versione verificata dal sorgente scaricato. Il test bundled_sqlite_includes_the_wal_reset_fix impedisce di tornare a una versione anteriore alla correzione. Il reader è comunque RO e non avvia checkpoint, mentre il writer rimane unico. Gestiti gli errori della nuova API progress_handler, senza ignorare l’installazione/rimozione del limite. Nessuna migrazione schema/dati o modifica journal fatta dal reader.

Fonte correttivo: [SQLite WAL-reset](https://www.sqlite.org/wal.html#walreset), correzione pubblicata in 3.51.3 e successive. Compatibilità verificata sui test e sull’archivio esistente; non è un audit di ogni dipendenza del prodotto.

