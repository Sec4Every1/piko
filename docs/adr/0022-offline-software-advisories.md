# ADR 0022 — Advisory offline e associazioni personali

Data: 2026-10-12. Stato: implementato; classificazione automatica dei prodotti,
feed firmati e patch management restano assenti.

Gate: letti `COMPONENT_AUDIT.md` e `LANGUAGE_DECISIONS.md`. Il parser, il matching
e la persistenza restano safe Rust in `app-control`; Tauri presenta quattro
comandi per utente e la UI usa Svelte/TypeScript. Nessuna nuova FFI, migrazione
di linguaggio, dipendenza o modifica privilegiata del PC.

L'input è una stringa JSON UTF-8 importata esplicitamente dall'utente, massimo
1 MiB. Il bridge non accetta un percorso file o un URL da scaricare. Schema v1
con proprietà sconosciute/duplicate rifiutate, fonti HTTPS limitate, date,
scadenza entro 90 giorni, massimo 256 prodotti, 100 versioni per prodotto,
1000 advisory e otto indicazioni manuali per advisory. Matching case-sensitive
per prodotto/versione esatta; nessuna deduzione da nomi, intervalli o semver.
CVSS è dichiarato dalla fonte con versione/vettore; non è ricalcolato e non è
una probabilità. Fine supporto non riceve un punteggio CVSS inventato.

Il comando di associazione rilegge l'inventario Windows e vincola l'ID corrente
ai metadati osservati e alla dichiarazione personale di prodotto/versione.
Se nome, editore o versione installer cambiano, il confronto si sospende. Un ID
non osservato, un prodotto non coperto e una versione non coperta hanno stati
distinti. Nessun advisory in un feed non è certificazione di sicurezza.

Persistenza per utente: SQLite DELETE journal/FULL, timeout 500 ms, massimo
4096 pagine da 4096 byte, 512 associazioni senza espulsioni silenziose. Le
directory sono controllate e mantenute con handle; il file è controllato e
protetto contro sostituzione prima che SQLite ne risolva il nome. Reparse point,
file troppo grandi e sidecar WAL/SHM inattesi falliscono. SQL parametrizzato,
dimensioni dei payload controllate prima della deserializzazione. Sostituzione
feed in transazione; errore di validazione non altera il feed precedente.
Il catalogo advisory compare una volta nella risposta e non viene duplicato
per ogni associazione. Un mutex non bloccante evita operazioni UI concorrenti.

SHA-256 confronta soltanto la copia locale salvata; autenticità e firme del feed
non sono verificate. Lo stesso utente o un amministratore può modificare insieme
archivio e digest. Non è una sorgente attendibile per enforcement automatico.
I feed scaduti restano visibili e indicati come tali. Nessuna rete, upload, patch,
esecuzione di comandi o apertura automatica delle fonti. Le remediation sono
testo da verificare; rete e sandbox hanno conferme e confini separati.

UI lazy, ricerca e cinque applicazioni per pagina; dettaglio e cinque advisory
per pagina. Nessun dato di esempio caricato nel prodotto. Fixture di sviluppo
marcata esplicitamente e non inclusa nel pacchetto.

Prove: parser negativo/limiti/coerenza, matching esatto e cambio metadati,
scadenza, riapertura SQLite, import fallito preserva stato, hash incoerente,
archivio oversize, limite associazioni senza espulsioni e file lock. Unit TS
verifica DTO incoerenti e CVSS ignoto; tre prove browser coprono import/binding,
dettagli/remediation e feed scaduto. Non eseguita una verifica vendor/CVE di un
prodotto installato né una prova avversaria di sostituzione simultanea dei
sidecar da un altro processo dello stesso utente.

