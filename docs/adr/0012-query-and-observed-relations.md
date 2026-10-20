# ADR 0012 — Ricerca strutturata e relazioni osservate

Safe Rust nel parser dedicato di event-storage e nel modello di investigazione.
Nessuna nuova FFI o dipendenza nativa: si usa SQLite gia incluso. Il frontend
rimane Svelte/TypeScript; nessuna decisione di enforcement deriva da ricerche.

La grammatica ammette campi normalizzati in allowlist, confronti tipizzati,
AND, OR e parentesi. Massimo 4096 byte, 32 confronti, 8 livelli di parentesi.
I valori sono sempre parametri SQLite, mai testo SQL o codice eseguibile.
NULL e' esplicito; un campo mancante non soddisfa !=. CONTAINS usa instr/lower:
case folding ASCII di SQLite, non equivalenza Unicode o identita di percorso.
Le query combinano i filtri esistenti, mantengono limiti di righe/byte/deadline
ed esaminano l'archivio prima di applicare il limite dei risultati.
FOLLOWED_BY, RELATED_TO e proprieta non raccolte sono rifiutati, non simulati.

Il builder genera la medesima grammatica. Le ricerche salvate sono preferenze
locali dell'interfaccia, massimo 20, non policy di sicurezza. Non modificano
Windows. Errori di sintassi o timeout restano distinti da zero risultati.

Il grafo di investigazione usa eventi conservati di una precisa istanza,
con ID evento su ogni relazione. Rappresenta associazioni osservate a SID e
endpoint TCP, non causalita, direzione del traffico, attacchi o percorsi potenziali.
PPID senza identita di istanza non crea archi. Snapshot assenti/incompleti e
query limitate non sono evidenze dell'assenza di attivita.

Riferimenti SQLite consultati per estrazione JSON, NULL e parametri:
https://www.sqlite.org/json1.html
https://www.sqlite.org/lang_expr.html

