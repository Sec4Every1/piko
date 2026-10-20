# ADR 0032 — Aggregazione contestuale dei caricamenti immagine

14 ottobre 2026. Ridurre lo spazio occupato dai caricamenti ripetitivi senza
affermare che un modulo sia innocuo. Modifica in `security-service` safe Rust;
usa le verifiche file e Authenticode locale già presenti in `win-platform`.

Per aggregare un caricamento servono tutti questi elementi: copertura ETW attiva;
evento nativo `image.etw.loaded` valido; istanza processo identificata da start
ETW e coerente con PID/creation time; sessione nota; eseguibile e modulo risolti
su disco locale, non reparse, PE valido, hash SHA-256 completo sotto handle
protetto; firma locale Authenticode o catalogo valida. L'identità include hash
e percorso di eseguibile e modulo, sessione e tipo di firma. Nessun nome,
percorso standard o firma da solo abilita il raggruppamento.

Il primo evento per contesto conserva raw ETW e snapshot hash dei due file.
Ripetizioni coerenti entro la finestra in memoria vengono raccolte in una
evidenza JSON derivata con conteggio, primo/ultimo orario e riferimenti a evento
e raw di esempio. Il record riepilogativo non è presentato come raw ETW. Una
modifica del file o una nuova coppia genera un nuovo evento completo. Se identità,
firma, percorso o lettura non sono certi, l'evento originale resta completo.
Fuori copertura ETW il filtro si disattiva e gli anchor vengono svuotati.

Il filtro opera prima dello storage ma non cambia gli eventi Event Log. Prepara
un lotto una volta e committa gli anchor solo dopo l'acknowledgement del writer;
un errore di quota ritenta il lotto già preparato. I contatori sono solo nella
salute live. La firma è locale/cache-only senza revoca online: non è un verdetto
di sicurezza. Non è implementata una modalità investigativa temporanea completa.

Trade-off: si perdono gli orari individuali delle ripetizioni raggruppate, mentre
restano il numero, gli estremi temporali e un campione raw. I caricamenti storici
non vengono eliminati. Il servizio aggiornato ha backup e SCM lo riporta avviato;
il bundle desktop e il pacchetto ZIP sono stati rigenerati. La query IPC readonly
è stata negata dalla ACL nel contesto di sviluppo, quindi aggregazione live e
contatori non sono ancora qualificati. Nessun cambiamento alla retention di 12
mesi o al limite 2 GiB.

