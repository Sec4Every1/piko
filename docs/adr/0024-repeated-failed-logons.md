# ADR 0024 — Credenziali errate ripetute

Stato: correlazione implementata; eventi Security live dipendono da audit e autorizzazione del sensore. Non qualificati su questo token.

Il core accetta esclusivamente Security/Microsoft-Windows-Security-Auditing/4625, versione 0, raw XML collegato per identità, fonte, canale, record e timestamp. Usa TargetUserName/TargetDomainName per l’account tentato, IpAddress per la sorgente, LogonType 3 o 10 e Status/SubStatus di credenziali errate o account inesistente (C000006A/C0000064, anche sotto C000006D). Rifiuta IP mancanti, multicast, unspecified e loopback anche IPv4 mapped. Il PID Execution non diventa autore. ProcessName è il chiamante dichiarato da Windows, non il software remoto responsabile.

Almeno cinque record unici per host, account/dominio esatti, IP canonico e tipo nella stessa finestra UTC fissa di 60 secondi generano una segnalazione medium. Non è una finestra scorrevole: errori a cavallo di due minuti possono non raggiungere la soglia. Deduplica record Event Log/timestamp anche se riacquisiti con UUID diversi. Mantiene i riferimenti a tutti gli eventi/raw inclusi. Le associazioni non dichiarano causalità o identità dell’attaccante. Non rileva password spraying tra account diversi.

Ad ogni lettura degli alert ricostruisce dai 256 record 4625 più recenti per posizione nell’archivio; budget eventi 4 MiB e XML complessivo 16 MiB. In caso di limite esclude il minuto più vecchio potenzialmente tagliato. Non garantisce analisi completa dell’archivio o dei minuti senza audit. Nessun nuovo indice detection contraffatto è usato come sorgente: dati normalizzati archiviati e digest raw sono rivalidati, con la catena locale verificata all’apertura. Non è autenticazione crittografica indipendente.

ID stabile: SHA-256 di chiave/finestra con componenti length-prefixed. Le review restano associate alla finestra anche se aumenta il conteggio; l’evidenza principale indica l’ultimo record incluso. Ripartenza ricostruisce le finestre dall’archivio. Nessuna modifica account, Firewall, audit o credenziali.

Score euristico 50/100 con un fattore spiegato, probabilità falso positivo null. UI raggruppata, account chiamato per nome, origine/tipo/chiamante/stati, remediation manuale (controllo credenziali salvate e servizi, verifica della fonte prima di limitare accesso remoto). Evidenze correlate chiuse, cinque riferimenti per pagina e XML su richiesta. Mapping di contesto T1110, nessuna subtecnica o attacco provato.

Verifiche: soglia 4/5/6, replay, campi/versione/timestamp ambigui, separazione account/IP/tipo/minuto, persistenza dopo riavvio, rifiuto digest alterato, UI/parser e pagina compatta. Prove su fixture; non generano login falliti sul computer.

Fonti primarie: [Microsoft 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625), [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/), consultate 13 ottobre 2026.

