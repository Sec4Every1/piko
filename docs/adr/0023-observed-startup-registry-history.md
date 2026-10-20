# ADR 0023 — Storico osservato dell’avvio automatico

Stato: implementato, letture locali in sola lettura. Requisito 17 coperto parzialmente.

La GUI confronta HKCU dell’utente della finestra e HKLM, Run/RunOnce nelle viste 32/64 bit. Prima lettura silenziosa; variazioni successive conservano tipo Windows, bytes originali e testo UTF-16 quando decodificabile. A→B→A tra tre letture rimane nello storico. Le variabili non sono espanse e i comandi non sono eseguiti.

RegOpenKeyExW usa solo KEY_QUERY_VALUE e la vista dichiarata. RegEnumValueW è bounded: 128 valori per chiave, 512 code unit nome, 2048 bytes dato, 1024 valori e 512 KiB complessivi. Errori, buffer insufficienti e cambio FILETIME durante la lettura rendono la singola chiave parziale. Non si inventa una scomparsa per valori mancanti nelle chiavi incomplete. ERROR_MORE_DATA non autorizza la lettura del buffer.

SQLite separato per utente: 16 MiB, 1024 identità, ultime 500 variazioni, 50 risultati e cursore per pagina. Raggiungere il limite identità interrompe il salvataggio con errore; la retention elimina le sole variazioni più vecchie di questo storico. Non modifica l’archivio Event Log. Letture serializzate nella GUI, file/reparse e payload validati. Export non firmato.

La pagina Permessi app contiene un pannello chiuso, ricerca sulle 50 variazioni caricate, cinque righe per pagina, confronto prima/dopo e bytes grezzi. L’ora è l’osservazione; autore e ora di scrittura sconosciuti. Non è telemetria continua né recupero del registro: cambiamenti tra letture possono sfuggire. Nome valore e stringa comando non identificano il programma autore. L’assenza non prova cancellazione. Nessuna detection malware o modifica automatica.

Verifiche: fixture A/B/A, tipi cambiati, assenza parziale/completa, duplicati, parser/escaping, browser; snapshot Windows reale in sola lettura e comando Tauri nativo.

Fonti API: [RegEnumValueW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew), [RegQueryInfoKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw).

