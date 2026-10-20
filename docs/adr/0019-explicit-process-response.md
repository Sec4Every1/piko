# ADR 0019 — Risposta esplicita su processi

Safe Rust broker con piani UUID 60s/max8, preview SID/sessione/percorso/creation FILETIME esatto. FFI minimale win-platform con OpenProcess, IsProcessCritical, GetProcessTimes e TerminateProcess sul medesimo handle detenuto. UI normale, nessuna elevazione o SeDebugPrivilege. Critici/Windows/piko e peer diversi esclusi; revalidazione prima di azione.

Intento durabile SQLite prima della terminazione, esito separato e bounded wait 2s. Timeout è uncertain, errori dopo intent failed_or_uncertain, intent incompleto letto come uncertain; nessun replay dopo restart. DB viewer 1000azioni/16MiB, query50, UI5perpagina. Log distinto dall’evidenza originale; non firmato. Terminazione irreversibile, senza arresto figli o veto al rilancio.

Test: parser frontend e consenso browser; test nativo soltanto su figlio fixture copiato/creato dal test, identity mismatch preserva il figlio, identità giusta ne conferma uscita. Nessun processo utente esistente fermato dai test.

