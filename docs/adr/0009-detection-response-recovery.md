# ADR 0009 — Detection e risposta verificabile

2026-10-06. Decisione: estensione incrementale della fondazione esistente.

L'audit conferma che normalizzazione, bookmark, storage e IPC esistono; nessun
motore trasforma ancora gli eventi in segnalazioni o effetti sul sistema.
Manteniamo Rust safe per regole, policy, journal e UI bridge. Le sole nuove FFI
Windows restano in win-platform: handle esclusivi, identità file, cancellazione
per handle, DPAPI e verifica del token del chiamante. Nessun driver.

Detection: regole deterministiche su canale, provider ed Event ID; evidenza
referenziata, motivazione e limiti. Installare un servizio non prova malware.
Le segnalazioni sono persistite nella stessa transazione degli eventi. Nessuna
azione automatica viene dedotta da una segnalazione o da un percorso potenziale.

Enforcement: quarantena esplicita di un file locale nelle radici autorizzate.
Risposta: piano con hash e identità file, scadenza, conferma, nuova validazione,
journal durabile prima degli effetti e verifica finale. Recovery: recupero del
contenuto verificato senza sovrascrivere file esistenti; ACL ereditata dalla
cartella di destinazione. Rifiutare link, stream alternativi, file di sistema,
file aperti e file oltre il limite. Backup DPAPI conservato anche dopo recovery.

Il servizio richiede token amministrativo elevato per le mutazioni; il viewer
rimane in sola lettura. In console il perimetro è lo stesso utente/sessione,
senza isolamento da malware già eseguito come quell'utente. Nessun privilegio
aggiuntivo viene attivato. Interruzioni durante un'azione producono stato incerto
recuperabile, mai una ripetizione automatica della cancellazione.

Fuori da questa estensione: prevenzione kernel in tempo reale, kill/suspend
processi, firewall, rollback di rete o memoria, VSS e protezione ransomware
generale. La UI deve mostrare queste capacità concrete senza promettere tali
funzioni.

