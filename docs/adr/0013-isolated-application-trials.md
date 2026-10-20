# ADR 0013 — Prova isolata manuale con Windows Sandbox

Stato: implementato il profilo e il lifecycle locale; qualificazione guest pendente.
Data: 2026-10-12.

L'utente chiede limiti per testare software necessario ma potenzialmente dannoso.
I blocchi file per processi host non possono essere simulati con ACL dell'utente:
condividerebbero l'identità con altre app. Questa slice usa il confine di Windows
Sandbox per una copia singola, senza dichiarare completati i contratti granulari.

Safe Rust in app-control, comandi Tauri non elevati, nessuna shell. Anteprima di
cinque minuti, massimo otto piani; copia solo dopo conferma. Riapertura del file
con divieto di write/delete sharing e controllo SHA-256 prima/dopo copia. Directory
parent bloccate e reparse point rifiutati. Il target non viene eseguito su host né
al logon del guest. Il launcher di sistema riceve solo il path .wsb generato.

Profilo fisso: networking, vGPU, input audio/video, stampanti e clipboard Disable;
ProtectedClient Enable; 4096 MiB; unica cartella con payload.exe ReadOnly true.
XML escaped e rifiuto percorsi con controlli o espansioni percentuali. Nessuna
cartella personale o directory di installazione viene condivisa. Windows guest
può modificare il proprio stato. Nessun congelamento aggiornamenti sul sistema host.

Sessioni persistenti nell'app_local_data_dir, massimo otto (2 GiB di payload nel
caso massimo); eliminazione confermata solo di nomi fissi, mai ricorsiva. Originale
preservato. Configurazione, hash e contenuto della cartella sono ricontrollati prima
della richiesta d'avvio. Nessuna resistenza dichiarata contro lo stesso account
ostile/amministratore; la copia salvata non è una quarantena cifrata. Errori e
sessioni incomplete restano espliciti; una sessione corrotta richiede ispezione
manuale della directory, senza cleanup automatico di percorsi non verificati.

Presenza del launcher è un'osservazione, non prova dei prerequisiti o dell'avvio.
Il frontend dice “avvio richiesto”, non “isolamento verificato”. Nessuna fallback
execution sul sistema host. Installer/portable singoli soltanto; DLL/dati/licenze
non vengono copiati. Telemetria guest, avvio riuscito, isolamento effettivo e
compatibilità Windows restano da qualificare in VM dedicate.

Test: XML/escaping, copia byte-identica, anteprima senza effetti, piani single-use,
scadenza/cambio hash, rifiuto config alterate; UI conferma e mancato launcher;
smoke Tauri con copia innocua, verifica profilo e rimozione. Nessun software non
fidato viene avviato dai test.

Fonte primaria: https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file

