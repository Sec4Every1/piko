# Installazione di piko su Windows x64

Il pacchetto contiene servizio, CLI e interfaccia desktop. È una build locale
non firmata: analizza registri Windows, conserva evidenze e offre quarantena
manuale e recovery del contenuto. Offre anche controlli di rete confermati, arresto di singole istanze e prove AppContainer; non è un antivirus completo. Le azioni file richiedono anteprima e conferma.

Prerequisiti: Windows x64 e WebView2 per la UI. Non disabilitare Defender,
Secure Boot o i controlli di sicurezza di Windows.

Per installare piko con monitoraggio automatico, estrarre lo ZIP e fare doppio
clic su **Install-Piko.cmd**. La richiesta UAC di Windows è necessaria per il
servizio protetto; l’installer ricava da solo l’account che userà la dashboard,
installa il monitor e apre piko al termine. Non copiare comandi o SID. La UI si
avvia come utente normale. Servizio e archivio si rimuovono con
**Uninstall-Piko.ps1** (richiede UAC e conserva i dati). Gli aggiornamenti in-place
sono ancora in sviluppo.

Per provare piko senza installare il servizio, fare doppio clic su
**Open-Piko.cmd**. Avvia monitor e UI; i dati sono in `%LocalAppData%\piko-monitor`.
Il monitor continua quando si chiude la UI e termina al logout: non configura
avvio automatico né protezione preventiva.

La **Dashboard** spiega le segnalazioni e i riferimenti MITRE ATT&CK. La pagina
**Quarantena e ripristino** contiene preparazione e conferma delle azioni sui file,
registro delle azioni e recovery senza sovrascrittura. **Log tecnici** conserva
anche heartbeat e diagnostica. **Manuale** spiega l'uso dell'app; nel pacchetto
è incluso `MANUALE_UTENTE.md`. **Permessi app** dichiara le funzioni mancanti:
sono disponibili blocchi rete in ingresso/uscita per percorso .exe con helper UAC, prove AppContainer e advisory locali.
I permessi generali su file, registro e dispositivi per tutte le app non sono ancora disponibili.
In console sono autorizzate Documents e Downloads del profilo (se esistono).
Configurare `response_roots` per cartelle reindirizzate. Backup DPAPI legati
all'identità Windows; limite file 15,94 MiB. Il recovery ricrea il contenuto con
permessi ereditati dalla cartella, senza ACL o date originali. Per dettagli
vedere `RESPONSE.md` incluso nel pacchetto.

1. Aprire PowerShell **come amministratore** nella cartella del pacchetto.
2. Eseguire il comando presente in `INSTALL-COMMAND.txt`: il SID identifica
   l'utente autorizzato a leggere il registro tramite l'app.
3. Da una normale sessione utente aprire `C:\Program Files\piko\piko-desktop.exe`.
   La UI non deve essere avviata come amministratore.

Il viewer del servizio rimane in sola lettura. Le mutazioni richiedono CLI
elevata e radici autorizzate tramite `-ResponseRoots` dell'installer o il campo
`response_roots` della configurazione protetta. Le ACL devono consentire al
servizio l'accesso; l'installer non allarga i permessi delle cartelle utente.

Il servizio `piko` parte automaticamente con avvio ritardato e funziona anche
con UI chiusa. Usa l'account virtuale `NT SERVICE\piko`; legge i canali consentiti
mediante Event Log Readers, senza cambiare audit policy. Il canale Security può
comunque risultare indisponibile secondo ACL e policy della macchina.

Il programma è in `%ProgramFiles%\piko`; configurazione protetta `service.json`;
dati in `%ProgramData%\piko`, modificabili dal servizio e dagli amministratori.

Verifica da utente autorizzato:

```powershell
& 'C:\Program Files\piko\piko.exe' health
& 'C:\Program Files\piko\piko.exe' events windows.event_log
& 'C:\Program Files\piko\piko.exe' verify
```

Per disinstallare eseguire `Uninstall-Piko.ps1` come amministratore. Conserva
sempre i dati. Aggiornamenti in-place e importazione di dati da una precedente
installazione richiedono ancora una procedura di migrazione; l'installer rifiuta
di sovrascrivere directory esistenti.

`Install-Piko.ps1 -ViewerSid <SID> -WhatIf` verifica il pacchetto e mostra le
modifiche previste senza installare. L'installazione effettiva richiede un token
amministrativo; scaricare le dipendenze o compilare non fornisce questo diritto.

Ripresa dei registri: il primo avvio importa fino a 16 eventi recenti per canale
accessibile; poi raccoglie i nuovi eventi. Ai riavvii usa il bookmark dell'ultimo
evento durabile. Un registro cancellato o un bookmark scaduto causa degrado
esplicito; non viene aggirato saltando automaticamente parte della storia.


## Permessi ETW del servizio

L’installer accetta **-EnableEtw**: iscrive soltanto **NT SERVICE\piko** a **Performance Log Users** (SID S-1-5-32-559), oltre a Event Log Readers. Non eleva la UI o il viewer. È facoltativo e la disinstallazione rimuove soltanto le appartenenze dell’account piko. Una installazione interrotta conserva file/dati/account per ispezione; usare la disinstallazione per rimuoverla.

Microsoft documenta il requisito per [StartTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew) e [EnableTraceEx2](https://learn.microsoft.com/it-it/windows/win32/api/evntrace/nf-evntrace-enabletraceex2). Policy o ACL del provider possono comunque impedire la raccolta. Dopo l’installazione, **Test-PikoService.ps1 -RequireEtw** deve confermare eventi ricevuti: la sola appartenenza al gruppo non è una prova.

## Ripresa dopo installazione parziale

L’installer supporta -ResumeIncomplete solo quando il servizio e l’archivio di sistema non esistono e la cartella programma contiene esattamente i quattro eseguibili e il manifest identici al pacchetto. Non cancella cartelle né dati. Invocazione sc.exe con argv Windows esplicito per preservare le virgolette dei percorsi in PowerShell 5.1. MaxDiskMiB default 512, validato 8–4096.


## Permesso specifico del provider ETW

Se EnableTraceEx2 è negato, -EnableEtwProviderAccess dell'installer concede soltanto TRACELOG_GUID_ENABLE a NT SERVICE\piko sul provider dei processi. È una modifica permanente di sicurezza da autorizzare esplicitamente. Per un servizio già installato, eseguire Set-PikoEtwPermission.ps1 come amministratore e riavviare soltanto piko. Il file protetto etw-provider-permission.json conserva il valore registro originale e quello applicato. Set-PikoEtwPermission.ps1 -Restore ripristina il valore originario soltanto se non sono intervenute modifiche esterne; la disinstallazione esegue questo ripristino prima di rimuovere il servizio. Non si elevano dashboard o viewer. Con -WhatIf non vengono modificati i permessi.



La dashboard release incorpora HTML/CSS/JavaScript e non richiede un server locale Vite. Compilare con npm run tauri -- build --no-bundle --ci -- --offline nella cartella desktop, oppure cargo build --release --features custom-protocol nel crate Tauri. La feature è default; release senza di essa vengono rifiutate. Per sviluppo con Vite: npm run tauri -- dev --no-default-features.


Compress-PikoArchive.ps1 (PowerShell amministratore) ricomprime lo storico a servizio fermo con backup protetto prima delle modifiche. Rifiuta identità SCM o directory dati inattese; controlla lo spazio per backup e margine WAL. Piko verifica prima e dopo il conteggio e la catena. Il file SQLite resta allocato, ma riusa pagine liberate. Backup conservato in ProgramData\\piko\\before-compression-*; richiede spazio aggiuntivo, fuori dal budget operativo SQLite. Non è una retention né una cancellazione automatica. Usare una build compatibile: precedenti versioni senza codec non leggono le nuove evidenze.

