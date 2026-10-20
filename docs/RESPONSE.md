# Detection, enforcement, risposta e recovery — piko 0.2.0

La pagina **Protezione** e la CLI usano il runtime reale, senza fixture o dati
dimostrativi. Questa versione implementa una capacità precisa per ciascun motore.

| Motore | Implementazione |
| --- | --- |
| Detection | Quattro regole su canale/provider/Event ID: Security 1102 (log cancellato), Security 4719 (policy audit), System 104 (log cancellato), System 7045 (servizio installato). Segnalazioni con ID regola/versione ed evento/XML collegati. |
| Enforcement | Quarantena manuale: rimozione dell'esatto file aperto dopo un backup cifrato verificato. Nessun comando per eseguire codice arbitrario. |
| Risposta | Anteprima con hash/identità, conferma esplicita, piano di 5 minuti, nuova validazione, journal prima degli effetti, SID del richiedente e del confermante. |
| Recovery | Decrittazione e verifica SHA-256, creazione esclusiva della destinazione originale, verifica finale. Nessun overwrite; backup conservato. |

Una segnalazione è un fatto da esaminare, non la prova di malware. Un servizio
installato può essere legittimo. Nessuna regola attiva automaticamente una
quarantena e nessun PID attore viene inventato dal processo emittente del log.
Le detection vengono salvate nella stessa transazione degli eventi. All'upgrade
sono valutati anche gli eventi già conservati, senza duplicare il log.

## Uso

Avviare `Start-Piko.ps1`, aprire **Protezione**, leggere le evidenze e inserire
il percorso completo del file. **Prepara quarantena** non rimuove nulla.
L'anteprima mostra percorso, SHA-256, dimensione e scadenza. La conferma esegue
l'operazione; il registro distingue esecuzione, backup pronto, quarantena,
ripristino, scadenza ed esito da verificare. Per recuperare il file usare
**Prepara ripristino**, controllare l'anteprima e confermare.

CLI equivalente:

```powershell
.\piko.exe alerts
.\piko.exe actions
.\piko.exe quarantine-plan 'C:\Users\nome\Downloads\file.txt'
.\piko.exe confirm <ID-piano> <SHA256-dell-anteprima>
.\piko.exe restore-plan <ID-quarantena>
.\piko.exe confirm <ID-piano-ripristino> <SHA256-dell-anteprima>
```

## Perimetro e limiti

- In console, radici predefinite: Documents e Downloads del profilo. Per cartelle
  reindirizzate o altre radici, configurare `response_roots` come array di percorsi
  locali assoluti in `console.json`; riavviare il runtime. Un array vuoto disabilita
  le azioni sui file. Non cambiare `data_dir` per aggirare conflitti.
- In SCM, le radici sono vuote per default. `Install-Piko.ps1 -ResponseRoots ...`
  oppure la configurazione protetta definisce l'ambito. Il servizio deve possedere
  i diritti necessari su quelle cartelle; non vengono concessi automaticamente.
  La UI viewer non può eseguire mutazioni: usare la CLI elevata. Test di installazione,
  DPAPI dell'account virtuale e matrice cross-user richiedono ancora un ambiente
  amministrativo. Un errore di autorizzazione/cifratura conserva l'originale.
- Limite contenuto: 16 MiB meno 64 KiB di margine per cifratura. Vault: 128 MiB
  compreso journal e file cifrati; journal SQLite: massimo 32 MiB. Tetto logico
  di 1000 piani di quarantena; i piani di recovery sono esclusi da quel tetto.
  Ultime 100 azioni esposte in UI/API; la CLI può preparare recovery di un backup
  precedente tramite il relativo UUID. Le quarantene lasciano 8 MiB di margine
  per journal e recovery. Raggiungere il tetto dei piani di quarantena non blocca
  il ripristino. Se si esaurisce lo spazio fisico o il budget disco del journal,
  preservare e far verificare archivio/profilo prima di manutenzione. Nessuna
  cancellazione automatica del vault.
- Esclusi directory, file di sistema/read-only/EFS, hard link, reparse point,
  stream alternativi (anche Zone.Identifier), percorsi UNC/device/ADS, file
  aperti in modo incompatibile e directory di sistema, del programma o dei dati piko.
- Lo stesso handle esclusivo serve per identità, lettura e cancellazione. L'hash
  e l'identità sono rivalidati alla conferma. Il path finale deve restare nelle
  radici autorizzate. Il file viene cancellato per handle, non risolvendo di nuovo
  il percorso iniziale. Non si promette di eliminare copie presenti altrove.
- Un lock esclusivo impedisce a due runtime di usare lo stesso vault, anche da
  sessioni diverse. Le radici canoniche sono confrontate per componenti senza
  fondere nomi Unicode distinti o directory NTFS con case sensitivity attiva.
  Se l'ispezione di un nuovo file di recovery fallisce, il file appena creato
  viene rimosso per handle senza interferire con destinazioni preesistenti.
- Il recovery recupera **contenuto**, con ACL ereditata dalla cartella. Non
  ripristina ACL o timestamp originali, memoria/processi, rete, sistema o VSS.
  Se la destinazione esiste, preservarla e spostarla esplicitamente prima di
  preparare un nuovo recovery; piko non la sovrascrive.
- DPAPI è legato all'identità Windows del runtime. Il vault non è un backup
  portabile su altre identità/macchine. Conservare dati e profilo Windows.
  In console non è isolato da malware con la stessa identità dell'utente.
- Timeout o riavvio durante un'azione producono un esito incerto. Consultare il
  journal e il filesystem; l'UUID non ripete mai automaticamente gli effetti.
  Un backup registrato e verificabile può essere recuperato con un nuovo piano.
  Il journal è durabile e senza API di modifica della storia, non firmato né
  immune a riscritture di un amministratore o dello stesso utente console.

## Fonti delle primitive

[CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata),
[SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle),
[ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient),
[1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102),
[raccolta eventi Windows](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection).

Il controllo rete supporta ora **In uscita** e **In ingresso**, dal menu della griglia o dalla direzione del percorso manuale. I piani e le regole indicano la direzione; due blocchi per lo stesso percorso coesistono e la rimozione riguarda solo quello scelto. In ingresso limita le connessioni iniziate da altri dispositivi, non sostituisce un blocco in uscita. Per applicare entrambi, prepara e conferma le due direzioni separatamente. Conferma con helper UAC, SHA-256 ricontrollato, file bloccato in lettura, template completo e journal Windows; nessuna regola globale viene modificata. Template COM verificati in memoria e UI con fixture; il filtraggio pacchetti in ingresso sotto token amministrativo non è stato qualificato sul PC.
