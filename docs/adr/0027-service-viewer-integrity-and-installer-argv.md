# ADR 0027 — Viewer normale e servizio Windows

Il servizio Windows usa un account virtuale distinto dall’utente della dashboard. L’installer deve costruire gli argomenti SCM in modo compatibile con Windows PowerShell 5.1 e consentire una ripresa limitata soltanto dopo verifica esatta dei file previsti. Dati e configurazione esistenti non vengono cancellati automaticamente.

La named pipe applica un mandatory label Medium e una DACL limitata al SID autorizzato, al servizio, a SYSTEM e agli amministratori. Il viewer riceve soltanto i diritti necessari per le richieste di lettura; non può creare istanze della pipe né accedere da remoto. Il server verifica il PID del client con SCM e rifiuta client remoti. Non delega l’identità né allarga i diritti a Everyone.

Gli errori di apertura e query del PID riportano la fase fallita. Il codice nativo PIPE_BUSY è preservato per retry limitati.

ETW richiede autorizzazioni Windows specifiche. Quando l’accesso del provider è negato, l’installer offre un’opzione amministrativa separata che concede soltanto TRACELOG_GUID_ENABLE all’account virtuale piko; salva l’ACL precedente e consente il ripristino condizionato se nessun altro l’ha modificata. Non eleva GUI o viewer. Vedi Set-PikoEtwPermission.ps1.

La coda di forwarding è limitata in memoria. Dopo un commit riuscito, il worker continua subito col lotto successivo; errori ritentano con timer senza loop serrato. Le perdite non vengono nascoste o rimosse dallo storico. Test di carico e reboot restano requisiti di qualifica, non implicazioni del test unitario.

Fonte primaria: [EventAccessControl](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccesscontrol).
