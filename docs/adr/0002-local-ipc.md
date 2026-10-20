# ADR-0002 — IPC Windows locale e sola lettura iniziale

- Stato: accettato per il runtime di sviluppo; broker del servizio di produzione da qualificare.
- Data: 2026-10-04.

## Decisione

Named pipe per SID/sessione con DACL esplicita, remote client rejection, prima istanza esclusiva, autenticazione identità OS, frame limitati e deadline. Richieste iniziali soltanto status/eventi/verifica; nessun HTTP localhost, comando shell, SQL o percorso file arbitrario. I client non inviano un segreto riusabile come prova di identità.

Le funzioni documentate consentono access control e isolamento locale; l'autenticazione di un account non dimostra l'identità esclusiva di un'applicazione né il consenso umano. Il client dovrà verificare il server prima di usare API privilegiate o telemetria sensibile. [Microsoft named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), verificato 2026-10-04.

## Conseguenze e gate

Il dev runtime è accessibile ai processi autorizzati di quel SID/sessione. Per il servizio multiutente servono nuovo scope di autorizzazione, test impersonation failure, session switching, server spoofing, slow client e richieste oltre limite. Ampliare la DACL senza queste prove non è una migrazione accettabile. Chiudere la UI non ferma il processo runtime separato.

