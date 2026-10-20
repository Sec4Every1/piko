# Windows FFI boundary

Estensione ADR 0008: `service.rs` incapsula SCM e `event_log.rs` gli handle di
raccolta. `EventHandle` usa `PhantomData<Rc<()>>`, quindi non lascia il thread
creatore. `EvtClose` precede il rilascio del segnale manual-reset; XML/bookmark
sono copie bounded. La subscription attende il segnale e lo resetta soltanto
dopo esaurimento dei risultati. Startup limitato a 16 record per canale.

Pipe installata: account virtuale in sessione 0; SID lettore da config protetta;
diritti dati e SYNCHRONIZE senza FILE_CREATE_PIPE_INSTANCE. Il client verifica
il PID tramite SCM (OWN_PROCESS, Running). La DACL autorizza l'apertura; un viewer
può delegare un handle o condividere risultati. Le query restano disponibili al
viewer; le mutazioni verificano il token elevato effettivo della richiesta,
tramite impersonation di identificazione sincrona con RevertToSelf obbligatorio.
`report_diagnostic` scrive messaggi piko locali bounded (4096 byte) in Application,
anche in caso di avvio fallito prima dello storage. [ADR 0008](../../docs/adr/0008-windows-service-and-event-log.md).

Decisione linguistica: KEEP Rust. Questo crate racchiude le primitive native
necessarie; policy e business logic restano nel core safe. ADR 0009 aggiunge
`file_response.rs`: apertura esclusiva, identità file, verifica stream/link,
cancellazione per handle e DPAPI con scope utente. `unsafe_op_in_unsafe_fn` è
vietato; gli altri crate di prodotto vietano unsafe proprietario.

`references.rs` apre, su clic esplicito nella UI non elevata, solo tre pagine
HTTPS MITRE compilate nel codice. Un ID esatto viene risolto prima di qualsiasi
effetto; URL arbitrari, percorsi, argomenti e verbo `runas` non sono accettati.
`ShellExecuteW` usa COM STA inizializzato e rilasciato sullo stesso worker;
il risultato numerico non viene trattato come un handle da chiudere.
Contratti: [ShellExecuteW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutew)
e [CoInitializeEx](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex).

## Ownership e memoria

- `GetCurrentProcess` restituisce uno pseudo-handle preso in prestito, mai passato a `OwnedHandle`.
- `OpenProcess`/`OpenProcessToken` riusciti trasferiscono un handle a `OwnedHandle`; `Drop` chiama `CloseHandle` una volta. Nessun riferimento sopravvive al proprietario.
- `GetTokenInformation(TokenUser)` viene prima interrogato per dimensione. Si verifica `ERROR_INSUFFICIENT_BUFFER`, si limita l'allocazione a 64 KiB e si usa `Vec<usize>` per l'allineamento. `TOKEN_USER` e SID vengono letti mentre il buffer è vivo.
- `ConvertSidToStringSidW` produce una stringa NUL-terminated allocata da Windows; viene copiata in `String` prima di `LocalFree`. Il puntatore non deriva da una richiesta IPC.
- Il descriptor SDDL usa il SID letto dal token, non testo ricevuto dal client. `SECURITY_ATTRIBUTES` e descriptor sono vivi durante la creazione; Windows cattura il descriptor e Tokio possiede l'handle della pipe.

## Threading, input e garanzie

Le funzioni native sono sincrone e brevi; non introducono impersonazione persistente o globali mutable. L'identità expected è prodotta dal token corrente. I PID dei peer provengono dalla pipe connessa e sono verificati tramite token; non vengono accettati da JSON. Errori su processo terminato/accesso negato non sono interpretati come autorizzazione.

La pipe ha DACL protetta per il SID, `PIPE_REJECT_REMOTE_CLIENTS`, controllo prima istanza e cinque istanze massime (quattro richieste più listener). I client usano `SECURITY_IDENTIFICATION`: nessuna delega/impersonazione operativa. Questo confine isola utenti/sessioni, **non** applicazioni ostili nello stesso utente. Amministratore/kernel compromesso non sono risolti da questa pipe.

`TokenSessionId` è usato nel nome e nel confronto IPC; non è l'authentication LUID. Gli eventi non inventano `logon_session` da tale valore.

## Errori e cleanup

Sizing errato, conversione fallita, identità diversa, pipe già presente, peer terminato, accesso negato e creazione fallita tornano come `io::Error`. Non esiste fallback con ACL aperta o autenticazione saltata. RAII rilascia handle/buffer anche durante un early return. Un eventuale errore di cleanup OS non amplia autorizzazioni; leak/failure injection richiedono ulteriore qualifica prima di produzione.

## Test e limiti

I test nativi verificano identità stabile, rifiuto di identità errata e prima istanza duplicata. Lo smoke completa creazione, connessione, peer check e trasporto in processi reali. Non equivalgono a prove cross-user/session/remoto, lifecycle SCM, ACL installer o stress/failure injection completi. Prima di estendere questo confine a operazioni privilegiate servono un nuovo modello autorizzativo e test dedicati.

Contratti: [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation), [named-pipe access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [GetNamedPipeClientProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid), [GetNamedPipeServerProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid).
