# Privacy di piko

Aggiornamento 0.2.0: soltanto i file scelti esplicitamente per quarantena vengono
copiati nel vault DPAPI locale. Il journal conserva percorso, hash, dimensione,
identità file, SID richiedente/confermante, stato e orario delle transizioni.
Nessuna scansione dei contenuti delle cartelle e nessun upload. Le copie restano
anche dopo recovery; non c'è retention automatica. I metadati del journal e il
registro eventi restano in chiaro; la cifratura dei backup non li cifra.

L'Attack Path Engine futuro conserverà riferimenti a identità, risorse e permessi; la presenza di un nodo Credential non richiede raccogliere il segreto. Criticità e topology possono essere sensibili: accesso, export e fleet sharing dovranno rispettare scope/minimizzazione. Un adapter esterno non autorizza automaticamente l'importazione di contenuti personali. Le proposte controfattuali restano locali e hanno retention separata dalle evidenze osservate.

Data: 2026-10-04. Politica tecnica di progetto, non attestazione di conformità legale.

## Prima slice

Estensione corrente: System, Application e Security sono sorgenti reali secondo
i diritti disponibili. Conserviamo XML reso da Windows, provider, record ID,
timestamp e bookmark. I payload possono includere account, percorsi e nomi host;
sono consultabili dal SID lettore autorizzato per l'intero dispositivo. Nessun
upload o modifica automatica della audit policy. Il primo avvio importa fino a
16 record recenti/canale; il seguito è continuo. Access denied rimane visibile.

Il runtime conserva localmente identità UUID della propria installazione, epoca runtime, eventi del proprio avvio/salute, timestamp e diagnostica di storage/pipeline. I campi opzionali dello schema non significano che il relativo dato sia già raccolto. La UI consulta il runtime attraverso IPC locale. Non sono previsti account cloud, upload automatici, crash report remoti, advertising, analytics o feed esterni attivati implicitamente.

I file del prototipo sono dati di sviluppo e non offrono cifratura at rest, protected history o isolamento rispetto ad altri processi dello stesso utente. Non inserirvi manualmente documenti o segreti reali come fixture. La directory di lavoro non è un vault. Build e installazione delle dipendenze possono richiedere rete: questo è distinto dal comportamento offline del prodotto.

## Minimo necessario per le prossime sorgenti

| Dato | Default progettato | Uso / cautela |
| --- | --- | --- |
| Hash, identity software, firma, PID e SID | Metadata pertinenti | SID e percorsi restano identificabili; accesso limitato |
| File/Registry path e tipo operazione | Raccolta mirata e configurabile | I nomi possono rivelare informazioni personali |
| Contenuto documenti | Non raccolto normalmente | Acquisizione forense mirata solo con policy/consenso espliciti |
| Command line, variabili d'ambiente | Escluse o redatte salvo esigenza documentata | Possono contenere token/password; non includerle indiscriminatamente nel raw |
| Password, cookie, session token, private key | Mai estratti per il normale monitoraggio | Osservare accesso al contenitore non equivale a leggerne il contenuto |
| DNS/domain/IP/TLS metadata | Metadata minimi e retention dedicata | Rivelano interessi; DoH/ECH può ridurre visibilità |
| Screenshot, audio, video, clipboard content | Nessuna cattura normale | Eventuale uso risorsa non autorizza acquisizione contenuto |
| Canary/decoy | Generati artificialmente | Nessun segreto reale e nessun accesso utile |
| Metriche CPU/RAM/queue | Locali | Nessun invio implicito |
| Capsule incidente | Sottoinsieme rilevante e motivato | Anteprima, scope e audit dell'export |

Il principio “preservare raw” si applica al dato autorizzato ad essere acquisito. La minimizzazione avviene prima della persistenza; se un raw viene redatto, conservarne la dichiarazione di trasformazione e non etichettarlo come originale completo. Non cancellare silenziosamente una sorgente già necessaria a un incidente per nascondere una modifica del parser.

## Accesso e condivisione

Gli utenti vedono soltanto lo scope autorizzato; una futura installazione multiutente non rende i log di ogni account leggibili da tutti. Export, capsule, enrollment, threat intelligence e fleet sharing sono operazioni distinte e spiegabili. Una richiesta di reputation di un hash può comunque rivelare software presente: l'invio sarà opzionale, minimizzato e auditato.

La fleet condivide fingerprint causali e metadati selezionati, non l'intera cronologia del PC. Per impostazione iniziale: nessun contenuto personale, nessuna credenziale, identificatori pseudonimi per scope fleet, scadenza e rimozione dell'enrollment. Pseudonimizzazione non equivale ad anonimato; path e combinazioni di eventi possono reidentificare. Nessuna funzione fleet appare su un singolo host.

## Retention, cancellazione e recovery

Il budget dev iniziale è 256 MiB configurabile, con minimo 8 MiB: al limite lo storage deve rifiutare nuove scritture e segnalare il problema. Questo **non è ancora retention HOT/WARM/COLD** e non promette un numero di giorni. La roadmap introduce quote separate per raw, indici e capsule, riserva spazio libero e policy di conservazione esplicite.

Il piano di produzione è HOT per query recenti, WARM per segmenti compressi, COLD per capsule conservate esplicitamente e DELETE per scadenza. Ogni policy indica quali dati, per quanto, perché e chi può cambiare la durata. Una legal/incident hold non deve essere silenziosa o illimitata. La cancellazione normale non prova cancellazione fisica da SSD, backup o copie esportate. La futura cifratura dovrà considerare rotazione e distruzione delle chiavi senza promettere proprietà del supporto non misurate.

Una richiesta di disinstallazione deve spiegare la scelta di conservare/esportare/eliminare dati e chiavi; non lasciare servizi/driver orfani. Recovery offline richiede che l'utente possa recuperare evidenze senza dipendere solo da un Windows compromesso. Progettare questa possibilità non autorizza l'invio a terzi.

Le valutazioni manuali e le note personali sono salvate in alert-reviews.sqlite per l’utente della UI: ultima scelta per massimo 2000 eventi, SID del valutatore derivato da Windows e orario. Non inviate al cloud. L’avvio al login scrive solo la voce HKCU Run PikoMonitor quando attivato esplicitamente; startup-status.txt conserva l’ultimo errore (svuotato dopo un tentativo riuscito).

Verifica firma locale: file/hash/codice e orario vengono mostrati su richiesta senza upload. WinVerifyTrust usa solo cache locale con revoca disabilitata. Nessun servizio di reputazione esterno o invio campioni.
