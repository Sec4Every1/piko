# Threat model di piko

Data: 2026-10-04. Questo modello descrive il prodotto obiettivo e i limiti della prima slice. Le mitigazioni progettate non sono tutte implementate.

## Asset e confini

Gli asset sono disponibilità del monitoraggio, veridicità degli stati mostrati, integrità delle policy, evidenze, chiavi, recovery history, documenti e identità dell'utente. Anche percorsi, SID, nomi software e cronologia delle connessioni sono dati sensibili.

Confini: applicazioni osservate → sensori; callback Windows → decoder; parser → fabric; fabric → storage; UI/CLI → IPC → servizio; servizio → kernel; host → eventuale coordinator; pacchetto update → installer. Tutti i payload esterni, inclusi provider Windows, nome file, XML, certificato e messaggi fleet, sono input non fidati. Il frontend non è autorità; il client dichiara una richiesta, il servizio decide cosa può leggere o fare.

## Avversari e garanzie

| Avversario | Obiettivo di progetto | Limite esplicito |
| --- | --- | --- |
| Processo ordinario con lo stesso account dell'utente | Limitare l'impatto e spiegare espansioni di capacità | Nel dev runtime può leggere l'API di self-health autorizzata al SID; il SID non prova l'intento umano |
| Altro utente locale | Impedire lettura/mutazione dei dati altrui | ACL, session binding e test multiutente sono necessari |
| Amministratore ostile/SYSTEM | Rilevare manomissioni e ridurre superficie; preservare ciò che è già ancorato | Non si promette invulnerabilità del servizio o segretezza totale di chiavi in uso |
| Driver ostile/BYOVD/kernel compromesso | Cross-view e boot/integrity evidence quando disponibile | Un kernel ostile può mentire a user-mode; nessuna attestazione assoluta locale |
| Attaccante remoto | Nessun listener remoto nella base; validazione di feed/coordinator futuri | Un endpoint remoto autenticato può comunque fornire evidenze malevole |
| Update/dependency compromessa | Build, provenance, firme e anti-rollback; probation comportamentale | Firma e repository ufficiale non provano benignità |
| Accesso offline al disco | Cifratura e checkpoint verificabili fuori host futuri | La versione dev non implementa cifratura at rest né anti-rollback esterno |

Il prodotto non promette di bonificare firmware ostile, riparare ogni file cifrato, ricostruire eventi mai osservati o prevenire ogni azione di un amministratore. Non contiene malware reale per i test.

## Scenari da verificare

| Minaccia | Mitigazione progettata | Evidenza/test richiesto |
| --- | --- | --- |
| Pipe squatting e server falso | Prima istanza esclusiva, identità server attesa, controllo errore | Processo ostile occupa il nome; il runtime rifiuta l'avvio, il client non trasmette segreti |
| Spoofing caller / confused deputy | DACL esplicita, SID/session dal sistema operativo, API chiusa e separazione read/action | Altro utente, sessione diversa, claim SID nel JSON, percorso arbitrario |
| Client lento o frame enorme | Limite byte, deadline, numero connessioni limitato, cancellazione | Slow client, troncamento, nested JSON, disconnessione durante risposta |
| Event flood | Queue/payload/batch limitati; contatore perdita e health | Producer sopra capacità, memoria limitata e loss event recuperabile |
| Replay o sequenza saltata | Identità runtime/boot, dedup, sequence e monotonic time | Duplicati, restart collector, PID reuse, clock rollback |
| Corruzione/manomissione log | Validazione payload, chain, segmenti e checkpoint successivi | Bit flip, middle delete, reorder; test separato per limiti di tail truncation |
| Cancellazione totale o riscrittura chain locale | Checkpoint firmati e ancoraggio esterno futuro | Confronto con digest già noto fuori dal DB; altrimenti risultato non attestabile |
| Sensore silenzioso | Health semantica, contatori di sorgente, cross-view | Arresto sessione ETW, policy audit disabilitata, errore accesso |
| Policy weakening | Autorizzazione distinta dalla lettura, versione, audit old/new/reason | Modifica non autorizzata rifiutata; replay di vecchia policy |
| Recovery cancellata dall'attaccante | Authority separata, ACL, store offline/esterno opzionale | Utente che scrive documento non può eliminare history di produzione |
| Parser exploit / XSS in evidenza | Rust safe, decoder limitato, stringhe escape, CSP, nessun eval | Corpus/fuzz; path con markup; dati non renderizzati come HTML |
| Update rollback | Version floor protetto, firma/hash, installazione transazionale | Package vecchio firmato rifiutato senza eccezione amministrata |
| Fleet poisoning | Enrollment, trust per peer, TTL, evidenza/confidence e approvazione graduata | Due anomalie correlate non generano automaticamente blocco globale |
| Confondere possibilità con attacco | Tipi Observed/Potential/Counterfactual separati; gate response su evidenza o policy esplicita | Percorso potenziale da solo non produce blocco |
| Topology poisoning o cache obsoleta | Provenienza/versione/freschezza e invalidazione per delta | ACL revocata, token cambiato e import esterno non restano permission valide |
| Graph explosion/ricerca incompleta | Budget di profondità/stati/cache/tempo; flag di incompletezza | Cicli e branching elevato non saturano memoria né producono falso “nessun percorso” |
| Scenario usato come autorizzazione | Overlay isolato, base revalidata, autorizzazione separata | Un counterfactual non cambia stato/policy e non si applica su una base diversa |
| Fingerprint fleet inapplicabile | Precondizioni verificate sul destinatario | Topologia o identità diverse impediscono un blocco universale |

La sicurezza della named pipe dipende dal security descriptor; il descriptor predefinito non è adatto a dati di sicurezza sensibili. L'identità ricavata tramite impersonazione è attendibile soltanto se l'operazione riesce: il servizio non deve continuare nel proprio contesto privilegiato dopo un errore. [Named Pipe Security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient), verificati 2026-10-04.

## Rischi residui della versione dev

Il processo è console/per-user; i file nel workspace non costituiscono protected storage. La telemetria riguarda la salute del runtime, non tutti i processi di Windows. Nessun blocco ransomware, account creation firewall, protezione credenziali, self-defense kernel, checkpoint remoto o recovery protetta è presente. Un indicatore “connesso” significa che l'API risponde, non che la macchina è sicura.

Prima di ampliare l'API a telemetria personale o azioni privilegiate sono obbligatori test multiutente/sessione e verifica dell'identità server; prima di distribuire un servizio privilegiato occorrono review delle ACL, installer, privilegi e percorso di update. Il threat model va aggiornato in ogni ADR che introduce un confine di fiducia.
