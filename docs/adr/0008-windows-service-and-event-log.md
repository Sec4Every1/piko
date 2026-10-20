# ADR 0008 — Servizio installabile e acquisizione Windows Event Log

Decisione: estendere i componenti esistenti, senza riscriverli. Il core resta safe
Rust; SCM, handle Event Log e named pipe rimangono nel confine `win-platform`.

| Capacità | API | Privilegio | Limite / fallback | Verifica |
|---|---|---|---|---|
| Lifecycle servizio | Windows SCM, windows-service | Admin solo per installare | Esecuzione console disponibile; nessuna elevazione automatica | start/stop, readiness, flush |
| Eventi OS reali | EvtQuery, EvtSubscribe pull, EvtNext, EvtRender | Accesso ai singoli canali | Access denied e bookmark scaduti degradano il sensore, senza saltare silenziosamente gli eventi | Event Log locale + fixture parser |
| Ripresa | Bookmark incluso nel record normalizzato | Nessuno aggiuntivo | Avanza soltanto con il commit atomico di evento e XML | riavvio e confronto record ID |
| API del servizio | Named pipe locale con DACL esplicita | SID lettore scelto all'installazione | Solo query; nessun comando di enforcement | autenticazione server con PID da SCM |

L'installazione usa l'account virtuale `NT SERVICE\piko`, directory protette e
un SID lettore esplicito. I diritti Event Log Readers sono assegnati al servizio
per leggere i canali consentiti; non viene modificata la policy di audit Windows.
L'accesso ai dati via pipe è autorizzato da Windows al momento dell'apertura.
Il lettore può delegare un handle o condividere i risultati: l'API è di sola
lettura e non promette isolamento fra programmi dello stesso utente.

Il client apre la pipe con diritti dati specifici, evitando GENERIC_WRITE che
include FILE_CREATE_PIPE_INSTANCE. Prima di trasmettere la richiesta verifica
che il PID server corrisponda al servizio `piko` in esecuzione nel SCM.
In caso di servizio installato ma fermo/errore di autenticazione, nessun fallback
silenzioso al runtime di sviluppo.

Il parser conserva XML UTF-8 originale reso da Windows, provider, ID, timestamp,
canale e bookmark. Non attribuisce Execution ProcessID al processo responsabile:
può essere soltanto il processo che emette l'evento. Primo avvio: importazione
limitata degli ultimi eventi, poi subscription; ripresa: bookmark dell'ultimo
record durabile. Limiti di dimensione, code bounded e backpressure espliciti.

Dati personali: i canali possono contenere nomi account, percorsi e metadati
host. Tutto rimane locale; nessun upload. La raccolta non equivale a detection
comportamentale né prevenzione. ETW resta una sorgente distinta da implementare.

Audit addendum: KEEP event-schema/storage/IPC/UI; REFACTOR fabric per conservare
raw, storage worker per commit e ripresa; ADD safe normalizer e boundary native.
Nessuna migrazione Rust→C/C++; nessuna nuova dipendenza graph/kernel.

Fonti: [EvtQuery](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery),
[EvtSubscribe](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe),
[EvtRender](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender),
[SCM](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

