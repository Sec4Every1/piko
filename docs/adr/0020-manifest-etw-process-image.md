# ADR 0020 — ETW processi e immagini

Data: 2026-10-12. Decisione: KEEP safe Rust per orchestrazione/normalizzazione;
FFI Windows confinata in `win-platform/etw.rs`. Audit e gate linguistico letti:
`COMPONENT_AUDIT.md`, `LANGUAGE_DECISIONS.md`. I binding ETW/TDH gia disponibili
non mostrano una ragione concreta per introdurre C, un driver o una migrazione.

## Comportamento

Una sessione realtime con nome `Piko.ProcessImage.<PID>.<UUID>` abilita soltanto
il provider manifest Microsoft-Windows-Kernel-Process, keyword PROCESS/IMAGE e
filtro event-ID 1, 2, 5, 6. Nessun NT Kernel Logger, stack sampling, log ETL,
modifica audit, aggiustamento privilegi o adesione a gruppi. Una sessione
precedente o di un altro programma non viene arrestata o riutilizzata.

Piko pubblica `degraded` con la causa: il sensore e implementato, ma la raccolta
realtime non e disponibile con questo token e non e stata qualificata. Le
fotografie processi/TCP rimangono una sorgente distinta.

## Ownership e limiti

- Controller StartTrace posseduto; GUID verificato prima di statistiche/stop.
  Il controller si arresta con ControlTrace, il consumer con CloseTrace.
- Un thread dedicato possiede OpenTrace/ProcessTrace e Box<Context>. Il contesto
  resta vivo fino al ritorno di ProcessTrace, anche dopo CloseTrace pending.
  Callback con catch_unwind: nessun panic attraversa Windows; nessun puntatore
  esce dal boundary. Eventi/extended data vengono copiati durante la callback.
- Buffer ETW 64 KiB, min 2/max 8, NO_PER_PROCESSOR_BUFFERING; massimo configurato
  512 KiB indipendente dalla CPU. Nessun logfile. Queue native 32 e forwarding 256 (aggiornamento 14 ottobre; fino a 16 MiB raw).
- Raw payload+extended data massimo 64 KiB/evento, 32 extended items. TDH metadata
  massimo 256 KiB, 128 proprieta top-level; campi massimo 8 KiB, testo 4096 byte.
- Consumer non bloccato dallo storage: le code piene incrementano contatori.
  Health distingue drop nativi, forwarding, eventi/buffer persi da ETW, record
  malformati, errori TDH e consumer terminato. Niente bookmark/replay/pre-start.
- Stop richiede flag, Stop/Close e attesa worker applicativa fino a 6 secondi;
  nessun join infinito o liberazione precoce del contesto. Chiamate OS lente,
  crash/orphan e stress/unload reali richiedono ancora qualificazione dedicata.

## Identita e raw

TDH legge metadata manifest installati e campi nominati con tipo/scalarita
verificati, anziche offset fissi. ProcessID del payload e separato dal PID header
del produttore. PID+FILETIME completa+host producono la stessa identita delle
fotografie; senza CreateTime valida l'istanza resta sconosciuta. Il PPID non
riceve identita parent o un arco causale. Nessun SID, logon LUID o attore viene
presunto. ImageLoad/Unload nominano l'immagine target, non l'eseguibile attore.
ANSI ImageName (ProcessStop) mostrato solo se ASCII, poiche manca una codepage
sorgente. Byte originali restano nel raw JSON hex, che e una copia dei campi
native selezionati/payload/extended data e **non un file ETL**. FILETIME e keyword
conservati come stringhe per precisione; errore schema lascia il raw senza
attribuzione. Gli eventi hanno severita informativa, senza verdetto malware.

## Verifica effettiva

Sei test platform e tre test safe sensor passati. TDH nativo decodifica fixture
con il manifest Windows realmente installato: ProcessStart v0/v4, ProcessStop
v2, ImageLoad/Unload v0; queue callback satura con perdita contata e raw
preservato; rejection di stringhe, puntatori/count e size fuori limite;
normalizzazione immagini, header-PID, PID reuse sub-millisecondo e health.
Probe realtime esplicita: negata al token corrente (5), nessun privilegio
modificato. **Replay/compilazione non dimostrano acquisizione elevata, stress,
copertura senza perdita o lifecycle reali su una VM di qualificazione.**

## Fonti primarie

- [StartTrace: permessi e scoping](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew)
- [EnableTraceEx2](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)
- [ProcessTrace: lifetime e timestamp](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace)
- [CloseTrace: chiusura pending](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace)
- [TdhGetProperty](https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgetproperty)

Il decoder dipende dai manifest e dalle autorizzazioni ETW disponibili sulla versione Windows. La raccolta e la copertura sotto carico devono essere qualificate su ogni configurazione supportata.


