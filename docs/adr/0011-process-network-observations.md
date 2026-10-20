# ADR 0011 — Osservazioni di processi e rete

Stato: implementazione, 8 ottobre 2026.

ToolHelp, GetProcessTimes, QueryFullProcessImageName e GetExtendedTcpTable
sono confinati nel boundary `win-platform`, in Rust con FFI Windows.
Handle RAII, buffer e tentativi limitati; nessuna modifica a processi, rete o audit.
Il modello serializzabile vive in `common-model`; acquisizione, differenze e
normalizzazione in safe Rust in `win-sensors`, persistenza nel fabric esistente.

Ogni 10 secondi viene acquisita una fotografia, rallentata dalla backpressure.
Non e' ETW e non garantisce di osservare processi o connessioni di breve durata.
Gli eventi sono prima osservazione, cambiamento e assenza dalla fotografia
successiva completa: l'assenza non prova la terminazione del processo.
Le fotografie parziali non generano eventi di scomparsa.
L'identita' di istanza usa host, PID e FILETIME completo a 100 ns, conservato
come stringa decimale nel JSON per evitare arrotondamenti JavaScript.
Una connessione e' associata all'istanza soltanto se i tempi di creazione
prima e dopo la lettura della tabella TCP coincidono. Altrimenti resta anonima.
PPID e' un riferimento osservato: non basta per provare causalita'.

Limiti: 4096 processi, budget JSON conservativo di 1 MiB per processi,
2048 connessioni esposte, tabelle native da massimo 2 MiB con tre tentativi.
Accessi negati, troncamento, ultimo aggiornamento e errori sono espliciti.
Nessun traffico UDP, DNS, TLS o contenuto dei pacchetti viene inferito.
I dati sono locali, letti tramite IPC autenticato; il frontend non acquisisce
telemetria autonomamente. Lo storico conserva l'evidenza JSON originale.

Contratti Microsoft:
- https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
- https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable

Qualificazione richiesta: PID riutilizzati, fotografie incomplete, failure
recovery, nessun falso allarme per connessioni ordinarie, integrazione IPC/UI.
La copertura ETW e il controllo kernel rimangono requisiti separati.

