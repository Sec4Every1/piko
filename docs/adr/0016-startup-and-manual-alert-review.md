# ADR 0016 — Avvio utente e valutazioni manuali

Stato: implementato; qualificazione di login Windows reale pendente.

La UI gestisce una sola voce HKCU Run con comando nativo assoluto e limite Windows di 260 unità UTF-16. Default disattivato, nessun UAC. Un comando estraneo non viene sovrascritto/rimosso. Il bootstrap evita duplicati tramite IPC autenticato, preferisce SCM, conserva console.json e avvia il sibling monitor senza shell o console visibile. Timeout, versione inattesa e errori sono registrati localmente e mostrati in Impostazioni. La configurazione Run non dimostra l’esecuzione: Windows può ritardare o disabilitare la voce. Nessuna resilienza prima del login.

Le annotazioni sono per viewer, separate dalla catena delle evidenze e dall’engine: open/investigating/expected/handled, ID regola:evento, SID nativo, timestamp e nota massimo 1000 byte. SQLite transazionale, 2000 ultime scelte, massimo 16 MiB, input e letture bounded, guardie reparse. Ultimo stato soltanto, non journal immutabile. Nuove occorrenze rimangono aperte. Errori di lettura impediscono di nascondere eventi. Atteso non alimenta automaticamente il modello di rischio.

Validazione: test SQLite reopen/input, parser UI, browser opt-in/disabilitazione e expected/riapertura. Native status letto senza mutare HKCU; nessun logout o cambio account effettuato.

