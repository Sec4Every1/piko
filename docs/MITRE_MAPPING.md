# Mappature MITRE ATT&CK della dashboard

Verifica delle fonti ufficiali: **12 ottobre 2026**. Le associazioni sono una guida di lettura delle dodici regole realmente implementate, versione 1. Non costituiscono una nuova detection, una correlazione comportamentale né una conferma di attacco. L’interfaccia non assegna una tecnica a regole sconosciute o a versioni non revisionate.

| Regola piko v1 | Osservazione Windows | Riferimento ufficiale | Interpretazione consentita |
|---|---|---|---|
| `audit-log-cleared` | Security, Microsoft-Windows-Eventlog, 1102 | [T1685.005 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/) | Svuotamento osservato; intento da verificare. |
| `event-log-cleared` | System, Microsoft-Windows-Eventlog, 104 | [T1685.005 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/) | Svuotamento osservato; manutenzione e abuso non distinguibili dal solo evento. |
| `audit-policy-changed` | Security, Microsoft-Windows-Security-Auditing, 4719 | [T1685.001 — Disable or Modify Windows Event Log](https://attack.mitre.org/techniques/T1685/001/) | Collegamento potenziale, da verificare se la variazione riduce le registrazioni. Può anche aumentarle. |
| `service-installed` | System, Service Control Manager, 7045 | [T1543.003 — Windows Service](https://attack.mitre.org/techniques/T1543/003/) | Collegamento potenziale: l’installazione di un servizio non ne dimostra l’abuso. |

Le prime due tecniche del catalogo consultato appartengono a **Defense Impairment**; Windows Service appartiene a **Persistence** e **Privilege Escalation**. Le etichette italiane nell’interfaccia sono traduzioni esplicative. I vecchi identificativi T1070.001 e T1562.002 non sono usati come collegamenti correnti.

Ogni scheda distingue ciò che è stato osservato, perché merita attenzione, una possibile spiegazione legittima e i passi manuali suggeriti. Nessuna remediation viene applicata automaticamente. La quarantena resta un’azione separata, limitata ai file consentiti e soggetta a piano e conferma.

## Evidenza leggibile e originale

Il pulsante «Leggi i dettagli dell’evento» richiede al runtime l’evidenza originale tramite il suo riferimento. Il riepilogo espone solo campi nominati e supportati dell’XML, dopo aver verificato radice, namespace, provider, canale e codice evento corrispondenti alla regola. Account, servizio, percorso e computer vengono mostrati come testo, senza inferire firma, affidabilità, privilegi effettivi o identità del processo. I valori mancanti o ambigui non vengono ricostruiti. I codici Windows non tradotti restano valori della fonte e possono richiedere assistenza tecnica.

Lo schema di 1102 usa `UserData/LogFileCleared`; quello di 4719 usa `EventData/Data`. Vedere [Microsoft: evento 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102) e [Microsoft: evento 4719](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719). Per il riepilogo vengono rifiutati DTD, campi duplicati, elementi annidati al posto di valori e XML fuori formato; l’originale rimane consultabile come testo nella sezione tecnica. L’interfaccia non esegue XML né testo proveniente dagli eventi.

I dettagli tecnici sono facoltativi: la spiegazione dell’evento e i passi suggeriti restano leggibili senza conoscere XML o ATT&CK. Gli heartbeat e gli altri record di funzionamento non ricevono queste associazioni.

Le schede mostrano `event_time` dal `wall_clock_time` originale Windows, mentre
`observed_at` conserva il tempo di raccolta. Un record storico importato oggi non
viene presentato come avvenuto oggi. Il campo aggiuntivo è facoltativo per
compatibilità: quando manca, la data è esplicitamente «Raccolto da piko».

## Nuove regole v1

| Regola | Evento | Mappatura condizionale |
|---|---|---|
| account-created | Security 4720 | [T1136](https://attack.mitre.org/techniques/T1136/): nessun sottotipo locale/dominio inferito. |
| group-member-added | Security 4732 | [T1098](https://attack.mitre.org/techniques/T1098/): non dimostra escalation o gruppo amministratori. |
| scheduled-task-created / updated | Security 4698 / 4702 | [T1053.005](https://attack.mitre.org/techniques/T1053/005/): possibile abuso, anche manutenzione legittima. |
| defender-realtime-disabled / config-changed | Defender Operational 5001 / 5007 | [T1685](https://attack.mitre.org/techniques/T1685/): possibile riduzione difese, non intento dimostrato. |
| defender-threat-reported / action-reported | Defender Operational 1116 / 1117 | Nessuna tecnica specifica: un nome antivirus non descrive la tecnica osservata. Azione registrata non prova rimozione riuscita. |

Nomi da XML verificato. Account/task/risorsa non equivalgono a processo autore identificato. UI e score conservano questa distinzione.

Correlazione 4625 v1: failed-logon-burst → [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/), consultato 13 ottobre 2026. Cinque errori di credenziali stesso account/IP/tipo/minuto; mapping di contesto, nessuna variante specifica o attacco confermato. Credenziali salvate non aggiornate possono produrre lo stesso segnale. ADR 0024.
