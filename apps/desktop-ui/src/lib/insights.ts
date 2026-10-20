import type { Alert, AlertAssessment } from './api';
import type { Language } from './i18n';

export interface AttackReference {
  id: string;
  name: string;
  tactics: string[];
  url: string;
}

export interface AlertInsight {
  title: string;
  observed: string;
  why: string;
  expected: string;
  nextSteps: string[];
  mappingContext: string;
  attack: AttackReference | null;
  evidenceFields: string;
}

/** A reviewed presentation mapping, not an additional detector or an attack verdict.
 * The current official ATT&CK pages were checked on 2026-10-07. Older IDs
 * T1070.001 / T1562.002 must not be presented as the current catalog entries.
 * Match the backend rule version exactly; a future rule may have different semantics.
 */
export const ATTACK_REVIEWED_AT = '2026-10-13';
export const ATTACK_SOURCES = {
  cleared: 'https://attack.mitre.org/techniques/T1685/005/',
  audit: 'https://attack.mitre.org/techniques/T1685/001/',
  service: 'https://attack.mitre.org/techniques/T1543/003/',
} as const;

const copy: Record<Language, Record<string, AlertInsight>> = {
  it: {
    'audit-log-cleared': {
      title: 'La cronologia di sicurezza di Windows è stata cancellata',
      observed: 'Windows ha registrato lo svuotamento del registro Security, che conserva tracce di accessi e altre attività di sicurezza.',
      why: 'Le registrazioni precedenti possono non essere più disponibili in Windows. Questo rende più difficile ricostruire ciò che è successo.',
      expected: 'Un amministratore può aver eseguito una pulizia autorizzata. Questo evento, da solo, non prova un attacco.',
      nextSteps: [
        'Verifica se tu o chi gestisce il PC avete eseguito manutenzione all’ora indicata.',
        'Apri l’evidenza per identificare l’account che ha cancellato il registro. Conserva l’evento dalla sezione Log tecnici prima di fare modifiche.',
        'Se la cancellazione non era prevista, chiedi a chi gestisce il PC di controllare gli accessi vicini a quell’ora e gli eventuali archivi dei log. piko non recupera le registrazioni Windows già cancellate.',
      ],
      mappingContext: 'Il comportamento osservato è una cancellazione del log. ATT&CK descrive come la stessa operazione può essere usata per nascondere tracce: l’intento resta da verificare.',
      attack: { id: 'T1685.005', name: 'Cancellazione dei log Windows', tactics: ['Indebolimento delle difese'], url: ATTACK_SOURCES.cleared },
      evidenceFields: 'Nell’XML cerca SubjectUserName e SubjectDomainName per l’account indicato da Windows.',
    },
    'event-log-cleared': {
      title: 'Un registro di Windows è stato svuotato',
      observed: 'Windows ha registrato la cancellazione del contenuto di un registro eventi. Il registro interessato è indicato nell’evidenza originale.',
      why: 'Una parte della cronologia del PC potrebbe non essere più consultabile nel registro di origine.',
      expected: 'Può trattarsi di manutenzione o pulizia dei log. La cancellazione non dimostra da sola un comportamento ostile.',
      nextSteps: [
        'Controlla se l’orario coincide con una manutenzione o con un intervento che riconosci.',
        'Apri l’evidenza per leggere quale registro è stato cancellato e l’account riportato, se presente. Conserva l’evento dalla sezione Log tecnici.',
        'Se non riconosci l’operazione, chiedi a chi gestisce il PC di esaminare le attività vicine a quell’ora e verificare l’esistenza di copie dei log. piko non ricrea i log Windows cancellati.',
      ],
      mappingContext: 'La cancellazione osservata è compatibile con il comportamento descritto da ATT&CK. Non sappiamo se servisse a nascondere tracce o a una manutenzione legittima.',
      attack: { id: 'T1685.005', name: 'Cancellazione dei log Windows', tactics: ['Indebolimento delle difese'], url: ATTACK_SOURCES.cleared },
      evidenceFields: 'Nell’XML cerca Channel per il registro e SubjectUserName per l’account, se presenti.',
    },
    'audit-policy-changed': {
      title: 'È cambiato ciò che Windows registra sulla sicurezza',
      observed: 'È stata modificata una regola di audit: una delle impostazioni che decidono quali attività Windows annota nel registro di sicurezza.',
      why: 'Se la modifica riduce le registrazioni, alcune attività potrebbero diventare meno visibili. L’evento può anche indicare un aumento delle registrazioni.',
      expected: 'Aggiornamenti e amministratori possono cambiare queste impostazioni legittimamente. piko non ha stabilito che l’audit sia stato disattivato.',
      nextSteps: [
        'Verifica se chi gestisce il PC ha cambiato le impostazioni di sicurezza all’ora indicata.',
        'Apri l’evidenza e fai confrontare le categorie modificate con la configurazione prevista. Controlla se sono state aggiunte o rimosse registrazioni.',
        'Solo se la modifica non è autorizzata, fai ripristinare all’amministratore la configurazione di audit approvata. piko non applica automaticamente questa correzione.',
      ],
      mappingContext: 'Collegamento potenziale: questa tecnica ATT&CK è pertinente se la modifica serve a ridurre o manomettere i log. Una semplice variazione della policy non basta a confermarla.',
      attack: { id: 'T1685.001', name: 'Disattivazione o modifica dei log Windows', tactics: ['Indebolimento delle difese'], url: ATTACK_SOURCES.audit },
      evidenceFields: 'Nell’XML cerca SubjectUserName, CategoryId, SubcategoryGuid e AuditPolicyChanges. I valori possono richiedere l’interpretazione di un amministratore.',
    },
    'service-installed': {
      title: 'Servizio installato · nome non disponibile',
      observed: 'È stato installato un servizio: un componente che può lavorare in background anche senza una finestra aperta.',
      why: 'I servizi possono avviarsi insieme a Windows e usare account con privilegi elevati, a seconda della configurazione.',
      expected: 'Installazioni e aggiornamenti di programmi aggiungono spesso servizi. L’evento non indica, da solo, un programma dannoso.',
      nextSteps: [
        'Confronta l’orario con le installazioni o gli aggiornamenti che riconosci.',
        'Apri l’evidenza per leggere nome del servizio, percorso del programma, tipo di avvio e account. Chiedi a chi gestisce il PC di verificare editore e firma del file se non li riconosci.',
        'Se il programma risulta indesiderato, usa la sua procedura di disinstallazione o chiedi assistenza. Non eliminare un servizio di sistema sulla base di questa sola segnalazione; la quarantena di piko non arresta i servizi in esecuzione.',
      ],
      mappingContext: 'Collegamento potenziale: ATT&CK descrive l’abuso dei servizi per restare attivi sul PC o ottenere più privilegi. Qui è osservata solo l’installazione, non l’abuso.',
      attack: { id: 'T1543.003', name: 'Servizio Windows', tactics: ['Persistenza', 'Aumento dei privilegi'], url: ATTACK_SOURCES.service },
      evidenceFields: 'Nell’XML cerca ServiceName, ImagePath, StartType e AccountName.',
    },
  },
  en: {
    'audit-log-cleared': {
      title: 'Windows security history was cleared',
      observed: 'Windows recorded the clearing of the Security log, which keeps records of sign-ins and other security activity.',
      why: 'Earlier records may no longer be available in Windows, making it harder to reconstruct what happened.',
      expected: 'An administrator may have performed authorized maintenance. This event alone does not prove an attack.',
      nextSteps: [
        'Check whether you or the person managing this PC performed maintenance at the recorded time.',
        'Open the evidence to identify the account that cleared the log. Preserve the event from Technical logs before making changes.',
        'If the clearing was unexpected, ask the person managing this PC to review nearby sign-ins and any archived logs. piko cannot recover Windows records that were already cleared.',
      ],
      mappingContext: 'The observed behavior is log clearing. ATT&CK describes how the same operation can hide evidence; its intent still needs investigation.',
      attack: { id: 'T1685.005', name: 'Clear Windows Event Logs', tactics: ['Defense Impairment'], url: ATTACK_SOURCES.cleared },
      evidenceFields: 'In the XML, look for SubjectUserName and SubjectDomainName for the account reported by Windows.',
    },
    'event-log-cleared': {
      title: 'A Windows log was emptied',
      observed: 'Windows recorded the clearing of an event log. The original evidence identifies the affected log.',
      why: 'Part of this PC’s history may no longer be available in the original log.',
      expected: 'This can happen during maintenance or log cleanup. Clearing alone does not demonstrate hostile behavior.',
      nextSteps: [
        'Check whether the recorded time matches maintenance or another change you recognize.',
        'Open the evidence to see which log was cleared and the account, if reported. Preserve the event from Technical logs.',
        'If the operation is unfamiliar, ask the person managing this PC to examine nearby activity and look for archived logs. piko cannot recreate cleared Windows logs.',
      ],
      mappingContext: 'The observed clearing is consistent with the behavior described by ATT&CK. Its purpose may be hiding evidence or legitimate maintenance; this event does not establish which.',
      attack: { id: 'T1685.005', name: 'Clear Windows Event Logs', tactics: ['Defense Impairment'], url: ATTACK_SOURCES.cleared },
      evidenceFields: 'In the XML, look for Channel for the affected log and SubjectUserName for the account, when present.',
    },
    'audit-policy-changed': {
      title: 'What Windows records about security has changed',
      observed: 'An audit policy was changed: one of the settings that decide which activities Windows records in its security log.',
      why: 'If the change reduces logging, some activity may become less visible. The event can also represent an increase in logging.',
      expected: 'Updates and administrators can legitimately change these settings. piko has not established that auditing was disabled.',
      nextSteps: [
        'Check whether the person managing this PC changed security settings at the recorded time.',
        'Open the evidence and have the changed categories compared with the expected configuration. Check whether logging was added or removed.',
        'Only if the change was unauthorized, ask an administrator to restore the approved audit configuration. piko does not apply this correction automatically.',
      ],
      mappingContext: 'Potential connection: this ATT&CK technique applies if the change reduces or tampers with logs. A policy change by itself does not confirm it.',
      attack: { id: 'T1685.001', name: 'Disable or Modify Windows Event Log', tactics: ['Defense Impairment'], url: ATTACK_SOURCES.audit },
      evidenceFields: 'In the XML, look for SubjectUserName, CategoryId, SubcategoryGuid and AuditPolicyChanges. An administrator may need to interpret these values.',
    },
    'service-installed': {
      title: 'Service installed · name unavailable',
      observed: 'A service was installed: a component that can run in the background without an open window.',
      why: 'Services can start with Windows and run under privileged accounts, depending on their configuration.',
      expected: 'Program installations and updates often add services. This event alone does not mean the program is malicious.',
      nextSteps: [
        'Compare the recorded time with installations or updates you recognize.',
        'Open the evidence to read the service name, program path, startup type and account. Ask the person managing this PC to check the file’s publisher and signature if they are unfamiliar.',
        'If the program is confirmed to be unwanted, use its uninstall procedure or ask for help. Do not delete a system service based on this alert alone; piko quarantine does not stop running services.',
      ],
      mappingContext: 'Potential connection: ATT&CK describes abusing services to remain active on a PC or obtain higher privileges. Only installation is observed here, not abuse.',
      attack: { id: 'T1543.003', name: 'Windows Service', tactics: ['Persistence', 'Privilege Escalation'], url: ATTACK_SOURCES.service },
      evidenceFields: 'In the XML, look for ServiceName, ImagePath, StartType and AccountName.',
    },
  },
};

copy.it["account-created"] = {"title":"Account creato","observed":"Windows ha registrato la creazione di un account.","why":"Un account può concedere nuovi accessi; la creazione può essere autorizzata.","expected":"Confronta l’evento con le attività autorizzate e verifica lo stato attuale prima di intervenire.","nextSteps":["Controlla l’account e chi lo ha creato; confronta con le richieste approvate. Se non autorizzato, chiedi all’amministratore di disabilitarlo dopo aver verificato le dipendenze."],"mappingContext":"Collegamento di contesto: l’evento osservato non prova l’intento ostile descritto da ATT&CK.","attack":{"id":"T1136","name":"Creazione account","tactics":["Persistenza"],"url":"https://attack.mitre.org/techniques/T1136/"},"evidenceFields":"Apri l’XML per i dati originali; campi mancanti e processo autore non vengono dedotti."};
copy.en["account-created"] = {"title":"Account created","observed":"Windows recorded an account being created.","why":"An account can provide new access; creation may be authorized.","expected":"Compare the event with authorized activities and verify current status before taking action.","nextSteps":["Check the account and its creator against approved requests. If unauthorized, ask the administrator to disable it after checking dependencies."],"mappingContext":"Context mapping: the observed event does not prove the hostile intent described by ATT&CK.","attack":{"id":"T1136","name":"Create Account","tactics":["Persistence"],"url":"https://attack.mitre.org/techniques/T1136/"},"evidenceFields":"Open XML for original fields; missing data and actor processes are not inferred."};
copy.it["group-member-added"] = {"title":"Membro aggiunto a un gruppo","observed":"Windows ha registrato una nuova appartenenza a un gruppo locale.","why":"I permessi dipendono dal gruppo; non è automaticamente un’aggiunta agli amministratori.","expected":"Confronta l’evento con le attività autorizzate e verifica lo stato attuale prima di intervenire.","nextSteps":["Controlla gruppo, SID del membro e autorizzazione. Chiedi all’amministratore di rimuovere soltanto l’appartenenza non autorizzata, preservando gli accessi necessari."],"mappingContext":"Collegamento di contesto: l’evento osservato non prova l’intento ostile descritto da ATT&CK.","attack":{"id":"T1098","name":"Modifica account","tactics":["Persistenza"],"url":"https://attack.mitre.org/techniques/T1098/"},"evidenceFields":"Apri l’XML per i dati originali; campi mancanti e processo autore non vengono dedotti."};
copy.en["group-member-added"] = {"title":"Member added to a group","observed":"Windows recorded a new local group membership.","why":"Permissions depend on the group; this is not automatically administrator membership.","expected":"Compare the event with authorized activities and verify current status before taking action.","nextSteps":["Check the group, member SID and authorization. Ask the administrator to remove only unauthorized membership while preserving necessary access."],"mappingContext":"Context mapping: the observed event does not prove the hostile intent described by ATT&CK.","attack":{"id":"T1098","name":"Account Manipulation","tactics":["Persistence"],"url":"https://attack.mitre.org/techniques/T1098/"},"evidenceFields":"Open XML for original fields; missing data and actor processes are not inferred."};
copy.it["scheduled-task-created"] = {"title":"Attività pianificata creata","observed":"Windows ha registrato una nuova attività che può eseguire operazioni a un orario o al verificarsi di condizioni.","why":"Installazioni e aggiornamenti usano spesso attività pianificate; il record non dimostra che il comando sia già stato eseguito.","expected":"Confronta l’evento con le attività autorizzate e verifica lo stato attuale prima di intervenire.","nextSteps":["Apri Utilità di pianificazione e controlla nome, azioni, account e trigger. Se non autorizzata, chiedi di disabilitarla dopo aver salvato l’evidenza. Non eseguire il comando per provarlo."],"mappingContext":"Collegamento di contesto: l’evento osservato non prova l’intento ostile descritto da ATT&CK.","attack":{"id":"T1053.005","name":"Attività pianificata Windows","tactics":["Persistenza"],"url":"https://attack.mitre.org/techniques/T1053/005/"},"evidenceFields":"Apri l’XML per i dati originali; campi mancanti e processo autore non vengono dedotti."};
copy.en["scheduled-task-created"] = {"title":"Scheduled task created","observed":"Windows recorded a new task that can run on a schedule or trigger.","why":"Installers and updates often use scheduled tasks; the record does not prove the command ran.","expected":"Compare the event with authorized activities and verify current status before taking action.","nextSteps":["Open Task Scheduler and check name, actions, account and triggers. If unauthorized, ask to disable it after saving evidence. Do not run the command to test it."],"mappingContext":"Context mapping: the observed event does not prove the hostile intent described by ATT&CK.","attack":{"id":"T1053.005","name":"Windows Scheduled Task","tactics":["Persistence"],"url":"https://attack.mitre.org/techniques/T1053/005/"},"evidenceFields":"Open XML for original fields; missing data and actor processes are not inferred."};
copy.it["scheduled-task-updated"] = {"title":"Attività pianificata modificata","observed":"Windows ha registrato una modifica a un’attività pianificata.","why":"La modifica può essere manutenzione; non prova esecuzione o persistenza ostile.","expected":"Confronta l’evento con le attività autorizzate e verifica lo stato attuale prima di intervenire.","nextSteps":["Confronta nome e nuova definizione XML con la configurazione approvata. Chiedi all’amministratore di ripristinare le sole modifiche non autorizzate."],"mappingContext":"Collegamento di contesto: l’evento osservato non prova l’intento ostile descritto da ATT&CK.","attack":{"id":"T1053.005","name":"Attività pianificata Windows","tactics":["Persistenza"],"url":"https://attack.mitre.org/techniques/T1053/005/"},"evidenceFields":"Apri l’XML per i dati originali; campi mancanti e processo autore non vengono dedotti."};
copy.en["scheduled-task-updated"] = {"title":"Scheduled task updated","observed":"Windows recorded a scheduled task change.","why":"The change may be maintenance; it does not prove execution or hostile persistence.","expected":"Compare the event with authorized activities and verify current status before taking action.","nextSteps":["Compare the task name and new XML definition with approved configuration. Ask the administrator to revert only unauthorized changes."],"mappingContext":"Context mapping: the observed event does not prove the hostile intent described by ATT&CK.","attack":{"id":"T1053.005","name":"Windows Scheduled Task","tactics":["Persistence"],"url":"https://attack.mitre.org/techniques/T1053/005/"},"evidenceFields":"Open XML for original fields; missing data and actor processes are not inferred."};
copy.it["defender-realtime-disabled"] = {"title":"Defender: protezione in tempo reale disattivata","observed":"Microsoft Defender ha registrato la disattivazione della protezione in tempo reale all’ora indicata.","why":"È un evento storico: la protezione potrebbe essere stata riattivata o sostituita da un antivirus approvato.","expected":"Confronta l’evento con le attività autorizzate e verifica lo stato attuale prima di intervenire.","nextSteps":["Apri Sicurezza di Windows → Protezione da virus e minacce. Verifica lo stato attuale e l’antivirus previsto; se la disattivazione non è autorizzata, chiedi di ripristinare la protezione e avviare una scansione."],"mappingContext":"Collegamento di contesto: l’evento osservato non prova l’intento ostile descritto da ATT&CK.","attack":{"id":"T1685","name":"Disattivazione o modifica delle difese","tactics":["Indebolimento delle difese"],"url":"https://attack.mitre.org/techniques/T1685/"},"evidenceFields":"Apri l’XML per i dati originali; campi mancanti e processo autore non vengono dedotti."};
copy.en["defender-realtime-disabled"] = {"title":"Defender: real-time protection disabled","observed":"Microsoft Defender recorded real-time protection being disabled at the indicated time.","why":"This is historical: protection may have been re-enabled or replaced by an approved antivirus.","expected":"Compare the event with authorized activities and verify current status before taking action.","nextSteps":["Open Windows Security → Virus & threat protection. Check current status and the expected antivirus; if unauthorized, ask to restore protection and run a scan."],"mappingContext":"Context mapping: the observed event does not prove the hostile intent described by ATT&CK.","attack":{"id":"T1685","name":"Disable or Modify Tools","tactics":["Defense Impairment"],"url":"https://attack.mitre.org/techniques/T1685/"},"evidenceFields":"Open XML for original fields; missing data and actor processes are not inferred."};
copy.it["defender-config-changed"] = {"title":"Defender: configurazione modificata","observed":"Microsoft Defender ha registrato un cambio di configurazione.","why":"Può dipendere da aggiornamenti o amministrazione. Non significa che le difese siano state disattivate.","expected":"Confronta l’evento con le attività autorizzate e verifica lo stato attuale prima di intervenire.","nextSteps":["Confronta valore precedente e nuovo con le impostazioni approvate. Fai verificare eventuali esclusioni indesiderate prima di rimuoverle."],"mappingContext":"Collegamento di contesto: l’evento osservato non prova l’intento ostile descritto da ATT&CK.","attack":{"id":"T1685","name":"Disattivazione o modifica delle difese","tactics":["Indebolimento delle difese"],"url":"https://attack.mitre.org/techniques/T1685/"},"evidenceFields":"Apri l’XML per i dati originali; campi mancanti e processo autore non vengono dedotti."};
copy.en["defender-config-changed"] = {"title":"Defender: configuration changed","observed":"Microsoft Defender recorded a configuration change.","why":"It may result from updates or administration. It does not mean defenses were disabled.","expected":"Compare the event with authorized activities and verify current status before taking action.","nextSteps":["Compare old and new values against approved settings. Have unwanted exclusions reviewed before removing them."],"mappingContext":"Context mapping: the observed event does not prove the hostile intent described by ATT&CK.","attack":{"id":"T1685","name":"Disable or Modify Tools","tactics":["Defense Impairment"],"url":"https://attack.mitre.org/techniques/T1685/"},"evidenceFields":"Open XML for original fields; missing data and actor processes are not inferred."};
copy.it["defender-threat-reported"] = {"title":"Defender ha segnalato una minaccia","observed":"La rilevazione proviene da Microsoft Defender, non da una scansione di piko.","why":"La rilevazione può riguardare malware o software potenzialmente indesiderato. Lo stato attuale richiede verifica.","expected":"Confronta l’evento con le attività autorizzate e verifica lo stato attuale prima di intervenire.","nextSteps":["Apri Cronologia protezione in Sicurezza di Windows e controlla nome, risorsa e stato. Segui le azioni raccomandate da Defender; se resta attiva, chiedi assistenza prima di consentire il file."],"mappingContext":"La sola rilevazione antivirus non identifica una tecnica ATT&CK specifica.","attack":null,"evidenceFields":"Apri l’XML per i dati originali; campi mancanti e processo autore non vengono dedotti."};
copy.en["defender-threat-reported"] = {"title":"Defender reported a threat","observed":"The detection comes from Microsoft Defender rather than a piko scan.","why":"The detection may involve malware or potentially unwanted software. Current status needs verification.","expected":"Compare the event with authorized activities and verify current status before taking action.","nextSteps":["Open Protection history in Windows Security and check name, resource and status. Follow Defender guidance; if still active, seek assistance before allowing the file."],"mappingContext":"An antivirus report alone does not identify a specific ATT&CK technique.","attack":null,"evidenceFields":"Open XML for original fields; missing data and actor processes are not inferred."};
copy.it["defender-action-reported"] = {"title":"Defender ha registrato un’azione","observed":"Microsoft Defender ha registrato un’azione su una rilevazione.","why":"L’azione può anche essere Consenti. Non conferma automaticamente rimozione o quarantena riuscita.","expected":"Confronta l’evento con le attività autorizzate e verifica lo stato attuale prima di intervenire.","nextSteps":["Controlla il tipo di azione, eventuali errori e lo stato attuale in Cronologia protezione. Se il file è stato consentito senza autorizzazione, chiedi una nuova valutazione."],"mappingContext":"La sola rilevazione antivirus non identifica una tecnica ATT&CK specifica.","attack":null,"evidenceFields":"Apri l’XML per i dati originali; campi mancanti e processo autore non vengono dedotti."};
copy.en["defender-action-reported"] = {"title":"Defender recorded an action","observed":"Microsoft Defender recorded an action for a detection.","why":"The action can also be Allow. It does not automatically confirm successful removal or quarantine.","expected":"Compare the event with authorized activities and verify current status before taking action.","nextSteps":["Check action type, errors and current status in Protection history. If the file was allowed without authorization, request reassessment."],"mappingContext":"An antivirus report alone does not identify a specific ATT&CK technique.","attack":null,"evidenceFields":"Open XML for original fields; missing data and actor processes are not inferred."};

copy.it['failed-logon-burst'] = {"title":"Accessi falliti ripetuti","observed":"Windows ha registrato errori di credenziali ripetuti per lo stesso account, indirizzo e tipo di accesso.","why":"Può essere un tentativo di indovinare la password, oppure un’app o servizio con credenziali salvate non aggiornate. L’IP non identifica una persona.","expected":"Controlla gli accessi previsti e le credenziali dei servizi prima di intervenire.","nextSteps":["Verifica account, origine e orario. Controlla password salvate, attività pianificate e servizi; se la fonte è inattesa, chiedi all’amministratore di limitare l’accesso remoto e aggiornare le credenziali. Non bloccare l’account alla cieca."],"mappingContext":"Compatibile con tentativi di forza bruta; non dimostra un attacco né distingue le varianti ATT&CK.","attack":{"id":"T1110","name":"Forza bruta","tactics":["Accesso alle credenziali"],"url":"https://attack.mitre.org/techniques/T1110/"},"evidenceFields":"Sono disponibili i riferimenti a tutti i record correlati. Non rappresentano una catena causale."};
copy.en['failed-logon-burst'] = {"title":"Repeated failed logons","observed":"Windows recorded repeated bad credentials for the same account, address and logon type.","why":"This may be password guessing or an app or service using outdated saved credentials. The IP does not identify a person.","expected":"Check expected logons and service credentials before intervening.","nextSteps":["Check account, source and time. Review saved passwords, scheduled tasks and services; if unexpected, ask the administrator to restrict remote access and update credentials. Do not blindly lock the account."],"mappingContext":"Consistent with brute-force attempts; does not establish an attack or identify an ATT&CK subtechnique.","attack":{"id":"T1110","name":"Brute Force","tactics":["Credential Access"],"url":"https://attack.mitre.org/techniques/T1110/"},"evidenceFields":"References to all correlated records are available. They do not form a causal chain."};

export function interpretAlert(alert: Alert, language: Language): AlertInsight {
  const definitions = copy[language];
  if (alert.rule_version === 1 && Object.hasOwn(definitions, alert.rule_id)) {
    return namedInsight(definitions[alert.rule_id], alert, language);
  }
  const it = language === 'it';
  return {
    title: alert.title,
    observed: alert.explanation,
    why: it ? 'Questa regola non ha ancora una spiegazione guidata verificata in questa versione dell’interfaccia.' : 'This rule does not yet have a reviewed guided explanation in this interface version.',
    expected: it ? 'La segnalazione va esaminata nel suo contesto; non è un verdetto automatico.' : 'Review this alert in context; it is not an automatic verdict.',
    nextSteps: [it ? 'Apri l’evidenza e chiedi a chi gestisce il PC di verificare l’evento prima di intervenire.' : 'Open the evidence and ask the person managing this PC to review the event before taking action.'],
    mappingContext: it ? 'Nessuna associazione ATT&CK verificata per questa regola e versione.' : 'No reviewed ATT&CK association for this rule and version.',
    attack: null,
    evidenceFields: it ? 'Le informazioni originali restano disponibili nell’evidenza, se raccolta.' : 'Original information remains available in the evidence, if collected.',
  };
}

/** Unknown rule/model versions retain their raw explanation; no new score or attribution is inferred. */
export function supportedAssessment(alert: Alert): AlertAssessment | null {
  return alert.rule_version === 1 && Object.hasOwn(copy.it, alert.rule_id)
    && alert.assessment?.model_version === 'piko-risk-v1' ? alert.assessment : null;
}

function namedInsight(definition: AlertInsight, alert: Alert, language: Language): AlertInsight {
  const it = language === 'it';
  const context = supportedAssessment(alert)?.context;
  const verified = context?.evidence_status === 'verified' ? context : null;
  const account = verified?.subject_user
    ? [verified.subject_domain, verified.subject_user].filter(Boolean).join('\\') : null;
  if (alert.rule_id === 'failed-logon-burst' && verified?.failed_logons) {
    const name=[verified.target_domain,verified.target_user].filter(Boolean).join('\\');
    return {...definition,title:definition.title+' · '+name,observed:definition.observed+' '+verified.failed_logons.count+(it?' record nello stesso minuto UTC.':' records in the same UTC minute.')};
  }
  const observedName = verified?.task_name ?? verified?.target_user ?? verified?.group_name ?? verified?.threat_name;
  if (observedName) return { ...definition, title: definition.title + ' · ' + observedName };
  if (alert.rule_id === 'service-installed') {
    const title = verified?.service_name
      ? (it ? `Installato il servizio «${verified.service_name}»` : `Service “${verified.service_name}” installed`)
      : definition.title;
    const program = verified?.image_path
      ? (it ? `Percorso del programma riportato da Windows: ${verified.image_path}.` : `Program path reported by Windows: ${verified.image_path}.`)
      : (it ? 'Il percorso del programma non è disponibile nell’evidenza verificata.' : 'The program path is unavailable in verified evidence.');
    return { ...definition, title, observed: `${definition.observed} ${program}` };
  }
  if (alert.rule_id === 'event-log-cleared' && verified?.log_channel && !account) {
    return { ...definition, title: it ? `Il registro «${verified.log_channel}» è stato svuotato` : `The “${verified.log_channel}” log was emptied` };
  }
  if (!account) return definition;
  const titles: Record<string, string> = it ? {
    'audit-log-cleared': `«${account}» ha cancellato la cronologia di sicurezza Windows`,
    'event-log-cleared': `«${account}» ha svuotato ${verified?.log_channel ? `il registro «${verified.log_channel}»` : 'un registro Windows'}`,
    'audit-policy-changed': `«${account}» ha modificato le registrazioni di sicurezza Windows`,
  } : {
    'audit-log-cleared': `“${account}” cleared Windows security history`,
    'event-log-cleared': `“${account}” emptied ${verified?.log_channel ? `the “${verified.log_channel}” log` : 'a Windows log'}`,
    'audit-policy-changed': `“${account}” changed Windows security logging`,
  };
  return { ...definition, title: titles[alert.rule_id] ?? definition.title };
}

export function assessmentFacts(alert: Alert, language: Language): EvidenceFact[] {
  const context = supportedAssessment(alert)?.context;
  if (context?.evidence_status !== 'verified') return [];
  const it = language === 'it';
  const fields: [string, string | null][] = alert.rule_id === 'service-installed' ? [
    [it ? 'Nome del servizio' : 'Service name', context.service_name],
    [it ? 'Programma del servizio' : 'Service program', context.image_path],
    [it ? 'Account del servizio' : 'Service account', context.service_account],
  ] : alert.rule_id==='failed-logon-burst' ? [
    [it?'Account tentato':'Attempted account',[context.target_domain,context.target_user].filter(Boolean).join('\\')],
    [it?'Indirizzo sorgente riportato':'Reported source address',context.source_ip??null],
    [it?'Tipo di accesso':'Logon type',context.logon_type==='10'?(it?'Desktop remoto (10)':'Remote desktop (10)'):context.logon_type==='3'?(it?'Rete (3)':'Network (3)'):null],
    [it?'Programma chiamante riportato':'Reported caller program',context.caller_path??null],
    [it?'Stato Windows':'Windows status',context.failure_status??null],
    [it?'Dettaglio stato':'Substatus',context.failure_sub_status??null],
  ] : [
    [it ? 'Account riportato da Windows' : 'Account reported by Windows', context.subject_user],
    [it ? 'Dominio o nome del PC' : 'Domain or PC name', context.subject_domain],
    [it ? 'Registro interessato' : 'Affected log', context.log_channel],
    [it ? 'Modifica di audit riportata' : 'Reported audit change', context.audit_changes],
  ];
  fields.push(
    [it ? 'Account creato' : 'Created account', context.target_user ?? null],
    [it ? 'Dominio account' : 'Account domain', context.target_domain ?? null],
    [it ? 'Gruppo' : 'Group', context.group_name ?? null],
    ['SID gruppo', context.group_sid ?? null], ['SID membro', context.member_sid ?? null],
    [it ? 'Attività pianificata' : 'Scheduled task', context.task_name ?? null],
    [it ? 'Nome rilevazione Defender' : 'Defender detection name', context.threat_name ?? null],
    [it ? 'Risorsa riportata' : 'Reported resource', context.resource_path ?? null],
    [it ? 'Azione Defender' : 'Defender action', context.defender_action ?? null],
    [it ? 'Valore precedente' : 'Old value', context.old_value ?? null],
    [it ? 'Valore nuovo' : 'New value', context.new_value ?? null]);
  return fields.filter((field): field is [string, string] => !!field[1]).map(([label, value]) => ({ label, value }));
}

export interface RiskInsight {
  score: number; factors: { label: string; points: number }[]; evidenceNote: string;
}

export function riskInsight(alert: Alert, language: Language): RiskInsight | null {
  const assessment = supportedAssessment(alert);
  if (!assessment) return null;
  const it = language === 'it';
  const factors: Record<string, string> = it ? {
    repeated_bad_credentials: "Almeno cinque errori di credenziali correlati nello stesso minuto",
    account_created: "Account creato",
    group_member_added: "Membro aggiunto a un gruppo",
    scheduled_task_created: "Attività pianificata creata",
    scheduled_task_updated: "Attività pianificata modificata",
    defender_realtime_disabled: "Defender: protezione in tempo reale disattivata",
    defender_config_changed: "Defender: configurazione modificata",
    defender_threat_reported: "Defender ha segnalato una minaccia",
    defender_action_reported: "Defender ha registrato un’azione",
    audit_log_cleared: 'Cancellazione della cronologia di sicurezza',
    event_log_cleared: 'Cancellazione di un registro Windows',
    audit_policy_changed: 'Modifica delle impostazioni di audit',
    service_installed: 'Installazione di un servizio Windows',
    service_untrusted_location: 'Percorso compatibile con una cartella utente o temporanea; autorizzazioni non verificate',
    audit_logging_removed: 'Rimozione di registrazioni di audit riportata da Windows',
    audit_logging_added_only: 'Solo aggiunta di registrazioni di audit',
    evidence_missing: 'Evidenza originale non disponibile',
    evidence_invalid: 'Evidenza non verificabile',
    evidence_version_unsupported: 'Versione dell’evidenza non supportata',
    service_details_missing: 'Dettagli del servizio incompleti: nessun dato mancante viene dedotto',
    audit_change_unknown: 'Non è stato possibile determinare se le registrazioni siano aumentate o diminuite',
  } : {
    account_created: "Account created",
    group_member_added: "Member added to a group",
    scheduled_task_created: "Scheduled task created",
    scheduled_task_updated: "Scheduled task updated",
    defender_realtime_disabled: "Defender: real-time protection disabled",
    defender_config_changed: "Defender: configuration changed",
    defender_threat_reported: "Defender reported a threat",
    defender_action_reported: "Defender recorded an action",
    audit_log_cleared: 'Security history cleared',
    event_log_cleared: 'Windows event log cleared',
    audit_policy_changed: 'Audit settings changed',
    service_installed: 'Windows service installed',
    service_untrusted_location: 'Path resembles a user or temporary folder; permissions not verified',
    audit_logging_removed: 'Removal of audit logging reported by Windows',
    audit_logging_added_only: 'Audit logging was only added',
    evidence_missing: 'Original evidence unavailable',
    evidence_invalid: 'Evidence could not be verified',
    evidence_version_unsupported: 'Unsupported evidence version',
    service_details_missing: 'Incomplete service details: missing values are not inferred',
    audit_change_unknown: 'Could not determine whether logging increased or decreased',
  };
  return {
    score: assessment.risk_score,
    factors: assessment.factors.map(factor => ({
      label: Object.hasOwn(factors, factor.code) ? factors[factor.code] : (it ? `Fattore del modello: ${factor.code}` : `Model factor: ${factor.code}`),
      points: factor.points,
    })),
    evidenceNote: assessment.context.evidence_status === 'verified'
      ? (it ? 'I campi usati sono stati verificati rispetto all’evidenza raccolta. Nomi e percorsi non provano l’identità o l’affidabilità del file.' : 'Used fields were checked against collected evidence. Names and paths do not establish file identity or trustworthiness.')
      : (it ? 'Il contesto originale non è verificabile: l’indice usa il comportamento della regola, senza dedurre i campi mancanti.' : 'Original context cannot be verified: the index uses the rule behavior without inferring missing fields.'),
  };
}

/** This is a summary of a bounded alert sample, never a host safety score. */
export function maximumRisk(alerts: readonly Alert[]): { score: number; assessed: number } | null {
  const scores = alerts.map(supportedAssessment).filter((item): item is AlertAssessment => item !== null);
  return scores.length ? { score: Math.max(...scores.map(item => item.risk_score)), assessed: scores.length } : null;
}

const priority: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function sortAlerts(alerts: readonly Alert[]): Alert[] {
  return [...alerts].sort((left, right) => (priority[right.severity] ?? 0) - (priority[left.severity] ?? 0)
    || (right.event_time ?? right.observed_at) - (left.event_time ?? left.observed_at) || left.id.localeCompare(right.id));
}

export interface EvidenceFact { label: string; value: string }

const eventNamespace = 'http://schemas.microsoft.com/win/2004/08/events/event';
const clearedNamespace = 'http://manifests.microsoft.com/win/2004/08/windows/eventlog';
const eventSources: Record<string, { id: string; channel: string; provider: string }> = {
  'audit-log-cleared': { id: '1102', channel: 'Security', provider: 'Microsoft-Windows-Eventlog' },
  'event-log-cleared': { id: '104', channel: 'System', provider: 'Microsoft-Windows-Eventlog' },
  'audit-policy-changed': { id: '4719', channel: 'Security', provider: 'Microsoft-Windows-Security-Auditing' },
  'service-installed': { id: '7045', channel: 'System', provider: 'Service Control Manager' },
  "account-created": {"id":"4720","channel":"Security","provider":"Microsoft-Windows-Security-Auditing"},
  "group-member-added": {"id":"4732","channel":"Security","provider":"Microsoft-Windows-Security-Auditing"},
  "scheduled-task-created": {"id":"4698","channel":"Security","provider":"Microsoft-Windows-Security-Auditing"},
  "scheduled-task-updated": {"id":"4702","channel":"Security","provider":"Microsoft-Windows-Security-Auditing"},
  "defender-realtime-disabled": {"id":"5001","channel":"Microsoft-Windows-Windows Defender/Operational","provider":"Microsoft-Windows-Windows Defender"},
  "defender-config-changed": {"id":"5007","channel":"Microsoft-Windows-Windows Defender/Operational","provider":"Microsoft-Windows-Windows Defender"},
  "defender-threat-reported": {"id":"1116","channel":"Microsoft-Windows-Windows Defender/Operational","provider":"Microsoft-Windows-Windows Defender"},
  "defender-action-reported": {"id":"1117","channel":"Microsoft-Windows-Windows Defender/Operational","provider":"Microsoft-Windows-Windows Defender"},
};

/** Read-only presentation of explicitly named source fields, never a detector.
 * Do not infer missing accounts, executable identities, audit outcomes or permission levels.
 * Keep the original evidence separate and render every returned value as escaped text.
 */
export function summarizeEvidence(xml: string, alert: Alert, language: Language): EvidenceFact[] {
  if (alert.rule_version !== 1 || !Object.hasOwn(eventSources, alert.rule_id)
    || xml.length > 1024 * 1024 || /<!DOCTYPE/i.test(xml) || typeof DOMParser === 'undefined') return [];
  try {
    const document = new DOMParser().parseFromString(xml, 'application/xml');
    if (document.getElementsByTagName('parsererror').length) return [];
    const root = document.documentElement;
    if (root.localName !== 'Event' || root.namespaceURI !== eventNamespace) return [];
    const child = (parent: Element | null, name: string, namespace = eventNamespace): Element | null => {
      const matches = Array.from(parent?.children ?? []).filter(item => item.localName === name && item.namespaceURI === namespace);
      return matches.length === 1 ? matches[0] : null;
    };
    const value = (element: Element | null): string => {
      if (!element || element.children.length) return '';
      const text = element.textContent?.trim() ?? '';
      return text.length <= 4096 ? text : '';
    };
    const system = child(root, 'System');
    const source = eventSources[alert.rule_id];
    if (value(child(system, 'EventID')) !== source.id || value(child(system, 'Channel')) !== source.channel
      || child(system, 'Provider')?.getAttribute('Name') !== source.provider) return [];
    const fields = new Map<string, string>();
    const duplicates = new Set<string>();
    const eventData = child(root, 'EventData');
    for (const item of Array.from(eventData?.children ?? [])) {
      if (item.localName !== 'Data' || item.namespaceURI !== eventNamespace) continue;
      const name = item.getAttribute('Name');
      if (!name) continue;
      if (fields.has(name)) duplicates.add(name);
      fields.set(name, value(item));
    }
    for (const name of duplicates) fields.delete(name);
    const cleared = child(child(root, 'UserData'), 'LogFileCleared', clearedNamespace);
    const read = (name: string): string => alert.rule_id.endsWith('log-cleared')
      ? value(child(cleared, name, clearedNamespace)) : fields.get(name) ?? '';
    const it = language === 'it';
    const facts: EvidenceFact[] = [];
    const add = (label: string, text: string) => { if (text) facts.push({ label, value: text }); };
    if (alert.rule_id === 'service-installed') {
      add(it ? 'Nome del servizio' : 'Service name', read('ServiceName'));
      add(it ? 'Programma del servizio' : 'Service program', read('ImagePath'));
      add(it ? 'Account del servizio' : 'Service account', read('AccountName'));
      add(it ? 'Tipo di avvio riportato da Windows' : 'Startup type reported by Windows', read('StartType'));
    } else {
      add(it ? 'Account riportato da Windows' : 'Account reported by Windows', read('SubjectUserName'));
      add(it ? 'Dominio o nome del PC dell’account' : 'Account domain or PC name', read('SubjectDomainName'));
      if (alert.rule_id === 'event-log-cleared') add(it ? 'Registro cancellato' : 'Cleared log', read('Channel'));
      if (alert.rule_id === 'audit-policy-changed') {
        add(it ? 'Categoria di audit (valore Windows)' : 'Audit category (Windows value)', read('CategoryId'));
        add(it ? 'Modifica riportata da Windows' : 'Change reported by Windows', read('AuditPolicyChanges'));
      }
    }
    if (eventData && ['account-created','group-member-added','scheduled-task-created','scheduled-task-updated','defender-realtime-disabled','defender-config-changed','defender-threat-reported','defender-action-reported'].includes(alert.rule_id)) {
      for (const [field,itLabel,enLabel] of [['TaskName','Attività pianificata','Scheduled task'],['TargetUserName','Nome account o gruppo','Account or group name'],['MemberSid','SID membro','Member SID'],['Threat Name','Nome rilevazione Defender','Defender detection name'],['Path','Risorsa riportata','Reported resource'],['Action Name','Azione Defender','Defender action'],['Old Value','Valore precedente','Old value'],['New Value','Valore nuovo','New value']]) {
        const nodes = Array.from(eventData.children).filter(n=>n.localName==='Data' && n.namespaceURI === eventNamespace && n.getAttribute('Name')===field); if(nodes.length===1) add(it ? itLabel : enLabel,value(nodes[0]));
      }
    }
    add(it ? 'Computer che ha registrato l’evento' : 'Computer that recorded the event', value(child(system, 'Computer')));
    return facts;
  } catch {
    return [];
  }
}
