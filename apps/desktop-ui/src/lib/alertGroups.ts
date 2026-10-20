import type { Alert } from './api';
import type { Language } from './i18n';
import { interpretAlert, maximumRisk, sortAlerts, supportedAssessment } from './insights';

export interface AlertGroup {
  key: string; ruleId: string; version: number; alerts: Alert[]; severity: string;
  latestCollected: number; risk: number | null; assessed: number;
}
/** Groups explain the same rule, not a proven incident or common cause. Versions never mix. */
export function groupAlerts(alerts: readonly Alert[]): AlertGroup[] {
  const groups = new Map<string, AlertGroup>();
  for (const alert of sortAlerts(alerts)) {
    const key = JSON.stringify([alert.rule_id, alert.rule_version]);
    let group = groups.get(key);
    if (!group) {
      group = { key, ruleId: alert.rule_id, version: alert.rule_version, alerts: [], severity: alert.severity, latestCollected: alert.observed_at, risk: null, assessed: 0 };
      groups.set(key, group);
    }
    group.alerts.push(alert);
    group.latestCollected = Math.max(group.latestCollected, alert.observed_at);
  }
  for (const group of groups.values()) {
    const risk = maximumRisk(group.alerts); group.risk = risk?.score ?? null; group.assessed = risk?.assessed ?? 0;
  }
  return [...groups.values()];
}
export function groupTitle(group: AlertGroup, language: Language): string {
  const known: Record<string, string> = language === 'it' ? {
    "failed-logon-burst": "Accessi falliti ripetuti",
    "account-created": "Account creato",
    "group-member-added": "Membro aggiunto a un gruppo",
    "scheduled-task-created": "Attività pianificata creata",
    "scheduled-task-updated": "Attività pianificata modificata",
    "defender-realtime-disabled": "Defender: protezione in tempo reale disattivata",
    "defender-config-changed": "Defender: configurazione modificata",
    "defender-threat-reported": "Defender ha segnalato una minaccia",
    "defender-action-reported": "Defender ha registrato un’azione",
    'service-installed': 'Servizi installati', 'audit-log-cleared': 'Cronologia di sicurezza cancellata',
    'event-log-cleared': 'Registri Windows svuotati', 'audit-policy-changed': 'Impostazioni di audit modificate',
  } : {
    "failed-logon-burst": "Repeated failed logons",
    "account-created": "Account created",
    "group-member-added": "Member added to a group",
    "scheduled-task-created": "Scheduled task created",
    "scheduled-task-updated": "Scheduled task updated",
    "defender-realtime-disabled": "Defender: real-time protection disabled",
    "defender-config-changed": "Defender: configuration changed",
    "defender-threat-reported": "Defender reported a threat",
    "defender-action-reported": "Defender recorded an action",
    'service-installed': 'Services installed', 'audit-log-cleared': 'Security history cleared',
    'event-log-cleared': 'Windows logs emptied', 'audit-policy-changed': 'Audit settings changed',
  };
  return group.version === 1 && Object.hasOwn(known, group.ruleId) ? known[group.ruleId] : interpretAlert(group.alerts[0], language).title;
}
export function groupSubjects(group: AlertGroup, language: Language): string {
  const subjects = new Set<string>();
  for (const alert of group.alerts) {
    const context = supportedAssessment(alert)?.context;
    if (context?.evidence_status !== 'verified') continue;
    const subject = context.task_name ?? context.target_user ?? context.group_name ?? context.threat_name ?? (alert.rule_id === 'service-installed' ? context.service_name
      : context.subject_user ? [context.subject_domain, context.subject_user].filter(Boolean).join('\\') : context.log_channel);
    if (subject) subjects.add(subject);
  }
  const names = [...subjects];
  if (!names.length) return language === 'it' ? 'Nomi non disponibili · apri i dettagli' : 'Names unavailable · open details';
  return names.slice(0, 2).join(' · ') + (names.length > 2 ? (language === 'it' ? ` · altri ${names.length - 2}` : ` · ${names.length - 2} more`) : '');
}
