import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Alert, AlertAssessment } from './api';
import { assessmentFacts, ATTACK_SOURCES, interpretAlert, maximumRisk, riskInsight, sortAlerts, summarizeEvidence } from './insights';

const base: Alert = { id: 'a', rule_id: 'service-installed', rule_version: 1, event_id: 'event-a', evidence_id: null,
  observed_at: 10, severity: 'low', title: 'Original title', explanation: 'Original explanation' };
const assessment: AlertAssessment = {
  model_version: 'piko-risk-v1', risk_score: 25, false_positive_probability: null,
  factors: [{ code: 'service_installed', points: 25 }],
  context: { evidence_status: 'verified', service_name: 'Example Updater', image_path: 'C:\\Example\\updater.exe',
    subject_user: null, subject_domain: null, service_account: 'LocalSystem', log_channel: null,
    audit_changes: null, installer_process: null },
};

describe('reviewed alert interpretation', () => {
  it('maps the original rule identities to current official techniques', () => {
    for (const language of ['it', 'en'] as const) {
      for (const [rule, technique, url] of [
        ['audit-log-cleared', 'T1685.005', ATTACK_SOURCES.cleared],
        ['event-log-cleared', 'T1685.005', ATTACK_SOURCES.cleared],
        ['audit-policy-changed', 'T1685.001', ATTACK_SOURCES.audit],
        ['service-installed', 'T1543.003', ATTACK_SOURCES.service],
      ]) {
        const insight = interpretAlert({ ...base, rule_id: rule }, language);
        expect(insight.attack).toMatchObject({ id: technique, url });
        expect(insight.nextSteps).toHaveLength(3);
        expect(insight.expected.length).toBeGreaterThan(30);
        expect(insight.mappingContext.length).toBeGreaterThan(50);
      }
    }
  });
  it('never assigns ATT&CK to unknown rules, inherited object keys or unreviewed versions', () => {
    for (const item of [
      { ...base, rule_id: 'runtime.heartbeat' }, { ...base, rule_id: 'future-rule' },
      { ...base, rule_id: 'toString' }, { ...base, rule_id: '__proto__' },
      { ...base, rule_version: 0 }, { ...base, rule_version: 2 },
    ]) {
      const insight = interpretAlert(item, 'it');
      expect(insight.attack).toBeNull();
      expect(insight.title).toBe(item.title);
      expect(insight.observed).toBe(item.explanation);
    }
  });
  it('does not turn an audit policy change into proven disabling or service installation into abuse', () => {
    const audit = interpretAlert({ ...base, rule_id: 'audit-policy-changed' }, 'en');
    expect(audit.why).toContain('increase in logging');
    expect(audit.expected).toContain('has not established');
    expect(audit.mappingContext).toContain('Potential connection');
    expect(interpretAlert(base, 'en').mappingContext).toContain('not abuse');
  });
  it('keeps untrusted source text as text without constructing source-supplied links', () => {
    const insight = interpretAlert({ ...base, rule_id: 'unknown', title: '<script>alert(1)</script>', explanation: 'javascript:bad()' }, 'en');
    expect(insight.title).toBe('<script>alert(1)</script>');
    expect(insight.observed).toBe('javascript:bad()');
    expect(insight.attack).toBeNull();
  });
});

describe('evidence names and risk interpretation', () => {
  it('names the service and its executable without attributing installation to that executable', () => {
    const alert = { ...base, assessment };
    expect(interpretAlert(alert, 'it').title).toBe('Installato il servizio «Example Updater»');
    expect(interpretAlert(alert, 'en').title).toBe('Service “Example Updater” installed');
    expect(interpretAlert(alert, 'it').observed).toContain('C:\\Example\\updater.exe');
    expect(assessmentFacts(alert, 'en')).toContainEqual({ label: 'Service account', value: 'LocalSystem' });
    expect(assessmentFacts(alert, 'en').some(fact => /install/i.test(fact.label))).toBe(false);
  });
  it('uses a known account or affected log without inventing a process name', () => {
    const alert = { ...base, rule_id: 'event-log-cleared', assessment: { ...assessment, context: { ...assessment.context,
      service_name: null, image_path: null, service_account: null, log_channel: 'Application' } } };
    expect(interpretAlert(alert, 'it').title).toBe('Il registro «Application» è stato svuotato');
    expect(interpretAlert({ ...alert, assessment: { ...alert.assessment, context: { ...alert.assessment.context,
      subject_user: 'utente', subject_domain: 'PC' } } }, 'en').title).toBe('“PC\\utente” emptied the “Application” log');
  });
  it('keeps missing and invalid source fields out of names while preserving the rule score', () => {
    for (const evidence_status of ['missing', 'invalid', 'unsupported_version'] as const) {
      const alert = { ...base, assessment: { ...assessment, context: { ...assessment.context, evidence_status } } };
      expect(interpretAlert(alert, 'en').title).toBe('Service installed · name unavailable');
      expect(assessmentFacts(alert, 'en')).toEqual([]);
      expect(riskInsight(alert, 'en')).toMatchObject({ score: 25 });
      expect(riskInsight(alert, 'en')?.evidenceNote).toContain('without inferring missing fields');
    }
  });
  it('never applies an old assessment to new rules or unknown model versions', () => {
    for (const alert of [
      { ...base }, { ...base, assessment: { ...assessment, model_version: 'piko-risk-v2' } },
      { ...base, assessment, rule_version: 2 }, { ...base, assessment, rule_id: 'toString' },
    ]) {
      expect(riskInsight(alert, 'it')).toBeNull();
      expect(assessmentFacts(alert, 'it')).toEqual([]);
      expect(maximumRisk([alert])).toBeNull();
    }
  });
  it('summarizes only assessed records and preserves true zero without claiming host safety', () => {
    expect(maximumRisk([])).toBeNull();
    expect(maximumRisk([{ ...base, assessment: { ...assessment, risk_score: 0, factors: [] } }])).toEqual({ score: 0, assessed: 1 });
    expect(maximumRisk([base, { ...base, assessment }, { ...base, assessment: { ...assessment, risk_score: 45 } }])).toEqual({ score: 45, assessed: 2 });
  });
  it('explains incomplete evidence and negative weights in both languages', () => {
    const alert = { ...base, rule_id: 'audit-policy-changed', assessment: { ...assessment, risk_score: 25,
      factors: [{ code: 'audit_policy_changed', points: 40 }, { code: 'audit_logging_added_only', points: -15 },
        { code: 'audit_change_unknown', points: 0 }, { code: 'service_details_missing', points: 0 }] } };
    for (const language of ['it', 'en'] as const) {
      const insight = riskInsight(alert, language)!;
      expect(insight.score).toBe(25);
      expect(insight.factors.map(factor => factor.points)).toEqual([40, -15, 0, 0]);
      expect(insight.factors.every(factor => !factor.label.includes('audit_') && !factor.label.includes('service_'))).toBe(true);
    }
  });
});

describe('alert priority order', () => {
  it('orders source event times independently of later historical collection', () => {
    expect(sortAlerts([
      { ...base, id: 'collected-later', observed_at: 500, event_time: 10 },
      { ...base, id: 'happened-later', observed_at: 400, event_time: 20 },
    ]).map(a => a.id)).toEqual(['happened-later', 'collected-later']);
  });
  it('sorts priority before newest timestamp without mutating the input', () => {
    const input = [
      { ...base, id: 'recent-low', observed_at: 500 },
      { ...base, id: 'old-high', severity: 'high', observed_at: 1 },
      { ...base, id: 'new-high', severity: 'high', observed_at: 20 },
      { ...base, id: 'medium', severity: 'medium', observed_at: 100 },
      { ...base, id: 'critical', severity: 'critical', observed_at: 1 },
    ];
    const original = [...input];
    expect(sortAlerts(input).map(a => a.id)).toEqual(['critical', 'new-high', 'old-high', 'medium', 'recent-low']);
    expect(input).toEqual(original);
  });
  it('keeps unknown priorities visible without inventing urgency and resolves ties deterministically', () => {
    expect(sortAlerts([{ ...base, id: 'z', severity: 'unknown' }, { ...base, id: 'a', severity: 'info' }]).map(a => a.id)).toEqual(['a', 'z']);
  });
});

describe('source evidence presentation boundaries', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('does not parse unreviewed rules, DTDs or oversized source text', () => {
    const parse = vi.fn(() => { throw new Error('must not parse'); });
    vi.stubGlobal('DOMParser', class { parseFromString = parse; });
    for (const [xml, alert] of [
      ['<Event/>', { ...base, rule_id: '__proto__' }],
      ['<Event/>', { ...base, rule_id: 'future-rule' }],
      ['<Event/>', { ...base, rule_version: 2 }],
      ['<!DOCTYPE Event [<!ENTITY sample SYSTEM "file:///private">]><Event>&sample;</Event>', base],
      [' '.repeat(1024 * 1024 + 1), base],
    ] as const) expect(summarizeEvidence(xml, alert, 'it')).toEqual([]);
    expect(parse).not.toHaveBeenCalled();
  });

  it('leaves original evidence usable when the XML parser is unavailable or fails', () => {
    vi.stubGlobal('DOMParser', undefined);
    expect(summarizeEvidence('<Event/>', base, 'en')).toEqual([]);
    vi.stubGlobal('DOMParser', class { parseFromString() { throw new Error('parser unavailable'); } });
    expect(summarizeEvidence('<Event/>', base, 'en')).toEqual([]);
  });
});

it('names new tasks and accounts only from verified evidence and treats Defender action as an outcome to review',()=>{
  const task={...base,rule_id:'scheduled-task-created',assessment:{...assessment,context:{...assessment.context,service_name:null,task_name:'Example Task'}}};
  expect(interpretAlert(task,'it').title).toContain('Example Task'); expect(interpretAlert(task,'it').attack?.id).toBe('T1053.005');
  const unknown={...task,assessment:{...task.assessment,context:{...task.assessment.context,evidence_status:'invalid' as const}}}; expect(interpretAlert(unknown,'it').title).not.toContain('Example Task');
  const outcome={...task,rule_id:'defender-action-reported'}; expect(interpretAlert(outcome,'it').why).toContain('Consenti'); expect(interpretAlert(outcome,'it').attack).toBeNull();
  for(const rule of ['account-created','group-member-added','scheduled-task-created','scheduled-task-updated','defender-realtime-disabled','defender-config-changed','defender-threat-reported','defender-action-reported'])for(const language of ['it','en'] as const) expect(interpretAlert({...base,rule_id:rule},language).nextSteps.length).toBeGreaterThan(0);
});

