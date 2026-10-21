import { describe, expect, it } from 'vitest';
import { buildFilter, getHealth, parseStartup, parseReview, parseAlerts, parseEvents, parseHealth, parseIntegrity } from './api';

// Synthetic parser fixtures are test-only and are never imported by the application.
const health = {
  product: 'piko', version: '0.1.0', protection_state: 'not_implemented', runtime_mode: 'console',
  uptime_seconds: 10, stored_events: 2, queue_depth: 0, dropped_events: 0,
  sensors: [{ id: 'piko.runtime', state: 'healthy', detail: 'Runtime heartbeat', last_seen_unix_ms: 1000 }],
};
const event = {
  schema_version: 1, event_id: 'test-event-id', host_id: 'test-host-id', boot_id: null,
  runtime_instance_id: 'test-runtime-id', sensor_id: 'piko.runtime', sequence: 1,
  wall_clock_time: 1000, monotonic_time: 10000, observation_time: 1000, ingestion_time: 1001,
  event_category: 'sensor_health', event_type: 'runtime.heartbeat', severity: 'info',
  actor_identity: null, logon_session: null, process: { pid: 42, instance_id: null, name: null, executable_path: null, creation_time_unix_ms: null },
  parent_process: null, target: null, operation: 'heartbeat', result: 'observed',
  causal_parents: [], correlation_ids: [], raw_evidence_reference: null,
  integrity_metadata: { normalization_version: 1, source_integrity: null },
};

describe('native response boundary', () => {
  it('preserves runtime observations and unknown sensor states without inventing protection', () => {
    expect(parseHealth(health)).toEqual(health);
    expect(parseHealth({ ...health, sensors: [{ ...health.sensors[0], state: 'future_state', last_seen_unix_ms: null }] }).sensors[0].state).toBe('future_state');
  });
  it('rejects malformed health rather than displaying healthy defaults', () => {
    for (const value of [null, {}, { ...health, stored_events: -1 }, { ...health, stored_events: Number.MAX_SAFE_INTEGER + 1 }, { ...health, sensors: [null] }]) {
      expect(() => parseHealth(value)).toThrow('Invalid HealthSnapshot');
    }
  });
  it('preserves nullable and source-supplied evidence', () => {
    expect(parseEvents([event])).toEqual([event]);
    expect(parseEvents([{ ...event, event_type: '<script>alert(1)</script>' }])[0].event_type).toBe('<script>alert(1)</script>');
  });
  it('rejects unsupported event schema and unsafe numeric identities', () => {
    for (const value of [{ ...event, schema_version: 99 }, { ...event, sequence: Number.MAX_SAFE_INTEGER + 1 }, { ...event, wall_clock_time: 9e15 }, { ...event, process: {} }, { ...event, severity: 'safe' }]) {
      expect(() => parseEvents([value])).toThrow('Invalid SecurityEvent');
    }
  });
  it('bounds lists and rejects malformed causal references', () => {
    expect(() => parseEvents(Array.from({ length: 1001 }, () => event))).toThrow();
    expect(() => parseEvents([{ ...event, causal_parents: [null] }])).toThrow();
  });
  it('never upgrades local chain verification into external attestation', () => {
    expect(parseIntegrity({ verified_events: 2, head_hash: 'abc', externally_anchored: false }).externally_anchored).toBe(false);
    expect(() => parseIntegrity({ verified_events: 2, head_hash: 'abc', externally_anchored: true })).toThrow();
  });
  it('reports that no native bridge exists in a standalone environment', async () => {
    await expect(getHealth()).rejects.toMatchObject({ code: 'browser' });
  });
});

describe('assessment response boundary', () => {
  const assessment = {
    model_version: 'piko-risk-v1', risk_score: 25, false_positive_probability: null,
    factors: [{ code: 'service_installed', points: 25 }],
    context: { evidence_status: 'verified', service_name: 'Example Service', image_path: 'C:\\Example\\service.exe',
      subject_user: null, subject_domain: null, service_account: null, log_channel: null, audit_changes: null, installer_process: null },
  };
  const alert = { id: 'a', rule_id: 'service-installed', rule_version: 1, event_id: 'e', evidence_id: null,
    observed_at: 10, severity: 'low', title: 'Service installed', explanation: 'A service was installed', assessment };
  it('accepts old records and preserves a versioned score with unavailable false-positive probability', () => {
    expect(parseAlerts([alert])[0].assessment).toEqual(assessment);
    expect(parseAlerts([{ ...alert, assessment: null }, { ...alert, assessment: undefined }])).toHaveLength(2);
    expect(parseAlerts([{ ...alert, assessment: { ...assessment, model_version: 'future-model' } }])[0].assessment?.model_version).toBe('future-model');
  });
  it('rejects invented false-positive percentages, invalid scores and inconsistent factors', () => {
    for (const invalid of [
      { ...assessment, false_positive_probability: 75 }, { ...assessment, false_positive_probability: 0 },
      { ...assessment, risk_score: -1 }, { ...assessment, risk_score: 101 }, { ...assessment, risk_score: 25.5 },
      { ...assessment, risk_score: 70 }, { ...assessment, factors: [{ code: 'service_installed', points: NaN }] },
      { ...assessment, factors: Array.from({ length: 33 }, () => ({ code: 'extra', points: 0 })) },
    ]) expect(() => parseAlerts([{ ...alert, assessment: invalid }])).toThrow('Invalid detection response');
  });
  it('rejects malformed or oversized context instead of rendering guessed names', () => {
    for (const context of [{}, null, { ...assessment.context, evidence_status: 'trusted' },
      { ...assessment.context, service_name: 'x'.repeat(4097) }, { ...assessment.context, service_name: 42 }]) {
      expect(() => parseAlerts([{ ...alert, assessment: { ...assessment, context } }])).toThrow('Invalid detection response');
    }
  });
  it('accepts zero and reduced risk without deriving a false-positive probability', () => {
    for (const risk of [
      { risk_score: 0, factors: [{ code: 'base', points: 0 }] },
      { risk_score: 25, factors: [{ code: 'audit_policy_changed', points: 40 }, { code: 'audit_logging_added_only', points: -15 }] },
    ]) expect(parseAlerts([{ ...alert, assessment: { ...assessment, ...risk } }])[0].assessment?.false_positive_probability).toBeNull();
  });
});

describe('query filter construction', () => {
  it('omits empty values and limits requested records', () => {
    expect(buildFilter('  ', '', '', 0)).toEqual({ limit: 200 });
  });
  it('passes literal search text without evaluating it and uses UTC milliseconds', () => {
    expect(buildFilter('  process.exe  ', 'high', 'runtime.heartbeat', 1, 7_200_000)).toEqual({
      limit: 200, search: 'process.exe', severity: 'high', event_type: 'runtime.heartbeat', since_unix_ms: 3_600_000,
    });
  });
  it('discards unsupported severity and clamps time bounds', () => {
    expect(buildFilter('', 'anything', '', 168, 100)).toEqual({ limit: 200, since_unix_ms: 0 });
  });
});

it('resource metrics preserve unknown CPU and reject invented or malformed readings',()=>{
  const snapshot={product:'piko',version:'0.2.0',protection_state:'limited',runtime_mode:'development_console',uptime_seconds:1,stored_events:0,queue_depth:0,dropped_events:0,sensors:[]};
  const metrics={sampled_at_unix_ms:Date.now(),working_set_bytes:1000,private_bytes:2000,cpu_percent_x100:null,interval_ms:0,logical_processors:4};
  expect(parseHealth({...snapshot,performance:metrics}).performance?.cpu_percent_x100).toBeNull();
  for(const bad of [{...metrics,cpu_percent_x100:10001},{...metrics,cpu_percent_x100:-1},{...metrics,working_set_bytes:'0'},{...metrics,logical_processors:0}])expect(()=>parseHealth({...snapshot,performance:bad})).toThrow();
  expect(parseHealth(snapshot).performance).toBeUndefined();
});

it('rejects ambiguous startup configuration',()=>{expect(parseStartup({enabled:false,conflict:false,command:'"C:\\piko.exe" --monitor-only'}).enabled).toBe(false);expect(()=>parseStartup({enabled:true,conflict:true,command:'x'})).toThrow();expect(()=>parseStartup({enabled:false,conflict:false,command:'x'.repeat(261)})).toThrow();});

it('validates manual review bounds',()=>{const value={alert_id:'test',state:'open',note:'',updated_at:100,reviewer_sid:'S-1-5-21-1-2-3-1000'};expect(parseReview(value).state).toBe('open');expect(()=>parseReview({...value,state:'confirmed_malware'})).toThrow();expect(()=>parseReview({...value,note:'é'.repeat(501)})).toThrow();});

describe('archive capacity',()=>{
 const archive={sampled_at_unix_ms:1000,budget_bytes:268435456,database_limit_bytes:134217728,database_bytes:134000000,total_bytes:135000000};
 it('keeps actual capacity and missing measurements explicit',()=>{expect(parseHealth({...health,archive}).archive).toEqual(archive);expect(parseHealth({...health,archive:null,archive_error:'Access denied'}).archive).toBeNull();});
 it('accepts measured SQLite limits without assuming exactly half the configured budget',()=>{
   for(const database_limit_bytes of [67108864,201326592])expect(parseHealth({...health,archive:{...archive,database_limit_bytes}}).archive?.database_limit_bytes).toBe(database_limit_bytes);
   for(const database_limit_bytes of [0,511,archive.budget_bytes+512,134217729])expect(()=>parseHealth({...health,archive:{...archive,database_limit_bytes}})).toThrow('Invalid archive usage');
 });
 it('accepts logical used space distinct from file allocation and validates retention',()=>{
  const current={...archive,database_active_bytes:50000000,retention_months:12,expired_events:20};
  expect(parseHealth({...health,archive:current}).archive).toEqual(current);
  for(const change of [{database_active_bytes:-1},{retention_months:0},{retention_months:121},{expired_events:-1}])expect(()=>parseHealth({...health,archive:{...current,...change}})).toThrow();
 });
 it('rejects impossible limits and aggregate sizes',()=>{for(const a of [{...archive,total_bytes:1},{...archive,database_limit_bytes:1},{...archive,sampled_at_unix_ms:0}])expect(()=>parseHealth({...health,archive:a})).toThrow('Invalid archive usage');});
});
