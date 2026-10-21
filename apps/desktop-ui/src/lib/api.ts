import { invoke, isTauri } from '@tauri-apps/api/core';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export interface SensorHealth { id: string; state: string; detail: string; last_seen_unix_ms: number | null }
export interface HealthSnapshot {
  product: string;
  version: string;
  protection_state: string;
  runtime_mode: string;
  uptime_seconds: number;
  stored_events: number;
  queue_depth: number;
  dropped_events: number;
  sensors: SensorHealth[];
  performance?: RuntimePerformance | null;
  performance_error?: string | null;
  archive?: ArchiveUsage | null;
  archive_error?: string | null;
}
export interface ArchiveUsage { sampled_at_unix_ms: number; budget_bytes: number; database_limit_bytes: number; database_bytes: number; database_active_bytes?: number | null; retention_months?: number | null; expired_events?: number; total_bytes: number }
export interface RuntimePerformance { sampled_at_unix_ms: number; working_set_bytes: number; private_bytes: number; cpu_percent_x100: number | null; interval_ms: number; logical_processors: number | null }
export interface ProcessContext {
  pid: number; instance_id: string | null; name: string | null;
  executable_path: string | null; creation_time_unix_ms: number | null;
}
export interface SecurityEvent {
  schema_version: number; event_id: string; host_id: string; boot_id: string | null;
  runtime_instance_id: string; sensor_id: string; sequence: number;
  wall_clock_time: number; monotonic_time: number; observation_time: number; ingestion_time: number;
  event_category: string; event_type: string; severity: Severity;
  actor_identity: { sid: string | null; display_name: string | null } | null;
  logon_session: string | null; process: ProcessContext | null; parent_process: ProcessContext | null;
  target: { kind: string; identifier: string } | null; operation: string; result: string;
  causal_parents: string[]; correlation_ids: string[]; raw_evidence_reference: string | null;
  integrity_metadata: { normalization_version: number; source_integrity: string | null };
}
export interface EventFilter {
  limit: number; search?: string; severity?: Severity; event_type?: string; since_unix_ms?: number; expression?: string;
}
export interface IntegrityReport { verified_events: number; head_hash: string | null; externally_anchored: false; expired_events?: number }
export type ApiErrorCode = 'browser' | 'unavailable' | 'invalid_response';
export class ApiError extends Error {
  constructor(public readonly code: ApiErrorCode, detail: string) { super(detail); }
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function integer(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}
function text(value: unknown): value is string { return typeof value === 'string'; }
function optionalText(value: unknown): boolean { return value === null || text(value); }
function timestamp(value: unknown): boolean { return value === null || (integer(value) && value <= 8.64e15); }
function stringArray(value: unknown): value is string[] { return Array.isArray(value) && value.every(text); }
function processContext(value: unknown): boolean {
  return value === null || (object(value) && integer(value.pid) && optionalText(value.instance_id)
    && optionalText(value.name) && optionalText(value.executable_path) && timestamp(value.creation_time_unix_ms));
}
const invalid = (detail: string): never => { throw new ApiError('invalid_response', detail); };

/** Presentation-boundary validation, not a security decision or authorization check. */
export function parseHealth(value: unknown): HealthSnapshot {
  if (!object(value) || !text(value.product) || !text(value.version) || !text(value.protection_state)
    || !text(value.runtime_mode) || !integer(value.uptime_seconds) || !integer(value.stored_events)
    || !integer(value.queue_depth) || !integer(value.dropped_events) || !Array.isArray(value.sensors)
    || !value.sensors.every(sensor => object(sensor) && text(sensor.id) && text(sensor.state)
      && text(sensor.detail) && timestamp(sensor.last_seen_unix_ms))) return invalid('Invalid HealthSnapshot response');
  if (value.performance_error !== undefined && !optionalText(value.performance_error)) return invalid('Invalid performance error');
  if (value.archive_error !== undefined && !optionalText(value.archive_error)) return invalid('Invalid archive error');
  const archive = value.archive;
  if (archive !== undefined && archive !== null && (!object(archive) || !integer(archive.sampled_at_unix_ms) || archive.sampled_at_unix_ms===0 || !integer(archive.budget_bytes) || archive.budget_bytes<8388608 || !integer(archive.database_limit_bytes) || archive.database_limit_bytes<512 || archive.database_limit_bytes>archive.budget_bytes || archive.database_limit_bytes%512!==0 || !integer(archive.database_bytes) || !integer(archive.total_bytes) || archive.total_bytes<archive.database_bytes || (archive.database_active_bytes !== undefined && archive.database_active_bytes !== null && !integer(archive.database_active_bytes)))) return invalid('Invalid archive usage');
  if (object(archive) && ((archive.retention_months !== undefined && archive.retention_months !== null && (!integer(archive.retention_months) || archive.retention_months < 1 || archive.retention_months > 120)) || (archive.expired_events !== undefined && !integer(archive.expired_events)))) return invalid('Invalid retention status');
  const metrics = value.performance;
  if (metrics !== undefined && metrics !== null && (!object(metrics) || !integer(metrics.sampled_at_unix_ms) || metrics.sampled_at_unix_ms === 0 || !integer(metrics.working_set_bytes) || !integer(metrics.private_bytes) || !integer(metrics.interval_ms) || !(metrics.cpu_percent_x100 === null || integer(metrics.cpu_percent_x100) && metrics.cpu_percent_x100 <= 10000) || !(metrics.logical_processors === null || integer(metrics.logical_processors) && metrics.logical_processors > 0))) return invalid('Invalid runtime performance');
  return value as unknown as HealthSnapshot;
}

export function parseEvents(value: unknown): SecurityEvent[] {
  if (!Array.isArray(value) || value.length > 1000) return invalid('Invalid event list response');
  for (const item of value) {
    if (!object(item) || item.schema_version !== 1 || !text(item.event_id) || !text(item.host_id)
      || !optionalText(item.boot_id) || !text(item.runtime_instance_id) || !text(item.sensor_id)
      || !integer(item.sequence) || item.sequence === 0 || !integer(item.monotonic_time)
      || !integer(item.wall_clock_time) || item.wall_clock_time > 8.64e15
      || !integer(item.observation_time) || !integer(item.ingestion_time)
      || !text(item.event_category) || !text(item.event_type) || !text(item.severity)
      || !['info', 'low', 'medium', 'high', 'critical'].includes(item.severity)
      || !optionalText(item.logon_session) || !processContext(item.process) || !processContext(item.parent_process)
      || !(item.actor_identity === null || (object(item.actor_identity)
        && optionalText(item.actor_identity.sid) && optionalText(item.actor_identity.display_name)))
      || !(item.target === null || (object(item.target) && text(item.target.kind) && text(item.target.identifier)))
      || !text(item.operation) || !text(item.result) || !stringArray(item.causal_parents)
      || !stringArray(item.correlation_ids) || !optionalText(item.raw_evidence_reference)
      || !object(item.integrity_metadata) || !integer(item.integrity_metadata.normalization_version)
      || !optionalText(item.integrity_metadata.source_integrity)) return invalid('Invalid SecurityEvent v1 response');
  }
  return value as SecurityEvent[];
}

export function parseIntegrity(value: unknown): IntegrityReport {
  if (!object(value) || !integer(value.verified_events) || !optionalText(value.head_hash)
    || value.externally_anchored !== false || (value.expired_events !== undefined && !integer(value.expired_events))) return invalid('Invalid IntegrityReport response');
  return value as unknown as IntegrityReport;
}

async function request(command: string, args?: Record<string, unknown>): Promise<unknown> {
  if (!isTauri()) throw new ApiError('browser', 'The browser preview has no native IPC bridge.');
  try { return await invoke<unknown>(command, args); }
  catch (error) {
    throw new ApiError('unavailable', typeof error === 'string' ? error : error instanceof Error ? error.message : JSON.stringify(error));
  }
}

export async function getHealth(): Promise<HealthSnapshot> { return parseHealth(await request('get_health')); }

export async function openAttackReference(techniqueId: string): Promise<void> {
  await request('open_attack_reference', { techniqueId });
}

export interface Alert {
  id: string; rule_id: string; rule_version: number; event_id: string; evidence_id: string | null;
  observed_at: number; event_time?: number | null; severity: string; title: string; explanation: string;
  assessment?: AlertAssessment | null;
}
export interface FailedLogonSummary { bucket_start:number; bucket_end:number; count:number; records:{event_id:string; evidence_id:string; event_time:number}[] }
export interface AlertAssessment {
  model_version: string; risk_score: number; false_positive_probability: number | null;
  factors: { code: string; points: number }[];
  context: {
    evidence_status: 'verified' | 'missing' | 'invalid' | 'unsupported_version';
    service_name: string | null; image_path: string | null;
    subject_user: string | null; subject_domain: string | null;
    service_account: string | null; log_channel: string | null;
    audit_changes: string | null; installer_process: string | null;
    target_user?: string | null;
    target_domain?: string | null;
    group_name?: string | null;
    group_sid?: string | null;
    member_sid?: string | null;
    task_name?: string | null;
    threat_name?: string | null;
    resource_path?: string | null;
    defender_action?: string | null;
    old_value?: string | null;
    new_value?: string | null;
    failed_logons?: FailedLogonSummary | null;
    source_ip?: string | null; logon_type?:string|null; caller_path?:string|null; failure_status?:string|null; failure_sub_status?:string|null;
  };
}

/** Scores describe the versioned heuristic, not calibrated event probabilities. */
function assessment(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (!object(value) || !text(value.model_version) || value.model_version.length > 64
    || !integer(value.risk_score) || value.risk_score > 100 || value.false_positive_probability !== null
    || !Array.isArray(value.factors) || value.factors.length > 32
    || !value.factors.every(factor => object(factor) && text(factor.code) && factor.code.length <= 80
      && typeof factor.points === 'number' && Number.isInteger(factor.points) && Math.abs(factor.points) <= 100)
    || !object(value.context) || !['verified', 'missing', 'invalid', 'unsupported_version'].includes(String(value.context.evidence_status))
    || !['service_name', 'image_path', 'subject_user', 'subject_domain', 'service_account', 'log_channel', 'audit_changes', 'installer_process']
      .every(key => optionalText(value.context && (value.context as Record<string, unknown>)[key])
        && ((value.context as Record<string, unknown>)[key] === null || String((value.context as Record<string, unknown>)[key]).length <= 4096))) return false;
  if (!["target_user","target_domain","group_name","group_sid","member_sid","task_name","threat_name","resource_path","defender_action","old_value","new_value","source_ip","logon_type","caller_path","failure_status","failure_sub_status"].every(key => (value.context as Record<string, unknown>)[key] === undefined || optionalText((value.context as Record<string, unknown>)[key]) && String((value.context as Record<string, unknown>)[key] ?? '').length <= 4096)) return false;
  if (!failedLogons(value.context.failed_logons)) return false;
  if (value.model_version === 'piko-risk-v1') {
    const sum = value.factors.reduce((total, factor) => total + factor.points, 0);
    if (Math.max(0, Math.min(100, sum)) !== value.risk_score) return false;
  }
  return true;
}

function failedLogons(v:unknown):boolean {
  if(v===undefined||v===null)return true;
  if(!object(v)||!integer(v.bucket_start)||v.bucket_start===0||v.bucket_start%60000!==0||!integer(v.bucket_end)||v.bucket_end!==v.bucket_start+60000||!integer(v.count)||v.count<5||v.count>256||!Array.isArray(v.records)||v.records.length!==v.count)return false;
  const uuid=(v:unknown)=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
  const seen=new Set<string>(), evidence=new Set<string>();let previous=0;
  for(const r of v.records){if(!object(r)||!uuid(r.event_id)||!uuid(r.evidence_id)||seen.has(String(r.event_id))||evidence.has(String(r.evidence_id))||!integer(r.event_time)||r.event_time<v.bucket_start||r.event_time>=v.bucket_end||r.event_time<previous)return false;seen.add(String(r.event_id));evidence.add(String(r.evidence_id));previous=r.event_time;}
  return true;
}

export function parseAlerts(value: unknown): Alert[] {
  if (!Array.isArray(value) || value.length > 100 || !value.every(a => object(a) && text(a.id)
    && text(a.rule_id) && integer(a.rule_version) && text(a.event_id) && optionalText(a.evidence_id)
    && integer(a.observed_at) && timestamp(a.observed_at) && (a.event_time === undefined || timestamp(a.event_time))
    && text(a.severity) && text(a.title) && text(a.explanation) && assessment(a.assessment) && (a.rule_id!=='failed-logon-burst' || a.rule_version!==1 || object(a.assessment) && object(a.assessment.context) && a.assessment.context.evidence_status==='verified' && object(a.assessment.context.failed_logons)))) return invalid('Invalid detection response');
  return value as Alert[];
}
export interface ResponseAction {
  id: string; kind: 'quarantine' | 'restore'; path: string; sha256: string; bytes: number;
  file_identity: string; created_at: number; expires_at: number; status: string;
  detail: string; backup_id: string | null;
}
export interface ResponseStatus { roots: string[]; max_file_bytes: number; vault_budget_bytes: number; actions: ResponseAction[] }
export function parseAction(value: unknown): ResponseAction {
  if (!object(value) || !text(value.id) || !['quarantine', 'restore'].includes(String(value.kind))
    || !text(value.path) || !text(value.sha256) || !/^[a-f0-9]{64}$/.test(value.sha256)
    || !integer(value.bytes) || !text(value.file_identity) || !integer(value.created_at)
    || !integer(value.expires_at) || !text(value.status) || !text(value.detail) || !optionalText(value.backup_id)) return invalid('Invalid response action');
  return value as unknown as ResponseAction;
}
export async function listAlerts(): Promise<Alert[]> {
  return parseAlerts(await request('list_alerts'));
}
export async function responseStatus(): Promise<ResponseStatus> {
  const value = await request('response_status');
  if (!object(value) || !stringArray(value.roots) || value.roots.length > 16 || !integer(value.max_file_bytes)
    || !integer(value.vault_budget_bytes) || !Array.isArray(value.actions) || value.actions.length > 100) return invalid('Invalid response status');
  return { roots: value.roots, max_file_bytes: value.max_file_bytes, vault_budget_bytes: value.vault_budget_bytes, actions: value.actions.map(parseAction) };
}
export async function prepareQuarantine(path: string): Promise<ResponseAction> { return parseAction(await request('prepare_quarantine', { path })); }
export async function prepareRestore(actionId: string): Promise<ResponseAction> { return parseAction(await request('prepare_restore', { actionId })); }
export async function executeAction(plan: ResponseAction): Promise<ResponseAction> {
  return parseAction(await request('execute_action', { actionId: plan.id, expectedSha256: plan.sha256 }));
}
export async function listEvents(filter: EventFilter): Promise<SecurityEvent[]> {
  return parseEvents(await request('list_events', { filter }));
}
export async function verifyStore(): Promise<IntegrityReport> { return parseIntegrity(await request('verify_store')); }

export async function getEvidence(evidenceId: string): Promise<string> {
  const value = await request('get_evidence', { evidenceId });
  if (!object(value) || value.evidence_id !== evidenceId || !text(value.source)
    || !text(value.content_type) || !Array.isArray(value.bytes) || value.bytes.length > 1024 * 1024
    || !value.bytes.every(byte => integer(byte) && byte <= 255)) return invalid('Invalid or missing raw evidence');
  try { return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(value.bytes)); }
  catch { return invalid('Evidence is not valid UTF-8'); }
}

export function buildFilter(search: string, severity: string, eventType: string, hours: number, now = Date.now()): EventFilter {
  const filter: EventFilter = { limit: 200 };
  if (search.trim()) filter.search = search.trim();
  if (['info', 'low', 'medium', 'high', 'critical'].includes(severity)) filter.severity = severity as Severity;
  if (eventType.trim()) filter.event_type = eventType.trim();
  if (Number.isFinite(hours) && hours > 0) filter.since_unix_ms = Math.max(0, now - hours * 3_600_000);
  return filter;
}

export interface StartupStatus { enabled: boolean; conflict: boolean; command: string; last_startup_error?: string | null }
export function parseStartup(value: unknown): StartupStatus {
 if (!object(value) || typeof value.enabled !== 'boolean' || typeof value.conflict !== 'boolean' || !text(value.command) || value.command.length > 260 || (value.enabled && value.conflict) || (value.last_startup_error != null && (!text(value.last_startup_error) || value.last_startup_error.length > 4096))) return invalid('Invalid startup status');
 return value as unknown as StartupStatus;
}
export async function startupStatus(): Promise<StartupStatus> { return parseStartup(await request('startup_status')); }
export async function setStartup(enabled: boolean): Promise<StartupStatus> { return parseStartup(await request('set_startup', { enabled })); }

export type ReviewState = 'open' | 'investigating' | 'expected' | 'handled';
export interface AlertReview { alert_id: string; state: ReviewState; note: string; updated_at: number; reviewer_sid: string }
export function parseReview(value: unknown): AlertReview { if(!object(value)||!text(value.alert_id)||value.alert_id.length>128||!['open','investigating','expected','handled'].includes(String(value.state))||!text(value.note)||new TextEncoder().encode(value.note).length>1000||!integer(value.updated_at)||value.updated_at===0||value.updated_at>8.64e12||!text(value.reviewer_sid)||value.reviewer_sid.length>184) return invalid('Invalid review'); return value as unknown as AlertReview; }
export async function listAlertReviews(): Promise<AlertReview[]> { const value=await request('list_alert_reviews');if(!Array.isArray(value)||value.length>2000)return invalid('Invalid review list');return value.map(parseReview); }
export async function saveAlertReview(alertId:string,state:ReviewState,note:string):Promise<AlertReview>{return parseReview(await request('save_alert_review',{alertId,state,note}));}
