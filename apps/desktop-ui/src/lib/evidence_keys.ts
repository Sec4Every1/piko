import { invoke, isTauri } from '@tauri-apps/api/core';
import { ApiError } from './api';

export interface EvidenceKeyStatus {
  state: 'not_prepared' | 'backup_required' | 'ready' | 'unavailable';
  backup_confirmed: boolean;
  new_raw_enabled: boolean;
  recoverable_mode: boolean;
  activation_pending: boolean;
}
export interface EvidenceKeyTicket { id: string; expires_at_unix_ms: number }
export type EvidenceProtectionTicket = EvidenceKeyTicket;
export interface EvidenceKeyBackup {
  ticket_id: string;
  archive_id: string;
  recipient: string;
  recovery_code: string;
}

const invalid = () => new ApiError('invalid_response', 'Invalid evidence key response');
function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw invalid();
  return value as Record<string, unknown>;
}
function uuid(value: unknown): value is string {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
    && value !== '00000000-0000-0000-0000-000000000000';
}
export function validRecoveryCode(value: string): boolean {
  return value.length <= 128 && /^AGE-SECRET-KEY-1[A-Z0-9]+$/.test(value);
}
export function parseEvidenceKeyStatus(value: unknown): EvidenceKeyStatus {
  const status = record(value);
  if (typeof status.state !== 'string'
    || !['not_prepared', 'backup_required', 'ready', 'unavailable'].includes(status.state)
    || typeof status.backup_confirmed !== 'boolean' || typeof status.new_raw_enabled !== 'boolean'
    || typeof status.recoverable_mode !== 'boolean'
    || (status.activation_pending !== undefined && typeof status.activation_pending !== 'boolean')
    || (status.state === 'ready' && !status.backup_confirmed)
    || (status.state === 'backup_required' && status.backup_confirmed)
    || (status.state === 'not_prepared' && status.backup_confirmed)) throw invalid();
  return {
    state: status.state as EvidenceKeyStatus['state'],
    backup_confirmed: status.backup_confirmed,
    new_raw_enabled: status.new_raw_enabled,
    recoverable_mode: status.recoverable_mode,
    activation_pending: status.activation_pending === true,
  };
}
async function call(command: string, args?: Record<string, unknown>): Promise<unknown> {
  if (!isTauri()) throw new ApiError('browser', 'Evidence keys require the Piko desktop app');
  try { return await invoke<unknown>(command, args); }
  catch { throw new ApiError('unavailable', 'Evidence key operation unavailable'); }
}
export async function getEvidenceKeyStatus(): Promise<EvidenceKeyStatus> {
  return parseEvidenceKeyStatus(await call('evidence_key_status'));
}
export async function cancelEvidenceKeyBackup(ticketId: string): Promise<void> {
  if (!uuid(ticketId)) throw invalid();
  const result = await call('cancel_evidence_key_backup', { ticketId });
  if (result !== null && result !== undefined) throw invalid();
}
function parseTicketValue(input: unknown): EvidenceKeyTicket {
  const value = record(input);
  const now = Date.now();
  if (!uuid(value.id) || typeof value.expires_at_unix_ms !== 'number'
    || !Number.isSafeInteger(value.expires_at_unix_ms) || value.expires_at_unix_ms <= now
    || value.expires_at_unix_ms > now + 5 * 60_000 + 5_000) throw invalid();
  return { id: value.id, expires_at_unix_ms: value.expires_at_unix_ms };
}
export async function beginEvidenceKeyBackup(): Promise<EvidenceKeyTicket> {
  return parseTicketValue(await call('begin_evidence_key_backup'));
}
export async function authorizeEvidenceKeyBackup(ticketId: string): Promise<void> {
  if (!uuid(ticketId)) throw invalid();
  const result = await call('authorize_evidence_key_backup', { ticketId });
  if (result !== null && result !== undefined) throw invalid();
}
export async function readEvidenceKeyBackup(ticketId: string): Promise<EvidenceKeyBackup> {
  if (!uuid(ticketId)) throw invalid();
  const value = record(await call('read_evidence_key_backup', { ticketId }));
  if (!uuid(value.ticket_id) || value.ticket_id !== ticketId || !uuid(value.archive_id)
    || typeof value.recipient !== 'string' || value.recipient.length > 128
    || !/^age1[0-9a-z]+$/.test(value.recipient)
    || typeof value.recovery_code !== 'string' || !validRecoveryCode(value.recovery_code)) throw invalid();
  return {
    ticket_id: value.ticket_id,
    archive_id: value.archive_id,
    recipient: value.recipient,
    recovery_code: value.recovery_code,
  };
}
export async function confirmEvidenceKeyBackup(ticketId: string, code: string): Promise<EvidenceKeyStatus> {
  if (!uuid(ticketId) || !validRecoveryCode(code)) throw invalid();
  return parseEvidenceKeyStatus(await call('confirm_evidence_key_backup', { ticketId, code }));
}
export async function beginEvidenceProtection(): Promise<EvidenceProtectionTicket> {
  return parseTicketValue(await call('begin_evidence_protection'));
}
export async function authorizeEvidenceProtection(ticketId: string): Promise<void> {
  if (!uuid(ticketId)) throw invalid();
  const result = await call('authorize_evidence_protection', { ticketId });
  if (result !== null && result !== undefined) throw invalid();
}
export async function resumeEvidenceProtection(): Promise<void> {
  const result = await call('resume_evidence_protection');
  if (result !== null && result !== undefined) throw invalid();
}
