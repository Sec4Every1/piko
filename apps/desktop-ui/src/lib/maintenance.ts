import { invoke, isTauri } from '@tauri-apps/api/core';
import { ApiError } from './api';

export interface ArchiveMaintenanceStatus {
  enabled: boolean;
  state: 'waiting' | 'running' | 'completed_batch' | 'blocked';
  sampled_at_unix_ms: number | null;
  scanned: number;
  changed: number;
  logical_bytes_saved: number;
  cycle_complete: boolean;
  detail: string | null;
}
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
export function parseArchiveMaintenance(v: unknown): ArchiveMaintenanceStatus {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new ApiError('invalid_response', 'Invalid archive maintenance status');
  const s = v as Record<string, unknown>;
  if (typeof s.enabled !== 'boolean' || !['waiting', 'running', 'completed_batch', 'blocked'].includes(String(s.state))
    || !(s.sampled_at_unix_ms === null || integer(s.sampled_at_unix_ms, 8.64e15))
    || !integer(s.scanned, 32) || !integer(s.changed, s.scanned) || !integer(s.logical_bytes_saved, 4 * 1024 * 1024)
    || typeof s.cycle_complete !== 'boolean'
    || !(s.detail === null || (typeof s.detail === 'string' && new TextEncoder().encode(s.detail).length <= 2048))) {
    throw new ApiError('invalid_response', 'Invalid archive maintenance status');
  }
  return v as unknown as ArchiveMaintenanceStatus;
}
export async function getArchiveMaintenance(): Promise<ArchiveMaintenanceStatus> {
  if (!isTauri()) throw new ApiError('browser', 'Open piko with Open-Piko.cmd.');
  let value: unknown;
  try { value = await invoke('archive_maintenance_status'); }
  catch (error) { throw new ApiError('unavailable', String(error)); }
  return parseArchiveMaintenance(value);
}
