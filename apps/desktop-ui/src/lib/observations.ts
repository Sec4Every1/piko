import { invoke, isTauri } from '@tauri-apps/api/core';
import { ApiError } from './api';

export interface ObservedProcess {
  instance_id: string | null; pid: number; parent_pid: number; name: string; executable: string | null;
  creation_filetime: string | null; sid: string | null; session_id: number | null; access_error: string | null;
}
export interface ObservedConnection {
  pid: number; process_creation_filetime: string | null; family: 'ipv4' | 'ipv6';
  local_address: string; local_port: number; remote_address: string; remote_port: number; state: number;
}
export interface ObservedUdpEndpoint {pid:number;process_creation_filetime:string|null;family:'ipv4'|'ipv6';local_address:string;local_port:number}
export interface ObservationSnapshot {
  started_at_unix_ms: number; completed_at_unix_ms: number; processes: ObservedProcess[];
  udp_endpoints?:ObservedUdpEndpoint[]; udp_complete?:boolean|null;
  connections: ObservedConnection[]; process_complete: boolean; network_complete: boolean; warnings: string[];
}
const object = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === 'string' && v.length <= 8192;
const optional = (v: unknown) => v === null || text(v);
const integer = (v: unknown, max = 0xffffffff): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const ticks = (v: unknown) => v === null || (typeof v === 'string' && /^[1-9][0-9]{0,19}$/.test(v) && BigInt(v) <= 18446744073709551615n);
const uuid = (v: unknown) => v === null || (typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v));
export function parseObservations(v: unknown): ObservationSnapshot {
  if (!object(v) || !integer(v.started_at_unix_ms, 8.64e15) || !integer(v.completed_at_unix_ms, 8.64e15)
    || typeof v.process_complete !== 'boolean' || typeof v.network_complete !== 'boolean'
    || !Array.isArray(v.warnings) || v.warnings.length > 32 || !v.warnings.every(text)
    || !Array.isArray(v.processes) || v.processes.length > 4096
    || !v.processes.every(p => object(p) && integer(p.pid) && integer(p.parent_pid) && text(p.name) && optional(p.executable)
      && ticks(p.creation_filetime) && uuid(p.instance_id) && (p.instance_id === null || p.creation_filetime !== null)
      && optional(p.sid) && optional(p.access_error) && (p.session_id === null || integer(p.session_id)))
    || new Set(v.processes.map(p => p.pid)).size !== v.processes.length
    || !Array.isArray(v.connections) || v.connections.length > 2048
    || !v.connections.every(c => object(c) && integer(c.pid) && ticks(c.process_creation_filetime)
      && ['ipv4', 'ipv6'].includes(String(c.family)) && text(c.local_address) && text(c.remote_address)
      && integer(c.local_port, 65535) && integer(c.remote_port, 65535) && integer(c.state))
    || !(v.udp_complete===undefined || v.udp_complete===null || typeof v.udp_complete==='boolean')
    || !(v.udp_endpoints===undefined || Array.isArray(v.udp_endpoints) && v.udp_endpoints.length<=2048 && (v.udp_endpoints.length===0 || typeof v.udp_complete==='boolean') && v.udp_endpoints.every(e=>object(e) && Object.keys(e).every(k=>['pid','process_creation_filetime','family','local_address','local_port'].includes(k)) && integer(e.pid) && ticks(e.process_creation_filetime) && ['ipv4','ipv6'].includes(String(e.family)) && text(e.local_address) && integer(e.local_port,65535)))) {
    throw new ApiError('invalid_response', 'Invalid process/TCP/UDP observation response');
  }
  return v as unknown as ObservationSnapshot;
}
export async function getObservations(): Promise<ObservationSnapshot> {
  if (!isTauri()) throw new ApiError('browser', 'Apri piko con Open-Piko.cmd per leggere le applicazioni attive.');
  let value: unknown;
  try { value = await invoke('get_observations'); } catch (e) { throw new ApiError('unavailable', String(e)); }
  return parseObservations(value);
}
export function belongsTo(connection: Pick<ObservedConnection, 'pid' | 'process_creation_filetime'>, process: ObservedProcess): boolean {
  return process.creation_filetime !== null && connection.pid === process.pid && connection.process_creation_filetime === process.creation_filetime;
}
export function tcpState(state: number): string {
  return ['Unknown', 'CLOSED', 'LISTEN', 'SYN_SENT', 'SYN_RCVD', 'ESTABLISHED', 'FIN_WAIT1', 'FIN_WAIT2', 'CLOSE_WAIT', 'CLOSING', 'LAST_ACK', 'TIME_WAIT', 'DELETE_TCB'][state] ?? `State ${state}`;
}
