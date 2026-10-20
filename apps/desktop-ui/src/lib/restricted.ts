import { invoke, isTauri } from '@tauri-apps/api/core';
export interface RestrictedPolicy { network_capabilities: 0; max_processes: 1; memory_limit_bytes: 536870912; original_unchanged: true; staged_read_only: true; stop_on_ui_exit: true }
export interface RestrictedPlan { id: string; executable: string; sha256: string; expires_at: number; policy: RestrictedPolicy }
export interface RestrictedSession { id: string; executable: string; sha256: string; pid: number; created_at: number; running: boolean; data_directory: string; policy: RestrictedPolicy }
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= 4096;
const uuid = (v: unknown) => text(v) && /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(v);
const time = (v: unknown) => Number.isSafeInteger(v) && Number(v) > 0 && Number(v) < 8.64e12;
function policy(v: unknown): v is RestrictedPolicy { return object(v) && v.network_capabilities === 0 && v.max_processes === 1 && v.memory_limit_bytes === 536870912 && v.original_unchanged === true && v.staged_read_only === true && v.stop_on_ui_exit === true; }
function identity(v: unknown): v is Record<string, unknown> { return object(v) && uuid(v.id) && text(v.executable) && text(v.sha256) && /^[a-f0-9]{64}$/.test(v.sha256) && policy(v.policy); }
function bad(): never { throw new Error('Invalid restricted trial response'); }
export function parseRestrictedPlan(v: unknown): RestrictedPlan { if (!identity(v) || !time(v.expires_at)) bad(); return v as unknown as RestrictedPlan; }
export function parseRestrictedSession(v: unknown): RestrictedSession { if (!identity(v) || !time(v.created_at) || !text(v.data_directory) || typeof v.running !== 'boolean' || !Number.isSafeInteger(v.pid) || Number(v.pid) < 1 || Number(v.pid) > 0xffffffff) bad(); return v as unknown as RestrictedSession; }
async function request(command: string, args?: Record<string, unknown>): Promise<unknown> { if (!isTauri()) throw new Error('Apri piko con Open-Piko.cmd per la prova AppContainer.'); return invoke(command, args); }
export const prepareRestricted = async (path: string) => parseRestrictedPlan(await request('prepare_restricted', { path }));
export const launchRestricted = async (planId: string) => parseRestrictedSession(await request('launch_restricted', { planId }));
export async function restrictedSessions(): Promise<RestrictedSession[]> { const v = await request('restricted_sessions'); if (!Array.isArray(v) || v.length > 2) bad(); return v.map(parseRestrictedSession); }
async function empty(command: string, args: Record<string, unknown>) { if (await request(command, args) !== null) bad(); }
export const discardRestricted = (planId: string) => empty('discard_restricted', { planId });
export const stopRestricted = (sessionId: string) => empty('stop_restricted', { sessionId });
