import { invoke, isTauri } from '@tauri-apps/api/core';
export interface SandboxStatus { launcher_available: boolean; max_sessions: number }
export interface SandboxPlan { id: string; executable: string; sha256: string; expires_at: number }
export interface SandboxSession { id: string; executable: string; sha256: string; created_at: number; configuration: string }
const obj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= 4096;
const uuid = (v: unknown) => text(v) && /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(v);
const time = (v: unknown) => Number.isSafeInteger(v) && Number(v) > 0 && Number(v) < 8.64e12;
const identity = (v: unknown): v is Record<string, unknown> => obj(v) && uuid(v.id) && text(v.executable) && text(v.sha256) && /^[a-f0-9]{64}$/.test(v.sha256);
const bad = (): never => { throw new Error('Invalid Sandbox response'); };
async function request(command: string, args?: Record<string, unknown>): Promise<unknown> {
  if (!isTauri()) throw new Error('Apri piko con Open-Piko.cmd per usare Windows Sandbox.');
  return invoke(command, args);
}
export function parseSandboxPlan(v: unknown): SandboxPlan { if (!identity(v) || !time(v.expires_at)) return bad(); return v as unknown as SandboxPlan; }
export function parseSandboxSession(v: unknown): SandboxSession { if (!identity(v) || !time(v.created_at) || !text(v.configuration) || !v.configuration.endsWith('.wsb')) return bad(); return v as unknown as SandboxSession; }
export async function sandboxStatus(): Promise<SandboxStatus> { const v = await request('sandbox_status'); if (!obj(v) || typeof v.launcher_available !== 'boolean' || v.max_sessions !== 8) return bad(); return v as unknown as SandboxStatus; }
export async function sandboxSessions(): Promise<SandboxSession[]> { const v = await request('sandbox_sessions'); if (!Array.isArray(v) || v.length > 8) return bad(); return v.map(parseSandboxSession); }
export const prepareSandbox = async (path: string) => parseSandboxPlan(await request('prepare_sandbox', { path }));
export const createSandbox = async (planId: string) => parseSandboxSession(await request('create_sandbox', { planId }));
async function empty(command: string, args: Record<string, unknown>) { if (await request(command, args) !== null) bad(); }
export const discardSandbox = (planId: string) => empty('discard_sandbox', { planId });
export const launchSandbox = (sessionId: string) => empty('launch_sandbox', { sessionId });
export const removeSandbox = (sessionId: string) => empty('remove_sandbox', { sessionId });
