import { invoke, isTauri } from '@tauri-apps/api/core';
import { ApiError } from './api';
export interface InstalledSoftware { id: string; display_name: string; publisher: string | null; version: string | null; install_location: string | null; install_date?: string | null; display_icon?: string | null; scope: string; registry_view: string; source: string; uninstall_key: string }
export interface InventorySnapshot { entries: InstalledSoftware[]; complete: boolean; truncated: boolean; warnings: string[] }
export interface NetworkProfile { id: number; name: string; active: boolean; firewall_enabled: boolean; block_all_inbound: boolean; excluded_interfaces: boolean }
export type NetworkDirection = 'outbound' | 'inbound';
export interface NetworkRule { direction?: NetworkDirection; id: string; executable: string; enabled: boolean; verified: boolean }
export interface NetworkSnapshot { active_profiles: number; profiles: NetworkProfile[]; local_policy_modify_state: string; rules: NetworkRule[]; complete: boolean; warnings: string[] }
export interface NetworkPlan { direction?: NetworkDirection; id: string; action: 'block' | 'remove_block'; rule_id: string; executable: string; display_name: string; sha256: string | null; expires_at: number }
const object = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === 'string' && v.length <= 8192;
const optionalText = (v: unknown) => v === null || text(v);
const hash = (v: unknown) => text(v) && /^[a-f0-9]{64}$/.test(v);
const warnings = (v: unknown) => Array.isArray(v) && v.length <= 32 && v.every(text);
const bad = (): never => { throw new ApiError('invalid_response', 'Invalid application control response'); };
async function request(command: string, args?: Record<string, unknown>): Promise<unknown> {
  if (!isTauri()) throw new ApiError('browser', 'Apri piko con Open-Piko.cmd per leggere e modificare i controlli Windows.');
  try { return await invoke(command, args); } catch (error) { throw new ApiError('unavailable', String(error)); }
}
export function parseInventory(v: unknown): InventorySnapshot {
  if (!object(v) || typeof v.complete !== 'boolean' || typeof v.truncated !== 'boolean' || !warnings(v.warnings)
    || !Array.isArray(v.entries) || v.entries.length > 4096 || !v.entries.every(e => object(e) && text(e.id) && text(e.display_name)
      && optionalText(e.publisher) && optionalText(e.version) && optionalText(e.install_location) && text(e.scope)
      && (e.install_date === undefined || optionalText(e.install_date)) && (e.display_icon === undefined || optionalText(e.display_icon))
      && text(e.registry_view) && e.source === 'windows_uninstall_registry' && text(e.uninstall_key))) return bad();
  return v as unknown as InventorySnapshot;
}
export function parseNetwork(v: unknown): NetworkSnapshot {
  if (!object(v) || !Number.isSafeInteger(v.active_profiles) || (v.active_profiles as number) < 0 || (v.active_profiles as number) > 7 || !text(v.local_policy_modify_state)
    || typeof v.complete !== 'boolean' || !warnings(v.warnings) || !Array.isArray(v.profiles) || v.profiles.length !== 3
    || !v.profiles.every(p => object(p) && [1, 2, 4].includes(p.id as number) && text(p.name) && typeof p.active === 'boolean'
      && p.active === Boolean((v.active_profiles as number) & (p.id as number))
      && typeof p.firewall_enabled === 'boolean' && typeof p.excluded_interfaces === 'boolean' && typeof p.block_all_inbound === 'boolean')
    || new Set(v.profiles.map(p => p.id)).size !== 3 || !Array.isArray(v.rules) || v.rules.length > 512
    || !v.rules.every(r => object(r) && hash(r.id) && text(r.executable) && (r.direction===undefined||['inbound','outbound'].includes(String(r.direction))) && typeof r.enabled === 'boolean' && typeof r.verified === 'boolean'
      && (!r.verified || r.enabled))) return bad();
  return v as unknown as NetworkSnapshot;
}
export function parseNetworkPlan(v: unknown): NetworkPlan {
  if (!object(v) || !text(v.id) || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v.id) || !['block', 'remove_block'].includes(String(v.action))
    || (v.direction!==undefined&&!['inbound','outbound'].includes(String(v.direction))) || !hash(v.rule_id) || !text(v.executable) || !text(v.display_name) || !Number.isSafeInteger(v.expires_at)
    || (v.expires_at as number) <= 0 || (v.expires_at as number) > 8.64e12 || (v.action === 'block' ? !hash(v.sha256) : v.sha256 !== null)) return bad();
  return v as unknown as NetworkPlan;
}
export const softwareInventory = async () => parseInventory(await request('software_inventory'));
export const networkSnapshot = async () => parseNetwork(await request('network_snapshot'));
export const prepareNetworkAction = async (action: NetworkPlan['action'], path: string, direction:NetworkDirection='outbound') => { const plan=parseNetworkPlan(await request('prepare_network_action', { action, path, direction }));if((plan.direction??'outbound')!==direction) return bad();return plan; };
export const directionLabel=(value:NetworkDirection|undefined,it:boolean)=>(value??'outbound')==='inbound' ? (it?'In ingresso':'Inbound') : (it?'In uscita':'Outbound');
export const executeNetworkAction = async (planId: string) => { const result = await request('execute_network_action', { planId }); if (result !== null) bad(); };

export interface ExecutableCandidates { app_id: string; paths: string[]; complete: boolean; warnings: string[] }
export async function applicationExecutables(appId: string): Promise<ExecutableCandidates> {
  const v = await request('application_executables', { appId });
  if (!object(v) || v.app_id !== appId || typeof v.complete !== 'boolean' || !warnings(v.warnings)
    || !Array.isArray(v.paths) || v.paths.length > 32 || !v.paths.every(p => text(p) && /^[a-z]:\\/i.test(p) && p.toLowerCase().endsWith('.exe'))
    || new Set(v.paths.map(p => String(p).toLowerCase())).size !== v.paths.length) return bad();
  return v as unknown as ExecutableCandidates;
}
export async function discardNetworkPlans(planIds: string[]): Promise<void> {
  if (planIds.length) await request('discard_network_plans', { planIds });
}

export interface ExecutableSignature { executable:string;sha256:string;status:'verified_locally'|'no_embedded_signature'|'digest_mismatch'|'not_verified';native_status:string;checked_at:number;revocation_checked:false;catalog_checked:false }
export function parseSignature(v:unknown):ExecutableSignature{if(!object(v)||!text(v.executable)||!hash(v.sha256)||!['verified_locally','no_embedded_signature','digest_mismatch','not_verified'].includes(String(v.status))||!text(v.native_status)||!/^0x[0-9A-F]{8}$/.test(v.native_status)||!Number.isSafeInteger(v.checked_at)||(v.checked_at as number)<=0||(v.checked_at as number)>8.64e12||v.revocation_checked!==false||v.catalog_checked!==false)return bad();const known:Record<string,string>={verified_locally:'0x00000000',no_embedded_signature:'0x800B0100',digest_mismatch:'0x80096010'};if(known[String(v.status)] ? v.native_status!==known[String(v.status)] : Object.values(known).includes(v.native_status))return bad();return v as unknown as ExecutableSignature;}
export const executableSignature=async(path:string)=>parseSignature(await request('executable_signature',{path}));
