import { invoke, isTauri } from '@tauri-apps/api/core';
export interface RegistryValue { scope_id: string; value_name: string; value_type: number; data_hex: string; text: string | null }
export interface RegistryChange { sequence: number; observed_at: number; kind: 'appeared'|'reappeared'|'changed'|'not_observed'; before: RegistryValue|null; after: RegistryValue|null }
export interface RegistryHistory { entries: RegistryChange[]; scopes: {id:string; complete:boolean; warnings:string[]}[]; observed_at:number; first_observed_at:number; has_more:boolean; retained_limit:500 }
export const scopes = ['HKLM','HKCU'].flatMap(h => ['64','32'].flatMap(v => ['Run','RunOnce'].map(k => h+':'+v+':SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\'+k)));
const obj = (v:unknown):v is Record<string,unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v:unknown,n:number):v is string => typeof v==='string' && v.length<=n;
const time = (v:unknown) => Number.isSafeInteger(v) && Number(v)>0 && Number(v)<=8.64e12;
const value = (v:unknown):v is RegistryValue => obj(v) && scopes.includes(String(v.scope_id)) && str(v.value_name,2048) && Number.isInteger(v.value_type) && Number(v.value_type)>=0 && Number(v.value_type)<=0xffffffff && str(v.data_hex,4096) && /^(?:[0-9a-f]{2})*$/.test(v.data_hex) && (v.text===null || str(v.text,4096));
export function parseRegistryHistory(v:unknown):RegistryHistory {
  if (!obj(v) || !time(v.observed_at) || !time(v.first_observed_at) || v.retained_limit!==500 || typeof v.has_more!=='boolean' || !Array.isArray(v.scopes) || v.scopes.length!==8 || !Array.isArray(v.entries) || v.entries.length>50) throw new Error('Invalid registry history');
  const seen = new Set<string>();
  for (const s of v.scopes) { if (!obj(s) || !scopes.includes(String(s.id)) || seen.has(String(s.id)) || typeof s.complete!=='boolean' || !Array.isArray(s.warnings) || s.warnings.length>8 || !s.warnings.every(w=>str(w,4096))) throw new Error('Invalid registry coverage'); seen.add(String(s.id)); }
  let previous=Infinity;
  for (const e of v.entries) {
    if (!obj(e) || !Number.isSafeInteger(e.sequence) || Number(e.sequence)<=0 || Number(e.sequence)>=previous || !time(e.observed_at) || !['appeared','reappeared','changed','not_observed'].includes(String(e.kind)) || !(e.before===null || value(e.before)) || !(e.after===null || value(e.after)) || (e.kind==='not_observed' ? e.before===null || e.after!==null : e.after===null) || (e.kind==='appeared' ? e.before!==null : e.before===null) || (value(e.before) && value(e.after) && (e.before.scope_id!==e.after.scope_id || e.before.value_name!==e.after.value_name))) throw new Error('Invalid registry change');
    previous=Number(e.sequence);
  }
  return v as unknown as RegistryHistory;
}
export async function registryHistory(beforeSequence:number|null=null):Promise<RegistryHistory> {
  if (!isTauri()) throw new Error('Apri piko con Open-Piko.cmd.');
  return parseRegistryHistory(await invoke('registry_history',{beforeSequence}));
}
export const safeRegistryText = (v:string) => v.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
