import { invoke, isTauri } from '@tauri-apps/api/core';
export interface SoftwareMetadata { id: string; name: string; publisher: string | null; version: string | null; install_location: string | null }
export interface SoftwareChange { sequence: number; observed_at: number; kind: 'appeared' | 'reappeared' | 'disappeared' | 'version_changed' | 'metadata_changed'; before: SoftwareMetadata | null; after: SoftwareMetadata | null }
export interface SoftwareHistory { entries: SoftwareChange[]; observed_at: number; first_observed_at: number; inventory_complete: boolean; has_more: boolean; retained_limit: number }
const obj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === 'string' && v.length <= 16384;
const optional = (v: unknown) => v === null || text(v);
const time = (v: unknown) => Number.isSafeInteger(v) && Number(v) > 0 && Number(v) <= 8.64e12;
const metadata = (v: unknown): v is SoftwareMetadata => obj(v) && text(v.id) && v.id.length > 0 && text(v.name) && optional(v.publisher) && optional(v.version) && optional(v.install_location);
export function parseHistory(v: unknown): SoftwareHistory {
  if (!obj(v) || !time(v.observed_at) || !time(v.first_observed_at) || typeof v.inventory_complete !== 'boolean' || typeof v.has_more !== 'boolean' || v.retained_limit !== 2000 || !Array.isArray(v.entries) || v.entries.length > 50) throw new Error('Invalid software history response');
  let previous = Infinity;
  for (const e of v.entries) {
    if (!obj(e) || !Number.isSafeInteger(e.sequence) || Number(e.sequence) <= 0 || Number(e.sequence) >= previous || !time(e.observed_at) || typeof e.kind !== 'string' || !['appeared','reappeared','disappeared','version_changed','metadata_changed'].includes(e.kind) || !(e.before === null || metadata(e.before)) || !(e.after === null || metadata(e.after)) || (e.kind === 'disappeared' ? e.after !== null || e.before === null : e.after === null) || (e.kind === 'appeared' && e.before !== null) || (['reappeared','version_changed','metadata_changed'].includes(e.kind) && e.before === null) || (metadata(e.before) && metadata(e.after) && e.before.id !== e.after.id)) throw new Error('Invalid software change');
    previous = Number(e.sequence);
  }
  return v as unknown as SoftwareHistory;
}
export async function softwareHistory(beforeSequence: number | null = null): Promise<SoftwareHistory> {
  if (!isTauri()) throw new Error('Apri piko con Open-Piko.cmd per leggere lo storico applicazioni.');
  return parseHistory(await invoke('software_history', { beforeSequence }));
}
