import { ApiError } from './api';
import { invoke, isTauri } from '@tauri-apps/api/core';

export async function loadBrowserInventory(): Promise<unknown> {
  if (!isTauri()) throw new ApiError('browser', 'Servizio Piko non disponibile.');
  try { return await invoke('browser_inventory'); }
  catch (error) { throw new ApiError('unavailable', String(error)); }
}

export interface BrowserCandidate {
  family: 'edge' | 'chrome' | 'firefox';
  registration_id: string;
  registered_name: string;
  registered_publisher: string | null;
  registered_version: string | null;
  scope: 'machine';
}
export interface BrowserInventory {
  candidates: BrowserCandidate[];
  registration_scan_complete: boolean;
  truncated: boolean;
  oversized_metadata: boolean;
  browser_discovery_complete: false;
  profiles_known: false;
  executable_identity_verified: false;
  protection_status_known: false;
}

const invalid = () => new ApiError('invalid_response', 'Invalid browser inventory response');
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const text = (value: unknown): value is string => typeof value === 'string'
  && new TextEncoder().encode(value).length <= 4096 && !value.includes('\0');
const optionalText = (value: unknown): value is string | null => value === null || text(value);

/** Reject unexpected capability or scope claims; unavailable data never becomes clean status. */
export function parseBrowserInventory(value: unknown): BrowserInventory {
  if (!object(value) || !Array.isArray(value.candidates) || value.candidates.length > 128
      || typeof value.registration_scan_complete !== 'boolean'
      || typeof value.truncated !== 'boolean' || typeof value.oversized_metadata !== 'boolean'
      || value.browser_discovery_complete !== false || value.profiles_known !== false
      || value.executable_identity_verified !== false || value.protection_status_known !== false
      || ((value.truncated || value.oversized_metadata) && value.registration_scan_complete)) throw invalid();
  const candidates: BrowserCandidate[] = value.candidates.map((item: unknown) => {
    if (!object(item) || !['edge', 'chrome', 'firefox'].includes(String(item.family))
        || !text(item.registration_id) || item.registration_id.length === 0
        || !text(item.registered_name) || item.registered_name.length === 0
        || !optionalText(item.registered_publisher) || !optionalText(item.registered_version)
        || item.scope !== 'machine') throw invalid();
    return {
      family: item.family as BrowserCandidate['family'], registration_id: item.registration_id,
      registered_name: item.registered_name, registered_publisher: item.registered_publisher,
      registered_version: item.registered_version, scope: 'machine',
    };
  });
  return {
    candidates, registration_scan_complete: value.registration_scan_complete,
    truncated: value.truncated, oversized_metadata: value.oversized_metadata,
    browser_discovery_complete: false, profiles_known: false,
    executable_identity_verified: false, protection_status_known: false,
  };
}
