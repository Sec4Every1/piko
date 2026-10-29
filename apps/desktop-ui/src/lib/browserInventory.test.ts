import { describe, expect, it } from 'vitest';
import { parseBrowserInventory } from './browserInventory';
const sample = () => ({
  candidates: [{ family: 'chrome', registration_id: 'registry', registered_name: 'Google Chrome', registered_publisher: null, registered_version: '1', scope: 'machine' }],
  registration_scan_complete: true, truncated: false, oversized_metadata: false,
  browser_discovery_complete: false, profiles_known: false, executable_identity_verified: false, protection_status_known: false,
});
describe('browser inventory response', () => {
  it('preserves unverified machine registrations and unknown capabilities', () => {
    const result = parseBrowserInventory(sample());
    expect(result.candidates[0].registered_name).toBe('Google Chrome');
    expect(result.protection_status_known).toBe(false);
  });
  it('rejects claims of verified security or user scope', () => {
    expect(() => parseBrowserInventory({ ...sample(), protection_status_known: true })).toThrow();
    expect(() => parseBrowserInventory({ ...sample(), profiles_known: true })).toThrow();
    expect(() => parseBrowserInventory({ ...sample(), candidates: [{ ...sample().candidates[0], scope: 'viewer' }] })).toThrow();
  });
  it('rejects invalid and inconsistent replies', () => {
    expect(() => parseBrowserInventory({ ...sample(), truncated: true })).toThrow();
    expect(() => parseBrowserInventory({ ...sample(), candidates: Array(129).fill(sample().candidates[0]) })).toThrow();
    expect(() => parseBrowserInventory({ ...sample(), candidates: [{ ...sample().candidates[0], registered_version: 'bad\0version' }] })).toThrow();
    expect(() => parseBrowserInventory({ ...sample(), candidates: [{ ...sample().candidates[0], family: 'other' }] })).toThrow();
  });
});
