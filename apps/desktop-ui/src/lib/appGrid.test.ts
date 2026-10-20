import { expect, it } from 'vitest';
import { installDate, sortApps } from './appGrid';
import type { InstalledSoftware } from './appControl';
const app = (id: string, date: string | null): InstalledSoftware => ({ id, display_name: id, install_date: date, publisher: null, version: null, install_location: null, scope: 'user', registry_view: '64', source: 'windows_uninstall_registry', uninstall_key: id });
it('sorts genuine declared dates with unknowns last and stable name ties', () => {
  const items = [app('unknown', null), app('old', '20250101'), app('new', '20261012')];
  expect(sortApps(items, 'newest').map(a => a.id)).toEqual(['new', 'old', 'unknown']);
  expect(sortApps(items, 'oldest').map(a => a.id)).toEqual(['old', 'new', 'unknown']);
  expect(items[0].id).toBe('unknown');
});
it('does not fabricate dates for absent or malformed installer metadata', () => {
  for (const value of [undefined, null, '', '20260230', '20260132', '2026-10-12', '<script>', '20261301']) expect(installDate(value)).toBeNull();
  expect(installDate('20240229')).toBe('2024-02-29');
});
