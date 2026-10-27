import { describe, expect, it } from 'vitest';
import { parseArchiveMaintenance } from './maintenance';

const completed = () => ({
  enabled: true, state: 'completed_batch', sampled_at_unix_ms: 100,
  scanned: 32, changed: 32, logical_bytes_saved: 4 * 1024 * 1024,
  cycle_complete: false, detail: null,
});

describe('archive maintenance response boundaries', () => {
  it('accepts bounded results and explicit unsampled states', () => {
    expect(parseArchiveMaintenance(completed())).toEqual(completed());
    for (const state of ['waiting', 'running', 'completed_batch', 'blocked']) {
      const value = { ...completed(), state, sampled_at_unix_ms: null, scanned: 0,
        changed: 0, logical_bytes_saved: 0, cycle_complete: true };
      expect(parseArchiveMaintenance(value)).toEqual(value);
    }
    expect(parseArchiveMaintenance({ ...completed(), sampled_at_unix_ms: 8.64e15 }).sampled_at_unix_ms).toBe(8.64e15);
  });

  it('rejects out-of-range counters, times and inconsistent changed counts', () => {
    for (const patch of [
      { scanned: 33 }, { scanned: -1 }, { scanned: 0.5 },
      { changed: 33 }, { changed: -1 }, { changed: 0.5 },
      { scanned: 1, changed: 2 }, { logical_bytes_saved: 4 * 1024 * 1024 + 1 },
      { logical_bytes_saved: -1 }, { logical_bytes_saved: 1.5 },
      { sampled_at_unix_ms: -1 }, { sampled_at_unix_ms: 8.64e15 + 1 },
      { sampled_at_unix_ms: 1.5 }, { scanned: NaN }, { changed: Infinity },
      { logical_bytes_saved: Number.MAX_SAFE_INTEGER + 1 },
    ]) {
      expect(() => parseArchiveMaintenance({ ...completed(), ...patch })).toThrow();
    }
  });

  it('bounds detail by 2048 UTF-8 bytes rather than character count', () => {
    for (const detail of ['x'.repeat(2048), '\u00e9'.repeat(1024), '\ud83d\udd12'.repeat(512)]) {
      expect(parseArchiveMaintenance({ ...completed(), detail }).detail).toBe(detail);
      expect(() => parseArchiveMaintenance({ ...completed(), detail: detail + 'x' })).toThrow();
    }
    expect(() => parseArchiveMaintenance({ ...completed(), detail: '\u00e9'.repeat(1025) })).toThrow();
  });

  it('rejects unavailable and malformed responses without inventing success', () => {
    for (const value of [undefined, null, [], 'unavailable', {}, { error: 'worker unavailable' },
      { ...completed(), state: 'success' }, { ...completed(), state: {} },
      { ...completed(), enabled: 1 }, { ...completed(), cycle_complete: 'false' },
      { ...completed(), detail: {} }, { ...completed(), sampled_at_unix_ms: undefined },
    ]) {
      expect(() => parseArchiveMaintenance(value)).toThrow();
    }
  });
});
