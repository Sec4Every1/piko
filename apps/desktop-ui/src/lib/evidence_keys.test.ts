import { beforeEach, describe, expect, it, vi } from 'vitest';
import { invoke, isTauri } from '@tauri-apps/api/core';
import { beginEvidenceKeyBackup, beginEvidenceProtection, confirmEvidenceKeyBackup,
  getEvidenceKeyStatus, parseEvidenceKeyStatus, readEvidenceKeyBackup } from './evidence_keys';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn() }));
const native = vi.mocked(invoke);
const ticket = '11111111-1111-4111-8111-111111111111';
const other = '22222222-2222-4222-8222-222222222222';
const code = 'AGE-SECRET-KEY-1SYNTHETICTEST';
const ready = () => ({ state: 'ready', backup_confirmed: true, new_raw_enabled: false,
  recoverable_mode: false });

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(isTauri).mockReturnValue(true);
});

describe('evidence key desktop boundaries', () => {
  it('defaults an absent activation marker to false and rejects contradictory status', () => {
    expect(parseEvidenceKeyStatus(ready()).activation_pending).toBe(false);
    for (const value of [null, [], {}, { ...ready(), state: 'active' },
      { ...ready(), backup_confirmed: false }, { ...ready(), state: 'backup_required' },
      { ...ready(), state: 'not_prepared' }, { ...ready(), new_raw_enabled: 'false' },
      { ...ready(), recoverable_mode: null }, { ...ready(), activation_pending: 1 }]) {
      expect(() => parseEvidenceKeyStatus(value)).toThrow('Invalid evidence key response');
    }
  });

  it('rejects invalid expired and excessively long-lived backup and activation tickets', async () => {
    const now = Date.now();
    for (const begin of [beginEvidenceKeyBackup, beginEvidenceProtection]) {
      for (const value of [null, { id: 'invalid', expires_at_unix_ms: now + 1000 },
        { id: '00000000-0000-0000-0000-000000000000', expires_at_unix_ms: now + 1000 },
        { id: ticket, expires_at_unix_ms: 0 }, { id: ticket, expires_at_unix_ms: now + 600_000 },
        { id: ticket, expires_at_unix_ms: Number.MAX_SAFE_INTEGER + 1 },
        { id: ticket, expires_at_unix_ms: now + 1000.5 }]) {
        native.mockResolvedValueOnce(value);
        await expect(begin()).rejects.toThrow('Invalid evidence key response');
      }
      native.mockResolvedValueOnce({ id: ticket, expires_at_unix_ms: Date.now() + 60_000 });
      expect((await begin()).id).toBe(ticket);
    }
  });

  it('binds backup replies to the requested ticket and validates recovery material', async () => {
    const reply = { ticket_id: ticket, archive_id: other, recipient: 'age1synthetic', recovery_code: code };
    for (const patch of [{ ticket_id: other }, { archive_id: 'invalid' },
      { recipient: 'wrong-prefix' }, { recipient: 'age1' + 'a'.repeat(129) },
      { recovery_code: 'AGE-SECRET-KEY-1lowercase' }, { recovery_code: 'x'.repeat(129) },
      { recovery_code: null }]) {
      native.mockResolvedValueOnce({ ...reply, ...patch });
      await expect(readEvidenceKeyBackup(ticket)).rejects.toThrow('Invalid evidence key response');
    }
    native.mockResolvedValueOnce(reply);
    await expect(readEvidenceKeyBackup(ticket)).resolves.toEqual(reply);
  });

  it('never invokes the native bridge for invalid confirmation input', async () => {
    for (const [id, input] of [['invalid', code], [ticket, ''], [ticket, 'AGE-SECRET-KEY-1bad'],
      [ticket, 'AGE-SECRET-KEY-1' + 'A'.repeat(129)], [ticket, code + '\n']]) {
      await expect(confirmEvidenceKeyBackup(id, input)).rejects.toThrow();
    }
    expect(native).not.toHaveBeenCalled();
  });

  it('masks invocation failures containing the submitted secret', async () => {
    native.mockRejectedValueOnce(new Error(`backend rejected secret ${code}`));
    const failure = await confirmEvidenceKeyBackup(ticket, code).catch(reason => reason);
    expect(failure).toMatchObject({ code: 'unavailable', message: 'Evidence key operation unavailable' });
    expect(String(failure)).not.toContain(code);
    expect(native).toHaveBeenCalledWith('confirm_evidence_key_backup', { ticketId: ticket, code });
  });

  it('refuses browser access before invoking native operations', async () => {
    vi.mocked(isTauri).mockReturnValue(false);
    await expect(getEvidenceKeyStatus()).rejects.toMatchObject({ code: 'browser' });
    expect(native).not.toHaveBeenCalled();
  });
});
