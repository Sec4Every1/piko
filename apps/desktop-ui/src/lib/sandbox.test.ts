import { expect, it } from 'vitest';
import { parseSandboxPlan, parseSandboxSession, sandboxStatus } from './sandbox';
const plan = {id:'bc1e69ce-8b01-4d27-955a-6078d3d65ea3',executable:'C:\\Apps\\test.exe',sha256:'a'.repeat(64),expires_at:1800000000};
it('rejects missing identities, malformed hashes and invalid expiry', () => {
  expect(parseSandboxPlan(plan)).toEqual(plan);
  for (const value of [null, {...plan,id:'x'}, {...plan,sha256:'safe'}, {...plan,expires_at:Infinity}, {...plan,expires_at:-1}]) expect(()=>parseSandboxPlan(value)).toThrow();
});
it('requires a persisted profile and timestamp', () => {
  const session = {...plan,configuration:'C:\\Sessions\\piko.wsb',created_at:1800000000};
  expect(parseSandboxSession(session)).toEqual(session);
  expect(()=>parseSandboxSession({...session,configuration:'C:\\run.cmd'})).toThrow();
  expect(()=>parseSandboxSession({...session,created_at:null})).toThrow();
});
it('does not simulate native availability in a browser', async () => { await expect(sandboxStatus()).rejects.toThrow('Open-Piko.cmd'); });
