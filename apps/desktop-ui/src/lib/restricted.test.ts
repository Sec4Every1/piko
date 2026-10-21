import { describe, expect, it } from 'vitest';
import { parseRestrictedPlan, parseRestrictedSession } from './restricted';
const policy = { network_capabilities: 0, max_processes: 1, memory_limit_bytes: 536870912, original_unchanged: true, staged_read_only: true, stop_on_ui_exit: true };
const plan = { id: '12345678-1234-1234-1234-123456789abc', executable: 'C:\\Downloads\\app.exe', sha256: 'a'.repeat(64), expires_at: 1900000000, policy };
describe('restricted trial contract', () => {
  it('requires an explicit mode matching the exact capability count', () => {
    expect(parseRestrictedPlan({...plan,policy:{...policy,network_access:'internet_client',network_capabilities:1}}).policy.network_access).toBe('internet_client');
    for (const p of [{...policy,network_access:'internet_client'}, {...policy,network_access:'none',network_capabilities:1},
      {...policy,network_access:'private_network',network_capabilities:1}, {...policy,network_access:'internet_client',network_capabilities:2}]) {
      expect(() => parseRestrictedPlan({...plan,policy:p})).toThrow();
    }
  });
  it('accepts only actual fixed restrictions', () => { expect(parseRestrictedPlan(plan)).toEqual(plan); for (const p of [{...policy, network_capabilities:1}, {...policy, staged_read_only:false}, {...policy, max_processes:0}, {...policy, memory_limit_bytes:Infinity}, {...policy, stop_on_ui_exit:false}]) expect(() => parseRestrictedPlan({...plan,policy:p})).toThrow(); });
  it('does not treat missing execution state as running', () => { const session = {...plan, created_at:1900000000,pid:12,running:false,data_directory:'C:\\Packages\\trial'}; expect(parseRestrictedSession(session).running).toBe(false); for (const bad of [{...session,running:undefined},{...session,pid:0},{...session,pid:2**32},{...session,data_directory:''},{...session,sha256:'guess'}]) expect(() => parseRestrictedSession(bad)).toThrow(); });
});
