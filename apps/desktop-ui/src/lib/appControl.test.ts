import { describe, expect, it } from 'vitest';
import { parseSignature, parseInventory, parseNetwork, parseNetworkPlan, softwareInventory } from './appControl';

const app = { id: 'machine-64-example', display_name: 'Example', publisher: 'Example Publisher', version: '1.0',
  install_location: 'C:\\Program Files\\Example', scope: 'machine', registry_view: '64',
  source: 'windows_uninstall_registry', uninstall_key: 'Example' };
const inventory = { entries: [app], complete: true, truncated: false, warnings: [] };
const network = { active_profiles: 2, profiles: [
  { id: 1, name: 'domain', active: false, firewall_enabled: true, block_all_inbound: false, excluded_interfaces: false },
  { id: 2, name: 'private', active: true, firewall_enabled: true, block_all_inbound: false, excluded_interfaces: false },
  { id: 4, name: 'public', active: false, firewall_enabled: true, block_all_inbound: false, excluded_interfaces: false },
], local_policy_modify_state: 'ok', rules: [], complete: true, warnings: [] };
const plan = { id: 'b16b49e1-13f1-41f6-bf5b-c893eb8cd70e', action: 'block', rule_id: 'a'.repeat(64),
  executable: 'C:\\Program Files\\Example\\app.exe', display_name: 'app.exe', sha256: 'b'.repeat(64), expires_at: 1800000000 };

describe('application inventory boundary', () => {
  it('preserves installer metadata and explicit partial results without claiming verified identity', () => {
    expect(parseInventory(inventory)).toEqual(inventory);
    expect(parseInventory({ ...inventory, complete: false, truncated: true, warnings: ['Access denied'],
      entries: [{ ...app, publisher: null, version: null, install_location: null }] })).toMatchObject({ complete: false, truncated: true });
  });
  it('rejects unsupported sources, oversized lists, malformed entries and non-text warnings', () => {
    for (const value of [null, { ...inventory, entries: [null] }, { ...inventory, entries: [{ ...app, source: 'guessed' }] },
      { ...inventory, entries: [{ ...app, display_name: 4 }] }, { ...inventory, entries: Array(4097).fill(app) },
      { ...inventory, warnings: [null] }, { ...inventory, warnings: Array(33).fill('warning') }]) {
      expect(() => parseInventory(value)).toThrow('Invalid application control response');
    }
  });
  it('reports the missing native bridge in a browser preview', async () => {
    await expect(softwareInventory()).rejects.toMatchObject({ code: 'browser' });
  });
});

describe('Windows firewall response boundary', () => {
  it('preserves disabled firewall, excluded interfaces and externally modified rules as observed', () => {
    const disabled = { ...network, profiles: network.profiles.map(profile => ({ ...profile, firewall_enabled: false, excluded_interfaces: true })),
      rules: [{ id: 'a'.repeat(64), executable: plan.executable, enabled: false, verified: false }],
      local_policy_modify_state: 'group_policy_override', complete: false, warnings: ['Partial read'] };
    expect(parseNetwork(disabled)).toEqual(disabled);
  });
  it('requires all three unique Windows profile identities', () => {
    for (const profiles of [[], network.profiles.slice(0, 2), [network.profiles[0], network.profiles[0], network.profiles[2]],
      network.profiles.map(profile => ({ ...profile, id: 8 })), [null, ...network.profiles.slice(1)]]) {
      expect(() => parseNetwork({ ...network, profiles })).toThrow();
    }
  });
  it('rejects inconsistent profile masks that could otherwise enable a block with no active profile checked', () => {
    for (const value of [{ ...network, active_profiles: -1 }, { ...network, active_profiles: 8 },
      { ...network, active_profiles: 4 }, { ...network, active_profiles: 2.5 },
      { ...network, profiles: network.profiles.map(profile => ({ ...profile, active: false })) }]) {
      expect(() => parseNetwork(value)).toThrow();
    }
    expect(parseNetwork({ ...network, active_profiles: 0, profiles: network.profiles.map(profile => ({ ...profile, active: false })) }).active_profiles).toBe(0);
  });
  it('bounds managed rules and rejects invalid rule identifiers or verified disabled rules', () => {
    const rule = { id: 'a'.repeat(64), executable: plan.executable, enabled: true, verified: true };
    for (const rules of [Array(513).fill(rule), [{ ...rule, id: 'not-a-rule' }], [{ ...rule, enabled: false }], [null]]) {
      expect(() => parseNetwork({ ...network, rules })).toThrow();
    }
  });
});

describe('network action preview boundary', () => {
  it('requires a fingerprint for blocking and preserves hash-free removal of a missing executable', () => {
    expect(parseNetworkPlan(plan)).toEqual(plan);
    expect(parseNetworkPlan({ ...plan, action: 'remove_block', sha256: null })).toMatchObject({ action: 'remove_block', sha256: null });
    expect(() => parseNetworkPlan({ ...plan, sha256: null })).toThrow();
    expect(() => parseNetworkPlan({ ...plan, action: 'remove_block' })).toThrow();
  });
  it('rejects malformed IDs, nonfinite or out-of-range timestamps, actions and fingerprints', () => {
    for (const value of [null, { ...plan, id: '-'.repeat(36) }, { ...plan, id: 'invalid' },
      { ...plan, expires_at: -1 }, { ...plan, expires_at: Infinity }, { ...plan, expires_at: Number.MAX_SAFE_INTEGER },
      { ...plan, action: 'allow_all' }, { ...plan, sha256: 'x'.repeat(64) }, { ...plan, rule_id: 'x'.repeat(64) }]) {
      expect(() => parseNetworkPlan(value)).toThrow();
    }
  });
});

it('preserves independent directions and rejects unsupported scope',()=>{expect(parseNetworkPlan({...plan,direction:'inbound'}).direction).toBe('inbound');expect(()=>parseNetworkPlan({...plan,direction:'both'})).toThrow();const rule={id:'a'.repeat(64),executable:plan.executable,enabled:true,verified:true};expect(parseNetwork({...network,rules:[{...rule,direction:'inbound'},{...rule,direction:'outbound'}]}).rules).toHaveLength(2);expect(()=>parseNetwork({...network,rules:[{...rule,direction:'other'}]})).toThrow();});

it('signature success requires the exact zero status and explicit incomplete coverage',()=>{const v={executable:plan.executable,sha256:'a'.repeat(64),status:'verified_locally',native_status:'0x00000000',checked_at:100,revocation_checked:false,catalog_checked:false};expect(parseSignature(v).status).toBe('verified_locally');expect(()=>parseSignature({...v,native_status:'0x800B0100'})).toThrow();expect(()=>parseSignature({...v,revocation_checked:true})).toThrow();expect(parseSignature({...v,status:'no_embedded_signature',native_status:'0x800B0100'}).status).toBe('no_embedded_signature');});
