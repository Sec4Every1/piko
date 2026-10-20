import { describe,it,expect } from 'vitest';
import { parseRegistryHistory,scopes,safeRegistryText } from './registryHistory';
const value={scope_id:scopes[0],value_name:'Test',value_type:1,data_hex:'4100',text:'A'};
const sample=()=>({entries:[{sequence:2,observed_at:2,kind:'changed',before:value,after:{...value,text:'B',data_hex:'4200'}}],scopes:scopes.map(id=>({id,complete:true,warnings:[]})),observed_at:3,first_observed_at:1,has_more:false,retained_limit:500});
describe('observed registry history',()=>{
  it('preserves both states and incomplete coverage',()=>{const h=sample();h.scopes[0].complete=false;expect(parseRegistryHistory(h).entries[0].before?.text).toBe('A');expect(safeRegistryText('A\u202eB')).toBe('A\\u202eB');});
  it('rejects mismatched identities, raw bounds, duplicate scopes and removal shapes',()=>{let h=sample();h.entries[0].after.value_name='Other';expect(()=>parseRegistryHistory(h)).toThrow();h=sample();h.entries[0].after.data_hex='0';expect(()=>parseRegistryHistory(h)).toThrow();h=sample();h.scopes[1].id=h.scopes[0].id;expect(()=>parseRegistryHistory(h)).toThrow();h=sample();h.entries[0].kind='not_observed';expect(()=>parseRegistryHistory(h)).toThrow();});
});
