import { expect,it } from 'vitest';
import { parseHistory } from './softwareHistory';
const meta={id:'app',name:'Example',publisher:null,version:'1',install_location:null};
const event={sequence:2,observed_at:1800000000000,kind:'version_changed',before:meta,after:{...meta,version:'2'}};
const history={entries:[event],observed_at:1800000000000,first_observed_at:1790000000000,inventory_complete:false,has_more:false,retained_limit:2000};
it('preserves explicit partial coverage and unknown metadata',()=>{expect(parseHistory(history)).toEqual(history);});
it('rejects malformed change identities, order and unsupported kinds',()=>{
  for(const entries of [[{...event,after:{...meta,id:'other'}}],[{...event,kind:'malware'}],[event,event],[{...event,kind:'disappeared'}],[{...event,sequence:-1}],[{...event,after:null}]])expect(()=>parseHistory({...history,entries})).toThrow();
  expect(()=>parseHistory({...history,entries:Array(51).fill(event)})).toThrow();
});
it('rejects non-string kinds without coercing them to valid labels',()=>{
  for(const kind of [['appeared'],['version_changed'],{},null,1,true])
    expect(()=>parseHistory({...history,entries:[{...event,kind}]})).toThrow();
  expect(()=>parseHistory({...history,entries:[{...event,kind:'appeared',before:meta}]})).toThrow();
  expect(parseHistory({...history,entries:[{...event,kind:'appeared',before:null}]}).entries[0].kind).toBe('appeared');
});
