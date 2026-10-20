import{describe,it,expect}from'vitest';import{parseAuthenticationPage,authenticationMeaning,logonTypeLabel,identityLabel}from'./identityActivity';
const empty={name:null,domain:null,sid:null};
const event={schema_version:1,event_id:'event-1',host_id:'host',boot_id:null,runtime_instance_id:'runtime',sensor_id:'windows.event_log.Security',sequence:1,wall_clock_time:1000,monotonic_time:1,observation_time:1000,ingestion_time:1000,event_category:'windows_event_log',event_type:'windows.event_log.4648',severity:'info',actor_identity:null,logon_session:null,process:null,parent_process:null,target:{kind:'windows_event_record',identifier:'Security:Microsoft-Windows-Security-Auditing:1'},operation:'observe',result:'recorded_by_windows',causal_parents:[],correlation_ids:[],raw_evidence_reference:'raw-1',integrity_metadata:{normalization_version:1,source_integrity:null}};
const context={evidence_status:'verified',account:{name:'alice',domain:'PC',sid:null},subject:empty,logon_type:null,logon_id:'0x3e7',address:'192.0.2.1',workstation:null,caller_path:'C:\\Windows\\System32\\svchost.exe',caller_pid:42,target_server:null,authentication_package:null,privileges:[]};
const row={position:10,kind:'explicit_credentials',event,context};
describe('authentication activity boundary',()=>{
 it('keeps names and facts without inventing a successful explicit-credential logon',()=>{expect(parseAuthenticationPage({records:[row],next_before:null}).records[0].context.account.name).toBe('alice');expect(authenticationMeaning('explicit_credentials','it')).toContain('non conferma');expect(logonTypeLabel(10,'it')).toBe('Desktop remoto');expect(identityLabel(empty,'it')).toBe('Account non disponibile');});
 it('rejects forged kind, duplicate records, bad cursors and fields from unverified evidence',()=>{
  for(const value of [{records:[{...row,kind:'successful_logon'}],next_before:null},{records:[row,row],next_before:null},{records:[row],next_before:10},{records:[{...row,context:{...context,evidence_status:'invalid'}}],next_before:null},{records:[{...row,context:{...context,caller_pid:-1}}],next_before:null},{records:[{...row,context:{...context,privileges:['<script>']}}],next_before:null}])expect(()=>parseAuthenticationPage(value)).toThrow();
  expect(()=>parseAuthenticationPage({records:[row],next_before:null},9)).toThrow();
  expect(()=>parseAuthenticationPage({records:[row],next_before:null},null,'failed_logon')).toThrow();
 });
 it('allows unknown context and validates a full page continuation',()=>{
  const unknown={...context,evidence_status:'unsupported_version',account:empty,subject:empty,address:null,logon_id:null,caller_path:null,caller_pid:null};expect(parseAuthenticationPage({records:[{...row,context:unknown}],next_before:null}).records).toHaveLength(1);
  const rows=Array.from({length:5},(_,i)=>({...row,position:10-i,event:{...event,event_id:`event-${i}`}}));expect(parseAuthenticationPage({records:rows,next_before:6}).next_before).toBe(6);
 });
});

it('accepts account lifecycle categories only with the corresponding event ID',()=>{
 for(const [kind,id] of [['account_created',4720],['account_enabled',4722],['account_disabled',4725],['account_deleted',4726]] as const){
  const record={...row,kind,event:{...event,event_type:`windows.event_log.${id}`}};
  expect(parseAuthenticationPage({records:[record],next_before:null},null,kind).records[0].kind).toBe(kind);
  expect(authenticationMeaning(kind,'it')).toContain('Windows registra');
  expect(authenticationMeaning(kind,'en')).toContain('Windows recorded');
  expect(()=>parseAuthenticationPage({records:[{...record,event}],next_before:null})).toThrow();
 }
});
