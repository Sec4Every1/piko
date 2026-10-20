import {invoke,isTauri} from '@tauri-apps/api/core';
import {ApiError,parseEvents,type SecurityEvent} from './api';
import type{Language}from'./i18n';
export type AuthenticationKind='successful_logon'|'failed_logon'|'explicit_credentials'|'special_privileges';
export interface AuthenticationIdentity{name:string|null;domain:string|null;sid:string|null}
export interface AuthenticationContext{evidence_status:'verified'|'missing'|'invalid'|'unsupported_version';account:AuthenticationIdentity;subject:AuthenticationIdentity;logon_type:number|null;logon_id:string|null;address:string|null;workstation:string|null;caller_path:string|null;caller_pid:number|null;target_server:string|null;authentication_package:string|null;privileges:string[]}
export interface AuthenticationRecord{position:number;kind:AuthenticationKind;event:SecurityEvent;context:AuthenticationContext}
export interface AuthenticationPage{records:AuthenticationRecord[];next_before:number|null}
const types:Record<AuthenticationKind,string>={successful_logon:'windows.event_log.4624',failed_logon:'windows.event_log.4625',explicit_credentials:'windows.event_log.4648',special_privileges:'windows.event_log.4672'};
export const authenticationKinds=Object.keys(types)as AuthenticationKind[];
const object=(v:unknown):v is Record<string,unknown>=>typeof v==='object'&&v!==null&&!Array.isArray(v);
const number=(v:unknown,max=Number.MAX_SAFE_INTEGER):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&v<=max;
const optionalText=(v:unknown,max=4096)=>v===null||(typeof v==='string'&&v.length<=max&&!/[\u0000-\u001f\u007f]/.test(v));
const identity=(v:unknown)=>object(v)&&optionalText(v.name)&&optionalText(v.domain)&&optionalText(v.sid,184);
export function parseAuthenticationPage(value:unknown,before:number|null=null,kind:AuthenticationKind|null=null,limit=5):AuthenticationPage{
 const invalid=():never=>{throw new ApiError('invalid_response','Invalid authentication activity');};
 if(!object(value)||!Array.isArray(value.records)||value.records.length>limit||!(value.next_before===null||(number(value.next_before)&&value.next_before>0)))return invalid();
 let previous=before??Number.MAX_SAFE_INTEGER;
 const seen=new Set<string>();
 for(const item of value.records){
  if(!object(item)||!number(item.position)||item.position===0||item.position>=previous||!authenticationKinds.includes(item.kind as AuthenticationKind)||(kind!==null&&item.kind!==kind))return invalid();
  const event=parseEvents([item.event])[0];const c=item.context;
  if(event.sensor_id!=='windows.event_log.Security'||event.event_category!=='windows_event_log'||event.event_type!==types[item.kind as AuthenticationKind]||seen.has(event.event_id)||!object(c)
   ||!['verified','missing','invalid','unsupported_version'].includes(String(c.evidence_status))||!identity(c.account)||!identity(c.subject)
   ||!(c.logon_type===null||number(c.logon_type,0xffffffff))||!(c.caller_pid===null||(number(c.caller_pid,0xffffffff)&&c.caller_pid>0))
   ||!optionalText(c.logon_id,18)||!optionalText(c.address,64)||!optionalText(c.workstation)||!optionalText(c.caller_path)||!optionalText(c.target_server)||!optionalText(c.authentication_package)
   ||!Array.isArray(c.privileges)||c.privileges.length>64||!c.privileges.every(p=>typeof p==='string'&&/^[a-zA-Z0-9_]{1,128}$/.test(p)))return invalid();
  if(c.evidence_status!=='verified'&&([...Object.values(c.account as Record<string,unknown>),...Object.values(c.subject as Record<string,unknown>),c.logon_type,c.logon_id,c.address,c.workstation,c.caller_path,c.caller_pid,c.target_server,c.authentication_package].some(v=>v!==null)||c.privileges.length))return invalid();
  previous=item.position;seen.add(event.event_id);
 }
 if(value.next_before!==null&&(value.records.length!==limit||value.records.at(-1)?.position!==value.next_before))return invalid();
 return value as unknown as AuthenticationPage;
}
export async function authenticationActivity(before:number|null,kind:AuthenticationKind|null):Promise<AuthenticationPage>{
 if(!isTauri())throw new ApiError('browser','Open the installed piko app.');
 let result:unknown;try{result=await invoke('authentication_activity',{filter:{before_position:before,kind,limit:5}});}catch(e){throw new ApiError('unavailable',String(e));}
 return parseAuthenticationPage(result,before,kind);
}
export function identityLabel(identity:AuthenticationIdentity,language:Language):string{return identity.name?(identity.domain?`${identity.domain}\\${identity.name}`:identity.name):identity.sid??(language==='it'?'Account non disponibile':'Account unavailable');}
export function authenticationLabel(kind:AuthenticationKind,language:Language):string{return (language==='it'?{successful_logon:'Accesso riuscito',failed_logon:'Accesso fallito',explicit_credentials:'Credenziali esplicite',special_privileges:'Privilegi assegnati'}:{successful_logon:'Successful logon',failed_logon:'Failed logon',explicit_credentials:'Explicit credentials',special_privileges:'Privileges assigned'})[kind];}
export function logonTypeLabel(type:number|null,language:Language):string{if(type===null)return'—';const labels:Record<number,[string,string]>={0:['Sistema','System'],2:['Accesso locale','Local sign-in'],3:['Accesso dalla rete','Network logon'],4:['Operazione pianificata','Batch'],5:['Servizio','Service'],7:['Sblocco','Unlock'],8:['Autenticazione di rete','Network authentication'],9:['Nuove credenziali in uscita','New outbound credentials'],10:['Desktop remoto','Remote desktop'],11:['Accesso con credenziali memorizzate','Cached sign-in'],12:['Desktop remoto con cache','Cached remote desktop'],13:['Sblocco con cache','Cached unlock']};return labels[type]?.[language==='it'?0:1]??(language==='it'?`Tipo ${type}`:`Type ${type}`);}
export function authenticationMeaning(kind:AuthenticationKind,language:Language):string{return (language==='it'?{
 successful_logon:'Windows ha creato una sessione di accesso per questo account. Non prova che la persona o il programma siano affidabili.',
 failed_logon:'Windows registra un tentativo di accesso fallito. Può dipendere da credenziali errate, salvate o scadute; un singolo errore non prova un attacco.',
 explicit_credentials:'Il programma chiamante ha tentato di usare credenziali indicate esplicitamente. Questo evento non conferma che l’accesso sia riuscito.',
 special_privileges:'Windows ha assegnato privilegi speciali alla sessione. Non prova che siano stati usati né che sia avvenuta un’escalation.'
 }:{successful_logon:'Windows created a logon session for this account. It does not establish that the person or program is trusted.',failed_logon:'Windows recorded a failed logon attempt. Incorrect, saved or expired credentials may cause it; one failure does not establish an attack.',explicit_credentials:'The caller attempted to use explicitly supplied credentials. This event does not establish a successful logon.',special_privileges:'Windows assigned special privileges to the session. It does not prove they were used or that privilege escalation occurred.'})[kind];}
