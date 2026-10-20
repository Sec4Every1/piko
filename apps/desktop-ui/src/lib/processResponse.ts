import {invoke,isTauri} from '@tauri-apps/api/core';
import {ApiError} from './api';
export interface ProcessTarget{pid:number;creation_filetime:string;executable:string;name:string;sid:string;session_id:number}
export interface ProcessPlan{id:string;target:ProcessTarget;expires_at:number}
export interface ProcessAction{id:string;target:ProcessTarget;requested_at:number;completed_at:number|null;status:'executing'|'terminated'|'uncertain'|'failed_or_uncertain';detail:string}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const integer=(v:unknown)=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
const text=(v:unknown,max:number):v is string=>typeof v==='string'&&v.length<=max;
const uuid=(v:unknown)=>text(v,36)&&/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(v);
const target=(v:unknown)=>object(v)&&integer(v.pid)&&(v.pid as number)>7&&(v.pid as number)<=0xffffffff&&text(v.creation_filetime,20)&&/^[1-9][0-9]{0,19}$/.test(v.creation_filetime)&&BigInt(v.creation_filetime)<=18446744073709551615n&&text(v.executable,8192)&&text(v.name,4096)&&text(v.sid,184)&&integer(v.session_id);
const bad=():never=>{throw new ApiError('invalid_response','Invalid process response');};
export function parseProcessPlan(v:unknown):ProcessPlan{if(!object(v)||!uuid(v.id)||!target(v.target)||!integer(v.expires_at)||(v.expires_at as number)>8.64e12)return bad();return v as unknown as ProcessPlan;}
export function parseProcessAction(v:unknown):ProcessAction{if(!object(v)||!uuid(v.id)||!target(v.target)||!integer(v.requested_at)||(v.requested_at as number)>8.64e12||(v.completed_at!==null&&(!integer(v.completed_at)||(v.completed_at as number)>8.64e12))||!['executing','terminated','uncertain','failed_or_uncertain'].includes(String(v.status))||!text(v.detail,4096))return bad();return v as unknown as ProcessAction;}
async function request(command:string,args?:Record<string,unknown>){if(!isTauri())throw new ApiError('browser','Open piko to manage processes');try{return await invoke(command,args);}catch(e){throw new ApiError('unavailable',String(e));}}
export const prepareProcessStop=async(pid:number,creationFiletime:string)=>parseProcessPlan(await request('prepare_process_stop',{pid,creationFiletime}));
export const confirmProcessStop=async(planId:string)=>parseProcessAction(await request('confirm_process_stop',{planId}));
export const discardProcessStop=async(planId:string)=>{await request('discard_process_stop',{planId});};
export const processActions=async()=>{const v=await request('process_actions');if(!Array.isArray(v)||v.length>50)return bad();return v.map(parseProcessAction);};
