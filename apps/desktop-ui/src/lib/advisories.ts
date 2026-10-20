import { invoke, isTauri } from '@tauri-apps/api/core';
export interface AdvisoryProduct { product_id: string; display_name: string; covered_versions: string[] }
export interface Advisory { id: string; product_id: string; affected_versions: string[]; kind: 'vulnerability'|'end_of_support'; title: string; summary: string; cvss_x100: number|null; cvss_version: string|null; cvss_vector: string|null; source_url: string; published_at: number; remediation: string[] }
export interface ProductBinding { application_id: string; application_name: string; publisher: string|null; installer_version: string|null; product_id: string; exact_version: string; bound_at: number }
export type AdvisoryMatchState = 'matched'|'no_known_advisory'|'product_not_covered'|'version_not_covered'|'metadata_changed'|'not_observed'|'no_feed';
export interface ApplicationAssessment { binding: ProductBinding; state: AdvisoryMatchState; advisory_count: number }
export interface AdvisoryFeedStatus { source_name: string; source_url: string; generated_at: number; expires_at: number; imported_at: number; sha256: string; advisory_count: number; product_count: number; products: AdvisoryProduct[]; stale: boolean; authenticity: 'not_verified' }
export interface AdvisorySnapshot { checked_at: number; inventory_complete: boolean; unbound_count: number; feed: AdvisoryFeedStatus|null; entries: ApplicationAssessment[]; advisories: Advisory[] }
const object = (v: unknown): v is Record<string,unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const text = (v: unknown,max: number): v is string => typeof v === 'string' && v.length>0 && new TextEncoder().encode(v).length<=max && v===v.trim() && !/[\p{Cc}\u202a-\u202e\u2066-\u2069]/u.test(v);
const identifier = (v: unknown): v is string => text(v,120) && /^[A-Za-z0-9_.:-]+$/.test(v);
const version = (v: unknown): v is string => text(v,80) && /^[A-Za-z0-9_.+-]+$/.test(v);
const number = (v: unknown,max: number,min=0): v is number => Number.isSafeInteger(v) && Number(v)>=min && Number(v)<=max;
const time = (v: unknown): v is number => number(v,8640000000,1);
export function validAdvisorySource(v: unknown): v is string {
  if (!text(v,2048) || !/^[\x21-\x7e]+$/.test(v) || /[\\%#"<>`]/.test(v) || !v.startsWith('https://')) return false;
  const host=v.slice(8).split('/')[0];
  return host.length<=253 && host.includes('.') && !/^[\d.]+$/.test(host) && host.split('.').every(part=>part.length>0 && part.length<=63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(part));
}
function product(v:unknown): v is AdvisoryProduct { return object(v) && identifier(v.product_id) && text(v.display_name,160) && Array.isArray(v.covered_versions) && v.covered_versions.length>0 && v.covered_versions.length<=100 && v.covered_versions.every(version) && new Set(v.covered_versions).size===v.covered_versions.length; }
function cvss(v:Record<string,unknown>):boolean {
  if(v.cvss_x100===null) return v.cvss_version===null && v.cvss_vector===null;
  return number(v.cvss_x100,1000) && v.cvss_x100%10===0 && ['3.0','3.1','4.0'].includes(String(v.cvss_version)) && text(v.cvss_vector,512) && v.cvss_vector.startsWith('CVSS:'+v.cvss_version+'/') && v.cvss_vector.split('/').length<=33 && v.cvss_vector.split('/').slice(1).every(m=>/^[A-Za-z0-9]+:[A-Za-z0-9]+$/.test(m));
}
function advisory(v:unknown): v is Advisory {
  return object(v) && identifier(v.id) && identifier(v.product_id) && ['vulnerability','end_of_support'].includes(String(v.kind)) && text(v.title,160) && text(v.summary,1000) && cvss(v) && (v.kind!=='end_of_support' || v.cvss_x100===null) && validAdvisorySource(v.source_url) && time(v.published_at) && Array.isArray(v.affected_versions) && v.affected_versions.length>0 && v.affected_versions.length<=100 && v.affected_versions.every(version) && new Set(v.affected_versions).size===v.affected_versions.length && Array.isArray(v.remediation) && v.remediation.length>0 && v.remediation.length<=8 && v.remediation.every(x=>text(x,512));
}
function binding(v:unknown): v is ProductBinding { return object(v) && text(v.application_id,2048) && text(v.application_name,2048) && (v.publisher===null || text(v.publisher,2048)) && (v.installer_version===null || text(v.installer_version,2048)) && identifier(v.product_id) && version(v.exact_version) && time(v.bound_at); }
export function parseAdvisories(v:unknown): AdvisorySnapshot {
  if (!object(v) || !time(v.checked_at) || typeof v.inventory_complete!=='boolean' || !number(v.unbound_count,3072) || !Array.isArray(v.entries) || v.entries.length>512) throw new Error('Invalid advisory snapshot');
  if (v.feed!==null) {
    const f=v.feed;
    if (!object(f) || !text(f.source_name,120) || !validAdvisorySource(f.source_url) || !time(f.generated_at) || !time(f.expires_at) || f.expires_at<=f.generated_at || f.expires_at-f.generated_at>90*86400 || !time(f.imported_at) || typeof f.sha256!=='string' || !/^[a-f0-9]{64}$/.test(f.sha256) || !number(f.advisory_count,1000) || !number(f.product_count,256,1) || !Array.isArray(f.products) || f.products.length!==f.product_count || !f.products.every(product) || new Set(f.products.map(p=>p.product_id)).size!==f.product_count || typeof f.stale!=='boolean' || f.stale!==(v.checked_at>=f.expires_at) || f.authenticity!=='not_verified') throw new Error('Invalid advisory feed status');
  }
  if (!Array.isArray(v.advisories) || v.advisories.length>1000 || !v.advisories.every(advisory) || new Set(v.advisories.map(a=>a.id)).size!==v.advisories.length || (v.feed===null ? !!v.advisories.length : v.advisories.length!==(v.feed as unknown as AdvisoryFeedStatus).advisory_count)) throw new Error('Invalid advisory catalogue');
  const catalogue=v.advisories;
  const feed=v.feed as AdvisoryFeedStatus|null;
  if (feed && (feed.generated_at>v.checked_at+300 || catalogue.some(a=>{
    const p=feed.products.find(p=>p.product_id===a.product_id);
    return !p || a.published_at>feed.generated_at || a.affected_versions.some(version=>!p.covered_versions.includes(version));
  }))) throw new Error('Advisory catalogue is outside declared coverage');
  const ids=new Set<string>();
  for (const e of v.entries) {
    if (!object(e) || !binding(e.binding) || ids.has(e.binding.application_id) || !['matched','no_known_advisory','product_not_covered','version_not_covered','metadata_changed','not_observed','no_feed'].includes(String(e.state)) || !number(e.advisory_count,1000) || (e.state==='matched' ? e.advisory_count===0 || v.feed===null : e.advisory_count!==0)) throw new Error('Invalid application assessment');
    const matchedBinding=e.binding;
    const matchCount=catalogue.filter(a=>a.product_id===matchedBinding.product_id && a.affected_versions.includes(matchedBinding.exact_version)).length;
    const coveredProduct=feed?.products.find(p=>p.product_id===matchedBinding.product_id);
    if (['matched','no_known_advisory'].includes(String(e.state)) && (!coveredProduct || !coveredProduct.covered_versions.includes(matchedBinding.exact_version) || e.advisory_count!==matchCount)) throw new Error('Advisory count or coverage mismatch');
    if (e.state==='no_feed' && feed!==null) throw new Error('No-feed state conflicts with catalogue');
    if (e.state==='product_not_covered' && (!feed || coveredProduct)) throw new Error('Product coverage state conflicts with catalogue');
    if (e.state==='version_not_covered' && (!coveredProduct || coveredProduct.covered_versions.includes(matchedBinding.exact_version))) throw new Error('Version coverage state conflicts with catalogue');
    ids.add(e.binding.application_id);
  }
  return v as unknown as AdvisorySnapshot;
}
function native() { if(!isTauri()) throw new Error('Apri piko con Open-Piko.cmd per usare gli advisory locali.'); }
export async function advisoryStatus(): Promise<AdvisorySnapshot> { native(); return parseAdvisories(await invoke('advisory_status')); }
export async function importAdvisoryFeed(json:string): Promise<void> { native(); if(new TextEncoder().encode(json).length>1024*1024) throw new Error('Feed oltre 1 MiB.'); await invoke('import_advisory_feed',{json}); }
export async function bindAdvisoryProduct(applicationId:string,productId:string,exactVersion:string): Promise<void> { native(); await invoke('bind_advisory_product',{applicationId,productId,exactVersion}); }
export async function unbindAdvisoryProduct(applicationId:string): Promise<void> { native(); await invoke('unbind_advisory_product',{applicationId}); }
export function advisoryLevel(a: Advisory): 'critical'|'high'|'medium'|'low'|'none'|'unknown' { return a.cvss_x100===null ? 'unknown' : a.cvss_x100>=900 ? 'critical' : a.cvss_x100>=700 ? 'high' : a.cvss_x100>=400 ? 'medium' : a.cvss_x100===0 ? 'none' : 'low'; }
