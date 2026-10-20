import { invoke, isTauri } from '@tauri-apps/api/core';
import { ApiError } from './api';
export interface InvestigationNode { id: string; kind: 'process' | 'identity' | 'tcp_endpoint'; label: string }
export interface InvestigationEdge { source: string; target: string; relation: 'observed_identity' | 'observed_tcp'; event_ids: string[]; evidence_ids: string[]; observation_count: number; first_observed: number; last_observed: number }
export interface Investigation { process_instance: string; events_considered: number; query_truncated: boolean; graph_truncated: boolean; references_truncated: boolean; nodes: InvestigationNode[]; edges: InvestigationEdge[] }
const object = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === 'string' && v.length <= 8192;
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const uuid = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const ids = (v: unknown): v is string[] => Array.isArray(v) && v.length <= 16 && v.every(uuid) && new Set(v).size === v.length;
export function parseInvestigation(v: unknown, instance: string): Investigation {
  const invalid = (): never => { throw new ApiError('invalid_response', 'Invalid observed relationship graph'); };
  if (!object(v) || v.process_instance !== instance || !uuid(instance) || !integer(v.events_considered, 500)
    || !['query_truncated', 'graph_truncated', 'references_truncated'].every(k => typeof v[k] === 'boolean')
    || !Array.isArray(v.nodes) || v.nodes.length > 64 || !Array.isArray(v.edges) || v.edges.length > 63
    || !v.nodes.every(n => object(n) && text(n.id) && text(n.label) && ['process', 'identity', 'tcp_endpoint'].includes(String(n.kind)))) return invalid();
  const nodes = new Map(v.nodes.map(n => [n.id, n]));
  if (nodes.size !== v.nodes.length || (v.nodes.length && nodes.get('process')?.kind !== 'process')
    || v.nodes.filter(n => n.kind === 'process').length !== (v.nodes.length ? 1 : 0)
    || !v.edges.every(e => object(e) && e.source === 'process' && text(e.target) && nodes.has(e.target)
      && (e.relation === 'observed_identity' ? nodes.get(e.target)?.kind === 'identity' : e.relation === 'observed_tcp' && nodes.get(e.target)?.kind === 'tcp_endpoint')
      && ids(e.event_ids) && e.event_ids.length > 0 && ids(e.evidence_ids) && e.evidence_ids.length <= e.event_ids.length
      && integer(e.observation_count, v.events_considered as number) && e.observation_count >= e.event_ids.length
      && integer(e.first_observed, 8.64e15) && integer(e.last_observed, 8.64e15) && e.first_observed <= e.last_observed)
    || new Set(v.edges.map(e => e.target)).size !== v.edges.length || v.edges.length !== Math.max(0, v.nodes.length - 1)) return invalid();
  return v as unknown as Investigation;
}
export async function getInvestigation(processInstance: string): Promise<Investigation> {
  if (!isTauri()) throw new ApiError('browser', 'Open piko with Open-Piko.cmd.');
  let result: unknown;
  try { result = await invoke('get_investigation', { processInstance }); }
  catch (e) { throw new ApiError('unavailable', String(e)); }
  return parseInvestigation(result, processInstance);
}
