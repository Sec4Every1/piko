import { invoke, isTauri } from '@tauri-apps/api/core';
import { ApiError } from './api';
export interface InvestigationNode { id: string; kind: 'process' | 'identity' | 'tcp_endpoint' | 'udp_local_endpoint' | 'parent_process' | 'child_process'; label: string; instance_id?: string | null }
export interface InvestigationEdge { source: string; target: string; relation: 'observed_identity' | 'observed_tcp' | 'observed_udp_bind' | 'observed_parent' | 'observed_child'; event_ids: string[]; evidence_ids: string[]; observation_count: number; first_observed: number; last_observed: number }
export interface InvestigationObservation { event_id: string; evidence_id: string | null; process_instance: string; event_type: string; observed_at: number; process_name: string }
export interface Investigation { process_instance: string; events_considered: number; query_truncated: boolean; graph_truncated: boolean; references_truncated: boolean; nodes: InvestigationNode[]; edges: InvestigationEdge[]; observations?: InvestigationObservation[]; observations_truncated?: boolean; observations_available?: boolean; observation_paging_available?: boolean; next_observation_cursor?: ObservationCursor | null }
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
    || !v.nodes.every(n => object(n) && text(n.id) && text(n.label) && ['process', 'identity', 'tcp_endpoint', 'udp_local_endpoint', 'parent_process', 'child_process'].includes(String(n.kind))
      && (n.instance_id == null || (uuid(n.instance_id) && n.instance_id !== '00000000-0000-0000-0000-000000000000' && ['process', 'parent_process', 'child_process'].includes(String(n.kind)))))) return invalid();
  const nodes = new Map(v.nodes.map(n => [n.id, n]));
  if (nodes.size !== v.nodes.length || (v.nodes.length && nodes.get('process')?.kind !== 'process')
    || (nodes.get('process')?.instance_id != null && nodes.get('process')?.instance_id !== instance)
    || v.nodes.some(n => ['parent_process', 'child_process'].includes(n.kind) && n.instance_id === instance)
    || v.nodes.some(n => n.kind === 'child_process' && !uuid(n.instance_id))
    || v.nodes.filter(n => n.kind === 'process').length !== (v.nodes.length ? 1 : 0)
    || !v.edges.every(e => object(e) && e.source === 'process' && text(e.target) && nodes.has(e.target)
      && (e.relation === 'observed_identity' ? nodes.get(e.target)?.kind === 'identity' : e.relation === 'observed_tcp' ? nodes.get(e.target)?.kind === 'tcp_endpoint' : e.relation === 'observed_udp_bind' ? nodes.get(e.target)?.kind === 'udp_local_endpoint' : e.relation === 'observed_parent' ? nodes.get(e.target)?.kind === 'parent_process' : e.relation === 'observed_child' && nodes.get(e.target)?.kind === 'child_process')
      && ids(e.event_ids) && e.event_ids.length > 0 && ids(e.evidence_ids) && e.evidence_ids.length <= e.event_ids.length
      && integer(e.observation_count, v.events_considered as number) && e.observation_count >= e.event_ids.length
      && integer(e.first_observed, 8.64e15) && integer(e.last_observed, 8.64e15) && e.first_observed <= e.last_observed)
    || new Set(v.edges.map(e => e.target)).size !== v.edges.length || v.edges.length !== Math.max(0, v.nodes.length - 1)) return invalid();
  if (v.observations_available !== undefined && typeof v.observations_available !== 'boolean') return invalid();
  if (v.observations !== undefined || v.observations_truncated !== undefined || v.observations_available === true) {
    const kinds = ['process.snapshot.observed', 'process.snapshot.changed', 'network.snapshot.observed', 'network.snapshot.changed', 'network.udp.snapshot.observed', 'network.udp.snapshot.changed'];
    if (!Array.isArray(v.observations) || v.observations.length > Math.min(128, v.events_considered as number)
      || typeof v.observations_truncated !== 'boolean'
      || (v.observations_available !== true && v.observations.length !== 0)
      || !v.observations.every(o => object(o) && uuid(o.event_id) && (o.evidence_id === null || uuid(o.evidence_id))
        && uuid(o.process_instance) && o.process_instance !== '00000000-0000-0000-0000-000000000000'
        && kinds.includes(String(o.event_type)) && (o.process_instance === instance || String(o.event_type).startsWith('process.snapshot.'))
        && integer(o.observed_at, 8.64e15) && text(o.process_name) && o.process_name.length > 0)
      || new Set(v.observations.map(o => o.event_id)).size !== v.observations.length) return invalid();
    const observations = v.observations as InvestigationObservation[];
    if (observations.reduce((total, o) => total + new TextEncoder().encode(o.process_name).length, 0) > 65536
      || observations.some((o, i) => i > 0 && (observations[i - 1].observed_at > o.observed_at
        || (observations[i - 1].observed_at === o.observed_at && observations[i - 1].event_id >= o.event_id)))) return invalid();
  }
  if (v.observation_paging_available !== undefined && typeof v.observation_paging_available !== 'boolean') return invalid();
  const cursor = v.next_observation_cursor;
  if (cursor != null && (!Array.isArray(cursor) || cursor.length !== 2 || !integer(cursor[0], 8.64e15) || !uuid(cursor[1]) || v.observation_paging_available !== true || v.query_truncated !== true)) return invalid();
  if (v.observation_paging_available === true && (v.events_considered as number) > 128) return invalid();
  return v as unknown as Investigation;
}
export interface InvestigationWindow { from: number; until: number }
export type ObservationCursor = [number, string];
export async function getInvestigation(processInstance: string, window: InvestigationWindow | null = null, before: ObservationCursor | null = null): Promise<Investigation> {
  if (!isTauri()) throw new ApiError('browser', 'Open piko with Open-Piko.cmd.');
  if (window && (!integer(window.from, 8.64e15) || !integer(window.until, 8.64e15) || window.until <= window.from)) throw new Error('Invalid observation-time window');
  let result: unknown;
  if (before && (!integer(before[0], 8.64e15) || !uuid(before[1]))) throw new Error('Invalid observation cursor');
  try { result = await invoke('get_investigation', { processInstance, observedFrom: window?.from ?? null, observedUntil: window?.until ?? null, before, paged: true }); }
  catch (e) { throw new ApiError('unavailable', String(e)); }
  const graph = parseInvestigation(result, processInstance);
  if (!graph.observation_paging_available) throw new ApiError('unavailable', 'Observation paging requires an updated service.');
  const next = graph.next_observation_cursor;
  if (next && (window && (next[0] < window.from || next[0] >= window.until)
    || before && (next[0] > before[0] || next[0] === before[0] && next[1] >= before[1]))) throw new ApiError('invalid_response', 'Observation cursor did not advance');
  return graph;
}
