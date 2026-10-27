import { describe, expect, it } from 'vitest';
import { parseInvestigation, type Investigation, type InvestigationObservation } from './investigation';

const instance = '12345678-1234-8234-9234-123456789012';
const child = '12345678-1234-8234-9234-123456789013';
const id = (number: number) => `00000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const row = (number = 1): InvestigationObservation => ({
  event_id: id(number), evidence_id: null, process_instance: instance,
  event_type: 'process.snapshot.observed', observed_at: 100, process_name: 'worker.exe',
});
function graph(observations: InvestigationObservation[] = [row()]): Investigation {
  return {
    process_instance: instance, events_considered: observations.length,
    query_truncated: false, graph_truncated: false, references_truncated: false,
    nodes: [{ id: 'process', kind: 'process', label: 'worker.exe', instance_id: instance }], edges: [],
    observations, observations_available: true, observations_truncated: false,
    observation_paging_available: true, next_observation_cursor: null,
  };
}

describe('observed history response boundaries', () => {
  it('preserves child process attribution and explicit old-service availability', () => {
    const childRow = { ...row(), process_instance: child, process_name: 'child.exe' };
    expect(parseInvestigation(graph([childRow]), instance).observations?.[0]).toEqual(childRow);
    const old = graph();
    delete old.observations;
    delete old.observations_available;
    delete old.observations_truncated;
    delete old.observation_paging_available;
    delete old.next_observation_cursor;
    expect(parseInvestigation(old, instance).observations_available).toBeUndefined();
    expect(parseInvestigation(graph([]), instance).observations_available).toBe(true);
  });

  it('rejects unsafe attribution, unsupported event types and invalid row values', () => {
    for (const patch of [
      { process_instance: '00000000-0000-0000-0000-000000000000' },
      { process_instance: child, event_type: 'network.snapshot.observed' },
      { event_type: 'process.started' },
      { event_id: 'invalid' }, { evidence_id: 'invalid' },
      { observed_at: -1 }, { observed_at: 100.5 }, { observed_at: 8.64e15 + 1 },
      { process_name: '' }, { process_name: 'x'.repeat(8193) },
    ]) {
      expect(() => parseInvestigation(graph([{ ...row(), ...patch }]), instance)).toThrow();
    }
    expect(() => parseInvestigation({ ...graph(), observations_available: false }, instance)).toThrow();
    expect(() => parseInvestigation({ ...graph(), observations_truncated: undefined }, instance)).toThrow();
  });

  it('requires unique timeline IDs and deterministic time then UUID ordering', () => {
    const ordered = graph([row(1), row(2)]);
    expect(parseInvestigation(ordered, instance).observations).toHaveLength(2);
    for (const observations of [
      [row(1), row(1)], [row(2), row(1)],
      [{ ...row(1), observed_at: 101 }, row(2)],
    ]) {
      expect(() => parseInvestigation(graph(observations), instance)).toThrow();
    }
    expect(() => parseInvestigation({ ...ordered, events_considered: 1 }, instance)).toThrow();
    expect(() => parseInvestigation(graph(Array.from({ length: 129 }, (_, i) => row(i + 1))), instance)).toThrow();
  });

  it('bounds aggregate UTF-8 labels even when every row fits its character limit', () => {
    const label = 'é'.repeat(4096);
    const admitted = graph(Array.from({ length: 8 }, (_, i) => ({ ...row(i + 1), process_name: label })));
    expect(parseInvestigation(admitted, instance).observations).toHaveLength(8);
    const oversized = graph(Array.from({ length: 9 }, (_, i) => ({ ...row(i + 1), process_name: label })));
    expect(() => parseInvestigation(oversized, instance)).toThrow();
  });

  it('requires valid cursors with explicit paging and truncation signals', () => {
    const paged = { ...graph(), query_truncated: true, next_observation_cursor: [100, id(1)] };
    expect(parseInvestigation(paged, instance).next_observation_cursor).toEqual([100, id(1)]);
    for (const next_observation_cursor of [[-1, id(1)], [100.5, id(1)], [8.64e15 + 1, id(1)], [100, 'invalid'], [100], [100, id(1), 'extra']]) {
      expect(() => parseInvestigation({ ...paged, next_observation_cursor }, instance)).toThrow();
    }
    expect(() => parseInvestigation({ ...paged, query_truncated: false }, instance)).toThrow();
    expect(() => parseInvestigation({ ...paged, observation_paging_available: false }, instance)).toThrow();
    expect(() => parseInvestigation({ ...graph(), observation_paging_available: 'true' }, instance)).toThrow();
    expect(() => parseInvestigation({ ...graph(), events_considered: 129 }, instance)).toThrow();
  });
});
