import { expect, it } from 'vitest';
import { parseInvestigation, type Investigation } from './investigation';
const instance = '12345678-1234-8234-9234-123456789012';
const graph: Investigation = { process_instance: instance, events_considered: 1, query_truncated: false, graph_truncated: false, references_truncated: false, nodes: [{ id: 'process', kind: 'process', label: 'example.exe' }, { id: 'node-1', kind: 'identity', label: 'S-1-5-21' }], edges: [{ source: 'process', target: 'node-1', relation: 'observed_identity', observation_count: 1, first_observed: 100, last_observed: 100, event_ids: [instance], evidence_ids: [] }] };
it('accepts a bounded graph and empty observations without inventing relationships', () => {
  expect(parseInvestigation(graph, instance)).toEqual(graph);
  expect(parseInvestigation({ ...graph, events_considered: 0, nodes: [], edges: [] }, instance).edges).toEqual([]);
});
it('rejects mismatched instances, dangling links, false relations and unbounded references', () => {
  expect(() => parseInvestigation(graph, instance.replace('1234-', '1235-'))).toThrow();
  for (const patch of [{ target: 'missing' }, { relation: 'caused' }, { first_observed: 101 }, { observation_count: 0 }, { event_ids: Array(17).fill(instance) }]) {
    expect(() => parseInvestigation({ ...graph, edges: [{ ...graph.edges[0], ...patch }] }, instance)).toThrow();
  }
  expect(() => parseInvestigation({ ...graph, nodes: [...graph.nodes, graph.nodes[1]] }, instance)).toThrow();
});
it('accepts an evidence-backed parent lifetime and rejects a parent edge to an account', () => {
  const parent = { ...graph, nodes: [graph.nodes[0], { id: 'node-1', kind: 'parent_process', label: 'launcher.exe' }], edges: [{ ...graph.edges[0], relation: 'observed_parent' }] };
  expect(parseInvestigation(parent, instance).nodes[1].label).toBe('launcher.exe');
  expect(() => parseInvestigation({ ...parent, nodes: graph.nodes }, instance)).toThrow();
});
