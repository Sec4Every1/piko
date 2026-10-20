import { describe, it, expect } from 'vitest';
import { parseObservations, belongsTo, type ObservationSnapshot } from './observations';
const fixture = (): ObservationSnapshot => ({ started_at_unix_ms: 1, completed_at_unix_ms: 2, process_complete: true, network_complete: true, warnings: [], processes: [{ instance_id: '12345678-1234-8234-9234-123456789012', pid: 42, parent_pid: 1, name: 'example.exe', executable: 'C:\\example.exe', creation_filetime: '133000000000000001', sid: null, session_id: null, access_error: null }], connections: [{ pid: 42, process_creation_filetime: '133000000000000001', family: 'ipv4', local_address: '127.0.0.1', local_port: 1234, remote_address: '127.0.0.1', remote_port: 80, state: 5 }] });
describe('process observation boundary', () => {
  it('preserves exact submillisecond identity across JSON', () => {
    const v = parseObservations(JSON.parse(JSON.stringify(fixture())));
    expect(v.processes[0].creation_filetime).toBe('133000000000000001');
    expect(belongsTo(v.connections[0], v.processes[0])).toBe(true);
    v.connections[0].process_creation_filetime = '133000000000000002';
    expect(belongsTo(v.connections[0], v.processes[0])).toBe(false);
    v.connections[0].process_creation_filetime = null;
    expect(belongsTo(v.connections[0], v.processes[0])).toBe(false);
  });
  it('rejects rounded native times, oversized times, ports and duplicate PIDs', () => {
    for (const invalid of [133000000000000001, '18446744073709551616', '-1', '1.5', '01']) {
      const v = fixture(); Object.assign(v.processes[0], { creation_filetime: invalid });
      expect(() => parseObservations(v)).toThrow();
    }
    const v = fixture(); v.connections[0].remote_port = 65536;
    expect(() => parseObservations(v)).toThrow();
    const duplicate = fixture(); duplicate.processes.push({ ...duplicate.processes[0] });
    expect(() => parseObservations(duplicate)).toThrow();
  });
  it('retains partial coverage and rejects fabricated instance identity', () => {
    const v = fixture(); v.process_complete = false; v.warnings = ['Truncated'];
    expect(parseObservations(v).process_complete).toBe(false);
    v.processes[0].creation_filetime = null;
    expect(() => parseObservations(v)).toThrow();
    v.processes[0].instance_id = null;
    expect(parseObservations(v).processes[0].instance_id).toBe(null);
  });
});

it('keeps UDP local-only and rejects invented remote endpoints or rounded owner lifetime',()=>{const v=fixture();v.udp_complete=false;v.udp_endpoints=[{pid:42,process_creation_filetime:'133000000000000001',family:'ipv4',local_address:'127.0.0.1',local_port:5353}];expect(parseObservations(v).udp_complete).toBe(false);expect(belongsTo(v.udp_endpoints[0],v.processes[0])).toBe(true);Object.assign(v.udp_endpoints[0],{remote_address:'192.0.2.1'});expect(()=>parseObservations(v)).toThrow();});
