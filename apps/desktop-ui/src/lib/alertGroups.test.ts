import { describe, it, expect } from 'vitest';
import { groupAlerts, groupSubjects, groupTitle } from './alertGroups';
import type { Alert } from './api';
const alert = (id: string, rule = 'service-installed', version = 1): Alert => ({ id, rule_id: rule, rule_version: version, event_id: id, evidence_id: null, observed_at: 42, severity: 'low', title: `Unknown ${rule}`, explanation: 'Original explanation' });
describe('compact alert grouping', () => {
  it('collapses 100 occurrences without discarding any event or mixing rule versions', () => {
    const rows = Array.from({ length: 100 }, (_, i) => alert(String(i)));
    const groups = groupAlerts(rows);
    expect(groups).toHaveLength(1); expect(groups[0].alerts).toHaveLength(100);
    rows[99].rule_version = 2;
    expect(groupAlerts(rows)).toHaveLength(2);
    expect(rows.map(r => r.id)).toEqual(Array.from({ length: 100 }, (_, i) => String(i)));
  });
  it('orders urgent groups first and leaves unknown risk and names unknown', () => {
    const high = { ...alert('high', 'audit-log-cleared'), severity: 'high' };
    const [first, second] = groupAlerts([alert('low'), high]);
    expect(first.severity).toBe('high'); expect(second.risk).toBeNull();
    expect(groupSubjects(second, 'it')).toContain('Nomi non disponibili');
    expect(groupTitle(groupAlerts([alert('future', 'future-rule', 2)])[0], 'it')).toBe('Unknown future-rule');
  });
});
