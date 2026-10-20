import { describe, expect, it } from 'vitest';
import { clause, appendClause, readSavedQueries, saveQuery } from './queries';
describe('structured search', () => {
  it('quotes paths and hostile values without turning them into conditions', () => {
    const value = 'C:\\Users\\test\\a.exe" OR process.pid = 1';
    expect(clause('process.path', '=', value)).toBe(`process.path = ${JSON.stringify(value)}`);
    expect(clause('process.pid', '>=', '0042')).toBe('process.pid >= 42');
    expect(clause('user.sid', 'IS NULL', '')).toBe('user.sid = NULL');
    expect(appendClause('event.type = "a" OR event.type = "b"', 'process.pid = 42', 'AND')).toBe('(event.type = "a" OR event.type = "b") AND process.pid = 42');
  });
  it('rejects unsupported fields, operators, numeric injection and byte overflow', () => {
    expect(() => clause('network.first_seen', '=', '1')).toThrow();
    expect(() => clause('process.pid', '=', '1 OR 1')).toThrow();
    expect(() => clause('process.pid', 'CONTAINS', '1')).toThrow();
    expect(() => clause('process.name', '=', '€'.repeat(400))).toThrow();
    expect(() => appendClause('x'.repeat(4096), 'x', 'AND')).toThrow();
  });
  it('preserves saved expressions and rejects corruption, duplicates and overflow', () => {
    const queries = saveQuery([], 'Browser', 'process.name = "browser.exe"');
    expect(readSavedQueries({ getItem: () => JSON.stringify({ version: 1, queries }) })).toEqual(queries);
    for (const raw of ['null', '{', JSON.stringify({ version: 2, queries }), JSON.stringify({ version: 1, queries: [...queries, ...queries] })]) {
      expect(readSavedQueries({ getItem: () => raw })).toEqual([]);
    }
    expect(readSavedQueries({ getItem: () => { throw Error('unavailable'); } })).toEqual([]);
    expect(() => saveQuery(queries, 'Browser', 'event.type = "a"')).toThrow();
    expect(() => saveQuery(Array.from({ length: 20 }, (_, i) => ({ name: String(i), expression: 'a' })), 'extra', 'a')).toThrow();
  });
});
