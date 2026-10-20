export const queryFields = ['process.name', 'process.path', 'process.instance', 'process.pid', 'user.sid', 'event.id', 'event.type', 'event.severity', 'event.category', 'event.operation', 'event.result', 'event.time', 'host.id', 'sensor.id', 'target.identifier'] as const;
export const savedQueryKey = 'piko.saved-queries.v1';
export interface SavedQuery { name: string; expression: string }
const bytes = (text: string) => new TextEncoder().encode(text).length;
export function clause(field: string, operator: string, value: string): string {
  if (!(queryFields as readonly string[]).includes(field)) throw Error('Unknown field');
  const numeric = field === 'process.pid' || field === 'event.time';
  if (operator === 'IS NULL' || operator === 'IS NOT NULL') return `${field} ${operator === 'IS NULL' ? '=' : '!='} NULL`;
  if (!(numeric ? ['=', '!=', '>', '>=', '<', '<='] : ['=', '!=', 'CONTAINS']).includes(operator)) throw Error('Invalid operator');
  if (bytes(value) > 1024) throw Error('Maximum value size: 1024 bytes');
  if (numeric && (!/^[0-9]+$/.test(value) || !Number.isSafeInteger(Number(value)))) throw Error('Expected a non-negative integer');
  return `${field} ${operator} ${numeric ? String(Number(value)) : JSON.stringify(value)}`;
}
export function appendClause(expression: string, next: string, join: 'AND' | 'OR'): string {
  const value = expression.trim() ? `(${expression.trim()}) ${join} ${next}` : next;
  if (bytes(value) > 4096) throw Error('Maximum expression size: 4096 bytes');
  return value;
}
export function readSavedQueries(storage: Pick<Storage, 'getItem'> = localStorage): SavedQuery[] {
  try {
    const raw = storage.getItem(savedQueryKey);
    if (!raw || raw.length > 100000) return [];
    const data = JSON.parse(raw);
    if (!data || data.version !== 1 || !Array.isArray(data.queries) || data.queries.length > 20) return [];
    if (!data.queries.every((q: SavedQuery) => q && typeof q.name === 'string' && q.name.trim() && q.name.length <= 80 && typeof q.expression === 'string' && q.expression.trim() && bytes(q.expression) <= 4096)) return [];
    if (new Set(data.queries.map((q: SavedQuery) => q.name)).size !== data.queries.length) return [];
    return data.queries.map((q: SavedQuery) => ({ name: q.name, expression: q.expression }));
  } catch { return []; }
}
export function saveQuery(queries: SavedQuery[], name: string, expression: string): SavedQuery[] {
  name = name.trim(); expression = expression.trim();
  if (!name || name.length > 80 || !expression || bytes(expression) > 4096) throw Error('Invalid saved expression');
  if (queries.some(q => q.name === name)) throw Error('A saved expression already has this name');
  if (queries.length >= 20) throw Error('Maximum 20 saved expressions');
  return [...queries, { name, expression }];
}
