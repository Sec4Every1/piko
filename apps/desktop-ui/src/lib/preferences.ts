import type { Language } from './i18n';

export type Theme = 'system' | 'light' | 'dark';
export interface Preferences { language: Language; theme: Theme }
export const preferenceKey = 'piko.preferences.v1';

export function parsePreferences(value: string | null): Preferences {
  const defaults: Preferences = { language: 'it', theme: 'system' };
  if (!value) return defaults;
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object') return defaults;
    const object = parsed as Record<string, unknown>;
    return {
      language: object.language === 'en' ? 'en' : 'it',
      theme: object.theme === 'light' || object.theme === 'dark' ? object.theme : 'system',
    };
  } catch { return defaults; }
}

export function readPreferences(): Preferences {
  try { return parsePreferences(localStorage.getItem(preferenceKey)); }
  catch { return parsePreferences(null); }
}
