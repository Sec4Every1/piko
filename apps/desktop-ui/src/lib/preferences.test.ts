import { describe, expect, it } from 'vitest';
import { parsePreferences } from './preferences';
import { messages } from './i18n';
import { formatCount, formatDuration, formatTime } from './format';

describe('local presentation preferences', () => {
  it('recovers safely from corrupted or unsupported local storage', () => {
    for (const value of [null, '{bad json', 'null', '42', '{"language":"xx","theme":"neon"}']) {
      expect(parsePreferences(value)).toEqual({ language: 'it', theme: 'system' });
    }
  });
  it('restores supported preferences only', () => {
    expect(parsePreferences('{"language":"en","theme":"dark","extra":true}')).toEqual({ language: 'en', theme: 'dark' });
  });
  it('has identical dictionary coverage in both supported languages', () => {
    expect(Object.keys(messages.it).sort()).toEqual(Object.keys(messages.en).sort());
  });
  it('distinguishes unknown counts from zero observations', () => {
    expect(formatCount(undefined, 'it')).toBe('—');
    expect(formatCount(0, 'it')).toBe('0');
    expect(formatTime(null, 'it')).toBe('—');
    expect(formatTime(Number.NaN, 'en')).toBe('—');
  });
  it('formats known uptime without implying Windows boot time', () => {
    expect(formatDuration(3665, messages.it)).toBe('1 h 1 min');
    expect(formatDuration(86400, messages.en)).toBe('1 d 0 h');
  });
});
