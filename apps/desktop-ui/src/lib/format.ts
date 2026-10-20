import type { Language, Messages } from './i18n';

export function formatTime(value: number | null, language: Language, empty = '—'): string {
  if (value === null || !Number.isFinite(value)) return empty;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return empty;
  return new Intl.DateTimeFormat(language === 'it' ? 'it-IT' : 'en-GB', {
    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit',
  }).format(date);
}

export function formatDuration(seconds: number, text: Messages): string {
  if (seconds < 60) return `${seconds} ${text.secondsShort}`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} ${text.minutesShort}`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} ${text.hoursShort} ${Math.floor(seconds % 3600 / 60)} ${text.minutesShort}`;
  return `${Math.floor(seconds / 86400)} ${text.daysShort} ${Math.floor(seconds % 86400 / 3600)} ${text.hoursShort}`;
}

export function formatCount(value: number | undefined, language: Language): string {
  return value === undefined ? '—' : new Intl.NumberFormat(language === 'it' ? 'it-IT' : 'en-GB').format(value);
}

export function eventTypeLabel(value: string, language: Language): string {
  if (value === 'image.etw.repeated') return language === 'it' ? 'Caricamenti ripetuti di un modulo' : 'Repeated module loads';
  return value;
}

export function eventSourceLabel(value: string, language: Language): string {
  if (value === 'piko.image_context') return language === 'it' ? 'Riepilogo moduli di piko' : 'Piko module summary';
  return value;
}

export function eventOperationLabel(value: string, eventType: string, language: Language): string {
  if (eventType === 'image.etw.repeated') return language === 'it' ? 'Raggruppa caricamenti uguali' : 'Group repeated loads';
  return value;
}

export function eventResultLabel(value: string, eventType: string, language: Language): string {
  if (eventType === 'image.etw.repeated') return language === 'it' ? 'Osservazioni aggregate' : 'Observations grouped';
  return value;
}

export function exportEvents(events: unknown[]): void {
  const data = JSON.stringify({ product: 'piko', export_schema_version: 1, exported_at: new Date().toISOString(), events }, null, 2);
  downloadJson(data, 'events');
}

export function downloadJson(data: string, kind: 'events' | 'alert'): void {
  const url = URL.createObjectURL(new Blob([data], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `piko-${kind}-${new Date().toISOString().replaceAll(':', '-')}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
