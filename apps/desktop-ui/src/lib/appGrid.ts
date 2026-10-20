import type { InstalledSoftware } from './appControl';
export function installDate(value?: string | null): string | null {
  if (!value || !/^\d{8}$/.test(value)) return null;
  const iso = `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6)}`;
  const date = new Date(`${iso}T00:00:00Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === iso ? iso : null;
}
export function sortApps(apps: InstalledSoftware[], order: string): InstalledSoftware[] {
  return [...apps].sort((a, b) => {
    const left = installDate(a.install_date), right = installDate(b.install_date);
    if (order !== 'name') {
      if (left && !right) return -1; if (!left && right) return 1;
      if (left && right && left !== right) return order === 'oldest' ? left.localeCompare(right) : right.localeCompare(left);
    }
    return a.display_name.localeCompare(b.display_name) || a.id.localeCompare(b.id);
  });
}
