<script lang="ts">
  export let name = 'grid';
  export let size = 20;
  const paths: Record<string, string> = {
    grid: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
    activity: 'M3 12h4l3-8 4 16 3-8h4',
    log: 'M8 3h8l4 4v14H4V3h4 M15 3v5h5 M8 12h8 M8 16h6',
    settings: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2',
    search: 'M10.5 3a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15 M16 16l5 5',
    arrow: 'M4 12h16 M14 6l6 6-6 6',
    chevron: 'M9 5l7 7-7 7',
    refresh: 'M20 7v5h-5 M4 17v-5h5 M6.1 6a8 8 0 0 1 13.1 3 M4.8 15a8 8 0 0 0 13.1 3',
    shield: 'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6z M12 8v5 M12 16v.1',
    layers: 'M12 3l10 5-10 5L2 8z M2 12l10 5 10-5 M2 16l10 5 10-5',
    pulse: 'M12 3v3 M12 18v3 M3 12h3 M18 12h3 M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8',
    device: 'M3 4h18v13H3z M8 21h8 M12 17v4',
    lock: 'M6 10h12v11H6z M8 10V6a4 4 0 0 1 8 0v4 M12 14v3',
    info: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20 M12 11v6 M12 7v.1',
    clock: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20 M12 6v6l4 2',
    warning: 'M12 3L2 21h20z M12 9v5 M12 17v.1',
    download: 'M12 3v12 M7 10l5 5 5-5 M4 16v5h16v-5',
    check: 'M5 12l4 4L19 6',
    close: 'M6 6l12 12 M6 18L18 6',
    sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v2 M12 20v2 M2 12h2 M20 12h2 M5 5l1.5 1.5 M17.5 17.5L19 19 M5 19l1.5-1.5 M17.5 6.5L19 5',
    moon: 'M21 13a9 9 0 0 1-10-10A9 9 0 1 0 21 13z',
    globe: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20 M2 12h20 M12 2c5 5 5 15 0 20 M12 2c-5 5-5 15 0 20',
    terminal: 'M3 4h18v16H3z M7 9l3 3-3 3 M13 15h4',
    link: 'M10 13a4 4 0 0 0 6 0l4-4a4 4 0 0 0-6-6l-2 2 M14 11a4 4 0 0 0-6 0l-4 4a4 4 0 0 0 6 6l2-2',
  };
</script>

<svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d={paths[name] ?? paths.info} /></svg>
