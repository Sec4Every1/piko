# ADR-0001 — Fondazione locale per vertical slices

- Stato: accettato.
- Data: 2026-10-04.
- Contesto: i 116 requisiti descrivono una piattaforma plurimilestone; implementarli superficialmente genererebbe false garanzie.

## Decisione

Il nome è `piko`. Rust stabile e workspace modulare, Tauri 2/Svelte/TypeScript per la UI. La prima slice realizza self-health → evento versionato → queue bounded → SQLite → IPC → UI/CLI. Nessuna detection inventata, driver iniziale o dipendenza cloud. Il runtime può partire in console mentre lifecycle SCM, installer e ACL di produzione vengono completati in una successiva slice della phase 1.

La UI resta non elevata e non contiene security logic. Ogni nuova capacità richiede matrice Windows, errore/degrado, prova reale e benchmark; un'etichetta “protetto” non è ammessa quando si conosce soltanto la salute del collector.

## Conseguenze

Si ottiene una base verificabile con superficie ridotta. Il prototipo non sostituisce le protezioni Windows esistenti. Le fasi future rimangono in documentazione finché non sono implementate; non si creano crate vuoti per suggerire completamento. Il costo è un prodotto iniziale limitato ma esplicito.

