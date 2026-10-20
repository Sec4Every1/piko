# ADR-0006 — Memory-safe by default, platform-native when justified

Stato: accettato. Data: 2026-10-04. Integra ADR-0001 e ADR-0004; prevale su interpretazioni che impongono Rust al 100%.

Trattare piko come brownfield. Conservare componenti verificabili e validi; safe Rust per logica e algoritmi, unsafe/FFI isolati, C per piccoli componenti Windows/WDK soltanto quando riduce il rischio totale. Nessuna migrazione attuale è motivata dall'[audit](../COMPONENT_AUDIT.md).

Le [decisioni linguistiche](../LANGUAGE_DECISIONS.md) definiscono gate, characterization test, confronto delle implementazioni e rollback. La disponibilità di esempi C o la preferenza per Rust non sono da sole ragioni sufficienti. Driver e recovery non sono implementati anticipatamente.

Conseguenza: nessuna conversione di codice in questa revisione. Le lacune di lifecycle/backpressure vengono corrette nella lingua esistente. Qualifica della sicurezza e compatibilità Windows precede convenienza implementativa.

