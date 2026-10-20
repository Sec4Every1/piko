# ADR-0004 — User-mode prima, enforcement soltanto dove supportato

- Stato: accettato.
- Data: 2026-10-04.

## Decisione

ETW/Event Log e API documentate precedono il driver. Observation, detection e enforcement sono capacità distinte. La prima roadmap può valutare policy e ransomware behavior senza fingere un veto preventivo. File/Registry mediation e blast-radius con garanzie richiederanno minifilter/callback o contenimento Windows equivalente qualificato.

Il driver arriva solo per gap misurati: niente hook privati, PatchGuard bypass, rete/ML in kernel o grandi parser. In base ad ADR-0006, C è ammesso e può essere preferito quando WDK, DDI, debugging, lifecycle e verificabilità riducono il rischio complessivo; non è soltanto un ripiego quando Rust fallisce. Rust WDK viene confrontato sul componente concreto, senza quote di linguaggio. Signing, HVCI e test driver sono gate, non opzioni da far disabilitare all'utente. [Driver Signing Policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-), verificato 2026-10-04.

## Conseguenze

Le fasi 6–7 possono uscire con evaluation/detection e limiti espliciti; prevenzione forte attende dipendenze della fase 12. Non esiste una promessa generale di veto account creation, blocco screenshot o isolamento credenziali del browser attraverso le API iniziali. Ogni gap segue desired behavior → limite → alternative supportate → implementazione raccomandata in [FEASIBILITY.md](../FEASIBILITY.md).

