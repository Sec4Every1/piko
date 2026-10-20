# ADR 0017 — Blocchi Firewall in ingresso

Le regole di blocco per percorso ora hanno direzione esplicita. ID percorso e prefissi inbound/outbound distinti mantengono compatibilità con regole precedenti. Direzione compresa nel piano serializzato, journal e scelta UI. Il broker mantiene il piano confermato: il chiamante della conferma passa solo il suo UUID. La rimozione trova nome, percorso e template completi della stessa direzione. Il default dei vecchi piani è outbound. Nessun filtro per porta/destinazione, nessuna allowlist e nessuna policy hash sul file futuro.

La direzione è verificata assieme al template COM prima dell’Add e dopo, e le collisioni/modifiche estranee fermano la mutazione. Le condizioni di profilo attivo, policy locale e interfacce escluse restano vincolanti. Le prove COM in memoria non modificano il Firewall; smoke nativo prepara e annulla soltanto. La qualificazione di traffico resta distinta dalla verifica della configurazione.

Fonte: [Microsoft Windows Firewall rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules).

