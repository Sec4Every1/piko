# ADR 0015 — Estensione detection Windows e diagnostica del monitor

Data: 2026-10-12. Stato: implementato nel codice; qualificazione multi-Windows residua.

Otto regole oltre le quattro originali: Security 4720/4732/4698/4702 e Defender
Operational 5001/5007/1116/1117. Ogni match richiede categoria, sensor ID, canale,
provider e ID esatti. Nessun match sulla sola severità Windows. Il canale Defender
usa il lifecycle Event Log esistente, capacità/backpressure/bookmark e health.
Nessun cambio automatico delle policy di audit o dei servizi Defender.

Assessment su raw di identità/sorgente/record verificati; schema v0 per tutti,
v1 aggiunto soltanto per task 4698/4702. TaskContent/New può raggiungere 64 KiB:
resta testo grezzo, non viene eseguito né usato per attribuire un processo. Altri
campi massimo 4096. DTD/PI, duplicati, namespace estranei e bidi restano rifiutati.
Nuovi campi optional/default per compatibilità; nessuna attribuzione dal PID emittente.

Pesi euristici: account 40, gruppo 45, task creato 35/modificato 40, Defender off 75,
config 25, report rilevazione 80, report azione 45. Probabilità FP sempre None.
1117 può indicare Allow: non stato bonificato. 5007 non è disattivazione. Nomi
riportati non verificano firma o identità binaria. Backfill additive/idempotent
senza cambiare gli eventi raw; indice derivato rigenerato da payload verificati.
MITRE contestuale T1136, T1098, T1053.005, T1685; nessun mapping specifico dedotto
per i soli report antivirus. Riferimenti di browser in allowlist compilata.

Diagnostica FFI soltanto win-platform: pseudo-handle del processo corrente,
K32GetProcessMemoryInfo e GetProcessTimes. Safe Rust campiona all'heartbeat e
calcola la CPU con delta monotono, processori disponibili, interi e bounds.
Primo campione, counter rollback o CPU count sconosciuto => None; errore resetta
il campione, non produce uno zero. Working set e private commit distinti.
Metriche non costituiscono stato di sicurezza, non includono UI/helper e non
aggiungono una nuova regola di enforcement. Campione/errori esposti in health;
Impostazioni segnala dati vecchi. Non auto-tuning o performance regression CI.

Test: replay XML per 8 nuovi ID, spoofing/record mismatch, versione task/oversize,
backfill invariance/idempotenza, reference allowlist, contatori nativi, CPU bounds,
parser UI metriche/contesto, gruppi/nominativi e testo azione Defender. Smoke nativo
con lettura canale reale e risorse; non genera minacce né mutazioni Security/Defender.

Fonti primarie: Microsoft auditing 4720, 4732, 4698, 4702; Microsoft Defender event IDs;
MITRE T1136/T1098/T1053.005/T1685; API GetProcessTimes e PROCESS_MEMORY_COUNTERS_EX.

