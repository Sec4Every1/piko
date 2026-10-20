# ADR-0007 — Un Security Graph, tre semantiche distinte

Stato: accettato, implementazione pianificata. Data: 2026-10-04.

Riutilizzare identificatori e archivio del Security Graph per Observed Causal, Potential Attack e Counterfactual. Archi osservati richiedono eventi; potenziali richiedono stato/precondizioni/freschezza; scenari richiedono base e proposta versionate. I grafi non si fondono semanticamente. Counterfactual non modifica il sistema o lo snapshot base.

Attack Path Engine e Counterfactual Engine saranno safe Rust, con aggiornamenti incrementali, query/cache limitate e risultati incompleti espliciti. Singolo host prima di AD/Entra/fleet. Nessuna dipendenza obbligatoria da BloodHound, Neo4j o PostgreSQL.

Detection può correlare progressione osservata e percorsi potenziali; la semplice possibilità non autorizza il blocco. Remediation fornisce cut points spiegati e alternative residue. Fleet verifica prerequisiti sul destinatario.

Conseguenza: architettura ampliata senza creare engine vuoti o dati demo. UI Attack Paths aggiunta solo con dati reali utili. Contratti e gate in [ATTACK_PATH_MODEL.md](../ATTACK_PATH_MODEL.md).

