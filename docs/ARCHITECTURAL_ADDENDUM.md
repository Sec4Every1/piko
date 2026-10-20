# PIKO — ADDENDUM ARCHITETTURALE

Queste istruzioni modificano e integrano la specifica precedente di Piko. Non ricominciare il progetto da zero e non effettuare conversioni massive di codice funzionante senza una motivazione tecnica documentata.

---

## 1. LANGUAGE STRATEGY — MEMORY SAFE BY DEFAULT, PLATFORM NATIVE WHEN JUSTIFIED

Piko NON deve più essere interpretato come un progetto obbligatoriamente 100% Rust.

La nuova regola è:

**Memory-safe by default. Platform-native when justified.**

Rust rimane il linguaggio predefinito per la maggior parte del prodotto.

C è esplicitamente consentito, e può essere preferito, nei componenti Windows low-level in cui documentazione Microsoft, WDK, debugging, tooling, API support, esempi ufficiali o affidabilità dell'implementazione risultino materialmente migliori in C.

Non scegliere C soltanto perché esistono più esempi in C.

Non scegliere Rust soltanto per raggiungere una percentuale arbitraria di codice Rust.

Scegli il linguaggio che minimizza il rischio complessivo del componente.

Priorità:

CORRECTNESS  
→ SECURITY  
→ RELIABILITY  
→ PLATFORM SUPPORT  
→ MEMORY SAFETY  
→ EXPLAINABILITY  
→ PERFORMANCE  
→ DEVELOPMENT CONVENIENCE

### Livello 1 — Safe Rust

Default per:

- Security Core
- Event Fabric
- Event Storage
- Causal Graph
- Attack Path Engine
- Query Engine
- Detection Engine
- Identity Engine
- Network Engine
- Intent Engine
- Capability Engine
- Policy Engine
- Software Inventory
- Software Genealogy
- Ransomware Engine
- Deception Engine
- Vulnerability Engine
- Response orchestration
- Fleet Coordinator
- CLI
- Crypto orchestration
- High-level Windows service logic

Usare safe Rust ogni volta che è ragionevole.

### Livello 2 — Unsafe Rust / Windows FFI

Consentito solo nei boundary Windows necessari.

Concentrare unsafe e FFI in moduli piccoli e dedicati.

Ogni boundary deve documentare:

- ownership;
- lifetime;
- buffer size;
- pointer validity;
- threading assumptions;
- synchronization;
- caller guarantees;
- failure modes;
- trusted/untrusted inputs;
- cleanup;
- Windows API contract.

Ogni blocco unsafe significativo deve avere commento SAFETY e test appropriati.

### Livello 3 — C / WDK / native Windows

C è permesso e preferibile quando costituisce chiaramente la soluzione Windows più matura, semplice, documentata e verificabile.

Candidati principali:

- kernel driver;
- WDK callbacks;
- kernel enforcement;
- boot/recovery components;
- very low-level Windows facilities;
- componenti in cui i binding Rust costringerebbero ad avere grandi quantità di unsafe;
- componenti in cui l'implementazione Rust richiederebbe wrapper custom fragili o API immature.

Il codice C deve essere:

- minimale;
- isolato;
- non responsabile di decisioni complesse;
- protetto da interfacce strette;
- sottoposto a static analysis;
- testato;
- fuzzato dove applicabile;
- compilato con hardening disponibile;
- privo di parsing complesso non necessario.

### Kernel architecture

Il kernel driver NON deve diventare Piko.

Architettura desiderata:

Windows Kernel

→ Minimal Native Sensor / Enforcement Driver

→ narrow versioned protocol

→ Piko Security Core

Il driver deve principalmente:

- raccogliere eventi che non possono essere osservati in modo sufficientemente affidabile da user mode;
- eseguire enforcement che richiede kernel mode;
- validare input;
- utilizzare bounded buffers;
- comunicare con il Security Core.

Non deve contenere:

- UI;
- SIEM;
- causal graph;
- attack path calculations;
- machine learning;
- threat intelligence;
- network reputation logic;
- policy interpretation complessa;
- database;
- business logic.

Questi elementi rimangono nel Security Core.

---

## 2. EXISTING CODE MIGRATION POLICY

Il progetto esistente deve essere trattato come brownfield.

NON:

- creare un nuovo repository senza necessità;
- buttare il codice esistente;
- convertire automaticamente Rust in C;
- riscrivere moduli funzionanti solo per uniformare il linguaggio.

Prima effettuare un Architecture & Language Audit.

Per ogni crate/modulo/componente esistente produrre una tabella:

| Component | Current Language | Status | Unsafe/FFI | Windows dependency | Test coverage | Recommendation |
|---|---|---|---|---|---|---|
| ... | Rust/C/... | working/partial/mock | low/medium/high | low/medium/high | ... | KEEP / REFACTOR / MIGRATE / DELETE |

Classificazioni:

### KEEP

Codice corretto, testabile, architetturalmente compatibile e non eccessivamente fragile.

Non riscriverlo.

### REFACTOR

La scelta del linguaggio è corretta ma struttura, API, unsafe usage o ownership devono essere migliorati.

### MIGRATE

Usare solo quando esiste una ragione concreta per cambiare linguaggio.

Esempi:

- Rust richiede grandi quantità di unsafe;
- Windows/WDK support è sostanzialmente più maturo in C;
- binding esistenti sono incompleti;
- debugging o lifecycle risultano più affidabili con l'implementazione native;
- il componente è sufficientemente piccolo da rendere la migrazione verificabile.

### DELETE

Solo codice mock, duplicato, architetturalmente errato o non utilizzato.

Ogni migrazione deve essere eseguita una componente alla volta.

Prima:

1. creare characterization tests;
2. definire input/output;
3. misurare comportamento corrente;
4. documentare invarianti;
5. creare nuovo componente;
6. eseguire entrambi contro gli stessi test;
7. confrontare risultati;
8. migrare;
9. rimuovere il precedente soltanto dopo verifica.

Non effettuare big-bang rewrite.

---

# 3. LANGUAGE MIGRATION GATE

Per convertire un componente Rust esistente in C deve essere prodotto un documento breve:

## Language Migration Decision

**Component:**  
**Current implementation:**  
**Problem:**  
**Why Rust is materially worse here:**  
**Why C reduces total risk:**  
**Security impact:**  
**Memory-safety impact:**  
**Testing strategy:**  
**Rollback strategy:**  
**Expected performance difference:**  
**Final recommendation:**

Se non esiste una motivazione convincente, mantenere Rust.

---

# 4. ATTACK PATH MANAGEMENT

Integrare in Piko un nuovo:

**Attack Path Engine**

Il Causal Security Graph deve distinguere almeno tre tipi di grafo.

## A. Observed Causal Graph

Rappresenta ciò che è realmente accaduto.

Domanda:

**What happened and what caused it?**

Esempio:

User  
→ Process  
→ Credential Access  
→ Authentication  
→ Remote Machine

Ogni relazione osservata deve essere supportata da evidenza.

---

## B. Potential Attack Graph

Rappresenta ciò che l'attuale configurazione del sistema rende possibile.

Domanda:

**What could happen?**

Deve modellare relazioni come:

- CAN_ADMIN;
- CAN_AUTHENTICATE;
- CAN_IMPERSONATE;
- CAN_READ;
- CAN_WRITE;
- CAN_MODIFY;
- CAN_EXECUTE;
- CAN_INSTALL;
- CAN_CONTROL_SERVICE;
- CAN_LOAD_DRIVER;
- CAN_READ_CREDENTIAL;
- CAN_CHANGE_POLICY;
- CAN_ACCESS_DATA;
- CAN_REACH_NETWORK;
- CAN_DELEGATE;
- CAN_OBTAIN_TOKEN;
- CAN_MODIFY_IDENTITY.

Nodi potenziali:

- User;
- Group;
- Machine;
- Process;
- Application;
- Token;
- Credential;
- Certificate;
- Service;
- Driver;
- Browser Session;
- Remote Session;
- Cloud Identity;
- Network Resource;
- Sensitive Data;
- Policy;
- Developer Tool;
- Package;
- Dependency;
- AI Agent;
- Fleet Endpoint.

Il Potential Attack Graph deve funzionare anche su un solo PC.

Active Directory, Entra e fleet sono estensioni del modello, non prerequisiti.

---

## C. Counterfactual Graph

Rappresenta ciò che diventerebbe possibile dopo una modifica proposta.

Domanda:

**What becomes possible if we allow/change X?**

Esempio:

CURRENT:

Application X  
→ no critical path

PROPOSED:

Application X  
→ SSH private key  
→ Server A  
→ privileged account  
→ Server B

Piko deve poter avvisare:

**This change creates a new path to a critical asset.**

Usare Counterfactual Analysis per:

- software permissions;
- account/group changes;
- firewall changes;
- privilege elevation;
- driver installation;
- service changes;
- credential access;
- package installation;
- policy changes;
- remote access;
- AI agent permissions.

---

# 5. OBSERVED PATH PROGRESSION

Il Detection Engine deve correlare:

Potential Attack Graph

+

Observed Causal Graph

+

Identity State

+

Historical Behavior

+

User Intent

+

Capability Contracts.

Se l'attività osservata comincia a percorrere un attack path conosciuto, aumentare progressivamente la confidence.

Esempio:

Potential path:

Alice  
→ Workstation  
→ Build Server  
→ Service Credential  
→ Domain Controller

Observed:

Alice  
→ Workstation  
→ suspicious process  
→ credential access  
→ Build Server

Piko deve poter produrre una detection:

**Known Attack Path In Progress**

con:

- posizione attuale nel percorso;
- risorsa critica raggiungibile;
- remaining hops;
- evidence;
- confidence;
- identities coinvolte;
- credential involved;
- causal timeline;
- alternative paths;
- recommended containment point.

Non aspettare necessariamente che l'attaccante raggiunga la risorsa finale.

---

# 6. PREDICTIVE CONTAINMENT

Il Response Engine può intervenire prima del completamento del percorso quando l'evidenza combinata è sufficientemente forte.

Progressione:

OBSERVE  
→ WARN  
→ RESTRICT  
→ CONTAIN  
→ BLOCK

La semplice esistenza di un possibile attack path non autorizza il blocco.

Il blocco richiede evidenza osservata o policy esplicita.

---

# 7. ATTACK PATH CRITICALITY

Ogni nodo può avere criticità:

LOW  
MEDIUM  
HIGH  
CRITICAL

Esempi CRITICAL:

- Domain Controller;
- privileged identity;
- security infrastructure;
- backup/recovery system;
- production deployment key;
- signing key;
- CI/CD administration;
- credential vault;
- Piko Security Core;
- protected recovery store.

Valutare un percorso considerando:

- numero di hop;
- privilege gained;
- credential value;
- path reliability;
- exposure;
- current attacker position;
- behavioral evidence;
- user intent;
- exploitability;
- target criticality.

Evitare un singolo opaque risk score.

Mostrare i fattori che compongono il rischio.

---

# 8. BLOODHOUND-STYLE CONCEPT WITHOUT BLOODHOUND DEPENDENCY

Piko può usare concetti analoghi all'attack-path analysis resa nota da sistemi come BloodHound, ma non deve dipendere architetturalmente da BloodHound.

Non introdurre automaticamente:

- Neo4j;
- PostgreSQL;
- un secondo enorme graph stack;
- collector esterni obbligatori;
- runtime pesanti;

solo per supportare attack-path analysis.

Riutilizzare il Piko Security Graph e aggiungere strutture/index ottimizzati per path analysis.

Se in futuro è utile importare dati BloodHound/OpenGraph, implementare un adapter separato.

Il core Piko deve restare indipendente.

---

# 9. INCREMENTAL GRAPH COMPUTATION

Evitare full graph recomputation continua.

Preferire:

event/state change  
→ affected nodes identified  
→ affected edges updated  
→ impacted paths recalculated  
→ detections re-evaluated

Mantenere cache e index bounded.

Misurare:

- graph update latency;
- path query latency;
- RAM per numero di nodi;
- storage growth;
- maximum path exploration;
- CPU during topology changes.

Prevedere limiti di profondità e strategie anti-explosion.

---

# 10. ATTACK PATH + CAPABILITY ENGINE

Una nuova capability può aprire un nuovo attack path.

Esempio:

Package v1:

node.exe  
→ project directory

Package v2:

node.exe  
→ SSH key  
→ remote server

Piko deve rilevare:

**Capability expansion introduces a new privileged path.**

Questo deve influenzare:

- software probation;
- policy;
- user confirmation;
- update trust;
- containment;
- Fleet/Collective Immunity.

---

# 11. ATTACK PATH + COLLECTIVE IMMUNITY

Quando un incidente confermato rivela un attack path sfruttabile, gli altri endpoint devono poter ricevere:

- causal fingerprint;
- vulnerable topology pattern;
- relevant identity relationships;
- required local preconditions;
- safe prevention point.

Non distribuire una regola di blocco universale se i prerequisiti non esistono sul destinatario.

Ogni endpoint deve valutare localmente l'applicabilità.

---

# 12. ATTACK PATH UI

Aggiungere una vista:

**Attack Paths**

ma mostrarla solo dove utile.

La visualizzazione deve distinguere chiaramente:

Observed  
Potential  
Counterfactual

con legenda visuale non dipendente esclusivamente dal colore.

Esempio:

Observed edge = evento realmente verificato.

Potential edge = relazione attualmente disponibile.

Counterfactual edge = relazione che esisterebbe dopo una modifica proposta.

L'utente deve poter chiedere:

- Why is this path possible?
- What permission creates this path?
- What is the shortest path?
- What is the safest remediation?
- What would break the path?
- Is this path currently being traversed?
- Which change introduced this path?
- When did this path first become possible?

---

# 13. PATH REMEDIATION

Non suggerire soltanto:

"remove administrator".

Calcolare possibili cut points.

Esempio:

A → B → C → D

Possibili remediation:

- rimuovere A→B;
- limitare B→C;
- proteggere credential C;
- eliminare D privilege;
- modificare capability/policy;
- introdurre stronger authentication;
- segmentare network.

Preferire la remediation:

- meno distruttiva;
- più reversibile;
- più specifica;
- con minor impatto operativo.

Mostrare perché interrompe il percorso.

---

# 14. ARCHITECTURE UPDATE

La struttura logica diventa:

Security Core

→ Observation Engine  
→ Memory Engine  
→ Response Engine  
→ Security Event Fabric  
→ Causal Graph Engine  
→ Attack Path Engine  
→ Counterfactual Engine  
→ Detection Engine  
→ Identity Engine  
→ Capability Engine  
→ Policy Engine  
→ Investigation / SIEM  
→ Collective Immunity

Observed Causal Graph, Potential Attack Graph e Counterfactual Graph devono condividere identity e object identifiers senza essere semanticamente confusi.

---

# 15. EXECUTION RULE FOR CURRENT PROJECT

Prima di implementare nuove feature:

1. non creare un nuovo progetto;
2. non convertire automaticamente il codice Rust;
3. analizzare il repository corrente;
4. generare COMPONENT_AUDIT.md;
5. generare LANGUAGE_DECISIONS.md;
6. aggiornare ARCHITECTURE.md;
7. identificare mock e prototipi;
8. identificare unsafe/FFI boundaries;
9. identificare componenti Windows che beneficerebbero realmente del C;
10. mantenere tutto il codice valido possibile;
11. creare characterization tests prima delle migrazioni;
12. procedere per vertical slice.

Ogni modifica deve mantenere il progetto compilabile e testabile il più possibile.

No big-bang rewrite.

---

# 16. FINAL PRINCIPLE

Il linguaggio è un mezzo, non una feature.

Piko deve privilegiare:

- security;
- correctness;
- memory safety;
- Windows compatibility;
- maintainability;
- debuggability;
- verifiability.

Una piccola componente C ben documentata può essere migliore di una grande componente Rust piena di unsafe.

Una grande componente safe Rust è normalmente preferibile alla stessa componente riscritta in C senza una necessità piattaforma-specifica.

Non ottimizzare il progetto per il linguaggio che l'LLM conosce meglio.

Ottimizzare il progetto per il codice che possiamo verificare meglio.