# OBIETTIVO DEL PROGETTO

Voglio progettare e implementare un nuovo prodotto di cybersecurity per Windows che non sia semplicemente un altro antivirus/EDR.

Il prodotto deve combinare:

- endpoint protection;
- state integrity;
- behavioral detection;
- causal analysis;
- historical system state;
- forensics;
- SIEM locale;
- identity protection;
- ransomware protection;
- software/dependency provenance;
- supply-chain protection;
- deception/honeypot;
- network behavioral analysis;
- vulnerability/patch intelligence;
- recovery;
- optional multi-endpoint collective immunity.

L'architettura deve essere progettata principalmente per Windows x86-64/AMD64, con consapevolezza WOW64 e con supporto sia alle versioni Windows client sia Windows Server attualmente supportate.

NON creare artificialmente edizioni "Home", "Enterprise", ecc. con capacità di sicurezza differenti.

Un singolo PC deve poter utilizzare tutte le funzionalità che hanno senso localmente.

Le funzionalità che richiedono necessariamente più endpoint devono apparire solo quando l'utente collega più macchine.

---

# 1. PRINCIPI FONDAMENTALI

L'intero progetto deve rispettare questi principi.

## 1.1 User Intent != Process Permission

Il fatto che un utente avvii un programma non significa che tale programma debba poter fare tutto ciò che l'account Windows potrebbe tecnicamente fare.

Esempio:

l'utente avvia un gioco.

Sono plausibili:

- GPU;
- audio;
- input;
- salvataggi;
- directory del gioco;
- multiplayer.

Non sono automaticamente autorizzati:

- lettura credenziali browser;
- lettura chiavi SSH;
- creazione utenti;
- modifica delle impostazioni di sicurezza;
- installazione driver;
- persistence;
- cancellazione backup;
- lettura indiscriminata dei documenti;
- esecuzione nascosta di PowerShell;
- modifica di altri programmi.

---

## 1.2 Trusted != Unlimited

Firma valida, publisher conosciuto, repository ufficiale e hash corretto sono evidenze di autenticità, NON garanzie di comportamento benigno.

Separare sempre:

- Identity;
- Provenance;
- Integrity;
- Authorization;
- Capability;
- Behavior.

Un aggiornamento npm ufficiale deve poter essere bloccato se tenta di acquisire capacità non coerenti con la propria funzione.

---

## 1.3 Unknown != Malicious

Un file sconosciuto non deve essere dichiarato malware semplicemente perché sconosciuto.

Combinare invece:

- comportamento;
- causalità;
- provenienza;
- integrità;
- capability expansion;
- history;
- deception triggers;
- network behavior;
- identity behavior;
- fleet correlation.

---

## 1.4 Explain everything

Nessuna decisione importante deve essere rappresentata unicamente da qualcosa come:

"AI score 87%".

Ogni detection deve poter spiegare:

- cosa è successo;
- quale processo;
- quale identità;
- chi lo ha generato;
- quale risorsa è stata toccata;
- quale policy è stata violata;
- quali segnali sono stati osservati;
- quali eventi precedenti sono causalmente collegati;
- perché è stata intrapresa un'azione.

---

# 2. ARCHITETTURA GENERALE

Non creare un monolite.

Utilizzare un'architettura di questo tipo:

```text
                         DESKTOP UI
                       unprivileged
                            │
                            │ authenticated IPC
                            ▼
                    LOCAL SECURITY API
                            │
                 ┌──────────┴──────────┐
                 │                     │
                 ▼                     ▼
          SECURITY CORE          QUERY / SIEM
          Windows Service           ENGINE
                 │
       ┌─────────┼─────────┐
       │         │         │
       ▼         ▼         ▼
 OBSERVATION   MEMORY    RESPONSE
   ENGINE      ENGINE     ENGINE
       │         │
       └────┬────┘
            ▼
     SECURITY EVENT FABRIC
            │
      ┌─────┴─────┐
      ▼           ▼
 CAUSAL GRAPH   DETECTION
    ENGINE        ENGINE
      │
      ├── Identity
      ├── Process
      ├── File
      ├── Registry
      ├── Network
      ├── Software
      ├── Data
      ├── Device
      ├── Policy
      └── History
```

Componenti opzionali:

```text
Minimal Kernel Sensor
Optional Fleet Coordinator
Offline Recovery Environment
Threat Intelligence Connectors
```

La UI NON deve contenere logica di sicurezza critica.

Chiudere la UI:

- non deve fermare il monitoraggio;
- non deve fermare le detection;
- non deve fermare il logging;
- non deve disattivare le policy.

---

# 3. STACK TECNOLOGICO

## Core

Utilizzare Rust stabile.

Creare un Cargo workspace modulare.

Preferire:

- Rust;
- async solo dove porta benefici reali;
- dipendenze piccole e mantenute;
- binding Windows ufficiali/focalizzati;
- API documentate.

Evitare:

- kernel hooking non documentato;
- PatchGuard bypass;
- hooking fragile;
- API Windows private se non strettamente necessario;
- dipendenze enormi per funzionalità banali.

---

# 4. REGOLE PER UNSAFE

Impostare:

```text
#![forbid(unsafe_code)]
```

su tutti i crate dove possibile.

Concentrare l'eventuale FFI unsafe in pochi moduli specifici, per esempio:

```text
win-ffi
kernel-ipc
native-sensors
```

Ogni blocco `unsafe` deve avere:

- commento SAFETY;
- invarianti;
- test;
- ownership chiaramente documentata;
- lifetime dei buffer documentato;
- comportamento su errori Windows verificato.

Non disseminare unsafe nel progetto.

---

# 5. COMPONENTE KERNEL

Non partire costruendo un gigantesco driver.

Utilizzare prima tutte le sorgenti Windows user-mode affidabili disponibili.

Aggiungere un driver solamente quando serve per:

- enforcement non ottenibile altrimenti;
- cross-view verification;
- file mediation;
- Registry mediation;
- process/thread/image telemetry più affidabile;
- self-protection;
- network enforcement dove necessario.

Il driver deve essere minimale.

Nessuna UI, machine learning o logica complessa nel kernel.

Schema:

```text
KERNEL
 ↓
minimal observations/enforcement
 ↓
bounded ring buffer / IPC
 ↓
Security Core
 ↓
analysis
```

Non fare operazioni di rete o attività pesanti da kernel mode.

Preferire Rust anche qui solamente se la toolchain WDK/Rust scelta è sufficientemente stabile per produzione.

Se ciò non fosse ancora vero, utilizzare un driver WDK minimale in C/C++ rigidamente isolato, mantenendo tutto il resto del prodotto in Rust.

La sicurezza è più importante del dogmatismo sul linguaggio.

---

# 6. CARGO WORKSPACE

Strutturare inizialmente circa così:

```text
/crates
    common-model
    event-schema
    win-platform
    win-sensors
    event-fabric
    event-storage
    causal-graph
    query-engine
    policy-engine
    intent-engine
    capability-engine
    detection-engine
    identity-engine
    network-engine
    software-inventory
    software-genealogy
    deception-engine
    ransomware-engine
    vulnerability-engine
    crypto-core
    response-engine
    recovery-model
    ipc
    fleet-protocol

/apps
    security-service
    desktop-ui
    cli
    fleet-coordinator
    recovery-tool

/driver
    optional-kernel-sensor

/docs
/tests
/benchmarks
```

Non creare dipendenze circolari.

`common-model` ed `event-schema` devono essere molto stabili.

---

# 7. SECURITY EVENT FABRIC

Windows Event Viewer è solamente UNA sorgente.

Il prodotto deve produrre una telemetria propria.

Sorgenti:

```text
Windows Event Log
ETW
process telemetry
thread telemetry
module/image loading
filesystem
Registry
network
DNS
TLS metadata
authentication
accounts
tokens
services
drivers
devices
remote sessions
software inventory
security policy
deception
internal sensor health
responses
```

Normalizzare tutto.

---

# 8. EVENT SCHEMA

Definire un `SecurityEvent` versionato.

Campi minimi:

```text
schema_version
event_id

host_id
boot_id
sensor_id

sequence
wall_clock_time
monotonic_time
observation_time
ingestion_time

event_category
event_type
severity

actor_identity
logon_session

process
parent_process

target
operation
result

causal_parents[]
correlation_ids[]

raw_evidence_reference

integrity_metadata
```

Ogni evento deve avere un ID globale o sufficientemente univoco.

---

# 9. RAW → NORMALIZED → ENRICHED

Mai distruggere la sorgente originale.

Pipeline:

```text
RAW EVENT
    ↓
NORMALIZED EVENT
    ↓
ENRICHED EVENT
    ↓
DETECTION
    ↓
INCIDENT
```

Conservare la relazione tra ogni livello.

Se in futuro cambia il parser deve essere possibile rianalizzare il dato originale.

---

# 10. TIME INTEGRITY

Non affidarsi esclusivamente all'orologio wall-clock.

Registrare:

- timestamp Windows;
- timestamp di osservazione;
- timestamp di ingest;
- sequenza monotona;
- boot ID;
- sensor sequence.

Una modifica dell'orologio di sistema non deve poter riscrivere logicamente l'ordine degli eventi.

---

# 11. PROTEZIONE DEI LOG

Implementare log tamper-evident.

Utilizzare:

- append-only segments;
- hash chaining;
- Merkle/checkpoint dove appropriato;
- signed checkpoints;
- encryption at rest;
- sequence verification.

Esempio:

```text
SEGMENT 40
previous_hash = ...
events = [...]
hash = H40

SEGMENT 41
previous_hash = H40
events = [...]
hash = H41
```

La modifica/cancellazione di un segmento deve essere rilevabile.

---

# 12. REMOTE LOG ANCHORING

Quando esiste un coordinator:

```text
Endpoint
   ↓
signed event checkpoint
   ↓
Coordinator
```

Una macchina compromessa successivamente non deve poter modificare ciò che era già stato verificato esternamente.

In single-host mode questa funzione semplicemente non esiste.

---

# 13. STORAGE

Progettare lo storage dietro trait/interfacce sostituibili.

Per il primo prodotto locale:

- SQLite per metadata, configurazione, indici e query;
- WAL;
- batch writes;
- append-only compressed event segments per payload ad alto volume;
- zstd o compressione equivalente ben mantenuta.

Non scrivere un record sul disco con una transazione separata per ogni singolo evento.

Batching e backpressure.

Implementare retention:

```text
HOT
WARM
COLD
DELETE
```

con budget disco configurabile.

Mai saturare il disco dell'utente.

---

# 14. NEGATIVE EVIDENCE

La mancanza di eventi può essere un evento.

Esempi:

```text
sensor heartbeat missing
event sequence gap
expected event absent
ETW session unexpectedly stopped
source A observes process X
source B does not
```

Generare:

```text
ObservationIntegrityEvent
```

e correlarlo nel causal graph.

---

# 15. CAUSAL SECURITY GRAPH

Il cuore del prodotto deve essere un grafo temporale causale.

Nodi:

- machine;
- user;
- session;
- token;
- process;
- thread;
- executable;
- file;
- Registry object;
- driver;
- service;
- software package;
- credential;
- certificate;
- connection;
- domain;
- IP;
- device;
- security policy;
- data object;
- incident.

Edge:

```text
created
spawned
opened
read
modified
executed
mapped
authenticated_as
connected_to
installed
loaded
derived_token_from
changed
authorized_by
caused
```

Ogni edge deve portare:

- timestamp;
- evidence;
- confidence;
- event references.

Non dedurre causalità forte quando si possiede solamente correlazione temporale.

---

# 16. SYSTEM MEMORY

Il sistema deve sapere COME si è raggiunto lo stato corrente.

Mantenere:

```text
Observed State
Verified State
Historical State
Expected State
```

Questo vale per:

- Registry;
- software;
- driver;
- utenti;
- gruppi;
- firewall;
- policy;
- services;
- scheduled tasks;
- boot state;
- network configuration.

---

# 17. REGISTRY HISTORY

Non mantenere solamente il Registry attuale.

Esempio:

```text
A → B → A
```

deve rimanere una sequenza di tre stati/eventi.

Memorizzare:

- key;
- value;
- old state;
- new state;
- actor;
- process;
- identity;
- time;
- causal transaction.

---

# 18. SOFTWARE GENEALOGY

Costruire una vera identità software.

Separare:

- product identity;
- publisher identity;
- binary identity;
- install identity;
- version identity.

Per ogni software:

```text
name
publisher
signing identity
version
architecture
install time
install origin

executables
hashes
signatures
certificates

services
drivers
Registry footprint
scheduled tasks
network history
dependencies
```

Mantenere genealogia:

```text
download
 ↓
installer
 ↓
package
 ↓
binary
 ↓
service
 ↓
driver
```

---

# 19. SOFTWARE SUPPLY CHAIN

Supportare almeno concettualmente:

- npm;
- PyPI;
- NuGet;
- package managers;
- development tools;
- IDE;
- build systems.

Esempio:

```text
developer
 ↓
npm
 ↓
Package A
 ↓
Package B
 ↓
postinstall
 ↓
PowerShell
```

Attribuire l'attività alla dipendenza corretta quando possibile.

---

# 20. SECURITY TRANSACTIONS

Creare il concetto di `SecurityTransaction`.

Esempio:

```text
INSTALL SOFTWARE
authorized_by: Alice
started: ...
expected_scope:
    filesystem
    registry
    services
```

Ogni modifica deve essere collegabile alla transazione.

Se tre ore dopo lo stesso programma crea un account Windows senza una transazione corrispondente:

```text
BLOCK / ALERT
```

Security Transaction per:

- installazione;
- update;
- driver;
- account;
- policy;
- software removal;
- backup deletion;
- sensitive system changes.

---

# 21. CAPABILITY & BEHAVIORAL CONTRACT ENGINE

Implementare un contratto dinamico per software.

Esempio:

```text
VisualStudio Extension X

FILES
project/**        RW

NETWORK
marketplace       ALLOW

CREDENTIALS
NONE

SERVICES
NONE

DRIVERS
NONE

ACCOUNT CREATION
NONE
```

Un update non deve ereditare automaticamente nuove capability sensibili.

Esempio:

```text
v1:
SSH access = NONE

v2:
attempts ~/.ssh/id_ed25519
```

Generare:

```text
CAPABILITY EXPANSION
```

e valutare:

- allow;
- ask;
- deny;
- contain.

---

# 22. BEHAVIOR DIFF TRA VERSIONI

Dopo ogni update confrontare:

```text
old version
vs
new version
```

su:

- filesystem;
- Registry;
- processes;
- child processes;
- network;
- persistence;
- credentials;
- privileges.

Mostrare all'utente:

```text
NEW BEHAVIOR

+ reads SSH keys
+ launches PowerShell
+ connects to new infrastructure
```

---

# 23. PROBATION MODE

Nuove versioni, software sconosciuti o provenienza ridotta possono entrare in:

```text
PROBATION
```

Limitare inizialmente capability ad alto impatto.

Non impedire attività normali senza motivo.

---

# 24. RANSOMWARE ENGINE

Implementare detection correlata basata su:

- write rate;
- rename rate;
- entropy/structure change;
- file-extension changes;
- breadth delle directory;
- process ancestry;
- known behavior;
- canary interaction.

Stato:

```text
NORMAL
 ↓
ANOMALOUS
 ↓
THROTTLE
 ↓
FREEZE
```

Non attendere una classificazione cloud prima di limitare un comportamento distruttivo evidente.

---

# 25. CRYPTOGRAPHIC CANARIES

Creare più file esca, non solamente uno.

Per esempio:

```text
4 KB
64 KB
512 KB
2-4 MB
```

con contenuti e tipologie differenti.

Conservare in protected storage:

- original;
- original hash.

Quando modificati:

- preservare pre-image;
- preservare post-image;
- identificare processo;
- preservare causal chain;
- congelare comportamento distruttivo se gli altri segnali concordano;
- preservare evidence.

Il known plaintext NON deve essere considerato garanzia di poter recuperare una chiave ransomware.

Serve come detection + forensic evidence.

---

# 26. BLAST RADIUS LIMITER

Software appena introdotto o poco affidabile non deve poter modificare centinaia di migliaia di documenti istantaneamente solo perché gira con l'account dell'utente.

Implementare limiti dinamici basati su:

- trust;
- provenance;
- behavior;
- modification velocity;
- directory breadth;
- canary access.

---

# 27. PROTECTED RECOVERY HISTORY

Il processo che può modificare i documenti dell'utente NON deve automaticamente poter distruggere anche:

- tutte le revisioni;
- recovery metadata;
- protected history;
- forensic evidence.

Separare authority sul file corrente da authority sul recovery store.

---

# 28. DECEPTION FABRIC

Implementare una piattaforma di deception locale.

Categorie:

```text
IDENTITY
DATA
SYSTEM
NETWORK
```

---

# 29. DECOY IDENTITY

Permettere opzionalmente all'utente di attivare un account fittizio.

Deve:

- non avere dati reali;
- non essere amministratore;
- non possedere privilegi utili;
- non poter diventare una backdoor;
- non essere utilizzato dall'utente.

Monitorare:

- enumeration;
- password attempts;
- authentication;
- token use;
- group changes;
- remote use;
- profile access.

Distinguere:

```text
enumeration = weak signal

actual authentication attempt = strong signal
```

---

# 30. DECOY CREDENTIALS

Creare credenziali-esca che NON concedano accesso reale a sistemi sensibili.

Monitorare:

```text
read
copy
authentication attempt
remote use
```

L'uso della decoy credential è evidence ad alta confidence.

---

# 31. DECOY DATA

Supportare:

- fake documents;
- fake backup;
- fake configuration;
- fake API secrets;
- fake SSH keys;
- ransomware canaries.

Gli oggetti devono essere chiaramente identificabili internamente come esche, ma non necessariamente ovvi a software automatico.

---

# 32. NETWORK BEHAVIOR ENGINE

Per ogni connessione conservare:

```text
Process
 ↓
DNS
 ↓
Domain
 ↓
IP
 ↓
ASN / provider
 ↓
TLS metadata
 ↓
Connection
```

Memorizzare:

- first seen;
- last seen;
- frequency;
- protocol;
- port;
- volume;
- application context;
- process ancestry.

---

# 33. DESTINATION REPUTATION

Considerare:

- reputation;
- known threat intelligence;
- first seen;
- ASN;
- hosting provider;
- infrastructure history;
- certificate history;
- domain relationships.

NON utilizzare il Paese come prova di maliciousness.

Geography è solamente contesto.

---

# 34. PER-APPLICATION NETWORK MODEL

Imparare nel tempo le destinazioni tipiche di un software.

Esempio:

```text
Application:
known API
known CDN
update server
```

Nuovo comportamento:

```text
03:14
raw IP
new ASN
8443
12 MB outbound
no user activity
```

deve diventare un'anomalia contestuale.

---

# 35. DNS / ENCRYPTED TRAFFIC INTELLIGENCE

Monitorare quando possibile:

- DNS;
- DoH/DoT metadata;
- SNI quando disponibile;
- certificate metadata;
- TLS characteristics;
- IP/domain rotation.

NON progettare il prodotto sulla necessità di fare indiscriminata TLS interception.

---

# 36. IDENTITY ENGINE

Rendere identity un'entità di primo livello.

Nodi:

```text
Account
Authentication
Logon Session
Token
Credential
Certificate
Browser Session
Process
Device
Remote Identity
```

Ogni processo deve avere:

```text
user
session
token
integrity
privileges
parent
software identity
```

---

# 37. TOKEN LINEAGE

Conservare genealogia dei token.

Voglio poter rispondere:

"Da quale autenticazione deriva l'autorità di questo processo?"

---

# 38. PRIVILEGE TRANSITIONS

Registrare esplicitamente:

```text
normal user
 ↓
elevated
 ↓
administrator
 ↓
SYSTEM
 ↓
kernel
```

e la causa del passaggio.

---

# 39. ACCOUNT CREATION POLICY

Creazione account Windows = security-sensitive transition.

Policy default:

```text
authorized interactive creation
    → allow + record

unauthorized creation
    → block

script/software creation
    → block/ask by default
```

Consentire provisioning legittimo tramite eccezioni esplicite.

Monitorare anche:

- privileged group additions;
- reactivation account;
- password modifications;
- logon rights;
- suspicious lookalike accounts.

---

# 40. CREDENTIAL ACCESS FIREWALL

Trattare credential stores come protected resources.

Policy basata su:

- caller;
- parent;
- ancestry;
- software identity;
- provenance;
- target;
- history;
- user intent.

Esempio:

```text
Chrome → Chrome profile
ALLOW

Game.exe → Chrome credential database
DENY
```

---

# 41. BROWSER SESSION PROTECTION

Proteggere/monitorare:

- cookies;
- tokens;
- credential DB;
- browser profiles;
- certificates;
- extensions;
- sensitive browser storage.

---

# 42. SENSITIVE RESOURCES

Telemetria per:

- clipboard;
- screenshot;
- microphone;
- camera.

Correlare sequenze.

Esempio:

```text
screen capture
 ↓
clipboard
 ↓
microphone
 ↓
network upload
```

può essere molto più significativo dei singoli eventi.

---

# 43. DATA SECURITY GRAPH

Creare nodi per:

- documents;
- photos;
- browser data;
- source code;
- SSH;
- backups;
- databases;
- protected folders.

Riconoscere comportamento:

```text
READ
 ↓
AGGREGATE
 ↓
COMPRESS
 ↓
ENCRYPT
 ↓
NETWORK
```

come possibile exfiltration chain.

---

# 44. DEVICES / PERIPHERALS

Costruire identità e storia per:

- USB storage;
- phones;
- Bluetooth;
- external devices.

Memorizzare:

```text
vendor
product
serial
first seen
last seen
driver
files introduced
files removed
```

Correlare:

```text
USB
 ↓
file copied
 ↓
executed
 ↓
persistence
```

---

# 45. REMOTE ADMINISTRATION

Tracciare:

- RDP;
- WinRM;
- SMB;
- remote management tools.

Creare `RemoteSessionIdentity`.

Collegare:

```text
origin
identity
authentication
destination
processes
files
privileges
termination
```

---

# 46. BOOT & FIRMWARE INTEGRITY

Costruire un `BootIdentity`.

Osservare quando disponibile:

- Secure Boot;
- TPM;
- measured boot;
- boot configuration;
- VBS;
- HVCI;
- bootloader;
- important firmware state.

Confrontare con history.

Classificare drift:

```text
EXPECTED
EXPLAINED
UNEXPLAINED
```

---

# 47. DRIVER TRUST ENGINE

Per ogni driver:

```text
hash
version
publisher
certificate
signature
origin
first seen
last changed
device
service
known vulnerabilities
```

Firma valida NON significa sicuro.

Gestire BYOVD come categoria concettuale:

```text
signed
+
known vulnerable
+
unexpected install
+
suspicious ancestry
```

---

# 48. SYSTEM INVARIANTS

Implementare un motore per invarianti.

Esempi:

- security agent remains present;
- protected history cannot silently disappear;
- unauthorized admin does not appear;
- Secure Boot state cannot silently change;
- policy cannot silently weaken;
- recovery store cannot be deleted by ordinary software;
- credential stores cannot be arbitrarily read.

Un invariant violation è distinto da anomaly detection statistica.

---

# 49. SELF-DEFENSE

Il prodotto deve assumere che un attaccante proverà a disattivarlo.

Separare:

```text
UI
Service
Sensors
Policy
History
```

Implementare:

- service recovery;
- watchdog;
- sensor heartbeat;
- cross-sensor verification;
- policy integrity;
- signed configuration;
- protected storage.

Non considerare nessun singolo processo invulnerabile.

---

# 50. SEMANTIC HEARTBEAT

Non basta sapere:

```text
sensor.exe is running
```

Verificare:

```text
sta ancora producendo ciò che dovrebbe osservare?
```

Esempio:

```text
kernel sensor:
317 events

user sensor:
0 events
```

→ Observation Integrity Incident.

---

# 51. DEEP DIAGNOSTIC ENGINE

Creare scansione on-demand capace di ricostruire la realtà corrente.

Fasi:

```text
system census
cross-view enumeration
process inventory
executable inventory
memory evidence
persistence
Registry
services
drivers
software
network
historical comparison
causal reconstruction
```

Deve poter rilevare discrepanze tra rappresentazioni indipendenti.

---

# 52. PUP CLASSIFICATION

Non confondere PUP e malware.

Dimensioni indipendenti:

```text
MALICIOUSNESS
UNWANTEDNESS
TRUST
PRIVILEGE
PRIVACY IMPACT
BEHAVIORAL ANOMALY
```

---

# 53. VULNERABILITY ENGINE

Software inventory:

```text
product
version
components
dependencies
drivers
runtime
```

→ vulnerability knowledge

→ remediation.

Non limitarsi alla versione del programma principale.

---

# 54. PATCH MANAGEMENT

Pipeline:

```text
discover update
 ↓
verify origin
 ↓
verify signature
 ↓
verify applicability
 ↓
snapshot relevant state
 ↓
install
 ↓
verify changed binaries/state
 ↓
behavioral probation
 ↓
confirm
```

Con rollback dove realisticamente possibile.

---

# 55. TARGETED SURVEILLANCE DETECTION

Non implementare detection per una singola famiglia spyware.

Rilevare classi:

- covert persistence;
- credential access;
- token theft;
- cross-process access;
- sensor tampering;
- microphone/camera abuse;
- browser/session access;
- data harvesting;
- low-and-slow exfiltration;
- privilege transitions;
- anti-forensics.

---

# 56. COLLECTIVE IMMUNITY

Solo quando esistono più endpoint.

Ogni endpoint continua a essere completamente autonomo.

Quando un endpoint identifica un attacco, distribuire:

```text
Causal Attack Fingerprint
```

contenente, quando disponibile:

- process ancestry;
- behavior sequence;
- software identity;
- signing identity;
- memory characteristics;
- persistence;
- network behavior;
- target resources.

NON distribuire solamente hash/IP.

---

# 57. FLEET RESPONSE

Confidence escalation:

```text
OBSERVE
 ↓
WARN
 ↓
RESTRICT
 ↓
CONTAIN
 ↓
FLEET BLOCK
```

Mai:

```text
same anomaly on 2 PCs → indiscriminate global block
```

senza altre evidenze.

---

# 58. PATIENT ZERO

La UI fleet deve mostrare:

```text
PC1
 ↓
identity/process
 ↓
PC2
 ↓
attempt
 ↓
PC3 PREVENTED
```

Ogni edge deve essere spiegabile.

---

# 59. PREVENTED INCIDENT

Quando PC3 blocca preventivamente un attacco imparato da PC1/PC2:

NON nascondere l'evento.

Mostrarlo come:

```text
PREEMPTIVE PREVENTION
```

evento principale da investigare.

---

# 60. SINGLE-HOST MODE

Questo è fondamentale.

Se esiste solamente un PC:

NON mostrare inutilmente:

- fleet;
- patient zero;
- endpoint correlation;
- collective immunity configuration.

Non mostrare tab disabilitati.

Nascondere semplicemente le funzionalità che non hanno senso.

Restano attivi:

- detection;
- SIEM;
- history;
- identity;
- ransomware;
- deception;
- network;
- Registry;
- software;
- recovery;
- vulnerability;
- logging;
- forensic analysis.

Quando viene aggiunto un secondo endpoint, far comparire automaticamente la sezione fleet.

---

# 61. CRYPTOGRAPHIC CORE

Creare un'astrazione:

```text
CryptoProvider
KeyStore
Signer
Verifier
KeyAgreement
AEAD
Hash
```

NON implementare primitive crittografiche custom.

---

# 62. POST-QUANTUM CRYPTOGRAPHY

Il prodotto deve essere PQC-ready/native e crypto-agile.

Prevedere supporto tramite librerie affidabili per:

```text
ML-KEM
ML-DSA
SLH-DSA
```

Utilizzarli dove appropriato per:

- endpoint ↔ coordinator;
- fleet messages;
- signed policies;
- signed log checkpoints;
- Evidence Capsules;
- security update signing;
- long-lived forensic evidence.

Per bulk encryption utilizzare primitive simmetriche moderne appropriate.

Non sostituire indiscriminatamente tutta la crittografia con PQC.

Supportare hybrid classical + PQC dove richiesto dall'interoperabilità.

---

# 63. KEY STORAGE

Utilizzare quando possibile:

- Windows protected key storage;
- TPM-backed key protection;
- per-machine identity.

Mai hardcodare private keys.

---

# 64. SECURITY UPDATE SYSTEM

Gli aggiornamenti del prodotto sono estremamente sensibili.

Devono includere:

```text
signed package
hash verification
version
publisher
anti-rollback
transactional install
rollback strategy
```

Un vecchio package correttamente firmato non deve poter essere utilizzato per fare downgrade verso una release vulnerabile senza esplicita autorizzazione.

---

# 65. SECURITY FLIGHT RECORDER

Mantenere un "black box" del sistema.

Deve permettere di ricostruire per esempio:

```text
USB
 ↓
file introduced
 ↓
execution
 ↓
credential access
 ↓
connection
 ↓
Registry persistence
 ↓
remote authentication
 ↓
other endpoint
```

Retention configurabile.

---

# 66. EVIDENCE CAPSULE

Quando un incidente serio viene rilevato:

preservare automaticamente:

- process ancestry;
- hashes;
- software identity;
- relevant event sequence;
- Registry changes;
- relevant file metadata;
- network;
- identity context;
- sensor state;
- deception triggers;
- security policy.

Firmare l'Evidence Capsule.

La remediation non deve distruggere inutilmente le prove.

---

# 67. COUNTERFACTUAL ANALYSIS

Dopo l'incidente:

```text
A → B → C → D → COMPROMISE
```

determinare il punto più precoce in cui sarebbe stato sicuro interrompere la catena.

Esempio:

```text
A too generic
B high false-positive risk
C sufficiently discriminating
D too late
```

La Collective Immunity dovrebbe preferire C.

---

# 68. PRIVACY

Local-first.

Non raccogliere contenuto personale quando bastano metadata.

Separare:

```text
document accessed
```

da:

```text
document contents
```

Il secondo non deve essere acquisito normalmente.

Configurare:

- retention;
- telemetry;
- external intelligence;
- fleet sharing.

Fleet correlation deve condividere il minimo necessario.

---

# 69. PERFORMANCE ARCHITECTURE

Il prodotto deve essere progettato per usare poche risorse.

Obiettivi iniziali, da verificare con benchmark:

- Security Service idle: idealmente <100-150 MB RAM;
- CPU idle: idealmente <0.5%;
- normale monitoraggio: obiettivo medio <2% CPU su macchina moderna;
- zero polling aggressivo;
- batching;
- bounded queues;
- memory pools dove utili;
- lazy enrichment;
- adaptive telemetry.

Non prendere questi numeri come promesse commerciali: misurarli.

Creare benchmark automatici.

---

# 70. ADAPTIVE TELEMETRY

Stato normale:

```text
NORMAL
↓
low/moderate resolution
```

Quando qualcosa diventa sospetto:

```text
SUSPICIOUS
↓
high fidelity telemetry
```

Ridurre overhead nei periodi normali.

---

# 71. BACKPRESSURE

Quando il sistema è sotto carico:

- non bloccare Windows;
- non allocare memoria senza limite;
- non accumulare queue infinite.

Usare bounded channels.

Se telemetria non critica viene persa, generare:

```text
TelemetryLossEvent
```

Non perdere eventi silenziosamente.

---

# 72. NIENTE HEAVY AI PER DEFAULT

Detection primaria:

- deterministic rules;
- state comparison;
- causal graph;
- behavioral statistics;
- anomaly models leggeri.

Modelli ML pesanti devono essere:

- opzionali;
- on-demand;
- fuori dai percorsi critici.

---

# 73. UI TECHNOLOGY

Utilizzare:

```text
Tauri 2
Rust backend
TypeScript
Svelte + Vite
```

oppure equivalente solo se esiste una motivazione tecnica documentata.

Non mettere logica di sicurezza nel JavaScript.

Frontend = presentazione/query.

---

# 74. UI PROCESS MODEL

La UI gira senza privilegi elevati.

Quando serve un'operazione privilegiata:

```text
UI
 ↓
authenticated request
 ↓
Security Service
 ↓
authorization
 ↓
action
```

Usare IPC locale autenticato con ACL.

Validare sempre:

- caller;
- session;
- message schema;
- permissions.

---

# 75. UX PHILOSOPHY

La UI deve essere:

- estremamente comprensibile;
- moderna;
- pulita;
- professionale;
- non intimidatoria;
- non infantile;
- non "scareware";
- accessibile.

La semplicità deve derivare da progressive disclosure, NON dalla rimozione delle funzionalità.

---

# 76. LIGHT / DARK MODE

Supportare:

```text
System
Light
Dark
```

Cambio immediato.

Usare design tokens CSS.

Non duplicare stili manualmente.

---

# 77. ACCESSIBILITÀ

Supportare:

- keyboard navigation;
- screen reader;
- focus indicators;
- contrast adeguato;
- high DPI;
- scalable fonts;
- non affidarsi solamente al colore;
- color blindness friendly visual language.

---

# 78. LOCALIZZAZIONE

Preparare fin dall'inizio i18n.

Almeno:

```text
Italian
English
```

Nessuna stringa UI importante hardcoded nei componenti.

---

# 79. PROGRESSIVE DISCLOSURE

Non creare "modalità stupido" e "modalità esperto" con capacità differenti.

Creare invece livelli di dettaglio.

Esempio:

Vista semplice:

```text
Credential theft attempt blocked
```

Espandi:

```text
GameSetup.exe
 ↓
temp\a91.exe
 ↓
browser credential access
 X BLOCKED
```

Dettaglio tecnico:

```text
PID
SID
logon session
token
hash
signature
file path
events
causal edges
raw evidence
```

Stessa detection, tre livelli.

---

# 80. TOOLTIPS EDUCATIVI

Ogni opzione non immediatamente comprensibile deve avere tooltip.

Hover/focus:

```text
Memory Integrity

Controlla che processi e componenti sensibili non subiscano
modifiche inattese in memoria.
```

Breve.

Aggiungere:

```text
Scopri di più
```

per spiegazioni più approfondite.

Non usare tooltip di 500 parole.

---

# 81. "PERCHÉ?"

Ogni alert deve avere un pulsante:

```text
Perché?
```

che mostra la spiegazione causale.

Esempio:

```text
Bloccato perché:

1. programma scaricato da Internet
2. prima esecuzione
3. ha letto il database credenziali browser
4. non lo aveva mai fatto prima
5. ha successivamente tentato una connessione first-seen
```

---

# 82. UI NAVIGATION

Navigation proposta:

```text
Overview
Incidents
Activity
Applications
Network
Identity
Devices
Vulnerabilities
Recovery
Investigate
Security Log
Settings
```

Quando fleet:

```text
Endpoints
Fleet
Collective Immunity
```

---

# 83. DASHBOARD

La dashboard non deve essere un muro di grafici inutili.

Mostrare:

```text
Protection status
Active incidents
Prevented incidents
Unresolved anomalies
Recent software changes
Identity events
Ransomware protection
Sensor health
Update state
```

---

# 84. INCIDENT VIEW

Layout principale:

```text
INCIDENT TITLE
severity / status / time

WHAT HAPPENED

WHY IT MATTERS

WHAT WAS BLOCKED

CAUSAL TIMELINE

PROCESS TREE

RELATED FILES

NETWORK

IDENTITY

ACTIONS

RAW EVIDENCE
```

---

# 85. GRAPHICAL INCIDENT VIEW

Implementare grafo interattivo.

Nodi differenziati:

```text
process
user
file
domain
machine
credential
Registry
```

Edge etichettati.

Supportare:

- zoom;
- pan;
- collapse;
- filter;
- time range;
- highlight causal path.

Non renderizzare 100.000 nodi contemporaneamente.

Progressive aggregation.

---

# 86. SECURITY LOG / SIEM UI

Creare un vero SIEM locale.

Funzioni:

- time filtering;
- event type;
- severity;
- process;
- user;
- host;
- domain/IP;
- software;
- free-text search;
- saved queries;
- pivot;
- causal expansion;
- export.

---

# 87. QUERY LANGUAGE

Creare un linguaggio semplice.

Esempio:

```text
process.name = "powershell.exe"
AND network.destination.first_seen = true
```

oppure:

```text
credential_access
FOLLOWED_BY network_connection
WITHIN 60s
```

e:

```text
RELATED_TO incident:721
```

Implementare parser dedicato.

NON usare `eval`.

---

# 88. QUERY BUILDER

Per utenti non tecnici offrire query visuali:

```text
[Process] [is] [powershell.exe]
+
[Destination] [is first seen]
```

e generare la query sottostante.

---

# 89. COMMAND PALETTE

Aggiungere ricerca globale:

```text
Ctrl+K
```

per:

- settings;
- incidents;
- software;
- query;
- help;
- actions.

Riduce complessità della navigazione.

---

# 90. ONBOARDING

Prima configurazione breve.

Mostrare:

1. stato protezione;
2. cosa viene monitorato;
3. privacy;
4. ransomware recovery;
5. deception opzionale;
6. default raccomandati.

Non costringere l'utente a configurare 100 opzioni.

---

# 91. SAFE DEFAULTS

Impostazioni default devono privilegiare:

```text
security
+
compatibility
+
low noise
```

Non mostrare popup per ogni evento.

Usare notification solamente quando richiedono attenzione umana.

---

# 92. REVERSIBLE ACTIONS

Dove possibile, le azioni devono essere reversibili.

Esempio:

```text
quarantine
network isolation
policy change
software rollback
```

Mostrare:

```text
Undo
```

solo quando tecnicamente sicuro.

---

# 93. POLICY HISTORY

Ogni modifica:

```text
who
when
old
new
reason
```

Versionare policy.

UI:

```text
v17
 ↓
user modification
 ↓
v18

Compare
Rollback
```

---

# 94. PERFORMANCE UI

La UI NON deve funzionare in background se chiusa.

Il Security Service continua.

WebView/UI process si chiude realmente.

System tray deve essere opzionale.

---

# 95. STARTUP

Non lanciare automaticamente la finestra all'avvio Windows.

Avviare solamente:

```text
Security Service
```

La UI viene aperta dall'utente o per alert importanti.

---

# 96. INSTALLER

L'installazione deve:

- spiegare chiaramente i componenti privilegiati;
- installare service;
- eventualmente driver;
- verificare firma;
- supportare clean uninstall;
- non lasciare driver/services orfani.

---

# 97. DEGRADED MODES

Progettare esplicitamente:

```text
Internet unavailable
Cloud unavailable
Coordinator unavailable
DNS intel unavailable
UI unavailable
Sensor degraded
Kernel sensor unavailable
Windows logging damaged
```

La protezione locale deve continuare quanto possibile.

---

# 98. NO CLOUD REQUIREMENT

Nessun account cloud obbligatorio.

Threat intelligence esterna può essere opzionale.

Core protection deve essere locale.

---

# 99. OFFLINE RECOVERY

Progettare una futura recovery utility indipendente dal Windows compromesso.

Deve poter confrontare:

```text
CURRENT OFFLINE STATE
vs
LAST VERIFIED STATE
vs
HISTORICAL STATE
```

Non implementarla nella primissima milestone, ma progettare storage e evidence affinché sia possibile.

---

# 100. TESTING

Richiedo:

```text
unit tests
integration tests
property tests
parser fuzzing
event replay tests
storage corruption tests
policy tests
UI tests
performance benchmarks
```

---

# 101. SECURITY REPLAY HARNESS

Creare una suite che simuli eventi benigni e malevoli SENZA malware reale.

Esempio:

```text
process create
file write
credential access synthetic event
network event
```

Usarla per riprodurre causal chain.

---

# 102. FUZZING

Fuzzare almeno:

- telemetry parsers;
- event decoder;
- IPC;
- query language;
- policy parser;
- external intelligence parsers.

---

# 103. DEPENDENCY SECURITY

Utilizzare:

- Cargo.lock;
- dependency auditing;
- license auditing;
- SBOM;
- minimal dependencies.

Nessuna dipendenza abbandonata senza motivazione.

---

# 104. REPRODUCIBLE BUILDS

Puntare a build riproducibili.

CI deve produrre:

```text
binary
hash
SBOM
test results
benchmark summary
```

---

# 105. OBSERVABILITY DEL PRODOTTO

Il prodotto deve monitorare anche se stesso.

Metriche interne:

```text
events/sec
events dropped
queue utilization
CPU
RAM
disk writes
sensor latency
storage latency
query latency
```

Non inviare automaticamente queste metriche fuori dal PC.

---

# 106. PERFORMANCE REGRESSION CI

Creare benchmark e fallire/warn CI quando:

- memoria aumenta significativamente;
- event throughput peggiora;
- query peggiorano;
- startup peggiora;
- binary size cresce senza motivo.

---

# 107. CODING STANDARD

Rust:

- rustfmt;
- clippy;
- warnings treated seriously;
- explicit errors;
- no panic nei service paths;
- no `.unwrap()` per eventi runtime non garantiti;
- structured logging;
- cancellation-aware tasks;
- bounded concurrency.

---

# 108. ERROR HANDLING

Distinguere:

```text
temporary error
sensor unavailable
permission problem
corrupt data
programming bug
```

Non trasformare tutto in generic `Error`.

---

# 109. NO SILENT FAILURE

Se un sensore fallisce:

NON:

```text
continue as if protection still complete
```

Generare:

```text
PROTECTION DEGRADED
```

e mostrarlo.

---

# 110. FEATURE CAPABILITY MATRIX

Prima di implementare ogni feature creare:

```text
Feature
User mode possible?
Kernel required?
Administrator required?
Reboot required?
Windows edition dependency?
Hardware dependency?
Single host?
Fleet?
Performance impact?
```

Non fingere di supportare una capacità che Windows non consente.

---

# 111. NON CREARE FUNZIONI FINTE

La UI NON deve contenere pulsanti che semplicemente mostrano mock data.

Durante sviluppo i mock devono essere chiaramente:

```text
development-only
```

e non finire nella release.

---

# 112. IMPLEMENTATION STRATEGY

NON tentare di implementare tutto simultaneamente.

Procedere per vertical slices.

---

# PHASE 0 — ARCHITECTURE

Prima di scrivere molte feature, produrre:

```text
docs/ARCHITECTURE.md
docs/THREAT_MODEL.md
docs/EVENT_SCHEMA.md
docs/SECURITY_MODEL.md
docs/PRIVACY.md
docs/PERFORMANCE_BUDGET.md
docs/FEASIBILITY.md
docs/ROADMAP.md
```

Documentare decisioni con ADR.

---

# PHASE 1 — FOUNDATION

Implementare:

```text
Cargo workspace
Windows Service
Tauri UI
authenticated IPC
common models
configuration
basic storage
event schema
event ingestion
health monitoring
```

UI iniziale:

```text
Dashboard
Activity
Security Log
Settings
```

---

# PHASE 2 — FIRST REAL TELEMETRY

Integrare sorgenti reali:

```text
ETW
Windows Event Log
process lifecycle
image/module
basic Registry
basic network
authentication
```

ETW deve essere una delle sorgenti principali di user-mode telemetry.

---

# PHASE 3 — EVENT FABRIC + SIEM

Implementare:

```text
normalization
raw evidence
indexes
query engine
filters
event detail
timeline
retention
integrity chain
```

A questo punto il prodotto deve già essere utile come sistema investigativo locale.

---

# PHASE 4 — CAUSAL GRAPH

Aggiungere:

```text
process relationships
identity relationships
file relationships
network relationships
causal timeline
incident graph UI
```

---

# PHASE 5 — SOFTWARE / REGISTRY HISTORY

Implementare:

```text
software inventory
hashing
signatures
Registry history
expected state
software genealogy
version behavior comparison
```

---

# PHASE 6 — POLICY / INTENT / CAPABILITY

Implementare:

```text
SecurityTransaction
Intent Engine
Capability Contract
Behavior Diff
Policy history
```

---

# PHASE 7 — RANSOMWARE PROTECTION

Implementare:

```text
canary set
modification-rate detection
Blast Radius Limiter
Evidence Capsule
protected recovery metadata
```

Testare esclusivamente con simulatori innocui.

---

# PHASE 8 — DECEPTION

Implementare:

```text
decoy files
decoy identity
decoy credentials
decoy Registry artifacts
deception events
```

---

# PHASE 9 — IDENTITY

Implementare:

```text
sessions
tokens
privileges
account creation
group changes
remote sessions
credential-sensitive resources
```

---

# PHASE 10 — NETWORK INTELLIGENCE

Implementare:

```text
process/network attribution
DNS history
TLS metadata
first-seen infrastructure
per-software behavior
```

---

# PHASE 11 — RESPONSE

Implementare:

```text
process terminate/suspend
quarantine
network restriction
software containment
transaction rollback
evidence preservation
```

Ogni response deve essere auditata.

---

# PHASE 12 — KERNEL SENSOR

Solo adesso valutare le visibilità mancanti.

Creare componente kernel MINIMALE per ciò che user-mode non può fare sufficientemente bene.

---

# PHASE 13 — BOOT / DRIVER / SYSTEM INTEGRITY

Implementare:

```text
driver genealogy
boot identity
Secure Boot state
TPM/measured boot where available
VBS/HVCI state
configuration drift
```

---

# PHASE 14 — VULNERABILITY / PATCHING

Software inventory → advisory feed → remediation.

Separare feed esterni dal core.

---

# PHASE 15 — COLLECTIVE IMMUNITY

Aggiungere solo dopo che il singolo endpoint è robusto.

Implementare:

```text
coordinator
endpoint enrollment
mutual authentication
causal fingerprint sharing
patient zero
prevented incident
fleet graph
```

---

# PHASE 16 — PQC

Il layer crypto deve essere predisposto dall'inizio.

Quando librerie/protocolli scelti sono sufficientemente maturi:

implementare provider PQC/hybrid senza modificare il resto dell'architettura.

---

# 113. REQUIREMENT FINALE PER CODEX

Non limitarti a generare codice.

Per ogni milestone:

1. analizza il requisito;
2. verifica quali API Windows documentate permettono di implementarlo;
3. documenta eventuali limitazioni;
4. implementa il vertical slice;
5. aggiungi test;
6. misura performance;
7. aggiorna documentazione;
8. esegui formatter/linter/test;
9. verifica che UI e service comunichino realmente;
10. non dichiarare completata una funzione che usa solamente mock;
11. non introdurre dipendenze inutilmente pesanti;
12. non compromettere sicurezza per comodità.

Se una feature richiede una soluzione fragile/non documentata, NON implementare hack silenziosi.

Documenta invece:

```text
desired behavior
Windows limitation
available supported alternatives
recommended implementation
```

---

# 114. PRIORITÀ ASSOLUTE

In ordine:

```text
CORRECTNESS
SECURITY
RELIABILITY
EXPLAINABILITY
LOW RESOURCE USAGE
USABILITY
PERFORMANCE
VISUAL QUALITY
FEATURE COUNT
```

Una feature incompleta ma corretta è preferibile a una falsa feature "completa".

---

# 115. OBIETTIVO UX FINALE

Una persona poco esperta deve poter vedere:

"È tutto protetto."

oppure:

"Abbiamo bloccato un programma che ha provato a leggere le credenziali del browser."

senza comprendere PID, ETW o token Windows.

Un analista deve poter aprire lo stesso evento e vedere:

```text
process tree
token
logon session
hash
signature
Registry
network
raw events
causal edges
policy
response
```

Non creare due prodotti differenti.

Creare due livelli di rappresentazione della stessa verità.

---

# 116. DEFINIZIONE DEL PRODOTTO

Considerare il prodotto come una piattaforma basata su sei proprietà:

```text
OBSERVABILITY
vedere ciò che realmente accade

INTEGRITY
sapere se stato e componenti sono autentici

CAUSALITY
sapere cosa ha causato cosa

MEMORY
sapere come il sistema è arrivato allo stato attuale

INTENT
sapere cosa l'utente aveva realmente autorizzato

IMMUNITY
trasformare un attacco compreso su una macchina
in prevenzione sulle altre
```

e tre dimensioni temporali:

```text
PAST
Security Memory / Forensics / Recovery

PRESENT
Observation / Detection / Containment

FUTURE
Collective Immunity / Prevention
```

Questa architettura deve guidare l'intero sviluppo.

Non trasformare il progetto in una raccolta di moduli antivirus indipendenti.

Tutti i componenti devono convergere su:

```text
SECURITY EVENT FABRIC
+
CAUSAL SECURITY GRAPH
+
HISTORICAL STATE
+
POLICY / INTENT
```

Questi sono il nucleo del prodotto.