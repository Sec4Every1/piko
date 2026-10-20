# Fattibilità Windows di piko

Verifica documentale: **2026-10-04**. Le fonti collegate sono documentazione primaria Microsoft, salvo SQLite e NIST nelle rispettive sezioni. La disponibilità di un'API non dimostra copertura, compatibilità o sicurezza della nostra implementazione: queste richiedono test. Le righe future non sono funzionalità consegnate.

## Piattaforme

Target primario: Windows x86-64/AMD64, processi nativi e WOW64. La policy del prodotto obiettivo copre release client e Server ancora supportate, senza creare edizioni piko diverse. Il prototipo non certifica ancora una matrice di sistemi operativi.

La matrice di qualifica dovrà registrare edition, build, patch, support lifecycle, architettura, modalità Desktop Experience/Server Core, WebView2 e capacità rilevate. Windows 11 segue cicli per release/edizione; per Server la documentazione corrente include 2016, 2019, 2022 e 2025 con date di supporto differenti. Versioni LTSC/ESU vanno valutate con il loro lifecycle effettivo, non deducendolo dal nome “Windows 10”. Le API con un vecchio “minimum supported client” non autorizzano a dichiarare supporto del prodotto su un OS fuori manutenzione. [Windows 11 lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro), [Windows Server release information](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info).

Il core e la CLI devono funzionare senza desktop sul Server; la UI Tauri/WebView2 richiede un ambiente grafico compatibile e viene qualificata separatamente. Un Server Core non deve perdere capacità locali perché manca una WebView. Non si installano componenti GUI come requisito del monitoraggio.

## Feature capability matrix

Legenda: U = user mode; K = nostro driver kernel; A = privilegi amministrativi/installazione; R = reboot; E = dipendenza edition/build/policy Windows; H = hardware. “No” nella colonna K non esclude componenti kernel già presenti in Windows. Tutte le voci sono design tranne la prima slice di health/storage/UI. Costi qualitativi da misurare, non benchmark.

| Feature | U possibile? | K richiesto? | A? | R? | E? | H? | Singolo host? | Fleet? | Impatto previsto |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Self-health, storage, query iniziali | Sì | No | No nel dev | No | API desktop | No | Sì | No | Basso |
| SCM, autostart, recovery del servizio | Sì | No | Installazione | Normalmente no | Service Control Manager | No | Sì | No | Basso |
| ETW process/thread/image | Sì, copertura variabile | No iniziale | Session/provider specifico | No | Provider e ACL | No | Sì | Opzionale | Variabile |
| Event Log/authentication | Sì se audit attivo | No | Canale/policy | No | Audit, canali, privilegi | No | Sì | Opzionale | Basso–medio |
| File metadata/change observation | Parziale | No | Risorse protette | No | Filesystem/API | No | Sì | No | Variabile |
| File read/write mediation preventiva | Non generale same-user | Minifilter per controllo fine | Sì | Possibile deployment | Filesystem/HVCI/signing | No | Sì | No | Critico, da misurare |
| Registry history | Parziale via notify/ETW | Per copertura/mediation fine | HKLM/ACL | Possibile con driver | Viste WOW64/provider | No | Sì | No | Variabile |
| Software inventory/genealogy | Sì, attribution parziale | No iniziale | Alcune risorse | No | Installer/package format | No | Sì | Opzionale | I/O hashing |
| Supply-chain attribution npm/PyPI/NuGet | Sì con provenance e strumenti | No iniziale | Non normalmente | No | Tool/version integration | No | Sì | Opzionale | Variabile |
| Intent/capability/policy history | Sì, decision model | Dipende dall'azione | Dipende dalla policy | Dipende dall'azione | Enforcement disponibile | No | Sì | Opzionale | Basso–medio |
| Probation eseguibile | Parziale con contenimento/App Control | Non sempre | Policy deployment | Possibile | App Control e build | No | Sì | Opzionale | Compatibilità |
| Ransomware detection/canary | Sì, best effort | Non per sola detection | Store protetto | No iniziale | Visibilità file | No | Sì | Opzionale | I/O e latenza |
| Blast radius garantito prima delle write | Non generale | Minifilter o contenimento equivalente | Sì | Possibile | Semantica filesystem | No | Sì | No | Percorso I/O critico |
| Decoy file/Registry/identity | Sì | Non iniziale | Account/HKLM | Normalmente no | Audit e diritti account | No | Sì | Opzionale | Basso |
| Token/session/privilege lineage | Parziale | Per segnali mancanti, da valutare | Token protetti | Possibile driver | PPL, privilege/audit | No | Sì | Opzionale | Variabile |
| Account creation block universale | Nessun veto generale scelto | Non risolto dal solo driver | Policy amministrativa | Variabile | Local/domain provisioning | No | Sì | Opzionale | Rischio compatibilità |
| Credential/browser access firewall | Metadata parziali | File mediation per parte del problema | Sì per mediazione | Possibile | Browser, PPL, storage | No | Sì | No | Critico |
| Clipboard/screen/mic/camera attribution | Parziale, sorgente da qualificare | Nessuna garanzia universale | Sorgente specifica | Non definito | Modello app/API privacy | Device pertinente | Sì | No | Privacy/compatibilità |
| Network observe + WFP filter | Sì con limiti | Per callout specializzati | Gestione filtri | Di norma no per filtri U | Layer WFP/provider | Rete | Sì | Opzionale | Throughput/latency |
| DNS/DoH/TLS/certificate metadata | Parziale | Non elimina cifratura | Provider specifico | No | Stack/app/protocollo | Rete | Sì | Opzionale | Variabile |
| USB/device/remote-session history | Sì, attribution da correlare | Non iniziale | Canali protetti | No per observe | Driver/protocollo/canali | Device/rete | Sì | Opzionale | Basso–medio |
| Terminate/quarantine/network restriction | Sì parziale | Per garanzie aggiuntive | Target/policy | Raro | Diritti/PPL/handle | No | Sì | Opzionale | Azione mirata |
| Protected recovery store/VSS | Parziale | Difesa fine opzionale | Sì | Recovery offline sì | Filesystem/writer/backup | Spazio/disco esterno opz. | Sì | Opzionale | I/O alto |
| Boot/Secure Boot/TPM/VBS/HVCI | Observe secondo API | Non necessariamente | Alcune query/config | Per cambiare stato | Firmware/build/config | TPM/UEFI/virtualization | Sì | Opzionale | Query basso |
| Self-defense forte | Limitata | ELAM/PPL con requisiti specifici | Sì | Possibile | Signing/Windows policy | Secure Boot opzionale | Sì | No | Disponibilità critica |
| Vulnerability/patch intelligence | Sì | No | Installare patch | Dipende dalla patch | Applicabilità e package | No | Sì | Opzionale | Feed/hashing/install |
| SIEM/grafo/capsule/counterfactual | Sì | No | Scope dati | No | No nuova dipendenza | Storage/RAM | Sì | Opzionale | Query/memoria |
| Potential Attack Graph e shortest paths | Sì; relazioni solo con precondizioni qualificate | No per calcolo | ACL/sorgenti protette possono richiederli | No | API Authz/token/security descriptor e contesto | RAM/storage | Sì, senza AD/Entra | Estensione | Bounded exploration e cache |
| Counterfactual permission/capability/policy | Sì, overlay senza applicazione | No per analisi | Lettura stato secondo scope | No | Semantica enforcement disponibile | RAM/storage | Sì | Estensione | Diff incrementale |
| Observed Path Progression e cut points | Sì con eventi e topology reali | Solo eventuale azione scelta | Dipende da response | Dipende dall'azione | Coverage sensori/azione | No aggiuntivo | Sì | Precondizioni locali obbligatorie | Correlazione e query limitate |
| Collective immunity/anchoring | Sì | No | Enrollment/response | No | Protocollo | Rete | Core resta autonomo | Necessaria | Banda/storage |
| PQC/hybrid | Con libreria/provider qualificato | No | Key provisioning | No | Provider/interoperabilità | TPM support variabile | Sì | Opzionale | Key/signature size |

## API e gap che influenzano l'architettura

### ETW e Windows Event Log

ETW offre controller, provider e consumer; `StartTrace`, `EnableTraceEx2`, `OpenTrace` e `ProcessTrace` sono la base prevista. Session ownership, privilegi, schema provider e buffer loss sono parte del contratto sensore. Non trattare un evento post-factum come barriera preventiva. `EvtSubscribe` può seguire canali supportati con callback/pull; bookmark e resubscription devono affrontare rollover e gap. Security log richiede audit e accesso effettivo. [ETW session setup](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session), [ETW e missing events](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing), [EvtSubscribe](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe).

**Implementazione consigliata:** acquisire provider documentati uno alla volta, fixture per versione, raw conservato, contatori loss, prova start/stop/restart e confronto con un census indipendente. Nessuna sorgente ETW è dichiarata attiva nella prima slice di self-health.

### File, Registry e WOW64

`ReadDirectoryChangesW` notifica modifiche della directory, può perdere dati se il buffer non basta e non fornisce di per sé un'attribuzione universale al processo o pre-image. `RegNotifyChangeKeyValue` segnala cambiamenti, non una storia completa di ogni valore intermedio con attore. Non può garantire `A → B → A` se si vede solo lo snapshot finale. [ReadDirectoryChangesW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw), [RegNotifyChangeKeyValue](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue).

**Desiderato:** mediare un accesso prima che alteri o riveli una risorsa. **Limite:** notifiche user-mode arrivano dopo o senza l'autorità per negarlo. **Alternativa supportata:** minifilter con callback pre/post per file; callback Registry documentate per mediazione. **Decisione:** observation prima, driver minimale solo con caso misurato; nessuna promessa di “freeze” atomico del filesystem in user-mode. [Filter Manager I/O](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/processing-i-o-operations), [Registry filtering](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filtering-registry-calls).

Per WOW64 usare esplicitamente `KEY_WOW64_32KEY`/`KEY_WOW64_64KEY`, registrare quale vista è stata letta e rispettare la redirezione filesystem. Due path testuali non sono necessariamente due file diversi, né lo stesso testo identifica sempre la stessa risorsa tra viste. [Alternate Registry View](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view), [File System Redirector](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector).

### Intent, account e credential firewall

**Desiderato:** autorizzare soltanto creazioni account coerenti con una transazione. **Limite verificato:** l'API di creazione `NetUserAdd` esegue access check Windows, non espone un callback generale al nostro servizio per chiedere consenso su tutte le altre creazioni. L'inferenza di progetto è che le API user-mode scelte non implementano quel veto universale. **Alternative:** least privilege, provisioning controllato, policy Windows e detection di audit; response successiva non equivale a prevenzione. Non intercettare API private SAM o modificare strutture kernel. [NetUserAdd](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd).

App Control può limitare quali applicazioni/driver eseguono, con caratteristiche dipendenti da release/build e gestione. Non è un motore universale di capability per ogni singola operazione di un processo già avviato. Le pagine Microsoft distinguono feature disponibili e requisiti di edizione/licensing; la qualifica non va ridotta alla frase “funziona ovunque”. [Feature availability](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability), [Application Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol).

Il credential firewall copre più superfici: file DB, memoria del browser, IPC, estensioni e sessione autenticata. Un minifilter può aiutare con i file ma non garantisce isolamento completo di una sessione compromessa. Non si leggono password/cookie per “proteggerli”, non si aggirano PPL/Credential Guard e non si promette un veto generico su ogni screenshot o accesso al microfono. Le fonti per tali risorse vanno provate per modello app e build: la presenza di controlli privacy Windows non implica un feed terze parti completo. [Windows privacy controls](https://learn.microsoft.com/en-us/windows/security/book/privacy-controls).

### Rete e traffico cifrato

WFP fornisce filtri e layer documentati per gestione del traffico; molte policy possono essere installate da user-mode, mentre callout specializzati sono kernel. Occorre qualificare process attribution, loopback, IPv4/IPv6, VPN, servizi condivisi e rollback dei filtri. [About Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform).

La ricostruzione `process → DNS → domain → IP → TLS` è un grafo di evidenze con confidence, non una catena sempre disponibile. DNS cache, proxy, connessioni condivise, DoH/DoT e handshake cifrati creano ambiguità. **Decisione progettuale:** mostrare “non disponibile” e usare metadata realmente osservati; niente TLS interception indiscriminata né giudizi di maliciousness basati sul Paese.

### Recovery, self-protection e driver

VSS crea snapshot coordinabili con writer; uno snapshot crash-consistent può contenere I/O incompleto. Non è di per sé una storia immutabile fuori dal controllo dell'amministratore. Recovery protetta richiede separazione d'autorità, verifica pre-image, gestione dello spazio e prove di restore. Il known plaintext dei canary non garantisce recupero delle chiavi ransomware. [VSS snapshots](https://learn.microsoft.com/en-us/windows/win32/vss/shadow-copies-and-shadow-copy-sets).

PPL per anti-malware richiede un percorso specifico di trust e signing/ELAM; watchdog e SCM recovery sono capacità diverse. Un kernel ostile resta fuori da una promessa di invulnerabilità locale. [Protecting anti-malware services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-).

Il driver futuro richiede signing del percorso Microsoft applicabile e qualifica HLK/HVCI. Secondo l'addendum C è esplicitamente ammesso e può essere preferibile per il componente WDK minimo quando riduce il rischio complessivo; Rust WDK non è un requisito dogmatico. Il confronto concreto è obbligatorio prima di implementare o migrare. Non chiedere agli utenti di disabilitare Secure Boot o abilitare test signing come normale installazione. [Driver Signing Policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-).

### Attack paths e accesso effettivo

AuthzAccessCheck consente di valutare un contesto contro un security descriptor; non dimostra da sola possesso di credenziali, bypass MFA, raggiungibilità applicativa o sfruttabilità. Un arco potenziale conserva mapping access mask, stato token/ACL, precondizioni e freschezza. Per esempio `CAN_REACH_NETWORK` non autorizza a derivare `CAN_AUTHENTICATE`. [Microsoft Authz](https://learn.microsoft.com/en-us/windows/win32/secauthz/checking-access-with-authz-api), verificato 2026-10-04.

Gli engine rimangono user-mode safe Rust e non richiedono graph stack aggiuntivi. Le condizioni controfattuali non cambiano il sistema; i cut points sono proposte da valutare con impatto operativo e alternative residue. L'enforcement necessario al cut point usa la propria riga della matrice, senza attribuire al grafo capacità Windows inesistenti. Vedere [ATTACK_PATH_MODEL.md](ATTACK_PATH_MODEL.md).

### PQC

NIST ha finalizzato standard per ML-KEM, ML-DSA e SLH-DSA. Questo non certifica una particolare libreria Rust, protocollo hybrid o provider TPM. La decisione è rendere gli envelope crypto versionati e sostituibili; qualificare provider mantenuti con test vector, interoperabilità e audit prima dell'uso. Nessuna primitiva crypto custom. [NIST PQC standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards).

## Gate per una nuova feature

Prima del codice: aggiornare la matrice, enumerare API/provider e privilegi, scrivere limite Windows e fallback, definire dato personale raccolto e test innocuo. Prima di dichiararla completa: implementazione reale, test su build target, simulazione di errore/perdita, benchmark e UI aderente al risultato. “Non supportato” è un risultato valido; un mock non è una soluzione al limite della piattaforma.
