# ADR 0010 — Score espliciti e controllo rete per eseguibile

Data: 2026-10-08. Stato: implementato; qualifica amministrativa end-to-end da completare.

## Decisione e confini

Le valutazioni rimangono safe Rust in security-core. Event-storage ricostruisce
nomi e score dalle evidenze XML con digest verificato, anche per dati precedenti.
Il modello versionato piko-risk-v1 espone fattori e punti, non probabilità calibrate;
false_positive_probability resta null. Nessun PID emittente viene attribuito come autore.

app-control è safe Rust: piani bounded (32, cinque minuti), hash, controllo del
percorso, validazione e consumo singolo prima di UAC. win-platform contiene solo
l’adapter Registry, COM Firewall, handle di file/cartelle e ShellExecuteEx.
L’interfaccia Tauri presenta dati e inoltra richieste; la decisione non è nel frontend.

Per questo controllo non viene estesa l’autorità del servizio/pipe: le letture di
inventario (HKCU dell’utente visibile) e firewall passano dal bridge Tauri direttamente
al boundary locale. Una modifica esplicita avvia l’adiacente piko-network-helper.exe
con il verbo runas. La UI resta non elevata; Windows gestisce consenso/credenziali.
Questa separazione consente di usare il controllo anche senza installazione SCM.
Il binario helper è un quarto artefatto nel manifest e viene copiato anche dall’installer.
In sviluppo deve essere copiato accanto al desktop prima di provare la conferma.

## Identità, effetti e recupero

Il payload è JSON strict codificato hex, limitato a 24 KiB, senza comandi shell,
script, URL o destinazioni arbitrarie di scrittura. L’helper ricontrolla scadenza,
token amministrativo, ID, percorso e hash. Sono accettati solo percorsi DOS locali
.exe fino a 256 MiB; Windows, cartella piko, UNC, ADS e reparse point sono esclusi.
Le cartelle vengono aperte da radice a foglia negando scrittura/rinomina; il file
resta aperto senza share write/delete. Il percorso finale deriva dall’handle.

La regola è outbound BLOCK per un percorso, tutti i profili/protocolli/destinazioni.
Il suo nome deriva da SHA-256 del percorso normalizzato e il gruppo è
piko network control. Add/Remove non cambiano impostazioni globali o regole altrui.
Template, duplicati, collisioni e modifiche esterne sono controllati prima e dopo.
Gli amministratori possono comunque concorrere: COM non offre compare-and-swap.
La rimozione è ammessa senza il file originale e anche con firewall disabilitato;
non crea una regola ALLOW. Nessun replay automatico in caso di esito incerto.

Il registro Application di Windows, origine piko, conserva intento prima dell’effetto
ed esito dopo. Un errore della scrittura iniziale impedisce la modifica. Errori finali
o timeout richiedono rilettura delle regole prima di riprovare.

Le regole persistono dopo la chiusura/disinstallazione di piko e riguardano tutti gli
utenti. Non seguono identità del processo, firma, hash, figli, proxy o copie in altri
percorsi. L’inventario uninstall non è un elenco completo di eseguibili né prova di
provenienza. FirewallEnabled è configurazione locale: policy di dominio e traffico
effettivo richiedono verifiche distinte. La UI non chiama “protetto” un percorso solo
per la presenza della regola e sospende nuovi blocchi su profili esclusi/disabilitati.

## Verifica

Test: parser/namespace/identità di eventi, ricalcolo storico, score; piani scaduti o
alterati, payload ostile, handle contro riscrittura/rinomina; snapshot nativi reali
Registry/Firewall; template COM creato solo in memoria; collisioni/duplicati; UI
prepara/conferma/rimozione/errori, dati mancanti e profili disabilitati.
I test automatici non aggiungono regole al firewall del PC. Restano da qualificare
UAC con credenziali alternative, policy di dominio e prova del traffico bloccato
su macchina di test amministrativa. Questi limiti non sono coperti dalle fixture UI.

Fonti: [INetFwPolicy2](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2),
[LocalPolicyModifyState](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_localpolicymodifystate),
[ShellExecuteEx](https://learn.microsoft.com/en-us/windows/win32/shell/launch).

