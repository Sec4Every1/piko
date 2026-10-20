# ADR 0013 — Griglia app e scoperta degli eseguibili

Inventario nativo: InstallDate e DisplayIcon aggiunti come metadati non attendibili;
nessuna firma verificata o identita di prodotto derivata dai nomi. Date valide
YYYYMMDD ordinate nel frontend; sconosciute ultime. InstallDate puo indicare una
manutenzione: https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key

Discovery in safe Rust in app-control; unica FFI rimane win-platform.
Il bridge riceve solo app_id, rilegge il registro e cerca file locali .exe da
DisplayIcon e InstallLocation. Nessun comando, espansione ambiente o programma
viene eseguito. Directory generiche, Windows, UNC, reparse point e ADS sono
esclusi. Lock dei parent durante la scansione; metadati bounded per voce,
1024 voci, 32 candidati, profondita 3 e deadline cooperativa 2s. Le chiamate OS
possono superare la deadline; non si dichiara una cancellazione di I/O nativo.
File trovati sono solo candidati: identita, header, dimensione, hash e path sono
verificati nuovamente dal Controller e dall'helper prima del firewall.

UI: 12 schede per pagina, ricerca e selezioni preservate, massimo 10 app e 20
eseguibili per anteprima. Percorsi deduplicati, singoli file escludibili.
Nessun effetto dalla selezione. I piani esistenti sono consumati sequenzialmente
con il normale helper UAC: nessun indebolimento del confine amministrativo.
Errore/cancellazione interrompe il gruppo; esiti individuali e refresh delle
regole reali. Nessuna transazione globale o rollback implicito. I piani annullati
sono scartati; quelli non raggiungibili scadono entro cinque minuti.

File fuori installazione, file di sistema e aggiornamenti rimangono disabilitati.
Non si usano ACL del normale utente come sandbox per un singolo programma.
Il blocco rete per percorso non e isolamento dei figli ne blocco universale degli
updater. Isolamento/VM e policy granulari richiedono un percorso di enforcement
separato e prove di compatibilita.

Riferimenti per il futuro profilo di test (non implementato):
https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file
https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference

