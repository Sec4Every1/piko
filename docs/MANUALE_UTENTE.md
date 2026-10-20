# piko — Manuale utente

Versione 0.2.0 · Windows x64 · Aggiornato il 14 ottobre 2026

piko raccoglie alcuni registri di Windows, segnala eventi da controllare e permette
di mettere in quarantena e ripristinare un file preciso, dopo conferma. La dashboard
traduce le segnalazioni disponibili in indicazioni comprensibili. Il registro
tecnico conserva i dati originali utili a chi deve approfondire.

## 1. Aprire piko

1. Estrarre il pacchetto ZIP in una cartella a scelta.
2. Per la modalità installata, fare doppio clic su **Install-Piko.cmd** e seguire la richiesta UAC di Windows. Aprire poi piko dal collegamento creato.
3. Per la modalità di prova senza installazione, usare **Open-Piko.cmd** se incluso nel pacchetto.

La dashboard va aperta come utente normale, non come amministratore. Il file `piko.exe` è un'interfaccia a riga di comando e facendo doppio clic non apre la dashboard. La disponibilità del monitoraggio dipende dai permessi concessi e dalla configurazione Windows.

Alternativa da PowerShell normale, nella cartella del pacchetto:

```powershell
.\Start-Piko.ps1
```

Se Windows impedisce l'esecuzione dello script o segnala la build non firmata,
leggere l'errore e verificare l'origine del pacchetto con chi lo ha preparato.
Il launcher non modifica le regole di sicurezza o la policy di PowerShell.
Per l'interfaccia serve WebView2. `LEGGIMI.md` descrive anche l'installazione come
servizio Windows, destinata a un amministratore: non è necessaria per questo avvio.

## 2. Come orientarsi

| Sezione | A cosa serve |
| --- | --- |
| Dashboard | Leggere le segnalazioni importanti, il loro significato e le verifiche consigliate. Gli heartbeat di piko non sono segnalazioni di sicurezza. |
| Quarantena e ripristino | Preparare e confermare la quarantena di un file; leggere il registro delle azioni e preparare un ripristino. |
| Attività applicazioni | Vedere processi, connessioni TCP e storico di una precisa istanza; passare ai controlli rete. |
| Log tecnici | Consultare gli eventi raccolti, compresi quelli di funzionamento di piko, e approfondire le evidenze disponibili. |
| Permessi app | Cercare i programmi registrati, leggere lo stato del Firewall Windows e bloccare la rete in uscita per un eseguibile preciso. |
| Manuale | Consultare una guida rapida dentro l'app. |

Usare **Aggiorna** per richiedere i dati correnti. Se la connessione non è
disponibile, non interpretare gli ultimi dati visualizzati come una verifica in
tempo reale.

### Cosa significano i colori

| Colore | Significato |
| --- | --- |
| Grigio e superfici neutre | Struttura, navigazione e informazioni neutre. |
| Blu | Navigazione, selezioni, azioni principali e informazioni. |
| Ambra | Verifica richiesta, copertura limitata o informazione da controllare. |
| Rosso | Priorità alta o errore che richiede attenzione. Non è da solo prova di un attacco. |
| Verde | Esito di un'operazione riuscita. Non significa «computer senza minacce». |
| Viola | Ripristino e informazioni di recovery. |

Il testo accanto al colore specifica sempre il significato. Una connessione
funzionante indica che interfaccia e monitor comunicano: non misura la sicurezza
del computer.

## 3. Leggere la dashboard

La dashboard presenta al massimo cinque gruppi compatti per pagina, con tipo,
nomi disponibili, conteggio, priorità e indice massimo. Raggruppa per regola e
versione le ultime 100 segnalazioni: non deduce che appartengano allo stesso
incidente. Gli altri gruppi si raggiungono con Precedenti/Successivi.

Apri una riga per la vista **Dettaglio evento**. Il selettore **Occorrenza** e
le frecce permettono di esaminare ogni evento del gruppo, uno alla volta.
Qui trovi spiegazione, dati verificati, score, MITRE ATT&CK e remediation.
In **Dettagli dell’evento**, premi **Leggi i dettagli dell’evento**; apri poi
**XML originale e riferimenti tecnici** per i dati grezzi. Escape o Chiudi
dettaglio torna alla dashboard e riporta il focus alla riga selezionata.

Le segnalazioni sono prodotte da dodici regole sui registri
Windows. Per ciascuna descrive cosa è successo, perché controllarlo, quali
spiegazioni legittime sono possibili e quali passi compiere. La priorità indica
quanto rapidamente verificare il fatto, non una diagnosi certa di malware.
La data «Evento Windows» è l'orario riportato dal registro di origine, anche
quando piko raccoglie il record più tardi. Se un runtime precedente non fornisce
questo dato, l'interfaccia etichetta la data come «Raccolto da piko» e invita a
consultare l'orario originale nell'evidenza.

| Evento osservato | Cosa può voler dire | Primo controllo consigliato |
| --- | --- | --- |
| Registro Security cancellato — evento 1102 | La cronologia di sicurezza è stata svuotata. Può dipendere da manutenzione o da un tentativo di nascondere attività. | Verificare se un amministratore aveva pianificato la pulizia; conservare l'evidenza prima di altre modifiche. |
| Un registro Windows cancellato — evento 104 | È stata rimossa parte della cronologia di un registro. | Controllare quale registro è stato cancellato, quando e se la manutenzione era prevista. |
| Criteri di controllo modificati — evento 4719 | È cambiato ciò che Windows registra delle attività di sicurezza. | Chiedere a chi gestisce il PC se la modifica era prevista; un tecnico può confrontarla con la configurazione attesa. |
| Servizio installato — evento 7045 | Un programma ha aggiunto un componente che può funzionare in background. Installazioni e aggiornamenti legittimi possono farlo. | Confrontare data e servizio con software appena installati; un tecnico può verificare percorso e produttore. |

### MITRE ATT&CK: a cosa serve

MITRE ATT&CK è un catalogo pubblico dei comportamenti usati negli attacchi. piko
collega queste segnalazioni a tecniche pertinenti per spiegare il contesto. Una
mappatura significa «questo fatto può comparire in questa tecnica», **non**
«questa tecnica è stata certamente eseguita da un attaccante». Non è una misura
di copertura dell'intero framework e non aggiunge sensori che piko non possiede.
I codici e i riferimenti delle tecniche sono consultabili nella dashboard.

Le associazioni usate in questa versione sono:

| Osservazione di piko | Riferimento ufficiale ATT&CK | Come interpretarlo |
| --- | --- | --- |
| Cancellazione dei log — 1102 e 104 | [T1685.005 · Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/) | Il comportamento è osservato, ma il suo scopo deve essere verificato. |
| Modifica dei criteri di audit — 4719 | [T1685.001 · Disable or Modify Windows Event Log](https://attack.mitre.org/techniques/T1685/001/) | Associazione potenziale: la modifica può anche aumentare le registrazioni e non indica necessariamente una riduzione delle difese. |
| Installazione di un servizio — 7045 | [T1543.003 · Windows Service](https://attack.mitre.org/techniques/T1543/003/) | Associazione potenziale: è osservata l'installazione, non un abuso del servizio. |

Riferimenti ufficiali verificati il 7 ottobre 2026. piko applica questa
interpretazione alle dodici regole puntuali e alla correlazione 4625 note di versione 1; una regola sconosciuta
non riceve automaticamente una tecnica ATT&CK.

### Remediation: suggerimento o azione eseguibile?

Le indicazioni per verificare una modifica, confrontare una configurazione,
contattare un tecnico o controllare un servizio sono **passi manuali**. piko non
li esegue automaticamente. Le azioni attualmente eseguibili dall'app sono la
quarantena e il ripristino del contenuto di un file, entro i limiti indicati sotto.
Una segnalazione non viene automaticamente associata a un file da eliminare.

Se non riconosci un evento, leggi prima i dettagli e verifica se coincide con
installazioni o interventi previsti. Conserva le evidenze. Se serve intervenire
su un servizio, una policy o un file di sistema, affidati a chi gestisce il PC.
Non disinstallare un servizio soltanto perché compare una segnalazione.

### «Nessuna segnalazione» e «Degradato»

«Nessuna segnalazione» significa che le regole e le sorgenti disponibili non
hanno prodotto risultati. Non garantisce l'assenza di minacce.

«Degradato» significa che una parte della raccolta o della persistenza non è
disponibile. Nella normale sessione utente, il registro Windows **Security** può
risultare «accesso negato»: mancano quindi le osservazioni di quel canale,
comprese le relative regole 1102 e 4719. I canali disponibili continuano a essere
raccolti. Non avviare l'interfaccia come amministratore per aggirare questo stato;
un'eventuale installazione del servizio e i diritti di lettura sono da valutare
con l'amministratore, senza indebolire le policy di Windows.

### Nomi degli eventi e score 0–100

Le schede mostrano il nome del servizio, il percorso e l’account quando le evidenze
verificate li contengono. Il servizio installato non viene confuso con il programma
che lo ha installato: se Windows non identifica l’autore, piko lo dichiara sconosciuto.

L’**indice di rischio** è una priorità euristica, non una probabilità di attacco o
la percentuale di sicurezza del PC. Il modello piko-risk-v1 assegna 70 punti alla
cancellazione del registro Security, 50 alla cancellazione degli altri registri,
40 al cambio audit e 25 all’installazione di un servizio. Aggiunge 20 per un percorso
di servizio sotto Users/Temp, 25 se l’audit viene ridotto e sottrae 15 per sole aggiunte
all’audit. Somma e limita il risultato tra 0 e 100; la scheda spiega i fattori usati.
Percorsi insoliti e servizi nuovi possono essere legittimi.

Il massimo in dashboard riguarda solo le segnalazioni caricate (fino a 100), non
l’intero sistema. Dati mancanti o versioni sconosciute non diventano rischio zero.
La **probabilità di falso positivo** è **Non stimabile**: manca un insieme di casi
validati per calcolarla. Non viene inventata una percentuale né usato 100 meno il rischio.

## 4. Quarantena e ripristino

### Mettere un file in quarantena

1. Aprire **Quarantena e ripristino** e leggere «Ambito e limiti delle azioni».
2. Inserire il percorso completo del file da isolare. Non scegliere un file
   soltanto in base alla presenza di una segnalazione.
3. Premere **Prepara quarantena**. Il file non viene ancora rimosso.
4. Controllare percorso, dimensione e scadenza dell'anteprima. SHA-256 è
   l'impronta del contenuto: permette a piko di verificare che il file non cambi.
5. Spuntare la conferma e premere **Esegui azione confermata**.
6. Verificare il risultato nel registro delle azioni.

piko crea e verifica una copia cifrata prima di rimuovere l'originale. La
quarantena non arresta un processo già in esecuzione e non elimina altre copie
del file. Un piano scade dopo cinque minuti: se scaduto, prepararne uno nuovo.

### Ripristinare un file

1. Nel registro azioni di **Quarantena e ripristino**, trovare la quarantena interessata.
2. Scegliere **Prepara ripristino**.
3. Controllare il percorso originale e confermare l'anteprima.
4. Verificare che lo stato risulti **Ripristinato**.

piko non sovrascrive un file già presente. Se la destinazione è occupata,
conservarla e chiarire quale contenuto serve prima di spostarla esplicitamente.
Il ripristino recupera i dati del file, con i permessi ereditati dalla cartella:
non ricostruisce i permessi o le date originali. Il backup cifrato viene conservato.

### Stati del registro azioni

| Stato | Come leggerlo |
| --- | --- |
| In attesa di conferma | L'anteprima è pronta; l'azione non è stata eseguita. |
| In esecuzione | Il risultato non è ancora definitivo. |
| Backup verificato | La copia è pronta; non implica che la quarantena sia terminata. |
| In quarantena | L'originale è stato rimosso dopo il backup verificato. |
| Ripristinato | Il contenuto è stato ricreato e verificato. |
| Scaduto | Preparare una nuova anteprima. |
| Da verificare | L'esito è incerto, ad esempio dopo un'interruzione; leggere il registro e far controllare il file. Non equivale a successo. |

Se un'azione sembra bloccata o va in timeout, aggiornare prima il registro:
l'operazione potrebbe essere proseguita nel monitor. Non presumere che sia stata
annullata chiudendo la finestra.

### Limiti pratici

- In modalità locale l'ambito predefinito comprende **Documents e Downloads**
  del profilo, se presenti. Le cartelle effettive compaiono in Quarantena e ripristino.
  Cartelle reindirizzate possono richiedere una configurazione esplicita.
- Il file deve essere più piccolo di circa **15,94 MiB**. Il vault cifrato ha un
  budget di **128 MiB**; non viene svuotato automaticamente.
- File aperti in modo incompatibile, link, file con stream aggiuntivi, file
  cifrati EFS, di sistema o in directory protette possono essere rifiutati.
  Anche il contrassegno di provenienza Internet `Zone.Identifier` è uno stream
  aggiuntivo: un download può quindi essere rifiutato. Non rimuoverlo solo per
  aggirare questa verifica.
- Le copie cifrate sono legate all'identità Windows del monitor. Non sono un
  backup portabile su un'altra macchina o un altro utente; conservare il profilo
  Windows e i dati di piko.
- Sono mostrati gli ultimi 100 record di azione. Il recupero di copie più vecchie
  tramite identificativo è disponibile nella CLI e descritto in `RESPONSE.md`.
- Con un servizio Windows installato, l'interfaccia è un viewer: le azioni
  richiedono la CLI elevata e cartelle autorizzate. Non elevare l'interfaccia.

## 5. Log tecnici e heartbeat

**Log tecnici** è la vista dettagliata delle osservazioni. Gli eventi Windows
possono avere nomi, provider, identificativi e XML pensati per tecnici. Servono
per capire l'origine di una segnalazione e preservare il contesto.

Un **heartbeat** è un segnale periodico che il monitor piko sta funzionando.
È diagnostica di piko, non un attacco e non un evento per cui prendere decisioni
di sicurezza. Per questo non entra nell'elenco delle segnalazioni importanti
della dashboard; resta consultabile nel registro tecnico. Un livello «errore»
di un evento Windows, da solo, non equivale a una detection.

La raccolta non importa automaticamente tutta la storia di Windows: al primo
avvio legge fino a 16 eventi recenti per canale accessibile, poi segue i nuovi
eventi. Ai riavvii riprende dalla posizione salvata. Un bookmark non più valido
o un registro cancellato produce una segnalazione di degrado della raccolta.

## 6. Permessi delle applicazioni: controllo rete

La pagina **Permessi app** comprende l’inventario dei programmi registrati in Windows,
lo stato dei tre profili del Firewall e i blocchi di rete creati da piko.

### Bloccare un eseguibile

1. Aprire **Permessi app**. Controllare lo stato del firewall: informazioni mancanti,
   profili attivi disabilitati, interfacce escluse o policy incompatibili impediscono nuovi blocchi.
2. Cercare il programma nell’inventario e scegliere **Configura rete**, oppure inserire
   direttamente il percorso del suo file **.exe**. L’inventario riporta metadati degli
   installatori: non verifica l’editore e può non includere app portabili o Microsoft Store.
3. Per trovare il file: Gestione attività → Dettagli → clic destro sul programma →
   Apri percorso file. Copiare il percorso completo dell’eseguibile nel campo di piko.
   Una cartella d’installazione non identifica automaticamente tutti i file del programma.
4. Scegliere **Prepara blocco**. Non viene ancora modificata alcuna regola.
5. Verificare nome, percorso e impronta SHA-256 nell’anteprima, valida cinque minuti.
   Spuntare la conferma e scegliere **Conferma con Windows**.
6. Autorizzare la richiesta amministrativa di Windows per **piko-network-helper.exe**.
   L’interfaccia resta non elevata. Annullando UAC non viene applicata la modifica.
7. Controllare l’esito e la voce in **Blocchi di rete di piko**.

Il blocco riguarda tutte le destinazioni, tutti i protocolli e i profili di rete,
per tutti gli utenti del PC: comprende Internet e rete locale. Può interrompere
aggiornamenti o sincronizzazioni. È una regola per **percorso**, non per firma o
impronta: si applica anche a nuove versioni nello stesso percorso e resta in
Windows dopo la chiusura o la rimozione di piko. Non comprende copie in altri
percorsi, processi figli o altri programmi usati come proxy; non equivale
all’isolamento completo del prodotto. La presenza della regola non è una misura
del traffico bloccato. La configurazione locale può differire dalle policy di dominio.

### Rimuovere un blocco

Per operare su più app, selezionarle nella griglia e scegliere la direzione:
**uscita**, **ingresso** oppure **ingresso e uscita**. **Prepara blocchi selezionati**
mostra tutti gli eseguibili prima della conferma. **Prepara rimozione selezionati**
mostra invece soltanto le regole piko verificate dei file selezionati, nelle
direzioni scelte; resta disponibile anche quando non si possono creare nuovi blocchi.
La rimozione va confermata e autorizzata tramite Windows come l'applicazione.
I limiti sono 10 app, 20 eseguibili e 32 regole per operazione (quindi al massimo
16 eseguibili se si applicano entrambe le direzioni). Una richiesta amministrativa
può comparire per ogni regola. Al primo errore o annullamento il lotto si ferma:
gli esiti indicano separatamente ingresso e uscita, modifiche completate, operazione
da verificare e richieste non eseguite. Non viene annullato automaticamente il lavoro
già completato. Solo le regole mostrate nell'anteprima saranno interessate.

Nella regola interessata scegliere **Prepara rimozione**, controllare il percorso,
confermare e autorizzare Windows. Questa operazione rimuove solo il blocco piko;
le altre regole di Windows continuano a valere. Funziona anche se il file è stato
rimosso. Regole modificate esternamente vengono segnalate e non alterate da piko.
In assenza di piko, un amministratore può esaminare le regole in uscita del gruppo
**piko network control** nel Firewall Windows con sicurezza avanzata.

Richieste ed esiti sono registrati nel registro **Application** di Windows, origine
**piko**, consultabile anche nei Log tecnici quando raccolto dal monitor. Dopo
un errore aggiornare prima di riprovare: una modifica potrebbe essere già stata
applicata. L'interfaccia attende che il componente amministratore termini, senza
considerare conclusa l'operazione dopo un semplice timeout. Una seconda operazione
non si accoda a un'altra ancora in corso. Dopo la chiusura della dashboard un helper
non ancora arrivato alla modifica rifiuta il piano della vecchia istanza; una modifica
già iniziata può completarsi e va verificata rileggendo le regole.
Non viene effettuato replay automatico.

Sono ammessi eseguibili locali fino a 256 MiB. Percorsi di rete, collegamenti,
reparse point, eseguibili sotto Windows e nella cartella di piko sono esclusi.
Il file viene nuovamente verificato dall’helper prima dell’effetto.

Permessi generali per cartelle, file, registro, dispositivi e regole per
singola destinazione non sono ancora implementati. Le cartelle response_roots
limitano le operazioni di quarantena di piko; non cambiano i diritti delle altre app.

## 7. Dati e assistenza

In modalità locale i dati e `console.json` si trovano in:

`%LOCALAPPDATA%\piko-monitor`

Non cancellare o spostare questa cartella per risolvere un errore: contiene
cronologia e copie di recovery. Non pubblicare log o XML senza controllarli:
possono contenere nomi utente, percorsi e dettagli del computer.

Per chiedere assistenza, annotare versione, pagina, messaggio d'errore, orario e
identificativo dell'azione o dell'evento. Non ripetere azioni dall'esito incerto
senza avere verificato il registro.

Il pacchetto contiene anche `RESPONSE.md` per i dettagli tecnici delle azioni e
`LEGGIMI.md` per l'installazione. Questa build include ETW processi/immagini secondo i diritti Windows e arresto confermato di singole istanze; non include recovery completo del sistema,
scansione antivirus generale o permessi su file e dispositivi per app. Il controllo
rete disponibile è descritto nella sezione 6.


## Attivita applicazioni: programmi, rete e storico

Apri **Attivita applicazioni** nella barra laterale. La fotografia si aggiorna
ogni 10 secondi mentre la pagina e visibile. Cerca nome, percorso o PID;
seleziona il nome per vedere SID, percorso, istanza, connessioni TCP e ultimi
100 eventi conservati per quella precisa istanza. Lo storico ha un pulsante
Aggiorna e puo essere in ritardo rispetto all'acquisizione.

**Gestisci accesso alla rete** apre Permessi app con il percorso osservato gia
compilato. Devi ancora preparare il piano, controllarlo e confermarlo tramite
Windows. Nessun blocco deriva automaticamente da una connessione.

LISTEN e una porta in ascolto; ESTABLISHED indica una connessione stabilita.
Non vengono letti contenuti, DNS o TLS. Le fotografie possono perdere attivita
brevi; accessi negati, troncamenti e dati obsoleti sono segnalati. Il PID padre
non dimostra da solo la causalita. Non osservato non equivale a terminato.
Le righe TCP prive di identita verificata non sono attribuite a un programma.
In Log tecnici cerca process.snapshot oppure network.snapshot; l'evidenza di
queste sorgenti e JSON. Dalla CLI usa piko.exe observations.

La matrice integrale del progetto e in docs/REQUIREMENT_MATRIX.md del repository;
le funzionalita mancanti non sono abilitate da questa estensione.

## Ricerca avanzata e ricerche salvate

In **Log tecnici**, apri **Ricerca avanzata e ricerche salvate**. Scegli campo,
operatore e valore, poi **Aggiungi condizione**. Il builder gestisce le virgolette
e gli escape dei percorsi. Premi **Applica filtri**: scrivere o richiamare
un'espressione non esegue automaticamente la ricerca. Tipo, gravita, testo libero
e periodo rimangono filtri aggiuntivi. **Azzera filtri** svuota anche l'espressione.

Esempi:

```text
process.name = "browser.exe"
process.name CONTAINS "piko" AND process.pid >= 1
user.sid != NULL AND event.category = "process"
(event.type = "process.snapshot.observed" OR event.type = "network.snapshot.observed")
```

I campi disponibili sono quelli del selettore, non proprieta non raccolte.
AND precede OR; le parentesi modificano l'ordine. Testi tra virgolette doppie
con escape JSON; numeri senza virgolette. event.time indica Unix in millisecondi.
CONTAINS ignora le maiuscole ASCII; non normalizza Unicode o percorsi Windows.
NULL indica un dato assente. Un confronto != con un valore non include i dati
assenti: per includerli aggiungi OR campo = NULL.

Limiti: 4096 byte, 32 condizioni, 8 livelli di parentesi; la UI mostra gli ultimi
200 risultati. La ricerca avviene su tutto l'archivio prima del limite, entro
budget di tempo e risposta. Un errore o timeout non significa zero eventi.
FOLLOWED_BY, RELATED_TO e query temporali comportamentali non sono implementati.

Assegna un nome e usa **Salva espressione**. Sono conservate fino a 20 espressioni
nel profilo locale dell'interfaccia. Gli altri filtri non vengono salvati; i nomi
duplicati sono rifiutati. Clicca il nome per richiamarla, poi Applica filtri.
Elimina rimuove soltanto la ricerca salvata, non gli eventi.

## Relazioni osservate e accesso alle evidenze

In **Attivita applicazioni**, seleziona un programma e premi **Carica relazioni**.
La stessa vista e disponibile nei dettagli di un evento con identita di istanza.
Il diagramma collega quella precisa istanza agli account SID e agli endpoint TCP
osservati nello storico. Clicca un collegamento, poi **Osservazione 1**, **2**, ecc.
per aprire i dettagli. **Leggi evidenza originale** carica il JSON raccolto;
**Evento grezzo** mostra il record normalizzato. I dati grezzi restano opzionali.

La vista considera fino alle ultime 500 osservazioni conservate, al massimo 64
nodi e 16 riferimenti per collegamento. Mostra cinque collegamenti per pagina;
eventuali troncamenti sono dichiarati. Il conteggio riguarda le osservazioni
registrate o cambiate, non pacchetti, durata o numero totale di connessioni.
Il refresh e esplicito. Non e un grafo causale o un verdetto di attacco: la
direzione del traffico e il legame padre-figlio non vengono dedotti dai PID.

CLI: piko.exe query '<espressione>' e piko.exe investigate <UUID-istanza>.

## Selezionare le app e applicare blocchi multipli

Apri **Permessi app**. La griglia mostra 12 app per pagina. Cerca nome, editore o
versione e scegli l'ordine: piu recenti, meno recenti, nome. La data proviene da
InstallDate dichiarata dall'installatore: puo rappresentare una manutenzione o
un aggiornamento, non necessariamente la prima installazione. Date mancanti o
non valide sono mostrate come sconosciute e restano in fondo.

Spunta una o piu app (massimo 10). piko cerca candidati .exe nella cartella
registrata e nel percorso icona; non esegue il programma. Apri il dettaglio della
selezione per controllare i percorsi ed escludere file non desiderati. La scansione
si limita a 3 livelli di sottocartelle, 1024 voci e 32 eseguibili per app, con
budget temporale cooperativo di 2 secondi. Percorsi generici e collegamenti sono
esclusi. Nomi, cartelle ed editori sono metadati dell'installatore, non attestazioni
di sicurezza. File portabili, Store, servizi o updater in altre cartelle possono
mancare: la selezione non garantisce copertura completa di un prodotto.

Scegli **Accesso alla rete — connessioni in uscita**, poi **Prepara blocchi
selezionati** (massimo 20 eseguibili). Controlla l'anteprima e conferma. Windows
puo richiedere l'autorizzazione amministrativa per ogni eseguibile. Nessuna regola
viene applicata dalla sola selezione o dalla preparazione. Al primo errore o
annullamento il gruppo si ferma. Gli esiti distinguono modifiche completate,
operazione da verificare e file non elaborati; non esiste rollback automatico.
Le regole gia applicate si rimuovono dalla sezione Blocchi di rete di piko.

Se non vengono trovati eseguibili, usa **Configura rete · percorso manuale**
oppure scegli un processo da Attivita applicazioni. La ricerca non perde le
selezioni gia effettuate. Svuota selezione le rimuove tutte.

Il menu mostra anche percorsi esterni, file di sistema e aggiornamenti, ma sono
**non disponibili**: nessuna di queste tre protezioni e applicata da questa build.
Bloccare la rete puo interferire con gli aggiornamenti, ma non impedisce
aggiornamenti offline, tramite servizi o altri programmi.

Per software obsoleto o sospetto: preferire un ambiente isolato, account senza
privilegi amministrativi, dati dedicati e rete disabilitata o limitata ai soli
servizi necessari. Per prove temporanee Windows Sandbox puo disabilitare rete,
appunti, microfono, videocamera e condivisioni; per uso continuativo valutare una
VM dedicata con snapshot. Piko gestisce ora un profilo Sandbox offline per un singolo exe, descritto nella sezione seguente. Le VM persistenti non sono gestite.

## Prova isolata con Windows Sandbox

In **Permessi app → Prova isolata · Windows Sandbox** puoi preparare un installer
oppure un programma portabile. Dalla griglia seleziona una app, espandi gli
eseguibili e scegli **Prova questo eseguibile in isolamento** per compilare il percorso.

1. Scegli **Prepara prova isolata** e controlla percorso e impronta SHA-256.
2. Conferma la copia e premi **Crea profilo isolato**. L'anteprima scade in cinque minuti.
3. Premi **Apri Windows Sandbox**. Il messaggio di piko conferma solo la richiesta
   al launcher: controlla l'effettiva apertura della finestra Windows Sandbox.
4. Solo dentro quella finestra apri `C:\PikoInput\payload.exe`: puoi copiarlo sul
   desktop virtuale prima di eseguirlo. Non eseguire la copia sul PC principale.
5. Chiudi Windows Sandbox per eliminare la sessione virtuale. In piko usa
   **Elimina copia e profilo**, poi conferma, per rimuovere i file preparati.

Il profilo richiede rete, appunti, microfono, videocamera, stampanti e GPU condivisa
disattivati, client protetto e una sola cartella di input in sola lettura. Nessun
programma viene avviato automaticamente. I profili sono salvati nella cartella
locale dell'app, `%LOCALAPPDATA%\local.piko.desktop\sandbox-sessions`; il percorso completo del file
.wsb è nei dettagli. Massimo otto copie da 256 MiB ciascuna.

Windows Sandbox deve essere installato e funzionante su un'edizione Windows
compatibile, con virtualizzazione disponibile. Piko non abilita feature Windows
automaticamente. Anche con launcher presente, policy o prerequisiti possono
impedire l'avvio. Un avvio fallito non comporta alcun ripiego sul PC principale.

Questa modalità copia **un singolo exe**: dipendenze, DLL, licenze e dati del
programma installato non vengono trasferiti. Non blocca l'app già installata,
non congela le sue versioni e non applica un contratto automatico per gli
aggiornamenti. Il programma può modificare il Windows virtuale. Non inserire
credenziali o dati sensibili; piko non acquisisce gli eventi interni della sandbox.
L'isolamento effettivo del guest resta da qualificare nella matrice Windows.

I profili non sono protetti da un amministratore o da un processo ostile con lo
stesso account. Piko rifiuta configurazioni o copie alterate al controllo di avvio.
Se una creazione viene interrotta, possono restare file incompleti: l'errore resta
visibile. A sandbox chiusa, controlla la cartella dei profili e rimuovi solo la
sottocartella della sessione incompleta, preservando gli altri profili.

Riferimento: [configurazione ufficiale Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file).


## Esportare una segnalazione

Apri un gruppo in Dashboard, scegli l'occorrenza e premi **Esporta segnalazione JSON**.
Il file contiene la segnalazione selezionata, interpretazione, score euristico,
remediation e riferimenti MITRE disponibili. Include l'evidenza grezza soltanto
se hai già premuto **Leggi i dettagli dell'evento**. Altrimenti indica che non è
caricata. L'esportazione non è firmata; controlla i dati personali prima di condividerla.

## Storico applicazioni e versioni

In **Permessi app → Storico applicazioni e versioni** piko confronta i metadati
registrati dagli installer. La prima apertura crea il riferimento iniziale;
le successive aperture e **Aggiorna storico** registrano solo le differenze.
Lo storico non viene acquisito in background mentre la sezione è chiusa.

Sono visibili nuove voci, voci ricomparse, voci non più presenti, cambi di versione
e cambi di nome/editore/cartella dichiarati. Apri **Vedi cosa è cambiato** per
confrontare prima e dopo. Una voce assente viene registrata soltanto dopo una
lettura completa e non dimostra una disinstallazione: un installer può sostituire
la propria chiave. Una versione mancante resta sconosciuta. Nomi ed editori non
sono firme verificate e questo confronto non misura il comportamento del software.

La vista mostra cinque variazioni per pagina. La ricerca riguarda le cinquanta
variazioni caricate; **Carica variazioni più vecchie** legge il blocco precedente.
**Esporta storico caricato** salva quelle cinquanta voci in un JSON non firmato.
Lo storico conserva al massimo 2.000 variazioni, eliminando le più vecchie,
e 4.096 identità di registro. Raggiungere il limite di identità interrompe il
salvataggio con un errore; la griglia app e gli altri controlli restano disponibili.

I dati sono locali per il profilo Windows in
`%LOCALAPPDATA%\local.piko.desktop\software-history.sqlite`. Il database ha un
limite di 16 MiB; il journal transazionale può richiedere spazio aggiuntivo.
Lo storico non ricostruisce i cambiamenti avvenuti tra due letture, non impedisce
aggiornamenti e non è protetto da modifiche eseguite dallo stesso account o da un
amministratore. Non è una verifica di vulnerabilità o una genealogia completa.

## Account, attività pianificate e Microsoft Defender

La dashboard comprende dodici regole. Le otto aggiunte leggono:

| Origine | ID | Segnalazione |
| --- | --- | --- |
| Security / Security-Auditing | 4720 | Account creato |
| Security / Security-Auditing | 4732 | Membro aggiunto a un gruppo locale |
| Security / Security-Auditing | 4698, 4702 | Attività pianificata creata o modificata |
| Windows Defender/Operational | 5001 | Protezione in tempo reale disattivata all'ora dell'evento |
| Windows Defender/Operational | 5007 | Configurazione modificata; non prova una disattivazione |
| Windows Defender/Operational | 1116 | Rilevazione riportata da Defender |
| Windows Defender/Operational | 1117 | Azione riportata da Defender; può anche essere Consenti |

I nomi disponibili vengono verificati sull'XML, insieme a canale, provider, record
ed ID. Un account o task non identifica automaticamente il programma autore.
Le azioni consigliate sono manuali: piko non crea o disabilita account, non cambia
l'audit, non modifica task e non altera Defender automaticamente.

Per Defender controlla **Sicurezza di Windows → Cronologia protezione**. Gli eventi
sono storici: rilevazione e azione non provano lo stato attuale del file o del PC.
Piko integra i record del motore Microsoft; non effettua una scansione antivirus.
Un report antivirus da solo non permette di assegnare una tecnica MITRE specifica.

Security richiede accesso al registro e categorie di audit attive; la presenza del
canale non garantisce che ogni operazione produca un evento. Defender può essere
assente o non attivo. I limiti sono visibili in Impostazioni. L'avvio senza bookmark
legge solo i 16 record recenti per canale, poi prosegue dalla sottoscrizione: non
importa l'intero passato. L'upgrade applica le nuove regole agli eventi già salvati.

Fonti: [Microsoft Security auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698),
[eventi Defender](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus),
[MITRE attività pianificate](https://attack.mitre.org/techniques/T1053/005/).

## Consumi del monitor

Apri **Impostazioni → Consumi del monitor**. La CPU è calcolata su due campioni e
normalizzata sui processori logici disponibili. Il primo campione resta sconosciuto.
La RAM indica il working set; la memoria privata impegnata può comprendere pagine
non residenti. La coda conta gli eventi in attesa del salvataggio. Sono misure del
processo monitor, escluse finestra e helper. Orario e intervallo rendono riconoscibili
campioni vecchi; letture fallite vengono mostrate come non disponibili. Non è un
indice di sicurezza e non avvia modifiche automatiche alle prestazioni.

## Avvio automatico facoltativo

In **Impostazioni → Avvio automatico** scegli **Attiva al login**. È disattivato inizialmente. La voce fissa HKCU Run **PikoMonitor** avvia il monitor per l’utente connesso, senza aprire la finestra o chiedere privilegi amministrativi. Usa gli stessi dati di Open-Piko.cmd. Un servizio SCM installato ha la precedenza; se non è disponibile, non viene avviato un secondo monitor. Per aprire l’interfaccia usa sempre Open-Piko.cmd.

**Disattiva** rimuove soltanto la voce con il comando della stessa installazione. Spostare la cartella rompe il percorso: disattiva prima lo startup e riattivalo dalla nuova posizione. Una voce diversa viene segnalata come conflitto. Windows può ritardare l’esecuzione o disabilitarla: verifica **Impostazioni Windows → App → Avvio**. “Configurato” descrive il registro, non prova il successo al login. Gli errori dell’ultimo tentativo appaiono in questo pannello e in LOCALAPPDATA\piko-monitor\startup-status.txt. Non copre la fase precedente all’accesso o altre sessioni; il monitor termina alla disconnessione.

Fonte: [Microsoft Run/RunOnce](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys).

## Valutare e raggruppare le segnalazioni

Apri un gruppo nella dashboard, scegli l’occorrenza e scorri a **La tua valutazione**. Puoi assegnare **Da esaminare**, **In verifica**, **Atteso / autorizzato** o **Gestito**, aggiungere una nota e premere **Salva valutazione**. La scelta riguarda solo quell’evento, non tutto il gruppo né gli eventi futuri.

Il filtro **Revisione** mostra gli eventi da esaminare, gli esaminati o tutti. Atteso e Gestito passano negli esaminati; In verifica rimane da esaminare. Per riaprire un evento seleziona Da esaminare e salva. Gli indicatori complessivi continuano a descrivere le ultime 100 segnalazioni lette, anche se filtrate.

Queste sono annotazioni manuali personali: non modificano rischio, probabilità, regole, raw o policy. “Atteso” non è una classificazione verificata di falso positivo, “Gestito” non prova una remediation. Il database alert-reviews.sqlite si trova nella cartella locale dell’app per l’utente; conserva l’ultima valutazione di massimo 2000 eventi e note di massimo 1000 byte. Le più vecchie vengono eliminate al superamento del limite. Non è uno storico firmato delle revisioni e non viene condiviso con altri utenti. Se la lettura fallisce, la dashboard mostra tutti gli eventi con un avviso.

Il controllo rete supporta ora **In uscita** e **In ingresso**, dal menu della griglia o dalla direzione del percorso manuale. I piani e le regole indicano la direzione; due blocchi per lo stesso percorso coesistono e la rimozione riguarda solo quello scelto. In ingresso limita le connessioni iniziate da altri dispositivi, non sostituisce un blocco in uscita. Per applicare entrambi, prepara e conferma le due direzioni separatamente. Conferma con helper UAC, SHA-256 ricontrollato, file bloccato in lettura, template completo e journal Windows; nessuna regola globale viene modificata. Template COM verificati in memoria e UI con fixture; il filtraggio pacchetti in ingresso sotto token amministrativo non è stato qualificato sul PC.

## Verifica firma locale degli eseguibili

In **Permessi app**, espandi un’app selezionata e usa **Verifica firma locale** sul candidato .exe; è disponibile anche accanto al percorso manuale. Il target non viene eseguito. Piko apre un file regolare locale senza reparse, calcola SHA-256 e mantiene handle e cartelle bloccati contro scrittura/rinomina durante la verifica. Usa la policy Authenticode Windows per la firma incorporata, senza UI e senza richieste di rete.

La verifica può restituire firma verificata localmente, firma incorporata non trovata, impronta non corrispondente alla firma o firma non verificata con codice Windows. Il risultato espone percorso, SHA-256 e orario: riguarda quel file al momento della lettura. Non verifica cataloghi, revoca aggiornata, reputazione, vulnerabilità o supporto del produttore. Una firma valida non prova che il programma sia innocuo; una firma assente non prova malware. Non modifica score o blocchi.

La UI esegue una verifica alla volta in un processo piko.exe separato, terminato dopo 20 secondi se il provider non risponde. Percorsi massimo 1024 byte, file massimo 256 MiB; Windows e la cartella piko sono esclusi dalle ispezioni app. Non cambia certificati o trust store. CLI: piko signature <percorso-assoluto-exe>; la CLI diretta non applica il timeout della UI.

Fonti: [Microsoft WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust), [opzioni offline](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data).

## Arresto controllato di un processo

In **Attività applicazioni**, seleziona l’istanza attiva di un programma e scegli **Prepara arresto**. Controlla nome, percorso e PID, poi conferma l’arresto forzato. Può perdere dati non salvati: non è annullabile. Il piano scade dopo 60 secondi e viene consumato una sola volta.

Piko ricontrolla il processo tramite handle: tempo di creazione in precisione Windows, SID, sessione e percorso. Sono esclusi processi Windows, critici, piko e altre sessioni/utenti. Un PID riutilizzato non corrisponde al piano. Non abilita privilegi amministrativi, non arresta automaticamente figli e non impedisce riavvii. Un programma non accessibile viene rifiutato.

**Registro arresti dei processi** mostra le ultime 50 operazioni personali, cinque per pagina. L’intento è salvato prima dell’effetto. “Arresto confermato” richiede l’uscita confermata da Windows sullo stesso handle; timeout, errori o interruzione possono lasciare un esito da verificare. Nessuna ripetizione automatica. SQLite per utente conserva fino a 1000 azioni/16MiB; non è un journal firmato o indipendente dall’utente.


## Avvio limitato con AppContainer


È isolamento sullo stesso Windows, non una VM: il profilo temporaneo resta scrivibile e alcune risorse condivise Windows/Program Files restano leggibili. Non applica un divieto universale fuori dalla cartella di installazione e non congela gli aggiornamenti dell’app originale. Per software ostile preferisci Windows Sandbox funzionante o una VM dedicata.

## Vulnerabilità e fine supporto

In **Permessi app**, apri **Vulnerabilità e fine supporto**, importa un feed JSON locale e associa esplicitamente l’app al prodotto e alla versione esatta. Il formato è in **ADVISORY_FEED.md**, incluso nel pacchetto. Il feed non viene scaricato né autenticato: verifica la fonte prima di importarlo. SHA-256 identifica il contenuto locale, non certifica il curatore.

Piko mostra advisory e remediation riportati dal feed, compreso fine supporto. CVSS è il punteggio della fonte, con versione/vettore, non la probabilità che il PC sia compromesso. Feed scaduto e metadati modificati rendono espliciti i limiti di attualità del risultato; nessuna corrispondenza non garantisce assenza di vulnerabilità. Nessuna patch è installata automaticamente.

Quando un’app associata ha advisory, **Prepara blocco rete per [nome app]** individua i `.exe` candidati e prepara un blocco in uscita per quei file. Controlla nome, percorsi e ambito nell’anteprima, poi conferma una volta per applicarlo. Il blocco comprende Internet e rete locale, resta attivo dopo la chiusura di piko e può impedire aggiornamenti e sincronizzazioni. L’inventario non garantisce di trovare ogni eseguibile o servizio del prodotto; il dettaglio dell’anteprima mostra i file effettivamente coperti. L’annullamento lascia il Firewall invariato.

## ETW e copertura reale

In **Impostazioni**, il sensore **windows.etw.process_image** riporta stato, eventi ricevuti e perdite. Nei **Log tecnici**, cerca **etw.** e apri il raw JSON con payload originale. Il collector usa lo schema TDH Windows per processi e immagini: il PID del produttore non diventa il programma responsabile. Se Windows nega l’accesso, il sensore è degradato e le altre sorgenti continuano. La raccolta live ETW su questa sessione normale non è qualificata.


## Capacità archivio e scritture sospese

La raccolta essenziale conserva avvio/arresto dei processi, caricamenti DLL e tutti
gli eventi Windows Security disponibili. Gli scaricamenti delle DLL sono esclusi;
l'heartbeat resta una misura live. Le statistiche dei sensori vengono archiviate
su cambiamenti di stato/errori, con un riepilogo ogni minuto se il degrado persiste.
Un evento frequente non è automaticamente innocuo: i blocchi rete e le connessioni
consentite restano consultabili.

di raccolta, eliminando soltanto il prefisso contiguo scaduto con checkpoint locale
e contatori. Il limite di spazio non accorcia i 12 mesi: se esaurito sospende le
scritture. Impostazioni mostra spazio usato e allocato. Set-PikoRetention.ps1
permette di cambiare i mesi con backup e riavvio da PowerShell amministratore.

Remove-PikoNoise.ps1 rimuove dallo storico soltanto heartbeat informativi e
scaricamenti DLL informativi decodificati, senza detection associate. Conserva
Security, caricamenti e raw mantenuti. Richiede amministratore e servizio fermo,
crea un backup completo protetto e una copia verificata. Questa pulizia crea
una **nuova catena d'integrità**, documentando la precedente; non fingere che
gli hash della vecchia catena siano rimasti invariati. Non elimina il backup,
che occupa spazio extra. Rifiuta archivi con checkpoint di scadenza già attivo.

Le nuove evidenze grezze vengono compresse automaticamente quando conviene.
I byte originali sono restituiti quando apri il log e restano verificati dalla
catena di integrità. Per i record già presenti è disponibile Compress-PikoArchive.ps1, da PowerShell amministratore: crea un backup protetto, comprime lo storico a servizio fermo e lo riavvia. Numero di eventi e hash devono restare invariati. Il file SQLite non si restringe: le pagine liberate sono riutilizzate per nuovi eventi; la misura del file allocato può quindi restare alta. Il backup occupa spazio aggiuntivo e resta conservato. Questa funzione
rallenta la crescita del disco, ma non elimina la cronologia né sostituisce
una politica di conservazione. Il risparmio varia secondo il contenuto.

In **Impostazioni → Capacità archivio** leggi database, limite effettivo e totale dei file SQLite/WAL/SHM. La metà del budget configurato è riservata ai checkpoint e al margine operativo: un budget 256 MiB ammette circa 128 MiB di database. I valori sono campionati dal worker di storage; letture assenti o vecchie restano esplicite. Un errore del sensore piko.storage segnala scritture fallite anche se la UI è collegata.

Piko non elimina evidenze recenti per liberare spazio: con retention attiva scade soltanto il prefisso oltre i mesi configurati. Per cambiare **max_disk_mib**, verifica lo spazio libero, arresta il solo monitor piko, conserva una copia di **%LOCALAPPDATA%\piko-monitor\console.json**, modifica il valore (8–4096 MiB), poi riapri **Open-Piko.cmd**. Chiudere soltanto la UI lascia il monitor attivo. Un servizio installato usa service.json protetto e richiede un amministratore per configurazione/riavvio. Non eliminare events.db, -wal o -shm mentre il monitor è attivo.


## Registro e accessi falliti

In **Attività applicazioni → Account, accessi e privilegi**, apri il pannello
per leggere gli eventi Security già conservati: accessi riusciti/falliti, tentativi
con credenziali esplicite, assegnazione di privilegi e account creati, abilitati,
disabilitati o eliminati (4720/4722/4725/4726). Mostra cinque righe per
pagina; Categoria accessi filtra prima del limite. Più vecchi/Più recenti naviga
lo storico; Aggiorna torna alle osservazioni più recenti.

Il nome principale è l'account coinvolto; il dettaglio distingue il richiedente
e il programma chiamante quando Windows li riporta. Nome programma/PID vengono
dai campi EventData, non dal processo che scrive il log. Apri evento e dati grezzi
apre il dettaglio; Leggi evidenza originale recupera l'XML verificato su richiesta.
Il tempo mostrato è quello dell'evento Windows; l'ordine è quello della raccolta.

Un tentativo con credenziali esplicite (4648) non conferma successo. Privilegi
assegnati (4672) non prova uso di privilegi o escalation. Questi fatti ordinari
non sono trasformati automaticamente in avvisi della dashboard. Se non riconosci
un'attività, controlla account, orario, programma e accesso remoto; per errori
ripetuti verifica prima password salvate/servizi. Nessun account viene bloccato.

La copertura dipende da audit, permessi Windows e conservazione. Versioni future
o XML ambiguo mostrano campi non disponibili, con raw consultabile. Gli ID di
sessione possono essere riutilizzati dopo il riavvio e non sono collegati
automaticamente. Il programma chiamante non identifica necessariamente la persona
o l'attaccante remoto. La CLI **piko identity** restituisce la prima pagina.

In **Permessi app → Registro: avvio automatico** apri il pannello per leggere Run/RunOnce di utente e computer (32/64 bit). Aggiorna registro confronta con la lettura precedente. Sono mostrati cinque cambiamenti per pagina, con ricerca sui 50 caricati e caricamento dei più vecchi. Confronta prima e dopo mostra tipo, testo e chiave; Dati grezzi mostra i bytes esadecimali. Il nome è quello del valore, non del programma autore. Nessuna scrittura o esecuzione.

La prima lettura crea il riferimento iniziale. Una chiave parziale non permette di dedurre scomparse. Ora di scrittura e autore non disponibili; cambiamenti tra letture possono sfuggire. Conserva le ultime 500 variazioni in 16 MiB (massimo 1024 identità); il limite identità produce un errore. Esporta lettura salva solo i dati caricati, senza firma. Non è un backup o ripristino del registro.

La dashboard raggruppa **Accessi falliti ripetuti** quando piko osserva almeno cinque errori di credenziali per lo stesso account, IP e tipo rete/desktop remoto nello stesso minuto UTC. Il dettaglio riporta account tentato e programma chiamante se presenti nel documento Windows. Il chiamante non identifica l’attaccante remoto; l’IP può appartenere a un proxy o host condiviso. Record correlati permette di aprire ogni XML, cinque riferimenti per pagina.

Controlla password salvate e servizi prima di intervenire. Se non riconosci la fonte, chiedi all’amministratore di verificare accesso remoto e credenziali. Nessun account viene bloccato automaticamente. Score 50/100 indica priorità euristica, non probabilità; T1110 è una mappatura di contesto. Dipende da audit Windows e accesso al log Security. Analizza gli ultimi 256 record 4625 (16 MiB), esclude il minuto più vecchio se tagliato; altri errori o errori tra minuti possono sfuggire. Non segnala automaticamente i login riusciti e non copre tutte le forme di forza bruta.

## Porte UDP

In **Attività applicazioni**, seleziona il programma e apri **Porte locali UDP**. Mostra solo indirizzo e porta locali associabili all’istanza osservata; massimo cinque per pagina. La lettura è ogni 10 secondi e può essere parziale o non disponibile. Non mostra destinazioni, contenuto, DNS o prova di invio/ricezione. Un bind può servire soltanto a inviare. I blocchi rete per exe restano in Permessi app.

La verifica della catena locale può richiedere fino a 30 secondi (IPC 32 s). Usa un lettore separato: il monitor può continuare ad archiviare. Il totale verificato riguarda lo snapshot del controllo e può essere inferiore al conteggio aggiornato dopo. Timeout e coda piena sono errori espliciti, non verifiche riuscite; non cancellare dati per risolverli. Nessun ancoraggio esterno è dichiarato.
# Caricamenti di moduli e spazio archivio

Piko registra per intero il primo caricamento verificato di una DLL per una coppia applicazione/modulo. Se lo stesso abbinamento ricompare senza cambiamenti, conserva un conteggio aggregato con primo/ultimo orario e un riferimento al campione completo. Un file cambiato, un nuovo abbinamento o una verifica incompleta resta un evento completo.

La verifica usa file, hash SHA-256, firma locale e identità del processo/sessione quando disponibili. La firma non prova che un file sia sicuro: anche software firmato può essere sfruttato. Se la verifica non riesce, Piko mantiene il caricamento completo. Nella sezione Salute sensori, `piko.image_context` mostra quante osservazioni sono state verificate, raggruppate o lasciate complete. La raccolta ETW può comunque perdere eventi se la coda o l'archivio sono saturi; il sensore segnala le perdite note.



