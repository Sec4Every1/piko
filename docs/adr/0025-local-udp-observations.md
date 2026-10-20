# ADR 0025 — Porte locali UDP osservate

Stato: lettura nativa IPv4/IPv6, runtime, storico raw e GUI integrati.

GetExtendedUdpTable/UDP_TABLE_OWNER_PID aggiunge endpoint locali alla fotografia processi/TCP ogni 10 secondi. Nessuna cattura o trasmissione di datagrammi. Un bind può essere usato solo per inviare: non prova ricezione, ascolto raggiungibile o traffico effettivo. Le tabelle non forniscono destinatari/contenuto: questi campi non sono creati.

Tre tentativi bounded per crescita tabella, buffer allineato fino a 2 MiB, row count checked prima delle copie POD unaligned, offset derivato dal layout SDK, 8192 righe per acquisizione e 2048 righe API. Errori e troncamento rendono udp_complete false indipendentemente dal TCP. IPv6 conserva scope e indirizzo; scope/porta convertiti dall’ordine rete. PID senza istanza non viene associato usando il solo numero. FILETIME uguale prima/dopo entrambe le tabelle consente la stessa associazione osservata usata da TCP.

Il runtime conserva network.udp.snapshot.observed/changed/not_observed con target udp_local_endpoint e raw JSON. Nessuna scomparsa dedotta da una lettura UDP parziale; snapshot brevi/tra due poll possono sfuggire. Stesso bind/istanza ripetuto è silenzioso. Non rappresenta ogni socket condiviso né una connessione remota. Nessuna detection automatica legata alla presenza di una porta.

Attività applicazioni mostra conteggio UDP e associazioni sconosciute; nel programma selezionato un pannello chiuso contiene massimo cinque endpoint per pagina. Risposte legacy prive di UDP sono dichiarate non disponibili, non una lettura vuota completa. Parser rifiuta destinazioni remote inventate in un endpoint UDP. Controllo rete per exe resta quello già disponibile.

Verifiche: socket fixture loopback bind senza datagrammi, owner e FILETIME, decoder IPv4/IPv6/order/bounds, polling parziale/silenzioso, parser e browser, snapshot runtime/IPC/Tauri reale. Non qualificato come telemetria di pacchetti, DNS, QUIC, TLS o prevenzione.

Fonti API: [GetExtendedUdpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable), [MIB_UDPROW_OWNER_PID](https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udprow_owner_pid), [MIB_UDP6ROW_OWNER_PID](https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udp6row_owner_pid).

