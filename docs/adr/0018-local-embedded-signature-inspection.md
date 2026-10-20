# ADR 0018 — Firma Authenticode locale

UI su richiesta, mai scansione continua o fonte di score. Riusa l’handle esclusivo dell’ispezione eseguibile per hash e WinVerifyTrust. Solo codice LONG esattamente zero consente verified_locally. WTD_UI_NONE, FILE, CACHE_ONLY_URL_RETRIEVAL e REVOCATION_CHECK_NONE; chiusura dello stato su ogni esito. Nessuna verifica cataloghi.

Il provider gira nel processo piko.exe signature, sibling della UI, senza shell o privilegi aggiuntivi. Una verifica alla volta, timeout GUI 20s con kill/wait RAII, output massimo 4096 byte, percorso massimo 1024 byte. Resta dipendenza dalla policy/trust store Windows locale, non trust crittografico indipendente. Il target non viene eseguito.

Test: PE Rust reale non firmato, stesso SHA prima/dopo; parser esito/codice/limiti; browser chiamata esplicita senza policy; smoke IPC Tauri con CLI reale e benigno unsigned PE. Non ancora fixture firmata con certificato di test, catalogo o firma alterata.

