# Parser fuzzing

Target iniziali: decoder SecurityEvent e decoder JSON del protocollo IPC, compresi enum/filtri. Non generano malware, non aprono IPC e non modificano impostazioni del sistema. I test unitari del protocollo coprono separatamente framing, dimensioni e troncamento.

I target richiedono Rust nightly e cargo-fuzz. Non sono parte della build desktop e non sono ancora una campagna di fuzzing completata. Su un runner Linux dedicato con tali strumenti:

```sh
cargo +nightly fuzz run event_decoder -- -max_len=262145 -max_total_time=60
cargo +nightly fuzz run ipc_decoder -- -max_len=16385 -max_total_time=60
```

Conservare crash/reproducer e versioni del toolchain. Nessun risultato di fuzzing viene dichiarato senza un run registrato. Telemetry parser, query language, policy e intelligence avranno target propri quando implementati.
