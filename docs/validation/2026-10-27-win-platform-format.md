# Existing Windows modules: formatting gate, 2026-10-27

Snapshot: ignored `.build/consolidation-win-format-20261027`, archived from
9ce7cd3 and overlaid only with these existing win-platform modules:
`etw`, `native`, `network_control`, `observations`, `process_control`,
`references`, `registry_history`, `restricted`, `service`,
`software_inventory`, `startup`.

Each selected file equals the existing rustfmt tool's `--edition 2024` output
of its archived HEAD source, normalizing only line endings for comparison.
Changes are mechanical formatting/import ordering. No native boundary, FFI,
privilege, dependency or runtime behavior is added. APP-03 additions and mixed
`lib.rs` / `network_elevation.rs` changes were excluded.

Passed against the exact selected snapshot:

- Targeted `rustfmt --edition 2024 --check` for all eleven modules.
- `cargo check --offline --locked --manifest-path <snapshot>/Cargo.toml
  -p piko-win-platform --all-targets --target-dir target`.
- Live selected Git blobs match the checked snapshot; staged whitespace check.

Logs remain in the ignored snapshot. The PowerShell stderr wrapper labels Cargo
progress as NativeCommandError; the process exited zero with Finished dev profile.
No tests or live operations were needed for the formatter-equivalent changes.
This targeted result is not a full-workspace formatting pass, Windows
qualification or evidence that the deferred APP-03 source was integrated.
