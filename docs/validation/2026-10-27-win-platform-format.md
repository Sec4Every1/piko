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

## Corrective workspace check

The broader gate exposed an incorrect edition assumption in the targeted check
above: the actual workspace uses edition 2021, not 2024. The explicit 2024
formatter rearranged imports differently. That targeted result did not establish
the repository's formatting gate and is superseded by this correction.

Ran `cargo fmt --all` on the exact selected snapshot, followed by the normal
`cargo fmt --all -- --check`: passed. Eleven files required correction versus
73b4ff7: ten of the native modules above (service.rs already matched), plus the
service runtime's two-condition line wrapping. Selected runtime formatting was
staged separately from the dirty APP-03 hunk. Corrected staged blobs match the
snapshot. `cargo check --offline --locked --workspace --all-targets` passed
against that snapshot, using the shared target directory. Logs:
`workspace-format.log`, `workspace-cargo-check.log`. No dependency changes,
tests or runtime operations occurred. The snapshot excludes deferred APP-03 changes; its Rust source is the exact
candidate selected for this correction.
