# Piko: repository instructions

## Start and resume
- Read `docs/NEXT_SESSION.md`, then the active item in `docs/WORK_QUEUE.md`.
- Check `git status --short` before editing; preserve existing work.
- Read only relevant code, tests and linked requirement sections. Do not reload
  the whole specification, chat history or all ADRs for every task.
- User instructions take precedence. Continue authorized work through completion;
  do not stop after a plan or ask again for permission already granted.

## Product contract
- Piko is an MIT Windows security product for nontechnical users. Automate setup;
  keep dashboard summaries compact, with progressive details and raw evidence.
- Name the application/account when evidence supplies it. Missing data stays
  unknown. Risk scores are explained heuristics, not false-positive probabilities.
- Requirements: `docs/REQUIREMENTS.md` + `docs/ARCHITECTURAL_ADDENDUM.md`.
  Coverage: `docs/REQUIREMENT_MATRIX.md`. Architecture/language decisions:
  `docs/COMPONENT_AUDIT.md`, `docs/LANGUAGE_DECISIONS.md`; read relevant parts.
- Implement real backend -> IPC -> UI paths where needed. A control or document
  alone does not constitute an implemented security capability.
- Safe Rust for core logic; native boundaries in win-platform; Svelte/TypeScript
  UI. Explain any new FFI, dependency, privilege or architectural change.
- Preserve raw evidence, attribution boundaries, bounded resources, failure
  visibility, durable writes and reversible response workflows.
- Never silently weaken protection or create OS/account/Firewall changes beyond
  the user's authorized scope. Honor existing authorization without adding gates.
- Keep personal identifiers, machine paths, secrets, runtime data and generated
  artifacts out of tracked source and publication. Stage explicitly, not `git add .`.

## Delivery and token discipline
- Select the highest-priority ready queue item. Fix its prerequisites first.
  Deliver the named outcome, rather than replacing it with unrelated easy tasks.
- Use targeted rg/read operations and concise tool output. Save long logs under
  ignored `.build/`; inspect failures rather than repeatedly printing whole logs.
- Run checks appropriate to the change. Broaden after failures or contract changes;
  do not rerun passed checks without a reason. Never claim an unrun check passed.
- Publish one reviewed code checkpoint for automatic full CI; keep its pending
  status explicit. Avoid idle polling and repeated cold desktop builds/audits when
  targeted local evidence already supports continuing independent work.
- Existing checks: `scripts/ci-checks.ps1`, `scripts/ci-sbom.ps1` (full release/CI);
  targeted `cargo test -p <crate>`, workspace fmt/Clippy; frontend npm check/test,
  affected Playwright scenarios, build when UI/native packaging changes.
- Distinguish source, tests, compiled package, installed runtime and remote CI.
  Compiler success is not a live-service or security qualification result.
- At a milestone or interruption update NEXT_SESSION: outcome, evidence, remaining
  blocker and exact next action. Update queue/matrix/manual only where affected.
  Replace stale state; keep detailed evidence in VALIDATION/ADRs, not this file.
- Final response: result, verification, material limitation and next item; brief.

## Delegation
- Delegate only when explicitly authorized by the user or applicable instructions.
  Current workflow permits delegation when it materially helps; default to one
  bounded helper for independent work, otherwise stay single-agent.
- Give each helper: task ID, exact outcome, owned files, relevant paths, acceptance
  checks and exclusions. Prefer a short standalone brief over full-chat context.
- Avoid simultaneous edits to shared files and duplicate test/build runs. Helpers
  return changed files, checks, blockers and residual risks in a concise report.
- Coordinator reviews/integrates changes and owns final verification and state.
  Helpers do not commit, push, install or alter live protections unless authorized.
