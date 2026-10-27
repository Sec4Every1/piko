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
- Delivery direction accepted 2026-10-27: prioritize consolidation and the
  first usable release in FIRST_RELEASE.md before further APP-03/browser work.
  Preserve those experiments, pass-through and not_enforced. "Continua/vai
  avanti" confirms this direction; resume autonomously without asking the user
  to restate scope. Close finite deliveries rather than stopping at checkpoints.
- Prepare coherent reviewed local commits, then push checked source to a
  development branch. The user's 2026-10-27 acceptance authorizes this workflow;
  merge to main, releases and manual remote CI dispatch remain separate.
  Before each push check exact staged scope, private data/artifacts and relevant
  validation. Preserve all unrelated local changes; do not use broad staging.
- Current user authorization (2026-10-24): resume targeted local validation.
  Run affected tests, type/compiler checks, Clippy and formatting checks as
  appropriate; build affected components when needed. Fix failures and continue.
  Use existing tooling/dependencies; do not install/update tools or rewrite
  lockfiles merely to enable checks. Keep tests isolated from installed runtime
  and real evidence. No installation, driver loading, live-protection changes
  or manual remote CI dispatch. Development-branch push follows the newer
  authorization above. New source stays unverified until relevant checks
  actually pass; local success never implies Windows/security qualification.
- Select the highest-priority ready queue item. Fix its prerequisites first.
  Deliver the named outcome, rather than replacing it with unrelated easy tasks.
- Use targeted rg/read operations and concise tool output. Save long logs under
  ignored `.build/`; inspect failures rather than repeatedly printing whole logs.
- Run checks appropriate to the change. Broaden after failures or contract changes;
  do not rerun passed checks without a reason. Never claim an unrun check passed.
- Prepare reviewed code checkpoints; releases, main merges and manual remote CI
  need separate authorization. Avoid idle polling and repeated cold desktop builds/audits when
  targeted local evidence already supports continuing independent work.
- Existing checks: `scripts/ci-checks.ps1`, `scripts/ci-sbom.ps1` (full release/CI);
  targeted `cargo test -p <crate>`, workspace fmt/Clippy; frontend npm check/test,
  affected Playwright scenarios, build when UI/native packaging changes.
- Distinguish source, tests, compiled package, installed runtime and remote CI.
  Compiler success is not a live-service or security qualification result.
- At a milestone or interruption update NEXT_SESSION: outcome, evidence, remaining
  blocker and exact next action. Update queue/matrix/manual only where affected.
  Replace stale state; keep detailed evidence in VALIDATION/ADRs, not this file.
- A checkpoint is a resume record, not a stopping point. Continue from its exact
  next action in the same turn while meaningful authorized source work remains.
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
