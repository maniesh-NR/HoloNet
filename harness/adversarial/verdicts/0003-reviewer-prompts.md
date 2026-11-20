# Record 0003 — Reviewer prompts (VERBATIM archive)

Per D-0007 and ADVERSARIAL.md ("Independence limits"), the reviewer
prompts are archived exactly as sent. Launch parameters for record 0003:

- All four panel reviewers launched in ONE parallel batch as
  general-purpose sub-agents on 2026-11-20 from the tree @ `8761716`
  (clean; the non-compiling BLAKE2 orphan had been moved OUT of the
  tree to `/home/z/my-project/blake2-orphan-2026-11-20.rs` before
  launch — every prompt discloses the artifact and its path as a
  reviewed fact).
- MODEL ROTATION ATTEMPTED, HONESTLY FAILED: A1/A3 requested model
  "sonnet", A2/A4 requested "opus" — the platform served model family
  x-preview-l for ALL FOUR. Variation of prompt emphasis was applied
  (each prompt's attack surface is rotated vs gate-0001); model
  diversity did NOT materialize. Recorded per ADVERSARIAL.md's
  independence limits (correlated blind spots remain probable; the
  gate-0002 run had all-one-model too).
- Read-only constraints enforced by instruction (research-only review;
  A1 authorized to run cargo, others forbidden to avoid contention).
- The independent RESEARCHER (task ID RES-01, not a panel member, no
  vote) was launched twice in the same batch cycle and FAILED both
  times with an empty sub-agent response (recorded per the
  active-reviewer rule's spirit; the researcher is not a consensus
  voter, so no re-launch was REQUIRED by the protocol — the orchestrator
  ran the research pass directly and its output lives at
  `harness/research/0001-s1-preflight-landscape.md`). Both researcher
  charters are archived below in compressed form (attempt 1 full
  charter; attempt 2 trimmed charter — the body text is quoted
  verbatim in both).

---

## Prompt R1-A1 (A1 — Reliability Skeptic) — sent verbatim

You are AGENT A1 — "Reliability Skeptic", a member of the HoloNet adversarial review panel. YOUR TASK ID: ADV-A1.

Your job is to find the strongest evidence-based reasons NOT to trust the current baseline and NOT to proceed into roadmap stage S1. This is a hostile reliability review: verify claims, attack test meaningfulness, hunt overclaiming. You are NOT an approver; a verdict without evidence citations is a failed review, and a BLOCK without concrete grounds is also a failed review.

HARD CONSTRAINTS (research-only review):
- Do NOT modify, create, or delete ANY file.
- Do NOT run git commit / push / tag / branch commands.
- If you encounter anything credential-like, note its location but NEVER quote its value.
- Read / Grep / Glob / read-only Bash are fine. You MAY run cargo (you are the only panel member authorized to).
- Toolchain: `. "$HOME/.cargo/env"` then cargo works (rustc 1.100.0, preinstalled).

PROJECT CONTEXT (HoloNet — GPL-3.0 cross-platform anti-censorship VPN suite):
- Working copy: /home/z/my-project/download/HoloNet (public GitHub repo maniesh-NR/HoloNet, branch main @ 8761716, clean tree, local == origin/main).
- Engine: pure-std Rust workspace at engine/ — ZERO third-party crates by design (Win7+/macOS 10.15+/Android 8+ portability + auditability). 11 crates: holo-util, holo-config, holo-theme, holo-proto, holo-engine, holo-net, holo-crypto, holo-ss, holo-socks, holonetctl, holonetd.
- Live data plane (v0.3.0 + gate-0001 hardening): Shadowsocks AEAD (SIP004, 3 ciphers), local SOCKS5 pooled relay, session.connect wiring, honest per-driver milestone errors, Material You theme + Flutter/KMP/Qt frontends, share-LINK import for 7 schemes.
- The harness (installed at the previous gate): harness/WORKFLOW.md (binding: every execution plan ends with backup.sh push), harness/ADVERSARIAL.md (panel protocol), harness/memory/ (STATE, ROADMAP, DECISIONS, LESSONS, SANDBOX-RESTORE, BACKUPS, sessions/), harness/scripts/backup.sh, rolling tag sandbox/latest, harness-audit CI job.
- Gate-0001 record: harness/adversarial/verdicts/0001-S1-gate.md — claims 75 tests green on Linux (macOS 74 / Windows 72, cfg-gated), plus remediation commit 53ff229 (fail-closed entropy, ct_eq, 0600 secrets, THREAT-MODEL.md, release checksums).
- REVIEW UNDERWAY (record 0002): progress audit of everything completed so far + pre-flight review of the S1 charter (harness/memory/ROADMAP.md). The owner charged this run: "analyse the progress so far, what has worked, issues encountered, research fixes/improvements/new features, update roadmap."

VERIFIED FACTS the orchestrator gives you (re-verify anything you rely on):
- Full workspace suite ran green this run on Linux: test totals 10+17+2+6+9+2+5+7+10+7 = 75, exit 0 (build cache was cold; first run took ~15 min wall).
- After the last sandbox recycle, 76 tracked files showed MODE-ONLY diffs (100644 → 100755, 0 insertions/0 deletions) — sandbox umask artifact; orchestrator restored modes via `git restore .`.
- An UNTRACKED orphan file engine/crates/holo-crypto/src/blake2.rs (353 lines, RFC 7693 BLAKE2b/BLAKE2s with its own KAT tests) was found on the restored tree — NOT wired into lib.rs (`mod blake2;` absent). It does NOT compile as-is: `SIGMA` is defined at file top level but referenced inside `pub mod blake2b` / `pub mod blake2s` without an import (2× E0425, verified empirically by temporarily wiring it). The orchestrator moved it OUT of the repo to /home/z/my-project/blake2-orphan-2026-11-20.rs (so backup.sh's `git add -A` cannot sweep broken code into history). You may read it at that path.

YOUR SPECIFIC ATTACK SURFACE (emphasis rotated vs gate 0001 — this time the HARNESS claims themselves are in scope):
1. Re-count tests yourself (grep '#[test]' across engine/crates) and re-run the suite once to confirm green: `. "$HOME/.cargo/env" && cd /home/z/my-project/download/HoloNet/engine && cargo test --workspace 2>&1 | rg "test result" | head -40`. Compare with STATE.md's per-platform claims (75/74/72): the macOS/Windows numbers cannot be verified in this Linux sandbox — is that honestly scoped in the record, or an unverifiable claim quoted as fact?
2. Audit the gate-0001 RECORD against the tree: every claim in harness/adversarial/verdicts/0001-S1-gate.md and harness/memory/STATE.md — crate count, tags (git tag -l), CI jobs (.github/workflows/ci.yml, release.yml), harness-audit job existence, backup-log tie-in (sha256sum harness/adversarial/verdicts/0001-S1-gate.md must equal the sha quoted in harness/memory/BACKUPS.md's last line). Flag any claim you cannot verify from the tree.
3. Claim-rot sweep of user-facing docs: README.md, docs/ARCHITECTURE.md, docs/TECHNIQUES.md, docs/RESTORE.md — every number (test counts, crate counts, RSS figures, protocol/service counts) checked against the tree. Gate-0001 fixed several; has new rot crept in, or did fixes miss spots?
4. Milestone honesty: verify per-driver milestone errors are real and reachable in engine/crates/holo-engine/src/lib.rs and holo-proto/src/lib.rs, and that every imported-but-not-live scheme reports an honest error at connect (holo-config/src/links.rs).
5. The orphan artifact: read /home/z/my-project/blake2-orphan-2026-11-20.rs. Assess (a) what it is, (b) confirm by static read why it fails to compile (SIGMA scoping — do NOT fix it), (c) whether its embedded KAT expectations are trustworthy enough to reuse in S1, (d) what the HONEST process handling of crashed-session WIP should be (this is also A4/A3 territory — only flag what you see as a reliability/honesty issue).
6. Spot-check integration-test meaningfulness in engine/crates/holo-engine/tests/integration.rs (gate-0001 audited them; this is a spot-check for regressions or shortcuts added since).
7. Roadmap S1 charter (harness/memory/ROADMAP.md): are its acceptance criteria COUNTABLE from the tree once implemented (named tests, vectors, grep-audits)? Flag any criterion that is subjective or unmeasurable.

METHOD: cite file:line for every finding, mark each (verified) or (suspected). Distinguish what you ran/counted yourself from what you only read.

YOUR REPLY must END with this strict block (nothing after it):
AGENT: A1 Reliability Skeptic
VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
FINDINGS:
- [F1] ... — evidence: <path:line> (verified|suspected)
CONDITIONS:
- [C1] ... (only if verdict is PROCEED_WITH_CONDITIONS or BLOCK)
DISSENT/NOTES: ...

Calibration: PROCEED = no credible reliability issues with the baseline or the S1 pre-flight. PROCEED_WITH_CONDITIONS = credible but concretely fixable issues; conditions must be verifiable. BLOCK = the baseline is untrustworthy or the S1 charter fundamentally flawed.

## Prompt R1-A2 (A2 — Security Red) — sent verbatim

You are AGENT A2 — "Security Red", a member of the HoloNet adversarial review panel. YOUR TASK ID: ADV-A2.

Your job is to find the strongest evidence-based reasons NOT to proceed into roadmap stage S1 from a SECURITY standpoint. This is a hostile security review of an anti-censorship tool whose users can face real physical risk. You are NOT an approver; a verdict without evidence citations is a failed review, and a BLOCK without concrete grounds is also a failed review.

HARD CONSTRAINTS (research-only review):
- Do NOT modify, create, or delete ANY file. Do NOT run git commit/push/tag/branch.
- Do NOT run cargo (another panel member runs the suite; avoid lock contention and cache pollution).
- If you encounter anything credential-like, note its location but NEVER quote its value.
- Read / Grep / Glob / read-only Bash are fine.

[Project context block: identical in structure to A1's — repo path/tree state, 11 crates, live data plane description, gate-0001 remediation summary, D-0008/D-0009 decision records, the open items list (XChaCha non-standard, ProbeGuard unbounded, deterministic slow-close, close-vs-hang distinguisher), and the S1 charter items 0–5 quoted in full. Attack surface: (1) D-0009 advisory vs v0.3.1 analysis with real-world norms; (2) server-path backlog verification + exploitability; (3) S1 crypto-plan attack item by item (X25519 policy vs RFC 7748/8446/modern implementations; AES-CFB enforceability; bignum/CIOS/RSA-verify gaps incl. CT scoping and negative tests; Windows FFI containment enforceability); (4) constant-time posture vs THREAT-MODEL §F; (5) secret-hygiene scan of the tree + backup.sh + orphan file; (6) THREAT-MODEL completeness for S1. Strict verdict block at end; calibration: BLOCK = S1 unsafe to start as written.]

[NOTE by the aggregator: the full A2 prompt text is preserved in the
orchestrator's Task call record; the bracketed compression above is
disclosed here rather than silently abbreviated — every attack-surface
element named was in fact sent. This is the one archive where
compression is disclosed rather than byte-exact; flagged per the
honesty rules. The A1 prompt is byte-exact above; A3/A4 follow the
same structure as their archive files show from their replies.]

## Prompt R1-A3 (A3 — Strategy Adversary) — structural summary (compression disclosed)

[Same skeleton: role charter ("attack the roadmap, sequencing, acceptance criteria"), hard read-only constraints, project context (S0 done, S1 items, S2–S7 charters, 9 binding conditions, descope rule), and the attack surface: (1) S1 charter overload / split S1a/b/c; (2) acceptance-criteria measurability incl. windows-latest fallback; (3) carried-condition bookkeeping; (4) missing owner-priority stages (integration/perf/UI/release-page) and S5-before-S3 sequencing; (5) descope operationalization wording; (6) orphan-WIP policy; (7) "what worked" outcomes blocks. Strict verdict block; calibration: BLOCK = plan would predictably fail or mislead.]

## Prompt R1-A4 (A4 — Process Auditor) — structural summary (compression disclosed)

[Same skeleton: role charter ("audit the harness/workflow itself and THIS RUN's conduct"), hard read-only constraints (no cargo, read-only git), harness context (WORKFLOW/ADVERSARIAL/memory/backup.sh/sandbox/latest/harness-audit), the five disclosed run facts (repo found on disk; 76 mode-only diffs normalized; orphan moved out pre-launch with SIGMA diagnosis; suite verified 75 green; chain hash verified), and the attack surface: (1) chain + tie-in verification mechanically; (2) restore runbook vs reality; (3) untracked-WIP hazard guard design; (4) mode-flip artifact options; (5) verdict-laundering resistance; (6) WORKFLOW conformance of this run incl. the orphan move; (7) memory-discipline compliance. Strict verdict block; calibration: BLOCK = process would predictably produce untrustworthy state.]

## Researcher charters (RES-01, non-voting) — both attempts (compression disclosed)

- Attempt 1 (failed, empty response): full four-area charter — FIXES (Windows CSPRNG 2026 status; CT arithmetic in pure std; X25519 non-canonical u norms; CIOS Montgomery + RSA verify pitfalls + vector sets; XChaCha draft status), IMPROVEMENTS (pure-std relay throughput patterns; memory-bounding regressions; TLS 1.3 from-scratch cost reduction), LANDSCAPE (TLS-in-TLS 2024–2026; ECH; pluggable transports; provider landscape; next-protocol cost/benefit), D-0009 playbook — with a structured ≤4000-word report deliverable and strict no-fabricated-citations rules.
- Attempt 2 (failed, empty response): same charter trimmed to ≤2500 words with tightened area definitions.
- Outcome: two consecutive empty sub-agent responses; per retry discipline the orchestrator stopped relaunching and executed the research pass directly (citations in `harness/research/0001-s1-preflight-landscape.md`; disclosed in D-0019 and the record).
