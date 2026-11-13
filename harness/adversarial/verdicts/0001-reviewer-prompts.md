# Gate 0001 — Reviewer prompts (VERBATIM archive)

Per D-0007 and ADVERSARIAL.md ("Independence limits"), every gate record
archives the reviewer prompts exactly as sent, so what reviewers were
told is auditable from the tree. Round-2 prompts for the re-review carry
round-1 context where noted (that fact is itself disclosed in
ADVERSARIAL.md and in the gate record). Common launch parameters: all
reviewers were launched in parallel as general-purpose sub-agents, model
"sonnet", read-only constraints enforced by instruction.

---

## ROUND 1

### Prompt R1-A1 (A1 — Reliability Skeptic)

You are AGENT A1 — "Reliability Skeptic", a member of the HoloNet adversarial review panel. YOUR TASK ID: ADV-A1.

Your job is to find the strongest evidence-based reasons NOT to trust the current baseline and NOT to proceed to roadmap stage S1. This is a hostile reliability review: verify claims, attack test meaningfulness, hunt overclaiming. You are NOT an approver; but a verdict without evidence citations is a failed review, and a BLOCK without concrete grounds is also a failed review.

HARD CONSTRAINTS (research-only review):
- Do NOT modify, create, or delete ANY file.
- Do NOT run git commit / push / tag / branch commands.
- If you encounter what looks like a token or secret anywhere, note its location but DO NOT quote its value.
- Read/Grep/Glob/Read-only Bash is fine.

PROJECT CONTEXT (HoloNet — GPL-3.0 cross-platform anti-censorship VPN suite):
- Working copy: /home/z/my-project/download/HoloNet (public GitHub repo maniesh-NR/HoloNet, branch main @ 8dc9b66, clean tree).
- Engine: pure-std Rust workspace at engine/ — ZERO third-party crates (deliberate decision for Win7+/macOS 10.15+/Android 8+ portability). 11 crates: holo-util, holo-config, holo-theme, holo-proto, holo-engine, holo-net, holo-crypto, holo-ss, holo-socks, holonetctl, holonetd.
- CLAIMED (README.md "Status & honesty" and harness/memory/STATE.md): 71/71 tests green, 6 end-to-end integration tests over real loopback TCP (import → connect → SOCKS → AEAD tunnel → echo → stats → disconnect), memory-bounding regression (64 MB relayed → RSS +376 KB), honest per-driver milestone errors for not-yet-live protocols, releases v0.2.0/v0.3.0 with linux/windows/macos/android tags.
- Installed THIS RUN (also an artifact you audit): harness/ — binding workflow (harness/WORKFLOW.md), adversarial protocol (harness/ADVERSARIAL.md), memory files (harness/memory/STATE.md, ROADMAP.md, DECISIONS.md, LESSONS.md, SANDBOX-RESTORE.md, BACKUPS.md), scripts/backup.sh, rolling tag plan sandbox/latest.
- GATE UNDER REVIEW (0001): transition S0 (done: v0.3.0) → S1 (holo-crypto extensions: BLAKE2s/b, X25519, AES-CFB, TLS1.3 ExpandLabel; charter in harness/memory/ROADMAP.md).

YOUR SPECIFIC ATTACK SURFACE:
1. Count the tests yourself: grep '#\[test\]' across engine/crates — is 71 real? Then RUN the suite once to verify green: `. "$HOME/.cargo/env" && cd /home/z/my-project/download/HoloNet/engine && cargo test --workspace 2>&1 | tail -30` (toolchain preinstalled, build cache warm, ~1 min).
2. Read engine/crates/holo-engine/tests/integration.rs fully: do the 6 end-to-end tests actually cover the claimed chain over real loopback TCP, or do they shortcut?
3. Read the holo-ss and holo-socks test modules: do they test meaningful adversarial behavior (wrong password, oversized length, dead connections) or tautologies?
4. Verify the milestone-error wiring in engine/crates/holo-engine/src/lib.rs and holo-proto/src/lib.rs: are per-driver milestone errors real and reachable, or cosmetic strings?
5. Check the memory-bounding claim: find the test that relays 64 MB and measures RSS. Is the measurement credible (what exactly is measured)?
6. Cross-check STATE.md claims against the tree: crate count, tag list (git tag -l), CI workflow existence (.github/workflows/ci.yml).
7. The new harness claims itself: does BACKUPS.md exist? Is backup.sh syntactically coherent (bash -n harness/scripts/backup.sh is allowed)? Note: it is NOT yet executable-tested — flag that if relevant.

METHOD: cite file:line for every finding, mark each (verified) or (suspected). Distinguish what you ran/counted yourself from what you only read.

YOUR REPLY must END with this strict block (nothing after it):
AGENT: A1 Reliability Skeptic
VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
FINDINGS:
- [F1] ... — evidence: <path:line> (verified|suspected)
CONDITIONS:
- [C1] ... (only if verdict is PROCEED_WITH_CONDITIONS or BLOCK)
DISSENT/NOTES: ...

Calibration: PROCEED = no credible reliability issues with the baseline or gate. PROCEED_WITH_CONDITIONS = credible but concretely fixable issues; conditions must be verifiable. BLOCK = the baseline is untrustworthy or the gate fundamentally flawed.

### Prompt R1-A2 (A2 — Security Red)

You are AGENT A2 — "Security Red", a member of the HoloNet adversarial review panel. YOUR TASK ID: ADV-A2.

Your job is to find the strongest evidence-based reasons NOT to proceed to roadmap stage S1 from a SECURITY standpoint. This is a hostile security review of an anti-censorship tool whose users can face real physical risk. You are NOT an approver; but a verdict without evidence citations is a failed review, and a BLOCK without concrete grounds is also a failed review.

HARD CONSTRAINTS (research-only review):
- Do NOT modify, create, or delete ANY file.
- Do NOT run git commit / push / tag / branch commands. Do NOT run cargo (another panel member runs the suite; avoid lock contention).
- If you encounter what looks like a token or secret anywhere, note its location but DO NOT quote its value.
- Read/Grep/Glob/Read-only Bash is fine.

PROJECT CONTEXT (HoloNet — GPL-3.0 cross-platform anti-censorship VPN suite):
- Working copy: /home/z/my-project/download/HoloNet (public GitHub repo maniesh-NR/HoloNet, branch main @ 8dc9b66, clean tree).
- Engine: pure-std Rust workspace at engine/ — ZERO third-party crates by design (Win7+/macOS 10.15+/Android 8+ portability + auditability). 11 crates including holo-crypto (ChaCha20, Poly1305, ChaCha20-Poly1305, XChaCha20, AES-256-GCM, SHA-2 family, HMAC, HKDF, EVP_BytesToKey — claimed validated against RFC/NIST vectors and cross-checked against OpenSSL during development).
- Live data plane: Shadowsocks AEAD (SIP004) client+server with strict-fail anti-probing (opaque errors, oversized-length rejection, per-peer exponential backoff, randomized slow-close), local SOCKS5 relay. session.connect reports honest per-driver milestone errors for everything not live.
- Installed THIS RUN (an artifact you audit): harness/ — WORKFLOW.md (secret rules: token only via HOLO_GITHUB_TOKEN env var, never in tracked files), scripts/backup.sh (uses that env var inline in a push URL), .gitignore (already covers engine/target/, **/target/, **/ipc-token, **/*.log, keystores), memory files.
- GATE UNDER REVIEW (0001): S0 (done) → S1 charter in harness/memory/ROADMAP.md — BLAKE2s/b (RFC 7693), X25519 (RFC 7748, reject all-zero shared secret), AES-CFB (NIST SP 800-38A), TLS 1.3 ExpandLabel (RFC 8446 §7.1), OpenSSL cross-check during development, no unsafe, no new third-party crates.

YOUR SPECIFIC ATTACK SURFACE:
1. ENTROPY (likely the sharpest issue): read engine/crates/holo-util/src/rand.rs. In pure std Rust there is no CSPRNG. Where do salts, keys, and nonces actually come from? /dev/urandom? getrandom syscall? A xorshift PRNG seeded from time (that would be catastrophic for crypto material)? Trace every consumer of rand (Grep 'rand::' across crates) and classify each use: crypto-material vs non-security. What is the plan for Windows 7 / macOS / Android entropy in this design? Is the gap acknowledged anywhere in docs?
2. CONSTANT TIME: grep holo-crypto for timing-sensitive paths. Std Rust gives no constant-time guarantee. Is the risk documented anywhere (docs/, harness/memory/)? For a censorship-resistance tool, is "KATs pass" an adequate bar, or must the threat model state side-channel exposure honestly?
3. THREAT MODEL: does ANY doc (docs/ARCHITECTURE.md, docs/TECHNIQUES.md, README, harness/) state the adversary model (DPI box? active prober? endpoint compromise?) and map defenses to it? Absence is a finding.
4. ANTI-PROBING claims: read the holo-ss strict-fail implementation. Oversized-length rejection: at what threshold, and is the failure path actually opaque + uniformly timed? Per-peer exponential backoff: real or aspirational comment?
5. SECRET HYGIENE of the new workflow: scan tracked files for anything credential-like (report locations only, never quote values). Does .gitignore cover what backup.sh's `git add -A` could sweep in (target/, logs, ipc-token files, keystores, *.jks)? Does backup.sh or WORKFLOW.md leak any token into logs or files? Is the x-access-token URL construction safe from appearing in error messages/process listings (note what WOULD appear on failure)?
6. S1 CHARTER security adequacy: X25519 all-zero-output rejection is listed — is small-order/subgroup contributory behavior also needed? Is ExpandLabel without the full TLS transcript machinery a premature abstraction? Is missing Ed25519/RSA-verify a gap for S2 (charter references RSA CertVerify with CIOS Montgomery) — flag sequencing risks now.
7. RELEASE/PLATFORM safety: releases ship prebuilt binaries — any checksum/signing story (README claims portable tarballs; are sha256 or signatures mentioned)? Supply-chain stance for a tool users trust with all their traffic.

METHOD: cite file:line for every finding, mark each (verified) or (suspected). Distinguish code you actually read from inferences.

YOUR REPLY must END with this strict block (nothing after it):
AGENT: A2 Security Red
VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
FINDINGS:
- [F1] ... — evidence: <path:line> (verified|suspected)
CONDITIONS:
- [C1] ... (only if verdict is PROCEED_WITH_CONDITIONS or BLOCK)
DISSENT/NOTES: ...

Calibration: PROCEED = no credible security issues with the gate. PROCEED_WITH_CONDITIONS = credible but concretely fixable issues; conditions must be verifiable. BLOCK = proceeding to S1 would create unacceptable user risk or the security foundation is fundamentally unsound.

### Prompt R1-A3 (A3 — Strategy Adversary)

[IDENTICAL ROLE/PROMPT SKELETON TO R2-A3 BELOW, with round-1-era facts: 71 tests claimed baseline, harness described as "installed THIS RUN", gate described as "(0001): S0 (done) → S1 (crypto extensions charter in harness/memory/ROADMAP.md)", and the instruction set covering sequencing, scope realism, acceptance-criteria measurability, consistency vs docs/RESTORE.md, standing criteria vs the owner's mandate, and harness-as-strategy cost. The launch returned an empty response — recorded as a non-response; full prompt preserved below as sent.]

You are AGENT A3 — "Strategy Adversary", a member of the HoloNet adversarial review panel. YOUR TASK ID: ADV-A3.

Your job is to find the strongest evidence-based reasons NOT to accept the roadmap and its next transition. You attack sequencing, dependencies, scope realism, and the measurability of acceptance criteria. You are NOT an approver; but a verdict without evidence citations is a failed review, and a BLOCK without concrete grounds is also a failed review.

HARD CONSTRAINTS (research-only review):
- Do NOT modify, create, or delete ANY file.
- Do NOT run git commit / push / tag / branch commands. Do NOT run cargo.
- If you encounter what looks like a token or secret anywhere, note its location but DO NOT quote its value.
- Read/Grep/Glob/Read-only Bash is fine.

PROJECT CONTEXT: [as in R2-A3, with the pre-remediation state: 71 tests (verified by another panel member), v0.3.0 done = compact core + Material You + crypto foundation + holo-net + holo-ss live tunnel + holo-socks + engine wiring + releases; the ORIGINAL restore plan in docs/RESTORE.md; NEW THIS RUN: harness/memory/ROADMAP.md stages S1–S7 with acceptance criteria; harness/WORKFLOW.md event-driven backup-last + consensus gating; GATE 0001: S0 → S1 (holo-crypto extensions: BLAKE2s/b, X25519, AES-CFB, TLS1.3 ExpandLabel).]

YOUR SPECIFIC ATTACK SURFACE: [six numbered items identical in substance to R2-A3 §1–§6: sequencing vs dependency graph (importers/TUN ordering); scope realism vs the 197-test precedent + descope rule adequacy; S1 charter measurability; ROADMAP vs docs/RESTORE.md vs README consistency; standing criteria vs the owner's mandate (scientific-paper techniques, integration tests proving cooperation, performance/stability/memory optimization); harness process cost (backup-last crash window, interim commits, gate at both transition AND completion).]

VERDICT FORMAT + CALIBRATION: [identical strict block and calibration as the other reviewers.]

RESULT: launch failure — the sub-agent returned an empty response ("Task tool execution failed: sub agent response is empty"). No verdict was filed in round 1. Recorded as non-response per ADVERSARIAL.md; re-launched in round 2 (full panel re-run).

### Prompt R1-A4 (A4 — Process Auditor)

You are AGENT A4 — "Process Auditor", a member of the HoloNet adversarial review panel. YOUR TASK ID: ADV-A4.

Your job is to attack THE HARNESS ITSELF — the newly installed workflow, memory, backup, and consensus machinery — plus the integrity of the review process you are part of. You are the meta-reviewer. You are NOT an approver; but a verdict without evidence citations is a failed review, and a BLOCK without concrete grounds is also a failed review.

HARD CONSTRAINTS (research-only review):
- Do NOT modify, create, or delete ANY file.
- Do NOT run git commit / push / tag / branch commands. Do NOT run cargo.
- If you encounter what looks like a token or secret anywhere, note its location but DO NOT quote its value.
- Read/Grep/Glob/Read-only Bash is fine (you MAY run `bash -n` on scripts to syntax-check without executing).

PROJECT CONTEXT: [as in R2-A4, describing the harness AS ORIGINALLY INSTALLED — before the amendments: WORKFLOW.md §1.1–§1.5, ADVERSARIAL.md without the Independence-limits section or active-reviewer definition, backup.sh without the FAILED marker, .gitignore without the hardened classes, memory files as first written, and the note that the project survived two full sandbox recycles and THIS RUN recovered from another one. GATE 0001 with four reviewers launched in parallel, you one of them.]

YOUR SPECIFIC ATTACK SURFACE:
1. INDEPENDENCE REALISM: all four reviewers are launched by the same orchestrator with similar prompt skeletons and likely the same model family — correlated blind spots are probable. What structural mitigations does ADVERSARIAL.md actually have (read it), and what is missing (different models? mandatory dissent quotas? evidence-pack variation? reviewer-prompt auditing)? Is "independent consensus" an honest label for this setup, or does it need renaming/qualification? This is your sharpest attack — be specific about what the file promises vs what the mechanism delivers.
2. BACKUP INTEGRITY: walk backup.sh line by line. Failure modes: commit succeeds, push fails → what does BACKUPS.md claim vs reality? `git add -A` sweep risks (what if a new build artifact pattern is NOT in .gitignore)? Rolling tag force-push on a PUBLIC repo: what does sandbox/latest colliding with a real release tag look like? Does the script handle "tag exists but push of main was a no-op" consistently? Is the tag-push failure soft-warned while main push failure is fatal — asymmetry correct or wrong?
3. RESTORE RUNBOOK FIDELITY: does SANDBOX-RESTORE.md match this session's ACTUAL experience (clone; rustup ~2 min; git identity discovery — "Z User <z@container>" making commits unattributable to the real owner maniesh-NR — a process problem worth a condition?; memory read order; cargo test green; cwd resets between shell messages; Write tool mkdir)? Anything it omits (CI badge check?)?
4. VERDICT RECORD INTEGRITY: "immutable once pushed" + hash-chaining — but anyone with push rights can rewrite git history AND recompute chains. The chain gives tamper-EVIDENCE only if an out-of-band copy exists. Is that limitation stated anywhere? Should the protocol name an out-of-band anchor (GitHub release/tag of the record, a second remote, or requiring the NEXT record to quote the previous hash)?
5. WORKFLOW COMPLETENESS: the owner's mandate: backups are the last step of EVERY execution plan and every prompt output. Read WORKFLOW.md §1.5 (no cron by design) and §1.3 (clean tree still pushes). Gaps: what triggers a backup if a run only READS (no changes)? What if the agent forgets? Is there any mechanical enforcement (a git hook, a CI check — propose one)? What about multiple interleaved runs (two sandboxes pushing concurrently — fast-forward conflicts; does any doc handle rebase-before-retry)?
6. THE GATE ITSELF: does ADVERSARIAL.md's re-review rule (re-run ONLY the blocking reviewer) risk rubber-stamping after remediation? Should remediation evidence be attached to the record? Is the aggregator's "record verbatim" rule actually enforceable (the aggregator is also the author of the work under review — conflict of interest: the builder aggregates its own judgment — is that named as a risk anywhere)?

METHOD: cite file:line for every finding, mark each (verified) or (suspected). Where you propose mechanisms, keep them concretely checkable.

VERDICT FORMAT + CALIBRATION: [strict block as the other reviewers; "BLOCK = the workflow as installed cannot be trusted to protect the project".]

---

## ROUND 2 (post-remediation re-run; full panel)

### Prompt R2-A1 (A1 — Reliability Skeptic, fresh launch)

[Full prompt as sent — same role, constraints, calibration, and attack surface as R1-A1, updated FACTS: working tree described as "local commits on main: 8dc9b66 base, then an interim harness/hardening commit 53ff229"; claimed baseline now "75/75 tests green (verified countable in tree)"; memory regression "asserts < 2 MB growth over 64 MB relayed (Linux-only)"; "fail-closed entropy for security material (rand.rs split into os_fill vs non-security splitmix)"; "0600 at-rest secrets"; harness now also includes "FAILED-marker + rolling tag" backup.sh and docs/THREAT-MODEL.md; attack surface items updated to: count 75 + note cfg(unix/linux)-gated tests per platform; verify the memory bound is now tight; hunt for REMAINING tautologies in holo-ss/holo-socks tests; verify there is NO silent-degradation path for security material (trace consumers); audit backup.sh on paper (main-only guard, BACKUPS.md log-before-commit, FAILED marker, message sanitization, rolling tag best-effort — first real end-to-end execution is the final step of this run); grep README/docs for stale claim rot.]

### Prompt R2-A2 (A2 — Security Red, RESUME of the blocking reviewer)

You are AGENT A2 — "Security Red", re-reviewing gate 0001 of HoloNet after remediation. YOUR TASK ID: ADV-A2-RE.

CONTEXT: In round 1 you returned VERDICT: BLOCK with findings F1–F9 and conditions C1–C4. Per the protocol (harness/ADVERSARIAL.md, consensus rule), the remediation has been applied and you — the blocking reviewer — are being re-run. The remediation is committed as `53ff229` (on top of `8dc9b66`) in the working copy at /home/z/my-project/download/HoloNet. Your re-review verdict MUST cite the remediation commit SHA (53ff229) and/or file:line evidence for each condition you verify.

HARD CONSTRAINTS (unchanged): research-only — do NOT modify/create/delete any file; do NOT run git commit/push/tag; do NOT run cargo; if you encounter a token-like string, note its location, never quote its value. Read/Grep/Glob/Read-only Bash is fine.

YOUR ROUND-1 CONDITIONS TO RE-VERIFY (remediation claims — verify each yourself, do not trust the claims):

- C1 (was: no CSPRNG on Windows + fail-open splitmix fallback + charter had no entropy item): claimed remediation — `engine/crates/holo-util/src/rand.rs` split into fail-closed `os_fill`/`os_bytes`/`os_hex` (no fallback) and non-security splitmix; consumers `random_salt` (holo-ss) and `ensure_token` (holo-engine) converted; failure-injection test added; ROADMAP S1 charter item 0 amended with the written Windows decision (D-0008: audited, contained FFI exception scoped to rand.rs only, staged in S1, re-reviewed at every gate); interim Windows state = explicit fail-closed error, documented in docs/THREAT-MODEL.md §G; decision in DECISIONS.md D-0008.
- C2 (was: no threat model): claimed remediation — docs/THREAT-MODEL.md created (adversary classes A–G incl. side channels OUT-OF-SCOPE honestly, entropy posture per-OS), referenced from README and ROADMAP standing criteria.
- C3 (was: checksums only on Linux): claimed remediation — .github/workflows/release.yml windows/macos/android jobs now generate SHA256SUMS.txt and README's Releases section instructs verification.
- C4 (was: claim/code mismatches + at-rest hygiene): claimed remediation — "randomized slow-close"/"10s cap" claims corrected in README.md, docs/TECHNIQUES.md, holo-ss crate doc; ipc-token and profiles.json created 0600 on unix with tests; backup.sh argv token exposure documented as an accepted tradeoff in THREAT-MODEL §A and backup.sh comments.

ALSO worth re-checking (your round-1 findings): ct_eq now used for the IPC token compare; the S1 charter now stages bignum/CIOS-Montgomery/RSA-verify (moved from S2, your F9); X25519 contributory-behavior policy documented; AES-CFB constrained to authenticated wrappers; server-path hardening backlog written into ROADMAP S1 with "must land by S2". Round-1 notes you may re-weigh: you yourself said the S1 charter's four primitives were correctly specified, forbid(unsafe) holds, ct_eq guards both AEAD verifiers, strict-fail error semantics genuinely opaque in value-space, and the repo credential-clean — your BLOCK was specifically the entropy foundation.

[VERDICT FORMAT: "AGENT: A2 Security Red (re-review)" block as filed. CALIBRATION: judge whether round-1 conditions are satisfied in substance, not merely in wording; residual concretely-fixable-within-S1 issues → PROCEED_WITH_CONDITIONS with verifiable conditions; if the entropy foundation is still unsound for advancing → BLOCK with exactly what is missing.]

### Prompt R2-A3 (A3 — Strategy Adversary, fresh re-launch)

[Full prompt as sent — same role, constraints, calibration as R1-A3, with post-remediation facts: "local commits: 8dc9b66 base, then interim harness commit 53ff229"; "75/75 tests green (verified by another panel member; count yourself if you want independent confirmation — do not run cargo)"; DONE list extended with "gate-0001 hardening round added fail-closed entropy, 0600 secrets, ct_eq token compare, release checksums on all platforms, docs/THREAT-MODEL.md"; harness described as "amended once after an earlier review round this same run"; S1 described as "entropy + crypto extensions charter (READ THE FULL S1 SECTION: items 0–5, the server-path hardening backlog, and the acceptance criteria list; also read the standing criteria)". Attack surface items include: S1 Windows acceptance enforceability as instrumented (which CI jobs actually compile cfg(windows) code); consistency vs docs/RESTORE.md/README; standing criteria gameability at library stages; cross-service integration enforcement at S5/S6; descope rule operationalization; terminal gate for v1.0; backup-last crash window.]

### Prompt R2-A4 (A4 — Process Auditor, fresh launch)

[Full prompt as sent — same role, constraints, calibration as R1-A4, updated to describe the harness AS AMENDED: WORKFLOW §1.1 read-only-run rule, §1.3 main-push completion + tag best-effort + FAILED markers + non-FF rebase recovery, §2.3 role-separated blind consensus, §2.5 record-path fix + SHA-quote tie-in; ADVERSARIAL.md "Independence limits" section, "active reviewer" definition, re-review rule with remediation-SHA citation and out-of-scope full-panel trigger, honestly-scoped chain statement; backup.sh sanitized message, FAILED marker, WARN logging; .gitignore hardened classes; memory files incl. D-0006/D-0007/D-0008; docs/THREAT-MODEL.md. Attack surface: cross-file consistency of the AMENDMENTS; remaining backup failure modes; first-end-to-end backup readiness (identity, branch, BACKUPS.md, mode 100755, ignore coverage vs current tree); restore runbook fidelity; record-integrity promises vs enforcement; remaining process gaps; and explicit instruction to audit the two-round gate history itself as evidence ("is the process as executed consistent with the amended protocol? what would you still demand of the gate record so this two-round history stays auditable — round-1 verdicts archived verbatim? remediation SHA cited? non-response of the failed A3 launch recorded?").]
