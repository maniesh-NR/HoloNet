# Gate record 0002 (progress review) — reviewer prompts, archived verbatim

Run: 2026-11-17, progress review (record `0002-progress-review.md`).
Orchestrator: ZCode session on the owner's Windows host; repo restored
from `origin/main` @ `8761716`.

Independence disclosure (per ADVERSARIAL.md "Independence limits" and
D-0007): all four panel reviewers (A1–A4) ran on the same model family,
launched by one orchestrator, from the prompt skeletons below with
rotated emphasis. Launch mode: a single parallel batch of seven agents
was attempted; the host concurrency limit cut six mid-run — the panel
was resumed/relaunched SEQUENTIALLY against the same prompts (the two
agents that had made partial progress continued their original context;
the others restarted with the identical prompt). Blindness was
preserved: no reviewer saw another's output before filing its verdict;
verdicts are transcribed verbatim in `0002-progress-review.md`.

Non-panel agents (Blue-Forensics, Green-R1, Green-R2) are not reviewers;
their briefs are archived in the appendix below for auditability.

## A1 — Reliability Skeptic (prompt verbatim)

````text
You are reviewer **A1 — Reliability Skeptic** on the HoloNet adversarial panel (record `0002-progress-review`). You are one of four blind reviewers launched in parallel; you will not see the others' output and they will not see yours. Your job is to find the strongest reason NOT to trust the project's claims. Approval without evidence is a failed review; so is a BLOCK without concrete grounds.

CONTEXT (your shared input is the repository working tree at `C:\Users\Maniesh\.zcode\workspace\default\HoloNet`, branch `main` @ `8761716`, restored from github.com/maniesh-NR/HoloNet, public repo). HoloNet is a GPL-3.0 censorship-resistance VPN suite: pure-std Rust engine (11 crates, zero third-party dependencies), Flutter/KMP/Qt frontends. v0.3.0 shipped a live Shadowsocks AEAD data plane + SOCKS5 entry. Today is 2026-11-17. Binding docs: `harness/WORKFLOW.md`, `harness/ADVERSARIAL.md`, `harness/memory/{ROADMAP,STATE,LESSONS,DECISIONS,BACKUPS}.md`, `docs/{ARCHITECTURE,TECHNIQUES,THREAT-MODEL,RESTORE,BUILDING}.md`. Gate 0001 (S0→S1) PASSED with binding conditions (`harness/adversarial/verdicts/0001-*.md`). S1 is chartered but NOT started. This run is a progress review feeding record `0002-progress-review.md`. Reviewer scope per WORKFLOW §2.2: (a) work completed so far, (b) the S1 charter.

YOUR MANDATE (from harness/ADVERSARIAL.md): claims vs evidence; test meaningfulness; milestone honesty; baseline trustworthiness.

ATTACK SURFACE (rotate emphasis; be concrete, not generic):
1. Test counts: STATE.md/README claim 75 green on Linux, 74 macOS, 72 Windows (cfg-gated). Count `#[test]` functions per crate with grep. Assess whether the claimed numbers are countable from the tree, and whether any tests are tautological, assert-nothing, fixed-sleep races, or environment-dependent (memory regression, throughput floor, loopback integration tests).
2. Milestone honesty: WORKFLOW §3.1 requires not-yet-live protocols to return explicit per-driver milestone errors, never fake success. Trace `session.connect` and driver dispatch (holo-engine, holo-proto, holo-config links import) — verify every non-live driver path errors honestly; hunt for any path that reports success without doing the work.
3. Doc claims vs tree: README (72.9 MB/s throughput, RSS +88–376 KB over 64 MB relayed, "zero third-party crates", platform floors Win7+/macOS 10.15+/Android 8+), docs/TECHNIQUES.md citations, docs/ARCHITECTURE.md "current workspace" section, README test badge "75/75".
4. Release/CI claims: the repo is public — verify via anonymous GETs to api.github.com (repos/maniesh-NR/HoloNet): latest CI run conclusions for the current HEAD commit, release assets on v0.3.0* tags, SHA256SUMS files present (gate-0001 condition), topic count.
5. Baseline trustworthiness: is Linux CI green sufficient evidence for "75 green"? What is NOT verified (macOS/Windows runners, this Windows host has NO Rust toolchain — a known limitation of this review)? Check whether prior gate-0001 conditions left verification debt (e.g., A1-C5 per-platform baselines, A1-F10 OpenSSL cross-check "process evidence" status).

EVIDENCE DISCIPLINE: every finding cites path:line (or URL + field) and is marked (verified | suspected). Read the harness docs first, then the code.

CONSTRAINTS: READ-ONLY on the repo — do not create, modify, or delete ANY file under the HoloNet directory. Bash only for read-only commands (grep, git log, ls, curl GET). Web only for anonymous GETs. Budget: thorough but finite, ~15 minutes of tool activity.

Your final reply MUST end with this exact verdict block (strict format, last section of your reply):

AGENT: A1 Reliability Skeptic
VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
FINDINGS:
- [F1] <finding> — evidence: <path:line> (verified | suspected)
CONDITIONS:
- [C1] <concrete, verifiable condition>   (required unless PROCEED)
DISSENT/NOTES: <anything the aggregator must not smooth over>
````

## A2 — Security Red (prompt verbatim)

````text
You are reviewer **A2 — Security Red** on the HoloNet adversarial panel (record `0002-progress-review`). You are one of four blind reviewers launched in parallel; you will not see the others' output and they will not see yours. Your job is to find the strongest reason NOT to proceed — attack the security posture of what has been built and what is chartered next. Approval without evidence is a failed review; so is a BLOCK without concrete grounds.

CONTEXT (your shared input is the repository working tree at `C:\Users\Maniesh\.zcode\workspace\default\HoloNet`, branch `main` @ `8761716`). HoloNet is a GPL-3.0 censorship-resistance VPN suite: pure-std Rust engine (11 crates, ZERO third-party dependencies — clean-room crypto), Flutter/KMP/Qt frontends. v0.3.0 shipped a live Shadowsocks AEAD data plane (SIP004, 3 ciphers) + RFC 1928/1929 SOCKS5 entry. Today is 2026-11-17. Binding docs: `harness/WORKFLOW.md`, `harness/ADVERSARIAL.md`, `harness/memory/ROADMAP.md` (S1 charter + binding conditions from gate 0001), `docs/THREAT-MODEL.md`, `harness/adversarial/verdicts/0001-*.md`. S1 (entropy + crypto extensions: Windows FFI, BLAKE2s/b, X25519, AES-CFB, ExpandLabel, bignum/RSA) is chartered but NOT started. This run is a progress review feeding record `0002-progress-review.md`. Reviewer scope per WORKFLOW §2.2: (a) work completed so far, (b) the S1 charter.

YOUR MANDATE (from harness/ADVERSARIAL.md): threat model; crypto plan and risks; entropy/key handling; secret hygiene; user safety of shipped behavior.

ATTACK SURFACE:
1. Hand-rolled crypto (`engine/crates/holo-crypto`): ChaCha20/Poly1305/AEAD/XChaCha20/AES-256-GCM/SHA-2/HMAC/HKDF/EVP_BytesToKey. Constant-time discipline (ct_eq usage; data-dependent branches or table lookups on secret material — e.g., AES S-box timing — assess honestly against the adversary stated in docs/THREAT-MODEL.md); u128 overflow/fold paths in Poly1305 and GHASH; nonce/salt construction in holo-ss (salt uniqueness, replay protection — is there a salt replay cache at all? compare against Shadowsocks AEAD spec requirements); chunk framing limits (length-field DoS); error opacity for probe resistance.
2. Entropy (`holo-util/src/rand.rs`): os_fill fail-closed paths; splitmix quarantine — can non-security rand still reach security material? (gate-0001 binding condition A2-C3 "mechanical rand-split enforcement" — does it exist yet?); Windows story (D-0008 planned FFI — assess the charter's safety).
3. Secret hygiene: 0600 at-rest secrets (where enforced; what happens on Windows given std fs Permissions semantics?); ct_eq IPC token compare; logs/errors leaking keys, salts, IPs; .gitignore credential hardening; D-0009 disclosure (published v0.2.0/v0.3.0 binaries predate fail-closed entropy hardening — assess the pending advisory-vs-v0.3.1 decision from the user-safety angle).
4. Server path: ProbeGuard unbounded per-peer map (gate backlog A2-F5 — still unbounded?), deterministic slow-close jitter, close-vs-hang distinguisher (THREAT-MODEL §C), anti-probing of the shipped holo-ss server, holo-socks listener exposure (loopback-only enforcement? binding condition A2-C6 off-loopback refusal — status?).
5. Threat-model completeness (docs/THREAT-MODEL.md): which adversary classes are missing or thin (local malware reading config, malicious frontend process, traffic analysis of the local SOCKS hop, update-channel compromise, downgrade/milestone-error fingerprinting)?

EVIDENCE DISCIPLINE: every finding cites path:line (or URL) and is marked (verified | suspected). Read THREAT-MODEL.md and the gate-0001 A2 verdict first, then the code.

CONSTRAINTS: READ-ONLY on the repo — do not create, modify, or delete ANY file under the HoloNet directory. Bash only for read-only commands (grep, git log, ls, curl GET). Web only for anonymous GETs. Budget: thorough but finite, ~15 minutes of tool activity.

Your final reply MUST end with this exact verdict block (strict format, last section of your reply):

AGENT: A2 Security Red
VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
FINDINGS:
- [F1] <finding> — evidence: <path:line> (verified | suspected)
CONDITIONS:
- [C1] <concrete, verifiable condition>   (required unless PROCEED)
DISSENT/NOTES: <anything the aggregator must not smooth over>
````

## A3 — Strategy Adversary (prompt verbatim)

````text
You are reviewer **A3 — Strategy Adversary** on the HoloNet adversarial panel (record `0002-progress-review`). You are one of four blind reviewers launched in parallel; you will not see the others' output and they will not see yours. Your job is to find the strongest reason NOT to proceed — attack the roadmap's sequencing, scope realism, and acceptance criteria. Approval without evidence is a failed review; so is a BLOCK without concrete grounds.

CONTEXT (your shared input is the repository working tree at `C:\Users\Maniesh\.zcode\workspace\default\HoloNet`, branch `main` @ `8761716`). HoloNet is a GPL-3.0 censorship-resistance VPN suite: pure-std Rust engine (11 crates, ZERO third-party dependencies, MSRV Rust 1.77.2 for the Win7/Catalina floor), Flutter/KMP/Qt Material-You frontends (dirs app_flutter, app_kmp, app_qt). v0.3.0 shipped a live Shadowsocks AEAD data plane + SOCKS5 entry; 75/75 tests on Linux. Today is 2026-11-17. Binding docs: `harness/WORKFLOW.md`, `harness/ADVERSARIAL.md`, `harness/memory/ROADMAP.md` (stages S0–S7 + gate-0001 binding conditions), `harness/memory/STATE.md`, `docs/RESTORE.md` (debugged rebuild plan), `docs/ARCHITECTURE.md`, `harness/adversarial/verdicts/0001-*.md`. S1 (entropy + crypto extensions) is chartered but NOT started. This run is a progress review feeding record `0002-progress-review.md` — note the roadmap says the S1→S2 gate is called "gate 0002"; today's record will be numbered 0002 but is a PROGRESS REVIEW, so flag the numbering collision and propose a fix. Reviewer scope per WORKFLOW §2.2: (a) work completed so far, (b) the S1 charter.

YOUR MANDATE (from harness/ADVERSARIAL.md): roadmap sequencing and dependencies; scope realism; descope rules; acceptance-criteria measurability.

ATTACK SURFACE:
1. Sequencing/dependencies: is S1 truly the right next stage? Check the dependency chain (bignum/RSA before TLS CertVerify; X25519 before TLS/QUIC/WireGuard; ExpandLabel before TLS; Windows FFI before Windows-green CI). Is anything in S1 a prerequisite that was skipped, or anything blocking that should be pulled IN (e.g., the binding-condition backlog: ProbeGuard eviction, CSPRNG-jittered slow-close, rand-split mechanical enforcement, XChaCha20 standardization)?
2. Scope realism: estimate relative effort per S1 item given the zero-dependency constraint and MSRV 1.77.2 (no div_ceil-era idioms beyond 1.73, no trendy std APIs). Is the S1 charter's acceptance list achievable in one stage, or should it split? Same spot-check for S2 (TLS 1.3 from scratch), S3 (QUIC v1 from scratch), S6 (TUN/killswitch) — flag any stage whose acceptance criteria cannot be measured as written.
3. Descope rules: the roadmap's descope rule says v1.0 may ship with fewer live protocols but "never a fake or half-validated plane". Binding condition A3-C1 requires the descope rule to NAME the v1.0 TLS/QUIC-based protocol — has it been named? Binding condition A3-C5 requires the descope tripwire (stage exceeding N recorded sessions triggers decision) and terminal gate 0008 charter — do they exist? If not, draft concrete language.
4. Measurability: for each stage S1–S7, check every acceptance criterion is binary-checkable (test names, grep-audits, CI-green conditions). Flag vague ones and propose replacements.
5. Operational risks: Windows CI red-until-S1 (what does that do to development cadence and to the "test count never drops" standing criterion?); frontends S7 realism (how mature are app_flutter/app_kmp/app_qt actually — inspect); provider stage S5 risks (credential material, live-API drift, legal/operational exposure); published-release disclosure D-0009 (advisory vs v0.3.1 re-release) still pending — what does delaying cost?

EVIDENCE DISCIPLINE: every finding cites path:line (or file/section) and is marked (verified | suspected).

CONSTRAINTS: READ-ONLY on the repo — do not create, modify, or delete ANY file under the HoloNet directory. Bash only for read-only commands. Web research allowed if it sharpens a feasibility estimate. Budget: thorough but finite, ~15 minutes of tool activity.

Your final reply MUST end with this exact verdict block (strict format, last section of your reply):

AGENT: A3 Strategy Adversary
VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
FINDINGS:
- [F1] <finding> — evidence: <path:line> (verified | suspected)
CONDITIONS:
- [C1] <concrete, verifiable condition>   (required unless PROCEED)
DISSENT/NOTES: <anything the aggregator must not smooth over>
````

## A4 — Process Auditor (prompt verbatim)

````text
You are reviewer **A4 — Process Auditor** on the HoloNet adversarial panel (record `0002-progress-review`). You are one of four blind reviewers launched in parallel; you will not see the others' output and they will not see yours. Your job is to find the strongest reason NOT to trust the harness/process itself — the machinery that is supposed to make everything else trustworthy. Approval without evidence is a failed review; so is a BLOCK without concrete grounds.

CONTEXT (your shared input is the repository working tree at `C:\Users\Maniesh\.zcode\workspace\default\HoloNet`, branch `main` @ `8761716`, restored from public github.com/maniesh-NR/HoloNet). Today is 2026-11-17. This run executes on a WINDOWS host (Git Bash), which is new for this project: previous runs were Linux sandboxes. Observed host facts you may rely on: no Rust toolchain installed (no cargo/rustup), no MSVC/gcc (`/usr/bin/link` is coreutils, not MSVC), git push works via cached Windows credential-manager credentials, `HOLO_GITHUB_TOKEN` is absent (backup.sh falls back to `origin`), winget exists. Binding docs: `harness/WORKFLOW.md`, `harness/ADVERSARIAL.md`, `harness/scripts/backup.sh`, `harness/memory/{ROADMAP,STATE,LESSONS,DECISIONS,BACKUPS,SANDBOX-RESTORE}.md`, `docs/RESTORE.md`, `.github/workflows/*`, `harness/adversarial/verdicts/0001-*.md`. Gate 0001 PASSED. This run is a progress review feeding record `0002-progress-review.md` — note the roadmap's "gate 0002" naming collision and assess it. Reviewer scope per WORKFLOW §2.2: (a) work completed so far, (b) the S1 charter — for you, (b) includes whether the harness can enforce S1's acceptance criteria.

YOUR MANDATE (from harness/ADVERSARIAL.md): the harness/workflow itself; consensus failure modes; backup integrity; restore runbook; rubber-stamp risk.

ATTACK SURFACE:
1. backup.sh line-by-line: message sanitization, FAILED-marker durability (committed locally, reaches remote only on NEXT success — trace the recovery path in WORKFLOW §1.4; is the rebase-keep-both-lines instruction actually executable as written?), token-in-argv exposure tradeoff, tag-push WARN path, non-fast-forward handling, behavior on a Windows host (bash availability, `date -u`, `cut -c1-200`, `tr` — anything platform-fragile?).
2. Consensus failure modes: the aggregator is the author/orchestrator of the work under review (disclosed conflict). Given gate-0001's actual history (A2 BLOCK → remediation → A2-only re-review), does the protocol's "if remediation touches anything outside the blocking finding's scope, the FULL panel re-runs" rule get enforced mechanically or only by convention? The current panel is four same-model agents launched by one orchestrator with rotated emphasis — what residual correlated-blind-spot risks remain, and what mechanical mitigations exist (e.g., archiving prompts verbatim, model rotation)?
3. Record integrity: chain-of-SHA-256 records — verify record 0001's chain line actually matches the SHA-256 of the previous record text it references (compute it); check `harness-audit` CI job (in .github/workflows/) — what does it actually verify, and what does it NOT (can it detect a gate record added without a backup log line? verdict text mutated after push?).
4. Restore runbook vs THIS host: docs/RESTORE.md and harness/memory/SANDBOX-RESTORE.md assume Linux sandboxes (curl rustup-init for x86_64-unknown-linux-gnu). On this Windows host there is no toolchain — what does an honest restore-and-reverify require HERE, and is the runbook wrong/missing a Windows section? STATE.md §"Re-verify after any restore" says cargo test green 75 Linux — impossible on this host today; how should STATE handle that honestly?
5. Rubber-stamp risk & drift: memory files claim things — spot-check STATE.md claims against the tree right now (e.g., 11 crates count, file references like holo-ss/src/lib.rs:97-98 dead n24 store, ROADMAP quotes of test names like os_entropy_fails_closed_on_unreadable_source — do they exist verbatim?); DECISIONS.md/LESSONS.md append-only discipline — any evidence of edits; BACKUPS.md FAILED-line semantics vs what a reader would conclude.

EVIDENCE DISCIPLINE: every finding cites path:line (or computed hash) and is marked (verified | suspected).

CONSTRAINTS: READ-ONLY on the repo — do not create, modify, or delete ANY file under the HoloNet directory. Bash only for read-only commands (grep, git log, ls, sha256sum, curl GET). Budget: thorough but finite, ~15 minutes of tool activity.

Your final reply MUST end with this exact verdict block (strict format, last section of your reply):

AGENT: A4 Process Auditor
VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
FINDINGS:
- [F1] <finding> — evidence: <path:line> (verified | suspected)
CONDITIONS:
- [C1] <concrete, verifiable condition>   (required unless PROCEED)
DISSENT/NOTES: <anything the aggregator must not smooth over>
````

## Appendix — non-panel briefs (verbatim)

### Blue-Forensics brief (abridged to scope; full text as sent)

Progress/forensics analyst: build the factual progress record (timeline
from git history/tags/releases/CI; verified-claims table with ≥ the
per-OS test counts, zero-deps, throughput, RSS, release assets,
SHA256SUMS, 11 crates, M3 33-role, 7 link schemes; what has worked;
issues encountered and resolution state; open risks; metrics snapshot).
Single write target:
`project-management/reports/progress-forensics.md` (OUTSIDE the repo;
repo READ-ONLY).

### Green-R1 brief (abridged to scope; full text as sent)

Research: fixes/improvements for the shipped plane grounded in the
ecosystem (salt-replay protection as in shadowsocks-rust/sing-box +
SIP022 caveats; probe-resistance literature incl. NDSS/IMC 2020; UDP
SIP004 + SOCKS5 UDP ASSOC; interop-oracle test design under D-0002;
clean-room crypto validation beyond vectors — differential vs OpenSSL
CLI, ACVP, fuzz in separate dev-only workspace; transport tuning;
SOCKS5/DNS leak patterns; release hygiene: reproducible builds,
minisign, SLSA, signed v0.3.1 closing D-0009). Deliverable:
`project-management/reports/research-improvements.md`, 10–15
prioritized recommendations. Single write target; repo READ-ONLY.

### Green-R2 brief (abridged to scope; full text as sent)

Research: new features + roadmap pressure-test (from-scratch TLS 1.3
feasibility; from-scratch QUIC v1 feasibility; userspace WireGuard +
Noise-IK crypto-coverage check against the S1 list; 2025–26
censorship-resistance landscape incl. REALITY/ShadowTLS v3/uTLS/ECH/
Hysteria2/TUIC/MASQUE and the descope-rule v1.0 protocol pick; provider
stage reality check; packaging/distribution per platform incl. Win7
floor; GUI maturity for 'wire live tunnel status'). Deliverable:
`project-management/reports/research-features-roadmap.md`, 10–15
candidates + explicit descope-rule answer. Single write target; repo
READ-ONLY.
