# Session journal — 2026-11-17/18: progress review 0002 (adversarial panel + forensics + research)

Owner-requested run: "Assign adversarial roles to teams of agents to
analyse the progress so far, what has worked, issues encountered,
research possible fixes/improvements/new features, update roadmap.
Extensively document and backup everything."

## Host / restore

First run on the owner's WINDOWS host (Git Bash; no Rust toolchain, no
MSVC — verification was static + public GitHub API only; recorded as a
disclosed limitation in STATE and the review record). Restored from
`origin/main` @ `8761716` (= `sandbox/latest`, clean). Push auth via
cached Windows credential manager (verified with a dry-run).

## What ran

- **Panel (blind, per ADVERSARIAL.md):** A1 Reliability Skeptic, A2
  Security Red, A3 Strategy Adversary, A4 Process Auditor. Launched as
  one 7-agent batch; host concurrency limits cut six mid-run; resumed
  (three from their own context, three fresh with identical prompts).
  One orchestrator mislabel incident during resume, corrected mid-run
  before any verdict; recorded in the record header and in A3/A4
  dissents. All four verdicts filed: **PROCEED_WITH_CONDITIONS ×4,
  0 BLOCK ⇒ CONSENSUS** (progress review — no transition authority).
  Record: `harness/adversarial/verdicts/0002-progress-review.md`
  (chain: 5bbc465c…ab4f4). Prompts archived verbatim:
  `0002-reviewer-prompts.md`.
- **Non-panel analysts:** Blue-Forensics (progress record), Green-R1
  (fixes/improvements research), Green-R2 (features/roadmap research).
  Reports live OUTSIDE the repo at `project-management/reports/`
  (owner workspace, backed up with this run):
  `progress-forensics.md`, `research-improvements.md`,
  `research-features-roadmap.md`, plus `RUN-SUMMARY.md`.

## Headline findings (full detail in the record + reports)

1. **A1:** public CI at HEAD is red on ubuntu (integration step) and
   on the 1.77.2 job — undisclosed before this review; only 3 releases
   actually public vs README's table; OpenSSL-journals claim was rot.
   Positives verified: 75 tests countable, per-OS arithmetic exact,
   zero third-party deps, default-deny honest dispatch, citations real.
2. **Blue (root causes):** 53ff229 rewrote Cargo.lock v3→v4 (breaks
   cargo 1.77.2 → the legacy-job failure); release runs "succeeded"
   but per-OS releases are invisible (drafts/deleted).
3. **A2:** NO salt-replay protection (absent from code AND threat
   model); shipped "xchacha20-ietf-poly1305" is non-standard (mislabel,
   non-interop, not a confidentiality break); Windows secret-at-rest
   will regress the day the S1 FFI lands; D-0009 has no deadline.
   Crypto core otherwise verified sound by reading.
4. **A3:** S1 sequencing right but overweight (ordering rule applied);
   off-loopback refusal pulled into S1 from S6; descope rule/tripwire/
   terminal-gate finally written (one cycle late — panel warning
   recorded); S5 split + credentials decision; S6 policy contradiction
   scheduled for pre-decision.
5. **A4:** hash anchors broke on CRLF checkout (fixed via
   .gitattributes + blob-hash wording); harness-audit CI is
   existence-only and skipped the only gate push (strengthening
   charted); backup.sh rebase-recovery hole (guard charted); restore
   runbook was Linux-only (Windows section added this run).
6. **Green-R1:** 15 recommendations — salt-replay cache, ProbeGuard
   bounding, SIP004 UDP + UDP ASSOCIATE, subprocess interop oracles,
   OpenSSL/ACVP differentials, fuzz workspace, dudect timing, release
   hygiene (minisign/SLSA). Adopted into ROADMAP research backlog.
7. **Green-R2:** S3 rescoped client-relay; S5 reordered/cut for v1.0;
   descope answer = **trojan over holo-tls** (D-0014 default); S7
   owner-cost decisions noted (macOS notarization, Play account).

## Changed (this run)

- `.gitattributes` (LF pinning); `WORKFLOW.md` §2.6 (record numbering,
  progress-review type, blob-hash verification; D-0011).
- `harness/memory/ROADMAP.md`: numbering fix; S1 amendments (ordering,
  salt-replay, Windows secrets, off-loopback refusal, 1M-vector mode,
  BLAKE2b cut, constant-time bar); S2 driver deliverable + no-X.509 +
  SNI-masking; S3 rescope; S5 split; S6 pre-decision; descope rule
  NAMED (D-0014) + tripwire N=4 + terminal gate; research backlog.
- `docs/THREAT-MODEL.md`: §A SOCKS-hop consequence, §C replay + slow-
  close fingerprint citation, §E release surface, §G Windows secrets;
  revision history.
- `README.md`: OpenSSL-journals honesty fix; Releases section rewritten
  to API-verified reality.
- `engine/Cargo.lock`: version 4 → 3 (the 1.77.2-breakage root cause).
- `harness/memory/STATE.md`: rewritten (full CI disclosure, per-host
  re-verify, this run's changes, open items). `DECISIONS.md`:
  D-0011…D-0014. `LESSONS.md`: orchestration + CI/evidence entries.
  `SANDBOX-RESTORE.md`: Windows variant + 4W fallback.
- New: `harness/adversarial/verdicts/0002-progress-review.md`,
  `0002-reviewer-prompts.md`, this journal; external reports + backups
  under the owner workspace `project-management/`.

## Not done (binding on the next run)

A1-C1 ubuntu-CI diagnosis (needs repo log access / toolchain);
A4-C2 harness-audit strengthening; A4-C3 backup.sh guard + WARN
durability; all S1 code. Owner decisions at next session start:
D-0009/D-0013 (advisory vs signed v0.3.1 — before the XChaCha20 wire
change), S5 credentials model, D-0014 confirmation.

## Gate status

Gate 0001 PASSED (S0→S1; S1 open, not started). Progress review 0002
PASSED (4× PROCEED_WITH_CONDITIONS, 0 BLOCK) — S1 charter amended;
next record number 0003 (expected: the S1→S2 gate).
