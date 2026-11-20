# Verdict archive — record 0003, round 1, reviewer A1 (verbatim)

Platform note: reproduced byte-exact from the reviewer agent's return
message, including its trailing platform-metrics footer (kept for
exactness; no editorial changes). Launch metadata: parallel batch,
2026-11-20, task ID ADV-A1, model requested "sonnet", platform served
model family x-preview-l (disclosed in the record + prompts archive).

---

# A1 Reliability Skeptic — Gate 0002 Review Report

## What I ran myself (vs. only read)

**Ran/counted:** full `cargo test --workspace` on this tree (cold-ish cache): **75 passed / 0 failed, exit 0** (suites 10+17+2+6+9+2+5+7+10+7) — matches the orchestrator's numbers exactly. Static `#[test]` count = **75**. `git grep` at tag **v0.3.0 = 71 tests**, delta +4 = rand +2, holo-config +1, holo-ss +1 (the oversized-length test) — STATE.md's "71 baseline + 4 hardening" arithmetic verified. `sha256sum` of the gate record = `5bbc465c…` = last BACKUPS.md line = backup commit message (tie-in ✓). Tags: `sandbox/latest` → HEAD `8761716`, 11 tags ✓. KAT verification of the orphan via OpenSSL oracles (`hashlib.blake2b/blake2s`, `b2sum`). Orphan compile/run diagnosis in a **/tmp scratch crate** (repo untouched; final `git status` clean).

**Only read:** CI/release workflow files, harness memory files, verdict archives, docs.

## Verification of gate-0001 record and harness claims (attack surface 2)

Everything load-bearing checked out from the tree: 11 crates (ARCHITECTURE:24-40); `ci.yml` permissions `contents: read` (:4), `branches: [main]` (:8), harness-audit job (:83-106); release.yml SHA256SUMS on **all four** jobs + 1.77.2 pins; `.gitignore` `id_ed25519*/id_ecdsa*/**/ipc-token` (:56,64-65); backup.sh message sanitization, immediate FAILED-marker commit, non-main refusal, env-only token. All 12 named tests in TECHNIQUES exist. Milestone honesty real: non-SS drivers get named errors (`holo-engine/src/lib.rs:277-281`), unsupported method lists live ciphers (:286-288), UDP milestone + test (`holo-ss:713-717,1135`), holonetctl entropy propagation (`main.rs:34-36`), `ct_eq` (:520). WORKFLOW "§x.y" citations are a section-item convention and **all resolve** (checked §1.3/§1.4/§2.5/§3.3) — not rot. Integration tests remain meaningful: real `serve_conn` server, full IPC chain, `#![forbid(unsafe_code)]`, retry-not-busy-locked, oversized-length never-dials-upstream, 64 MB memory bound < 2 MB (`integration.rs:439-442`).

**Per-platform counts:** the 74/72 numbers are arithmetically coherent — exactly 1 Linux-gated test (`integration.rs:364-365`) and 2 unix-gated tests (`holo-config/src/lib.rs:325`, `holo-util/src/rand.rs:110`) → 75−1=74, 74−2=72. But they are **derivations, never executed**: no macOS run is evidenced anywhere in the tree, and the Windows suite *cannot* pass today (fail-closed entropy, D-0008). STATE.md:14-16 places them under a "Tests:" heading in a way that reads as green-everywhere; "Windows 72" is a would-run count, not a green count. This is the one place the record quotes an unverifiable number as fact.

## The orphan BLAKE2 (attack surface 5)

- **(a)** RFC 7693 BLAKE2b/BLAKE2s WIP, 353 lines, 5 tests, written as a paste-in holo-crypto module (tests call `crate::from_hex/to_hex`, lines 232/235, which only exist in holo-crypto).
- **(b)** Does not compile as-is: `SIGMA` at file top level (:16) referenced unqualified inside child modules `blake2b` (:59) and `blake2s` (:156) → E0425 ×2 (orchestrator-verified; statically consistent — child modules don't see parent items).
- **(c)** Expectations **authentic**: all 32 hex expectations (unkeyed+keyed, b+s, lengths 0/1/3/64/65/127/128/255, plus both RFC 7693 "abc" vectors) match OpenSSL independently (hashlib; b2sum cross-check on blake2b unkeyed). **Reusable in S1.** The *implementation* is not: in my scratch copy with only the scoping fix, **3/5 tests fail their own KATs** (blake2b unkeyed at inlen 64; blake2s unkeyed; keyed). Per-length diagnosis: digests correct only for degenerate inputs where m[2]==m[8] (0–3 bytes); wrong for every length ≥31 probed → a single message-schedule defect consistent with `SIGMA[3][8]=2` in the file vs `8` in the RFC reference table (exact canonical row: suspected; the KAT failures: verified). My one-token swap hypothesis made it worse — repair requires re-deriving the schedule from RFC 7693 §3.3, not a quick edit.
- **(d)** Process/honesty: the orphan now lives *outside* any repo/backup/journal — a sandbox recycle loses it silently, and no DECISIONS/LESSONS/journal entry records its existence or findings. LESSONS.md:25 carries only "ROTR not ROTL" — but ROTR was correct in this code; the actual bug was **SIGMA transcription** (+ module scoping). ROADMAP:60's lesson emphasis is pointed at the wrong pitfall given this evidence.

## Claim-rot sweep (attack surface 3)

Gate-0001 fixed most rot, but two new/missed spots: phantom citation `docs/ARCHITECTURE.md §12` (TECHNIQUES.md:211 — ARCHITECTURE has no numbered sections at all); and TECHNIQUES.md:28-29 "the SS dialer records connect RTT samples" — **false on the tree**: zero `rtt`/`Rtt` references outside holo-net, and holo-net isn't even a runtime dependency of holo-ss. Also the recurring "OpenSSL cross-checks … recorded in the harness session journals" chain (README:31-35, TECHNIQUES:183-185, RESTORE:17-18) — the sole journal contains **no** OpenSSL record; the evidence is cited to a place it doesn't exist. All other checked numbers (75/71/per-crate counts/RSS 88–376 KB/<2 MB/33 roles/7 schemes/CLI verbs/11 tags) match the tree.

## S1 charter countability (attack surface 7)

Criteria are largely countable (named entropy test already exists at `rand.rs:119-125`; RFC 7693/7748/SP 800-38A/8448/8017 vector sets named; mechanical unsafe grep; named server-hardening tests; per-platform monotonic counts). Soft spots, non-fatal: jitter test "two peers … different delays" is probabilistic (needs fixed-seed/range assertion to avoid a flaky gate); "bounded under N peers" leaves N unspecified; the OpenSSL-journal criterion repeats the F3 pattern. The A3-round-2 items that are unenforceable today (ubuntu-only 1.77.2 job, `ci.yml:108-122`) are honestly **carried in the charter** as S1 acceptance items (ROADMAP:88-92) — not dropped.

---

AGENT: A1 Reliability Skeptic
VERDICT: PROCEED_WITH_CONDITIONS

FINDINGS:
- [F1] Phantom doc citation: TECHNIQUES.md cites "docs/ARCHITECTURE.md §12" which cannot exist — ARCHITECTURE.md has no numbered sections — evidence: docs/TECHNIQUES.md:211, docs/ARCHITECTURE.md:1-77 (verified)
- [F2] False wiring claim: "the SS dialer records connect RTT samples" — RttEstimator is referenced nowhere outside holo-net/src and holo-net is not a runtime dep of holo-ss — evidence: docs/TECHNIQUES.md:28-29, rg -i 'rtt' across engine/crates (empty outside holo-net), engine/crates/holo-ss/Cargo.toml (verified)
- [F3] Broken evidence chain: README/TECHNIQUES/RESTORE say OpenSSL cross-checks are "recorded in the harness session journals"; the only journal (2026-11-13-harness-gate0001.md) contains no OpenSSL record — evidence: README.md:31-35, docs/TECHNIQUES.md:183-185, docs/RESTORE.md:17-18, harness/memory/sessions/ (rg -i openssl → no journal hits) (verified)
- [F4] Per-platform test counts (macOS 74 / Windows 72) quoted as fact in STATE/ARCHITECTURE though derived, never executed; Windows suite cannot pass today per D-0008 — evidence: harness/memory/STATE.md:14-16, docs/ARCHITECTURE.md:51-52; derivation verified via integration.rs:364-365, holo-config/src/lib.rs:325, holo-util/src/rand.rs:110 (verified as derivation; unverifiable as runs)
- [F5] Orphan BLAKE2 is doubly broken — E0425 SIGMA scoping (orchestrator-verified, statically consistent: blake2-orphan:16 vs :59,:156) AND, after scoping fix alone, fails its own authentic KATs (3/5 tests; digests wrong for any input where m[2]≠m[8], isolated mechanically); its 32 KAT expectations independently match OpenSSL and ARE reusable in S1; the artifact is un-referenced by harness memory and will be silently lost on recycle; LESSONS.md:25/ROADMAP.md:60 emphasize ROTR — the wrong pitfall for what this code demonstrates — evidence: /home/z/my-project/blake2-orphan-2026-11-20.rs (read), /tmp scratch run (verified), harness/memory/LESSONS.md:25, harness/memory/ROADMAP.md:60 (verified)
- [F6] No guard against the umask mode-diff hazard that already hit this run (76 files 100644→100755): no core.fileMode normalization or mode-diff preflight in SANDBOX-RESTORE.md/WORKFLOW.md/backup.sh — evidence: harness/memory/SANDBOX-RESTORE.md, harness/scripts/backup.sh (rg umask|filemode → empty) (verified absence; the 76-file event itself per orchestrator, suspected-reproducible)
- [F7] Hygiene nits: unused dependency `holo-util` in holo-socks (cargo warning); holo-engine lists holo-util/holo-ss in both [dependencies] and [dev-dependencies] — evidence: engine/crates/holo-socks/Cargo.toml:11, engine/crates/holo-engine/Cargo.toml:15,20,18-21 (verified)
- [F8] S1 charter soft spots (non-blocking): probabilistic jitter-test wording and unspecified N in ProbeGuard bound; OpenSSL-journal criterion repeats the F3 pattern — evidence: harness/memory/ROADMAP.md:111-117 (verified as wording)
- [F9] Positive verification set (calibration): suite 75 green exit 0 re-run this review; record↔BACKUPS.md SHA tie-in exact; harness-audit job present; tags/checksums/permissions as claimed; milestone honesty real at all five probed surfaces; integration tests non-trivial; v0.3.0=71 and per-crate counts match the tree exactly — evidence: harness/adversarial/verdicts/0001-S1-gate.md:122-124, harness/memory/BACKUPS.md:final line, .github/workflows/ci.yml:83-106, .github/workflows/release.yml:53,99,145,209, engine/crates/holo-engine/src/lib.rs:274-288, engine/crates/holo-engine/tests/integration.rs (verified)

CONDITIONS:
- [C1] Fix TECHNIQUES.md:211 to cite a real target (holo-proto Params/Registry or an actually-written ARCHITECTURE section); gate check: `rg 'ARCHITECTURE\.md §' docs/ harness/` returns zero hits outside verdict archives
- [C2] Reword TECHNIQUES.md:28-29 to match the tree (RTT estimator validated but unwired until the QUIC/UDP stages) or actually wire it; gate check: the doc claim and `rg -i 'rtt' engine/crates` agree
- [C3] Repair the OpenSSL evidence chain: either append a real cross-check record (commands+digests) to a session journal, or reword README.md:31-35, TECHNIQUES.md:183-185, RESTORE.md:17-18, ROADMAP.md:116-117 to "self-attested in pre-harness sessions; no independent record"
- [C4] Scope platform counts honestly in STATE.md:14-16 and ARCHITECTURE.md:51-52: mark 74/72 as derived-from-cfg-gating (1 Linux-gated + 2 unix-gated), not executed; Windows count is a would-run number while the suite is red by design (D-0008) — consistent with WORKFLOW §3 rule 4 ("test counts quoted anywhere must be countable from the tree")
- [C5] Record the orphan's disposition in harness memory this run (DECISIONS or session journal): its out-of-repo path, its two defects (SIGMA scoping E0425; SIGMA[3] message-schedule defect proven by KAT failure), its authentic reusable KAT set (32/32 vs OpenSSL); add the two new pitfalls to LESSONS.md and correct ROADMAP:60's ROTR emphasis; S1 must re-derive the mix schedule from RFC 7693 §3.3 rather than repair the orphan in place
- [C6] Add a mode-diff guard to the restore runbook or backup.sh preflight (e.g., `git config core.fileMode false` after restore, or a `git diff --summary` mode-only check before `git add -A`); gate check: the guard exists and the umask scenario is named in SANDBOX-RESTORE.md

DISSENT/NOTES: Baseline is trustworthy — every load-bearing claim I could check from the tree checked out, the suite is genuinely green (I re-ran it), and the harness did the right thing quarantining the broken orphan out of backup reach. What remains is precisely the class of defect this project claims to have eliminated: three docs spots citing evidence that doesn't exist as cited (F1-F3) — the same rot class gate 0001 fixed, missed in two places and recurring in one. F5 is the sharpest lesson: the crashed session's WIP "knew" the ROTR lesson and still shipped a corrupt SIGMA row; official-vector gates (already in the S1 charter) are what caught it, which is exactly why the countable-criteria charter deserves to stay binding. Verification transparency: my orphan diagnosis ran in a /tmp scratch crate (`/tmp/a1-blake2-check`) with the repo untouched (final `git status` clean); the authorized suite run wrote only gitignored `engine/target` artifacts; the macOS/Windows counts remain unverifiable in this Linux sandbox and I treated them as derivations, not facts. I made no edits to any tracked file and ran no state-changing git commands.

Tokens -> prompt:112280 completion:3753 total:116033
Resume by calling Task with "resume": "agent-663d77fb-6242-4312-b04d-0fa28448c372".
