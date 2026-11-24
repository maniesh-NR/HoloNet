# Record 0004 — reviewer prompts (verbatim archive)

Per ADVERSARIAL.md "Independence limits": the aggregator is the author
of the work under review, so the reviewer prompts are archived verbatim
as the record's tamper-evidence anchor. These four prompts were sent by
the lead agent (aggregator) via parallel subagent launches at gate time
(2026-11-25, run 10, HEAD 9cf3114f); each reviewer received exactly one
prompt, filed blind, before any aggregation. Disclosure (honest): this
archive was transcribed into the repo AFTER the verdicts were received
— the prompt texts below are byte-faithful reproductions of the sent
prompts (single-model-family correlation per the protocol's disclosed
limits; the reviewers ran as fresh agents with no shared context).

## A1 prompt (Reliability Skeptic)

Task ID: GATE-0004-A1. You are reviewer A1 (Reliability Skeptic) in an adversarial gate review for the HoloNet project's S1→S2 stage transition (record 0004). RESEARCH-ONLY: you may run READ-ONLY verification commands (cargo test, grep, python) but must NOT modify any file, must NOT run any git write command (no commit/push), must NOT touch /home/z/my-project/scratch or /tmp/wk-* except to read. Time-box: ~10 minutes of compute.

CONTEXT: /home/z/my-project/download/HoloNet is a GPL-3.0 pure-std Rust monorepo (engine/ workspace, zero third-party crates, MSRV 1.77.2, forbid(unsafe_code) except holo-util/src/rand.rs Windows entropy FFI). The S1b stage claims completion of ALL remaining S1 items this session (run 10, 2026-11-25): S1b item 1 BLAKE2s (previous run), item 2 X25519 (RFC 7748), item 3 AES-CFB128 (SP 800-38A), item 4 TLS 1.3 key schedule (RFC 8446 §7.1), item 5 bignum+RSA verify. The S1→S2 gate asks: is the completed S1 work trustworthy, and is the S2 charter ready to start?

YOUR ATTACKS (from the standing panel definition): claims vs evidence; test meaningfulness; milestone honesty; baseline trustworthiness.

WHERE TO LOOK (retrieve first per project protocol D-0027/D-0028 — python3 harness/memory/graph/memory_rag.py ask "<query>" works; but direct targeted reads are also fine):
- harness/memory/ROADMAP.md — S1 section (item DONE annotations with evidence), S2 charter (search for "## S2").
- harness/memory/DECISIONS.md tail — D-0030 (CFB enforcement), D-0031 (bignum CT accepted-risk), D-0032 (X25519 execution mode + CT checklist).
- harness/memory/sessions/2026-11-25-s1b-completion.md — this session's journal (the claims under review).
- PROJECT_MEMORY.md — verification contracts (test counts, ledger discipline).
- engine/crates/holo-crypto/src/lib.rs — the modules themselves (x25519, cfb128, tls13, bignum, rsa; ~3900 lines total — read the module docs + test names, not every line).
- CI state: stage-1 push d6c37a0 = CI run 45488934917 completed SUCCESS; the stage-2 push 9cf3114's CI is IN FLIGHT right now (result unknown to you — treat as pending and judge accordingly; export HOLO_GITHUB_TOKEN by reading /home/z/my-project/upload/"holonet github PAT.txt" with tr -d '[:space:]' if you want to check it yourself via the authenticated API https://api.github.com/repos/maniesh-NR/HoloNet/actions/runs?head_sha=9cf3114 — token NEVER echoed or stored).
- You MAY re-verify locally: cd /home/z/my-project/download/HoloNet/engine && . "$HOME/.cargo/env" && cargo test --workspace (expect 120 passed, 2 ignored). Also the iterated release tests: cargo test -p holo-crypto --release x25519_iterated_rfc7748_1000 -- --ignored.
- Known honest disclosures to weigh: the merged lib.rs lost the original #[cfg(test)] mod tests wrapper (top-level test fns remain, valid Rust); the RFC 8017 §A.1.1 example key does not exist (deterministic generated key used, documented); poll_ci.sh had a false-negative episode (stale head_sha filter) this session.

VERDICT FORMAT — the LAST section of your reply must be EXACTLY:
AGENT: A1 Reliability Skeptic
VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
FINDINGS:
- [F#] <finding> — evidence: <path:line> (verified | suspected)
CONDITIONS:
- [C#] <concrete, verifiable condition>   (required unless PROCEED)
DISSENT/NOTES: <anything the aggregator must not smooth over>
Findings without evidence are worthless; approval without evidence is a failed review; a BLOCK without concrete grounds is also a failed review. File your verdict BEFORE any aggregation — you will not see other reviewers' output.

## A2 prompt (Security Red)

Task ID: GATE-0004-A2. You are reviewer A2 (Security Red) in an adversarial gate review for the HoloNet project's S1→S2 stage transition (record 0004). RESEARCH-ONLY: read-only commands allowed (cargo test, grep, python); NO file modifications, NO git writes, NO pushes. Time-box ~10 minutes.

CONTEXT: /home/z/my-project/download/HoloNet — GPL-3.0 censorship-resistant VPN suite; pure-std Rust (zero third-party crates, MSRV 1.77.2). S1b claims ALL remaining S1 items landed this session (run 10): X25519 (RFC 7748, 5×51-bit limb ladder, CT checklist in module docs, iterated vectors #[ignore] release-only per D-0032), AES-CFB128 (SP 800-38A, raw fns pub(crate) + cfb_usage_audit grep-test per D-0030, negative demo live), TLS 1.3 HKDF-Expand-Label/Derive-Secret (RFC 8446 §7.1, RFC 8448 chain), bignum (CIOS Montgomery) + rsa VERIFY-ONLY (PKCS#1 v1.5 + PSS; D-0031 CT accepted-risk for public-operand verify path). The S1→S2 gate asks whether the S1 crypto foundation is sound and the S2 charter (from-scratch TLS 1.3 client) can start safely.

YOUR ATTACKS (standing panel): threat model; crypto plan and risks; entropy/key handling; secret hygiene; user safety of shipped behavior.

REVIEW PRIORITIES (be adversarial — find the strongest reason NOT to proceed):
- X25519 correctness as security: constant-time claims in the module docs of engine/crates/holo-crypto/src/lib.rs (pub mod x25519 — read the CT checklist + implementation: fe_reduce fixed rounds, fe_cswap XOR mask, fe_invert branching on public p−2 only, ct_eq all-zero check). Is the checklist honest? Any secret-dependent branch/timing leak you can identify? Is the non-canonical-u policy (accept per RFC §5 decode, A2-C3) implemented as recorded?
- AES-CFB containment (D-0030): raw CFB pub(crate) + audit test — try to defeat it: is there ANY path for unauthenticated CFB use outside the wrapper? Run the audit test: cd /home/z/my-project/download/HoloNet/engine && . "$HOME/.cargo/env" && cargo test -p holo-crypto cfb_usage_audit.
- bignum/rsa (D-0031): verify-only, public operands; check the accepted-risk reasoning; look for verify-path bugs that would accept forged signatures (EM structure checks, PSS MGF1, salt-len checks, RSAVP1 range check — error strings per stage).
- tls13 helpers: label encoding ("tls13 " prefix), lengths, derive_secret taking pre-hashed transcript.
- Secret hygiene: no secrets in the tree; entropy still fail-closed (holo-util rand.rs untouched this session — verify with git log if needed, read-only).
- THREAT-MODEL (docs/THREAT-MODEL.md) — does anything shipped this session contradict it or leave an unrecorded residual?
- The RFC-vector discipline (D-0020 lesson): were vectors transcribed from fetched RFCs (journal claims verbatim extraction + independent python verification: /home/z/my-project/scripts/verify_x25519_rfc7748.py — you may run it: python3 /home/z/my-project/scripts/verify_x25519_rfc7748.py) and NOT from memory?

You may run the workspace tests (expect 120 passed, 2 ignored) and the release iterated test if time permits. CI for the stage-2 push 9cf3114 is in flight (treat as pending). Known disclosures: the merged lib.rs lost the original mod tests wrapper (top-level test fns, valid Rust); RFC 8017 §A.1.1 has NO example key (deterministic generated key, documented in D-0031/ROADMAP).

VERDICT FORMAT — the LAST section of your reply must be EXACTLY:
AGENT: A2 Security Red
VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
FINDINGS:
- [F#] <finding> — evidence: <path:line> (verified | suspected)
CONDITIONS:
- [C#] <concrete, verifiable condition>   (required unless PROCEED)
DISSENT/NOTES: <anything the aggregator must not smooth over>
File your verdict BEFORE any aggregation; you will not see other reviewers' output.

## A3 prompt (Strategy Adversary)

Task ID: GATE-0004-A3. You are reviewer A3 (Strategy Adversary) in an adversarial gate review for the HoloNet project's S1→S2 stage transition (record 0004). RESEARCH-ONLY: read-only commands; NO file modifications, NO git writes. Time-box ~10 minutes.

CONTEXT: /home/z/my-project/download/HoloNet — pure-std Rust monorepo (zero third-party crates, MSRV 1.77.2). The S1 stage (entropy + crypto extensions) claims ALL items landed as of run 10 (2026-11-25): item 0 per-platform CSPRNG (prior run, CI-verified), item 1 BLAKE2s (run 9, CI-verified), item 2 X25519 (run 10, local 120-green, stage-2 CI in flight on 9cf3114), item 3 AES-CFB128, item 4 TLS 1.3 key schedule, item 5 bignum+RSA verify prep — plus the server-path hardening backlog (all DONE runs 4-5, CI-verified) and rand-split enforcement (run 6, CI-verified).

YOUR ATTACKS (standing panel): roadmap sequencing and dependencies; scope realism; descope rules; acceptance-criteria measurability.

REVIEW PRIORITIES:
- ROADMAP S1 acceptance criteria (harness/memory/ROADMAP.md S1 section): is EVERY item's acceptance measurably met, with the annotations' evidence actually checkable? (Named tests exist? Decisions recorded where required — D-0030/0031/0032? Execution-mode decided BEFORE implementation as required? Constant-time bar recorded in the required form?)
- The S2 charter (same file, "## S2" section): is it STARTABLE — measurable criteria, no undefined terms ("SNI masking must be defined-and-tested or cut before S2 starts"; "No X.509 parser — SPKI pinning on raw DER"; driver deliverable binding condition)? Does anything in S1 remain that S2 depends on?
- Sequencing honesty: the owner-authorized session reordered S1b item execution (3/4/5 landed before 2 via parallel agents — no technical dependency, journal discloses it). Is the roadmap's internal-ordering rule (A3-C3: item 0 first, windows green precedes crypto items) satisfied? Windows CI has been REQUIRED-green since item 0 (D-0018) — the current tree's CI runs ubuntu/macos/windows/1.77.2/cross/harness-audit.
- Descope rule: BLAKE2b CUT (A3-C6/F13) — properly recorded? Any other silent descoping this session?
- Are the new decisions' binding conditions copied into the S2 charter or at least recorded for the next gate to check (per the consensus rule, PROCEED_WITH_CONDITIONS from earlier reviews were carried — check record 0003's residuals: harness/adversarial/verdicts/0003-cross-validation.md)?
- Test-count bookkeeping: PROJECT_MEMORY verification contract now says 124 countable / 120 runnable Linux / expected 119 macOS+Windows — is that consistent with the tree (grep -rn '#\[test\]' engine/crates --include='*.rs' | wc -l from /home/z/my-project/download/HoloNet) and with the 2 #[ignore] x25519 iterated tests?

VERDICT FORMAT — the LAST section of your reply must be EXACTLY:
AGENT: A3 Strategy Adversary
VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
FINDINGS:
- [F#] <finding> — evidence: <path:line> (verified | suspected)
CONDITIONS:
- [C#] <concrete, verifiable condition>   (required unless PROCEED)
DISSENT/NOTES: <anything the aggregator must not smooth over>
File your verdict BEFORE any aggregation; you will not see other reviewers' output.

## A4 prompt (Process Auditor)

Task ID: GATE-0004-A4. You are reviewer A4 (Process Auditor) in an adversarial gate review for the HoloNet project's S1→S2 stage transition (record 0004). RESEARCH-ONLY: read-only commands (git read commands ALLOWED: status/log/show/diff; sha256sum; python); NO file modifications, NO git write commands (no commit/push/tag). Time-box ~10 minutes.

CONTEXT: /home/z/my-project/download/HoloNet — the harness (harness/) enforces a strict process: WORKFLOW.md is binding; memory files are append-only (DECISIONS/LESSONS/BACKUPS); session journals in harness/memory/sessions/; hash-chained gate records in harness/adversarial/verdicts/ (each ends with a chain: line = SHA-256 of the previous record's full BLOB text, verified via git show HEAD:<path> | sha256sum); CI harness-audit job enforces memory-graph coverage (every session journal needs a graph node BEFORE push — check via python3 harness/memory/graph/memory_graph.py check).

YOUR ATTACKS (standing panel): the harness/workflow itself; consensus failure modes; backup integrity; restore runbook; rubber-stamp risk.

REVIEW PRIORITIES for THIS session's process (run 10, 2026-11-25, journal: harness/memory/sessions/2026-11-25-s1b-completion.md):
- Session-start ritual (runbook 0/0b): remote reconciliation MATCH, toolchain reinstall (5th wipe), baseline 97-green BEFORE changes — journal claims these; spot-check what you can (git log, BACKUPS.md tail).
- Backup integrity: two pushes this session — d6c37a0 (stage 1) CI run 45488934917 SUCCESS; 9cf3114 (stage 2, X25519) pushed 21:30:09Z, CI in flight. BACKUPS.md lines present and truthful? Working tree clean at HEAD?
- Append-only discipline: DECISIONS.md gained D-0030/D-0031/D-0032 — are they APPENDS (no history rewrite)? Use git diff HEAD~2..HEAD -- harness/memory/DECISIONS.md (read-only) or git show to check.
- Graph coverage: memory_graph.py check + memory_rag.py smoke (both should pass: 155 nodes/115 edges).
- Hash chain: verify record 0003's chain line — the record's tail says chain: 72d8858d…; compute git show HEAD:harness/adversarial/verdicts/0002-progress-review.md | sha256sum and compare (the chain points to the PREVIOUS record's blob hash). Report whether the chain is intact through 0003.
- Rubber-stamp risk for THIS gate: the aggregator (lead agent) is ALSO the author of the work under review (disclosed conflict per the protocol's Independence limits) — the gate record must archive reviewer prompts verbatim and transcribe verdicts exactly. You are one of four blind reviewers launched in parallel.
- The task brief for this session included a stale claim (Windows ACL decision listed as open work) — the journal corrected it (already recorded D-0018/A2-F4, THREAT-MODEL lines 191-200). Does the correction hold (check THREAT-MODEL)?
- poll_ci.sh false-negative episode (stale head_sha filter, stage-1 CI): is the poll-script quirk honestly recorded, and does anything in the backup/CI chain depend on the faulty poll result? (The lead verified via direct authenticated API query — journal Addendum 1.)

VERDICT FORMAT — the LAST section of your reply must be EXACTLY:
AGENT: A4 Process Auditor
VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
FINDINGS:
- [F#] <finding> — evidence: <path:line> (verified | suspected)
CONDITIONS:
- [C#] <concrete, verifiable condition>   (required unless PROCEED)
DISSENT/NOTES: <anything the aggregator must not smooth over>
File your verdict BEFORE any aggregation; you will not see other reviewers' output.
